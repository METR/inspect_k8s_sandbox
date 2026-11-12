package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// server authenticates connections; each then runs one command.
type server struct {
	keyHash     []byte
	preauth     chan struct{} // a slot per connection not yet authenticated
	authTimeout time.Duration // for a connection to send its AUTH
	pingEvery   time.Duration
	// After an exit execd reads on this long for the client to close: closing first, with stdin unread, would reset the connection under the EXIT.
	lingerFor time.Duration
}

// Bounds on unauthenticated connections: the AUTH payload, and how many at once.
const maxKey, maxPreauth = 64, 32

const maxStart = 16 << 20 // a START: argv and env as JSON

// call is one command and the connection it runs on.
type call struct {
	s        *server
	nc       net.Conn
	wmu      sync.Mutex // a frame at a time
	stream   bool
	tag      string
	timedOut atomic.Bool
	mu       sync.Mutex
	pid      int      // 0 until the command starts, and once it is reaped
	stdin    *os.File // nil once closed
}

func newServer(keyHashHex string) (*server, error) {
	h, err := hex.DecodeString(keyHashHex)
	if err != nil || len(h) != sha256.Size {
		return nil, fmt.Errorf("key hash must be 64 hex characters")
	}
	return &server{
		keyHash: h, preauth: make(chan struct{}, maxPreauth),
		authTimeout: 10 * time.Second, pingEvery: 15 * time.Second, lingerFor: time.Minute,
	}, nil
}

func (s *server) serve(l net.Listener) {
	for {
		s.preauth <- struct{}{} // past the bound, connections wait in the listen queue
		nc, err := l.Accept()
		if err == nil && !fromThisPod(nc) { // the client dials from another pod: here, only the sandbox would
			go s.handle(nc)
			continue
		}
		<-s.preauth
		if err != nil {
			// A transient error, such as running out of file descriptors, must not end the daemon.
			time.Sleep(50 * time.Millisecond)
		} else {
			nc.Close()
		}
	}
}

// fromThisPod says whether a connection comes from the pod itself: from loopback or any of its addresses.
func fromThisPod(nc net.Conn) bool {
	remote, ok := nc.RemoteAddr().(*net.TCPAddr)
	if !ok || remote.IP.IsLoopback() {
		return ok
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(remote.IP) {
			return true
		}
	}
	return false
}

func (s *server) handle(nc net.Conn) {
	defer nc.Close()
	// Before AUTH the peer is anyone who can reach the port: bound its time and memory.
	nc.SetReadDeadline(time.Now().Add(s.authTimeout))
	auth, err := readFrame(nc, maxKey)
	<-s.preauth
	if err != nil || auth.kind != fAuth {
		return
	}
	got := sha256.Sum256(auth.payload)
	if subtle.ConstantTimeCompare(got[:], s.keyHash) != 1 {
		return
	}
	nc.SetReadDeadline(time.Time{})
	start, err := readFrame(nc, maxStart)
	var req startRequest
	if err != nil || start.kind != fStart || json.Unmarshal(start.payload, &req) != nil || len(req.Argv) == 0 {
		return
	}
	(&call{s: s, nc: nc, stream: req.Stream}).serve(req)
}

// serve runs the command and feeds it stdin until the client closes the connection.
func (c *call) serve(req startRequest) {
	if err := c.start(req); err != nil {
		// Report like a shell would: the message on stderr and 126 or 127 as the exit code.
		code := 126
		if strings.HasPrefix(err.Error(), "cd: ") {
			code = 1
		} else if os.IsNotExist(err) || strings.Contains(err.Error(), "not found") {
			code = 127
		}
		msg := err.Error()
		stderr := "execd: " + msg + "\n"
		c.send(fStderr, []byte(stderr[max(0, len(stderr)-chunk):])) // its end says why
		// Out of band too, so the command's own stderr can't fake it; capped, so even
		// escaped to JSON it fits the client's 4 KiB control frame.
		c.finish(exitStatus{Code: code, Error: msg[:min(len(msg), 512)]})
	}
	done := make(chan struct{})
	defer close(done)
	go func() { // a write is what finds a client gone while the read below waits on the command
		for {
			select {
			case <-done:
				return
			case <-time.After(c.s.pingEvery):
				c.send(fPing, nil)
			}
		}
	}()
	for {
		f, err := readFrame(c.nc, chunk)
		if err != nil {
			break
		}
		if f.kind == fStdin {
			c.writeStdin(f.payload)
		}
	}
	c.drop()
}

func (c *call) send(kind byte, payload []byte) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := c.nc.Write(encodeFrame(kind, payload)); err != nil {
		c.drop()
	}
}

// drop ends a call whose client is gone; it frees serve's read, or its write to a command that isn't reading.
func (c *call) drop() {
	c.nc.Close()
	c.kill() // before stdin ends, which the command must not take for the end of its input
	c.closeStdin()
}

// finish sends the exit, then waits only so long for the client to close.
func (c *call) finish(status exitStatus) {
	b, _ := json.Marshal(status)
	c.send(fExit, b)
	c.nc.SetReadDeadline(time.Now().Add(c.s.lingerFor))
}

// writeStdin waits while the command doesn't read, so TCP holds back the rest.
func (c *call) writeStdin(data []byte) {
	if len(data) == 0 {
		c.closeStdin()
		return
	}
	c.mu.Lock()
	w := c.stdin
	c.mu.Unlock()
	if w != nil {
		w.Write(data) // a command that exits without reading its stdin makes this fail; that is not an error
	}
}

func (c *call) closeStdin() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stdin != nil {
		c.stdin.Close()
		c.stdin = nil
	}
}

// kill stops a running command: a stream's own process, else its process group and every process still carrying its tag.
func (c *call) kill() {
	c.mu.Lock()
	pid := c.pid
	c.mu.Unlock()
	switch {
	case pid == 0: // never started, or reaped: its id may now be another's
	case c.stream:
		syscall.Kill(pid, syscall.SIGKILL)
	default:
		syscall.Kill(-pid, syscall.SIGKILL)
		killTagged(c.tag)
	}
}

func (c *call) start(req startRequest) error {
	if req.Env == nil { // "env": null
		req.Env = map[string]string{}
	}
	if !req.Stream { // nothing looks for a stream's processes
		tag := make([]byte, 8)
		rand.Read(tag)
		c.tag = hex.EncodeToString(tag)
		req.Env["HAWK_NEXT_EXEC"] = c.tag
	}
	attr := &syscall.SysProcAttr{Setpgid: true}
	if req.User != "" {
		cred, home, name, err := lookupUser(req.User)
		if err != nil {
			return err
		}
		if cred != nil {
			attr.Credential = cred
			// As runuser sets them, unless the caller did.
			for k, v := range map[string]string{"HOME": home, "USER": name, "LOGNAME": name} {
				if _, set := req.Env[k]; !set {
					req.Env[k] = v
				}
			}
		}
	}
	if _, err := os.Stat(req.Cwd); req.Cwd != "" && err != nil {
		return fmt.Errorf("cd: %s: %w", req.Cwd, errors.Unwrap(err))
	}
	env := childEnv(req.Env)
	argv0, err := lookPath(req.Argv[0], env, req.Cwd)
	if err != nil {
		return err
	}
	stdinR, stdinW, err := stdinPipe(req.Stdin)
	if err != nil {
		return err
	}
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	reaper.mu.Lock() // so the reaper cannot collect the exit before it is registered
	p, err := os.StartProcess(argv0, req.Argv, &os.ProcAttr{
		Dir: req.Cwd, Env: env, Files: []*os.File{stdinR, outW, errW}, Sys: attr,
	})
	stdinR.Close()
	outW.Close()
	errW.Close()
	if err != nil {
		reaper.mu.Unlock()
		outR.Close()
		errR.Close()
		if stdinW != nil {
			stdinW.Close()
		}
		if errors.Is(err, syscall.EACCES) && req.Cwd != "" && !entered(req.Cwd, attr) {
			return fmt.Errorf("cd: %s: %w", req.Cwd, syscall.EACCES)
		}
		return err
	}
	exited := reaper.watch(p.Pid)
	reaper.mu.Unlock()
	c.mu.Lock()
	c.pid, c.stdin = p.Pid, stdinW // before Release, which sets the Pid to -1
	c.mu.Unlock()
	p.Release()
	var deadline *time.Timer
	if req.Timeout > 0 && req.Timeout < 1e9 { // longer is never; converting it could overflow to "now"
		deadline = time.AfterFunc(time.Duration(req.Timeout*float64(time.Second)), func() {
			c.timedOut.Store(true)
			c.kill()
		})
	}
	var drained sync.WaitGroup
	var read [2]atomic.Int64 // bytes read from each pipe
	pipes := []*os.File{outR, errR}
	for i, r := range pipes {
		drained.Add(1)
		go func() {
			defer drained.Done()
			c.copyOut(byte(fStdout+i), r, &read[i])
		}()
	}
	go func() {
		code := <-exited
		c.mu.Lock()
		c.pid = 0
		c.mu.Unlock()
		if deadline != nil {
			deadline.Stop()
		}
		status := exitStatus{Code: code, Timeout: c.timedOut.Load()}
		// Deliver all output written before exit; stop 100 ms on, so a background child can't hold the call.
		var want [2]int64
		for i, r := range pipes {
			want[i] = buffered(r) // before the count, so want can't fall short
			want[i] += read[i].Load()
		}
		done := make(chan struct{})
		go func() { drained.Wait(); close(done) }()
		grace := time.Now().Add(100 * time.Millisecond)
		for {
			select {
			case <-done:
				c.finish(status)
				return
			case <-time.After(10 * time.Millisecond):
			}
			delivered := true
			for i, r := range pipes {
				delivered = delivered && (read[i].Load() >= want[i] || buffered(r) == 0)
			}
			if delivered && time.Now().After(grace) {
				outR.Close()
				errR.Close()
				<-done
				c.finish(status)
				return
			}
		}
	}()
	return nil
}

// entered says whether a start with these credentials gets into dir: its exec of nothing fails only after the chdir.
func entered(dir string, sys *syscall.SysProcAttr) bool {
	_, err := os.StartProcess("", []string{""}, &os.ProcAttr{Dir: dir, Sys: sys})
	return errors.Is(err, syscall.ENOENT)
}

// copyOut sends a pipe's output: a full buffer at once, less only a millisecond after the last, so small writes make few frames.
func (c *call) copyOut(kind byte, r *os.File, read *atomic.Int64) {
	defer r.Close()
	buf := make([]byte, chunk)
	var sent time.Time
	for {
		r.SetReadDeadline(time.Time{})
		n, err := r.Read(buf)
		read.Add(int64(n))
		for err == nil && n < len(buf) {
			r.SetReadDeadline(sent.Add(time.Millisecond))
			var m int
			m, err = r.Read(buf[n:])
			read.Add(int64(m))
			n += m
		}
		if n > 0 {
			c.send(kind, buf[:n])
			sent = time.Now()
		}
		if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			return
		}
	}
}

// buffered says how many bytes wait unread in a pipe (0 once it is closed).
func buffered(f *os.File) int64 {
	var n int32
	if rc, err := f.SyscallConn(); err == nil {
		rc.Control(func(fd uintptr) {
			syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCINQ, uintptr(unsafe.Pointer(&n)))
		})
	}
	return int64(n)
}

func stdinPipe(wanted bool) (*os.File, *os.File, error) {
	if !wanted {
		f, err := os.Open(os.DevNull)
		return f, nil, err
	}
	return os.Pipe()
}

// childEnv is execd's own environment, plus the call's.
func childEnv(extra map[string]string) []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if _, over := extra[k]; !over {
			env = append(env, kv)
		}
	}
	for k, v := range extra {
		env = append(env, k+"="+v)
	}
	return env
}

// lookPath resolves as a shell would: relative PATH entries from cwd; a non-executable match is 126.
func lookPath(name string, env []string, cwd string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	path := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			path = v
		}
	}
	denied := ""
	for _, dir := range filepath.SplitList(path) {
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(cwd, dir)
		}
		p, _ := filepath.Abs(filepath.Join(dir, name)) // absolute: the child starts in cwd
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			continue
		}
		if st.Mode()&0o111 != 0 {
			return p, nil
		}
		if denied == "" {
			denied = p
		}
	}
	if denied != "" {
		return "", &os.PathError{Op: "exec", Path: denied, Err: syscall.EACCES}
	}
	return "", fmt.Errorf("%s: not found", name)
}

// lookupUser resolves a name or uid in /etc/passwd; a nil credential means execd's own user.
func lookupUser(name string) (*syscall.Credential, string, string, error) {
	var u *user.User
	var err error
	if name == "root" { // uid 0, whatever the image's passwd says
		name = "0"
	}
	if _, numErr := strconv.ParseUint(name, 10, 32); numErr == nil { // no uid wraps to 0
		if u, err = user.LookupId(name); err != nil {
			u = &user.User{Uid: name, Gid: name, Username: name, HomeDir: "/"}
		}
	} else if u, err = user.Lookup(name); err != nil {
		return nil, "", "", fmt.Errorf("unknown user %s", name)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if uid == os.Getuid() {
		return nil, u.HomeDir, u.Username, nil
	}
	if os.Getuid() != 0 {
		return nil, "", "", fmt.Errorf("cannot run as %s: execd is not root", name)
	}
	var groups []uint32
	if ids, err := u.GroupIds(); err == nil {
		for _, g := range ids {
			if n, err := strconv.Atoi(g); err == nil {
				groups = append(groups, uint32(n))
			}
		}
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}, u.HomeDir, u.Username, nil
}

// killTagged SIGKILLs every process whose environment holds HAWK_NEXT_EXEC=<tag>, even after setsid.
func killTagged(tag string) {
	needle := []byte("HAWK_NEXT_EXEC=" + tag + "\x00")
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		data, err := os.ReadFile("/proc/" + e.Name() + "/environ")
		if err == nil && strings.Contains(string(data)+"\x00", string(needle)) {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

// The reaper reaps every child, orphans included; it waits on mu until run() registers the PID.
type reaperState struct {
	mu      sync.Mutex
	waiting map[int]chan int
}

var reaper = &reaperState{waiting: map[int]chan int{}}

// watch must be called with mu held.
func (r *reaperState) watch(pid int) chan int {
	ch := make(chan int, 1)
	r.waiting[pid] = ch
	return ch
}

func startReaper() {
	sigs := make(chan os.Signal, 64)
	signal.Notify(sigs, syscall.SIGCHLD)
	go func() {
		for range sigs {
			for {
				var ws syscall.WaitStatus
				pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
				if pid <= 0 || err != nil {
					break
				}
				code := ws.ExitStatus()
				if ws.Signaled() {
					code = 128 + int(ws.Signal())
				}
				reaper.mu.Lock()
				if ch, ok := reaper.waiting[pid]; ok {
					delete(reaper.waiting, pid)
					ch <- code
				}
				reaper.mu.Unlock()
			}
		}
	}()
}
