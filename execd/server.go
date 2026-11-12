package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

// server owns every process started through it. A call outlives the connection that
// started it: its output is buffered until the client releases it, so a client that lost
// its connection can resume the call on a new one from the offsets it already has.
type server struct {
	keyHash []byte
	mu      sync.Mutex
	calls   map[uint64]*call
	preauth chan struct{} // a slot per connection not yet authenticated
}

const idleTimeout = 60 * time.Second

// authTimeout bounds the TLS handshake and the AUTH frame; maxKey bounds AUTH's payload;
// maxPreauth bounds the connections doing either at once.
const authTimeout, maxKey, maxPreauth = 10 * time.Second, 64, 32

type call struct {
	id  uint64
	tag string
	pid int
	// stdin frames wait in stdinQ for a writer goroutine, so a command that does not read
	// its stdin cannot stall the connection other calls share.
	stdinQ   [][]byte
	stdinGot int  // bytes of stdin received
	stdinPut int  // bytes of stdin written to the process
	stdinEOF bool // the client closed stdin
	mu       sync.Mutex
	out      [2][]byte // stdout, stderr: what the process wrote and the client has not acked
	base     [2]int    // the stream offset of out[i][0]
	sent     [2]int    // the offset up to which the current subscriber has been sent output
	room     *sync.Cond
	gone     bool // released: drop any further output
	exited   bool
	code     int
	sub      *conn // the connection streaming this call, if any
}

type conn struct {
	nc   net.Conn
	wmu  sync.Mutex
	dead chan struct{}
	once sync.Once
}

func (c *conn) send(kind byte, id uint64, payload []byte) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	select {
	case <-c.dead:
		return
	default:
	}
	// A peer that stops reading (a partitioned network) must not stall the call forever.
	c.nc.SetWriteDeadline(time.Now().Add(idleTimeout))
	if _, err := c.nc.Write(encodeFrame(kind, id, payload)); err != nil {
		c.close()
	}
}

func (c *conn) close() {
	c.once.Do(func() { close(c.dead); c.nc.Close() })
}

func newServer(keyHashHex string) (*server, error) {
	h, err := hex.DecodeString(keyHashHex)
	if err != nil || len(h) != sha256.Size {
		return nil, fmt.Errorf("key hash must be 64 hex characters")
	}
	return &server{keyHash: h, calls: map[uint64]*call{}, preauth: make(chan struct{}, maxPreauth)}, nil
}

func (s *server) serve(l net.Listener) {
	for {
		nc, err := l.Accept()
		if err != nil {
			// A transient error, such as running out of file descriptors, must not end the daemon.
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case s.preauth <- struct{}{}:
			go s.handle(&conn{nc: nc, dead: make(chan struct{})})
		default: // a flood of unauthenticated connections
			nc.Close()
		}
	}
}

func (s *server) handle(c *conn) {
	defer s.detach(c)
	defer c.close()
	// Before AUTH the peer is anyone who can reach the port: bound its time and memory.
	c.nc.SetReadDeadline(time.Now().Add(authTimeout))
	first, err := readFrameMax(c.nc, maxKey)
	<-s.preauth
	if err != nil || first.kind != fAuth {
		return
	}
	got := sha256.Sum256(first.payload)
	if subtle.ConstantTimeCompare(got[:], s.keyHash) != 1 {
		return
	}
	ok, _ := json.Marshal(map[string]int{"pid": os.Getpid()})
	c.send(fOK, 0, ok)
	for {
		c.nc.SetReadDeadline(time.Now().Add(idleTimeout)) // clients ping every 15 s
		f, err := readFrame(c.nc)
		if err != nil {
			return
		}
		switch f.kind {
		case fStart:
			s.start(c, f)
		case fStdin:
			if cl := s.get(f.id); cl != nil {
				cl.writeStdin(f.payload)
			}
		case fKill:
			if cl := s.get(f.id); cl != nil {
				cl.kill()
			}
		case fResume:
			s.resume(c, f)
		case fAck:
			var req resumeRequest
			if cl := s.get(f.id); cl != nil && json.Unmarshal(f.payload, &req) == nil {
				cl.ack(req)
			}
		case fRelease:
			s.mu.Lock()
			cl := s.calls[f.id]
			delete(s.calls, f.id)
			s.mu.Unlock()
			if cl != nil {
				cl.mu.Lock()
				cl.gone, cl.out = true, [2][]byte{}
				cl.room.Broadcast()
				cl.mu.Unlock()
			}
		case fPing:
			c.send(fPong, f.id, nil)
		}
	}
}

// detach stops streaming to a closed connection; its calls keep running and buffering.
func (s *server) detach(c *conn) {
	s.mu.Lock()
	calls := make([]*call, 0, len(s.calls))
	for _, cl := range s.calls {
		calls = append(calls, cl)
	}
	s.mu.Unlock()
	for _, cl := range calls {
		cl.mu.Lock()
		if cl.sub == c {
			cl.sub = nil
		}
		cl.mu.Unlock()
	}
}

func (s *server) get(id uint64) *call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[id]
}

func (s *server) start(c *conn, f frame) {
	var req startRequest
	req.Env = map[string]string{}
	if err := json.Unmarshal(f.payload, &req); err != nil || len(req.Argv) == 0 {
		c.send(fError, f.id, []byte("bad start request"))
		return
	}
	if req.Env == nil { // "env": null
		req.Env = map[string]string{}
	}
	cl := &call{id: f.id, tag: req.Tag, sub: c}
	cl.room = sync.NewCond(&cl.mu)
	s.mu.Lock()
	if _, dup := s.calls[f.id]; dup {
		s.mu.Unlock()
		c.send(fError, f.id, []byte("call id in use"))
		return
	}
	s.calls[f.id] = cl
	s.mu.Unlock()
	if err := cl.run(req); err != nil {
		// Report like a shell would: the message on stderr and 126 or 127 as the exit code.
		code := 126
		if os.IsNotExist(err) || strings.Contains(err.Error(), "not found") {
			code = 127
		}
		cl.output(1, []byte("execd: "+err.Error()+"\n"))
		cl.finish(code)
	}
}

func (s *server) resume(c *conn, f frame) {
	var req resumeRequest
	cl := s.get(f.id)
	if cl == nil || json.Unmarshal(f.payload, &req) != nil {
		c.send(fError, f.id, []byte("unknown call"))
		return
	}
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.sub = c
	// Tell the client how much stdin arrived, so it can send the rest.
	got, _ := json.Marshal(map[string]any{"stdin": cl.stdinGot, "eof": cl.stdinEOF, "put": cl.stdinPut})
	c.send(fResumed, f.id, got)
	cl.ackLocked(req) // the client has everything before the offsets it resumes from
	cl.sent = [2]int{cl.base[0], cl.base[1]}
	cl.flush()
}

func (cl *call) run(req startRequest) error {
	if req.Tag != "" {
		req.Env["HAWK_NEXT_EXEC"] = req.Tag
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
	env := childEnv(req.Env)
	argv0, err := lookPath(req.Argv[0], env)
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
		return err
	}
	exited := reaper.watch(p.Pid)
	reaper.mu.Unlock()
	p.Release()
	cl.pid = p.Pid
	var deadline *time.Timer
	if req.Timeout > 0 {
		deadline = time.AfterFunc(time.Duration(req.Timeout*float64(time.Second)), cl.kill)
	}
	if stdinW != nil {
		go cl.feedStdin(stdinW)
	}
	var drained sync.WaitGroup
	var read [2]atomic.Int64 // bytes read from each pipe
	pipes := []*os.File{outR, errR}
	for i, r := range pipes {
		drained.Add(1)
		go func() {
			defer drained.Done()
			defer r.Close()
			buf := make([]byte, 256<<10)
			for {
				n, err := r.Read(buf)
				if n > 0 {
					read[i].Add(int64(n))
					cl.output(i, buf[:n])
				}
				if err != nil {
					return
				}
			}
		}()
	}
	go func() {
		code := <-exited
		if deadline != nil {
			deadline.Stop()
		}
		// All the command wrote before it exited is in the pipes: read it, however slowly the
		// client takes it. Then, 100 ms on, stop reading, so a background child that keeps a
		// pipe open can't hold the call open forever.
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
				cl.finish(code)
				return
			case <-time.After(10 * time.Millisecond):
			}
			delivered := true
			for i, r := range pipes {
				delivered = delivered && (read[i].Load() >= want[i] || buffered(r) == 0)
			}
			if delivered && time.Now().After(grace) {
				outR.SetReadDeadline(time.Now())
				errR.SetReadDeadline(time.Now())
				<-done
				cl.finish(code)
				return
			}
		}
	}()
	return nil
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

func (cl *call) writeStdin(data []byte) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.stdinEOF {
		return
	}
	if len(data) == 0 {
		cl.stdinEOF = true
	} else {
		cl.stdinQ = append(cl.stdinQ, data)
		cl.stdinGot += len(data)
	}
	cl.room.Broadcast()
}

func (cl *call) feedStdin(w *os.File) {
	defer w.Close()
	for {
		cl.mu.Lock()
		for len(cl.stdinQ) == 0 && !cl.stdinEOF && !cl.exited {
			cl.room.Wait()
		}
		if len(cl.stdinQ) == 0 {
			cl.mu.Unlock()
			return
		}
		data := cl.stdinQ[0]
		cl.stdinQ = cl.stdinQ[1:]
		cl.mu.Unlock()
		// A command that exits without reading its stdin makes this fail; that is not an error.
		if _, err := w.Write(data); err != nil {
			return
		}
		cl.mu.Lock()
		cl.stdinPut += len(data)
		if cl.sub != nil {
			b, _ := json.Marshal(map[string]int{"stdin": cl.stdinPut})
			cl.sub.send(fStdinAck, cl.id, b)
		}
		cl.mu.Unlock()
	}
}

// maxUnacked bounds the output execd holds for one stream of a call; past it, reading the
// process's pipe waits for acks, so a disconnected client pauses the writer, not memory.
const maxUnacked = 32 << 20

func (cl *call) output(stream int, data []byte) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	for len(cl.out[stream]) > maxUnacked && !cl.gone {
		cl.room.Wait()
	}
	if cl.gone {
		return
	}
	cl.out[stream] = append(cl.out[stream], data...)
	cl.flush()
}

func (cl *call) ack(req resumeRequest) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.ackLocked(req)
}

// ackLocked forgets output the client confirmed it has.
func (cl *call) ackLocked(req resumeRequest) {
	for i, upto := range []int{req.Stdout, req.Stderr} {
		n := min(max(upto-cl.base[i], 0), len(cl.out[i]))
		cl.out[i] = cl.out[i][n:]
		cl.base[i] += n
		cl.sent[i] = max(cl.sent[i], cl.base[i])
	}
	cl.room.Broadcast()
}

// kill stops the call's process group, and every process still carrying its tag.
func (cl *call) kill() {
	if cl.pid > 0 { // 0: it never started, and -0 would be execd's own group
		syscall.Kill(-cl.pid, syscall.SIGKILL)
	}
	killTagged(cl.tag)
}

func (cl *call) finish(code int) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.exited, cl.code = true, code
	cl.room.Broadcast()
	cl.flush()
}

// flush sends the subscriber whatever it has not seen yet, then the exit. Holding cl.mu
// while sending keeps the frames in order.
func (cl *call) flush() {
	if cl.sub == nil {
		return
	}
	for i, kind := range []byte{fStdout, fStderr} {
		end := cl.base[i] + len(cl.out[i])
		for cl.sent[i] < end {
			next := min(end, cl.sent[i]+1<<20)
			cl.sub.send(kind, cl.id, cl.out[i][cl.sent[i]-cl.base[i]:next-cl.base[i]])
			cl.sent[i] = next
		}
	}
	if cl.exited {
		b, _ := json.Marshal(map[string]int{"code": cl.code})
		cl.sub.send(fExit, cl.id, b)
	}
}

// childEnv is execd's own environment without its HN_EXECD_ settings, plus the call's.
func childEnv(extra map[string]string) []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if _, over := extra[k]; !strings.HasPrefix(k, "HN_EXECD_") && !over {
			env = append(env, kv)
		}
	}
	for k, v := range extra {
		env = append(env, k+"="+v)
	}
	return env
}

func lookPath(name string, env []string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	path := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			path = v
		}
	}
	for _, dir := range filepath.SplitList(path) {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: not found", name)
}

// lookupUser resolves a name or numeric uid from the container's /etc/passwd. It returns a
// nil credential when the user is the one execd already runs as.
func lookupUser(name string) (*syscall.Credential, string, string, error) {
	var u *user.User
	var err error
	if uidPart, gidPart, ok := strings.Cut(name, ":"); ok { // "uid:gid", as a spec may give
		cred, home, uname, err := lookupUser(uidPart)
		if gid, gErr := strconv.ParseUint(gidPart, 10, 32); err == nil && cred != nil && gErr == nil {
			cred.Gid, cred.Groups = uint32(gid), nil
		}
		return cred, home, uname, err
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

// killTagged SIGKILLs every process whose environment holds HAWK_NEXT_EXEC=<tag>, which
// finds a command's whole tree even after setsid or a double fork.
func killTagged(tag string) {
	if tag == "" {
		return
	}
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

// The reaper collects every child that exits, including orphans reparented to execd (it is
// a subreaper), and hands exit codes to whoever registered the PID. Wait4 can reap
// a child before run() registers it; the reaper then blocks on mu until it has.
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

func copyClose(dst io.WriteCloser, src io.Reader) {
	io.Copy(dst, src)
	dst.Close()
}
