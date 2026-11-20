package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"os/signal"
	"os/user"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// fromAnotherUser says whether a Unix socket's peer runs as a user other than execd's, who could hold every unauthenticated slot.
func fromAnotherUser(nc net.Conn) bool {
	if secured, ok := nc.(interface{ NetConn() net.Conn }); ok {
		nc = secured.NetConn()
	}
	local, ok := nc.(*net.UnixConn)
	if !ok {
		return false
	}
	uid := -1
	if raw, err := local.SyscallConn(); err == nil {
		raw.Control(func(fd uintptr) {
			if peer, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED); err == nil {
				uid = int(peer.Uid)
			}
		})
	}
	return uid != os.Geteuid()
}

// server owns every process; a call outlives its connection, so a client can resume it.
type server struct {
	keyHash []byte
	mu      sync.Mutex
	calls   map[uint64]*call
	preauth chan struct{} // a slot per connection not yet authenticated
	current *conn         // the newest authenticated connection: the client's only live one
}

const idleTimeout = 60 * time.Second

// abandonAfter outlasts the client's reconnect window (5 minutes).
const abandonAfter = 6 * time.Minute

var shName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`) // a variable name sh keeps

var afterFunc = time.AfterFunc // tests fire the abandon timers themselves, stand in for a call's deadline, and end a kill's grace

// termGrace is how long what a kill's SIGTERM reached has to end before its SIGKILL: timeout(1)'s -k 5s, as over Kubernetes exec.
const termGrace = 5 * time.Second

var interfaceAddrs = net.InterfaceAddrs // tests make it fail, to check fromThisPod refuses when it can't tell

var workdir, _ = syscall.Getwd() // where execd started, and so does a command given no cwd; the kernel's name for it

// Tests hold execd at these points, or hear that it has reached them.
var afterRead, afterDrainCheck, beforeKill, afterTaken, beforeExit, beforeWait atomic.Pointer[func(late bool)]

func hook(h *atomic.Pointer[func(late bool)], late bool) {
	if f := h.Load(); f != nil {
		(*f)(late)
	}
}

// What one read of a command's pipe takes: a default pipe's capacity, and the most Go keeps off the heap.
const pipeRead = 64 << 10

// Bounds on unauthenticated connections: time, AUTH payload, and how many at once.
const authTimeout, maxKey, maxPreauth = 10 * time.Second, 64, 32

type call struct {
	id  uint64
	tag string
	kmu sync.Mutex // guards pid, status, as, killed, timeoutKilled and ending: a kill must not wait for mu
	pid int
	// its kill, from its SIGTERM on: closed once what that reached has ended or been killed, which its exit waits for
	ending chan struct{}
	// where the reaper sends its command's exit status
	status chan syscall.WaitStatus
	as     *syscall.Credential // who its command runs as, if not execd
	// queued for a writer goroutine, so a command that ignores stdin can't stall the connection
	stdinQ   [][]byte
	stdinGot int  // bytes of stdin received
	stdinPut int  // bytes of stdin written to the process
	stream   bool // killed when its connection drops, as nothing resumes it
	detached int  // times its connection dropped
	stdinEOF bool // the client closed stdin
	mu       sync.Mutex
	out      [2]fifo   // stdout, stderr: what the process wrote and the client has not acked
	base     [2]int    // the stream offset of out[i][0]
	sent     [2]int    // the offset up to which the current subscriber has been sent output
	flushed  time.Time // when output was last sent
	deferred bool      // a flush waits for its millisecond
	room     *sync.Cond
	gone     bool // released: drop any further output
	exited   bool
	code     int
	startErr string // why the command never started, if it didn't
	sub      *conn  // the connection streaming this call, if any
	// killed for want of a client, and kept so a RESUME can be told so
	abandoned bool
	killed    bool // asked to stop: a start still under way sees to it
	timedOut  bool // a timeout's kill went ahead on it: its exit says so, as the code alone can't
	// its timeout's kill went ahead on it
	timeoutKilled bool
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
		if fromThisPod(nc) || fromAnotherUser(nc) { // the client dials from another pod, or through an exec as execd's user
			nc.Close()
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

// fromThisPod says whether a connection comes from the pod itself.
func fromThisPod(nc net.Conn) bool {
	remote, ok := nc.RemoteAddr().(*net.TCPAddr)
	if !ok || remote.IP.IsLoopback() {
		return ok
	}
	addrs, err := interfaceAddrs()
	if err != nil { // can't tell: refuse, rather than admit a dial from the sandbox
		return true
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(remote.IP) {
			return true
		}
	}
	return false
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
	s.authenticated(c)
	c.send(fOK, 0, nil)
	for {
		c.nc.SetReadDeadline(time.Now().Add(idleTimeout)) // clients ping every 15 s
		f, err := readFrameMax(c.nc, maxPayload)
		if err != nil {
			return
		}
		s.dispatch(c, f)
	}
}

// authenticated makes c the client's connection and closes the one it replaces.
func (s *server) authenticated(c *conn) {
	s.mu.Lock()
	old := s.current
	s.current = c
	s.mu.Unlock()
	if old != nil {
		old.close()
	}
}

func (s *server) dispatch(c *conn, f frame) {
	s.mu.Lock()
	stale := s.current != c
	s.mu.Unlock()
	if stale { // a late frame from a replaced connection: a START would run its command again
		return
	}
	switch f.kind {
	case fStart:
		s.start(c, f)
	case fStdin:
		if cl := s.get(f.id); cl != nil {
			cl.writeStdin(c, f.payload)
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
		s.release(f.id)
	case fPing:
		c.send(fPong, f.id, nil)
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
		mine := cl.sub == c
		if mine {
			cl.sub = nil
			cl.detached++
		}
		detached := cl.detached
		cl.mu.Unlock()
		switch {
		case mine && cl.stream: // nothing resumes a stream
			cl.kill()
			s.release(cl.id)
		case mine: // a client that hasn't resumed it by then has given up
			afterFunc(abandonAfter, func() {
				cl.mu.Lock()
				orphaned := cl.sub == nil && cl.detached == detached // not resumed since
				if orphaned {
					cl.abandoned = true // not forgotten: "unknown call" would have the client send its START again
				}
				cl.mu.Unlock()
				if orphaned {
					cl.kill() // before its output is let go: a command that ended on that would leave what it started
					cl.mu.Lock()
					cl.gone, cl.out, cl.stdinQ = true, [2]fifo{}, nil
					cl.room.Broadcast()
					cl.mu.Unlock()
				}
			})
		}
	}
}

// release forgets a call and frees its buffered output.
func (s *server) release(id uint64) {
	s.mu.Lock()
	cl := s.calls[id]
	delete(s.calls, id)
	s.mu.Unlock()
	if cl != nil {
		cl.mu.Lock()
		cl.gone, cl.out, cl.stdinQ = true, [2]fifo{}, nil // a dropped connection's timer holds cl for six minutes
		cl.room.Broadcast()
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
	if err := json.Unmarshal(f.payload, &req); err != nil || len(req.Argv) == 0 {
		c.send(fError, f.id, []byte("bad start request"))
		return
	}
	if req.Env == nil { // "env": null
		req.Env = map[string]string{}
	}
	cl := &call{id: f.id, tag: req.Tag, sub: c, stream: req.Stream}
	cl.room = sync.NewCond(&cl.mu)
	s.mu.Lock()
	if s.current != nil && s.current != c { // its client may have run this call again since dispatch looked
		s.mu.Unlock()
		return
	}
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
		if strings.HasPrefix(err.Error(), "cd: ") {
			code = 1
		} else if os.IsNotExist(err) {
			code = 127
		}
		msg := err.Error()
		cl.output(1, []byte("execd: "+msg+"\n"))
		// Out of band too, so the command's stderr can't fake it; capped to fit the client's 4 KiB control frame.
		cl.finish(code, msg[:min(len(msg), 512)])
	}
}

func (s *server) resume(c *conn, f frame) {
	var req resumeRequest
	cl := s.get(f.id)
	if cl == nil || json.Unmarshal(f.payload, &req) != nil {
		c.send(fError, f.id, []byte("unknown call")) // the client sends its START again
		return
	}
	cl.mu.Lock()
	defer cl.mu.Unlock()
	for cl.abandoned && !cl.gone { // the kill that abandons it is under way: whether a timeout's got there first is known once it is done
		hook(&beforeWait, false)
		cl.room.Wait()
	}
	s.mu.Lock()
	replaced := s.current != nil && s.current != c // the call is the new connection's to resume
	s.mu.Unlock()
	if replaced {
		return
	}
	cl.kmu.Lock()
	byTimeout := cl.timeoutKilled // the kill's own word: its exit may not have said so yet
	cl.kmu.Unlock()
	if cl.abandoned && !byTimeout { // one its own timeout ended still says so: that takes none of the output let go
		c.send(fError, f.id, []byte("call abandoned after "+abandonAfter.String()+" with no client"))
		return
	}
	cl.sub = c
	// Tell the client how much stdin arrived, so it can send the rest.
	got, _ := json.Marshal(map[string]any{"stdin": cl.stdinGot, "eof": cl.stdinEOF, "put": cl.stdinPut})
	c.send(fResumed, f.id, got)
	cl.ackLocked(req) // the client has everything before the offsets it resumes from
	cl.sent = [2]int{cl.base[0], cl.base[1]}
	charge(cl.flush())
}

func (cl *call) run(req startRequest) error {
	if strings.HasPrefix(req.Argv[0], "-") { // bash and busybox would read it as an option of their exec
		return &os.PathError{Op: "exec", Path: req.Argv[0], Err: syscall.ENOENT}
	}
	for name := range req.Env { // sh starts the command, and dash passes on no other name
		if !shName.MatchString(name) {
			return fmt.Errorf("bad variable name %s", name)
		}
	}
	req.Env["HAWK_NEXT_EXEC"] = req.Tag
	argv := append([]string{"/bin/sh", "-c", `exec "$@"`, "/bin/sh"}, req.Argv...)
	dir := req.Cwd
	var as *syscall.Credential
	if req.User != "" {
		cred, home, name, err := lookupUser(req.User)
		if err != nil {
			return err
		}
		if cred != nil {
			// A child Go switched to the user would be theirs to stop before it execs, with execd waiting on it.
			argv = append([]string{"/proc/self/exe", "as", dir, fmt.Sprint(cred.Uid), fmt.Sprint(cred.Gid), strings.Trim(fmt.Sprint(cred.Groups), "[]")}, argv...)
			as, dir = cred, ""
			// As runuser sets them, unless the caller did.
			for k, v := range map[string]string{"HOME": home, "USER": name, "LOGNAME": name} {
				if _, set := req.Env[k]; !set {
					req.Env[k] = v
				}
			}
		}
	}
	// By its path, as Kubernetes exec does: a command may have replaced the directory.
	if err := os.Chdir(workdir); err != nil && !strings.HasPrefix(req.Cwd, "/") {
		// A user who cannot enter it by its path stays in it, while that path is still this directory.
		if here, _ := syscall.Getwd(); !errors.Is(err, syscall.EACCES) || here != workdir {
			return fmt.Errorf("cd: %s: %w", workdir, errors.Unwrap(err))
		}
	}
	if req.Cwd != "" && as == nil { // one execd's user can enter, else the cd fails, not the command; another user's cd is its launcher's
		if err := syscall.Access(req.Cwd+"/.", 0); err != nil {
			return fmt.Errorf("cd: %s: %w", req.Cwd, err)
		}
	}
	stdinR, stdinW, err := stdinPipe(req.Stdin)
	if err != nil {
		return err
	}
	outR, outW, noOut := os.Pipe()
	errR, errW, noErr := os.Pipe()
	var envR, envW *os.File
	var noEnv error
	if as != nil {
		envR, envW, noEnv = os.Pipe()
	}
	if err := errors.Join(noOut, noErr, noEnv); err != nil { // out of descriptors: it would run with a stream missing
		for _, f := range []*os.File{stdinR, stdinW, outR, outW, errR, errW, envR, envW} {
			f.Close()
		}
		return err
	}
	reaper.mu.Lock() // so the reaper cannot collect the exit before it is registered
	env, files := childEnv(req.Env), []*os.File{stdinR, outW, errW}
	if as != nil { // its environment goes by a pipe: in the launcher's own, the Go runtime would read it
		raw := make([][]byte, len(env)) // as bytes: JSON would rewrite text that isn't UTF-8
		for i, kv := range env {
			raw[i] = []byte(kv)
		}
		go func() { json.NewEncoder(envW).Encode(raw); envW.Close() }()
		defer envR.Close()
		env, files = []string{"GOMAXPROCS=1"}, append(files, envR) // each launcher thread takes a PID of the pod's
	}
	// The user's own shell finds the command on PATH and becomes it, a script with no #! line too.
	p, err := os.StartProcess(argv[0], argv, &os.ProcAttr{
		Dir: dir, Env: env, Files: files, Sys: &syscall.SysProcAttr{Setpgid: true},
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
	cl.kmu.Lock()
	cl.pid, cl.as, cl.status = p.Pid, as, exited // before Release, which sets it to -1
	killed := cl.killed
	cl.kmu.Unlock()
	if killed { // while it started: nothing is reaped under this lock, so the id is its own
		signalTree(as, p.Pid, []int{p.Pid}, syscall.SIGKILL)
	}
	reaper.mu.Unlock()
	if killed { // that holds for what it left running too
		cl.search(as, syscall.SIGKILL, nil)
	}
	p.Release()
	var deadline *time.Timer
	if req.Timeout > 0 && req.Timeout < 1e9 { // longer is never; converting it could overflow to "now"
		deadline = afterFunc(time.Duration(req.Timeout*float64(time.Second)), func() { cl.stop(true) })
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
			buf := make([]byte, pipeRead)
			for {
				n, err := r.Read(buf)
				if n > 0 {
					hook(&afterRead, false)
					read[i].Add(int64(n))
					cl.output(i, buf[:n])
				}
				if errors.Is(err, os.ErrDeadlineExceeded) { // closed now, the pipe would raise SIGPIPE at the next write of what the command left running
					select {
					case held <- struct{}{}:
						keep(r, keeper, held)
						return
					default: // no place left: closed, and that write raises SIGPIPE
					}
				}
				if err != nil {
					r.Close()
					return
				}
			}
		}()
	}
	go func() {
		ws := <-exited
		hook(&beforeExit, false)
		code := ws.ExitStatus()
		if ws.Signaled() {
			code = 128 + int(ws.Signal())
		}
		if stdinW != nil {
			stdinW.Close() // or its writer waits for ever on what the command left holding its stdin
		}
		if deadline != nil {
			deadline.Stop()
		}
		cl.kmu.Lock()
		cl.pid = 0 // reaped: its id may now be another group's
		byTimeout, ending := cl.timeoutKilled, cl.ending
		cl.kmu.Unlock()
		if ending != nil { // what its SIGTERM reached may run on through the grace: the exit waits, and takes what they write
			<-ending
		}
		cl.mu.Lock()
		cl.timedOut = byTimeout
		cl.mu.Unlock()
		// Deliver all output written before exit; stop 100 ms on, so a background child can't hold the call.
		var want [2]int64
		for i, r := range pipes {
			want[i] = buffered(r)                // before the count, so want can't fall short
			want[i] += read[i].Load() + pipeRead // a read under way has taken bytes it hasn't counted
		}
		done := make(chan struct{})
		go func() {
			drained.Wait()
			if said := signalLine(ws); said != "" && !byTimeout { // after the command's own stderr, as a shell's line is; none for a timeout's kill
				cl.output(1, []byte(said))
			}
			close(done)
		}()
		grace := time.Now().Add(100 * time.Millisecond)
		for {
			select {
			case <-done:
				cl.finish(code, "")
				return
			case <-time.After(10 * time.Millisecond):
			}
			delivered := true
			for i, r := range pipes {
				delivered = delivered && (read[i].Load() >= want[i] || buffered(r) == 0)
			}
			late := time.Now().After(grace)
			if delivered && late {
				outR.SetReadDeadline(time.Now())
				errR.SetReadDeadline(time.Now())
				hook(&afterDrainCheck, true)
				<-done
				cl.finish(code, "")
				return
			}
			hook(&afterDrainCheck, late)
		}
	}()
	return nil
}

// leftOutput is how much execd takes of what a process left running writes to its command's pipe.
const leftOutput = 1 << 20

// held bounds the kept pipes to half of execd's descriptors, and to what leaves it 24: its own nine, and a command's start beside one that runs.
var held = func() chan struct{} {
	var files syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &files) != nil {
		files.Cur = 0 // a limit execd cannot read: it keeps no pipe
	}
	return make(chan struct{}, min(files.Cur/2, max(files.Cur, 24)-24))
}()

// keep hands the pipe to the keeper, out of the runtime's own poller, which a pipe wakes at every write to it.
func keep(r *os.File, keeper int, places chan struct{}) {
	fd := -1
	if rc, err := r.SyscallConn(); err == nil {
		rc.Control(func(pipe uintptr) {
			if dup, _, errno := syscall.Syscall(syscall.SYS_FCNTL, pipe, syscall.F_DUPFD_CLOEXEC, 0); errno == 0 {
				fd = int(dup)
			}
		})
	}
	r.Close()
	if syscall.EpollCtl(keeper, syscall.EPOLL_CTL_ADD, fd, &syscall.EpollEvent{Events: syscall.EPOLLIN, Fd: int32(fd)}) != nil {
		syscall.Close(fd) // no descriptor for it, or no keeper: let go
		<-places
	}
}

// keeper is the epoll in which the kept pipes wait: for execd to take leftOutput bytes of each, and then for its writers to go.
var keeper = -1

// startKeeper starts the keeper's thread at execd's start: a pod out of PIDs can start none.
var startKeeper = sync.OnceFunc(func() {
	ep, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		return
	}
	keeper = ep
	go func() {
		taken := map[int32]int{} // what execd has read of each pipe, and dropped
		var events [64]syscall.EpollEvent
		var dropped [4096]byte
		for {
			// The call the runtime's poller makes, and as there: one a signal cut short is made again, and one refused ends execd.
			n, _, errno := syscall.Syscall6(syscall.SYS_EPOLL_PWAIT, uintptr(ep), uintptr(unsafe.Pointer(&events)), uintptr(len(events)), ^uintptr(0), 0, 0)
			if errno != 0 && errno != syscall.EINTR {
				fail("epoll_pwait: " + errno.Error())
			}
			read := false
			for _, e := range events[:max(int(n), 0)] {
				fd, gone := e.Fd, e.Events&(syscall.EPOLLHUP|syscall.EPOLLERR) != 0
				for taken[fd] < leftOutput {
					got, err := syscall.Read(int(fd), dropped[:min(leftOutput-taken[fd], len(dropped))])
					if got <= 0 {
						gone = err != syscall.EAGAIN && err != syscall.EINTR // read to its end, it has no writer
						break
					}
					taken[fd], read = taken[fd]+got, true
				}
				if taken[fd] >= leftOutput {
					// Asked for no event, an epoll tells only that every writer has gone. A pipe that cannot be asked so is let go.
					gone = gone || syscall.EpollCtl(ep, syscall.EPOLL_CTL_MOD, int(fd), &syscall.EpollEvent{Fd: fd}) != nil
					hook(&afterTaken, false)
				}
				if gone {
					// Left in the epoll, a pipe closed here is told of again while a child not yet exec'd holds it, and gives back a place each time.
					if err := syscall.EpollCtl(ep, syscall.EPOLL_CTL_DEL, int(fd), nil); err != nil {
						fail("epoll_ctl: " + err.Error())
					}
					syscall.Close(int(fd))
					delete(taken, fd)
					<-held
				}
			}
			if read {
				time.Sleep(time.Millisecond) // what is written meanwhile takes one wake, not one for each write
			}
		}
	}()
})

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

func (cl *call) writeStdin(c *conn, data []byte) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.sub != c || cl.stdinEOF || cl.exited { // a dropped connection's: its RESUME counted what came
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
		cl.stdinQ[0] = nil // or the queue's array keeps what the command has read
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

// Unacked output per stdout or stderr before reading waits; a stream's reader takes it as needed.
const maxUnacked, streamUnacked = 4 << 20, 1 << 20

// fifo is a stream's unacked output, kept in a ring: an ack frees its front without a copy.
type fifo struct {
	buf     []byte
	head, n int // where its first byte is in buf, and how many it holds
}

func (f *fifo) Len() int { return f.n }

// Write adds data; most is all the fifo will be asked to hold, and it doubles no further.
func (f *fifo) Write(data []byte, most int) {
	if need := f.n + len(data); need > len(f.buf) {
		grown := make([]byte, max(need, min(2*len(f.buf), most)))
		k := copy(grown, f.buf[f.head:min(f.head+f.n, len(f.buf))])
		copy(grown[k:], f.buf[:f.n-k])
		f.buf, f.head = grown, 0
	}
	tail := (f.head + f.n) % len(f.buf)
	copy(f.buf, data[copy(f.buf[tail:], data):])
	f.n += len(data)
}

// Next drops the first n bytes.
func (f *fifo) Next(n int) {
	if n > 0 {
		f.head, f.n = (f.head+n)%len(f.buf), f.n-n
	}
}

// span is the n bytes from offset off: a copy where they pass the ring's end.
func (f *fifo) span(off, n int) []byte {
	start := (f.head + off) % len(f.buf)
	if start+n <= len(f.buf) {
		return f.buf[start : start+n]
	}
	return append(append(make([]byte, 0, n), f.buf[start:]...), f.buf[:start+n-len(f.buf)]...)
}

func (cl *call) output(stream int, data []byte) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	limit := maxUnacked
	if cl.stream {
		limit = streamUnacked
	}
	for cl.out[stream].Len() > limit && !cl.gone {
		cl.room.Wait()
	}
	if cl.gone {
		return
	}
	cl.out[stream].Write(data, limit+len(data))
	cl.flushSoon()
}

// When the next call may send output: calls take turns, to keep within the client's frame pace.
var slot atomic.Int64

var epoch = time.Now() // turns are measured from here, on the monotonic clock

const slotEvery, slotBurst = 600 * time.Microsecond, 8

const slotAhead = slotBurst * slotEvery // how long exits' and resumes' turns may hold others' output

// flushSoon sends a call's output at most once a millisecond, and any call's once a slot past a burst.
func (cl *call) flushSoon() {
	if cl.deferred || cl.sub == nil {
		return // the waiting flush sends this too, or the resume does
	}
	now := time.Now()
	at := now.Sub(epoch)
	if !cl.flushed.IsZero() {
		at = max(at, cl.flushed.Add(time.Millisecond).Sub(epoch))
	}
	for {
		taken := time.Duration(slot.Load())
		send := max(at, taken-slotBurst*slotEvery)
		if slot.CompareAndSwap(int64(taken), int64(max(taken, send)+slotEvery)) {
			at = send
			break
		}
	}
	wait := at - now.Sub(epoch)
	if wait <= 0 {
		cl.flushed = now
		cl.flush()
		return
	}
	cl.deferred = true
	time.AfterFunc(wait, func() {
		cl.mu.Lock()
		defer cl.mu.Unlock()
		cl.deferred = false
		if !cl.gone && !cl.exited { // finish flushed it all, with the exit
			cl.flushed = time.Now()
			cl.flush()
		}
	})
}

// charge takes the turns of frames a flush sent without one: an exit's, or a resume's.
func charge(frames int) {
	for frames > 0 {
		taken, now := time.Duration(slot.Load()), time.Since(epoch)
		next := min(max(taken, now)+time.Duration(frames)*slotEvery, now+slotAhead)
		if next <= taken || slot.CompareAndSwap(int64(taken), int64(next)) {
			return
		}
	}
}

func (cl *call) ack(req resumeRequest) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.ackLocked(req)
}

// ackLocked forgets output the client confirmed it has.
func (cl *call) ackLocked(req resumeRequest) {
	for i, upto := range []int{req.Stdout, req.Stderr} {
		n := min(max(upto-cl.base[i], 0), cl.out[i].Len())
		cl.out[i].Next(n)
		cl.base[i] += n
		cl.sent[i] = max(cl.sent[i], cl.base[i])
	}
	cl.room.Broadcast()
}

// signalLine is dash's line on stderr for a command a signal ended, in glibc's words: here execd is the command's parent, not a shell.
func signalLine(ws syscall.WaitStatus) string {
	sig := ws.Signal()
	if !ws.Signaled() || sig == syscall.SIGINT || sig == syscall.SIGPIPE {
		return ""
	}
	said := strings.ToUpper(sig.String()[:1]) + sig.String()[1:]
	switch { // Go names 1 to 31 as glibc does, and no other
	case sig > 33:
		said = "Real-time signal " + strconv.Itoa(int(sig)-34)
	case sig > 31:
		said = "Unknown signal " + strconv.Itoa(int(sig))
	}
	if ws.CoreDump() {
		said += " (core dumped)"
	}
	return said + "\n"
}

// kill ends the call's process group, what descends from its command, and every process still carrying its tag: with SIGTERM, and with SIGKILL those that termGrace later have not ended.
func (cl *call) kill() { cl.stop(false) }

// stop is kill; a timeout's notes that the command was running, so only then does the exit say "timed out".
func (cl *call) stop(timeout bool) {
	cl.kmu.Lock()
	cl.killed = true
	pid, as, status := cl.pid, cl.as, cl.status
	cl.kmu.Unlock()
	refused := false // waitid, as a seccomp profile can: nothing then says the command has stopped, and a kill does not wait to hear it
	seen := func(states int) bool {
		var info [128]byte // a siginfo_t: waitid sets its first field for a child in one of the states, and leaves it unreaped
		_, _, errno := syscall.Syscall6(syscall.SYS_WAITID, 1, uintptr(pid), uintptr(unsafe.Pointer(&info)), uintptr(states|syscall.WNOHANG|syscall.WNOWAIT), 0, 0)
		refused = errno != 0
		return info[0] != 0
	}
	// Not started, or ended and not yet reaped: what it left running is not the call's to kill.
	if pid <= 0 || seen(syscall.WEXITED) {
		return
	}
	reaper.mu.Lock()     // nothing is reaped meanwhile: an id the reaper still holds for the command is its own
	its := func() bool { // and no earlier kill is at it: a second SIGTERM would cut short what the first began
		cl.kmu.Lock()
		defer cl.kmu.Unlock()
		return cl.ending == nil && reaper.waiting[pid] == status
	}
	running, up, sig := its(), make(chan struct{}), syscall.SIGTERM
	if running {
		hook(&beforeKill, false)
		began := time.Now()
		if syscall.Kill(pid, syscall.SIGSTOP) == nil || signalAs(as, pid, syscall.SIGSTOP) { // stopped, it cannot end by itself between the look that follows and its kill
			// Unlocked for the wait: other commands start, end and are killed meanwhile.
			reaper.mu.Unlock()
			told := make(chan os.Signal, 1)
			signal.Notify(told, syscall.SIGCHLD) // told of the stop at once: a timer alone comes a millisecond late
			// In its exit it takes no stop: that is waited for, a second at most.
			for until := time.Now().Add(time.Second); !seen(syscall.WEXITED|syscall.WSTOPPED) && !refused && time.Now().Before(until); {
				select {
				case <-told:
				case <-time.After(time.Millisecond):
				}
			}
			signal.Stop(told)
			reaper.mu.Lock()
		}
		if time.Since(began) > termGrace/10 { // too loaded to stop in a tenth of the grace, it gets none: the SIGKILL of old, at once
			sig = syscall.SIGKILL
		}
		running = its() && !seen(syscall.WEXITED) // reaped meanwhile, its id may be another's
	}
	var reached, listed map[int]string
	var group uintptr
	if running {
		hook(&beforeKill, true)
		cl.kmu.Lock()
		cl.timeoutKilled = cl.timeoutKilled || timeout
		cl.ending = make(chan struct{})
		cl.kmu.Unlock()
		group, _, _ = syscall.Syscall(434, uintptr(pid), 0, 0) // pidfd_open, while its id is its own: what it leaves in its group is signalled through this
		afterFunc(termGrace, func() { close(up) })             // from here, not from the SIGTERMs: a kill slow to list a loaded pod's processes ends no later for it
		reached, listed, sig = signalTree(as, pid, []int{pid}, sig, syscall.SIGCONT)
	}
	reaper.mu.Unlock()
	if running { // else ended or reaped: what it left running is not the call's to kill, and its id may be another's
		found := make(chan hits, 1)
		go cl.sweep(pid, as, status, reached, found, up, group)
		// Only what was listed, started since the command and had no SIGTERM may carry its tag and take one: no other's environment is read.
		since, _ := strconv.ParseUint(listed[pid], 10, 64)
		maps.DeleteFunc(listed, func(p int, started string) bool {
			at, _ := strconv.ParseUint(started, 10, 64)
			return reached[p] != "" || at < since
		})
		var sent hits
		if len(listed) > 0 { // else none it could signal: no search, whose own listing a loaded pod takes seconds over
			sent = cl.search(as, sig, listed)
		}
		found <- sent
	}
}

// sweep gives what a kill's SIGTERM reached its grace to end, then SIGKILL to what has not, and to what they left in the command's group or carrying its tag: the call's exit waits for it.
func (cl *call) sweep(pid int, as *syscall.Credential, status chan syscall.WaitStatus, reached map[int]string, found <-chan hits, up <-chan struct{}, group uintptr) {
	defer close(cl.ending)
	defer syscall.Close(int(group))
	defer func() { go cl.search(as, syscall.SIGKILL, nil) }() // off the exit's path: each read of an environment may wait behind its process's memory
	left := func() bool {                                     // the command, or a process a SIGTERM reached: what they start has none, and no grace
		reaper.mu.Lock()
		running := reaper.waiting[pid] == status
		reaper.mu.Unlock()
		for p, started := range reached {
			if !ended(p, started) {
				return true
			}
		}
		return running
	}
	helper := 0
	select { // no look at what is left before the search's word: what it signalled is waited for too, and killed with the rest
	case t := <-found:
		maps.Copy(reached, t.sent)
		helper = t.helper
	case <-up:
	}
	for wait, over := time.Millisecond, false; !over && left(); wait = min(2*wait, 100*time.Millisecond) {
		select {
		case <-up:
			over = true
		case <-time.After(wait):
		}
	}
	reaper.mu.Lock() // nothing is reaped meanwhile: a helper that has not ended still has its id
	if helper != 0 && !ended(helper, reached[helper]) && syscall.Kill(helper, syscall.SIGTERM) != nil {
		signalAs(as, helper, syscall.SIGTERM)
	}
	reaper.mu.Unlock()
	// At its SIGTERM the helper kills what it signalled, as their user, by their ids: it has a second for it.
	for until := time.Now().Add(time.Second); helper != 0 && !ended(helper, reached[helper]) && time.Now().Before(until); {
		time.Sleep(time.Millisecond)
	}
	reaper.mu.Lock() // nothing is reaped meanwhile: an id the reaper still holds for the command is its own, and so is its group's
	// Each process a SIGTERM reached is killed while it is still the one that started then, with what it has started since.
	var survivors []int
	for p, started := range reached {
		if p != pid && !ended(p, started) {
			survivors = append(survivors, p)
		}
	}
	lead := 0
	if reaper.waiting[pid] == status {
		lead, survivors = pid, append(survivors, pid)
	}
	if len(survivors) > 0 {
		signalTree(as, lead, survivors, syscall.SIGKILL)
	}
	// By its pidfd, what a reaped command left in its group: the number may be another group's by now. shortcut: gVisor and kernels before 6.9 signal no group so, and there it runs on unless it carries the tag.
	if _, _, err := syscall.Syscall6(424, group, uintptr(syscall.SIGKILL), 0, 4, 0, 0); err == syscall.EPERM {
		signalAs(as, -pid, syscall.SIGKILL) // another user's, which root may not signal without CAP_KILL: the group refused is still that one
	}
	reaper.mu.Unlock()
}

// signalAs sends another user's process, or its group, that user's own signal, and says whether it was sent: root's reaches neither without CAP_KILL.
func signalAs(as *syscall.Credential, target int, sig syscall.Signal) bool {
	if as == nil {
		return false
	}
	runtime.LockOSThread() // the identity it takes is this thread's alone
	defer runtime.UnlockOSThread()
	setids(as.Uid, as.Gid)
	sent := syscall.Kill(target, sig) == nil
	setids(uint32(os.Getuid()), uint32(os.Getgid()))
	if os.Geteuid() != os.Getuid() || os.Getegid() != os.Getgid() { // unlocked so, the thread would do execd's own work as that user
		fail("a thread could not take execd's identity back")
	}
	return sent
}

// stat is /proc/PID/stat after the name, which may hold spaces and parentheses: the state, the parent, and 20th the start time.
func stat(pid int) []string {
	data, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	return strings.Fields(string(data[bytes.LastIndexByte(data, ')')+1:]))
}

// signalTree stops lead's group, if any, and what runs under roots, sends them sigs in turn, and gives those reached, all listed and the first signal sent: stopped, each takes one SIGTERM however many reach it.
func signalTree(as *syscall.Credential, lead int, roots []int, sigs ...syscall.Signal) (reached, listed map[int]string, sent syscall.Signal) {
	began := time.Now()
	for _, target := range append([]int{-lead}, roots...) { // the group at once: stopped, a process starts no other, and its children stay its own; the command by its own id too: it may have left its group for another
		if target != 0 {
			syscall.Kill(target, syscall.SIGSTOP)
		}
	}
	var stopped []int
	seen, waits := map[int]bool{}, 0
	reached = map[int]string{}
	// Eight listings at most: a command that starts them faster than they are listed would hold every start and exit.
	for pass, more := 0, true; more && pass < 8; pass++ {
		more = false
		children, started := map[int][]int{}, map[int]string{}
		entries, _ := os.ReadDir("/proc")
		for _, e := range entries {
			p, _ := strconv.Atoi(e.Name())
			if f := stat(p); len(f) > 19 {
				ppid, _ := strconv.Atoi(f[1])
				children[ppid], started[p] = append(children[ppid], p), f[19]
				if slices.Contains(roots, p) || lead != 0 && f[2] == strconv.Itoa(lead) { // in the command's group: its signals are the group's
					reached[p] = f[19]
				}
			}
		}
		listed = started
		first := len(stopped)
		var queue []int
		for _, root := range roots {
			queue = append(queue, children[root]...)
		}
		for ; len(queue) > 0; queue = queue[1:] {
			p := queue[0]
			queue = append(queue, children[p]...)
			delete(children, p) // taken once: an id given again while they were read could close a loop
			if !seen[p] && signalIf(p, started[p], syscall.SIGSTOP) {
				stopped, seen[p], more = append(stopped, p), true, true
				reached[p] = started[p]
			}
		}
		for _, p := range stopped[first:] { // one signalled while it starts a process still starts it: listed again once it has
			for ; waits < 1000 && stopping(p); waits++ {
				time.Sleep(time.Millisecond) // a thousand in all: one given no processor to stop on must not hold the rest
			}
		}
	}
	if time.Since(began) > max(termGrace/10, time.Duration(len(listed))*10*time.Millisecond) { // as a kill too slow to stop its command: one too slow to stop and list the rest, or over 10 ms each, gives no grace
		sigs = []syscall.Signal{syscall.SIGKILL}
	}
	for _, sig := range sigs {
		// Each before its parent: a parent that ended first would leave one still stopped, in a group of its own, to the kernel's SIGHUP for an orphaned group.
		for _, p := range slices.Backward(stopped) { // shortcut: stopped, each keeps its id unless something else kills it now; signal as signalIf does if that can matter
			syscall.Kill(p, sig)
		}
		for _, target := range append([]int{-lead}, roots...) { // as its user too: root's signal reaches neither without CAP_KILL
			if target != 0 {
				syscall.Kill(target, sig)
				signalAs(as, target, sig)
			}
		}
	}
	return reached, listed, sigs[0]
}

// stopping reports whether a thread of pid still runs or sleeps: any of them may be the one starting a process.
func stopping(pid int) bool {
	threads, _ := os.ReadDir("/proc/" + strconv.Itoa(pid) + "/task")
	for _, t := range threads {
		tid, _ := strconv.Atoi(t.Name())
		if f := stat(tid); len(f) > 0 && strings.Contains("RS", f[0]) {
			return true
		}
	}
	return false
}

// signalIf signals process pid if it is still the one that started then: its id may be another's by now.
func signalIf(pid int, started string, sig syscall.Signal) bool {
	handle, _ := os.FindProcess(pid)
	defer handle.Release()
	if f := stat(pid); len(f) <= 19 || f[19] != started {
		return false
	}
	return handle.Signal(sig) == nil
}

// ended says the process pid that started then is no more.
func ended(pid int, started string) bool {
	if f := stat(pid); len(f) > 19 {
		return f[19] != started
	}
	_, err := os.Stat("/proc/" + strconv.Itoa(pid)) // one execd cannot read of, out of descriptors or memory, has not ended
	return errors.Is(err, os.ErrNotExist)
}

// hits is what a search by tag signalled, and its helper, which holds another user's: it runs until they have ended, and kills them at its SIGTERM.
type hits struct {
	sent   map[int]string
	helper int
}

// search signals whatever carries the call's tag, as signalTagged does: as execd, and for another user's command as that user.
func (cl *call) search(as *syscall.Credential, sig syscall.Signal, among map[int]string) (found hits) {
	found.sent = signalTagged(cl.tag, sig, among)
	if as == nil {
		return found
	}
	// Without CAP_SYS_PTRACE only the command's user may read its processes' environments.
	if sig == syscall.SIGKILL { // a pod out of PIDs starts no child: what is left is killed at least
		go func() { searches <- search{cl.tag, as} }()
	}
	// gVisor lets them be read only with the user's real ids, which let the user signal their holder: a child holds them, not execd.
	argv := []string{"/proc/self/exe", "search", fmt.Sprint(as.Uid), fmt.Sprint(as.Gid), strings.Trim(fmt.Sprint(as.Groups), "[]"), cl.tag, strconv.Itoa(int(sig))}
	var rest []string
	for p, started := range among { // with its start time: an id given again since is another process's
		if _, did := found.sent[p]; !did { // execd's own search signalled it, where it may read another user's processes: one SIGTERM each
			rest = append(rest, strconv.Itoa(p)+":"+started)
		}
	}
	if among != nil && rest == nil {
		return found // none is left for the helper, which signals every process when given none
	}
	argv = append(argv, rest...)
	reaper.mu.Lock() // nothing is reaped meanwhile: the id read is the helper's own
	if child, err := os.StartProcess(argv[0], argv, &os.ProcAttr{Env: []string{"GOMAXPROCS=1"}}); err == nil {
		if f := stat(child.Pid); len(f) > 19 {
			found.sent[child.Pid], found.helper = f[19], child.Pid
		}
		child.Release()
	}
	reaper.mu.Unlock()
	return found
}

type search struct {
	tag string
	as  *syscall.Credential
}

var searches = make(chan search)

// startSearcher starts the searching thread at execd's start: a pod out of PIDs can start none.
var startSearcher = sync.OnceFunc(func() {
	go func() {
		runtime.LockOSThread() // the identities it takes are this thread's alone
		for s := range searches {
			setids(s.as.Uid, s.as.Gid) // its kills are then the user's own: root may lack CAP_KILL
			signalTagged(s.tag, syscall.SIGKILL, nil)
			setids(uint32(os.Getuid()), uint32(os.Getgid()))
		}
	}()
})

// setids gives this thread an effective identity; its real and saved ones stay, to come back to.
func setids(uid, gid uint32) {
	keep := ^uintptr(0)
	if uid != 0 { // the group first while still root, and root first on the way back
		syscall.RawSyscall(syscall.SYS_SETRESGID, keep, uintptr(gid), keep)
	}
	syscall.RawSyscall(syscall.SYS_SETRESUID, keep, uintptr(uid), keep)
	if uid == 0 {
		syscall.RawSyscall(syscall.SYS_SETRESGID, keep, uintptr(gid), keep)
	}
	undumpable() // a change of identity resets it, for the whole process
}

func (cl *call) finish(code int, startErr string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.exited, cl.code, cl.startErr = true, code, startErr
	cl.room.Broadcast()
	if cl.deferred { // the turn its waiting flush took goes unused: this flush sends its output
		slot.Add(-int64(slotEvery))
	}
	charge(cl.flush())
}

// flush sends what the subscriber hasn't seen, then the exit; holding cl.mu keeps them in order.
func (cl *call) flush() (frames int) {
	if cl.sub == nil {
		return 0
	}
	for i, kind := range []byte{fStdout, fStderr} {
		end := cl.base[i] + cl.out[i].Len()
		for cl.sent[i] < end {
			next := min(end, cl.sent[i]+1<<20)
			cl.sub.send(kind, cl.id, cl.out[i].span(cl.sent[i]-cl.base[i], next-cl.sent[i]))
			cl.sent[i] = next
			frames++
		}
	}
	if cl.exited {
		b, _ := json.Marshal(struct {
			Code    int    `json:"code"`
			Error   string `json:"error,omitempty"`
			Timeout bool   `json:"timeout,omitempty"`
		}{cl.code, cl.startErr, cl.timedOut})
		cl.sub.send(fExit, cl.id, b)
		frames++
	}
	return frames
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
	if _, given := extra["PATH"]; !given {
		if _, inherited := os.LookupEnv("PATH"); !inherited { // else bash's own ends in the working directory
			env = append(env, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
		}
	}
	return env
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
			if name != "0" && name != strconv.Itoa(os.Getuid()) { // as runuser refuses a user with no entry
				return nil, "", "", fmt.Errorf("unknown user %s", name)
			}
			u = &user.User{Uid: name, Gid: name, Username: name, HomeDir: "/"}
		}
	} else if u, err = user.Lookup(name); err != nil {
		return nil, "", "", fmt.Errorf("unknown user %s", name)
	}
	uid, uidErr := strconv.ParseInt(u.Uid, 10, 64)
	if uidErr == nil && uid == int64(os.Getuid()) {
		return nil, u.HomeDir, u.Username, nil
	}
	gid, gidErr := strconv.ParseInt(u.Gid, 10, 64)
	if uidErr != nil || gidErr != nil || uid>>32 != 0 || gid>>32 != 0 { // narrowed to 32 bits, 4294967296 would be root's
		return nil, "", "", fmt.Errorf("unknown user %s", name)
	}
	if os.Getuid() != 0 {
		return nil, "", "", fmt.Errorf("cannot run as %s: execd is not root", name)
	}
	var groups []uint32
	if ids, err := u.GroupIds(); err == nil {
		for _, g := range ids {
			if n, err := strconv.ParseInt(g, 10, 64); err == nil && n>>32 == 0 && n != 1<<32-1 { // setgroups refuses the whole list for (gid_t)-1
				groups = append(groups, uint32(n))
			}
		}
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}, u.HomeDir, u.Username, nil
}

// More than execve lets an environment hold (6 MiB at most).
const maxEnviron = 8 << 20

// Tests open another file in an environment's place for the search of a tag.
var openEnviron atomic.Pointer[func(tag, environ string) (*os.File, error)]

// tagged says whether the environment that open shows of a /proc/PID/environ file holds needle, and whether it shows none at all.
func tagged(open func(string) (*os.File, error), environ string, needle []byte, room *[]byte) (is, none bool) {
	// In one read: an execve between two lets the environment go, and the second ends the file short of its tag.
	for {
		f, err := open(environ)
		if err != nil {
			return false, false
		}
		data := *room
		n, _ := f.Read(data)
		f.Close()
		// A read it fills may not hold it all: a process can make its own look any size.
		whole := n < len(data) || len(data) == maxEnviron
		is = bytes.Contains(data[:n], needle)
		if is || whole { // a tag it shows is enough: the next open may fail
			return is, n == 0
		}
		*room = make([]byte, min(4*len(data), maxEnviron)) // kept for the search's later reads: each open more is one an execve can empty
	}
}

// signalTagged signals every process whose environment holds HAWK_NEXT_EXEC=<tag>, even after setsid: only those among, if that is given.
func signalTagged(tag string, sig syscall.Signal, among map[int]string) (sent map[int]string) {
	sent = map[int]string{}
	needle := []byte("HAWK_NEXT_EXEC=" + tag + "\x00")
	open := os.Open
	if stand := openEnviron.Load(); stand != nil {
		open = func(environ string) (*os.File, error) { return (*stand)(tag, environ) }
	}
	read, room := map[int]bool{}, make([]byte, 4<<10)
	// Eight listings at most, until one holds no process not yet read: what a process starts while one is read is in the next.
	for pass, more, starting := 0, true, false; more && pass < 8; pass++ {
		if starting {
			time.Sleep(time.Millisecond) // an execve takes about a tenth of that
		}
		more, starting = false, false
		entries, _ := os.ReadDir("/proc")
		for _, e := range entries {
			pid, err := strconv.Atoi(e.Name())
			if err != nil || pid == os.Getpid() || read[pid] {
				continue
			}
			if _, listed := among[pid]; among != nil && !listed { // none of the search's to signal: its environment, which may wait behind its memory, is not read
				read[pid] = true
				continue
			}
			more = true
			is, none := tagged(open, "/proc/"+e.Name()+"/environ", needle, &room)
			if none {
				if f := stat(pid); len(f) > 0 && f[0] != "Z" { // its execve may be under way, its environment not yet in place: read again
					starting = true
					continue
				}
			}
			read[pid] = true
			if is && syscall.Kill(pid, sig) == nil { // one execd may not signal is its helper's, as its user
				syscall.Kill(pid, syscall.SIGCONT) // as timeout(1) sends it: stopped, it would take no SIGTERM
				sent[pid] = among[pid]
			}
		}
	}
	return sent
}

// The reaper reaps every child under mu, so an id is never reused before its status is sent.
type reaperState struct {
	mu      sync.Mutex
	waiting map[int]chan syscall.WaitStatus
}

var reaper = &reaperState{waiting: map[int]chan syscall.WaitStatus{}}

// watch must be called with mu held.
func (r *reaperState) watch(pid int) chan syscall.WaitStatus {
	ch := make(chan syscall.WaitStatus, 1)
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
				reaper.mu.Lock()
				pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
				if pid <= 0 || err != nil {
					reaper.mu.Unlock()
					break
				}
				if ch, ok := reaper.waiting[pid]; ok {
					delete(reaper.waiting, pid)
					ch <- ws
				}
				reaper.mu.Unlock()
			}
		}
	}()
}
