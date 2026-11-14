package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"os/user"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

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

var afterFunc = time.AfterFunc // tests fire the abandon timers themselves, and stand in for a call's deadline

var workdir, _ = os.Getwd() // where execd started, and so does a command given no cwd

// Tests hold a reader here with output taken but not counted, and an exit that has checked its pipes.
var afterRead, afterDrainCheck atomic.Pointer[func(late bool)]

func hook(h *atomic.Pointer[func(late bool)], late bool) {
	if f := h.Load(); f != nil {
		(*f)(late)
	}
}

// Bounds on unauthenticated connections: time, AUTH payload, and how many at once.
const authTimeout, maxKey, maxPreauth = 10 * time.Second, 64, 32

type call struct {
	id  uint64
	tag string
	kmu sync.Mutex // guards pid, status, as, killed and timeoutKilled: a kill must not wait for mu
	pid int
	// where the reaper sends its command's exit status
	status chan int
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
	timedOut  bool // its timeout killed it: its exit says so, as the code alone can't
	// its timeout found it running and signalled it
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
		if fromThisPod(nc) { // the client dials from another pod: here, only the sandbox would
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
	addrs, _ := net.InterfaceAddrs()
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
		cl.gone, cl.out = true, [2]fifo{}
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
	s.mu.Lock()
	replaced := s.current != nil && s.current != c // the call is the new connection's to resume
	s.mu.Unlock()
	if replaced {
		return
	}
	if cl.abandoned {
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
	// By its path, as Kubernetes exec does; a user who cannot enter it that way stays in it.
	if err := os.Chdir(workdir); err != nil && !errors.Is(err, syscall.EACCES) && !strings.HasPrefix(req.Cwd, "/") {
		return fmt.Errorf("cd: %s: %w", workdir, errors.Unwrap(err))
	}
	if req.Cwd != "" { // a directory this user can enter: else it is the cd that fails, not the command
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
		syscall.Kill(-p.Pid, syscall.SIGKILL)
	}
	reaper.mu.Unlock()
	if killed { // that holds for what it left running too
		cl.end(as)
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
			defer r.Close()
			buf := make([]byte, 256<<10)
			for {
				n, err := r.Read(buf)
				if n > 0 {
					hook(&afterRead, false)
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
		if stdinW != nil {
			stdinW.Close() // or its writer waits for ever on what the command left holding its stdin
		}
		if deadline != nil {
			deadline.Stop()
		}
		cl.kmu.Lock()
		cl.pid = 0 // reaped: its id may now be another group's
		byTimeout := cl.timeoutKilled
		cl.kmu.Unlock()
		cl.mu.Lock()
		cl.timedOut = byTimeout && code == 128+int(syscall.SIGKILL)
		cl.mu.Unlock()
		// Deliver all output written before exit; stop 100 ms on, so a background child can't hold the call.
		var want [2]int64
		for i, r := range pipes {
			want[i] = buffered(r)               // before the count, so want can't fall short
			want[i] += read[i].Load() + 256<<10 // a read under way has taken bytes it hasn't counted
		}
		done := make(chan struct{})
		go func() { drained.Wait(); close(done) }()
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

// kill stops the call's process group, and every process still carrying its tag.
func (cl *call) kill() { cl.stop(false) }

// stop is kill; a timeout's notes that the command was running, so only then does the exit say "timed out".
func (cl *call) stop(timeout bool) {
	cl.kmu.Lock()
	cl.killed = true
	pid, as, status := cl.pid, cl.as, cl.status
	cl.kmu.Unlock()
	var ended [128]byte // a siginfo_t: waitid sets its first field for a child exited and not yet reaped
	syscall.Syscall6(syscall.SYS_WAITID, 1, uintptr(pid), uintptr(unsafe.Pointer(&ended)), syscall.WEXITED|syscall.WNOHANG|syscall.WNOWAIT, 0, 0)
	// Not started, or ended and not yet reaped: what it left running is not the call's to kill.
	if pid <= 0 || ended[0] != 0 {
		return
	}
	reaper.mu.Lock() // nothing is reaped meanwhile: an id the reaper still holds for the command is its own
	running := reaper.waiting[pid] == status
	if running {
		cl.kmu.Lock()
		cl.timeoutKilled = cl.timeoutKilled || timeout
		cl.kmu.Unlock()
		syscall.Kill(-pid, syscall.SIGKILL)
	}
	reaper.mu.Unlock()
	if running { // else reaped: what it left running is not the call's to kill, and its id may be another's
		cl.end(as)
	}
}

// end kills whatever carries the call's tag.
func (cl *call) end(as *syscall.Credential) {
	killTagged(cl.tag)
	if as != nil { // without CAP_SYS_PTRACE only the command's user may read its processes' environments
		go func() { searches <- search{cl.tag, as} }()
	}
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
			setfs(s.as.Uid, s.as.Gid)
			killTagged(s.tag)
			setfs(uint32(os.Geteuid()), uint32(os.Getegid()))
		}
	}()
})

// setfs gives this thread a filesystem identity, which is what opening /proc/PID/environ checks.
func setfs(uid, gid uint32) {
	syscall.RawSyscall(syscall.SYS_SETFSGID, uintptr(gid), 0, 0)
	syscall.RawSyscall(syscall.SYS_SETFSUID, uintptr(uid), 0, 0)
	prctl(prSetDumpable, 0) // a change of identity resets it, for the whole process
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

// More than execve lets an environment hold (6 MiB).
const maxEnviron = 8 << 20

// tagged says whether the environment a /proc/PID/environ file shows holds needle.
func tagged(environ string, needle []byte) bool {
	f, err := os.Open(environ)
	if err != nil {
		return false
	}
	defer f.Close()
	data, _ := io.ReadAll(io.LimitReader(f, maxEnviron)) // a process can make its own look any size
	return bytes.Contains(append(data, 0), needle)
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
		if tagged("/proc/"+e.Name()+"/environ", needle) {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

// The reaper reaps every child under mu, so an id is never reused before its status is sent.
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
				reaper.mu.Lock()
				pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
				if pid <= 0 || err != nil {
					reaper.mu.Unlock()
					break
				}
				code := ws.ExitStatus()
				if ws.Signaled() {
					code = 128 + int(ws.Signal())
				}
				if ch, ok := reaper.waiting[pid]; ok {
					delete(reaper.waiting, pid)
					ch <- code
				}
				reaper.mu.Unlock()
			}
		}
	}()
}
