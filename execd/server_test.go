package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
	"unsafe"
	"weak"
)

// run() starts this binary, as it starts execd, to become another user.
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "first" {
		firstProcess(os.Args[2:])
		return
	}
	if len(os.Args) > 2 && os.Args[1] == "refused" {
		refused(os.Args[2])
		return
	}
	if len(os.Args) > 2 && os.Args[1] == "leave" { // runs the rest as a command that left its group for its parent's, and its environment
		group, _ := syscall.Getpgid(os.Getppid())
		syscall.Setpgid(0, group)
		os.Stdout.WriteString(strconv.Itoa(os.Getpid()) + "\n")
		syscall.Exec(os.Args[2], os.Args[2:], nil)
		os.Exit(1) // not on into the tests, as the command
	}
	if len(os.Args) > 6 && os.Args[1] == "as" || len(os.Args) > 1 && (os.Args[1] == "listen" || os.Args[1] == "serve" || os.Args[1] == "connect" || os.Args[1] == "search") {
		main()
		return
	}
	startReaper()
	startSearcher()
	startKeeper()
	os.Exit(m.Run())
}

func testConn(t *testing.T) *conn {
	a, b := net.Pipe()
	go io.Copy(io.Discard, b) //nolint:errcheck // drains what the server sends
	t.Cleanup(func() { a.Close(); b.Close() })
	return &conn{nc: a, dead: make(chan struct{})}
}

func TestOnlyTheKeysHolderIsServed(t *testing.T) {
	key, long := []byte("the session key"), bytes.Repeat([]byte("k"), maxKey+1)
	for _, tc := range []struct {
		name      string
		key, sent []byte
		served    bool
	}{
		{"the key", key, key, true},
		{"another key", key, []byte("another key"), false},
		{"a key past the bound on what is read before AUTH", long, long, false},
	} {
		sum := sha256.Sum256(tc.key)
		s, _ := newServer(hex.EncodeToString(sum[:]))
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		s.preauth <- struct{}{} // as serve() takes a slot for it
		go s.handle(&conn{nc: a, dead: make(chan struct{})})
		go b.Write(encodeFrame(fAuth, 0, tc.sent)) //nolint:errcheck // a refused peer's write fails
		b.SetReadDeadline(time.Now().Add(30 * time.Second))

		f, err := readFrameMax(b, maxPayload)

		if served := err == nil && f.kind == fOK; served != tc.served {
			t.Errorf("%s: served %v, want %v", tc.name, served, tc.served)
		}
	}
}

func TestAConnectionFromThePodItselfIsRefused(t *testing.T) {
	key := []byte("the session key")
	sum := sha256.Sum256(key)
	s, _ := newServer(hex.EncodeToString(sum[:]))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.serve(l) // left listening: serve has no end
	nc, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	nc.Write(encodeFrame(fAuth, 0, key))
	nc.SetReadDeadline(time.Now().Add(30 * time.Second))

	if f, err := readFrameMax(nc, maxPayload); err == nil {
		t.Fatalf("a connection from loopback, with the key, got frame %d: the sandbox could dial its own execd", f.kind)
	}
}

// remoteConn is a connection from a chosen address, for fromThisPod.
type remoteConn struct {
	net.Conn
	addr net.Addr
}

func (c remoteConn) RemoteAddr() net.Addr { return c.addr }

func TestAConnectionIsRefusedWhenTheInterfacesCannotBeListed(t *testing.T) {
	interfaceAddrs = func() ([]net.Addr, error) { return nil, net.UnknownNetworkError("no netlink") }
	t.Cleanup(func() { interfaceAddrs = net.InterfaceAddrs })
	// A non-loopback peer execd can't place: with the error dropped it would be served.
	if !fromThisPod(remoteConn{addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1")}}) {
		t.Fatal("a connection was admitted while execd could not list its own addresses")
	}
}

// pipes is a listener whose connections come from no address of the pod's.
type pipes chan net.Conn

func (p pipes) Accept() (net.Conn, error) { return <-p, nil }
func (p pipes) Close() error              { return nil }
func (p pipes) Addr() net.Addr            { return nil }

// silent is a connection that never authenticates, and that no deadline ends.
type silent struct{ net.Conn }

func (silent) SetReadDeadline(time.Time) error { return nil }

func TestConnectionsNotYetAuthenticatedAreBounded(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	l := make(pipes)
	go s.serve(l) // left waiting for the next: serve has no end
	dial := func() net.Conn {
		ours, theirs := net.Pipe()
		t.Cleanup(func() { ours.Close(); theirs.Close() })
		select {
		case l <- silent{theirs}:
		case <-time.After(30 * time.Second):
			t.Fatal("serve took no more connections")
		}
		return ours
	}
	first := dial()
	for range maxPreauth - 1 {
		dial()
	}

	late := dial()

	late.SetReadDeadline(time.Now().Add(30 * time.Second)) // only bounds a hang
	if _, err := late.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("with %d connections yet to authenticate, one more got %v, want it closed: a flood of them would take execd's memory", maxPreauth, err)
	}
	first.Close() // it gives up: its place is the next connection's
	for deadline := time.Now().Add(30 * time.Second); len(s.preauth) == maxPreauth; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("a connection that ended kept its place: execd would refuse every connection after its first %d", maxPreauth)
		}
	}
}

func TestAReleasedCallIsForgotten(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	c := testConn(t)
	s.authenticated(c)
	req, _ := json.Marshal(startRequest{Argv: []string{"echo", "held"}, Env: map[string]string{}, Tag: "released"})
	s.dispatch(c, frame{kind: fStart, id: 38, payload: req})
	exitCode(t, s.get(38))

	s.dispatch(c, frame{kind: fRelease, id: 38})

	if s.get(38) != nil {
		t.Fatal("a released call is still held: each command's output would stay in memory until execd ends")
	}
}

func TestACommandGivenNoCwdFailsOnceThatDirectoryIsGone(t *testing.T) {
	tests := workdir
	t.Cleanup(func() { workdir = tests; os.Chdir(tests) }) // back where the tests run
	workdir = filepath.Join(t.TempDir(), "work")
	os.Mkdir(workdir, 0o755)
	os.Chdir(workdir) // as execd starts in it
	s, _ := newServer(strings.Repeat("00", 32))
	os.RemoveAll(workdir) // as a command's rm -rf of it, with a file put in its place
	os.WriteFile(workdir, nil, 0o644)
	made := filepath.Join(t.TempDir(), "made")
	req, _ := json.Marshal(startRequest{Argv: []string{"touch", made}, Env: map[string]string{}, Tag: "g"})

	s.start(testConn(t), frame{kind: fStart, id: 40, payload: req})

	if code := exitCode(t, s.get(40)); code != 1 {
		t.Fatalf("exit %d, want 1: the command's directory is gone", code)
	}
	if _, err := os.Stat(made); err == nil {
		t.Fatal("the command ran, in the directory that was removed")
	}
}

func TestACommandGivenNoCwdRunsWhereItsUserCannotEnterTheDirectoryByPath(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root enters any directory")
	}
	for _, shut := range []string{"", "work"} { // its parent, or itself: a 700 /root for uid 1000, in /root/work or /root
		t.Run("shut="+shut, func(t *testing.T) {
			tests, closed := workdir, t.TempDir()
			t.Cleanup(func() { os.Chmod(filepath.Join(closed, shut), 0o755); workdir = tests; os.Chdir(tests) }) // back where the tests run
			workdir = filepath.Join(closed, "work")
			os.Mkdir(workdir, 0o755)
			os.Chdir(workdir)
			os.Chmod(filepath.Join(closed, shut), 0)
			s, _ := newServer(strings.Repeat("00", 32))
			req, _ := json.Marshal(startRequest{Argv: []string{"true"}, Env: map[string]string{}, Tag: "p"})

			s.start(testConn(t), frame{kind: fStart, id: 42, payload: req})

			if code := exitCode(t, s.get(42)); code != 0 {
				t.Fatalf("exit %d: over Kubernetes exec the command runs, in the directory its container started in", code)
			}
		})
	}
}

func TestACommandGivenNoCwdFailsOnceItsDirectoryIsReplacedByOneItCannotEnter(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root enters any directory")
	}
	for _, shut := range []string{"work", ""} { // the one put in its place, or the parent of both
		t.Run("shut="+shut, func(t *testing.T) {
			tests, parent := workdir, t.TempDir()
			t.Cleanup(func() { os.Chmod(parent, 0o755); workdir = tests; os.Chdir(tests) }) // back where the tests run
			workdir = filepath.Join(parent, "work")
			os.Mkdir(workdir, 0o755)
			os.Chdir(workdir)
			os.Rename(workdir, filepath.Join(parent, "old")) // as a command might, to have the next ones run there
			os.Mkdir(workdir, 0o755)
			os.Chmod(filepath.Join(parent, shut), 0)
			s, _ := newServer(strings.Repeat("00", 32))
			made := filepath.Join(t.TempDir(), "made")
			req, _ := json.Marshal(startRequest{Argv: []string{"touch", made}, Env: map[string]string{}, Tag: "r"})

			s.start(testConn(t), frame{kind: fStart, id: 45, payload: req})

			if code := exitCode(t, s.get(45)); code != 1 {
				t.Fatalf("exit %d, want 1: the directory at its path is not the one it would run in", code)
			}
			if _, err := os.Stat(made); err == nil {
				t.Fatal("the command ran, in the directory that was moved away")
			}
		})
	}
}

func TestAUidWithNoPasswdEntryIsUnknownUnlessItIsRootOrExecdsOwn(t *testing.T) {
	// Over Kubernetes exec runuser refuses such a user; execd ran the command as that uid.
	if _, _, _, err := lookupUser("4242424"); err == nil || !strings.HasPrefix(err.Error(), "unknown user") {
		t.Fatalf("a uid with no passwd entry got %v, want unknown user", err)
	}
	for _, own := range []string{"0", strconv.Itoa(os.Getuid())} {
		if _, _, _, err := lookupUser(own); err != nil && strings.HasPrefix(err.Error(), "unknown user") {
			t.Fatalf("uid %s got %v: root and execd's own user need no passwd entry", own, err)
		}
	}
	// Nor a switch, which a container without CAP_SETGID, or one that isn't root, cannot make.
	if as, _, _, err := lookupUser(strconv.Itoa(os.Getuid())); as != nil || err != nil {
		t.Fatalf("execd's own uid got the credential %v and %v, want neither", as, err)
	}
}

func TestAConnectionThatDoesNotAuthenticateLosesItsPlaceInTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, _ := newServer(strings.Repeat("00", 32))
		ours, theirs := net.Pipe()
		defer ours.Close()
		s.preauth <- struct{}{}
		go s.handle(&conn{nc: theirs, dead: make(chan struct{})})

		time.Sleep(authTimeout)
		synctest.Wait()

		if len(s.preauth) != 0 {
			t.Fatalf("a silent connection kept its place past %v: %d of them would take every one", authTimeout, maxPreauth)
		}
	})
}

func TestAPingIsAnswered(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)

	s.dispatch(c, frame{kind: fPing})

	// The client takes a connection that answers none for dead.
	if f := nextFrame(t, frames); f.kind != fPong {
		t.Fatalf("a PING was answered with frame %d", f.kind)
	}
}

func TestAStreamsCommandIsKilledWhenItsConnectionDrops(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	t.Cleanup(func() { killTagged("stream") })
	// It never ends by itself.
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", "kill -STOP $$"}, Env: map[string]string{}, Stdin: true, Tag: "stream", Stream: true})
	c := testConn(t)
	s.start(c, frame{kind: fStart, id: 36, payload: req})
	cl := s.get(36)

	s.detach(c)

	if code := exitCode(t, cl); code != 143 || s.get(36) != nil {
		t.Fatalf("exit %d, still held %v: nothing resumes a stream, so its command would run on unseen", code, s.get(36) != nil)
	}
}

func TestAResumedCallOutlivesAnEarlierDropsTimer(t *testing.T) {
	var timers []func()
	afterFunc = func(_ time.Duration, f func()) *time.Timer { timers = append(timers, f); return nil }
	t.Cleanup(func() { afterFunc = time.AfterFunc })
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"sleep", "10"}, Env: map[string]string{}, Tag: "t"})
	first := testConn(t)
	s.start(first, frame{kind: fStart, id: 1, payload: req})
	t.Cleanup(s.get(1).kill)
	resume := frame{kind: fResume, id: 1, payload: []byte(`{"stdout":0,"stderr":0}`)}

	s.detach(first)
	again := testConn(t)
	s.resume(again, resume)
	s.detach(again)
	timers[0]() // the first drop's

	if abandoned(s.get(1)) {
		t.Fatal("abandoned by the first drop's timer, though resumed since")
	}
	timers[1]()
	if !abandoned(s.get(1)) {
		t.Fatal("not abandoned by its last drop's timer")
	}
}

func abandoned(cl *call) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return cl.abandoned
}

func TestARelativePathEntryUnderARelativeCwdRuns(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	os.MkdirAll(filepath.Join(dir, "work", "bin"), 0o755)
	os.WriteFile(filepath.Join(dir, "work", "bin", "hello"), []byte("#!/bin/sh\nexit 7\n"), 0o755)
	tests := workdir
	workdir = dir // as execd started there
	t.Cleanup(func() { workdir = tests; os.Chdir(tests) })
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"hello"}, Env: map[string]string{"PATH": "bin"}, Cwd: "work", Tag: "p"})

	s.start(testConn(t), frame{kind: fStart, id: 2, payload: req})

	// As a shell finds it: work/bin/hello, run in work.
	if code := exitCode(t, s.get(2)); code != 7 {
		t.Fatalf("exit %d, want hello's 7", code)
	}
}

func TestACommandGivenNoCwdStartsWhereExecdDidThoughTheDirectoryWasReplaced(t *testing.T) {
	tests := workdir
	t.Cleanup(func() { workdir = tests; os.Chdir(tests) }) // back where the tests run
	workdir = filepath.Join(t.TempDir(), "work")
	os.Mkdir(workdir, 0o755)
	os.Chdir(workdir) // as execd starts in it
	s, _ := newServer(strings.Repeat("00", 32))
	os.RemoveAll(workdir) // as a command's rm -rf and mkdir of it
	os.Mkdir(workdir, 0o755)
	os.WriteFile(filepath.Join(workdir, "made"), nil, 0o644)
	req, _ := json.Marshal(startRequest{Argv: []string{"test", "-e", "made"}, Env: map[string]string{}, Tag: "w"})

	s.start(testConn(t), frame{kind: fStart, id: 35, payload: req})

	if code := exitCode(t, s.get(35)); code != 0 {
		t.Fatalf("exit %d: the command ran in the directory that was removed", code)
	}
}

func exitCode(t *testing.T, cl *call) int {
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		cl.mu.Lock()
		exited, code := cl.exited, cl.code
		cl.mu.Unlock()
		if exited {
			return code
		}
		if time.Now().After(deadline) {
			t.Fatal("the command never exited")
		}
	}
}

func TestStdinFromADroppedConnectionIsNotWrittenAgain(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	out := filepath.Join(t.TempDir(), "stdin")
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", "cat > " + out}, Env: map[string]string{}, Stdin: true, Tag: "s"})
	first := testConn(t)
	s.authenticated(first)
	s.dispatch(first, frame{kind: fStart, id: 3, payload: req})
	s.dispatch(first, frame{kind: fStdin, id: 3, payload: []byte("AAAA")})
	again := testConn(t)
	s.authenticated(again)
	s.detach(first)
	s.dispatch(again, frame{kind: fResume, id: 3, payload: []byte(`{"stdout":0,"stderr":0}`)})

	s.get(3).writeStdin(first, []byte("BBBB"))                             // in flight on the dropped connection
	s.dispatch(again, frame{kind: fStdin, id: 3, payload: []byte("BBBB")}) // resent from RESUMED's count
	s.dispatch(again, frame{kind: fStdin, id: 3})

	exitCode(t, s.get(3))
	if got, _ := os.ReadFile(out); string(got) != "AAAABBBB" {
		t.Fatalf("stdin was %q", got)
	}
}

func TestALateStartOnAReplacedConnectionDoesNotRun(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"true"}, Env: map[string]string{}, Tag: "r"})
	first := testConn(t)
	s.authenticated(first)
	s.authenticated(testConn(t))

	s.dispatch(first, frame{kind: fStart, id: 4, payload: req}) // its call may have run and been released
	s.start(first, frame{kind: fStart, id: 5, payload: req})    // or it was replaced after dispatch had looked

	if s.get(4) != nil || s.get(5) != nil {
		t.Fatal("a START from a replaced connection ran")
	}
}

func TestALateResumeOnAReplacedConnectionLeavesTheCallToTheNewOne(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"true"}, Env: map[string]string{}, Tag: "s"})
	first, second := testConn(t), testConn(t)
	s.authenticated(first)
	s.start(first, frame{kind: fStart, id: 6, payload: req})
	s.mu.Lock()
	s.current = second // as authenticated() does, a moment before it closes the first
	s.mu.Unlock()
	resume := frame{kind: fResume, id: 6, payload: []byte(`{"stdout":0,"stderr":0}`)}
	s.resume(second, resume)

	s.resume(first, resume) // dispatch had looked before the connection was replaced

	cl := s.get(6)
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.sub != second {
		t.Fatal("a RESUME from a replaced connection took the call from the client's")
	}
}

func TestWithNoPathAnywhereACommandGetsTheUsualOne(t *testing.T) {
	if path, set := os.LookupEnv("PATH"); set {
		os.Unsetenv("PATH")
		t.Cleanup(func() { os.Setenv("PATH", path) })
	}
	s, _ := newServer(strings.Repeat("00", 32))
	out := filepath.Join(t.TempDir(), "env")
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", `env >"$0"`, out}, Env: map[string]string{}, Tag: "p"})

	s.start(testConn(t), frame{kind: fStart, id: 31, payload: req})

	exitCode(t, s.get(31))
	env, _ := os.ReadFile(out)
	_, path, _ := strings.Cut("\n"+string(env), "\nPATH=")
	path, _, _ = strings.Cut(path, "\n")
	// Left to itself the shell searches its own list, and bash's ends in the working directory.
	if dirs := strings.Split(path, ":"); slices.Contains(dirs, "") || slices.Contains(dirs, ".") {
		t.Fatalf("the command's PATH was %q in %q", path, env)
	}
}

func TestACommandKilledAtItsTimeoutSaysSoInItsExit(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	tag := strconv.FormatInt(time.Now().UnixNano(), 36) // its own: the last run's kill may still be searching
	req, _ := json.Marshal(startRequest{Argv: []string{"sleep", "60"}, Env: map[string]string{}, Tag: tag, Timeout: 0.05})
	c, frames := recordedConn(t)
	s.authenticated(c)

	s.dispatch(c, frame{kind: fStart, id: 7, payload: req})

	if status := exitStatus(t, frames); status["timeout"] != true {
		t.Fatalf("EXIT %v: the client can't tell the timeout from a kill -9", status)
	}
}

func TestACommandKilledAtItsTimeoutLeavesNoLineForItsSignal(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	tag := strconv.FormatInt(time.Now().UnixNano(), 36) // its own: the last run's kill may still be searching
	req, _ := json.Marshal(startRequest{Argv: []string{"sleep", "60"}, Env: map[string]string{}, Tag: tag, Timeout: 0.05})
	c, frames := recordedConn(t)
	s.authenticated(c)

	s.dispatch(c, frame{kind: fStart, id: 9, payload: req})

	for f := nextFrame(t, frames); f.kind != fExit; f = nextFrame(t, frames) {
		if f.kind == fStderr {
			t.Fatalf("stderr %q: the line counts against its caller's output limit, where the command's own output was within it", f.payload)
		}
	}
}

func TestTheLineForACommandASignalEndedIsDashs(t *testing.T) {
	const core = 0x80 // a wait status's mark of a core dump
	for status, want := range map[syscall.WaitStatus]string{
		syscall.WaitStatus(syscall.SIGSYS):         "Bad system call\n", // 31, the last signal Go names
		syscall.WaitStatus(syscall.SIGSEGV | core): "Segmentation fault (core dumped)\n",
		syscall.WaitStatus(syscall.SIGINT):         "", // dash says nothing of these two
		syscall.WaitStatus(syscall.SIGPIPE):        "",
		syscall.WaitStatus(32):                     "Unknown signal 32\n", // glibc keeps 32 and 33 for its threads
		syscall.WaitStatus(33):                     "Unknown signal 33\n",
		syscall.WaitStatus(34):                     "Real-time signal 0\n",
	} {
		if got := signalLine(status); got != want {
			t.Errorf("status %#x: %q, want %q", uint32(status), got, want)
		}
	}
}

func TestASignalsLineFollowsWhatTheCommandWroteItself(t *testing.T) {
	taken, passOn, reaped := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var first, once sync.Once
	read := func(bool) { // the reader holds the command's own stderr: read, and not yet passed on
		first.Do(func() { close(taken); <-passOn })
	}
	release := sync.OnceFunc(func() { close(passOn) })
	drainChecked := func(bool) { once.Do(func() { close(reaped) }) } // the exit is at work: the command is reaped
	afterRead.Store(&read)
	afterDrainCheck.Store(&drainChecked)
	t.Cleanup(func() { release(); afterRead.Store(nil); afterDrainCheck.Store(nil) })
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	// SIGKILL is what the out-of-memory killer sends; Inspect's bash tool shows a model stderr and no exit code.
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", "echo err >&2; kill -KILL $$"}, Env: map[string]string{}, Tag: "l"})
	s.dispatch(c, frame{kind: fStart, id: 12, payload: req})
	for _, step := range []chan struct{}{taken, reaped} {
		select {
		case <-step:
		case <-time.After(30 * time.Second):
			t.Fatal("the reader never took the command's stderr, or the command was never reaped")
		}
	}

	release()

	var stderr string
	for f := nextFrame(t, frames); f.kind != fExit; f = nextFrame(t, frames) {
		if f.kind == fStderr {
			stderr += string(f.payload)
		}
	}
	if stderr != "err\nKilled\n" {
		t.Fatalf("stderr %q, want the command's own and then the line for its signal", stderr)
	}
}

func TestACommandThatEndsByItselfAsItsTimerFiresIsTimedOutOnlyIfTheKillHadGoneAhead(t *testing.T) {
	for _, end := range []struct {
		code  int
		late  bool // the timer's kill has found the command running, and the command ends before the kill reaches it
		ahead bool // the kill had seen it stopped by then, and gone ahead on what it left running: the exit says so, whatever its code
	}{{3, false, false}, {137, false, false}, {137, true, false}, {7, true, true}} { // 137: a kill's exit code, from a command nothing killed
		code := end.code
		t.Run(strconv.Itoa(code)+", late "+strconv.FormatBool(end.late)+", ahead "+strconv.FormatBool(end.ahead), func(t *testing.T) {
			var fire func()
			afterFunc = func(_ time.Duration, f func()) *time.Timer {
				fire = f
				fired := time.NewTimer(0) // a timer that has fired: it can no longer be stopped
				<-fired.C
				return fired
			}
			t.Cleanup(func() { afterFunc = time.AfterFunc })
			s, _ := newServer(strings.Repeat("00", 32))
			req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", "read x; exit " + strconv.Itoa(code)}, Env: map[string]string{}, Stdin: true, Tag: "e", Timeout: 60})
			c, frames := recordedConn(t)
			s.authenticated(c)
			s.dispatch(c, frame{kind: fStart, id: 8, payload: req})
			cl := s.get(8)
			cl.kmu.Lock()
			pid := cl.pid
			cl.kmu.Unlock()
			fired := make(chan struct{})
			noted := sync.OnceFunc(reaper.mu.Unlock)
			if end.late {
				found, kill := make(chan struct{}), make(chan struct{})
				var once sync.Once
				hold := func(ahead bool) { // the kill waits here, holding the reaper's lock
					if ahead == end.ahead {
						once.Do(func() { close(found); <-kill })
					}
				}
				beforeKill.Store(&hold)
				noted = sync.OnceFunc(func() {
					close(kill)
					select {
					case <-fired:
					case <-time.After(30 * time.Second):
						t.Error("the timer's kill never returned")
					}
					beforeKill.Store(nil)
				})
				t.Cleanup(noted)
				go func() { fire(); close(fired) }()
				select {
				case <-found:
				case <-time.After(30 * time.Second):
					t.Fatal("the timer's kill never found the command running")
				}
				syscall.Kill(pid, syscall.SIGCONT) // stopped, where the kill has gone ahead: it runs on to its end
			} else {
				reaper.mu.Lock() // the command ends, and execd has yet to note it
				t.Cleanup(noted)
			}
			s.dispatch(c, frame{kind: fStdin, id: 8, payload: []byte("\n")})
			for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				stat, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
				if strings.Contains(string(stat), ") Z ") {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the command never ended")
				}
			}

			if !end.late {
				go func() { fire(); close(fired) }() // the timer's callback runs now: its kill finds the command gone
				select {
				case <-fired:
				case <-time.After(30 * time.Second):
					t.Fatal("the timeout's kill waited to see the command reaped")
				}
			}
			noted()
			if t.Failed() { // the kill never returned, so no exit will come: don't wait for one
				return
			}

			if status := exitStatus(t, frames); status["code"] != float64(code) || (status["timeout"] == true) != end.ahead {
				t.Fatalf("EXIT %v, want code %d and a timeout only where the kill had gone ahead (%v)", status, code, end.ahead)
			}
		})
	}
}

func TestATimeoutKillsACommandWhoseOutputWaitsOnAStalledConnection(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	t.Cleanup(func() { killTagged("stalled") })
	ours, theirs := net.Pipe() // nobody reads theirs: a write to it waits, as to a partitioned network
	t.Cleanup(func() { ours.Close(); theirs.Close() })
	c := &conn{nc: ours, dead: make(chan struct{})}
	s.authenticated(c)
	var timeout func()
	afterFunc = func(_ time.Duration, f func()) *time.Timer {
		timeout = f
		return time.NewTimer(time.Hour)
	}
	t.Cleanup(func() { afterFunc = time.AfterFunc })
	pidFile := filepath.Join(t.TempDir(), "pid")
	script := `echo $$ >"$0"; echo x; exec sleep 600`
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", script, pidFile}, Env: map[string]string{}, Tag: "stalled", Timeout: 60})
	s.dispatch(c, frame{kind: fStart, id: 39, payload: req})
	cl := s.get(39)
	for held, deadline := 0, time.Now().Add(30*time.Second); held < 3; time.Sleep(10 * time.Millisecond) {
		if cl.mu.TryLock() { // not held: the write of what it printed has yet to wait
			cl.mu.Unlock()
			held = 0
		} else {
			held++
		}
		if time.Now().After(deadline) {
			t.Fatal("the write of the command's output never waited")
		}
	}

	var killed sync.WaitGroup
	killed.Go(timeout)
	defer killed.Wait() // back before the test's timers are put back: the kill starts its grace by one

	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		written, _ := os.ReadFile(pidFile)
		if pid, err := strconv.Atoi(strings.TrimSpace(string(written))); err == nil && syscall.Kill(pid, 0) != nil {
			return // killed and reaped
		}
		if time.Now().After(deadline) {
			t.Fatal("the command outlived its timeout: its kill waited for the write of its output")
		}
	}
}

func TestACommandKilledBeforeItsTimeoutIsNotTimedOut(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", "kill -9 $$"}, Env: map[string]string{}, Tag: "k", Timeout: 60})
	c, frames := recordedConn(t)
	s.authenticated(c)

	s.dispatch(c, frame{kind: fStart, id: 9, payload: req})

	if status := exitStatus(t, frames); status["code"] != 137.0 || status["timeout"] != nil {
		t.Fatalf("EXIT %v, want code 137 and no timeout", status)
	}
}

// exitStatus returns a call's EXIT under the keys the client reads: a struct would match them in any case.
func exitStatus(t *testing.T, frames <-chan frame) (status map[string]any) {
	t.Helper()
	deadline := time.After(30 * time.Second)
	for {
		select {
		case f := <-frames:
			if f.kind == fExit {
				json.Unmarshal(f.payload, &status)
				return status
			}
		case <-deadline:
			t.Fatal("no EXIT")
		}
	}
}

// nextFrame takes the next frame sent; its budget only bounds a hang.
func nextFrame(t *testing.T, frames <-chan frame) frame {
	t.Helper()
	select {
	case f := <-frames:
		return f
	case <-time.After(30 * time.Second):
		t.Fatal("no frame")
		return frame{}
	}
}

// recordedConn is a connection whose sent frames arrive on the channel.
func recordedConn(t *testing.T) (*conn, <-chan frame) {
	a, b := net.Pipe()
	frames := make(chan frame, 64)
	go func() {
		for {
			f, err := readFrameMax(b, maxPayload)
			if err != nil {
				return
			}
			frames <- f
		}
	}()
	t.Cleanup(func() { a.Close(); b.Close() })
	return &conn{nc: a, dead: make(chan struct{})}, frames
}

func TestAVariableNameShWouldDropFailsTheCall(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	req, _ := json.Marshal(startRequest{Argv: []string{"true"}, Env: map[string]string{"a-b": "1"}, Tag: "n"})

	s.dispatch(c, frame{kind: fStart, id: 10, payload: req})

	// dash would start the command without the variable, in silence.
	status := exitStatus(t, frames)
	if why, _ := status["error"].(string); status["code"] != 126.0 || !strings.Contains(why, "a-b") {
		t.Fatalf("EXIT %v, want the name refused", status)
	}
}

func TestACwdThatCannotBeEnteredFailsAsItsCdNotAsTheCommand(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, nil, 0o644)
	closed := filepath.Join(t.TempDir(), "closed")
	os.Mkdir(closed, 0)
	for _, cwd := range []string{file, closed} {
		if cwd == closed && os.Getuid() == 0 {
			continue // root enters it all the same
		}
		s, _ := newServer(strings.Repeat("00", 32))
		c, frames := recordedConn(t)
		s.authenticated(c)
		req, _ := json.Marshal(startRequest{Argv: []string{"true"}, Env: map[string]string{}, Cwd: cwd, Tag: "c"})

		s.dispatch(c, frame{kind: fStart, id: 43, payload: req})

		// 126 would read to the client as a command it may not execute.
		if status := exitStatus(t, frames); status["code"] != 1.0 {
			t.Fatalf("cwd %s: EXIT %v, want a failed cd's 1", cwd, status)
		}
	}
}

func TestAStartErrorFitsTheClientsControlFrame(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	cwd := "/" + strings.Repeat("\x01", 5000) // six bytes each, escaped to JSON
	req, _ := json.Marshal(startRequest{Argv: []string{"true"}, Env: map[string]string{}, Cwd: cwd, Tag: "e"})

	s.dispatch(c, frame{kind: fStart, id: 6, payload: req})

	deadline := time.After(30 * time.Second)
	for {
		select {
		case f := <-frames:
			if f.kind != fExit {
				continue
			}
			if len(f.payload) > 4096 { // the client's MAX_CONTROL: past it, it reconnects for ever
				t.Fatalf("EXIT is %d bytes", len(f.payload))
			}
			return
		case <-deadline:
			t.Fatal("no EXIT")
		}
	}
}

func TestExecdIsNotDumpableFromItsStart(t *testing.T) {
	const prGetDumpable = 3
	// init() has run, as it runs before main.
	if dumpable, _, _ := syscall.RawSyscall(syscall.SYS_PRCTL, prGetDumpable, 0, 0); dumpable != 0 {
		t.Fatal("dumpable: a same-uid process could reopen the start's stdout through /proc")
	}
}

// onItsOwnClock runs a test of the turns in a bubble, where time passes only while every goroutine waits.
func onItsOwnClock(t *testing.T, test func(t *testing.T)) {
	ahead := time.Now().Add(time.Hour)
	synctest.Test(t, func(t *testing.T) {
		time.Sleep(time.Until(ahead))        // past the real clock: an earlier test's late turn can't move these
		slot.Store(int64(time.Since(epoch))) // the turns are shared, and counted from execd's start
		defer slot.Store(0)
		test(t)
	})
}

func TestManySmallWritesMakeFewFramesAndTakeFewTurns(t *testing.T) {
	onItsOwnClock(t, func(t *testing.T) {
		c, frames := recordedConn(t)
		cl := &call{id: 7, sub: c}
		cl.room = sync.NewCond(&cl.mu)
		other, others := recordedConn(t)
		next := &call{id: 8, sub: other}
		next.room = sync.NewCond(&next.mu)
		began := time.Now()

		for range 50 {
			cl.output(0, []byte("line\n")) // as its reader takes each small write
		}
		next.output(0, []byte("x"))

		<-others
		if held := time.Since(began); held > 0 {
			t.Fatalf("another call's output waited %v behind the turns 50 writes took", held)
		}
		outputs := 0
		for got := 0; got < 50*len("line\n"); outputs++ {
			got += len((<-frames).payload)
		}
		// The client paces frames at 4,096 a second: a frame a write would crawl.
		if outputs > 2 {
			t.Fatalf("%d frames for 50 writes made at once, want the first and one a millisecond on", outputs)
		}
	})
}

func TestCallsTakeTurnsToSend(t *testing.T) {
	onItsOwnClock(t, func(t *testing.T) {
		var sent []<-chan frame
		began := time.Now()
		for i := range 20 {
			c, frames := recordedConn(t)
			cl := &call{id: uint64(10 + i), sub: c}
			cl.room = sync.NewCond(&cl.mu)
			cl.output(0, []byte("x")) // each call's first: only the turns hold it
			sent = append(sent, frames)
		}

		for _, frames := range sent {
			<-frames
		}

		// Many calls sending at once would pass the client's frame pace, and others' calls wait behind them.
		if took := time.Since(began); took < 6*time.Millisecond {
			t.Fatalf("20 calls sent within %v, not a turn each past the burst", took)
		}
	})
}

func TestCallsWithNoConnectionTakeNoTurns(t *testing.T) {
	onItsOwnClock(t, func(t *testing.T) {
		for i := range 200 {
			cl := &call{id: uint64(100 + i)} // its connection dropped: the resume sends what it has
			cl.room = sync.NewCond(&cl.mu)
			cl.output(0, []byte("x"))
		}
		c, frames := recordedConn(t)
		cl := &call{id: 99, sub: c}
		cl.room = sync.NewCond(&cl.mu)
		began := time.Now()

		cl.output(0, []byte("x"))

		<-frames
		if took := time.Since(began); took > 0 {
			t.Fatalf("a live call waited %v behind calls with nowhere to send", took)
		}
	})
}

func TestAnExitTakesTurnsForWhatItSends(t *testing.T) {
	slot.Store(0) // turns other tests took could leave less than two to take
	c, frames := recordedConn(t)
	cl := &call{id: 12, sub: c, out: [2]fifo{{buf: []byte("out"), n: 3}, {}}}
	cl.room = sync.NewCond(&cl.mu)
	before := max(time.Duration(slot.Load()), time.Since(epoch))

	cl.finish(0, "")

	nextFrame(t, frames)
	nextFrame(t, frames) // the output, then the exit
	// Exits sent without turns, many calls ending at once, would pass the client's frame pace.
	if moved := time.Duration(slot.Load()) - before; moved < 2*slotEvery {
		t.Fatalf("turns moved %v for the two frames an exit sent", moved)
	}
}

func TestExitsHoldOthersOutputBackOnlySoLong(t *testing.T) {
	onItsOwnClock(t, func(t *testing.T) {
		for range 100_000 {
			charge(3) // calls ending faster than turns come: three minutes of turns
		}
		c, frames := recordedConn(t)
		cl := &call{id: 97, sub: c}
		cl.room = sync.NewCond(&cl.mu)

		cl.output(0, []byte("x"))

		select {
		case <-frames:
		case <-time.After(50 * time.Millisecond):
			t.Fatal("output held over 50 ms behind exits' turns")
		}
	})
}

func TestCallsThatEndBeforeTheirTurnHoldOthersOutputBackOnlySoLong(t *testing.T) {
	charge(100_000)                     // exits already hold the turns as far ahead as they may
	t.Cleanup(func() { slot.Store(0) }) // the turns are shared: leave none taken
	for i := range 1000 {
		cl := &call{id: uint64(1000 + i), sub: testConn(t)}
		cl.room = sync.NewCond(&cl.mu)
		cl.output(0, []byte("x")) // its flush waits for a turn
		cl.finish(0, "")          // and it ends before the turn comes
	}

	if ahead := time.Duration(slot.Load()) - time.Since(epoch); ahead > 2*slotAhead {
		t.Fatalf("turns run %v ahead after 1,000 short calls", ahead)
	}
}

func TestAResumeTakesTurnsForWhatItSends(t *testing.T) {
	slot.Store(0) // turns other tests took could leave less than two to take
	s, _ := newServer(strings.Repeat("00", 32))
	s.calls[13] = &call{id: 13, out: [2]fifo{{buf: []byte("out"), n: 3}, {buf: []byte("err"), n: 3}}}
	s.calls[13].room = sync.NewCond(&s.calls[13].mu)
	c, frames := recordedConn(t)
	before := max(time.Duration(slot.Load()), time.Since(epoch))

	s.resume(c, frame{kind: fResume, id: 13, payload: []byte(`{"stdout":0,"stderr":0}`)})

	nextFrame(t, frames)
	nextFrame(t, frames)
	nextFrame(t, frames) // RESUMED, then what each stream has waiting
	// Resumes sent without turns, many calls resuming at once, would pass the client's frame pace.
	if moved := time.Duration(slot.Load()) - before; moved < 2*slotEvery {
		t.Fatalf("turns moved %v for the two frames a resume sent", moved)
	}
}

func TestAChargeNeverGivesBackTurnsTaken(t *testing.T) {
	ahead := time.Since(epoch) + 200*time.Millisecond // waiting flushes have taken the turns before this
	slot.Store(int64(ahead))
	t.Cleanup(func() { slot.Store(0) })

	charge(1)

	if got := time.Duration(slot.Load()); got < ahead {
		t.Fatalf("turns moved back %v: flushes waiting for them would send together", ahead-got)
	}
}

func TestAScriptWithNoInterpreterLineRuns(t *testing.T) {
	script := filepath.Join(t.TempDir(), "seven")
	os.WriteFile(script, []byte("exit 7\n"), 0o755)
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{script}, Env: map[string]string{}, Tag: "n"})

	s.start(testConn(t), frame{kind: fStart, id: 20, payload: req})

	// As a shell runs it: execve refuses the file, and the shell reads it.
	if code := exitCode(t, s.get(20)); code != 7 {
		t.Fatalf("exit %d, want the script's 7", code)
	}
}

func TestArgumentsReachTheCommandAsGiven(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	args := []string{"a  b", "$(id)", "`id`", ";x", "$PATH", "*", ""}
	req, _ := json.Marshal(startRequest{Argv: append([]string{"printf", "%s\n"}, args...), Env: map[string]string{}, Tag: "l"})

	s.dispatch(c, frame{kind: fStart, id: 25, payload: req})

	var out []byte
	deadline := time.After(30 * time.Second)
	for {
		select {
		case f := <-frames:
			if f.kind == fStdout {
				out = append(out, f.payload...)
				continue
			}
			if f.kind != fExit {
				continue
			}
			// The shell that starts the command must not read its arguments as shell.
			if want := strings.Join(args, "\n") + "\n"; string(out) != want {
				t.Fatalf("printf got %q, want %q", out, want)
			}
			return
		case <-deadline:
			t.Fatal("no EXIT")
		}
	}
}

func TestACommandNamedLikeAShellBuiltinIsTheOneOnThePath(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "printf"), []byte("#!/bin/sh\nexit 7\n"), 0o755)
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"printf"}, Env: map[string]string{"PATH": dir}, Tag: "b"})

	s.start(testConn(t), frame{kind: fStart, id: 24, payload: req})

	// The shell that finds the command must not run its own printf in its place.
	if code := exitCode(t, s.get(24)); code != 7 {
		t.Fatalf("exit %d, want 7 from the printf on PATH", code)
	}
}

func TestACommandNamedLikeAnOptionIsNotFound(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"-c", "true"}, Env: map[string]string{}, Tag: "o"})

	s.start(testConn(t), frame{kind: fStart, id: 34, payload: req})

	// bash would run `true` with no environment, as an option of its exec: the shell isn't asked.
	cl := s.get(34)
	if code := exitCode(t, cl); code != 127 || cl.startErr == "" {
		t.Fatalf("exit %d, start error %q: want 127 from execd itself", code, cl.startErr)
	}
}

func TestACommandIsFoundOnThePathAsItsUser(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root runs a command as another user")
	}
	dir := t.TempDir()
	os.Chmod(filepath.Dir(dir), 0o755) // so the other user reaches it
	for name, script := range map[string]string{"roots": "#!/bin/sh\nexit 3\n", "anyones": "#!/bin/sh\nexit 7\n"} {
		os.Mkdir(filepath.Join(dir, name), 0o755)
		os.WriteFile(filepath.Join(dir, name, "tool"), []byte(script), 0o755)
	}
	os.Chmod(filepath.Join(dir, "roots"), 0o700)
	path := filepath.Join(dir, "roots") + ":" + filepath.Join(dir, "anyones")
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"tool"}, Env: map[string]string{"PATH": path}, User: "65534", Tag: "u"})

	s.start(testConn(t), frame{kind: fStart, id: 21, payload: req})

	// Root sees roots/tool first; the user can't run it, and their shell goes on to the next.
	if code := exitCode(t, s.get(21)); code != 7 {
		t.Fatalf("exit %d, want 7 from the tool the user can run", code)
	}
	// A child of execd that switched user would share its memory till it execs: the flag is reset.
	if dumpable() {
		t.Fatal("dumpable once it has run a command as another user")
	}
}

func TestACommandRunAsAnotherUserHasTheirIdentityAndItsOwnEnvironment(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root runs a command as another user")
	}
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	t.Setenv("RAW", "\xff") // execd's own environment, which a command inherits, need not be text
	// GODEBUG has a Go program trace its start on stderr.
	env := map[string]string{"GODEBUG": "inittrace=1", "GOMAXPROCS": "7", "BIG": strings.Repeat("x", 128<<10-len("BIG=")-1)}
	script := "id -u; id -g; id -G; echo $GODEBUG $GOMAXPROCS ${#BIG} $RAW; echo $HOME $USER $LOGNAME; [ ! -e /proc/$$/fd/3 ] || echo descriptor 3 is open"
	nobody, _ := user.LookupId("65534") // HOME, USER and LOGNAME are theirs, as runuser sets them, but for one the caller set
	run := func(id uint64, asked string) {
		req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", script}, Env: env, User: "65534", Tag: "e"})

		s.dispatch(c, frame{kind: fStart, id: id, payload: req})

		var out []byte
		deadline := time.After(30 * time.Second)
		for {
			select {
			case f := <-frames:
				if f.kind == fStdout || f.kind == fStderr {
					out = append(out, f.payload...)
					continue
				}
				if f.kind != fExit {
					continue
				}
				// execd, a Go program, becomes the user itself: the environment isn't its own to read or to mark.
				if string(out) != "65534\n65534\n65534\ninittrace=1 7 131067 \xff\n"+nobody.HomeDir+" "+asked+" "+nobody.Username+"\n" {
					t.Fatalf("the command's output was %q", out)
				}
				return
			case <-deadline:
				t.Fatal("no EXIT")
			}
		}
	}
	run(27, nobody.Username)
	env["USER"] = "asked"
	run(28, "asked")
}

// nofile sets the open-file limit, not by syscall.Setrlimit: after it, Go starts a command with this limit, not its own first one.
func nofile(to syscall.Rlimit) {
	syscall.RawSyscall6(syscall.SYS_PRLIMIT64, 0, syscall.RLIMIT_NOFILE, uintptr(unsafe.Pointer(&to)), 0, 0, 0)
}

func TestACommandForAnotherUserGetsRunusersOpenFileLimit(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root runs a command as another user")
	}
	var was syscall.Rlimit
	syscall.Getrlimit(syscall.RLIMIT_NOFILE, &was)
	if was.Max < 2048 {
		t.Skip("needs a hard open-file limit of 2048")
	}
	nofile(syscall.Rlimit{Cur: 2048, Max: was.Max}) // what a command inherits here: above runuser's 1024, as a container's is
	t.Cleanup(func() { nofile(was) })
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)

	limits := map[string]string{}
	for id, who := range []string{"65534", ""} {
		req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", "ulimit -Sn; ulimit -Hn"}, Env: map[string]string{}, User: who, Tag: "f"})
		s.dispatch(c, frame{kind: fStart, id: uint64(60 + id), payload: req})
		for f := nextFrame(t, frames); f.kind != fExit; f = nextFrame(t, frames) {
			if f.kind == fStdout {
				limits[who] += string(f.payload)
			}
		}
	}

	// Over Kubernetes exec runuser resets another user's soft limit and no other; execd's own user keeps the container's.
	hard := strconv.FormatUint(was.Max, 10)
	if limits["65534"] != "1024\n"+hard+"\n" || limits[""] != "2048\n"+hard+"\n" {
		t.Fatalf("soft and hard limits: another user's command %q, execd's own user's %q", limits["65534"], limits[""])
	}
}

func TestACommandForAnotherUserDoesNotRunWithoutItsEnvironment(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root runs a command as another user")
	}

	// With no pipe to read the environment from, as when execd has no descriptor to spare.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // only bounds a hang
	defer cancel()
	out, _ := exec.CommandContext(ctx, "/proc/self/exe", "as", "", "65534", "65534", "", "/bin/echo", "RAN").CombinedOutput()

	if !strings.HasPrefix(string(out), "execd: ") || strings.Contains(string(out), "RAN") {
		t.Fatalf("with no environment to read, its output was %q", out)
	}
}

func TestACommandForAnotherUserEntersItsDirectoryAsThem(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root runs a command as another user")
	}
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"true"}, Env: map[string]string{}, Cwd: t.TempDir(), User: "65534", Tag: "d"})

	s.start(testConn(t), frame{kind: fStart, id: 26, payload: req})

	// Root may enter a test's directory (mode 700); the user may not, and a failed cd is exit 1.
	if code := exitCode(t, s.get(26)); code != 1 {
		t.Fatalf("exit %d, want 1 from a cd its user can't make", code)
	}
}

func TestACommandForAnotherUserEntersADirectoryOnlyTheyCan(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root runs a command as another user")
	}
	open := t.TempDir()
	home := filepath.Join(open, "home") // a 700 home: root without CAP_DAC_OVERRIDE can't enter it
	os.Mkdir(home, 0o700)
	os.Chown(home, 65534, 65534)
	t.Cleanup(func() { os.Chown(home, 0, 0) }) // root's again, to be removed
	os.Chmod(open, 0o755)
	os.Chmod(filepath.Dir(open), 0o755)
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"true"}, Env: map[string]string{}, Cwd: home, User: "65534", Tag: "h"})

	s.start(testConn(t), frame{kind: fStart, id: 27, payload: req})

	if code := exitCode(t, s.get(27)); code != 0 {
		t.Fatalf("exit %d: execd looked for the directory as itself, not as the command's user", code)
	}
}

func TestAKillReachesWhatAnotherUsersCommandDetached(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root runs a command as another user")
	}
	prctl(prSetChildSubreaper, 1) // as execd: what the command detached is reaped here once killed
	t.Cleanup(func() { prctl(prSetChildSubreaper, 0) })
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	detach := "setsid sh -c 'echo $$; kill -STOP $$' & wait" // out of the group a kill signals, it names itself
	victims := map[uint64]int{}
	for id := uint64(100); id < 120; id++ {
		req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", detach}, Env: map[string]string{}, User: "65534", Tag: "detached" + strconv.Itoa(int(id))})
		s.dispatch(c, frame{kind: fStart, id: id, payload: req})
	}
	deadline := time.After(30 * time.Second)
	for len(victims) < 20 {
		select {
		case f := <-frames:
			if f.kind == fStdout {
				pid, _ := strconv.Atoi(strings.TrimSpace(string(f.payload)))
				victims[f.id] = pid
				t.Cleanup(func() { syscall.Kill(pid, syscall.SIGKILL) })
			}
		case <-deadline:
			t.Fatal("a command never printed what it detached")
		}
	}

	for id := range victims { // at once: their searches wait in turn for the one thread
		s.dispatch(c, frame{kind: fKill, id: id})
	}

	// Without CAP_SYS_PTRACE root can't read another user's environment, where the call's tag is.
	for id, pid := range victims {
		for deadline := time.Now().Add(30 * time.Second); syscall.Kill(pid, 0) != syscall.ESRCH; time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("process %d, which call %d's command detached, outlived its kill", pid, id)
			}
		}
	}
	var searched sync.WaitGroup
	for range 200 { // a collection under way moves a goroutine not held to its thread
		searched.Add(1)
		go func() { defer searched.Done(); searches <- search{"none", &syscall.Credential{Uid: 65534, Gid: 65534}} }()
		runtime.GC()
	}
	done := make(chan struct{})
	go func() { searched.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the searches were never taken")
	}
	// Taking the user's identity resets the flag to the host's fs.suid_dumpable, for an instant each time.
	for deadline := time.Now().Add(30 * time.Second); dumpable(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("dumpable once it has killed a command run as another user")
		}
	}
	// The identity is one thread's, for the search alone: on another it would fail what execd does as itself.
	for deadline := time.Now().Add(30 * time.Second); len(borrowed()) > 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("threads kept the user's identity: %v", borrowed())
		}
	}
}

// borrowed lists the filesystem ids of this process's threads that aren't its own.
func borrowed() (ids []string) {
	tasks, _ := filepath.Glob("/proc/self/task/*/status")
	for _, task := range tasks {
		status, _ := os.ReadFile(task)
		for _, line := range strings.Split(string(status), "\n") {
			if f := strings.Fields(line); len(f) == 5 && (f[0] == "Uid:" || f[0] == "Gid:") && f[4] != f[1] {
				ids = append(ids, line)
			}
		}
	}
	return ids
}

func dumpable() bool {
	d, _, _ := syscall.RawSyscall(syscall.SYS_PRCTL, 3, 0, 0) // PR_GET_DUMPABLE
	return d != 0
}

// endAsNobody kills what a failed test left of that user's: without CAP_KILL root's own signal reaches none of it.
func endAsNobody(pids ...int) {
	for _, pid := range pids {
		signalAs(&syscall.Credential{Uid: 65534, Gid: 65534}, pid, syscall.SIGKILL)
		signalAs(&syscall.Credential{Uid: 65534, Gid: 65534}, -pid, syscall.SIGKILL)
	}
}

func killTagged(tag string) { signalTagged(tag, syscall.SIGKILL, nil) } // what a test left carrying a tag

// graced has each kill's grace, timeout(1)'s -k 5s over Kubernetes exec, last until the test ends it; end ends them, and says how many.
func graced(t *testing.T) (end func() int) {
	up, kept := make(chan func(), 64), afterFunc
	afterFunc = func(d time.Duration, f func()) *time.Timer {
		if d != 5*time.Second {
			return kept(d, f)
		}
		up <- f
		return nil
	}
	end = func() (n int) {
		for ; len(up) > 0; n++ {
			(<-up)()
		}
		return n
	}
	t.Cleanup(func() { end(); afterFunc = kept }) // one the test left open: its kill ends with the test
	return end
}

// ready starts a command under a tag of the run's own, which the last run's kill is not searching by, and takes its first frame.
func ready(t *testing.T, user string, argv ...string) (s *server, c *conn, frames <-chan frame, tag string) {
	tag = strconv.FormatInt(time.Now().UnixNano(), 36)
	s, _ = newServer(strings.Repeat("00", 32))
	c, frames = recordedConn(t)
	s.authenticated(c)
	t.Cleanup(func() { killTagged(tag) })
	req, _ := json.Marshal(startRequest{Argv: argv, Env: map[string]string{}, User: user, Tag: tag})
	s.dispatch(c, frame{kind: fStart, id: 80, payload: req})
	nextFrame(t, frames)
	return s, c, frames, tag
}

// said is what a command goes on to print, until that is enough.
func said(t *testing.T, frames <-chan frame, enough func(string) bool) (out string) {
	for deadline := time.Now().Add(30 * time.Second); !enough(out); {
		out += string(awaited(t, frames, fStdout, deadline).payload)
	}
	return out
}

// until waits for a condition; its budget only bounds a hang.
func until(t *testing.T, what string, met func() bool) {
	for deadline := time.Now().Add(30 * time.Second); !met(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
	}
}

func TestAKilledCommandHasItsSigtermAndWhenTheGraceIsUpItsSigkill(t *testing.T) {
	end := graced(t)
	s, c, frames, _ := ready(t, "", "env", "-i", "/bin/sh", "-c", `trap 'echo x' TERM; echo ready; while :; do echo .; sleep 0.01; done`) // it counts each SIGTERM it takes and runs on; with no tag of the call's, only the kill of the command itself ends it
	on := func(out string) bool { return strings.Count(out[strings.LastIndex(out, "x")+1:], ".") >= 3 }
	s.dispatch(c, frame{kind: fKill, id: 80})
	said(t, frames, func(out string) bool { return strings.Contains(out, "x") && on(out) })
	s.dispatch(c, frame{kind: fKill, id: 80}) // as its client's, behind its timeout's
	if out := said(t, frames, on); strings.Contains(out, "x") {
		t.Fatalf("a second kill sent a second SIGTERM, which cuts short what the first began: %q", out)
	}
	if n, status := end(), exitStatus(t, frames); n != 1 || status["code"] != 137.0 {
		t.Fatalf("%d timers of 5 s, EXIT %v: want the first kill's alone, and the SIGKILL of a command that ran on to its grace's end", n, status)
	}
}

func TestAKillsSearchByTagSendsSigtermOnceAndWhenItsGraceIsUpSigkill(t *testing.T) {
	end := graced(t)
	user := map[bool]string{true: "65534"}[os.Getuid() == 0]                                                         // whose environments root may not read: the search is then its helper's, as that user
	helper := `sh -c "trap \"echo y\" TERM; echo h; while :; do echo .; sleep 0.01; done"`                           // which the command's handler starts: it counts its SIGTERMs too
	detached := `(setsid sh -c 'trap "echo t$$" TERM; echo ready; kill -STOP $$; while :; do sleep 0.01; done' &); ` // in a session of its own, its parent gone, only the tag leads to it: stopped, it says its id at its SIGTERM and runs on
	s, c, frames, tag := ready(t, user, "sh", "-c", `trap 'echo x; `+helper+` & wait' TERM; `+detached+`while :; do sleep 0.01; done`)
	own, seen := "/proc/"+strconv.Itoa(s.get(80).pid)+"/environ", ""
	var over atomic.Bool
	held := func(of, environ string) (*os.File, error) { // the search reads on once the handler's helper runs, as a slow one would
		if of != tag || over.Load() { // another kill's search, or this one's later search for its SIGKILLs: other goroutines'
			return os.Open(environ)
		}
		for of == tag && !strings.Contains(seen, "h") {
			seen += said(t, frames, func(out string) bool { return out != "" })
		}
		seen += map[bool]string{true: "read"}[of == tag && (environ == own || environ == "/proc/1/environ")] // the command's own, which its kill has signalled, or that of a process older than the command
		return os.Open(environ)
	}
	openEnviron.Store(&held)
	t.Cleanup(func() { openEnviron.Store(nil) })
	s.dispatch(c, frame{kind: fKill, id: 80}) // back once its search is done, or its helper started
	over.Store(true)
	out := seen + said(t, frames, func(out string) bool { _, since, _ := strings.Cut(out, "t"); return strings.Count(since, ".") >= 3 }) // until what only the tag leads to has said its SIGTERM, and three dots more: a helper's search is not waited for
	pid, _ := strconv.Atoi(strings.SplitN(out[strings.Index(out, "t")+1:], "\n", 2)[0])
	if strings.Count(out, "x") != 1 || strings.Count(out, "t") != 1 || strings.Contains(out, "y") || strings.Contains(out, "read") {
		t.Fatalf("the command, what only its tag leads to, its handler's helper and the search said %q: want one SIGTERM for each of the first two, none for the helper, and no read of the command's environment", out)
	}
	end()
	exitStatus(t, frames)
	until(t, "what only the call's tag leads to outlived the kill's grace", func() bool { f := stat(pid); return len(f) == 0 || strings.Contains("ZX", f[0]) }) // ended: a zombie, or one being reaped
}

func TestAKilledCallsExitWaitsForWhatHadItsSigtermAndTheRestIsKilledAtOnce(t *testing.T) {
	for name, argv := range map[string][]string{
		"left in its group by a handler":     {map[bool]string{true: "65534"}[os.Getuid() == 0], "env", "-i", "/bin/sh", "-c", `trap 'sleep 600 >/dev/null 2>&1 & echo $!; exit' TERM; echo ready; while :; do sleep 0.01; done`},                                                                // at its SIGTERM it starts one, says its id and ends: no SIGTERM went to that one, and with no tag only the command's group leads there
		"left out of its group by a handler": {"", "sh", "-c", `trap 'setsid sleep 600 >/dev/null 2>&1 & echo $!; exit' TERM; echo ready; while :; do sleep 0.01; done`},                                                                                                                         // the same in a session of its own: only the tag leads there
		"found by its tag":                   {map[bool]string{true: "65534"}[os.Getuid() == 0], "sh", "-c", `trap exit TERM; (setsid sh -c 'trap "echo $$; exec env -i sh -c \"while :; do :; done\" >/dev/null 2>&1" TERM; echo ready; while :; do :; done' &); while :; do sleep 0.01; done`}, // in a session of its own, its parent gone, one says its id at its SIGTERM and runs on with no output and no tag: only the tag led there, for another user's the search's helper, and only its id leads the SIGKILL there
	} {
		t.Run(name, func(t *testing.T) {
			end := graced(t)
			s, c, frames, tag := ready(t, argv[0], argv[1:]...)
			gone := func() bool { cl := s.get(80); cl.kmu.Lock(); defer cl.kmu.Unlock(); return cl.pid == 0 }
			wait := func(ours bool) { until(t, "the command ran on", func() bool { return !ours || gone() }) }
			held := func(of, environ string) (*os.File, error) { wait(of == tag); return os.Open(environ) } // the search reads on once the command has ended, as a slow one would: the exit waits for its word
			openEnviron.Store(&held)
			t.Cleanup(func() { openEnviron.Store(nil) })
			s.dispatch(c, frame{kind: fKill, id: 80})
			straggler, _ := strconv.Atoi(strings.TrimSpace(said(t, frames, func(out string) bool { return strings.HasSuffix(out, "\n") })))
			wait(true)
			if name == "found by its tag" { // it had a SIGTERM: another call runs from its START to its EXIT meanwhile, three of the sweep's looks, and an exit that did not wait would have come by then
				other, _ := json.Marshal(startRequest{Argv: []string{"sleep", "0.3"}, Env: map[string]string{}, Tag: "other"})
				s.dispatch(c, frame{kind: fStart, id: 81, payload: other})
				if f := awaited(t, frames, fExit, time.Now().Add(30*time.Second)); f.id != 81 {
					t.Fatal("the killed call's exit did not wait for what ran on")
				}
				end()
			}
			exitStatus(t, frames) // with no grace to wait out where nothing that had a SIGTERM is left
			until(t, "what ran on outlived the kill", func() bool { f := stat(straggler); return len(f) == 0 || strings.Contains("ZX", f[0]) })
		})
	}
}

// awaited is the next frame of a kind, within a test's one deadline.
func awaited(t *testing.T, frames <-chan frame, kind byte, deadline time.Time) frame {
	t.Helper()
	for {
		select {
		case f := <-frames:
			if f.kind == kind {
				return f
			}
		case <-time.After(time.Until(deadline)):
			t.Fatalf("no frame of kind %d", kind)
		}
	}
}

func TestAKillReachesAnotherUsersProcessThatExecdFindsAndMayNotSignal(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root runs a command as another user")
	}
	prctl(prSetChildSubreaper, 1) // as execd: what the command detached is reaped here once killed
	t.Cleanup(func() { prctl(prSetChildSubreaper, 0) })
	graced(t) // no SIGKILL ends it: its user's helper sends the SIGTERM execd may not
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	// With CAP_SYS_PTRACE execd reads another user's environment, and without CAP_KILL, as in CI's second job, may not signal them.
	shown := filepath.Join(t.TempDir(), "environ")
	os.WriteFile(shown, []byte("HAWK_NEXT_EXEC=found\x00"), 0o600)
	var detached atomic.Int64
	read := func(tag, environ string) (*os.File, error) {
		if syscall.Geteuid() == 0 && environ == "/proc/"+strconv.FormatInt(detached.Load(), 10)+"/environ" {
			return os.Open(shown)
		}
		return os.Open(environ)
	}
	openEnviron.Store(&read)
	t.Cleanup(func() { openEnviron.Store(nil) })
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", "setsid sh -c 'echo $$; kill -STOP $$' & wait"}, Env: map[string]string{}, User: "65534", Tag: "found"})
	s.dispatch(c, frame{kind: fStart, id: 121, payload: req})
	deadline := time.Now().Add(30 * time.Second) // for the whole test
	pid, _ := strconv.Atoi(strings.TrimSpace(string(awaited(t, frames, fStdout, deadline).payload)))
	if pid == 0 { // or the looks below would be at this process's own group
		t.Fatal("the command never printed what it detached")
	}
	detached.Store(int64(pid))
	t.Cleanup(func() { endAsNobody(pid) })

	s.dispatch(c, frame{kind: fKill, id: 121})

	for ; syscall.Kill(pid, 0) != syscall.ESRCH; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("process %d, which execd's own search found and may not signal, outlived its kill: the user's own searches did not look for it", pid)
		}
	}
}

func TestAKillReachesAnotherUsersCommandAndItsGroupThoughTheyCarryNoTag(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root runs a command as another user")
	}
	prctl(prSetChildSubreaper, 1) // as execd: the command's child is reaped here once killed
	t.Cleanup(func() { prctl(prSetChildSubreaper, 0) })
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	open := t.TempDir() // where the user can run a copy of this binary: its own directory is root's alone
	os.Chmod(open, 0o755)
	os.Chmod(filepath.Dir(open), 0o755)
	this, _ := os.Executable()
	binary, _ := os.ReadFile(this)
	leave := filepath.Join(open, "leave")
	os.WriteFile(leave, binary, 0o755)
	deadline := time.Now().Add(30 * time.Second) // for the whole test
	// Without CAP_KILL root's signal reaches neither, and with no tag no search finds them: each names what must end.
	for id, argv := range [][]string{
		{"env", "-i", "sh", "-c", "sleep 600 & echo $! $$; wait"}, // the command and a child in its group
		{leave, "leave", "/bin/sleep", "600"},                     // the command, out of its own group
	} {
		// A tag each: the child that searches for the first's still runs as the second starts.
		req, _ := json.Marshal(startRequest{Argv: argv, Env: map[string]string{}, User: "65534", Tag: "none" + strconv.Itoa(id)})
		s.dispatch(c, frame{kind: fStart, id: uint64(80 + id), payload: req})
		t.Cleanup(func() { s.dispatch(c, frame{kind: fKill, id: uint64(80 + id)}) }) // whatever fails below
		printed := awaited(t, frames, fStdout, deadline)
		var pids []int
		for _, field := range strings.Fields(string(printed.payload)) {
			pid, _ := strconv.Atoi(field)
			pids = append(pids, pid)
		}
		if len(pids) == 0 || slices.Contains(pids, 0) { // or the kills below would be of this process's own group
			t.Fatalf("the command printed %q, not its processes", printed.payload)
		}
		t.Cleanup(func() { endAsNobody(pids...) })

		s.dispatch(c, frame{kind: fKill, id: uint64(80 + id)})

		for _, pid := range pids {
			for ; syscall.Kill(pid, 0) != syscall.ESRCH; time.Sleep(10 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatalf("process %d of %q, run as another user, outlived its kill", pid, argv)
				}
			}
		}
		awaited(t, frames, fExit, deadline) // read before the next command's output
	}
	// The user's identity is the killing thread's for its two signals alone; the search's thread may hold it a while yet.
	for ; len(borrowed()) > 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("threads kept the user's identity: %v", borrowed())
		}
	}
}

func TestAKillThatComesBeforeAnotherUsersCommandHasStartedReachesItThoughItCarriesNoTag(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root runs a command as another user")
	}
	open := t.TempDir() // where the user can write
	os.Chmod(open, 0o777)
	os.Chmod(filepath.Dir(open), 0o755)
	cl := &call{id: 82, tag: "early"}
	cl.room = sync.NewCond(&cl.mu)
	pid := filepath.Join(open, "pid")
	req := startRequest{Argv: []string{"env", "-i", "sh", "-c", `echo $$ >"$0"; exec sleep 600`, pid}, Env: map[string]string{}, User: "65534", Tag: "early"}

	cl.kill()     // from another connection, while this one's START is still at work
	cl.kmu.Lock() // and stays at work until the command runs as its user, whom root's signal does not reach without CAP_KILL
	noted := sync.OnceFunc(cl.kmu.Unlock)
	t.Cleanup(noted)
	started := make(chan error, 1)
	go func() { started <- cl.run(req) }()
	var command int
	deadline := time.Now().Add(30 * time.Second) // for the whole test
	for ; command == 0; time.Sleep(10 * time.Millisecond) {
		written, _ := os.ReadFile(pid)
		command, _ = strconv.Atoi(strings.TrimSpace(string(written)))
		if time.Now().After(deadline) {
			t.Fatal("the command never ran")
		}
	}
	t.Cleanup(func() { endAsNobody(command) })
	noted()
	select {
	case err := <-started:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Until(deadline)):
		t.Fatal("the START never returned")
	}

	for ; syscall.Kill(command, 0) != syscall.ESRCH; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("command %d, run as another user with no tag, outlived a kill that came before it started", command)
		}
	}
}

func TestAKillReachesAChildThatLeftTheGroupAndDroppedTheTag(t *testing.T) {
	prctl(prSetChildSubreaper, 1) // as execd: the child is reaped here once killed
	t.Cleanup(func() { prctl(prSetChildSubreaper, 0) })
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	// As runuser --login --command leaves its child: a session of its own, no tag, its parent waiting on it.
	leave := `env -i setsid sh -c 'echo $$; exec sleep 600' & wait`
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", leave}, Env: map[string]string{}, Tag: "tree"})
	s.dispatch(c, frame{kind: fStart, id: 50, payload: req})
	printed := nextFrame(t, frames)
	child, _ := strconv.Atoi(strings.TrimSpace(string(printed.payload)))
	if printed.kind != fStdout || child <= 0 { // or the kills below would be of this process's own group
		t.Fatalf("the command printed %q, not the process it left", printed.payload)
	}
	t.Cleanup(func() { syscall.Kill(child, syscall.SIGKILL) })

	s.dispatch(c, frame{kind: fKill, id: 50})

	for deadline := time.Now().Add(30 * time.Second); syscall.Kill(child, 0) != syscall.ESRCH; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("process %d, which left the command's group and dropped its tag, outlived the kill", child)
		}
	}
}

func TestAKillReachesACommandThatLeftItsOwnGroupAndDroppedTheTag(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	this, _ := os.Executable()
	req, _ := json.Marshal(startRequest{Argv: []string{this, "leave", "/bin/sleep", "600"}, Env: map[string]string{}, Tag: "left"})
	s.dispatch(c, frame{kind: fStart, id: 52, payload: req})
	printed := nextFrame(t, frames)
	command, _ := strconv.Atoi(strings.TrimSpace(string(printed.payload)))
	if printed.kind != fStdout || command <= 0 { // or the kill below would be of this process's own group
		t.Fatalf("the command printed %q, not its id", printed.payload)
	}
	t.Cleanup(func() { syscall.Kill(command, syscall.SIGKILL) })

	s.dispatch(c, frame{kind: fKill, id: 52})

	for deadline := time.Now().Add(30 * time.Second); syscall.Kill(command, 0) != syscall.ESRCH; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("command %d, which left its own group and dropped its tag, outlived its kill", command)
		}
	}
}

func TestAKillThatComesBeforeItsCommandHasStartedReachesAChildThatLeftTheGroupAndDroppedTheTag(t *testing.T) {
	prctl(prSetChildSubreaper, 1) // as execd: the child is reaped here once killed
	t.Cleanup(func() { prctl(prSetChildSubreaper, 0) })
	cl := &call{id: 51, tag: "early"}
	cl.room = sync.NewCond(&cl.mu)
	pid := filepath.Join(t.TempDir(), "pid")
	leave := `env -i setsid sh -c 'echo $$ >"$0"; exec sleep 600' "$0" & wait`
	req := startRequest{Argv: []string{"sh", "-c", leave, pid}, Env: map[string]string{}, Tag: "early"}

	cl.kill()     // from another connection, while this one's START is still at work
	cl.kmu.Lock() // and stays at work until the command's child has left it
	noted := sync.OnceFunc(cl.kmu.Unlock)
	t.Cleanup(noted)
	started := make(chan error, 1)
	go func() { started <- cl.run(req) }()
	var child int
	for deadline := time.Now().Add(30 * time.Second); child == 0; time.Sleep(10 * time.Millisecond) {
		written, _ := os.ReadFile(pid)
		child, _ = strconv.Atoi(strings.TrimSpace(string(written)))
		if time.Now().After(deadline) {
			t.Fatal("the command's child never left it")
		}
	}
	t.Cleanup(func() { syscall.Kill(child, syscall.SIGKILL) })
	noted()
	select {
	case err := <-started:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the START never returned")
	}

	for deadline := time.Now().Add(30 * time.Second); syscall.Kill(child, 0) != syscall.ESRCH; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("process %d, which left the command's group and dropped its tag, outlived a kill that came before it started", child)
		}
	}
}

func TestAKillReachesWhatIsStartedAsItKills(t *testing.T) {
	end := graced(t)
	prctl(prSetChildSubreaper, 1) // as execd: what the kill ends is reaped here
	t.Cleanup(func() { prctl(prSetChildSubreaper, 0) })
	// Fewer descriptors than it has processes to kill: a kill that keeps one for each runs out.
	var limit syscall.Rlimit
	syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit)
	t.Cleanup(func() { nofile(limit) })
	open, _ := os.ReadDir("/proc/self/fd")
	nofile(syscall.Rlimit{Cur: uint64(len(open)) + 32, Max: limit.Max})
	s, _ := newServer(strings.Repeat("00", 32))
	c := testConn(t)
	s.authenticated(c)
	this, _ := os.Executable()
	// In the middle of starting 3,000 processes, each out of the group and with no tag: more than eight listings take.
	starting := `trap "" TERM; i=0; while [ $i -lt 3000 ]; do env -i setsid sleep "$0" & i=$((i+1)); done; wait` // deaf to SIGTERM: the SIGKILL of a grace's end must reach each
	for id := uint64(60); id < 72; id++ {                                                                        // a kill that lists them once, or lets their starter run on, leaves one in most
		mark := "600." + strconv.Itoa(int(id))
		argv := []string{"sh", "-c", starting, mark} // the command starts them itself
		switch id % 4 {
		case 1: // or its child does, out of the group itself
			argv = []string{"sh", "-c", `setsid sh -c "$1" "$0" & wait`, mark, starting}
		case 2: // or it does, out of its own group
			argv = []string{this, "leave", "/bin/sh", "-c", starting, mark}
		case 3: // or its child does, for longer than a kill waits for a process to stop
			argv = []string{"sh", "-c", `setsid sh -c "$1" "$0" & wait`, mark, strings.Replace(starting, "&", "& sleep 0.001;", 1)}
		}
		req, _ := json.Marshal(startRequest{Argv: argv, Env: map[string]string{}, Tag: "starting" + mark}) // its own: the last one's kill may still be searching by its tag
		live := func() (pids []int) {                                                                      // what it started, and itself, by their last argument
			entries, _ := os.ReadDir("/proc")
			for _, e := range entries {
				cmdline, _ := os.ReadFile("/proc/" + e.Name() + "/cmdline")
				if pid, _ := strconv.Atoi(e.Name()); strings.HasSuffix(string(cmdline), "\x00"+mark+"\x00") {
					pids = append(pids, pid)
				}
			}
			return pids
		}
		t.Cleanup(func() {
			for _, pid := range live() {
				syscall.Kill(pid, syscall.SIGKILL)
			}
		})
		s.dispatch(c, frame{kind: fStart, id: id, payload: req})
		for deadline := time.Now().Add(30 * time.Second); len(live()) < 100; time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("the command never started its processes")
			}
		}

		s.dispatch(c, frame{kind: fKill, id: id})
		end()

		for deadline := time.Now().Add(30 * time.Second); len(live()) > 0; time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%d processes the command started outlived its kill", len(live()))
			}
		}
	}
}

func TestAKillReachesWhatIsStartedWhileItSearchesByTag(t *testing.T) {
	prctl(prSetChildSubreaper, 1) // as execd: what the command detached is reaped here once it ends
	t.Cleanup(func() { prctl(prSetChildSubreaper, 0) })
	s, _ := newServer(strings.Repeat("00", 32))
	c := testConn(t)
	s.authenticated(c)
	base := filepath.Join(t.TempDir(), "detached")
	// Out of the command's group and no longer its child, only the tag leads a kill to it; signalled, it starts its successor and ends.
	detached := `trap 'sleep 600 & echo $! > "$0.new"; exit' USR1; echo $$ > "$0.pid"; while :; do sleep 0.01; done`
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", `(setsid sh -c "$1" "$0" &); sleep 600`, base, detached}, Env: map[string]string{}, Tag: "handoff"})
	s.dispatch(c, frame{kind: fStart, id: 73, payload: req})
	t.Cleanup(func() { s.dispatch(c, frame{kind: fKill, id: 73}) }) // whatever fails below
	deadline := time.Now().Add(30 * time.Second)                    // for the whole test
	named := func(file string) (pid int) {                          // the process a file names, once the file is written
		for ; pid == 0 && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
			if data, _ := os.ReadFile(file); bytes.HasSuffix(data, []byte("\n")) {
				pid, _ = strconv.Atoi(strings.TrimSpace(string(data)))
			}
		}
		return pid
	}
	first, second := named(base+".pid"), 0
	for ; first != 0 && !orphaned(first) && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
	}
	if first == 0 || !orphaned(first) {
		t.Fatal("the command never detached its process")
	}
	var once sync.Once
	handoff := func(tag, environ string) (*os.File, error) { // listed by this kill's search, the detached process is gone before it is read
		if tag == "handoff" {
			once.Do(func() {
				syscall.Kill(first, syscall.SIGUSR1)
				second = named(base + ".new")
				for ; syscall.Kill(first, 0) != syscall.ESRCH && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
				}
			})
		}
		return os.Open(environ)
	}
	openEnviron.Store(&handoff)
	t.Cleanup(func() {
		openEnviron.Store(nil)
		for _, pid := range []int{first, second} {
			if pid > 0 {
				syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})

	s.dispatch(c, frame{kind: fKill, id: 73})

	if second == 0 {
		t.Fatal("the detached process started nothing as the kill searched")
	}
	for ; syscall.Kill(second, 0) != syscall.ESRCH; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("process %d, started by one the kill's search had listed and that ended before it was read, outlived the kill", second)
		}
	}
}

// orphaned says whether pid is this process's own child by now.
func orphaned(pid int) bool {
	f := stat(pid)
	return len(f) > 1 && f[1] == strconv.Itoa(os.Getpid())
}

// detach starts a command whose process is out of its group and no longer its child, so that only the tag leads a kill to it.
func detach(t *testing.T, id uint64, tag string) (detached int, kill func(), deadline time.Time) {
	prctl(prSetChildSubreaper, 1) // as execd: what the command detached is reaped here once killed
	t.Cleanup(func() { prctl(prSetChildSubreaper, 0) })
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", `(setsid sh -c 'echo $$; exec sleep 600' &); sleep 600`}, Env: map[string]string{}, Tag: tag})
	deadline = time.Now().Add(30 * time.Second) // for the whole test
	kill = func() { s.dispatch(c, frame{kind: fKill, id: id}) }
	s.dispatch(c, frame{kind: fStart, id: id, payload: req})
	t.Cleanup(kill) // whatever fails
	printed := awaited(t, frames, fStdout, deadline)
	detached, _ = strconv.Atoi(strings.TrimSpace(string(printed.payload)))
	if detached <= 0 { // or the kill would be of this process's own group
		t.Fatalf("the command printed %q, not the process it detached", printed.payload)
	}
	t.Cleanup(func() { syscall.Kill(detached, syscall.SIGKILL) })
	for ; !orphaned(detached); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the command never detached its process")
		}
	}
	return detached, kill, deadline
}

func TestAKillReachesAProcessWhoseEnvironmentWasNotYetInPlaceWhenFirstRead(t *testing.T) {
	detached, kill, deadline := detach(t, 74, "starting up")
	shown := false
	starting := func(tag, environ string) (*os.File, error) { // as the kernel shows a process whose execve is under way: no environment, then its own
		if tag == "starting up" && environ == "/proc/"+strconv.Itoa(detached)+"/environ" && !shown {
			shown = true
			return os.Open(os.DevNull)
		}
		return os.Open(environ)
	}
	openEnviron.Store(&starting)
	t.Cleanup(func() { openEnviron.Store(nil) })

	kill()

	for ; syscall.Kill(detached, 0) != syscall.ESRCH; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("process %d, whose environment was not yet in place when the kill's search first read it, outlived the kill", detached)
		}
	}
}

func TestAKillReachesAProcessWhoseEnvironmentIsGoneAfterItsFirstRead(t *testing.T) {
	detached, kill, deadline := detach(t, 75, "one read")
	once := func(tag, environ string) (*os.File, error) { // as of a process about to execve: one read takes what it asks, the next finds none
		if tag != "one read" || environ != "/proc/"+strconv.Itoa(detached)+"/environ" {
			return os.Open(environ)
		}
		record, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0) // a short read loses its record's rest
		if err != nil {
			return nil, err
		}
		syscall.Write(record[1], append(bytes.Repeat([]byte("PAD=x\x00"), 100), "HAWK_NEXT_EXEC=one read\x00"...)) // its tag past 512 bytes
		syscall.Close(record[1])
		return os.NewFile(uintptr(record[0]), environ), nil
	}
	openEnviron.Store(&once)
	t.Cleanup(func() { openEnviron.Store(nil) })

	kill()

	for ; syscall.Kill(detached, 0) != syscall.ESRCH; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("process %d, whose environment was gone after the first read of it, outlived the kill", detached)
		}
	}
}

func TestAKillReachesAProcessWhoseTagIsPastTheFirstReadOfAnEnvironmentThatOpensNoThirdTime(t *testing.T) {
	detached, kill, deadline := detach(t, 76, "second read")
	environment := filepath.Join(t.TempDir(), "environ") // more than the first read takes, its tag past that, and more than the second takes after it
	pad := bytes.Repeat([]byte("PAD=x\x00"), 1000)
	if err := os.WriteFile(environment, append(append(pad, "HAWK_NEXT_EXEC=second read\x00"...), bytes.Repeat(pad, 4)...), 0o600); err != nil {
		t.Fatal(err)
	}
	opens := 0
	twice := func(tag, environ string) (*os.File, error) { // as of a process that makes its environment unreadable while the search reads it
		if tag != "second read" || environ != "/proc/"+strconv.Itoa(detached)+"/environ" {
			return os.Open(environ)
		}
		if opens++; opens > 2 {
			return nil, syscall.EACCES
		}
		return os.Open(environment)
	}
	openEnviron.Store(&twice)
	t.Cleanup(func() { openEnviron.Store(nil) })

	kill()

	for ; syscall.Kill(detached, 0) != syscall.ESRCH; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("process %d, whose tag the search's second read of its environment held, outlived the kill", detached)
		}
	}
}

func TestAKillReadsALargeEnvironmentInOneReadOnceItHasMadeRoomForIt(t *testing.T) {
	detached, kill, deadline := detach(t, 77, "kept room")
	environment := filepath.Join(t.TempDir(), "environ") // more than the first read takes, its tag at its end
	if err := os.WriteFile(environment, append(bytes.Repeat([]byte("PAD=x\x00"), 1000), "HAWK_NEXT_EXEC=kept room\x00"...), 0o600); err != nil {
		t.Fatal(err)
	}
	opens := 0
	emptied := func(tag, environ string) (*os.File, error) { // as of a process that execs itself in a loop: every second read finds none
		if tag != "kept room" || environ != "/proc/"+strconv.Itoa(detached)+"/environ" {
			return os.Open(environ)
		}
		if opens++; opens%2 == 0 {
			return os.Open(os.DevNull)
		}
		return os.Open(environment)
	}
	openEnviron.Store(&emptied)
	t.Cleanup(func() { openEnviron.Store(nil) })

	kill()

	for ; syscall.Kill(detached, 0) != syscall.ESRCH; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("process %d, whose environment took two reads at first and was gone at every second one, outlived the kill", detached)
		}
	}
}

func TestAKillsSearchReadsAgainOnlyAProcessThatMayYetShowItsEnvironment(t *testing.T) {
	keeper := exec.Command("sh", "-c", "sleep 0 & exec sleep 600") // the sleep the shell becomes reaps nothing: its child stays a zombie
	bare := exec.Command("sleep", "600")
	bare.Env = []string{} // it runs with no environment, as after `env -i`
	for _, c := range []*exec.Cmd{keeper, bare} {
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Process.Kill() })
	}
	zombie := 0
	deadline := time.Now().Add(30 * time.Second) // for the whole test
	for ; zombie == 0; time.Sleep(time.Millisecond) {
		entries, _ := os.ReadDir("/proc")
		for _, e := range entries {
			pid, _ := strconv.Atoi(e.Name())
			if f := stat(pid); len(f) > 1 && f[0] == "Z" && f[1] == strconv.Itoa(keeper.Process.Pid) {
				zombie = pid
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the shell's child never ended")
		}
	}
	ended, running := "/proc/"+strconv.Itoa(zombie)+"/environ", "/proc/"+strconv.Itoa(bare.Process.Pid)+"/environ"
	reads := map[string]int{}
	counted := func(tag, environ string) (*os.File, error) {
		if tag == "no process carries it" {
			reads[environ]++
			if environ == ended { // as the kernels that open a zombie's show it: empty (this one may refuse the open)
				return os.Open(os.DevNull)
			}
			if environ != running { // another's process with no environment would keep a search with no bound going
				return nil, os.ErrNotExist
			}
		}
		return os.Open(environ)
	}
	openEnviron.Store(&counted)
	t.Cleanup(func() { openEnviron.Store(nil) })

	var waited time.Duration
	synctest.Test(t, func(t *testing.T) { // on a clock that only the search's own waits move
		began, searched := time.Now(), make(chan struct{})
		go func() { killTagged("no process carries it"); close(searched) }()
		select {
		case <-searched:
		case <-time.After(time.Second): // a thousand of its waits
			bare.Process.Kill() // it ends once nothing shows an empty environment
			<-searched
			t.Fatal("the search did not end beside a process that shows no environment")
		}
		waited = time.Since(began)
	})

	// The one that has ended will never show one; the other may, and is read again once it has had time.
	if reads[ended] != 1 || reads[running] < 2 || waited == 0 {
		t.Fatalf("the search read the environment of a process that has ended %d times, and of one that runs and shows none %d times, and waited %v", reads[ended], reads[running], waited)
	}
}

func TestAKillReadsNoMoreOfAnEnvironmentThanOneCanHold(t *testing.T) {
	huge := filepath.Join(t.TempDir(), "environ")
	if err := os.WriteFile(huge, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(huge, 1<<30); err != nil { // as prctl(PR_SET_MM_MAP) lets any process make its own look
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	room := make([]byte, 4<<10)
	tagged(os.Open, huge, []byte("HAWK_NEXT_EXEC=huge\x00"), &room)

	runtime.ReadMemStats(&after)
	if took := (after.TotalAlloc - before.TotalAlloc) >> 20; took > 64 {
		t.Fatalf("took %d MiB to read an environment of 1 GiB", took)
	}
}

func TestAKillThatComesBeforeItsCommandHasStartedReachesWhatItLeftRunning(t *testing.T) {
	prctl(prSetChildSubreaper, 1) // as execd: what the command leaves running is reaped here once killed
	t.Cleanup(func() { prctl(prSetChildSubreaper, 0) })
	t.Cleanup(func() { killTagged("ended") })
	cl := &call{id: 33, tag: "ended"}
	cl.room = sync.NewCond(&cl.mu)
	pids := filepath.Join(t.TempDir(), "pids")
	// It leaves two processes: one in its group with no tag, one with its tag in a session of its own.
	leave := `env -i sleep 600 >/dev/null 2>&1 & grouped=$!; setsid sleep 600 >/dev/null 2>&1 & echo $$ $grouped $! >"$0"`
	req := startRequest{Argv: []string{"sh", "-c", leave, pids}, Env: map[string]string{}, Tag: "ended"}

	cl.kill()     // from another connection, while this one's START is still at work
	cl.kmu.Lock() // and stays at work: the command has ended before the START notes its id
	noted := sync.OnceFunc(cl.kmu.Unlock)
	t.Cleanup(noted)
	started := make(chan error, 1)
	go func() { started <- cl.run(req) }()
	var leader, grouped, detached int
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if b, _ := os.ReadFile(pids); len(strings.Fields(string(b))) == 3 {
			leader, _ = strconv.Atoi(strings.Fields(string(b))[0])
			grouped, _ = strconv.Atoi(strings.Fields(string(b))[1])
			detached, _ = strconv.Atoi(strings.Fields(string(b))[2])
		}
		// Ended and not reaped: the START holds the reaper's lock until it has noted the id.
		if stat, _ := os.ReadFile("/proc/" + strconv.Itoa(leader) + "/stat"); detached != 0 && strings.Contains(string(stat), ") Z ") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the command never ended")
		}
	}
	noted()
	select {
	case err := <-started:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the START never returned")
	}

	// Only the signal to its group reaches the first, only the search for its tag the second.
	for _, left := range []int{grouped, detached} {
		for deadline := time.Now().Add(30 * time.Second); syscall.Kill(left, 0) == nil; time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("process %d, which the command left running, outlived a kill that came before it started", left)
			}
		}
	}
}

func TestWhatACommandLeftRunningOutlivesItsAbandonedCall(t *testing.T) {
	var timers []func()
	afterFunc = func(_ time.Duration, f func()) *time.Timer { timers = append(timers, f); return nil }
	t.Cleanup(func() { afterFunc = time.AfterFunc })
	s, _ := newServer(strings.Repeat("00", 32))
	alive := filepath.Join(t.TempDir(), "alive")
	t.Cleanup(func() { killTagged("left") })
	// Once let go, it leaves a loop running that keeps putting a file back, prints and ends.
	left := `until [ -e "$0.go" ]; do sleep 0.01; done; (while :; do : >"$0"; sleep 0.01; done) >/dev/null 2>&1 & echo x`
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", left, alive}, Env: map[string]string{}, Tag: "left"})
	c := testConn(t)
	s.start(c, frame{kind: fStart, id: 28, payload: req})
	cl := s.get(28)
	cl.output(0, make([]byte, maxUnacked+1)) // all execd holds for a client: its exit waits on what it prints
	os.WriteFile(alive+".go", nil, 0o644)
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		cl.kmu.Lock()
		ended := cl.pid == 0
		cl.kmu.Unlock()
		if ended {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the command never ended")
		}
	}
	s.detach(c)

	timers[0]() // six minutes with no client
	cl.kill()   // and the client's KILL, on finding the call abandoned

	os.Remove(alive)
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(alive); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("what the command left running was killed after it ended")
		}
	}
}

func TestAnExitDoesNotWaitForWhatTheCommandLeftHoldingItsOutput(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	t.Cleanup(func() { killTagged("holder") })
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", "sleep 600 & echo x"}, Env: map[string]string{}, Tag: "holder"})

	s.dispatch(c, frame{kind: fStart, id: 40, payload: req})

	if status := exitStatus(t, frames); status["code"] != 0.0 { // no EXIT: it waited for the sleeper
		t.Fatalf("the exit was %v", status)
	}
}

// unheld waits for execd to have closed the pipe.
func unheld(t *testing.T, pipe, why string) {
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		held := false
		fds, _ := os.ReadDir("/proc/self/fd")
		for _, fd := range fds {
			link, _ := os.Readlink("/proc/self/fd/" + fd.Name())
			held = held || link == pipe
		}
		if !held {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("execd still holds %s, %s", pipe, why)
		}
	}
}

func TestACommandsPipeIsClosedWhenItsOutputEnds(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1)) // for unheld
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	req, _ := json.Marshal(startRequest{Argv: []string{"readlink", "/proc/self/fd/1"}, Env: map[string]string{}, Tag: "ended"})
	s.dispatch(c, frame{kind: fStart, id: 43, payload: req})
	var pipe string
	for f := nextFrame(t, frames); f.kind != fExit; f = nextFrame(t, frames) {
		if f.kind == fStdout {
			pipe += string(f.payload)
		}
	}

	unheld(t, strings.TrimSpace(pipe), "whose command has ended")
}

// mkfifo makes a FIFO and opens it for both ends, so neither a test nor the process it talks to waits to open it.
func mkfifo(t *testing.T, path string) *os.File {
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestWhatACommandLeftRunningStillWritesToItsOutput(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1)) // for unheld
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	t.Cleanup(func() { killTagged("writer") })
	base := filepath.Join(t.TempDir(), "f")
	let, wrote := mkfifo(t, base+".go"), mkfifo(t, base+".wrote")
	// It says which pipe its stdout is, and leaves a process that writes to it each time it is let go.
	left := `trap "" PIPE; readlink /proc/$$/fd/1; (for i in 1 2 3 4 5 6 7 8; do read go <"$0.go"; echo late; out=$?; echo late >&2; echo $out$? >"$0.wrote"; done) &`
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", left, base}, Env: map[string]string{}, Tag: "writer"})
	s.dispatch(c, frame{kind: fStart, id: 41, payload: req})
	var pipe string
	for f := nextFrame(t, frames); f.kind != fExit; f = nextFrame(t, frames) {
		if f.kind == fStdout {
			pipe += string(f.payload)
		}
	}
	pipe = strings.TrimSpace(pipe)

	for range 8 { // more than once: a pipe closed at the first write fails a later one
		let.Write([]byte("\n")) // the command has ended, and its call with it
		wrote.SetReadDeadline(time.Now().Add(30 * time.Second))
		said := make([]byte, 8)
		n, _ := wrote.Read(said)
		if string(said[:n]) != "00\n" { // a server left running this way logs each request to its stderr: over Kubernetes exec it goes on answering
			t.Fatalf("its writes to stdout and stderr ended with statuses %q, want 00", said[:n])
		}
	}
	unheld(t, pipe, "which no process has open to write")
}

func TestWhatACommandLeftRunningMayWriteBeforeItWaits(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1)) // for unheld
	// looks counts how often execd, past what it takes of a pipe, has looked whether its writers have gone.
	var looks atomic.Int32
	note := func(bool) { looks.Add(1) }
	afterTaken.Store(&note)
	t.Cleanup(func() { afterTaken.Store(nil) })
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	t.Cleanup(func() { killTagged("spender") })
	base := filepath.Join(t.TempDir(), "f")
	let, wrote := mkfifo(t, base+".go"), mkfifo(t, base+".wrote")
	// It says which pipe its stdout is, and leaves a process that writes there as many bytes as it is told.
	left := `readlink /proc/$$/fd/1; (while read n <"$0.go"; do head -c "$n" /dev/zero && echo "$n" >"$0.wrote"; done) &`
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", left, base}, Env: map[string]string{}, Tag: "spender"})
	s.dispatch(c, frame{kind: fStart, id: 44, payload: req})
	var pipe string
	for f := nextFrame(t, frames); f.kind != fExit; f = nextFrame(t, frames) {
		if f.kind == fStdout {
			pipe += string(f.payload)
		}
	}
	pipe = strings.TrimSpace(pipe)
	var held uintptr // execd's end of that pipe, which this process has
	fds, _ := os.ReadDir("/proc/self/fd")
	for _, fd := range fds {
		if link, _ := os.Readlink("/proc/self/fd/" + fd.Name()); link == pipe {
			n, _ := strconv.Atoi(fd.Name())
			held = uintptr(n)
		}
	}
	write := func(n int, why string) {
		let.Write([]byte(strconv.Itoa(n) + "\n"))
		wrote.SetReadDeadline(time.Now().Add(30 * time.Second))
		if _, err := wrote.Read(make([]byte, 16)); err != nil {
			t.Fatalf("its write of %d bytes has not gone through, %s", n, why)
		}
	}
	unread := func() (n int32) {
		syscall.Syscall(syscall.SYS_IOCTL, held, syscall.TIOCINQ, uintptr(unsafe.Pointer(&n)))
		return
	}
	write(136<<10, "which over Kubernetes exec does on runc and gVisor: a server left running that has logged as much goes on answering")
	// All but a byte of what execd takes, and all of it read: the two bytes that follow come in one read, which may take one.
	write(1<<20-136<<10-1, "which is the rest of the megabyte execd takes, but a byte")
	for deadline := time.Now().Add(30 * time.Second); unread() > 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d bytes wait unread of what execd takes of a pipe", unread())
		}
	}
	write(2, "which the pipe has room for")
	// Read without end, a writer that never stops would have the sandbox's CPU; over Kubernetes exec it waits.
	for deadline := time.Now().Add(30 * time.Second); looks.Load() == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("execd does not wait on the pipe once it has what it takes: it reads on, or has let the pipe go")
		}
	}

	if n := unread(); n != 1 {
		t.Fatalf("%d bytes wait unread, want the one written past what execd takes: execd has read on, or has let the pipe go", n)
	}
	// What execd's epoll is asked to tell of each pipe: of this one, that its writers have gone, and not that it holds more to read.
	asked, _ := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(keeper))
	want := "tfd: " + strconv.Itoa(int(held)) + " events: " + strconv.FormatInt(syscall.EPOLLERR|syscall.EPOLLHUP, 16) + " "
	if !strings.Contains(strings.Join(strings.Fields(string(asked)), " "), want) {
		t.Fatalf("of a pipe it reads no more, execd's epoll is asked:\n%swant %q: a write to the pipe must not wake execd", asked, want)
	}
	killTagged("spender")
	unheld(t, pipe, "which it had stopped reading and no process has open to write")
}

// answered has one call of this thread's return an errno from now on (0: nothing, with nothing done), as a seccomp profile can.
func answered(call uintptr, answer syscall.Errno) syscall.Errno {
	runtime.LockOSThread() // the filter is this thread's, which ends with its goroutine
	filter := []syscall.SockFilter{
		{Code: 0x20, K: 0},                        // the call's number
		{Code: 0x15, Jf: 1, K: uint32(call)},      // another call: allowed
		{Code: 0x06, K: 0x50000 | uint32(answer)}, // SECCOMP_RET_ERRNO
		{Code: 0x06, K: 0x7fff0000},               // SECCOMP_RET_ALLOW
	}
	prog := syscall.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	const prSetNoNewPrivs, prSetSeccomp, seccompModeFilter = 38, 22, 2
	prctl(prSetNoNewPrivs, 1) // without it a filter needs CAP_SYS_ADMIN
	_, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilter, uintptr(unsafe.Pointer(&prog)))
	return errno
}

// startedWith is what this process was handed besides its stdio, and hands every child in turn: a CI runner's own pipes.
var startedWith = func() (links []string) {
	fds, _ := os.ReadDir("/proc/self/fd")
	for _, fd := range fds {
		n, _ := strconv.Atoi(fd.Name())
		if flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(n), syscall.F_GETFD, 0); n > 2 && errno == 0 && flags&syscall.FD_CLOEXEC == 0 {
			link, _ := os.Readlink("/proc/self/fd/" + fd.Name())
			links = append(links, link)
		}
	}
	return links
}()

func TestACommandGetsNoDescriptorOfExecdsOwn(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	t.Cleanup(func() { killTagged("keeps") })
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", "sleep 600 &"}, Env: map[string]string{}, Tag: "keeps"})
	s.dispatch(c, frame{kind: fStart, id: 45, payload: req})
	exitStatus(t, frames) // its two pipes are kept now

	req, _ = json.Marshal(startRequest{Argv: []string{"sh", "-c", `for fd in /proc/$$/fd/*; do readlink "$fd"; done`}, Env: map[string]string{}, Tag: "lists"})
	s.dispatch(c, frame{kind: fStart, id: 46, payload: req})
	var open string
	for f := nextFrame(t, frames); f.kind != fExit; f = nextFrame(t, frames) {
		if f.kind == fStdout {
			open += string(f.payload)
		}
	}
	has := strings.Fields(open)
	for _, link := range startedWith { // past its stdin, which is listed first
		if i := slices.Index(has[min(1, len(has)):], link); i >= 0 {
			has = slices.Delete(has, i+1, i+2)
		}
	}
	if len(has) != 3 || has[0] != os.DevNull || !strings.HasPrefix(has[1], "pipe:") || !strings.HasPrefix(has[2], "pipe:") {
		t.Fatalf("a command has %q open, want its stdin and its two pipes: with a kept pipe it reads what another call's process writes, and with the keeper's epoll it has execd close what it names", has)
	}
}

func TestAPipeExecdCannotKeepIsLetGo(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	place := make(chan struct{}, 1) // its own: execd's are taken and given back by what other tests left running
	place <- struct{}{}

	keep(r, -1, place) // as where execd had no descriptor for a keeper at its start

	if _, err := w.Write([]byte("late")); err == nil {
		t.Fatal("a write to the pipe went through: execd holds a pipe that nothing will let go")
	}
	if len(place) != 0 {
		t.Fatal("the pipe's place was not given back: each one lost is a pipe the less that execd keeps")
	}
}

func TestAKillOfACommandAlreadyReapedLeavesTheCommandThatHasItsIdNow(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	alive := filepath.Join(t.TempDir(), "alive")
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", `while :; do : >"$0"; sleep 0.01; done`, alive}, Env: map[string]string{}, Tag: "other"})
	s.start(testConn(t), frame{kind: fStart, id: 32, payload: req})
	other := s.get(32)
	t.Cleanup(other.kill)
	other.kmu.Lock()
	// A call whose command was reaped, its end not yet noted: the id it still holds is another command's by now.
	cl := &call{id: 37, tag: "reaped", pid: other.pid, status: make(chan syscall.WaitStatus, 1)}
	other.kmu.Unlock()

	cl.kill()

	os.Remove(alive)
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(alive); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("a kill reached the command that had been given its own command's id")
		}
	}
}

func TestStdinACommandLeftUnreadIsLetGoWhenTheCommandEnds(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	t.Cleanup(func() { killTagged("unread") })
	// It leaves a process holding its stdin, says which pipe that is, and ends.
	left := `exec 3<&0; sleep 600 <&3 >/dev/null 2>&1 & readlink /proc/$$/fd/0`
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", left}, Env: map[string]string{}, Stdin: true, Tag: "unread"})
	c, frames := recordedConn(t)
	s.authenticated(c)
	s.dispatch(c, frame{kind: fStart, id: 35, payload: req})
	s.dispatch(c, frame{kind: fStdin, id: 35, payload: make([]byte, 1<<20)}) // more than a pipe holds
	var pipe string
	deadline := time.After(30 * time.Second)
	for exited := false; !exited; {
		select {
		case f := <-frames:
			if f.kind == fStdout {
				pipe += string(f.payload)
			}
			exited = f.kind == fExit
		case <-deadline:
			t.Fatal("no EXIT")
		}
	}
	if pipe = strings.TrimSpace(pipe); !strings.HasPrefix(pipe, "pipe:") {
		t.Fatalf("the command's stdin was %q, want a pipe", pipe)
	}

	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		held := false
		fds, _ := os.ReadDir("/proc/self/fd")
		for _, fd := range fds {
			link, _ := os.Readlink("/proc/self/fd/" + fd.Name())
			held = held || link == pipe
		}
		if !held {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("execd still holds %s, the stdin of a command that has ended", pipe)
		}
	}
}

func TestStdinACommandLeftUnreadIsLetGoWhenItsCallIsReleased(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"sleep", "600"}, Env: map[string]string{}, Stdin: true, Tag: "queued"})
	c := testConn(t)
	s.authenticated(c)
	s.dispatch(c, frame{kind: fStart, id: 37, payload: req})
	cl := s.get(37)
	s.dispatch(c, frame{kind: fStdin, id: 37, payload: make([]byte, 1<<20)}) // more than a pipe holds: its writer waits
	chunk := make([]byte, 1<<20)
	queued := weak.Make(&chunk[0])
	s.dispatch(c, frame{kind: fStdin, id: 37, payload: chunk})

	s.detach(c) // its timer holds the call for six minutes
	cl.kill()
	exitCode(t, cl)
	s.release(37)

	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if runtime.GC(); queued.Value() == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("execd still holds the stdin of a call that is released")
		}
	}
}

func TestStdinACommandHasReadIsLetGoWhileItRuns(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", "cat >/dev/null"}, Env: map[string]string{}, Stdin: true, Tag: "read"})
	c, frames := recordedConn(t)
	s.authenticated(c)
	s.dispatch(c, frame{kind: fStart, id: 36, payload: req})
	chunk := make([]byte, 1<<20)
	sent := weak.Make(&chunk[0])
	s.dispatch(c, frame{kind: fStdin, id: 36, payload: chunk})
	if f := nextFrame(t, frames); f.kind != fStdinAck { // written to the command
		t.Fatalf("frame %d came before the stdin ack", f.kind)
	}

	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if runtime.GC(); sent.Value() == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("execd still holds stdin its command has read")
		}
	}
	s.dispatch(c, frame{kind: fStdin, id: 36})
	exitStatus(t, frames)
}

func TestAKillOfACommandThatEndedAndIsNotYetReapedLeavesWhatItLeftRunning(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	alive := filepath.Join(t.TempDir(), "alive")
	t.Cleanup(func() { killTagged("unreaped") })
	// Once let go, it leaves a loop running that keeps putting a file back, and ends.
	left := `read x; (while :; do : >"$0"; sleep 0.01; done) >/dev/null 2>&1 &`
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", left, alive}, Env: map[string]string{}, Stdin: true, Tag: "unreaped"})
	c := testConn(t)
	s.authenticated(c)
	s.dispatch(c, frame{kind: fStart, id: 34, payload: req})
	cl := s.get(34)
	cl.kmu.Lock()
	pid := cl.pid
	cl.kmu.Unlock()
	reaper.mu.Lock() // the command ends, and nothing reaps it
	reaped := sync.OnceFunc(reaper.mu.Unlock)
	t.Cleanup(reaped)
	s.dispatch(c, frame{kind: fStdin, id: 34, payload: []byte("\n")})
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		stat, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if strings.Contains(string(stat), ") Z ") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the command never ended")
		}
	}
	killed := make(chan struct{})

	go func() { cl.kill(); close(killed) }() // as its timeout does

	select {
	case <-killed:
	case <-time.After(30 * time.Second):
		t.Fatal("a kill of a command that had ended went on to signal its group, once it was reaped")
	}
	os.Remove(alive)
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(alive); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("what the command left running was killed after it ended")
		}
	}
}

func TestAKillThatFindsItsCommandRunningLeavesWhatItLeftRunningIfItEndsFirst(t *testing.T) {
	for name, told := range map[string]bool{"seen to end": true, "where waitid tells nothing": false} {
		t.Run(name, func(t *testing.T) {
			s, _ := newServer(strings.Repeat("00", 32))
			alive := filepath.Join(t.TempDir(), "alive")
			tag := strconv.FormatInt(time.Now().UnixNano(), 36) // its own: the last run's kill may still be searching
			t.Cleanup(func() { killTagged(tag) })
			// Once let go, it leaves a loop running that keeps putting a file back, and ends.
			left := `read x; (while :; do : >"$0"; sleep 0.01; done) >/dev/null 2>&1 &`
			req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", left, alive}, Env: map[string]string{}, Stdin: true, Tag: tag})
			c, frames := recordedConn(t)
			s.authenticated(c)
			s.dispatch(c, frame{kind: fStart, id: 36, payload: req})
			cl := s.get(36)
			cl.kmu.Lock()
			pid := cl.pid
			cl.kmu.Unlock()
			found, kill, killed := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			hold := func(bool) { once.Do(func() { close(found); <-kill }) } // the kill waits here, holding the reaper's lock
			beforeKill.Store(&hold)
			t.Cleanup(func() { beforeKill.Store(nil) })
			letGo := sync.OnceFunc(func() { close(kill) }) // at a failure too: held, the kill keeps the reaper's lock from the tests that follow
			t.Cleanup(letGo)
			go func() {
				defer close(killed)
				if !told && answered(syscall.SYS_WAITID, 0) != 0 { // it returns, and has told nothing: the reaper alone knows of the end
					t.Error("seccomp refused the filter")
					return
				}
				s.dispatch(c, frame{kind: fKill, id: 36}) // as a client sends for a call it gives up
			}()
			select {
			case <-found:
			case <-time.After(30 * time.Second):
				t.Fatal("the kill never found the command running")
			}
			s.dispatch(c, frame{kind: fStdin, id: 36, payload: []byte("\n")})
			for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				stat, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
				if strings.Contains(string(stat), ") Z ") {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the command never ended")
				}
			}

			letGo()

			select {
			case <-killed:
			case <-time.After(30 * time.Second):
				t.Fatal("the kill never returned")
			}
			if status := exitStatus(t, frames); status["code"] != 0.0 || status["timeout"] != nil {
				t.Fatalf("EXIT %v, want the command's own status 0 and no timeout", status)
			}
			os.Remove(alive)
			for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				if _, err := os.Stat(alive); err == nil {
					return
				}
				if time.Now().After(deadline) {
					t.Fatal("what the command left running was killed, and its exit says it ended by itself: its caller takes it all for done")
				}
			}
		})
	}
}

func TestACommandAKillFoundRunningCannotEndByItselfBeforeTheKill(t *testing.T) {
	user := map[bool]string{true: "65534"}[os.Getuid() == 0] // as one root's own SIGSTOP does not reach without CAP_KILL, as in CI's second job
	s, _ := newServer(strings.Repeat("00", 32))
	tag := strconv.FormatInt(time.Now().UnixNano(), 36) // its own: the last run's kill may still be searching
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", "echo up; read x; exit 3"}, Env: map[string]string{}, Stdin: true, User: user, Tag: tag})
	c, frames := recordedConn(t)
	s.authenticated(c)
	s.dispatch(c, frame{kind: fStart, id: 37, payload: req})
	awaited(t, frames, fStdout, time.Now().Add(30*time.Second)) // it runs as its user: its launcher is still root's to stop
	cl := s.get(37)
	cl.kmu.Lock()
	pid := cl.pid
	cl.kmu.Unlock()
	found, kill := make(chan struct{}), make(chan struct{})
	var stopped [128]byte       // a siginfo_t: waitid sets its first field for a child that has stopped
	hold := func(looked bool) { // the kill waits here once it has looked again, holding the reaper's lock
		if looked {
			syscall.Syscall6(syscall.SYS_WAITID, 1, uintptr(pid), uintptr(unsafe.Pointer(&stopped)), syscall.WSTOPPED|syscall.WNOHANG|syscall.WNOWAIT, 0, 0)
			close(found)
			<-kill
		}
	}
	beforeKill.Store(&hold)
	t.Cleanup(func() { beforeKill.Store(nil) })
	letGo := sync.OnceFunc(func() { close(kill) }) // at a failure too: held, the kill keeps the reaper's lock from the tests that follow
	t.Cleanup(letGo)
	go s.dispatch(c, frame{kind: fKill, id: 37}) // as a client sends for a call it gives up
	select {
	case <-found:
	case <-time.After(30 * time.Second):
		t.Fatal("the kill never found the command running")
	}
	if stopped[0] == 0 {
		t.Fatal("the kill looked last at a command it had not seen stop: it can still end by itself before the kill")
	}
	s.dispatch(c, frame{kind: fStdin, id: 37, payload: []byte("\n")}) // on which it would end at once, if it still ran

	letGo()

	if status := exitStatus(t, frames); status["code"] != 143.0 {
		t.Fatalf("EXIT %v: the command ended by itself after the kill's last look, and the kill went on to end what it left running", status)
	}
}

func TestAKillGoesAheadWhereNothingSaysItsCommandHasStopped(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	tag := strconv.FormatInt(time.Now().UnixNano(), 36) // its own: the last run's kill may still be searching
	t.Cleanup(func() { killTagged(tag) })
	req, _ := json.Marshal(startRequest{Argv: []string{"sleep", "600"}, Env: map[string]string{}, Tag: tag})
	c, frames := recordedConn(t)
	s.authenticated(c)
	s.dispatch(c, frame{kind: fStart, id: 39, payload: req})
	killed := make(chan syscall.Errno, 1)
	go func() {
		errno := answered(syscall.SYS_WAITID, 0) // it returns, and has told nothing
		if errno == 0 {
			s.dispatch(c, frame{kind: fKill, id: 39}) // as a client sends for a call it gives up; a command a debugger holds reports no stop either
		}
		killed <- errno
	}()

	select {
	case errno := <-killed:
		if errno != 0 {
			t.Fatalf("seccomp: %v", errno)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the kill waits for ever to hear that its command has stopped, and never kills it")
	}
	if status := exitStatus(t, frames); status["code"] != 143.0 {
		t.Fatalf("EXIT %v: the kill did not go ahead", status)
	}
}

func TestACallExecdAbandonedIsNotTakenForOneThatNeverStarted(t *testing.T) {
	var timers []func()
	afterFunc = func(_ time.Duration, f func()) *time.Timer { timers = append(timers, f); return nil }
	t.Cleanup(func() { afterFunc = time.AfterFunc })
	s, _ := newServer(strings.Repeat("00", 32))
	// It never ends by itself.
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", "kill -STOP $$"}, Env: map[string]string{}, Tag: "a"})
	first := testConn(t)
	s.start(first, frame{kind: fStart, id: 23, payload: req})
	s.detach(first)
	timers[0]() // six minutes with no client
	if code := exitCode(t, s.get(23)); code != 143 {
		t.Fatalf("exit %d: an abandoned call is killed", code)
	}
	late, frames := recordedConn(t)

	// The client sends the START of an "unknown call" again: right for 99, which never came; 23 would run twice.
	for id, unknown := range map[uint64]bool{99: true, 23: false} {
		go s.resume(late, frame{kind: fResume, id: id, payload: []byte(`{"stdout":0,"stderr":0}`)}) // one that waits fails the wait below
		select {
		case f := <-frames:
			if f.kind != fError || (string(f.payload) == "unknown call") != unknown {
				t.Fatalf("a RESUME of call %d got frame %d %q", id, f.kind, f.payload)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("a RESUME of call %d got no answer", id)
		}
	}
}

func TestACallExecdAbandonedStillSaysThatItsOwnTimeoutEndedIt(t *testing.T) {
	var timers []func()
	afterFunc = func(_ time.Duration, f func()) *time.Timer { timers = append(timers, f); return nil }
	t.Cleanup(func() { afterFunc = time.AfterFunc })
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"sleep", "600"}, Env: map[string]string{}, Tag: "outlives", Timeout: 60})
	first := testConn(t)
	s.start(first, frame{kind: fStart, id: 24, payload: req})
	timers[0]() // its timeout
	exitCode(t, s.get(24))
	s.detach(first)
	timers[len(timers)-1]() // six minutes with no client: the last asked for, after its kill's graces
	late, frames := recordedConn(t)

	go s.resume(late, frame{kind: fResume, id: 24, payload: []byte(`{"stdout":0,"stderr":0}`)}) // a RESUME that waits fails by the frames' wait

	// Its client, back at last, is told what execd knows: "abandoned" would say that how it ended is not known.
	if said := nextFrame(t, frames); said.kind != fResumed {
		t.Fatalf("a RESUME of a call that execd's timeout ended, and execd then abandoned, got a frame of kind %d: %s", said.kind, said.payload)
	}
	if said := nextFrame(t, frames); said.kind != fExit || !bytes.Contains(said.payload, []byte(`"timeout":true`)) {
		t.Fatalf("a RESUME of a call that execd's timeout ended, and execd then abandoned, got a frame of kind %d: %s", said.kind, said.payload)
	}
}

func TestAResumeAsExecdAbandonsACallThatItsTimeoutIsKillingIsToldOfTheTimeout(t *testing.T) {
	var timers []func()
	afterFunc = func(_ time.Duration, f func()) *time.Timer { timers = append(timers, f); return nil }
	t.Cleanup(func() { afterFunc = time.AfterFunc })
	s, _ := newServer(strings.Repeat("00", 32))
	tag := strconv.FormatInt(time.Now().UnixNano(), 36) // its own: the last run's kill may still be searching
	req, _ := json.Marshal(startRequest{Argv: []string{"sleep", "600"}, Env: map[string]string{}, Tag: tag, Timeout: 60})
	first := testConn(t)
	s.start(first, frame{kind: fStart, id: 25, payload: req})
	cl, deadline := s.get(25), time.Now().Add(30*time.Second)
	killing, kill, exit, waits := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}, 1)
	var began sync.Once
	held := func(committed bool) { // the timeout's kill waits as it is about to go ahead
		if committed {
			began.Do(func() { close(killing); <-kill })
		}
	}
	kept := func(bool) { <-exit } // and the command's exit is kept from the call
	waiting := func(bool) {
		select {
		case waits <- struct{}{}:
		default:
		}
	}
	beforeKill.Store(&held)
	beforeExit.Store(&kept)
	beforeWait.Store(&waiting)
	release, exits := sync.OnceFunc(func() { close(kill) }), sync.OnceFunc(func() { close(exit) })
	t.Cleanup(func() { // whatever fails: the held kill has the reaper's lock, and the call waits for its exit
		beforeKill.Store(nil)
		beforeExit.Store(nil)
		beforeWait.Store(nil)
		release()
		exits()
	})
	go timers[0]() // its timeout
	select {
	case <-killing:
	case <-time.After(time.Until(deadline)):
		t.Fatal("the timeout's kill never began")
	}
	s.detach(first)
	go timers[1]() // six minutes with no client: the kill that abandons it waits for the timeout's
	for abandoned := false; !abandoned; time.Sleep(time.Millisecond) {
		cl.mu.Lock()
		abandoned = cl.abandoned
		cl.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("the call was never abandoned")
		}
	}
	late, frames := recordedConn(t)
	answered := make(chan struct{})

	go func() {
		s.resume(late, frame{kind: fResume, id: 25, payload: []byte(`{"stdout":0,"stderr":0}`)})
		close(answered)
	}()

	select {
	case <-waits: // for the kill that abandons it
	case <-answered: // at once: the frames show what
	case <-time.After(time.Until(deadline)):
		t.Fatal("the RESUME neither waited nor was answered")
	}
	release()
	select {
	case f := <-frames:
		// Neither kill has yet said which ended it, nor has its exit: "abandoned" would say that how it ended is not known.
		if f.kind != fResumed {
			t.Fatalf("a RESUME of a call that its timeout was killing as execd abandoned it got a frame of kind %d: %s", f.kind, f.payload)
		}
	case <-time.After(time.Until(deadline)):
		t.Fatal("the RESUME got no answer")
	}
	exits()
	if said := awaited(t, frames, fExit, deadline); !bytes.Contains(said.payload, []byte(`"timeout":true`)) {
		t.Fatalf("the call that its timeout killed as execd abandoned it got the exit %s", said.payload)
	}
}

func TestAnExitDeliversTheOutputBehindAReadNotYetCounted(t *testing.T) {
	var armed atomic.Bool
	taken, count := make(chan struct{}), make(chan struct{})
	read := func(bool) {
		if armed.Swap(false) {
			close(taken)
			<-count
		}
	}
	checked, acked := make(chan bool), make(chan struct{})
	drainChecked := func(late bool) {
		select {
		case checked <- late:
		case <-acked:
		}
	}
	afterRead.Store(&read)
	afterDrainCheck.Store(&drainChecked)
	t.Cleanup(func() { afterRead.Store(nil); afterDrainCheck.Store(nil) })
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	const head = maxUnacked + 1 // unacked, it makes the reader wait in output() with what it reads next
	script := "head -c " + strconv.Itoa(head) + " /dev/zero; read x; printf a; read x; printf b"
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", script}, Env: map[string]string{}, Stdin: true, Tag: "o"})
	s.dispatch(c, frame{kind: fStart, id: 9, payload: req})
	got := 0
	next := func() byte {
		select {
		case f := <-frames:
			if f.kind == fStdout {
				got += len(f.payload)
			}
			return f.kind
		case <-time.After(30 * time.Second):
			t.Fatalf("no frame after %d bytes of stdout", got)
			return 0
		}
	}
	check := func() bool { // the exit has checked its pipes once more: whether its grace is over
		select {
		case late := <-checked:
			return late
		case <-time.After(30 * time.Second):
			t.Fatal("the exit never checked its pipes")
			return false
		}
	}
	for got < head {
		next()
	}

	armed.Store(true)
	s.dispatch(c, frame{kind: fStdin, id: 9, payload: []byte("\n")}) // it writes "a"
	select {
	case <-taken: // a reader has taken "a" and not counted it
	case <-time.After(30 * time.Second):
		t.Fatal("no reader took the output")
	}
	s.dispatch(c, frame{kind: fStdin, id: 9, payload: []byte("\n")}) // it writes "b" and exits
	// The exit has worked out how much to wait for, "a" not counted.
	check()
	close(count)
	for deadline := time.Now().Add(30 * time.Second); !check(); { // a slow client acks after the exit's grace
		if time.Now().After(deadline) {
			t.Fatal("the exit's grace never ended")
		}
	}
	close(acked)
	s.dispatch(c, frame{kind: fAck, id: 9, payload: []byte(`{"stdout":` + strconv.Itoa(head) + `}`)})

	for next() != fExit {
	}
	if got != head+2 {
		t.Fatalf("%d of %d bytes of stdout arrived: the exit stopped reading the pipe", got, head+2)
	}
}
