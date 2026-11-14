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
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
	"weak"
)

// run() starts this binary, as it starts execd, to become another user.
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "first" {
		firstProcess(os.Args[2:])
		return
	}
	if len(os.Args) > 6 && os.Args[1] == "as" || len(os.Args) > 1 && (os.Args[1] == "listen" || os.Args[1] == "serve") {
		main()
		return
	}
	startReaper()
	startSearcher()
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

	if code := exitCode(t, cl); code != 137 || s.get(36) != nil {
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

func TestACommandThatEndsByItselfAsItsTimerFiresIsNotTimedOut(t *testing.T) {
	for _, code := range []int{3, 137} { // 137: a kill's exit code, from a command nothing killed
		t.Run(strconv.Itoa(code), func(t *testing.T) {
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
			reaper.mu.Lock() // the command ends, and execd has yet to note it
			noted := sync.OnceFunc(reaper.mu.Unlock)
			t.Cleanup(noted)
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

			fired := make(chan struct{})
			go func() { fire(); close(fired) }() // the timer's callback runs now: its kill finds the command gone
			select {
			case <-fired:
			case <-time.After(30 * time.Second):
				t.Fatal("the timeout's kill waited to see the command reaped")
			}
			noted()

			if status := exitStatus(t, frames); status["code"] != float64(code) || status["timeout"] != nil {
				t.Fatalf("EXIT %v, want code %d and no timeout", status, code)
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

	go timeout()

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
	script := "id -u; id -g; id -G; echo $GODEBUG $GOMAXPROCS ${#BIG} $RAW; [ ! -e /proc/$$/fd/3 ] || echo descriptor 3 is open"
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", script}, Env: env, User: "65534", Tag: "e"})

	s.dispatch(c, frame{kind: fStart, id: 27, payload: req})

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
			if string(out) != "65534\n65534\n65534\ninittrace=1 7 131067 \xff\n" {
				t.Fatalf("the command's output was %q", out)
			}
			return
		case <-deadline:
			t.Fatal("no EXIT")
		}
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

func TestAKillReadsNoMoreOfAnEnvironmentThanOneCanHold(t *testing.T) {
	huge := filepath.Join(t.TempDir(), "environ")
	os.WriteFile(huge, nil, 0o644)
	os.Truncate(huge, 1<<30) // as prctl(PR_SET_MM_MAP) lets any process make its own look
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	tagged(huge, []byte("HAWK_NEXT_EXEC=huge\x00"))

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

func TestAKillOfACommandAlreadyReapedLeavesTheCommandThatHasItsIdNow(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	alive := filepath.Join(t.TempDir(), "alive")
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", `while :; do : >"$0"; sleep 0.01; done`, alive}, Env: map[string]string{}, Tag: "other"})
	s.start(testConn(t), frame{kind: fStart, id: 32, payload: req})
	other := s.get(32)
	t.Cleanup(other.kill)
	other.kmu.Lock()
	// A call whose command was reaped, its end not yet noted: the id it still holds is another command's by now.
	cl := &call{id: 37, tag: "reaped", pid: other.pid, status: make(chan int, 1)}
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
	if code := exitCode(t, s.get(23)); code != 137 {
		t.Fatalf("exit %d: an abandoned call is killed", code)
	}
	late, frames := recordedConn(t)

	// The client sends the START of an "unknown call" again: right for 99, which never came; 23 would run twice.
	for id, unknown := range map[uint64]bool{99: true, 23: false} {
		s.resume(late, frame{kind: fResume, id: id, payload: []byte(`{"stdout":0,"stderr":0}`)})
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
