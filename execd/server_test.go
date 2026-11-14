package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// run() starts this binary, as it starts execd, to become another user; a test starts it as execd itself.
func TestMain(m *testing.M) {
	if len(os.Args) > 6 && os.Args[1] == "as" || len(os.Args) > 1 && os.Args[1] == "listen" {
		main()
		return
	}
	os.Exit(m.Run())
}

func testConn(t *testing.T) *conn {
	a, b := net.Pipe()
	go io.Copy(io.Discard, b) //nolint:errcheck // drains what the server sends
	t.Cleanup(func() { a.Close(); b.Close() })
	return &conn{nc: a, dead: make(chan struct{})}
}

func TestAResumedCallOutlivesAnEarlierDropsTimer(t *testing.T) {
	var timers []func()
	afterFunc = func(_ time.Duration, f func()) *time.Timer { timers = append(timers, f); return nil }
	t.Cleanup(func() { afterFunc = time.AfterFunc })
	startReaper()
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
	startReaper()
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	os.MkdirAll(filepath.Join(dir, "work", "bin"), 0o755)
	os.WriteFile(filepath.Join(dir, "work", "bin", "hello"), []byte("#!/bin/sh\nexit 7\n"), 0o755)
	wd, _ := os.Getwd()
	os.Chdir(dir)
	t.Cleanup(func() { os.Chdir(wd) })
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"hello"}, Env: map[string]string{"PATH": "bin"}, Cwd: "work", Tag: "p"})

	s.start(testConn(t), frame{kind: fStart, id: 2, payload: req})

	// As a shell finds it: work/bin/hello, run in work.
	if code := exitCode(t, s.get(2)); code != 7 {
		t.Fatalf("exit %d, want hello's 7", code)
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
	startReaper()
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

	s.get(3).writeStdin(first, []byte("BBBB"))                             // still in flight on the dropped connection
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
	startReaper()
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
	startReaper()
	s, _ := newServer(strings.Repeat("00", 32))
	out := filepath.Join(t.TempDir(), "env")
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", `env >"$0"`, out}, Env: map[string]string{}, Tag: "p"})

	s.start(testConn(t), frame{kind: fStart, id: 31, payload: req})

	exitCode(t, s.get(31))
	// Left to itself the shell searches its own list, and bash's ends in the working directory.
	if env, _ := os.ReadFile(out); !strings.Contains("\n"+string(env), "\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n") {
		t.Fatalf("the command's environment was %q", env)
	}
}

func TestAHugeTimeoutIsNoTimeout(t *testing.T) {
	startReaper()
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", "sleep 0.2; exit 3"}, Env: map[string]string{}, Tag: "h", Timeout: 1e18})
	c := testConn(t)
	s.authenticated(c)

	s.dispatch(c, frame{kind: fStart, id: 5, payload: req})

	if code := exitCode(t, s.get(5)); code != 3 {
		t.Fatalf("exit %d, want 3: the timeout fired at once", code)
	}
}

func TestACommandKilledAtItsTimeoutSaysSoInItsExit(t *testing.T) {
	startReaper()
	s, _ := newServer(strings.Repeat("00", 32))
	tag := strconv.FormatInt(time.Now().UnixNano(), 36) // its own: a repeat's kill may still be looking for the last one's
	req, _ := json.Marshal(startRequest{Argv: []string{"sleep", "60"}, Env: map[string]string{}, Tag: tag, Timeout: 0.05})
	c, frames := recordedConn(t)
	s.authenticated(c)

	s.dispatch(c, frame{kind: fStart, id: 7, payload: req})

	if status := exitStatus(t, frames); status["timeout"] != true {
		t.Fatalf("EXIT %v: the client can't tell the timeout from a kill -9", status)
	}
}

func TestACommandThatEndsByItselfAsItsTimerFiresIsNotTimedOut(t *testing.T) {
	afterFunc = func(time.Duration, func()) *time.Timer {
		fired := time.NewTimer(0) // a timer that has fired, whose kill found the command gone
		<-fired.C
		return fired
	}
	t.Cleanup(func() { afterFunc = time.AfterFunc })
	startReaper()
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", "exit 3"}, Env: map[string]string{}, Tag: "e", Timeout: 60})
	c, frames := recordedConn(t)
	s.authenticated(c)

	s.dispatch(c, frame{kind: fStart, id: 8, payload: req})

	if status := exitStatus(t, frames); status["code"] != 3.0 || status["timeout"] != nil {
		t.Fatalf("EXIT %v, want code 3 and no timeout", status)
	}
}

// exitStatus waits for a call's EXIT and returns it under the keys the client reads: a struct would match them in any case.
func exitStatus(t *testing.T, frames <-chan frame) (status map[string]any) {
	t.Helper()
	for {
		select {
		case f := <-frames:
			if f.kind == fExit {
				json.Unmarshal(f.payload, &status)
				return status
			}
		case <-time.After(30 * time.Second):
			t.Fatal("no EXIT")
		}
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

func TestAStartErrorFitsTheClientsControlFrame(t *testing.T) {
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	cwd := "/" + strings.Repeat("\x01", 5000) // six bytes each, escaped to JSON
	req, _ := json.Marshal(startRequest{Argv: []string{"true"}, Env: map[string]string{}, Cwd: cwd, Tag: "e"})

	s.dispatch(c, frame{kind: fStart, id: 6, payload: req})

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
		case <-time.After(10 * time.Second):
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

func TestManySmallWritesMakeFewFrames(t *testing.T) {
	startReaper()
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	lines := "i=0; while [ $i -lt 20000 ]; do echo $i; i=$((i+1)); done"
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", lines}, Env: map[string]string{}, Tag: "w"})

	began := time.Now()
	s.dispatch(c, frame{kind: fStart, id: 7, payload: req})

	outputs := 0
	for {
		select {
		case f := <-frames:
			switch f.kind {
			case fStdout:
				outputs++
			case fExit:
				// The client paces frames at 4,096 a second: a frame a line would crawl.
				if took := time.Since(began); outputs > int(took/time.Millisecond)+2 {
					t.Fatalf("%d frames for 20,000 lines in %v: more than one a millisecond", outputs, took)
				}
				return
			}
		case <-time.After(30 * time.Second):
			t.Fatal("no EXIT")
		}
	}
}

func TestCallsTakeTurnsToSend(t *testing.T) {
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
}

func TestCallsWithNoConnectionTakeNoTurns(t *testing.T) {
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
	if took := time.Since(began); took > 30*time.Millisecond {
		t.Fatalf("a live call waited %v behind calls with nowhere to send", took)
	}
}

func TestAnExitTakesTurnsForWhatItSends(t *testing.T) {
	slot.Store(0) // turns other tests took could leave less than two to take
	c, frames := recordedConn(t)
	cl := &call{id: 12, sub: c, out: [2][]byte{[]byte("out"), nil}}
	cl.room = sync.NewCond(&cl.mu)
	before := max(time.Duration(slot.Load()), time.Since(epoch))

	cl.finish(0, "")

	<-frames
	<-frames // the output, then the exit
	// Exits sent without turns, many calls ending at once, would pass the client's frame pace.
	if moved := time.Duration(slot.Load()) - before; moved < 2*slotEvery {
		t.Fatalf("turns moved %v for the two frames an exit sent", moved)
	}
}

func TestExitsHoldOthersOutputBackOnlySoLong(t *testing.T) {
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
	s.calls[13] = &call{id: 13, out: [2][]byte{[]byte("out"), []byte("err")}}
	s.calls[13].room = sync.NewCond(&s.calls[13].mu)
	c, frames := recordedConn(t)
	before := max(time.Duration(slot.Load()), time.Since(epoch))

	s.resume(c, frame{kind: fResume, id: 13, payload: []byte(`{"stdout":0,"stderr":0}`)})

	<-frames
	<-frames
	<-frames // RESUMED, then what each stream has waiting
	// Resumes sent without turns, many calls resuming at once, would pass the client's frame pace.
	if moved := time.Duration(slot.Load()) - before; moved < 2*slotEvery {
		t.Fatalf("turns moved %v for the two frames a resume sent", moved)
	}
}

func TestOutputWhileAFlushWaitsIsLeftToIt(t *testing.T) {
	c, frames := recordedConn(t)
	cl := &call{id: 9, sub: c, deferred: true} // its flush is set, and its time has come
	cl.room = sync.NewCond(&cl.mu)

	cl.output(0, []byte("x"))

	select {
	case <-frames: // and the waiting flush sends another
		t.Fatal("sent at once, as well as by the flush that waits")
	case <-time.After(50 * time.Millisecond):
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
	startReaper()
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
	startReaper()
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	args := []string{"a  b", "$(id)", "`id`", ";x", "$PATH", "*", ""}
	req, _ := json.Marshal(startRequest{Argv: append([]string{"printf", "%s\n"}, args...), Env: map[string]string{}, Tag: "l"})

	s.dispatch(c, frame{kind: fStart, id: 25, payload: req})

	var out []byte
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
		case <-time.After(30 * time.Second):
			t.Fatal("no EXIT")
		}
	}
}

func TestACommandNamedLikeAShellBuiltinIsTheOneOnThePath(t *testing.T) {
	startReaper()
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
	startReaper()
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"-c", "true"}, Env: map[string]string{}, Tag: "o"})

	s.start(testConn(t), frame{kind: fStart, id: 34, payload: req})

	// bash would run `true` with no environment and busybox nothing, both as options of their exec: the shell isn't asked.
	cl := s.get(34)
	if code := exitCode(t, cl); code != 127 || cl.startErr == "" {
		t.Fatalf("exit %d, start error %q: want 127 from execd itself", code, cl.startErr)
	}
}

func TestACommandIsFoundOnThePathAsItsUser(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root runs a command as another user")
	}
	startReaper()
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
	// A child of execd that switched user would share its memory till it execs: the flag is reset, and execd waits on a child that user can stop.
	if dumpable() {
		t.Fatal("dumpable once it has run a command as another user")
	}
}

func TestACommandRunAsAnotherUserHasTheirIdentityAndItsOwnEnvironment(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root runs a command as another user")
	}
	startReaper()
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	t.Setenv("RAW", "\xff") // execd's own environment, which a command inherits, need not be text
	// GODEBUG has a Go program trace its start on stderr, and execd sets a GOMAXPROCS of its own for its start as
	// another user; BIG is as long as the kernel lets a variable be.
	env := map[string]string{"GODEBUG": "inittrace=1", "GOMAXPROCS": "7", "BIG": strings.Repeat("x", 128<<10-len("BIG=")-1)}
	script := "id -u; id -g; id -G; echo $GODEBUG $GOMAXPROCS ${#BIG} $RAW; [ ! -e /proc/$$/fd/3 ] || echo descriptor 3 is open"
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", script}, Env: env, User: "65534", Tag: "e"})

	s.dispatch(c, frame{kind: fStart, id: 27, payload: req})

	var out []byte
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
			// execd, a Go program, becomes the user itself: none of root's groups stay, and the environment isn't its own to read or to mark.
			if string(out) != "65534\n65534\n65534\ninittrace=1 7 131067 \xff\n" {
				t.Fatalf("the command's output was %q", out)
			}
			return
		case <-time.After(30 * time.Second):
			t.Fatal("no EXIT")
		}
	}
}

func TestACommandForAnotherUserDoesNotRunWithoutItsEnvironment(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root runs a command as another user")
	}

	// As run() starts it, but with no pipe to read the environment from, as when execd has no descriptor to spare.
	out, _ := exec.Command("/proc/self/exe", "as", "", "65534", "65534", "", "/bin/echo", "RAN").CombinedOutput()

	if !strings.HasPrefix(string(out), "execd: ") || strings.Contains(string(out), "RAN") {
		t.Fatalf("with no environment to read, its output was %q", out)
	}
}

func TestACommandForAnotherUserEntersItsDirectoryAsThem(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root runs a command as another user")
	}
	startReaper()
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"true"}, Env: map[string]string{}, Cwd: t.TempDir(), User: "65534", Tag: "d"})

	s.start(testConn(t), frame{kind: fStart, id: 26, payload: req})

	// Root may enter a test's directory (mode 700); the user may not, and a failed cd is exit 1.
	if code := exitCode(t, s.get(26)); code != 1 {
		t.Fatalf("exit %d, want 1 from a cd its user can't make", code)
	}
}

func TestAKillReachesWhatAnotherUsersCommandDetached(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root runs a command as another user")
	}
	prctl(prSetChildSubreaper, 1) // as execd: what the command detached is reaped here once killed
	t.Cleanup(func() { prctl(prSetChildSubreaper, 0) })
	startReaper()
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	detach := "setsid sh -c 'echo $$; kill -STOP $$' & wait" // it names itself once out of the group a kill signals
	victims := map[uint64]int{}
	for id := uint64(100); id < 120; id++ {
		req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", detach}, Env: map[string]string{}, User: "65534", Tag: "detached" + strconv.Itoa(int(id))})
		s.dispatch(c, frame{kind: fStart, id: id, payload: req})
	}
	for len(victims) < 20 {
		select {
		case f := <-frames:
			if f.kind == fStdout {
				pid, _ := strconv.Atoi(strings.TrimSpace(string(f.payload)))
				victims[f.id] = pid
				t.Cleanup(func() { syscall.Kill(pid, syscall.SIGKILL) })
			}
		case <-time.After(30 * time.Second):
			t.Fatal("a command never printed what it detached")
		}
	}

	for id := range victims { // at once: their searches wait in turn for the one thread
		s.dispatch(c, frame{kind: fKill, id: id})
	}

	// Without CAP_SYS_PTRACE root can't read another user's environment, where the call's tag is.
	for id, pid := range victims {
		for deadline := time.Now().Add(30 * time.Second); syscall.Kill(pid, 0) == nil; time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("process %d, which call %d's command detached, outlived its kill", pid, id)
			}
		}
	}
	var searched sync.WaitGroup
	for range 200 { // many more searches, each with a collection under way: that moves a goroutine not held to its thread
		searched.Add(1)
		go func() { defer searched.Done(); searches <- search{"none", &syscall.Credential{Uid: 65534, Gid: 65534}} }()
		runtime.GC()
	}
	searched.Wait()
	// Taking the user's identity to look for it resets the flag to the host's fs.suid_dumpable, for an instant each time.
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

func TestAKillThatComesBeforeItsCommandHasStartedStopsIt(t *testing.T) {
	startReaper()
	t.Cleanup(func() { killTagged("early") })
	cl := &call{id: 30, tag: "early"}
	cl.room = sync.NewCond(&cl.mu)
	req := startRequest{Argv: []string{"sh", "-c", "kill -STOP $$"}, Env: map[string]string{}, Tag: "early"} // it never ends by itself

	cl.kill() // from another connection, while this one's START is still at work
	if err := cl.run(req); err != nil {
		t.Fatal(err)
	}

	if code := exitCode(t, cl); code != 137 {
		t.Fatalf("exit %d: the kill was lost", code)
	}
}

func TestAKillThatComesBeforeItsCommandHasStartedReachesWhatItLeftRunning(t *testing.T) {
	prctl(prSetChildSubreaper, 1) // as execd: what the command leaves running is reaped here once killed
	t.Cleanup(func() { prctl(prSetChildSubreaper, 0) })
	startReaper()
	t.Cleanup(func() { killTagged("ended") })
	cl := &call{id: 33, tag: "ended"}
	cl.room = sync.NewCond(&cl.mu)
	pids := filepath.Join(t.TempDir(), "pids")
	// It leaves two processes running, says which, and ends: one in its group with no tag, one with its tag in a session of its own.
	leave := `env -i sleep 600 >/dev/null 2>&1 & grouped=$!; setsid sleep 600 >/dev/null 2>&1 & echo $$ $grouped $! >"$0"`
	req := startRequest{Argv: []string{"sh", "-c", leave, pids}, Env: map[string]string{}, Tag: "ended"}

	cl.kill()    // from another connection, while this one's START is still at work
	cl.mu.Lock() // and stays at work: the command has ended before the START can note its id
	noted := sync.OnceFunc(cl.mu.Unlock)
	t.Cleanup(noted)
	started := make(chan error, 1)
	go func() { started <- cl.run(req) }()
	var leader, grouped, detached int
	for deadline := time.Now().Add(30 * time.Second); detached == 0 || syscall.Kill(leader, 0) == nil; time.Sleep(10 * time.Millisecond) {
		if b, _ := os.ReadFile(pids); len(strings.Fields(string(b))) == 3 {
			leader, _ = strconv.Atoi(strings.Fields(string(b))[0])
			grouped, _ = strconv.Atoi(strings.Fields(string(b))[1])
			detached, _ = strconv.Atoi(strings.Fields(string(b))[2])
		}
		if time.Now().After(deadline) {
			t.Fatal("the command never ended")
		}
	}
	noted()
	if err := <-started; err != nil {
		t.Fatal(err)
	}

	// The first is reached by the signal to the command's group alone, the second by the search for its tag alone.
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
	startReaper()
	s, _ := newServer(strings.Repeat("00", 32))
	alive := filepath.Join(t.TempDir(), "alive")
	t.Cleanup(func() { killTagged("left") })
	// Once let go, it leaves a loop running that keeps putting a file back, prints and ends.
	left := `until [ -e "$0.go" ]; do sleep 0.01; done; (while :; do : >"$0"; sleep 0.01; done) >/dev/null 2>&1 & echo x`
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", left, alive}, Env: map[string]string{}, Tag: "left"})
	c := testConn(t)
	s.start(c, frame{kind: fStart, id: 28, payload: req})
	cl := s.get(28)
	cl.output(0, make([]byte, maxUnacked+1)) // all that execd holds for a client: what it prints now waits, and its exit with that
	os.WriteFile(alive+".go", nil, 0o644)
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		cl.mu.Lock()
		ended := cl.pid == 0
		cl.mu.Unlock()
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

func TestAKillAsACommandsEndIsBeingNotedLeavesWhatItLeftRunning(t *testing.T) {
	startReaper()
	s, _ := newServer(strings.Repeat("00", 32))
	alive := filepath.Join(t.TempDir(), "alive")
	t.Cleanup(func() { killTagged("noted") })
	// Once let go, it leaves a loop running that keeps putting a file back, and ends.
	left := `until [ -e "$0.go" ]; do sleep 0.01; done; (while :; do : >"$0"; sleep 0.01; done) >/dev/null 2>&1 &`
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", left, alive}, Env: map[string]string{}, Tag: "noted"})
	s.start(testConn(t), frame{kind: fStart, id: 32, payload: req})
	cl := s.get(32)
	cl.mu.Lock()
	pid := cl.pid
	cl.mu.Unlock()
	reaper.mu.Lock() // as while another command starts: an end is collected, and waits to be noted
	noted := sync.OnceFunc(reaper.mu.Unlock)
	t.Cleanup(noted)
	os.WriteFile(alive+".go", nil, 0o644)
	for deadline := time.Now().Add(30 * time.Second); syscall.Kill(pid, 0) == nil; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the command never ended")
		}
	}

	cl.kill()

	noted()
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
	startReaper()
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", "kill -STOP $$"}, Env: map[string]string{}, Tag: "a"}) // it never ends by itself
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
	afterRead = func() {
		if armed.Swap(false) {
			close(taken)
			<-count
		}
	}
	checked, acked := make(chan bool), make(chan struct{})
	afterDrainCheck = func(late bool) {
		select {
		case checked <- late:
		case <-acked:
		}
	}
	t.Cleanup(func() { afterRead, afterDrainCheck = func() {}, func(bool) {} })
	startReaper()
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
	check()                                                          // the exit has worked out how much to wait for, "a" not counted
	close(count)
	for !check() { // a slow client: it acks only once the exit's grace is over
	}
	close(acked)
	s.dispatch(c, frame{kind: fAck, id: 9, payload: []byte(`{"stdout":` + strconv.Itoa(head) + `}`)})

	for next() != fExit {
	}
	if got != head+2 {
		t.Fatalf("%d of %d bytes of stdout arrived: the exit stopped reading the pipe", got, head+2)
	}
}
