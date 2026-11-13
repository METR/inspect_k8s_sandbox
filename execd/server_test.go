package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// kill() runs this binary, as it runs execd, to look for a call's processes as its user.
func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == "kill" {
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

	if s.get(1) == nil {
		t.Fatal("released by the first drop's timer, though resumed since")
	}
	timers[1]()
	if s.get(1) != nil {
		t.Fatal("not released by its last drop's timer")
	}
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
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		cl.mu.Lock()
		exited, code := cl.exited, cl.code
		cl.mu.Unlock()
		if exited {
			return code
		}
	}
	t.Fatal("the command never exited")
	return 0
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

	if s.get(4) != nil {
		t.Fatal("a START from a replaced connection ran")
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
}

func TestAKillReachesWhatAnotherUsersCommandDetached(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root runs a command as another user")
	}
	prctl(prSetChildSubreaper, 1) // as execd: what the command detached is reaped here once killed
	startReaper()
	s, _ := newServer(strings.Repeat("00", 32))
	c, frames := recordedConn(t)
	s.authenticated(c)
	detach := "setsid sh -c 'echo $$; kill -STOP $$' & wait" // it names itself once out of the group a kill signals
	req, _ := json.Marshal(startRequest{Argv: []string{"sh", "-c", detach}, Env: map[string]string{}, User: "65534", Tag: "detached"})
	s.dispatch(c, frame{kind: fStart, id: 22, payload: req})
	var pid int
	for pid == 0 {
		select {
		case f := <-frames:
			if f.kind == fStdout {
				pid, _ = strconv.Atoi(strings.TrimSpace(string(f.payload)))
			}
		case <-time.After(30 * time.Second):
			t.Fatal("the command never printed what it detached")
		}
	}
	t.Cleanup(func() { syscall.Kill(pid, syscall.SIGKILL) })

	s.dispatch(c, frame{kind: fKill, id: 22})

	// Without CAP_SYS_PTRACE root can't read another user's environment, where the call's tag is.
	for deadline := time.Now().Add(30 * time.Second); syscall.Kill(pid, 0) == nil; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("process %d, which the command detached, outlived its kill", pid)
		}
	}
}

func TestACallExecdAbandonedIsNotTakenForOneThatNeverStarted(t *testing.T) {
	var timers []func()
	afterFunc = func(_ time.Duration, f func()) *time.Timer { timers = append(timers, f); return nil }
	t.Cleanup(func() { afterFunc = time.AfterFunc })
	startReaper()
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"sleep", "10"}, Env: map[string]string{}, Tag: "a"})
	first := testConn(t)
	s.start(first, frame{kind: fStart, id: 23, payload: req})
	s.detach(first)
	timers[0]() // six minutes with no client: killed and forgotten
	late, frames := recordedConn(t)

	s.resume(late, frame{kind: fResume, id: 23, payload: []byte(`{"stdout":0,"stderr":0}`)})

	// The client sends the START of an "unknown call" again: the command would run twice.
	if f := <-frames; f.kind != fError || string(f.payload) == "unknown call" {
		t.Fatalf("a late RESUME got frame %d %q", f.kind, f.payload)
	}
}
