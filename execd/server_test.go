package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

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
