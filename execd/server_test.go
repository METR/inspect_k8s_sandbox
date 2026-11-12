package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	cl := s.get(2)
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		cl.mu.Lock()
		exited, code := cl.exited, cl.code
		cl.mu.Unlock()
		if exited {
			if code != 7 {
				t.Fatalf("exit %d, want hello's 7", code)
			}
			return
		}
	}
	t.Fatal("hello never exited")
}
