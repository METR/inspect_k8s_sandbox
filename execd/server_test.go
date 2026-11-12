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
	abandonAfter = time.Second
	startReaper()
	s, _ := newServer(strings.Repeat("00", 32))
	req, _ := json.Marshal(startRequest{Argv: []string{"sleep", "10"}, Env: map[string]string{}, Tag: "t"})
	first := testConn(t)
	s.start(first, frame{kind: fStart, id: 1, payload: req})
	t.Cleanup(s.get(1).kill)

	s.detach(first) // its timer fires at 1.0 s
	time.Sleep(200 * time.Millisecond)
	again := testConn(t)
	s.resume(again, frame{kind: fResume, id: 1, payload: []byte(`{"stdout":0,"stderr":0}`)})
	time.Sleep(300 * time.Millisecond)
	s.detach(again) // at 0.5 s; its timer fires at 1.5 s
	time.Sleep(700 * time.Millisecond)

	if s.get(1) == nil {
		t.Fatal("released at 1.2 s by the first drop's timer, though resumed since")
	}
	time.Sleep(600 * time.Millisecond)
	if s.get(1) != nil {
		t.Fatal("not released 1 s after its last drop")
	}
}

func TestARelativePathEntryUnderARelativeCwdRuns(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	os.MkdirAll(filepath.Join(dir, "work", "bin"), 0o755)
	os.WriteFile(filepath.Join(dir, "work", "bin", "hello"), []byte("#!/bin/sh\n"), 0o755)
	wd, _ := os.Getwd()
	os.Chdir(dir)
	t.Cleanup(func() { os.Chdir(wd) })

	got, err := lookPath("hello", []string{"PATH=bin"}, "work")

	// The child starts in cwd, so a path relative to execd's own cwd would miss.
	if err != nil || got != filepath.Join(dir, "work", "bin", "hello") {
		t.Fatalf("lookPath = %q, %v", got, err)
	}
}
