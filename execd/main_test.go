package main

import (
	"bytes"
	"context"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTheMemoryLimitIsHalfTheContainers(t *testing.T) {
	for cgroupMax, want := range map[string]int64{
		"1999998976\n": 999999488,
		"16777216\n":   32 << 20,      // never less: execd idles at 7 MiB
		"max\n":        math.MaxInt64, // a container with no limit
	} {
		if got := memoryLimit([]byte(cgroupMax), nil); got != want {
			t.Errorf("memory.max %q: limit %d, want %d", cgroupMax, got, want)
		}
	}
	if got := memoryLimit(nil, os.ErrNotExist); got != 32<<20 { // cgroup v1
		t.Errorf("no memory.max: limit %d, want 32 MiB", got)
	}
}

func TestTheFirstExecPrintsItsDaemonsFingerprintAndReturns(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // only bounds a hang
	defer cancel()
	first := exec.CommandContext(ctx, os.Args[0], "listen", "--key-sha256", strings.Repeat("00", 32)) // any port
	// The daemon it leaves running.
	t.Cleanup(stopOthers)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	first.Stdout = w
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	w.Close()
	r.SetReadDeadline(time.Now().Add(30 * time.Second)) // only bounds a hang
	out, err := io.ReadAll(r)                           // ends once the exec and its daemon have both let go
	first.Wait()                                        // its exit status may go to another test's reaper

	if err != nil {
		t.Fatalf("the first exec's stdout stayed open: %v", err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}\n$`).Match(out) {
		t.Fatalf("the first exec printed %q, want its daemon's fingerprint", out)
	}
}

// firstProcess runs execd as a pod's first process that reaps nothing would.
func firstProcess(argv []string) {
	prctl(prSetChildSubreaper, 1)
	start := exec.Command(os.Args[0], argv...)
	start.Stderr = os.Stderr
	start.Run()
	stats, _ := filepath.Glob("/proc/[0-9]*/stat")
	for _, stat := range stats {
		data, _ := os.ReadFile(stat)
		// After the name, which may hold spaces: the state, then the parent.
		if f := strings.Fields(string(data[bytes.LastIndexByte(data, ')')+1:])); len(f) > 1 && f[1] == strconv.Itoa(os.Getpid()) {
			os.Stdout.Write(data)
		}
	}
}

func TestAStartThatFindsThePortTakenLeavesNoProcessBehind(t *testing.T) {
	taken, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	port := strconv.Itoa(taken.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // only bounds a hang
	defer cancel()
	first := exec.CommandContext(ctx, os.Args[0], "first", "listen", "--port", port, "--key-sha256", strings.Repeat("00", 32))
	var said strings.Builder
	first.Stderr = &said

	left, _ := first.Output() // its exit status may go to the tests' reaper

	if !strings.Contains(said.String(), "address already in use") {
		t.Fatalf("the start said %q, want the port found taken", said.String())
	}
	if len(left) > 0 {
		t.Fatalf("the start left a process behind: %s", left)
	}
}
