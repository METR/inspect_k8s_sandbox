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
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
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
	if got := memoryLimit(nil, os.ErrNotExist); got != 32<<20 {
		t.Errorf("no cgroup file: limit %d, want 32 MiB", got)
	}
}

func TestTheMemoryLimitIsReadFromCgroupV2OrV1(t *testing.T) {
	for _, file := range []string{"memory.max", "memory/memory.limit_in_bytes"} { // v1 is all gVisor has
		root := t.TempDir()
		os.Mkdir(root+"/memory", 0o755)
		if err := os.WriteFile(root+"/"+file, []byte("2147483648\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := memoryLimit(cgroupLimit(root)); got != 1<<30 {
			t.Errorf("%s: limit %d, want half of 2 GiB", file, got)
		}
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

// refused runs execd where the kernel refuses PR_SET_DUMPABLE, as a seccomp profile can, and says so if execd then ran on.
func refused(at string) {
	if at != "ran on" {
		runtime.LockOSThread() // the filter is this thread's, and an exec keeps it
		filter := []syscall.SockFilter{
			{Code: 0x20, K: 0},                               // the call's number
			{Code: 0x15, Jf: 3, K: syscall.SYS_PRCTL},        // not prctl: allowed
			{Code: 0x20, K: 16},                              // its first argument
			{Code: 0x15, Jf: 1, K: prSetDumpable},            // another option: allowed
			{Code: 0x06, K: 0x50000 | uint32(syscall.EPERM)}, // SECCOMP_RET_ERRNO
			{Code: 0x06, K: 0x7fff0000},                      // SECCOMP_RET_ALLOW
		}
		prog := syscall.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
		const prSetNoNewPrivs, prSetSeccomp, seccompModeFilter = 38, 22, 2
		prctl(prSetNoNewPrivs, 1) // without it a filter needs CAP_SYS_ADMIN
		if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilter, uintptr(unsafe.Pointer(&prog))); errno != 0 {
			fail("seccomp: " + errno.Error())
		}
		if at == "start" { // init() runs again, under the filter
			syscall.Exec("/proc/self/exe", []string{os.Args[0], "refused", "ran on"}, os.Environ())
		}
		setids(uint32(os.Getuid()), uint32(os.Getgid()))
	}
	os.Stdout.WriteString("ran on")
}

func TestExecdEndsWhereItCannotBeMadeNonDumpable(t *testing.T) {
	for _, at := range []string{"start", "change of identity"} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // only bounds a hang
		defer cancel()
		child := exec.CommandContext(ctx, os.Args[0], "refused", at)
		var said strings.Builder
		child.Stderr = &said

		ran, _ := child.Output() // its exit status may go to the tests' reaper

		if len(ran) > 0 || !strings.Contains(said.String(), "prctl(PR_SET_DUMPABLE): operation not permitted") {
			t.Errorf("at its %s execd said %q, then %q: its user could read its memory", at, said.String(), ran)
		}
	}
}
