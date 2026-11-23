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
	"sync/atomic"
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
	if !regexp.MustCompile(`^[0-9a-f]{64} \S+\n$`).Match(out) {
		t.Fatalf("the first exec printed %q, want its daemon's fingerprint and its container", out)
	}
}

func TestConnectWaitsWhileItsOutputIsNotRead(t *testing.T) {
	const unread = 500 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // only bounds a hang
	defer cancel()
	name := "execd-test-" + strconv.Itoa(os.Getpid())
	daemon, err := net.Listen("unix", "@"+name)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()
	bridge := exec.CommandContext(ctx, os.Args[0], "connect", name)
	stdin, _ := bridge.StdinPipe() // open until the test ends: connect ends when its stdin does
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	bridge.Stdout = w
	if err := bridge.Start(); err != nil {
		t.Fatal(err)
	}
	w.Close()
	defer bridge.Wait() // its exit status may go to the tests' reaper
	defer stdin.Close()
	daemon.(*net.UnixListener).SetDeadline(time.Now().Add(30 * time.Second)) // only bounds a hang
	c, err := daemon.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ran := func() time.Duration { // the bridge's user and system time so far, which /proc counts in hundredths of a second
		stat, err := os.ReadFile("/proc/" + strconv.Itoa(bridge.Process.Pid) + "/stat")
		if err != nil {
			t.Fatal(err)
		}
		f := strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:])) // after the name, which may hold spaces
		user, _ := strconv.Atoi(f[11])
		system, _ := strconv.Atoi(f[12])
		return time.Duration(user+system) * 10 * time.Millisecond
	}
	started := ran()                // it has connected: what it took to start does not count
	go c.Write(make([]byte, 1<<20)) // more than the exec's stdout holds

	time.Sleep(unread)

	if spent := ran() - started; spent > unread/10 {
		t.Fatalf("connect ran for %v of the %v its output went unread: want it to wait", spent, unread)
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

// refused runs execd where the kernel refuses it a call, as a seccomp profile can, and says how execd ran on.
func refused(at string) {
	if at == "kept" || at == "ended" { // every thread under the filter: execd keeps a pipe, written a byte past what it takes, or its writer goes
		var looks atomic.Int32
		look := func(bool) { looks.Add(1) }
		afterTaken.Store(&look)
		startKeeper()
		r, w, _ := os.Pipe()
		held <- struct{}{}
		keep(r, keeper, held)
		for range 1000 { // a signal at each thread, as any may come while the keeper waits
			tasks, _ := os.ReadDir("/proc/self/task")
			for _, task := range tasks {
				tid, _ := strconv.Atoi(task.Name())
				syscall.Tgkill(os.Getpid(), tid, syscall.SIGURG)
			}
		}
		if at == "ended" {
			w.Close()
		} else {
			w.Write(make([]byte, leftOutput+1))
		}
		for len(held) > 0 {
			if looks.Load() > 2 {
				os.Stdout.WriteString("looked again")
				return
			}
			time.Sleep(time.Millisecond)
		}
		if at == "kept" { // its place given back, a pipe is closed too
			if _, err := syscall.Write(int(w.Fd()), []byte{0}); err != syscall.EPIPE {
				os.Stdout.WriteString("still open")
				return
			}
		}
		os.Stdout.WriteString("let go")
		return
	}
	if at != "ran on" {
		runtime.LockOSThread() // the filter is this thread's, and an exec keeps it
		// What is refused: prctl's first argument, the option; or the second of setresuid or setresgid, root as the effective id.
		call, argument, value := uint32(syscall.SYS_PRCTL), uint32(16), uint32(prSetDumpable)
		if at == "user back" {
			call, argument, value = syscall.SYS_SETRESUID, 24, 0
		} else if at == "group back" {
			call, argument, value = syscall.SYS_SETRESGID, 24, 0
		} else if at == "no event" { // epoll_ctl's second, the change that asks a pipe for no event: the runtime's poller makes none
			call, argument, value = syscall.SYS_EPOLL_CTL, 24, syscall.EPOLL_CTL_MOD
		} else if at == "wait" { // epoll_pwait's third, the events the keeper takes at once: the runtime's poller takes 128
			call, argument, value = syscall.SYS_EPOLL_PWAIT, 32, 64
		} else if at == "removal" { // epoll_ctl's second again: the runtime's poller takes no word from its own removals
			call, argument, value = syscall.SYS_EPOLL_CTL, 24, syscall.EPOLL_CTL_DEL
		}
		filter := []syscall.SockFilter{
			{Code: 0x20, K: 0},                               // the call's number
			{Code: 0x15, Jf: 3, K: call},                     // another call: allowed
			{Code: 0x20, K: argument},                        // its argument
			{Code: 0x15, Jf: 1, K: value},                    // another value: allowed
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
		if at == "no event" || at == "wait" { // the keeper's thread is another
			syscall.Exec("/proc/self/exe", []string{os.Args[0], "refused", "kept"}, os.Environ())
		}
		if at == "removal" {
			syscall.Exec("/proc/self/exe", []string{os.Args[0], "refused", "ended"}, os.Environ())
		}
		if strings.HasSuffix(at, " back") { // of no process: only the user's identity is taken, and given back
			signalAs(&syscall.Credential{Uid: 65534, Gid: 65534}, 1<<30, syscall.SIGKILL)
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

func TestAKeptPipeExecdCannotAskForNoEventIsLetGo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // only bounds a hang
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "refused", "no event")
	var said strings.Builder
	child.Stderr = &said

	ran, _ := child.Output() // its exit status may go to the tests' reaper

	if string(ran) != "let go" {
		t.Fatalf("with its megabyte taken of a pipe, execd said %q, then %q (%v), want it let go", said.String(), ran, ctx.Err())
	}
}

func TestExecdEndsWhereItsKeepersWaitIsRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // only bounds a hang
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "refused", "wait")
	var said strings.Builder
	child.Stderr = &said

	ran, _ := child.Output() // its exit status may go to the tests' reaper

	if ctx.Err() != nil || len(ran) > 0 || !strings.Contains(said.String(), "epoll_pwait: operation not permitted") {
		t.Fatalf("execd said %q, then %q (%v): it would make the call again and again, and let no kept pipe go", said.String(), ran, ctx.Err())
	}
}

func TestExecdEndsWhereItCannotTakeAPipeOutOfItsKeeper(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 29*time.Second) // only bounds a hang
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "refused", "removal")
	child.Cancel = func() error { return child.Process.Signal(syscall.SIGQUIT) } // a hang leaves its goroutines in what it said
	child.WaitDelay = time.Second
	var said strings.Builder
	child.Stderr = &said

	ran, _ := child.Output() // its exit status may go to the tests' reaper

	if ctx.Err() != nil || len(ran) > 0 || !strings.Contains(said.String(), "epoll_ctl: operation not permitted") {
		t.Fatalf("execd said %q, then %q (%v): a pipe it has closed is told of again while a child not yet exec'd holds it, each time for a place it does not hold", said.String(), ran, ctx.Err())
	}
}

func TestExecdEndsWhereAThreadCannotTakeItsIdentityBack(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root takes another user's identity")
	}
	for _, half := range []string{"user back", "group back"} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // only bounds a hang
		defer cancel()
		child := exec.CommandContext(ctx, os.Args[0], "refused", half)
		var said strings.Builder
		child.Stderr = &said

		ran, _ := child.Output() // its exit status may go to the tests' reaper

		if ctx.Err() != nil || len(ran) > 0 || !strings.Contains(said.String(), "could not take execd's identity back") {
			t.Fatalf("refused its %s, execd said %q, then %q (%v): the thread would do execd's other work as another", half, said.String(), ran, ctx.Err())
		}
	}
}

// Regression: Go's listeners take Multipath TCP, and a multipath peer's bytes wait in buffers nothing set on execd's socket bounds.
func TestExecdsListenerTakesAMultipathDialAsPlainTCP(t *testing.T) {
	if on, _ := os.ReadFile("/proc/sys/net/mptcp/enabled"); strings.TrimSpace(string(on)) != "1" {
		t.Skip("the kernel has Multipath TCP off")
	}
	l, err := listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var multipath net.Dialer
	multipath.SetMultipathTCP(true)
	c, err := multipath.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	taken, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	if is, _ := taken.(*net.TCPConn).MultipathTCP(); is {
		t.Fatal("execd's listener took a Multipath TCP connection")
	}
}
