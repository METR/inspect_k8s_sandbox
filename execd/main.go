// execd runs k8s_sandbox's commands in the sandbox, over pinned TLS (see src/k8s_sandbox/_pod/execd.py).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// As early as it can be; only a binary its exec can't read (mode 111, and no CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH) closes the window.
func init() { undumpable() }

func main() {
	if len(os.Args) > 6 && os.Args[1] == "as" { // how run() starts a command for another user
		become(os.Args[2], os.Args[3:6], os.Args[6:])
	}
	if len(os.Args) > 6 && os.Args[1] == "search" { // how the daemon signals what carries a tag as another user, with every id of theirs
		if err := take(os.Args[2:5]); err != nil {
			fail(err.Error())
		}
		sig, _ := strconv.Atoi(os.Args[6])
		skip := map[int]string{}
		var among map[int]string // after a "+": the only processes to signal, each as id:start time
		for _, p := range os.Args[7:] {
			id, started, _ := strings.Cut(p, ":")
			if pid, _ := strconv.Atoi(id); p == "+" {
				among = map[int]string{}
			} else if among != nil {
				among[pid] = started
			} else {
				skip[pid] = ""
			}
		}
		signalTagged(os.Args[5], syscall.Signal(sig), skip, among)
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "connect" { // how the client reaches a daemon on a socket
		connect(os.Args[2])
	}
	if len(os.Args) < 2 || os.Args[1] != "listen" && os.Args[1] != "serve" {
		fail("usage: execd listen (--port N | --socket NAME) --key-sha256 HEX")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	port := fs.Int("port", 0, "TCP port")
	socket := fs.String("socket", "", "abstract Unix socket")
	keyHash := fs.String("key-sha256", "", "hex SHA-256 of the session key")
	replace := fs.Bool("replace", false, "stop any execd already listening")
	fs.Parse(os.Args[2:])
	if os.Args[1] == "listen" { // an exec's: the daemon it starts runs "serve"
		if *replace {
			stopOthers()
		}
		start()
		return
	}
	network, address := "tcp", fmt.Sprintf(":%d", *port)
	if *socket != "" {
		network, address = "unix", "@"+*socket
	}
	run(network, address, *keyHash, *replace)
}

// connect joins an exec's stdin and stdout to the daemon on the abstract socket name, until either ends.
func connect(name string) {
	c, err := net.Dial("unix", "@"+name)
	if err != nil {
		fail(err.Error())
	}
	go func() { io.Copy(c, os.Stdin); os.Exit(0) }()
	io.Copy(struct{ io.Writer }{os.Stdout}, c) // not os.Stdout's ReadFrom: it splices, and while the exec's stdout is full it retries without waiting
	os.Exit(0)
}

// memoryLimit is half the cgroup's memory limit, or 32 MiB if that is more or the limit can't be read; none where it has none.
func memoryLimit(cgroupMax []byte, err error) int64 {
	limit := strings.TrimSpace(string(cgroupMax))
	if limit == "max" {
		return math.MaxInt64
	}
	n, bad := strconv.ParseInt(limit, 10, 64)
	if err != nil || bad != nil {
		return 32 << 20
	}
	return max(n/2, 32<<20)
}

// cgroupLimit reads cgroup v2's memory limit under root, or v1's where there is none, as on gVisor.
func cgroupLimit(root string) ([]byte, error) {
	if limit, err := os.ReadFile(root + "/memory.max"); err == nil {
		return limit, nil
	}
	return os.ReadFile(root + "/memory/memory.limit_in_bytes")
}

// take gives this process a user's identity for good: their groups, gid and uid, each real, effective and saved.
func take(ids []string) error {
	var n []int
	for _, id := range append([]string{ids[0], ids[1]}, strings.Fields(ids[2])...) {
		i, err := strconv.Atoi(id)
		if err != nil {
			fail(err.Error())
		}
		n = append(n, i)
	}
	err := syscall.Setgroups(n[2:])
	if err == nil {
		err = syscall.Setgid(n[1])
	}
	if err == nil {
		err = syscall.Setuid(n[0])
	}
	return err
}

// become takes a user's identity, enters cwd as them and execs argv, failing as a shell would.
func become(cwd string, ids, argv []string) {
	err := take(ids)
	code := 126
	if err == nil && cwd != "" {
		if err = os.Chdir(cwd); err != nil {
			err, code = fmt.Errorf("cd: %s: %w", cwd, errors.Unwrap(err)), 1
		}
	}
	var raw [][]byte
	if err == nil {
		pipe := os.NewFile(3, "environment") // run()'s
		err = json.NewDecoder(pipe).Decode(&raw)
		pipe.Close()
	}
	if err == nil {
		env := make([]string, len(raw))
		for i, kv := range raw {
			env[i] = string(kv)
		}
		var files syscall.Rlimit
		if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &files) == nil && files.Max >= 1024 { // as runuser leaves it since util-linux 2.38
			files.Cur = 1024
			syscall.Setrlimit(syscall.RLIMIT_NOFILE, &files)
		}
		if err = syscall.Exec(argv[0], argv, env); errors.Is(err, syscall.ENOENT) {
			code = 127
		}
		err = fmt.Errorf("%s: %w", argv[0], err)
	}
	fmt.Fprintln(os.Stderr, "execd:", err)
	os.Exit(code)
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "execd:", msg)
	os.Exit(2)
}

// Non-dumpable: same-uid processes can't open its /proc files. Subreaper: it reaps orphans.
const prSetDumpable, prSetChildSubreaper = 4, 36

func prctl(option, arg uintptr) syscall.Errno {
	_, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, option, arg, 0)
	return errno
}

// undumpable ends execd where the kernel refuses, as a seccomp profile can: its user could read its memory.
func undumpable() {
	if errno := prctl(prSetDumpable, 0); errno != 0 {
		fail("prctl(PR_SET_DUMPABLE): " + errno.Error())
	}
}

// start re-runs execd in a new session, so it outlives this exec, and relays its status line.
func start() {
	// A socket, not a pipe: /proc/PID/fd can't reopen it, so only the daemon writes its status.
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		fail(err.Error())
	}
	r, w := os.NewFile(uintptr(fds[0]), "status"), os.NewFile(uintptr(fds[1]), "status")
	devnull, _ := os.Open(os.DevNull)
	daemon, err := os.StartProcess("/proc/self/exe", append([]string{os.Args[0], "serve"}, os.Args[2:]...), &os.ProcAttr{
		Files: []*os.File{devnull, devnull, devnull, w},
		Sys:   &syscall.SysProcAttr{Setsid: true},
	})
	if err != nil {
		fail(err.Error())
	}
	w.Close()
	line, _ := io.ReadAll(io.LimitReader(r, 4096))
	msg := strings.TrimSpace(string(line))
	fingerprint, ok := strings.CutPrefix(msg, "ok ")
	if !ok {
		daemon.Wait() // it has exited: no zombie is left to a first process that reaps none
		fail("daemon did not start: " + msg)
	}
	fmt.Println(fingerprint, container())
}

// container names the container execd is in: a client that finds another has seen a restart, whatever Kubernetes shows.
func container() string {
	boot, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if f := stat(1); len(f) > 19 { // the kernel's boot, and when the container's first process started
		return strings.TrimSpace(string(boot)) + ":" + f[19]
	}
	return "unknown"
}

func run(network, address, keyHash string, replace bool) {
	status := os.NewFile(3, "status")
	report := func(msg string) {
		status.WriteString(msg + "\n")
		status.Close()
	}
	prctl(prSetChildSubreaper, 1)
	debug.SetMemoryLimit(memoryLimit(cgroupLimit("/sys/fs/cgroup"))) // soft: execd's garbage counts against the sandbox's memory
	s, err := newServer(keyHash)
	if err != nil {
		report(err.Error())
		os.Exit(2)
	}
	cert, fingerprint, err := selfSigned()
	if err != nil {
		report(err.Error())
		os.Exit(2)
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	l, err := tls.Listen(network, address, config)
	for i := 0; replace && err != nil && i < 20 && errors.Is(err, syscall.EADDRINUSE); i++ {
		time.Sleep(100 * time.Millisecond) // the daemon --replace stopped may still hold the address
		l, err = tls.Listen(network, address, config)
	}
	if err != nil {
		report(err.Error())
		os.Exit(2)
	}
	startReaper()
	startSearcher()
	startKeeper()
	report("ok " + fingerprint)
	s.serve(l)
}

// stopOthers kills every other process running this binary as the daemon.
func stopOthers() {
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cmdline, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		args := strings.Split(string(cmdline), "\x00")
		if err == nil && len(args) > 1 && args[0] == os.Args[0] && args[1] == "serve" {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

// selfSigned makes the certificate clients pin by fingerprint; its key stays in memory.
func selfSigned() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:]), nil
}
