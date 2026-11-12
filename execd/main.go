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
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const foregroundEnv = "HN_EXECD_FOREGROUND"

// Before main, and so before --replace scans /proc: the sandbox can't reopen its stdout.
func init() { prctl(prSetDumpable, 0) }

func main() {
	if len(os.Args) < 2 || os.Args[1] != "listen" {
		fail("usage: execd listen --port N --key-sha256 HEX")
	}
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	port := fs.Int("port", 0, "TCP port")
	keyHash := fs.String("key-sha256", "", "hex SHA-256 of the session key")
	replace := fs.Bool("replace", false, "stop any execd already listening")
	fs.Parse(os.Args[2:])
	if os.Getenv(foregroundEnv) == "" {
		if *replace {
			stopOthers()
		}
		start()
		return
	}
	run(*port, *keyHash, *replace)
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "execd:", msg)
	os.Exit(2)
}

// Non-dumpable: same-uid processes can't open its /proc files. Subreaper: it reaps orphans.
const prSetDumpable, prSetChildSubreaper = 4, 36

func prctl(option, arg uintptr) {
	syscall.RawSyscall(syscall.SYS_PRCTL, option, arg, 0)
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
	_, err = os.StartProcess("/proc/self/exe", os.Args, &os.ProcAttr{
		Env:   append(os.Environ(), foregroundEnv+"=1"),
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
		fail("daemon did not start: " + msg)
	}
	fmt.Println(fingerprint)
}

func run(port int, keyHash string, replace bool) {
	os.Unsetenv(foregroundEnv)
	status := os.NewFile(3, "status")
	report := func(msg string) {
		status.WriteString(msg + "\n")
		status.Close()
	}
	prctl(prSetChildSubreaper, 1)
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
	l, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), config)
	for i := 0; replace && err != nil && i < 20 && errors.Is(err, syscall.EADDRINUSE); i++ {
		time.Sleep(100 * time.Millisecond) // the daemon --replace stopped may still hold the port
		l, err = tls.Listen("tcp", fmt.Sprintf(":%d", port), config)
	}
	if err != nil {
		report(err.Error())
		os.Exit(2)
	}
	startReaper()
	report("ok " + fingerprint)
	s.serve(l)
}

// stopOthers kills every other process running this binary's listen mode.
func stopOthers() {
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		cmdline, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		args := strings.Split(string(cmdline), "\x00")
		if err == nil && len(args) > 1 && args[0] == os.Args[0] && args[1] == "listen" {
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
