// execd: a process daemon in a sandbox container, which k8s_sandbox reaches over the pod network
// (src/k8s_sandbox/_pod/execd.py speaks its protocol). Adapted from METR/hawk-next's execd.
//
//	execd listen --port N --key-sha256 HEX [--replace]
//
// starts the daemon in the background, serving TLS 1.3 on port N with a certificate it makes at
// start, and prints "<pid> <SHA-256 of the certificate>" once it accepts connections. The client
// pins that certificate, and the first frame on a connection must carry the key whose SHA-256 is
// HEX. --replace first stops any execd already listening, which no client can use without its
// key (a client's first start does this). It is a static binary, copied into each Pod by an init
// container, so task images need no change. Processes are children of execd, not of the
// connection, so a dropped connection loses nothing: output is buffered until the client
// acknowledges it.
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
	run(*port, *keyHash)
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "execd:", msg)
	os.Exit(2)
}

// prctl options: a non-dumpable process's /proc files (environ, mem, fd) are closed to
// other processes of the same uid, and a subreaper inherits its descendants' orphans.
const prSetDumpable, prSetChildSubreaper = 4, 36

func prctl(option, arg uintptr) {
	syscall.RawSyscall(syscall.SYS_PRCTL, option, arg, 0)
}

// start re-runs execd in a new session, so the daemon outlives the exec that started it, and
// relays the line the daemon writes on fd 3 once it listens: its fingerprint, or its error.
func start() {
	r, w, err := os.Pipe()
	if err != nil {
		fail(err.Error())
	}
	devnull, _ := os.Open(os.DevNull)
	p, err := os.StartProcess("/proc/self/exe", os.Args, &os.ProcAttr{
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
	fmt.Printf("%d %s\n", p.Pid, fingerprint)
}

func run(port int, keyHash string) {
	os.Unsetenv(foregroundEnv)
	status := os.NewFile(3, "status")
	report := func(msg string) {
		status.WriteString(msg + "\n")
		status.Close()
	}
	prctl(prSetDumpable, 0)
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
	for i := 0; err != nil && i < 20 && errors.Is(err, syscall.EADDRINUSE); i++ {
		time.Sleep(100 * time.Millisecond) // a daemon just stopped by --replace
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

// selfSigned makes the daemon's certificate. Its key never leaves this process's memory; the
// client trusts the certificate by the fingerprint the start exec printed.
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
