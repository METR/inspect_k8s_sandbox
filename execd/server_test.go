package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

var testKey = []byte("the key")

// As the daemon runs: orphans come to this process, and it reaps them.
func TestMain(m *testing.M) {
	prctl(prSetChildSubreaper, 1)
	startReaper()
	os.Exit(m.Run())
}

func testServer() *server {
	sum := sha256.Sum256(testKey)
	s, _ := newServer(hex.EncodeToString(sum[:]))
	return s
}

// connect gives a server a connection, and returns the client's end and the frames execd sends on it.
func connect(t *testing.T, s *server) (net.Conn, <-chan frame) {
	client, daemon := net.Pipe()
	t.Cleanup(func() { client.Close() })
	s.preauth <- struct{}{}
	go s.handle(daemon)
	return client, received(client)
}

// received is closed when execd closes the connection.
func received(client net.Conn) <-chan frame {
	frames := make(chan frame, 1<<16)
	go func() {
		defer close(frames)
		for {
			f, err := readFrame(client, chunk)
			if err != nil {
				return
			}
			frames <- f
		}
	}()
	return frames
}

// begin starts a call, as the client does.
func begin(t *testing.T, s *server, req startRequest) (net.Conn, <-chan frame) {
	client, frames := connect(t, s)
	request(client, req)
	return client, frames
}

func request(client net.Conn, req startRequest) {
	payload, _ := json.Marshal(req)
	client.Write(encodeFrame(fAuth, testKey))
	client.Write(encodeFrame(fStart, payload))
}

// next returns the next frame of a kind, or fails once execd closes the connection without one.
func next(t *testing.T, frames <-chan frame, kind byte) frame {
	t.Helper()
	for budget := time.After(30 * time.Second); ; {
		select {
		case f, open := <-frames:
			if !open {
				t.Fatalf("the connection closed with no frame of kind %d", kind)
			}
			if f.kind == kind {
				return f
			}
		case <-budget:
			t.Fatalf("no frame of kind %d", kind)
		}
	}
}

func exit(t *testing.T, frames <-chan frame) exitStatus {
	t.Helper()
	var status exitStatus
	json.Unmarshal(next(t, frames, fExit).payload, &status)
	return status
}

// until waits for a condition; the budget only bounds a hang.
func until(t *testing.T, what string, condition func() bool) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); !condition(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
	}
}

func gone(pid int) bool { return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) }

// pids reads the process ids a command printed, one a line.
func pids(t *testing.T, frames <-chan frame, n int) []int {
	t.Helper()
	var out string
	for strings.Count(out, "\n") < n {
		out += string(next(t, frames, fStdout).payload)
	}
	ids := make([]int, n)
	for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fmt.Sscan(line, &ids[i])
		t.Cleanup(func() { syscall.Kill(ids[i], syscall.SIGKILL) })
	}
	return ids
}

// First: a command run as another user leaves the flag at the host's fs.suid_dumpable.
func TestExecdIsNotDumpableFromItsStart(t *testing.T) {
	const prGetDumpable = 3
	// init() has run, as it runs before main.
	if dumpable, _, _ := syscall.RawSyscall(syscall.SYS_PRCTL, prGetDumpable, 0, 0); dumpable == 1 {
		t.Fatal("dumpable: a same-uid process could reopen the start's stdout through /proc")
	}
}

func TestOnlyTheKeyStartsACommand(t *testing.T) {
	made := filepath.Join(t.TempDir(), "made")
	client, frames := connect(t, testServer())
	req, _ := json.Marshal(startRequest{Argv: []string{"touch", made}})

	client.Write(encodeFrame(fAuth, []byte("not the key")))
	client.Write(encodeFrame(fStart, req))

	for range frames { // until execd closes the connection
	}
	if _, err := os.Stat(made); err == nil {
		t.Fatal("a connection without the key ran a command")
	}
}

func TestAnAuthOverItsBoundIsRefusedAtItsHeader(t *testing.T) {
	s := testServer()
	s.authTimeout = time.Hour // so only the bound closes the connection
	client, frames := connect(t, s)

	client.Write([]byte{fAuth, 0, 0, 0, maxKey + 1}) // and no payload: execd must not wait for one

	select {
	case <-frames:
	case <-time.After(30 * time.Second):
		t.Fatal("execd waited for an AUTH payload over its bound")
	}
}

func TestAConnectionThatSendsNoAuthIsClosed(t *testing.T) {
	s := testServer()
	s.authTimeout = 50 * time.Millisecond

	_, frames := connect(t, s)

	select {
	case <-frames:
	case <-time.After(30 * time.Second):
		t.Fatal("a connection that never authenticated stayed open")
	}
	until(t, "its slot was never freed", func() bool { return len(s.preauth) == 0 })
}

type listener chan net.Conn

func (l listener) Accept() (net.Conn, error) { return <-l, nil }
func (l listener) Close() error              { return nil }
func (l listener) Addr() net.Addr            { return nil }

func TestConnectionsPastTheBoundWaitForASlot(t *testing.T) {
	s, l := testServer(), make(listener)
	go s.serve(l)
	var unauthenticated []net.Conn
	for range maxPreauth {
		client, daemon := net.Pipe()
		t.Cleanup(func() { client.Close() })
		l <- daemon
		unauthenticated = append(unauthenticated, client)
	}
	client, daemon := net.Pipe()
	t.Cleanup(func() { client.Close() })

	select {
	case l <- daemon:
		t.Fatal("accepted a connection past the bound")
	case <-time.After(50 * time.Millisecond):
	}
	unauthenticated[0].Close()
	select {
	case l <- daemon: // not refused: a burst of calls waits its turn
	case <-time.After(30 * time.Second):
		t.Fatal("a freed slot let no connection in")
	}

	frames := received(client)
	request(client, startRequest{Argv: []string{"true"}})
	if status := exit(t, frames); status.Code != 0 {
		t.Fatalf("exit %+v", status)
	}
}

func TestAConnectionFromThePodItselfIsRefused(t *testing.T) {
	s := testServer()
	s.authTimeout = time.Hour // so only the refusal closes a connection
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { l.Close() })
	go s.serve(l)

	for range maxPreauth + 1 { // more than the slots: a refusal must not keep one
		client, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.Close() })

		select {
		case <-received(client):
		case <-time.After(30 * time.Second):
			t.Fatal("a connection from loopback was not refused")
		}
	}
}

func TestStdinReachesTheCommandAndItsEndEndsIt(t *testing.T) {
	client, frames := begin(t, testServer(), startRequest{Argv: []string{"wc", "-c"}, Stdin: true})

	for range 4 { // more than a pipe holds
		client.Write(encodeFrame(fStdin, make([]byte, chunk)))
	}
	client.Write(encodeFrame(fStdin, nil))

	if counted := strings.TrimSpace(string(next(t, frames, fStdout).payload)); counted != "1048576" {
		t.Fatalf("the command read %s bytes of stdin, want 1048576", counted)
	}
	if status := exit(t, frames); status.Code != 0 {
		t.Fatalf("exit %+v", status)
	}
}

func TestALostConnectionKillsTheCommandAndWhatItStarted(t *testing.T) {
	finished := filepath.Join(t.TempDir(), "finished")
	// A child in the command's process group that has dropped its environment, one that left the group, then the command waits on its stdin.
	script := `env -i sh -c 'echo $$; exec sleep 100' & setsid sh -c 'echo $$; exec sleep 100' & echo $$; cat; touch "$1"`
	client, frames := begin(t, testServer(), startRequest{Argv: []string{"sh", "-c", script, "sh", finished}, Stdin: true})
	started := pids(t, frames, 3)

	client.Close()

	for _, pid := range started {
		until(t, "a process outlived the call's connection", func() bool { return gone(pid) })
	}
	if _, err := os.Stat(finished); err == nil {
		t.Fatal("the command took its lost connection for the end of its stdin")
	}
}

func TestAStreamsEndClosesStdinAndKillsOnlyItsCommand(t *testing.T) {
	ended := filepath.Join(t.TempDir(), "ended")
	// A child shares the stream's stdin and process group, as a tools server its command started would.
	script := `exec 3<&0; (cat <&3; touch "$1") & echo $$; exec sleep 100`
	client, frames := begin(t, testServer(), startRequest{Argv: []string{"sh", "-c", script, "sh", ended}, Stdin: true, Stream: true})
	command := pids(t, frames, 1)[0]

	client.Close()

	until(t, "the stream's command outlived it", func() bool { return gone(command) })
	until(t, "the child never saw stdin end: it was killed, or stdin stayed open", func() bool {
		_, err := os.Stat(ended)
		return err == nil
	})
}

func TestAClientGoneIsFoundWhileItsCommandLeavesStdinUnread(t *testing.T) {
	s := testServer()
	s.pingEvery = 10 * time.Millisecond
	client, frames := begin(t, s, startRequest{Argv: []string{"sh", "-c", "echo $$; exec sleep 100"}, Stdin: true})
	command := pids(t, frames, 1)[0]
	// More than the pipe holds: execd waits on the command, reads no more, and so can't see the connection close.
	client.Write(encodeFrame(fStdin, make([]byte, chunk)))

	client.Close()

	until(t, "the command outlived its client", func() bool { return gone(command) })
}

func TestACwdThatCantBeEnteredFailsAsCdDoes(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "data"), nil, 0o644)
	user := ""
	if os.Getuid() == 0 { // root enters any directory: run as a user the temporary directory's parent keeps out
		user = "nobody"
	}

	// A file that can't be run fails the same way in the kernel, and must stay a 126.
	_, frames := begin(t, testServer(), startRequest{Argv: []string{"./data"}, Cwd: dir})
	denied := exit(t, frames)
	os.Chmod(dir, 0)
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	_, frames = begin(t, testServer(), startRequest{Argv: []string{"true"}, Cwd: dir, User: user})
	entered := exit(t, frames)

	if denied.Code != 126 {
		t.Fatalf("a file that can't be run: %+v, want 126", denied)
	}
	if entered.Code != 1 || !strings.HasPrefix(entered.Error, "cd: ") {
		t.Fatalf("a cwd that can't be entered: %+v, want cd's failure", entered)
	}
}

func TestATimeoutKillsTheCommandAndSaysSo(t *testing.T) {
	_, frames := begin(t, testServer(), startRequest{Argv: []string{"sleep", "100"}, Timeout: 0.05})

	status := exit(t, frames)

	if !status.Timeout || status.Code != 128+int(syscall.SIGKILL) {
		t.Fatalf("exit %+v, want a timeout's SIGKILL", status)
	}
}

func TestAHugeTimeoutIsNoTimeout(t *testing.T) {
	_, frames := begin(t, testServer(), startRequest{Argv: []string{"sh", "-c", "sleep 0.2; exit 3"}, Timeout: 1e18})

	if status := exit(t, frames); status.Code != 3 || status.Timeout {
		t.Fatalf("exit %+v, want 3: the timeout fired at once", status)
	}
}

func TestOutputWrittenBeforeTheExitArrivesThoughAChildHoldsThePipe(t *testing.T) {
	_, frames := begin(t, testServer(), startRequest{Argv: []string{"sh", "-c", "sleep 100 & echo $!"}})

	pids(t, frames, 1) // the child's, which keeps stdout open: the exit must not wait for it
	if status := exit(t, frames); status.Code != 0 {
		t.Fatalf("exit %+v", status)
	}
}

func TestAClientThatNeverClosesIsDroppedAfterTheExit(t *testing.T) {
	s := testServer()
	s.lingerFor = 50 * time.Millisecond
	_, frames := begin(t, s, startRequest{Argv: []string{"true"}})

	exit(t, frames)

	select {
	case _, open := <-frames:
		if open {
			t.Fatal("a frame after the exit")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("execd kept the connection of a client that never closed it")
	}
}

func TestARelativePathEntryUnderARelativeCwdRuns(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	os.MkdirAll(filepath.Join(dir, "work", "bin"), 0o755)
	os.WriteFile(filepath.Join(dir, "work", "bin", "hello"), []byte("#!/bin/sh\nexit 7\n"), 0o755)
	wd, _ := os.Getwd()
	os.Chdir(dir)
	t.Cleanup(func() { os.Chdir(wd) })

	_, frames := begin(t, testServer(), startRequest{Argv: []string{"hello"}, Env: map[string]string{"PATH": "bin"}, Cwd: "work"})

	// As a shell finds it: work/bin/hello, run in work.
	if status := exit(t, frames); status.Code != 7 {
		t.Fatalf("exit %+v, want hello's 7", status)
	}
}

func TestAStartErrorFitsTheClientsControlFrame(t *testing.T) {
	cwd := "/" + strings.Repeat("\x01", 5000) // six bytes each, escaped to JSON

	_, frames := begin(t, testServer(), startRequest{Argv: []string{"true"}, Cwd: cwd})

	if n := len(next(t, frames, fExit).payload); n > 4096 { // the client's MAX_CONTROL
		t.Fatalf("EXIT is %d bytes", n)
	}
}

func TestManySmallWritesMakeAtMostAFrameAMillisecond(t *testing.T) {
	lines := "i=0; while [ $i -lt 20000 ]; do echo $i; i=$((i+1)); done"
	began := time.Now()
	_, frames := begin(t, testServer(), startRequest{Argv: []string{"sh", "-c", lines}})

	outputs, size := 0, 0
	for f := range frames {
		if f.kind == fExit {
			break
		}
		outputs++
		size += len(f.payload)
	}

	if size != 108890 {
		t.Fatalf("%d bytes of output, want the 108,890 the lines make", size)
	}
	// The client fails a pod whose execd sends ten times this.
	if took := time.Since(began); outputs > int(took/time.Millisecond)+2 {
		t.Fatalf("%d frames for 20,000 lines in %v: more than one a millisecond", outputs, took)
	}
}
