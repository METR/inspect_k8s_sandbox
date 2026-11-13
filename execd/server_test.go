package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync/atomic"
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

// connect gives a server a connection; it returns the client's end and the frames execd sends.
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

// output reads frames up to the exit: each kind's payloads joined, and the count before the exit.
func output(t *testing.T, frames <-chan frame) (map[byte][]byte, int) {
	t.Helper()
	got := map[byte][]byte{}
	for n, budget := 0, time.After(30*time.Second); ; n++ {
		select {
		case f, open := <-frames:
			if !open {
				t.Fatal("the connection closed before the exit")
			}
			got[f.kind] = append(got[f.kind], f.payload...)
			if f.kind == fExit {
				return got, n
			}
		case <-budget:
			t.Fatal("no exit")
		}
	}
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

const prGetDumpable = 3

func TestExecdIsNotDumpableFromItsStart(t *testing.T) {
	// init() has run, as it runs before main.
	if dumpable, _, _ := syscall.RawSyscall(syscall.SYS_PRCTL, prGetDumpable, 0, 0); dumpable != 0 {
		t.Fatal("dumpable: a same-uid process could reopen the start's stdout through /proc")
	}
}

func TestOnlyTheKeyStartsACommand(t *testing.T) {
	made := filepath.Join(t.TempDir(), "made")
	client, frames := connect(t, testServer())
	req, _ := json.Marshal(startRequest{Argv: []string{"touch", made}})

	client.Write(encodeFrame(fAuth, []byte("not the key")))
	client.Write(encodeFrame(fStart, req))

	select {
	case f, open := <-frames:
		if open {
			t.Fatalf("execd answered a connection without the key: a frame of kind %d", f.kind)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("execd kept a connection without the key")
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

func TestACommandOutlivesTheTimeToAuthenticate(t *testing.T) {
	s := testServer()
	s.authTimeout = 50 * time.Millisecond

	_, frames := begin(t, s, startRequest{Argv: []string{"sh", "-c", "sleep 0.2; exit 3"}})

	if status := exit(t, frames); status.Code != 3 {
		t.Fatalf("exit %+v, want 3: the connection's first deadline still stood", status)
	}
}

type listener chan net.Conn

func (l listener) Accept() (net.Conn, error) { return <-l, nil }
func (l listener) Close() error              { return nil }
func (l listener) Addr() net.Addr            { return nil }

func TestConnectionsPastTheBoundWaitForASlot(t *testing.T) {
	s, l := testServer(), make(listener)
	s.authTimeout = time.Hour // so only a closed connection frees a slot
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
	l, _ := net.Listen("tcp", ":0")
	t.Cleanup(func() { l.Close() })
	go s.serve(l)
	port := l.Addr().(*net.TCPAddr).Port
	own := []string{"127.0.0.1"}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
			own = append(own, n.IP.String()) // a connection to it comes from it
		}
	}

	for i := range maxPreauth + len(own) { // more than the slots: a refusal must not keep one
		client, err := net.Dial("tcp", net.JoinHostPort(own[i%len(own)], fmt.Sprint(port)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.Close() })

		select {
		case <-received(client):
		case <-time.After(30 * time.Second):
			t.Fatalf("a connection from %s was not refused", own[i%len(own)])
		}
	}
}

func TestStdinStdoutAndStderrEachArriveWhole(t *testing.T) {
	client, frames := begin(t, testServer(), startRequest{Argv: []string{"sh", "-c", "cat; echo to stderr >&2"}, Stdin: true})
	stdin := make([]byte, 4*chunk) // more than a pipe holds
	for i := range stdin {
		stdin[i] = byte(i % 251)
	}

	for i := 0; i < len(stdin); i += chunk {
		client.Write(encodeFrame(fStdin, stdin[i:i+chunk]))
	}
	client.Write(encodeFrame(fStdin, nil)) // its end: cat exits

	got, _ := output(t, frames)
	if !bytes.Equal(got[fStdout], stdin) || string(got[fStderr]) != "to stderr\n" || string(got[fExit]) != `{"code":0}` {
		t.Fatalf("stdout is %d bytes of the %d sent; stderr %q; exit %s", len(got[fStdout]), len(stdin), got[fStderr], got[fExit])
	}
}

func TestALostConnectionKillsTheCommandAndWhatItStarted(t *testing.T) {
	// One child in the group has no environment, one has left the group; the command waits on stdin.
	script := `env -i sh -c 'echo $$; exec sleep 100' & setsid sh -c 'echo $$; exec sleep 100' & echo $$; cat`
	client, frames := begin(t, testServer(), startRequest{Argv: []string{"sh", "-c", script}, Stdin: true})
	started := pids(t, frames, 3)

	client.Close()

	for _, pid := range started {
		until(t, "a process outlived the call's connection", func() bool { return gone(pid) })
	}
}

func TestALostConnectionKillsAProcessInsideExecve(t *testing.T) {
	// Eight left the group and exec without end: while one does, /proc shows it no environment.
	script := `for i in 1 2 3 4 5 6 7 8; do setsid sh -c 'echo $$; eval "$AGAIN"' & done; cat`
	req := startRequest{Argv: []string{"sh", "-c", script}, Env: map[string]string{"AGAIN": `exec sh -c "$AGAIN"`}, Stdin: true}
	for range 30 {
		client, frames := begin(t, testServer(), req)
		started := pids(t, frames, 8)

		client.Close()

		for _, pid := range started {
			until(t, "a process inside execve outlived the call's connection", func() bool { return gone(pid) })
		}
	}
}

func TestALostConnectionKillsWhatAProcessOutsideTheGroupForksMeanwhile(t *testing.T) {
	// One that left the group forks without pause, so some start while execd looks through /proc.
	forked := filepath.Join(t.TempDir(), "forked")
	script := `setsid sh -c 'echo $$; while :; do sleep 100 >/dev/null 2>&1 & echo $! >>"$0"; done' "$1" & cat`
	client, frames := begin(t, testServer(), startRequest{Argv: []string{"sh", "-c", script, "sh", forked}, Stdin: true})
	forker := pids(t, frames, 1)[0]
	until(t, "the forker forked nothing", func() bool {
		list, _ := os.ReadFile(forked)
		return bytes.Count(list, []byte("\n")) >= 20
	})

	client.Close()

	until(t, "the forker outlived the call's connection", func() bool { return gone(forker) })
	list, _ := os.ReadFile(forked)
	for _, line := range strings.Fields(string(list)) {
		var pid int
		fmt.Sscan(line, &pid)
		t.Cleanup(func() { syscall.Kill(pid, syscall.SIGKILL) })
		until(t, "a process forked during the kill outlived the call's connection", func() bool { return gone(pid) })
	}
}

func TestAProcessThatClearedItsEnvironmentIsLookedAtTenTimesOnly(t *testing.T) {
	// It shows no environment at every look; one inside execve does at one or two.
	_, frames := begin(t, testServer(), startRequest{Argv: []string{"sh", "-c", "echo $$; exec env -i sleep 100"}})
	cleared := fmt.Sprintf("/proc/%d/environ", pids(t, frames, 1)[0])
	until(t, "env never cleared the environment", func() bool {
		environment, err := os.ReadFile(cleared)
		return err == nil && len(environment) == 0
	})

	// Others here may be inside execve too, each for a look or two more.
	if looks := killTagged("no call's tag"); looks > 50 {
		t.Fatalf("%d looks for a tag no process holds", looks)
	}
}

func TestStdinACommandDoesNotReadWaitsInTheConnection(t *testing.T) {
	client, frames := begin(t, testServer(), startRequest{Argv: []string{"sh", "-c", "echo $$; exec sleep 100"}, Stdin: true})
	pids(t, frames, 1)
	var taken atomic.Int32
	go func() {
		for range 8 {
			client.Write(encodeFrame(fStdin, make([]byte, chunk))) // returns once execd has read it
			taken.Add(1)
		}
	}()

	time.Sleep(50 * time.Millisecond) // long enough for execd to take them all, if it would

	// One fills the command's pipe and is held; the next waits where TCP would hold it back.
	if n := taken.Load(); n > 2 {
		t.Fatalf("execd took %d frames of stdin its command has not read", n)
	}
}

func TestAStreamsEndClosesStdinAndKillsOnlyItsCommand(t *testing.T) {
	gc := debug.SetGCPercent(-1) // so no finalizer closes a stdin execd left open
	t.Cleanup(func() { debug.SetGCPercent(gc) })
	ended := filepath.Join(t.TempDir(), "ended")
	// A child shares the stream's stdin and process group, as a tools server it started would.
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
	// More than the pipe holds: execd waits on the command, so it can't see the connection close.
	client.Write(encodeFrame(fStdin, make([]byte, chunk)))

	client.Close()

	until(t, "the command outlived its client", func() bool { return gone(command) })
}

func TestACwdThatCantBeEnteredFailsTheCallAsCdDoes(t *testing.T) {
	dir := t.TempDir()
	open, _ := os.MkdirTemp("", "execd") // where any user could make a file
	os.Chmod(open, 0o777)
	t.Cleanup(func() { os.RemoveAll(open) })
	made := filepath.Join(open, "made")
	os.WriteFile(filepath.Join(dir, "file"), nil, 0o644)
	closed := filepath.Join(dir, "closed")
	os.Mkdir(closed, 0)
	user := ""
	if os.Getuid() == 0 { // root enters any directory: run as a user this one keeps out
		user = "nobody"
	}

	for _, cwd := range []string{closed, filepath.Join(dir, "file"), filepath.Join(dir, "missing")} {
		_, frames := begin(t, testServer(), startRequest{Argv: []string{"touch", made}, Cwd: cwd, User: user})

		// As cd fails in the shell, already running as the user: not as a command that can't start.
		if status := exit(t, frames); status.Code == 0 || status.Code == 126 || status.Error != "" {
			t.Fatalf("cwd %s: %+v, want cd's failure", cwd, status)
		}
	}
	if _, err := os.Stat(made); err == nil {
		t.Fatal("the command ran outside its cwd")
	}
}

func TestAVariableNameShWouldDropFailsTheCall(t *testing.T) {
	_, frames := begin(t, testServer(), startRequest{Argv: []string{"true"}, Env: map[string]string{"a-b": "1"}})

	if status := exit(t, frames); status.Code != 126 || !strings.Contains(status.Error, "a-b") {
		t.Fatalf("exit %+v, want the name refused", status)
	}
}

func TestExecdStaysNonDumpableAfterACommandAsAnotherUser(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root can run a command as another user")
	}
	_, frames := begin(t, testServer(), startRequest{Argv: []string{"true"}, User: "nobody"})

	exit(t, frames)

	// The change of user sets the flag to the host's fs.suid_dumpable: 2 on Ubuntu.
	if dumpable, _, _ := syscall.RawSyscall(syscall.SYS_PRCTL, prGetDumpable, 0, 0); dumpable != 0 {
		t.Fatalf("dumpable is %d after a command as another user", dumpable)
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
	client, frames := begin(t, testServer(), startRequest{Argv: []string{"sh", "-c", "sleep 100 & echo $!"}})

	child := pids(t, frames, 1)[0] // which keeps stdout open: the exit must not wait for it
	if status := exit(t, frames); status.Code != 0 {
		t.Fatalf("exit %+v", status)
	}

	client.Close()

	time.Sleep(50 * time.Millisecond) // long enough for execd to kill the child, if it would
	if gone(child) {
		t.Fatal("closing a finished call's connection killed what its command left running")
	}
}

func TestACommandGivenNoCwdStartsWhereExecdDidThoughTheDirectoryWasReplaced(t *testing.T) {
	s := testServer()
	tests := s.workdir
	t.Cleanup(func() { os.Chdir(tests) }) // back where the tests run
	s.workdir = filepath.Join(t.TempDir(), "work")
	for _, content := range []string{"old", "new"} { // as a command's rm -rf and mkdir of it
		os.RemoveAll(s.workdir)
		os.Mkdir(s.workdir, 0o755)
		os.WriteFile(filepath.Join(s.workdir, "f"), []byte(content), 0o644)
		_, frames := begin(t, s, startRequest{Argv: []string{"cat", "f"}})

		if got, _ := output(t, frames); string(got[fStdout]) != content {
			t.Fatalf("cat f gave %q, want %q: the command ran in the directory that was removed", got[fStdout], content)
		}
	}
}

func TestOutputStillInThePipeAtTheExitArrives(t *testing.T) {
	client, daemon := net.Pipe()
	t.Cleanup(func() { client.Close() })
	s := testServer()
	s.preauth <- struct{}{}
	go s.handle(daemon)
	// A child keeps stdout open; the command prints while its first line waits unread, then exits.
	request(client, startRequest{Argv: []string{"sh", "-c", "sleep 100 & echo $!; sleep 0.1; head -c 4000 /dev/zero"}})

	time.Sleep(400 * time.Millisecond) // past the exit and the grace a held pipe gets
	frames := received(client)

	child := pids(t, frames, 1)[0]
	got, _ := output(t, frames)
	if size := len(got[fStdout]); size != 4000 { // which fit the smallest pipe
		t.Fatalf("%d of the 4,000 bytes written before the exit arrived (child %d)", size, child)
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

func TestAStartErrorFitsTheClientsControlFrame(t *testing.T) {
	user := strings.Repeat("\x01", 5000) // six bytes each, escaped to JSON

	_, frames := begin(t, testServer(), startRequest{Argv: []string{"true"}, User: user})

	if n := len(next(t, frames, fExit).payload); n > 4096 { // the most the client takes in an EXIT
		t.Fatalf("EXIT is %d bytes", n)
	}
}

func TestManySmallWritesMakeAtMostAFrameAMillisecond(t *testing.T) {
	lines := "i=0; while [ $i -lt 20000 ]; do echo $i; i=$((i+1)); done"
	began := time.Now()
	_, frames := begin(t, testServer(), startRequest{Argv: []string{"sh", "-c", lines}})

	got, outputs := output(t, frames)

	if size := len(got[fStdout]); size != 108890 {
		t.Fatalf("%d bytes of output, want the 108,890 the lines make", size)
	}
	// The client fails a pod whose execd sends ten times this.
	if took := time.Since(began); outputs > int(took/time.Millisecond)+2 {
		t.Fatalf("%d frames for 20,000 lines in %v: more than one a millisecond", outputs, took)
	}
}
