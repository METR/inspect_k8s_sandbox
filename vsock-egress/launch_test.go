package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const vmUID = 4242 // a VM's uid in the tests that run as root

// fakeNode lays out a node's directories as AWS's runtime and libcni do.
func fakeNode(t *testing.T) *launcher {
	t.Helper()
	dir, err := os.MkdirTemp("", "node")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	os.Chmod(dir, 0o755) // a VM's uid must reach its own directory
	l := newLauncher()
	l.node = node{vms: dir + "/vms", cni: dir + "/cni", netns: "/proc/self/ns"}
	for _, d := range []string{l.vms, l.cni} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

// addSandbox writes the record libcni keeps for a pod's interface and makes the VM's directory, owned by uid.
func addSandbox(t *testing.T, l *launcher, id, ifName string, annotations map[string]string, uid int) (recordFile string) {
	t.Helper()
	r := map[string]any{
		"kind": "cniCacheV1", "containerId": id, "ifName": ifName, "netns": "/var/run/netns/net",
		"cniArgs":        [][2]string{{"K8S_POD_NAMESPACE", "ns"}, {"K8S_POD_NAME", "pod-" + id[:4]}},
		"capabilityArgs": map[string]any{"io.kubernetes.cri.pod-annotations": annotations},
	}
	b, _ := json.Marshal(r)
	recordFile = filepath.Join(l.cni, "aws-cni-"+id+"-"+ifName)
	if err := os.WriteFile(recordFile, b, 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(l.vms, id[:12], "root")
	os.Mkdir(filepath.Dir(root), 0o755) // root's and open to all, as the runtime has it
	if err := os.Mkdir(root, 0o700); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(root, uid, uid); err != nil {
			t.Fatal(err)
		}
	}
	return recordFile
}

func id(c string) string { return strings.Repeat(c, 64) }

func TestOnlySandboxesThatNameAProxyAreWanted(t *testing.T) {
	proxied := map[string]string{proxyAnnotation: "10.0.0.9:3128"}
	for name, tc := range map[string]struct {
		ifName      string
		annotations map[string]string
		uid         int // of the VM's directory, where the test can choose it: as root
		wanted      bool
	}{
		"a proxy by address":              {"eth0", proxied, vmUID, true},
		"a proxy by name":                 {"eth0", map[string]string{proxyAnnotation: "proxy.ns.svc.cluster.local.:3128"}, vmUID, true},
		"no proxy":                        {"eth0", map[string]string{"other": "annotation"}, vmUID, false},
		"more than host:port":             {"eth0", map[string]string{proxyAnnotation: "http://10.0.0.9:3128 -rate=1"}, vmUID, false},
		"the loopback interface's record": {"lo", proxied, vmUID, false},
		"a VM directory that is root's":   {"eth0", proxied, 0, false},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.uid == 0 && os.Geteuid() != 0 {
				t.Skip("only root can make a directory root's")
			}
			l := fakeNode(t)
			addSandbox(t, l, id("a"), tc.ifName, tc.annotations, tc.uid)
			wanted, err := l.wanted()
			if err != nil {
				t.Fatal(err)
			}
			sb, ok := wanted[id("a")]
			if ok != tc.wanted || len(wanted) > 1 {
				t.Fatalf("wanted %v, want the sandbox: %v", wanted, tc.wanted)
			}
			want := sandbox{pod: "ns/pod-aaaa", root: filepath.Join(l.vms, id("a")[:12], "root"), netns: "/proc/self/ns/net",
				target: tc.annotations[proxyAnnotation], uid: sb.uid, gid: sb.gid}
			if ok && (sb != want || os.Geteuid() == 0 && sb.uid != vmUID) {
				t.Fatalf("got %+v, want %+v", sb, want)
			}
		})
	}
}

func TestSandboxWhoseUidAnotherVMHasGetsNoWorker(t *testing.T) {
	l := fakeNode(t)
	addSandbox(t, l, id("a"), "eth0", map[string]string{proxyAnnotation: "10.0.0.9:3128"}, vmUID)
	addSandbox(t, l, id("b"), "eth0", nil, vmUID) // names no proxy, and runs as the same uid
	wanted, err := l.wanted()
	if err != nil {
		t.Fatal(err)
	}
	if len(wanted) != 0 {
		t.Fatalf("wanted %v: a worker as that uid could open the other VM's socket", wanted)
	}
}

func TestLaunchNeedsAPIDNamespaceOfItsOwn(t *testing.T) {
	err := launch([]string{"-cni", filepath.Join(t.TempDir(), "none")})
	if err == nil || !strings.Contains(err.Error(), "PID namespace") {
		t.Fatalf("got %v: among the node's processes, ending a worker would end its VM", err)
	}
}

// podNetns makes a network namespace for the test's pod, and returns the directory that holds its file "net".
func podNetns(t *testing.T) string {
	t.Helper()
	made, done := make(chan string), make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		runtime.LockOSThread() // never unlocked: the namespace lasts as long as this thread, which ends with the test
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			made <- ""
			return
		}
		made <- fmt.Sprintf("/proc/self/task/%d/ns", unix.Gettid())
		<-done
	}()
	dir := <-made
	if dir == "" {
		t.Skip("cannot make a network namespace here: needs CAP_SYS_ADMIN")
	}
	return dir
}

// status reads a field of a process's /proc status, as "Uid:\t4242\t4242\t4242\t4242".
func status(t *testing.T, pid int, field string) string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, field+":") {
			return strings.Join(strings.Fields(line)[1:], " ")
		}
	}
	return ""
}

// listening waits until the sandbox's worker has made its socket in the VM's directory.
func listening(t *testing.T, l *launcher, id string) {
	t.Helper()
	socket := filepath.Join(l.vms, id[:12], "root", fmt.Sprintf("vm.vsock_%d", streamPort))
	for deadline := time.Now().Add(budget); ; time.Sleep(time.Millisecond) {
		if _, err := os.Stat(socket); err == nil {
			return
		}
		if time.Now().After(deadline) || l.workers[id].exited() {
			t.Fatalf("the worker did not come to listen at %s", socket)
		}
	}
}

func ended(t *testing.T, w *child) {
	t.Helper()
	select {
	case <-w.done:
	case <-time.After(budget):
		t.Fatalf("worker %d is still running", w.cmd.Process.Pid)
	}
}

func TestWorkerRunsAsItsVMsUidAndEndsWithItsSandbox(t *testing.T) {
	self, _ := os.Executable()
	for d := filepath.Dir(self); d != "/"; d = filepath.Dir(d) {
		if st, err := os.Stat(d); os.Geteuid() != 0 || err != nil || st.Mode().Perm()&0o005 != 0o005 {
			t.Skip("needs root, and this test binary where another uid can run it: go test -c -o DIR/x.test with DIR open to all")
		}
	}
	l := fakeNode(t)
	l.netns = podNetns(t)
	record := addSandbox(t, l, id("a"), "eth0", map[string]string{proxyAnnotation: "127.0.0.1:9"}, vmUID)
	t.Cleanup(func() {
		for _, w := range l.workers {
			w.end()
		}
	})
	if err := l.pass(); err != nil {
		t.Fatal(err)
	}
	first := l.workers[id("a")]
	if first == nil {
		t.Fatal("no worker for a sandbox that names a proxy")
	}
	listening(t, l, id("a"))
	pid := first.cmd.Process.Pid
	uids, caps := fmt.Sprintf("%d %[1]d %[1]d %[1]d", vmUID), "0000000000000000"
	if got := status(t, pid, "Uid"); got != uids {
		t.Fatalf("the worker's uids are %q, want %q", got, uids)
	}
	for _, set := range []string{"CapPrm", "CapEff", "CapAmb"} {
		if got := status(t, pid, set); got != caps {
			t.Fatalf("the worker's %s is %s, want none", set, got)
		}
	}
	if got := status(t, pid, "Groups"); got != "" {
		t.Fatalf("the worker kept groups %q", got)
	}
	pod, _ := os.Readlink(l.netns + "/net")
	if got, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid)); got != pod {
		t.Fatalf("the worker is in network namespace %q (%v), not the pod's %s", got, err, pod)
	}
	threads, _ := filepath.Glob("/proc/self/task/*/ns/net")
	for _, thread := range threads {
		if got, _ := os.Readlink(thread); got == pod && thread != l.netns+"/net" {
			t.Fatalf("%s stayed in the pod's network namespace", thread)
		}
	}

	syscall.Kill(pid, syscall.SIGKILL)
	ended(t, first)
	l.retry = time.Hour
	if err := l.pass(); err != nil {
		t.Fatal(err)
	}
	if again := l.workers[id("a")]; again != nil {
		t.Fatal("a worker that died just after it started was started again at once")
	}
	l.retry = 0
	if err := l.pass(); err != nil {
		t.Fatal(err)
	}
	second := l.workers[id("a")]
	if second == nil {
		t.Fatal("a worker that died was not replaced")
	}
	listening(t, l, id("a"))

	// The next worker does not end when its stdin closes: it is ended all the same.
	t.Setenv(deafWorker, "1")
	syscall.Kill(second.cmd.Process.Pid, syscall.SIGKILL)
	ended(t, second)
	if err := l.pass(); err != nil {
		t.Fatal(err)
	}
	second = l.workers[id("a")]
	if second == nil {
		t.Fatal("a worker that died was not replaced")
	}

	os.Remove(record) // the sandbox is deleted
	if err := l.pass(); err != nil {
		t.Fatal(err)
	}
	ended(t, second)
	if len(l.workers) != 0 {
		t.Fatalf("the launcher still holds %d workers", len(l.workers))
	}
}
