package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
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
	proxied := map[string]string{proxyAnnotation: "proxy.ns.svc.cluster.local.:3128"}
	for name, tc := range map[string]struct {
		ifName      string
		annotations map[string]string
		uid         int // of the VM's directory, where the test can choose it: as root
		wanted      bool
	}{
		"a Service of its namespace":      {"eth0", proxied, vmUID, true},
		"an address":                      {"eth0", map[string]string{proxyAnnotation: "10.0.0.9:3128"}, vmUID, false},
		"a Service of another namespace":  {"eth0", map[string]string{proxyAnnotation: "proxy.other.svc.cluster.local:3128"}, vmUID, false},
		"no proxy":                        {"eth0", map[string]string{"other": "annotation"}, vmUID, false},
		"more than a name and a port":     {"eth0", map[string]string{proxyAnnotation: "proxy.ns.svc.cluster.local:3128 -rate=1"}, vmUID, false},
		"the loopback interface's record": {"lo", proxied, vmUID, false},
		"a VM directory that is root's":   {"eth0", proxied, 0, false},
		"a VM with the reaper's uid":      {"eth0", proxied, reaperUID, false},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.uid != vmUID && os.Geteuid() != 0 {
				t.Skip("only root can give a directory to another uid")
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
	addSandbox(t, l, id("a"), "eth0", map[string]string{proxyAnnotation: "proxy.ns.svc.cluster.local:3128"}, vmUID)
	addSandbox(t, l, id("b"), "eth0", nil, vmUID) // names no proxy, and runs as the same uid
	wanted, err := l.wanted()
	if err != nil {
		t.Fatal(err)
	}
	if len(wanted) != 0 {
		t.Fatalf("wanted %v: a worker as that uid could open the other VM's socket", wanted)
	}
}

// A profile made again from the node's default would bring these back: io_uring, and the calls by which a worker could slow its own reaper.
func TestProfilesRefuseWhatWasCutFromTheNodesDefault(t *testing.T) {
	everywhere := []string{"io_uring_setup", "io_uring_enter", "io_uring_register"}
	launchers := []string{"sched_setattr", "sched_setscheduler", "sched_setparam", "sched_setaffinity", "setpriority", "ioprio_set"}
	files, _ := filepath.Glob("profiles/*/*.json")
	if len(files) != 4 {
		t.Fatalf("found %d profiles, want two for each of two architectures: %v", len(files), files)
	}
	for _, file := range files {
		var profile struct {
			Syscalls []struct {
				Names  []string `json:"names"`
				Action string   `json:"action"`
			} `json:"syscalls"`
		}
		b, err := os.ReadFile(file)
		if err != nil || json.Unmarshal(b, &profile) != nil || len(profile.Syscalls) == 0 {
			t.Fatalf("%s is no seccomp profile: %v", file, err)
		}
		refused := everywhere
		if strings.HasSuffix(file, "-launcher.json") {
			refused = append(refused, launchers...)
		}
		for _, rule := range profile.Syscalls {
			for _, name := range rule.Names {
				if rule.Action == "SCMP_ACT_ALLOW" && slices.Contains(refused, name) {
					t.Errorf("%s allows %s", file, name)
				}
			}
		}
	}
}

func TestLaunchNeedsAPIDNamespaceOfItsOwn(t *testing.T) {
	if os.Getpid() == 1 {
		t.Skip("this binary is the first process of a PID namespace")
	}
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
	for line := range strings.SplitSeq(string(b), "\n") {
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

// alone skips a test that ends workers unless root runs it, and then refuses unless this binary is the first process of a PID namespace: a reaper signals every process of its uid there.
func alone(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if os.Getpid() != 1 {
		t.Fatal("as root, run this test binary under unshare -pf --mount-proc: its reapers would kill the machine's processes of the tests' uids")
	}
	self, _ := os.Executable()
	for d := filepath.Dir(self); d != "/"; d = filepath.Dir(d) {
		if st, err := os.Stat(d); err != nil || st.Mode().Perm()&0o005 != 0o005 {
			t.Fatalf("no other uid can run this test binary from %s: go test -c -o DIR/x.test with DIR open to all", d)
		}
	}
}

func TestWorkerRunsAsItsVMsUidAndEndsWithItsSandbox(t *testing.T) {
	alone(t)
	l := fakeNode(t)
	l.reap = budget
	l.netns = podNetns(t)
	record := addSandbox(t, l, id("a"), "eth0", map[string]string{proxyAnnotation: "proxy.ns.svc.cluster.local:9"}, vmUID)
	addSandbox(t, l, id("b"), "eth0", map[string]string{proxyAnnotation: "proxy.ns.svc.cluster.local:9"}, vmUID+1)
	t.Cleanup(func() {
		for _, w := range l.workers {
			w.end(budget)
		}
	})
	if err := l.pass(); err != nil {
		t.Fatal(err)
	}
	first, other := l.workers[id("a")], l.workers[id("b")]
	if first == nil || other == nil {
		t.Fatal("no worker for a sandbox that names a proxy")
	}
	listening(t, l, id("a"))
	listening(t, l, id("b"))
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

	os.Remove(record) // the sandbox is deleted
	if err := l.pass(); err != nil {
		t.Fatal(err)
	}
	ended(t, second)
	// Through two ends of its neighbour's workers, the other sandbox kept its own.
	if l.workers[id("b")] != other || len(l.workers) != 1 || other.exited() {
		t.Fatalf("the launcher holds %d workers, and the other sandbox's has ended: %v", len(l.workers), other.exited())
	}
}

// A worker the guest has taken over can signal every process of its own uid, the VM's.
func TestWorkerThatSignalsItsOwnUidStillEndsWithItsSandbox(t *testing.T) {
	alone(t)
	for name, signal := range map[string]syscall.Signal{"kills": syscall.SIGKILL, "stops": syscall.SIGSTOP} {
		t.Run(name, func(t *testing.T) {
			const uid = vmUID + 2 // no other test's processes run as it
			l := fakeNode(t)
			l.reap = budget
			record := addSandbox(t, l, id("a"), "eth0", map[string]string{proxyAnnotation: "proxy.ns.svc.cluster.local:9"}, uid)
			t.Setenv(hostileWorker, strconv.Itoa(int(signal)))
			t.Cleanup(func() { // whatever a failed run left as that uid
				stats, _ := filepath.Glob("/proc/[0-9]*/status")
				for _, file := range stats {
					if b, _ := os.ReadFile(file); strings.Contains(string(b), fmt.Sprintf("\nUid:\t%d\t", uid)) {
						pid, _ := strconv.Atoi(filepath.Base(filepath.Dir(file)))
						syscall.Kill(pid, syscall.SIGKILL)
					}
				}
			})
			if err := l.pass(); err != nil {
				t.Fatal(err)
			}
			w := l.workers[id("a")]
			if w == nil {
				t.Fatal("no worker for a sandbox that names a proxy")
			}
			signalling := filepath.Join(l.vms, id("a")[:12], "root", "signalling")
			for deadline := time.Now().Add(budget); ; time.Sleep(time.Millisecond) {
				if _, err := os.Stat(signalling); err == nil {
					break
				}
				if time.Now().After(deadline) || w.exited() {
					t.Fatal("the worker did not come to signal its uid")
				}
			}

			os.Remove(record) // the sandbox is deleted
			passed := make(chan error, 1)
			go func() { passed <- l.pass() }()
			select {
			case err := <-passed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(budget):
				t.Fatal("the launcher's pass did not return: no sandbox on the node gets or loses a worker now")
			}
			ended(t, w)
			if len(l.workers) != 0 { // a reaper the worker reached may still have ended it, and then been stopped or killed itself
				t.Fatal("the worker's reaper did not end cleanly: the launcher still holds the worker")
			}
		})
	}
}

func TestNoReaperStartsOnceAPassIsOutOfTime(t *testing.T) {
	alone(t)
	l := fakeNode(t)
	record := addSandbox(t, l, id("a"), "eth0", map[string]string{proxyAnnotation: "proxy.ns.svc.cluster.local:9"}, vmUID+4)
	if err := l.pass(); err != nil {
		t.Fatal(err)
	}
	w := l.workers[id("a")]
	if w == nil {
		t.Fatal("no worker for a sandbox that names a proxy")
	}
	listening(t, l, id("a"))

	os.Remove(record) // the sandbox is deleted
	l.reap = 0        // as when the reapers before this worker's used all of the pass's time
	if err := l.pass(); err != nil {
		t.Fatal(err)
	}
	if w.reaper != nil || l.workers[id("a")] != w {
		t.Fatal("a reaper started past the pass's deadline: reapers that run together end each other")
	}
	l.reap = budget
	if err := l.pass(); err != nil {
		t.Fatal(err)
	}
	ended(t, w)
}

// A reaper can fail, and a process of its uid outside this namespace can stop it: the launcher goes on, resumes or replaces the reaper, and gives the uid to no other sandbox meanwhile.
func TestWorkerWhoseReaperDidNotEndItIsEndedOnALaterPass(t *testing.T) {
	alone(t)
	for _, how := range []string{"stops", "fails"} {
		t.Run("a reaper that "+how, func(t *testing.T) {
			const uid = vmUID + 3 // no other test's processes run as it
			proxied := map[string]string{proxyAnnotation: "proxy.ns.svc.cluster.local:9"}
			l := fakeNode(t)
			l.reap, l.retry = time.Millisecond, 0
			record := addSandbox(t, l, id("a"), "eth0", proxied, uid)
			if err := l.pass(); err != nil {
				t.Fatal(err)
			}
			w := l.workers[id("a")]
			if w == nil {
				t.Fatal("no worker for a sandbox that names a proxy")
			}
			listening(t, l, id("a"))

			os.Remove(record) // the sandbox is deleted
			t.Setenv(brokenReaper, how)
			passed := make(chan error, 1)
			go func() { passed <- l.pass() }()
			if err := within(t, passed, "return from the launcher's pass: no sandbox on the node gets or loses a worker now"); err != nil {
				t.Fatal(err)
			}
			if l.workers[id("a")] != w || w.exited() {
				t.Fatal("the launcher let go of a worker that nothing had ended")
			}

			addSandbox(t, l, id("b"), "eth0", proxied, uid) // the VM's uid goes to a new sandbox while the old worker runs
			if err := l.pass(); err != nil {
				t.Fatal(err)
			}
			if l.workers[id("a")] != nil && l.workers[id("b")] != nil {
				t.Fatal("a new sandbox got a worker as a uid whose last worker has not been ended")
			}
			t.Setenv(brokenReaper, "")
			for deadline := time.Now().Add(budget); l.workers[id("a")] != nil || l.workers[id("b")] == nil; time.Sleep(time.Millisecond) {
				if err := l.pass(); err != nil {
					t.Fatal(err)
				}
				if time.Now().After(deadline) {
					t.Fatalf("no later pass ended the old worker and started the new sandbox's: the launcher holds %d", len(l.workers))
				}
			}
			ended(t, w)
			next := l.workers[id("b")]
			t.Cleanup(func() { next.end(budget) })
			if next.exited() {
				t.Fatal("the old worker's reaper ended the new sandbox's worker")
			}
		})
	}
}
