package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// proxyAnnotation names, as host:port, the one place a sandbox's streams are joined to: its sample's egress proxy.
const proxyAnnotation = "inspect-k8s-sandbox/egress-proxy"

// A proxy is a Service of the pod's own namespace and a port: it keeps its address when its pod is replaced, and nothing else reaches a worker's command line.
var proxyTarget = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?\.([a-z0-9]([-a-z0-9]*[a-z0-9])?)\.svc\.cluster\.local\.?:[0-9]{1,5}$`)

// node is where this node keeps what the launcher reads. It asks neither containerd nor the API server.
type node struct {
	vms   string // AWS's runtime keeps a VM's files at <vms>/<first 12 characters of the sandbox id>/root
	cni   string // libcni's cache: a record for each interface of each pod
	netns string // where each pod's network namespace is bound
}

func (n *node) flags(fs *flag.FlagSet) {
	fs.StringVar(&n.vms, "vms", "/var/lib/nitro-sandbox/firecracker", "where the runtime keeps each VM's directory")
	fs.StringVar(&n.cni, "cni", "/var/lib/cni/results", "libcni's cache of results")
	fs.StringVar(&n.netns, "netns", "/run/netns", "where each pod's network namespace is bound")
}

// record is what libcni keeps for a pod's eth0, as the pod was when its sandbox was made: a later change to the pod changes nothing here.
type record struct {
	ContainerID string      `json:"containerId"`
	IfName      string      `json:"ifName"`
	Netns       string      `json:"netns"`
	CNIArgs     [][2]string `json:"cniArgs"`
	Capability  struct {
		Annotations map[string]string `json:"io.kubernetes.cri.pod-annotations"`
	} `json:"capabilityArgs"`
}

// pod is the record's pod as namespace/name.
func (r record) pod() string {
	args := map[string]string{}
	for _, a := range r.CNIArgs {
		args[a[0]] = a[1]
	}
	return args["K8S_POD_NAMESPACE"] + "/" + args["K8S_POD_NAME"]
}

func (n *node) records() ([]record, error) {
	files, err := os.ReadDir(n.cni)
	if err != nil {
		return nil, err
	}
	var records []record
	for _, f := range files {
		var r record
		b, err := os.ReadFile(filepath.Join(n.cni, f.Name()))
		if err != nil || json.Unmarshal(b, &r) != nil || r.IfName != "eth0" || len(r.ContainerID) < 12 {
			continue // half written, just removed, or not a pod's interface
		}
		records = append(records, r)
	}
	return records, nil
}

// sandbox is one pod's VM as the node sees it.
type sandbox struct {
	pod      string
	root     string // the VM's directory: Firecracker's jail root, which holds vm.vsock
	uid, gid uint32 // the VM's own: Firecracker runs as them, and so does the VM's worker
	netns    string
	target   string
}

// sandbox finds a record's VM. Its errors name what the launcher assumes of the runtime's layout.
func (n *node) sandbox(r record) (sandbox, error) {
	sb := sandbox{
		pod:    r.pod(),
		root:   filepath.Join(n.vms, r.ContainerID[:12], "root"),
		netns:  filepath.Join(n.netns, filepath.Base(r.Netns)),
		target: r.Capability.Annotations[proxyAnnotation],
	}
	st, err := os.Stat(sb.root)
	if err != nil {
		return sb, fmt.Errorf("no VM directory at %s (the first 12 characters of the sandbox id, then root): %w", sb.root, err)
	}
	owner := st.Sys().(*syscall.Stat_t)
	if owner.Uid == 0 {
		return sb, fmt.Errorf("%s is root's: expected a uid of the VM's own", sb.root)
	}
	if owner.Uid == reaperUID {
		return sb, fmt.Errorf("%s is uid %d's, which a worker may not have: its reaper runs as that uid", sb.root, reaperUID)
	}
	sb.uid, sb.gid = owner.Uid, owner.Gid
	return sb, nil
}

// child is a process started as a VM's uid.
type child struct {
	cmd      *exec.Cmd
	uid, gid uint32
	done     chan struct{} // closed when the process has ended
	reaper   *child        // a worker's, from when its end began until that reaper has ended
	unended  bool          // a worker's failed end is in the log
}

func (c *child) exited() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// start runs this program as uid and gid, inside the network namespace at netns if one is named.
func start(uid, gid uint32, netns string, args ...string) (*child, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(self, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
	if netns == "" {
		err = cmd.Start()
	} else {
		started := make(chan error)
		go func() { started <- inNetns(netns, cmd.Start) }() // the thread that makes the child gives it its namespace
		err = <-started
	}
	if err != nil {
		return nil, err
	}
	c := &child{cmd: cmd, uid: uid, gid: gid, done: make(chan struct{})}
	go func() {
		cmd.Wait()
		close(c.done)
	}()
	return c, nil
}

// end stops a worker and whatever else runs as its uid here, through a reaper: the launcher may not signal another uid.
func (c *child) end(wait time.Duration) error {
	if c.reaper == nil {
		if wait <= 0 { // reapers share a real uid, so two that run together end each other: none starts once a pass is out of time
			return errors.New("no reaper yet: the pass was out of time")
		}
		reaper, err := start(0, 0, "", "reap", strconv.Itoa(int(c.uid)))
		if err != nil {
			return err
		}
		c.reaper = reaper
	} else {
		c.reaper.cmd.Process.Signal(syscall.SIGCONT) // a process of the reaper's uid outside this namespace can stop it, and the launcher's session may resume it
	}
	select { // the launcher goes on, and looks again on its next pass
	case <-c.reaper.done:
	case <-time.After(wait):
	}
	if !c.reaper.exited() {
		return fmt.Errorf("its reaper, process %d, has not ended", c.reaper.cmd.Process.Pid)
	}
	reaper := c.reaper
	c.reaper = nil
	if !reaper.cmd.ProcessState.Success() {
		return fmt.Errorf("its reaper ended with %v", reaper.cmd.ProcessState)
	}
	return nil
}

const reaperUID = 65534 // the reaper's real and saved uid, which no VM may have

// reap kills every process of one VM's uid here. Only its effective uid is the VM's, so no such process can signal it first.
func reap(args []string) error {
	uid, err := strconv.Atoi(strings.Join(args, " "))
	if err != nil || uid <= 0 || uid == reaperUID {
		return fmt.Errorf("%q is no VM's uid", args)
	}
	if err := syscall.Setresuid(reaperUID, uid, reaperUID); err != nil {
		return err
	}
	if err := syscall.Kill(-1, syscall.SIGKILL); err != syscall.ESRCH { // none left: the worker had ended by itself
		return err
	}
	return nil
}

// inNetns runs f on a thread inside the network namespace at path; a thread that cannot come back stays locked, so it ends with its goroutine.
func inNetns(path string, f func() error) error {
	ns, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("the pod's network namespace is not at %s: %w", path, err)
	}
	defer ns.Close()
	runtime.LockOSThread()
	home, err := os.Open("/proc/thread-self/ns/net")
	if err == nil {
		defer home.Close()
		err = unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET)
	}
	if err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("enter the pod's network namespace at %s: %w", path, err)
	}
	err = f()
	if unix.Setns(int(home.Fd()), unix.CLONE_NEWNET) == nil {
		runtime.UnlockOSThread()
	}
	return err
}

// launcher keeps one worker for each sandbox on this node whose pod names an egress proxy.
type launcher struct {
	node
	rate     int
	retry    time.Duration        // the least time between two starts of one sandbox's worker
	reap     time.Duration        // how long a pass waits for its workers' reapers
	workers  map[string]*child    // by sandbox id
	tried    map[string]time.Time // when each sandbox's worker was last started
	reported map[string]bool      // sandboxes whose fault is already in the log
}

func newLauncher() *launcher {
	return &launcher{retry: 5 * time.Second, reap: time.Second, workers: map[string]*child{}, tried: map[string]time.Time{}, reported: map[string]bool{}}
}

func launch(args []string) error {
	l := newLauncher()
	fs := flag.NewFlagSet("launch", flag.ExitOnError)
	l.flags(fs)
	fs.IntVar(&l.rate, "rate", 0, "bytes a second a sandbox's streams may carry, both ways together; 0 for no cap")
	fs.Parse(args)
	if os.Getpid() != 1 { // or ending a worker would reach every process of its uid on the node: the VM's Firecracker
		return errors.New("launch must be the first process of a PID namespace of its own")
	}
	for ; ; time.Sleep(500 * time.Millisecond) {
		if err := l.pass(); err != nil {
			return err
		}
	}
}

// wanted is the sandboxes that should have a worker now.
func (l *launcher) wanted() (map[string]sandbox, error) {
	records, err := l.records()
	if err != nil {
		return nil, err
	}
	wanted, present, vms := map[string]sandbox{}, map[string]bool{}, map[uint32]int{}
	for _, r := range records {
		if sb, err := l.sandbox(r); err == nil {
			vms[sb.uid]++
		}
	}
	for _, r := range records {
		present[r.ContainerID] = true
		if r.Capability.Annotations[proxyAnnotation] == "" {
			continue
		}
		sb, err := l.sandbox(r)
		if m := proxyTarget.FindStringSubmatch(sb.target); err == nil && (m == nil || m[2] != strings.Split(sb.pod, "/")[0]) {
			err = fmt.Errorf("its annotation %s is %q, not <service>.<its namespace>.svc.cluster.local:<port>", proxyAnnotation, sb.target)
		}
		if err == nil && vms[sb.uid] > 1 { // a worker could open the other VM's socket, and ending it would end the other's
			err = fmt.Errorf("%d live VMs on this node run as its uid %d", vms[sb.uid], sb.uid)
		}
		if err == nil {
			wanted[r.ContainerID] = sb
		} else if !errors.Is(err, os.ErrNotExist) && !l.reported[r.ContainerID] { // a VM's directory can follow its record
			l.reported[r.ContainerID] = true
			log.Printf("%s: no worker: %v", sb.pod, err)
		}
	}
	for id := range l.reported {
		if !present[id] {
			delete(l.reported, id)
		}
	}
	return wanted, nil
}

// pass starts a worker for each sandbox that lacks one, and ends the worker of each sandbox that has gone.
func (l *launcher) pass() error {
	wanted, err := l.wanted()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(l.reap)
	for id, w := range l.workers {
		if _, ok := wanted[id]; !ok || w.exited() {
			if err := w.end(time.Until(deadline)); err != nil { // kept: the next pass ends it again, and no new worker runs as its uid meanwhile
				if !w.unended {
					w.unended = true
					log.Printf("uid %d: its processes are not ended yet: %v", w.uid, err)
				}
				continue
			}
			delete(l.workers, id)
		}
	}
	for id := range l.tried {
		if _, ok := wanted[id]; !ok {
			delete(l.tried, id)
		}
	}
	held := map[uint32]bool{}
	for _, w := range l.workers {
		held[w.uid] = true
	}
	for id, sb := range wanted {
		if l.workers[id] != nil || held[sb.uid] || time.Since(l.tried[id]) < l.retry { // one that cannot start, or dies at once, is not started twice a second
			continue
		}
		l.tried[id] = time.Now()
		w, err := start(sb.uid, sb.gid, sb.netns, "work", "-pod", sb.pod, "-vsock", filepath.Join(sb.root, "vm.vsock"),
			"-target", sb.target, "-rate", strconv.Itoa(l.rate))
		if err != nil {
			log.Printf("%s: %v", sb.pod, err)
			continue
		}
		log.Printf("%s: worker %d as uid %d for %s", sb.pod, w.cmd.Process.Pid, sb.uid, sb.target)
		l.workers[id] = w
	}
	return nil
}
