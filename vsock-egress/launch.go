package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
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

const (
	// proxyAnnotation names, as host:port, the one place a sandbox's proxy streams are joined to: its sample's egress proxy.
	proxyAnnotation = "inspect-k8s-sandbox/egress-proxy"
	// siblingsAnnotation names, as address=host with commas between, the Service behind each address that stands for a sibling in the sandbox.
	siblingsAnnotation = "inspect-k8s-sandbox/egress-siblings"
	// portsAnnotation names the ports of the pod its siblings may reach: *, or a list with commas between.
	portsAnnotation = "inspect-k8s-sandbox/ingress-ports"
	// listenAnnotation names ports of the pod its worker takes connections on, from whoever the pod's network policy lets in: a list with commas between.
	listenAnnotation = "inspect-k8s-sandbox/ingress-listen"
)

var (
	// A proxy is a Service of the pod's own namespace and a port: it keeps its address when its pod is replaced, and nothing else reaches a worker's command line.
	proxyTarget = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?\.([a-z0-9]([-a-z0-9]*[a-z0-9])?)\.svc\.cluster\.local\.?:([0-9]{1,5})$`)
	// A sibling is an address of siblingRange and a Service of the pod's own namespace.
	siblingTarget = regexp.MustCompile(`^([0-9.]+)=[a-z0-9]([-a-z0-9]*[a-z0-9])?\.([a-z0-9]([-a-z0-9]*[a-z0-9])?)\.svc\.cluster\.local\.?$`)
)

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
	target   string // its four annotations
	siblings string
	ports    string
	listen   string
}

// carried checks what a sandbox's annotations ask its worker to carry.
func (sb sandbox) carried() error {
	namespace := strings.Split(sb.pod, "/")[0]
	if m := proxyTarget.FindStringSubmatch(sb.target); sb.target != "" && (m == nil || m[2] != namespace || !isPort(m[4])) {
		return fmt.Errorf("its annotation %s is %q, not <service>.<its namespace>.svc.cluster.local:<port from 1 to 65535>", proxyAnnotation, sb.target)
	}
	if sb.siblings != "" {
		for _, sibling := range strings.Split(sb.siblings, ",") {
			var at netip.Addr // none, where the annotation gives no address: no range holds it
			m := siblingTarget.FindStringSubmatch(sibling)
			if m != nil {
				at, _ = netip.ParseAddr(m[1])
			}
			if m == nil || m[3] != namespace || !siblingRange.Contains(at) {
				return fmt.Errorf("its annotation %s is %q, not <address in %s>=<service>.<its namespace>.svc.cluster.local, with commas between", siblingsAnnotation, sb.siblings, siblingRange)
			}
		}
	}
	if sb.ports != "" && sb.ports != "*" {
		for _, port := range strings.Split(sb.ports, ",") {
			if !isPort(port) {
				return fmt.Errorf("its annotation %s is %q, not * or ports from 1 to 65535 with commas between", portsAnnotation, sb.ports)
			}
		}
	}
	if sb.listen != "" {
		for _, port := range strings.Split(sb.listen, ",") {
			// A worker is no root, so binds no port below 1024, and holds relayPort itself.
			if n, _ := strconv.Atoi(port); !isPort(port) || n < 1024 || n == relayPort {
				return fmt.Errorf("its annotation %s is %q, not ports from 1024 to 65535 other than %d, with commas between", listenAnnotation, sb.listen, relayPort)
			}
		}
	}
	return nil
}

// sandbox finds a record's VM. Its errors name what the launcher assumes of the runtime's layout.
func (n *node) sandbox(r record) (sandbox, error) {
	sb := sandbox{
		pod:      r.pod(),
		root:     filepath.Join(n.vms, r.ContainerID[:12], "root"),
		netns:    filepath.Join(n.netns, filepath.Base(r.Netns)),
		target:   r.Capability.Annotations[proxyAnnotation],
		siblings: r.Capability.Annotations[siblingsAnnotation],
		ports:    r.Capability.Annotations[portsAnnotation],
		listen:   r.Capability.Annotations[listenAnnotation],
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
	cmd     *exec.Cmd
	uid     uint32
	done    chan struct{} // closed when the process has ended
	reaper  *child        // a worker's, from when its end began until that reaper has ended
	unended time.Time     // when a worker's end first failed, or that was last in the log
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
	c := &child{cmd: cmd, uid: uid, done: make(chan struct{})}
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

// launcher keeps one worker for each sandbox on this node whose pod names an egress proxy or siblings.
type launcher struct {
	node
	rate     int
	retry    time.Duration        // the least time between two starts of one sandbox's worker
	reap     time.Duration        // how long a pass waits for its workers' reapers
	workers  map[string]*child    // by sandbox id
	tried    map[string]time.Time // when each sandbox's worker was last started
	reported map[string]time.Time // when each sandbox without a worker was first seen so, or last in the log
	had      map[string]bool      // sandboxes whose VM directory has been there
	sees     bool                 // a record's network namespace has been there: only then does a missing one tell of a sandbox that has gone
	started  map[string]bool      // sandboxes that have had a worker
}

// faultAgain is how long a fault lasts before its first line, and between lines.
const faultAgain = time.Minute

func newLauncher() *launcher {
	return &launcher{retry: 5 * time.Second, reap: time.Second, workers: map[string]*child{}, tried: map[string]time.Time{}, reported: map[string]time.Time{}, had: map[string]bool{}, started: map[string]bool{}}
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
		sb, err := l.sandbox(r)
		if err == nil {
			vms[sb.uid]++
		}
		if fi, err := os.Stat(sb.netns); err == nil && !fi.IsDir() { // a record that names no namespace names their directory
			l.sees = true
		}
	}
	for _, r := range records {
		present[r.ContainerID] = true
		if named := r.Capability.Annotations; named[proxyAnnotation] == "" && named[siblingsAnnotation] == "" && named[portsAnnotation] == "" && named[listenAnnotation] == "" {
			continue
		}
		sb, err := l.sandbox(r)
		gone := errors.Is(err, os.ErrNotExist)
		l.had[r.ContainerID] = l.had[r.ContainerID] || !gone
		if err == nil {
			err = sb.carried()
		}
		if err == nil && vms[sb.uid] > 1 { // a worker could open the other VM's socket, and ending it would end the other's
			err = fmt.Errorf("%d live VMs on this node run as its uid %d", vms[sb.uid], sb.uid)
		}
		_, bound := os.Stat(sb.netns)
		switch {
		case err == nil:
			wanted[r.ContainerID] = sb
		case gone && l.had[r.ContainerID]: // its sandbox is being deleted: the directory goes before the record does
		case gone && l.sees && errors.Is(bound, os.ErrNotExist): // with no network namespace either, the record outlived its sandbox
		default:
			l.fault(r.ContainerID, sb.pod, err)
		}
	}
	for id := range l.had {
		if !present[id] {
			delete(l.had, id)
			delete(l.reported, id)
			delete(l.started, id)
		}
	}
	return wanted, nil
}

func isPort(digits string) bool {
	port, err := strconv.ParseUint(digits, 10, 16)
	return err == nil && port > 0
}

// fault writes why a sandbox has no worker once that has lasted faultAgain: a VM's directory follows its record, and is root's at first.
func (l *launcher) fault(id, pod string, err error) {
	if last, seen := l.reported[id]; !seen {
		l.reported[id] = time.Now()
	} else if time.Since(last) >= faultAgain {
		l.reported[id] = time.Now()
		log.Printf("%s: no_worker: %v", pod, err)
	}
}

// pass starts a worker for each sandbox that lacks one, and ends the worker of each sandbox that has gone.
func (l *launcher) pass() error {
	wanted, err := l.wanted()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(l.reap)
	for id, w := range l.workers {
		if sb, ok := wanted[id]; !ok || w.exited() {
			if ok { // its sandbox has none now, and no start failed: one that ends after each start is this fault alone
				l.fault(id, sb.pod, errors.New("its worker ended"))
			}
			if err := w.end(time.Until(deadline)); err != nil { // kept: the next pass ends it again, and no new worker runs as its uid meanwhile
				if w.unended.IsZero() { // a pass out of time ends it on the next: only one that is faultAgain late is a fault
					w.unended = time.Now()
				} else if time.Since(w.unended) >= faultAgain {
					w.unended = time.Now()
					log.Printf("uid %d: worker_not_ended: %v", w.uid, err)
				}
				continue
			}
			delete(l.workers, id)
		} else if time.Since(l.tried[id]) >= faultAgain { // not sooner: one that is killed after each start would never be a fault
			delete(l.reported, id) // it serves its sandbox: a later fault gets a minute of its own
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
			"-target", sb.target, "-siblings", sb.siblings, "-ports", sb.ports, "-listen", sb.listen, "-rate", strconv.Itoa(l.rate))
		if err != nil {
			l.fault(id, sb.pod, err)
			continue
		}
		if !l.started[id] { // what kept it from its first worker is over: one that ends gets a minute of its own
			l.started[id] = true
			delete(l.reported, id)
		}
		log.Printf("%s: worker %d as uid %d for proxy %q, siblings %q, ports %q", sb.pod, w.cmd.Process.Pid, sb.uid, sb.target, sb.siblings, sb.ports)
		l.workers[id] = w
		held[sb.uid] = true // wanted counts a uid's VMs, then reads each again: one whose directory came between is a second of this uid
	}
	return nil
}
