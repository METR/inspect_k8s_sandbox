package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// proxyAnnotation names, as ip:port, the one address a sandbox's streams are joined to: its sample's egress proxy.
const proxyAnnotation = "inspect-k8s-sandbox/egress-proxy"

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

// record is what libcni keeps for a pod's eth0: the sandbox, its network namespace, and the pod's name and
// annotations as they were when the sandbox was made. A later change to the pod changes nothing here.
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
	sb.uid, sb.gid = owner.Uid, owner.Gid
	return sb, nil
}

// child is a process started as a VM's uid inside its pod's network namespace. Closing its stdin ends it:
// the launcher holds no capability to signal another uid's process.
type child struct {
	cmd   *exec.Cmd
	stdin io.Closer
	done  chan struct{} // closed when the process has ended
}

func (c *child) exited() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func start(sb sandbox, args ...string) (*child, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(self, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: sb.uid, Gid: sb.gid}}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	started := make(chan error)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread ends with this goroutine, in the namespace it entered
		ns, err := os.Open(sb.netns)
		if err == nil {
			err = unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET)
			ns.Close()
		}
		if err != nil {
			err = fmt.Errorf("enter the pod's network namespace at %s: %w", sb.netns, err)
		} else {
			err = cmd.Start() // this thread makes the child, so the child is in its namespace
		}
		started <- err
	}()
	if err := <-started; err != nil {
		stdin.Close()
		return nil, err
	}
	c := &child{cmd, stdin, make(chan struct{})}
	go func() {
		cmd.Wait()
		close(c.done)
	}()
	return c, nil
}

// launcher keeps one worker for each sandbox on this node whose pod names an egress proxy.
type launcher struct {
	node
	rate     int
	workers  map[string]*child // by sandbox id
	reported map[string]bool   // sandboxes whose fault is already in the log
}

func launch(args []string) error {
	l := &launcher{workers: map[string]*child{}, reported: map[string]bool{}}
	fs := flag.NewFlagSet("launch", flag.ExitOnError)
	l.flags(fs)
	fs.IntVar(&l.rate, "rate", 0, "bytes a second a sandbox's streams may carry, both ways together; 0 for no cap")
	fs.Parse(args)
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
	wanted := map[string]sandbox{}
	for _, r := range records {
		if r.Capability.Annotations[proxyAnnotation] == "" {
			continue
		}
		sb, err := l.sandbox(r)
		if err == nil {
			_, err = netip.ParseAddrPort(sb.target) // an address, never a name: the worker resolves nothing
		}
		if err == nil {
			wanted[r.ContainerID] = sb
		} else if !errors.Is(err, os.ErrNotExist) && !l.reported[r.ContainerID] { // a VM's directory can follow its record
			l.reported[r.ContainerID] = true
			log.Printf("%s: no worker: %v", sb.pod, err)
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
	for id, w := range l.workers {
		if _, ok := wanted[id]; !ok || w.exited() {
			w.stdin.Close()
			delete(l.workers, id)
		}
	}
	for id, sb := range wanted {
		if l.workers[id] != nil {
			continue
		}
		w, err := start(sb, "work", "-pod", sb.pod, "-vsock", filepath.Join(sb.root, "vm.vsock"),
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
