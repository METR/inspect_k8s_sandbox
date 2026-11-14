package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// check is the contract with AWS's runtime, to run before nodes take a new release of it: it fails, naming the assumption that broke, unless the launcher would still find and reach the VM of the pod that runs canary.
func check(args []string) error {
	var n node
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	n.flags(fs)
	pod := fs.String("pod", "", "the pod that runs canary, as namespace/name")
	wait := fs.Duration("wait", 30*time.Second, "how long to wait for the canary's connection")
	fs.Parse(args)
	records, err := n.records()
	if err != nil {
		return fmt.Errorf("libcni's cache is not at %s: %w", n.cni, err)
	}
	for _, r := range records {
		if r.pod() != *pod {
			continue
		}
		if r.Capability.Annotations == nil {
			return fmt.Errorf("the CNI record of %s holds no pod annotations: the launcher would find no sandbox's proxy", *pod)
		}
		sb, err := n.sandbox(r)
		if err != nil {
			return err
		}
		p, err := start(sb.uid, sb.gid, sb.netns, "probe", "-vsock", filepath.Join(sb.root, "vm.vsock"), "-wait", wait.String())
		if err != nil {
			return err
		}
		<-p.done
		if !p.cmd.ProcessState.Success() {
			return errors.New("the contract with the runtime is broken")
		}
		fmt.Printf("ok: %s runs as uid %d at %s; its guest binds and dials vsock, and the node reaches a guest-bound port\n", *pod, sb.uid, sb.root)
		return nil
	}
	return fmt.Errorf("no CNI record of pod %s in %s: the cache has moved, or the pod is not on this node", *pod, n.cni)
}

// probe is check's part that runs as the VM's uid.
func probe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	vsock := fs.String("vsock", "", "Firecracker's socket for the VM")
	wait := fs.Duration("wait", 30*time.Second, "how long to wait for the canary's connection")
	fs.Parse(args)
	return probeVM(*vsock, *wait)
}

func probeVM(vsock string, wait time.Duration) error {
	st, err := os.Lstat(vsock)
	if err != nil {
		return fmt.Errorf("Firecracker's socket is not at %s: %w", vsock, err)
	}
	if owner := st.Sys().(*syscall.Stat_t).Uid; st.Mode().Type() != os.ModeSocket || owner != uint32(os.Geteuid()) {
		return fmt.Errorf("%s is not a socket of the VM's uid: mode %v, uid %d", vsock, st.Mode(), owner)
	}
	path := fmt.Sprintf("%s_%d", vsock, canaryPort)
	os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("no listener for the guest's connections at %s: %w", path, err)
	}
	defer l.Close()
	l.(*net.UnixListener).SetDeadline(time.Now().Add(wait))
	dialled := make(chan string, 1)
	go func() { // the canary dials once a second, and says whether it could bind
		var said string
		if c, err := l.Accept(); err == nil {
			c.SetDeadline(time.Now().Add(dialWait))
			said, _ = bufio.NewReader(c).ReadString('\n')
			c.Close()
		}
		dialled <- said
	}()
	reach := greet(vsock)
	said := <-dialled
	switch {
	case said == "" && reach != nil:
		return fmt.Errorf("no vsock path between guest and node either way (%v; nothing reached %s in %s): "+
			"a guest process can no longer bind or dial vsock, or the pod does not run canary", reach, path, wait)
	case said == "":
		return fmt.Errorf("a guest process can no longer dial the node: nothing reached %s in %s", path, wait)
	case said != "bind: ok\n":
		return fmt.Errorf("a guest process can no longer bind a vsock port: the canary says %q", said)
	case reach != nil:
		return fmt.Errorf("the node can no longer reach a guest-bound port: %w", reach)
	}
	return nil
}

// greet connects to the canary's port in the guest and reads its greeting.
func greet(vsock string) error {
	c, err := guestDial(vsock, canaryPort)
	if err != nil {
		return err
	}
	defer c.Close()
	if line, err := bufio.NewReader(c).ReadString('\n'); line != "canary\n" {
		return fmt.Errorf("guest vsock port %d said %q: %v", canaryPort, line, err)
	}
	return nil
}

// canary is check's part in the sandbox: it holds a vsock port for the node to reach, and dials the node once a second to say whether it could.
func canary([]string) error {
	bound := "ok"
	if l, err := vsockListen(canaryPort); err != nil {
		log.Print(err)
		bound = err.Error()
	} else {
		go func() {
			for {
				c, peer, err := l.accept()
				if err != nil {
					log.Print(err)
					return
				}
				if peer == hostCID {
					io.WriteString(c, "canary\n")
				}
				c.Close()
			}
		}()
	}
	for last := ""; ; time.Sleep(time.Second) {
		c, err := vsockDial(hostCID, canaryPort)
		if err != nil {
			if last != err.Error() { // reset while no check is running: said once
				last = err.Error()
				log.Print(err)
			}
			continue
		}
		fmt.Fprintf(c, "bind: %s\n", bound)
		c.Close()
	}
}
