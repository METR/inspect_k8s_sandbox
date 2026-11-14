// vsock-egress carries a sandbox's proxy connections out of an AWS Nitro Sandbox that has no network card.
// In the sandbox, forward serves the proxy port on loopback and sends each connection over the VM's vsock.
// On the node, launch starts a worker for each such VM, as the VM's own uid inside the pod's network
// namespace, and the worker joins each connection to the one address the pod's annotation names. Linux only.
package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"time"
)

const (
	streamPort = 3129 // the sandbox dials this vsock port on the node, once for each proxy connection
	keyPort    = 3130 // the sandbox serves its key on this vsock port, to the node alone
	canaryPort = 3131 // check and canary meet on this vsock port, both ways
	hostCID    = 2
	keySize    = 32
	maxStreams = 64 // a sandbox's streams at once: the next is refused, not queued

	dialWait      = 5 * time.Second
	handshakeWait = 10 * time.Second
)

func main() {
	log.SetFlags(0)
	// Each command waits on sockets, where more threads only wake each other. It also holds a sandbox's
	// forwarder to one of its own CPUs and its worker to one of the node's.
	runtime.GOMAXPROCS(1)
	commands := map[string]func([]string) error{
		"forward": forward, "ready": ready, "canary": canary, // in the sandbox
		"launch": launch, "check": check, // on the node
		"work": work, "probe": probe, // started by launch and check, as a VM's uid
	}
	if len(os.Args) < 2 || commands[os.Args[1]] == nil {
		fmt.Fprintln(os.Stderr, "usage: vsock-egress forward|canary (in the sandbox), launch|check (on the node)")
		os.Exit(2)
	}
	if err := commands[os.Args[1]](os.Args[2:]); err != nil {
		log.Fatalf("vsock-egress %s: %v", os.Args[1], err)
	}
}
