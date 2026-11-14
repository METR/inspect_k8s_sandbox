// vsock-egress carries a sandbox's proxy connections out of an AWS Nitro Sandbox with no network card, over the VM's vsock to the one address its pod names. Linux only.
package main

import (
	"fmt"
	"log"
	"os"
	"time"
)

const (
	streamPort = 3129 // the sandbox dials this vsock port on the node, once for each proxy connection
	keyPort    = 3130 // the sandbox serves its key on this vsock port, to the node alone
	canaryPort = 3131 // check and canary meet on this vsock port, both ways
	hostCID    = 2
	keySize    = 32
	maxStreams = 64  // a sandbox's streams at once: the forwarder holds the next back until one ends
	maxWaiting = 448 // connections the forwarder holds back at once: the next is reset

	dialWait      = 5 * time.Second
	handshakeWait = 10 * time.Second
)

func main() {
	log.SetFlags(0)
	commands := map[string]func([]string) error{
		"forward": forward, "ready": ready, "canary": canary, // in the sandbox
		"launch": launch, "check": check, // on the node
		"work": work, "probe": probe, "reap": reap, // started by launch and check
	}
	if len(os.Args) < 2 || commands[os.Args[1]] == nil {
		fmt.Fprintln(os.Stderr, "usage: vsock-egress forward|canary (in the sandbox), launch|check (on the node)")
		os.Exit(2)
	}
	if err := commands[os.Args[1]](os.Args[2:]); err != nil {
		log.Fatalf("vsock-egress %s: %v", os.Args[1], err)
	}
}
