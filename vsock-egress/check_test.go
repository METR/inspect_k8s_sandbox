package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// canaryDials plays the canary's connection to the node: it dials the probe's socket until it is there.
func canaryDials(t *testing.T, vsock, says string) {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if c, err := net.Dial("unix", fmt.Sprintf("%s_%d", vsock, canaryPort)); err == nil {
				c.Write([]byte(says))
				c.Close()
				return
			}
		}
	}()
}

func TestProbeNamesTheAssumptionThatBroke(t *testing.T) {
	const greeting = "canary\n"
	for name, tc := range map[string]struct {
		guest map[uint32]string // what the guest's ports say to the node; none if the node cannot reach them
		dials string            // what the canary says when it dials the node; "" if it cannot
		moved bool              // Firecracker's socket is somewhere else
		want  string            // in the error; "" for a pass
	}{
		"all holds":                       {guest: map[uint32]string{canaryPort: greeting}, dials: "bind: ok\n"},
		"the socket moved":                {guest: map[uint32]string{canaryPort: greeting}, dials: "bind: ok\n", moved: true, want: "Firecracker's socket is not at"},
		"the guest cannot bind":           {dials: "bind: vsock socket: operation not permitted\n", want: "can no longer bind a vsock port"},
		"the guest cannot dial":           {guest: map[uint32]string{canaryPort: greeting}, want: "can no longer dial the node"},
		"the node cannot reach the guest": {dials: "bind: ok\n", want: "can no longer reach a guest-bound port"},
		"no path either way":              {want: "no vsock path between guest and node either way"},
		"the canary's line has no end":    {guest: map[uint32]string{canaryPort: greeting}, dials: strings.Repeat("x", 1<<20), want: "can no longer bind a vsock port"},
		"the guest's greeting has no end": {guest: map[uint32]string{canaryPort: strings.Repeat("x", 1<<20)}, dials: "bind: ok\n", want: "can no longer reach a guest-bound port"},
	} {
		t.Run(name, func(t *testing.T) {
			vsock := firecracker(t, tc.guest)
			wait := budget
			if tc.dials == "" {
				wait = 50 * time.Millisecond // nothing will dial: the probe's own bound on waiting ends it
			} else {
				canaryDials(t, vsock, tc.dials)
			}
			if tc.moved {
				os.Rename(vsock, vsock+".moved")
			}
			err := probeVM(vsock, wait)
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("got %.300v, want %q", err, tc.want)
			}
			if err != nil && len(err.Error()) > 1<<10 {
				t.Fatalf("the error is %d bytes long: the probe kept all that the guest sent", len(err.Error()))
			}
		})
	}
}
