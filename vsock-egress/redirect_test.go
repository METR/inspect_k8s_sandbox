package main

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRedirectSendsAConnectionToASiblingsAddressToTheForwarderAndNoOther(t *testing.T) {
	skipped, failed := make(chan string, 1), make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the network namespace made here ends with this thread, and every socket below is made in it
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			skipped <- "cannot make a network namespace here: needs CAP_SYS_ADMIN"
			return
		}
		failed <- func() error {
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			lo, _ := unix.NewIfreq("lo") // down in a new namespace, up in a guest
			lo.SetUint16(unix.IFF_UP)
			if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, lo); err != nil {
				return err
			}
			if err := redirect(nil); err != nil {
				return fmt.Errorf("redirect: %w", err)
			}
			forwarder, err := listen(fmt.Sprintf("127.0.0.1:%d", capturePort), clientBuffer)
			if err != nil {
				return err
			}
			defer forwarder.Close()
			forwarder.(*net.TCPListener).SetDeadline(time.Now().Add(budget))
			// A server of the task's on that sibling's port, on every address: redirect must not leave the connection to it.
			everywhere, err := net.Listen("tcp", "0.0.0.0:8000")
			if err != nil {
				return err
			}
			defer everywhere.Close()
			everywhere.(*net.TCPListener).SetDeadline(time.Now().Add(budget))
			c, err := net.Dial("tcp", "198.18.0.2:8000")
			if err != nil {
				return fmt.Errorf("a connection to a sibling's address: %w", err)
			}
			defer c.Close()
			got, err := forwarder.Accept()
			if err != nil {
				return fmt.Errorf("the forwarder took no connection that was going to a sibling's address: %w", err)
			}
			defer got.Close()
			if going, err := originalDst(got.(*net.TCPConn)); err != nil || going.String() != "198.18.0.2:8000" {
				return fmt.Errorf("the forwarder took a connection that was going to %v (%v): want 198.18.0.2:8000", going, err)
			}

			// Where the forwarder delivers a sibling's connection: to a server on every address, and to none on 127.0.0.1 alone.
			delivered, err := net.Dial("tcp", net.JoinHostPort(deliverTo.String(), "8000"))
			if err != nil {
				return fmt.Errorf("a connection to %v, where a server listens on every address: %w", deliverTo, err)
			}
			defer delivered.Close()
			there, err := everywhere.Accept()
			if err != nil {
				return fmt.Errorf("the server on every address took no connection to %v: %w", deliverTo, err)
			}
			defer there.Close()
			if from := there.RemoteAddr().(*net.TCPAddr).IP; from.IsLoopback() {
				return fmt.Errorf("the server sees its sibling at %v, as a program of its own machine", from)
			}
			private, err := net.Listen("tcp", "127.0.0.1:8001")
			if err != nil {
				return err
			}
			defer private.Close()
			if c, err := net.Dial("tcp", net.JoinHostPort(deliverTo.String(), "8001")); !errors.Is(err, syscall.ECONNREFUSED) {
				if err == nil {
					c.Close()
				}
				return fmt.Errorf("a connection to %v reached a server on 127.0.0.1 alone (%v): want it refused", deliverTo, err)
			}
			return nil
		}()
	}()
	select {
	case why := <-skipped:
		t.Skip(why)
	case err := <-failed:
		if err != nil {
			t.Fatal(err)
		}
	}
}
