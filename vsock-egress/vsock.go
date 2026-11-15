package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// vsockListener accepts connections to a vsock port of this VM.
type vsockListener struct{ f *os.File }

func vsockListen(port uint32) (*vsockListener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}
	if err = unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err == nil {
		err = unix.Listen(fd, unix.SOMAXCONN)
	}
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("vsock listen %d: %w", port, err)
	}
	return &vsockListener{os.NewFile(uintptr(fd), "vsock")}, nil
}

// accept returns the next connection and its peer's CID, which the kernel stamps.
func (l *vsockListener) accept() (*os.File, uint32, error) {
	raw, err := l.f.SyscallConn()
	if err != nil {
		return nil, 0, os.ErrClosed
	}
	var fd int
	var peer unix.Sockaddr
	var errno error
	if err := raw.Read(func(listener uintptr) bool {
		fd, peer, errno = unix.Accept4(int(listener), unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
		return errno != unix.EAGAIN && errno != unix.EINTR // the kernel says EINTR, not EAGAIN, while a signal is pending
	}); err != nil { // the listener was closed while this waited
		return nil, 0, os.ErrClosed
	}
	if errno != nil {
		return nil, 0, fmt.Errorf("vsock accept: %w", errno)
	}
	c := os.NewFile(uintptr(fd), "vsock")
	vm, ok := peer.(*unix.SockaddrVM)
	if !ok {
		c.Close()
		return nil, 0, fmt.Errorf("vsock accept: peer address %T", peer)
	}
	return c, vm.CID, nil
}

const vsockBuffer = 1 << 20 // bytes a dialled socket takes from its peer at a time

// vsockDial connects to a vsock port, on a new socket after a signal interrupts it: the kernel cancels that connect.
func vsockDial(cid, port uint32) (*os.File, error) {
	for {
		fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return nil, fmt.Errorf("vsock socket: %w", err)
		}
		// Unless told, a guest socket takes 256 KiB at a time, which holds a download back; the maximum goes first, since it bounds the size.
		unix.SetsockoptUint64(fd, unix.AF_VSOCK, unix.SO_VM_SOCKETS_BUFFER_MAX_SIZE, vsockBuffer)
		unix.SetsockoptUint64(fd, unix.AF_VSOCK, unix.SO_VM_SOCKETS_BUFFER_SIZE, vsockBuffer)
		if err = unix.Connect(fd, &unix.SockaddrVM{CID: cid, Port: port}); err == nil {
			unix.SetNonblock(fd, true) // so that the runtime polls it
			return os.NewFile(uintptr(fd), "vsock"), nil
		}
		unix.Close(fd)
		if err != unix.EINTR {
			return nil, fmt.Errorf("vsock connect %d:%d: %w", cid, port, err)
		}
	}
}

// peerBuffer is Firecracker's CONN_TX_BUF_SIZE: all it holds of a connection's bytes from the guest.
const peerBuffer = 64 << 10

// fitted is a dialled vsock connection whose frames end where the peer's buffer ends.
type fitted struct {
	*os.File
	used int // bytes in the peer's buffer since it was last empty
}

// payload is the most the next frame carries: what fills the peer's buffer. A nil fitted fits nothing.
func (f *fitted) payload() int {
	if f == nil {
		return maxFrame
	}
	if room := peerBuffer - f.used; room > 4 {
		return room - 4
	}
	return maxFrame - 4 // no frame fits in under five bytes of room: four bytes short leaves the next one five to eight
}

func (f *fitted) Write(p []byte) (int, error) {
	raw, err := f.File.SyscallConn()
	if err != nil {
		return 0, err
	}
	done, full := 0, -1 // full: where in p the peer's buffer was found full
	var failed error
	if err := raw.Write(func(fd uintptr) bool {
		for done < len(p) {
			n, err := unix.Write(int(fd), p[done:])
			switch err {
			case nil:
				if done += n; done < len(p) { // the kernel cuts a write short only where the peer's buffer is full
					full = done
				}
			case unix.EINTR:
			case unix.EAGAIN:
				return false
			default:
				failed = fmt.Errorf("vsock write: %w", err)
				return true
			}
		}
		return true
	}); err != nil {
		return done, err
	}
	if full >= 0 {
		f.used = -full // the rest of p went into an emptied buffer
	}
	f.used = (f.used + len(p)) % peerBuffer
	return done, failed
}
