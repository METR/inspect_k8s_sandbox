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
		return nil, 0, err
	}
	var fd int
	var peer unix.Sockaddr
	var errno error
	if err := raw.Read(func(listener uintptr) bool {
		fd, peer, errno = unix.Accept4(int(listener), unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
		return errno != unix.EAGAIN
	}); err != nil {
		return nil, 0, err
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

// vsockDial connects to a vsock port. The kernel cancels a connect that a signal interrupts, so that one
// starts again on a new socket.
func vsockDial(cid, port uint32) (*os.File, error) {
	for {
		fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return nil, fmt.Errorf("vsock socket: %w", err)
		}
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
