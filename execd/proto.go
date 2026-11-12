package main

// A frame: type (u8), length (u32, big-endian), payload. A connection carries one call.

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// client -> execd
	fAuth  = 1 // payload: the key
	fStart = 2 // payload: startRequest as JSON
	fStdin = 3 // payload: bytes; an empty payload closes the command's stdin

	// execd -> client
	fStdout = 17
	fStderr = 18
	fExit   = 19 // payload: exitStatus as JSON
	fPing   = 20 // every pingEvery, so each end can tell the other is gone
)

const headerLen = 5

// The most output in a frame, and the most stdin execd holds for a call.
const chunk = 256 << 10

type frame struct {
	kind    byte
	payload []byte
}

type startRequest struct {
	Argv  []string          `json:"argv"`
	Env   map[string]string `json:"env"`
	Cwd   string            `json:"cwd"`
	User  string            `json:"user"`
	Stdin bool              `json:"stdin"`
	// Seconds until the command is killed; 0: never.
	Timeout float64 `json:"timeout"`
	// A stream (exec_stdio): when its connection ends, only the command itself is killed.
	Stream bool `json:"stream"`
}

type exitStatus struct {
	Code    int    `json:"code"`            // 128+signal for a signal death
	Error   string `json:"error,omitempty"` // why the command never started
	Timeout bool   `json:"timeout,omitempty"`
}

// readFrame refuses a payload over limit before allocating it.
func readFrame(r io.Reader, limit uint32) (frame, error) {
	var h [headerLen]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return frame{}, err
	}
	n := binary.BigEndian.Uint32(h[1:])
	if n > limit {
		return frame{}, fmt.Errorf("frame of %d bytes is too large", n)
	}
	f := frame{kind: h[0], payload: make([]byte, n)}
	_, err := io.ReadFull(r, f.payload)
	return f, err
}

func encodeFrame(kind byte, payload []byte) []byte {
	b := make([]byte, headerLen+len(payload))
	b[0] = kind
	binary.BigEndian.PutUint32(b[1:], uint32(len(payload)))
	copy(b[headerLen:], payload)
	return b
}
