package main

// The wire protocol between k8s_sandbox (src/k8s_sandbox/_pod/execd.py) and execd.
//
// Every message is one frame: a 13-byte header (type u8, call id u64, payload length u32,
// all big-endian) and the payload. Many calls share one connection; the call id, chosen by
// the client, says which call a frame belongs to. The first frame on a connection must be
// AUTH with the per-sandbox key, whose SHA-256 execd was given at start.

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// client -> execd
	fAuth   = 1 // payload: the key
	fStart  = 2 // payload: startRequest as JSON
	fStdin  = 3 // payload: bytes; an empty payload closes the call's stdin
	fKill   = 4 // SIGKILL every process the call started (found by its exec tag)
	fResume = 5 // payload: resumeRequest; replay output from these offsets, then stream.
	// An unknown call gets ERROR "unknown call": its START never arrived, so the client
	// sends START again.
	fRelease = 6 // forget a finished call and free its buffered output
	fPing    = 7
	fAck     = 8 // payload: resumeRequest; the client has the output before these offsets

	// execd -> client
	fOK     = 16 // reply to AUTH; payload: {"pid": execd's pid}
	fStdout = 17
	fStderr = 18
	fExit   = 19 // payload: {"code": n} (128+signal for a signal death)
	fPong   = 20
	fError  = 21 // payload: message; the call is unknown or could not start
	// reply to RESUME, before any replayed output; payload: {"stdin": bytes received, "eof": bool,
	// "put": bytes written to the process}
	fResumed = 22
	// payload: {"stdin": bytes written to the process}; the client keeps a window of stdin
	// in flight above it, so a call's queued stdin stays bounded
	fStdinAck = 23
)

const headerLen = 13
const maxPayload = 64 << 20

type frame struct {
	kind    byte
	id      uint64
	payload []byte
}

type startRequest struct {
	Argv  []string          `json:"argv"`
	Env   map[string]string `json:"env"`
	Cwd   string            `json:"cwd"`
	User  string            `json:"user"`
	Stdin bool              `json:"stdin"`
	// The value of HAWK_NEXT_EXEC in Env: KILL stops every process carrying it.
	Tag string `json:"tag"`
	// Seconds until the call is killed, as KILL does, even if no client is connected; 0: never.
	Timeout float64 `json:"timeout"`
	// A stream (exec_stdio) is never resumed: it is killed when its connection drops.
	Stream bool `json:"stream"`
}

type resumeRequest struct {
	Stdout int `json:"stdout"`
	Stderr int `json:"stderr"`
}

// readFrameMax refuses a payload over limit before allocating it.
func readFrameMax(r io.Reader, limit uint32) (frame, error) {
	var h [headerLen]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return frame{}, err
	}
	n := binary.BigEndian.Uint32(h[9:])
	if n > limit {
		return frame{}, fmt.Errorf("frame of %d bytes is too large", n)
	}
	f := frame{kind: h[0], id: binary.BigEndian.Uint64(h[1:9]), payload: make([]byte, n)}
	_, err := io.ReadFull(r, f.payload)
	return f, err
}

func encodeFrame(kind byte, id uint64, payload []byte) []byte {
	b := make([]byte, headerLen+len(payload))
	b[0] = kind
	binary.BigEndian.PutUint64(b[1:9], id)
	binary.BigEndian.PutUint32(b[9:], uint32(len(payload)))
	copy(b[headerLen:], payload)
	return b
}
