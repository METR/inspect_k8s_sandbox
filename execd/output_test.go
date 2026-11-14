package main

import (
	"bytes"
	"math/rand/v2"
	"runtime"
	"sync"
	"testing"
)

func TestAFifoHoldsWhatASliceWould(t *testing.T) {
	var f fifo
	var want []byte
	r := rand.New(rand.NewPCG(1, 2)) // the same writes and acks every run
	for i := range 5000 {
		if r.IntN(3) > 0 {
			data := bytes.Repeat([]byte{byte(i)}, 1+r.IntN(9))
			f.Write(data, 16)
			want = append(want, data...)
		} else {
			n := r.IntN(len(want) + 1)
			f.Next(n)
			want = want[n:]
		}
		if f.Len() != len(want) {
			t.Fatalf("after %d steps it holds %d bytes, want %d", i+1, f.Len(), len(want))
		}
		if len(want) == 0 {
			continue
		}
		off := r.IntN(len(want))
		n := 1 + r.IntN(len(want)-off)
		if got := f.span(off, n); !bytes.Equal(got, want[off:off+n]) {
			t.Fatalf("after %d steps, %d bytes from %d are %v, want %v", i+1, n, off, got, want[off:off+n])
		}
	}
}

func TestACallsUnreadOutputTakesLittleMoreMemoryThanItHolds(t *testing.T) {
	cl := &call{id: 41}
	cl.room = sync.NewCond(&cl.mu)
	read := make([]byte, 256<<10)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	for range maxUnacked/len(read) + 1 { // all execd holds for a client that reads nothing
		cl.output(0, read)
	}

	runtime.GC()
	runtime.ReadMemStats(&after)
	// A buffer that doubles as it fills holds twice this, for every stream of every command that prints.
	if took := int(after.HeapAlloc) - int(before.HeapAlloc); cl.out[0].Len() <= maxUnacked || took > maxUnacked*3/2 {
		t.Fatalf("%d MiB of unread output took %d MiB", cl.out[0].Len()>>20, took>>20)
	}
	runtime.KeepAlive(cl)
}
