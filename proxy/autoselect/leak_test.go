package autoselect_test

import (
	"bytes"
	"context"
	"io"
	gonet "net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/autoselect"
)

func settle(d time.Duration) int {
	best := runtime.NumGoroutine()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		runtime.GC()
		if n := runtime.NumGoroutine(); n < best {
			best = n
		}
	}
	return best
}

func TestEndedConnectionsLeaveNothingPolling(t *testing.T) {
	sink, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	const upload = 300 << 10
	go func() {
		for {
			c, err := sink.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.CopyN(io.Discard, c, upload)
				c.Write([]byte("done"))
			}()
		}
	}()

	m0 := newFakeSocks(t, "ok", time.Millisecond)
	m1 := newFakeSocks(t, "ok", 20*time.Millisecond)
	r := newRig(t, `"initial":"m0"`, m0, m1)
	r.waitFor("a selection", 10*time.Second, func(s autoselect.GroupStatus) bool { return s.Selected != "" })

	runBatch(t, r, sink, upload, 4)
	base := settle(2 * time.Second)

	stop := make(chan struct{})
	go func() {
		modes := []string{"blackhole", "drop", "ok"}
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			case <-time.After(250 * time.Millisecond):
				m0.set(modes[i%len(modes)], time.Millisecond)
			}
		}
	}()
	runBatch(t, r, sink, upload, 40)
	close(stop)
	m0.set("ok", time.Millisecond)

	after := settle(6 * time.Second)
	t.Logf("goroutines: base=%d after=%d delta=%+d", base, after, after-base)
	if after > base+16 {
		t.Fatalf("goroutines did not come back after the connections ended: %d before, %d after "+
			"(+%d for 40 connections)", base, after, after-base)
	}
}

func runBatch(t *testing.T, r *rig, sink gonet.Listener, upload, n int) {
	t.Helper()
	port := net.Port(sink.Addr().(*gonet.TCPAddr).Port)
	payload := bytes.Repeat([]byte("x"), upload)
	var wg sync.WaitGroup
	var failed atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			c, err := core.Dial(ctx, r.inst, net.TCPDestination(net.LocalHostIP, port))
			if err != nil {
				failed.Add(1)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(15 * time.Second))
			if _, err := c.Write(payload); err != nil {
				failed.Add(1)
				return
			}
			got := make([]byte, 4)
			io.ReadFull(c, got)
		}()
	}
	wg.Wait()
}
