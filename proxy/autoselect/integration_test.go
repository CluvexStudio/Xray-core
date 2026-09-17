package autoselect_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	gonet "net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy/autoselect"
)

// fakeSocks is a SOCKS5 server whose behaviour a test can change while it runs.
type fakeSocks struct {
	ln      gonet.Listener
	mode    atomic.Value // "ok", "blackhole", "drop"
	latency atomic.Int64 // added before each handshake reply
	accepts atomic.Int32
}

func newFakeSocks(t *testing.T, mode string, latency time.Duration) *fakeSocks {
	t.Helper()
	ln, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSocks{ln: ln}
	f.set(mode, latency)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.accepts.Add(1)
			go f.handle(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeSocks) set(mode string, latency time.Duration) {
	f.mode.Store(mode)
	f.latency.Store(int64(latency))
}

func (f *fakeSocks) port() int { return f.ln.Addr().(*gonet.TCPAddr).Port }

func (f *fakeSocks) handle(c gonet.Conn) {
	defer c.Close()
	mode := f.mode.Load().(string)
	lat := time.Duration(f.latency.Load())
	if mode == "blackhole" || mode == "freeze" {
		io.Copy(io.Discard, c)
		return
	}
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, hdr[1])); err != nil {
		return
	}
	time.Sleep(lat)
	c.Write([]byte{5, 0})
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	var host string
	switch req[3] {
	case 1:
		ip := make([]byte, 4)
		io.ReadFull(c, ip)
		host = gonet.IP(ip).String()
	case 3:
		l := make([]byte, 1)
		io.ReadFull(c, l)
		d := make([]byte, l[0])
		io.ReadFull(c, d)
		host = string(d)
	case 4:
		ip := make([]byte, 16)
		io.ReadFull(c, ip)
		host = gonet.IP(ip).String()
	}
	pb := make([]byte, 2)
	io.ReadFull(c, pb)
	port := binary.BigEndian.Uint16(pb)
	time.Sleep(lat)
	ok := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	if mode == "freeze" {
		return
	}
	if mode == "drop" {
		// Takes the request and the first client bytes, then dies without answering.
		c.Write(ok)
		c.Read(make([]byte, 4096))
		return
	}
	upstream, err := gonet.Dial("tcp", gonet.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	c.Write(ok)
	go f.relay(upstream, c)
	f.relay(c, upstream)
}

// relay copies until either side closes, holding data back for as long as the server is frozen:
// a server that stops forwarding without closing anything, the way a blocked one does.
func (f *fakeSocks) relay(dst, src gonet.Conn) {
	defer dst.Close()
	b := make([]byte, 32<<10)
	for {
		n, err := src.Read(b)
		for n > 0 && f.mode.Load().(string) == "freeze" {
			time.Sleep(20 * time.Millisecond)
		}
		if n > 0 {
			if _, werr := dst.Write(b[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// echoServer counts connections and the bytes it received.
type echoServer struct {
	ln    gonet.Listener
	conns atomic.Int32
	mu    sync.Mutex
	got   bytes.Buffer
}

func newEchoServer(t *testing.T) *echoServer {
	t.Helper()
	ln, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &echoServer{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			e.conns.Add(1)
			go func() {
				defer c.Close()
				b := make([]byte, 4096)
				for {
					n, err := c.Read(b)
					if n > 0 {
						e.mu.Lock()
						e.got.Write(b[:n])
						e.mu.Unlock()
						c.Write(b[:n])
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return e
}

func (e *echoServer) received() []byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]byte(nil), e.got.Bytes()...)
}

type rig struct {
	t      *testing.T
	inst   *core.Instance
	probes atomic.Int32
	echo   *echoServer
	socks  []*fakeSocks
}

func newRig(t *testing.T, settings string, members ...*fakeSocks) *rig {
	t.Helper()
	r := &rig{t: t, echo: newEchoServer(t), socks: members}
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r.probes.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(probe.Close)

	var tags, outbounds []string
	for i, m := range members {
		tag := fmt.Sprintf("m%d", i)
		tags = append(tags, `"`+tag+`"`)
		outbounds = append(outbounds, fmt.Sprintf(
			`{"tag":%q,"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":%d}]}}`, tag, m.port()))
	}
	if settings != "" {
		settings = "," + settings
	}
	config := fmt.Sprintf(`{
	  "log": {"loglevel": "none"},
	  "policy": {"levels": {"0": {"handshake": 3}}, "system": {"statsOutboundUplink": true, "statsOutboundDownlink": true}},
	  "stats": {},
	  "outbounds": [
	    {"tag": "auto", "protocol": "autoselect", "settings": {
	      "outbounds": [%s], "probeURL": %q, "probeTimeout": "1s",
	      "activeInterval": "1s", "standbyInterval": "1s", "sweepInterval": "2s"%s}},
	    %s
	  ]}`, strings.Join(tags, ","), probe.URL+"/generate_204", settings, strings.Join(outbounds, ",\n"))
	cfg, err := serial.LoadJSONConfig(strings.NewReader(config))
	if err != nil {
		t.Fatalf("config: %v\n%s", err, config)
	}
	inst, err := core.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inst.Close() })
	r.inst = inst
	return r
}

func (r *rig) status() autoselect.GroupStatus {
	for _, s := range autoselect.Statuses() {
		if s.Tag == "auto" {
			return s
		}
	}
	return autoselect.GroupStatus{}
}

func (r *rig) waitFor(what string, timeout time.Duration, ok func(autoselect.GroupStatus) bool) autoselect.GroupStatus {
	r.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		s := r.status()
		if ok(s) {
			return s
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("timed out waiting for %s; status: %+v", what, s)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func member(s autoselect.GroupStatus, tag string) autoselect.MemberStatus {
	for _, m := range s.Members {
		if m.Tag == tag {
			return m
		}
	}
	return autoselect.MemberStatus{}
}

// exchange opens a connection through the group, sends payload and returns what came back.
func (r *rig) exchange(payload []byte, timeout time.Duration) ([]byte, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	c, err := core.Dial(ctx, r.inst, net.TCPDestination(net.LocalHostIP, net.Port(r.echo.ln.Addr().(*gonet.TCPAddr).Port)))
	if err != nil {
		return nil, 0, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(payload); err != nil {
		return nil, time.Since(start), err
	}
	got := make([]byte, len(payload))
	_, err = io.ReadFull(c, got)
	return got, time.Since(start), err
}

// A TLS ClientHello record header: replaying it on a fresh connection is invisible to the app.
var clientHello = append([]byte{0x16, 0x03, 0x01, 0x00, 0x40, 0x01}, bytes.Repeat([]byte{0xab}, 64)...)

func TestPicksTheFastestMember(t *testing.T) {
	r := newRig(t, "",
		newFakeSocks(t, "ok", 120*time.Millisecond),
		newFakeSocks(t, "ok", 5*time.Millisecond),
		newFakeSocks(t, "ok", 60*time.Millisecond),
	)
	s := r.waitFor("m1 selected", 5*time.Second, func(s autoselect.GroupStatus) bool {
		return s.Selected == "m1" && member(s, "m0").Samples > 0 && member(s, "m2").Samples > 0
	})
	if s.State != "ok" {
		t.Fatalf("state = %q, want ok", s.State)
	}
	got, _, err := r.exchange(clientHello, 3*time.Second)
	if err != nil || !bytes.Equal(got, clientHello) {
		t.Fatalf("exchange: %v", err)
	}
}

func TestHedgesOffADeadSelectionAndFailsOver(t *testing.T) {
	m0 := newFakeSocks(t, "ok", 2*time.Millisecond)
	m1 := newFakeSocks(t, "ok", 30*time.Millisecond)
	r := newRig(t, `"initial":"m0"`, m0, m1)
	r.waitFor("both measured, m0 selected", 5*time.Second, func(s autoselect.GroupStatus) bool {
		return s.Selected == "m0" && member(s, "m1").Samples > 0 && member(s, "m0").Samples > 0
	})

	m0.set("blackhole", 0)
	got, took, err := r.exchange(clientHello, 6*time.Second)
	if err != nil || !bytes.Equal(got, clientHello) {
		t.Fatalf("exchange through a dead selection failed: %v", err)
	}
	// m0's budget floor is 2.5s; the race against m1 must have answered well before that.
	if took > 2*time.Second {
		t.Fatalf("connection took %v; the hedge should have carried it", took)
	}
	s := r.waitFor("failover to m1", 6*time.Second, func(s autoselect.GroupStatus) bool {
		return s.Selected == "m1"
	})
	last := s.Events[len(s.Events)-1]
	if last.Reason != "failover" || last.From != "m0" {
		t.Fatalf("last event = %+v, want failover from m0", last)
	}
	// Now straight to m1, no racing needed.
	_, took, err = r.exchange(clientHello, 3*time.Second)
	if err != nil || took > time.Second {
		t.Fatalf("after failover: err=%v took=%v", err, took)
	}
}

func TestReplaysAConnectionWhoseMemberDied(t *testing.T) {
	m0 := newFakeSocks(t, "ok", time.Millisecond)
	m1 := newFakeSocks(t, "ok", 40*time.Millisecond)
	r := newRig(t, `"initial":"m0"`, m0, m1)
	r.waitFor("both measured", 5*time.Second, func(s autoselect.GroupStatus) bool {
		return s.Selected == "m0" && member(s, "m1").Samples > 0 && member(s, "m0").Samples > 0
	})
	m0.set("drop", 0)
	got, _, err := r.exchange(clientHello, 6*time.Second)
	if err != nil || !bytes.Equal(got, clientHello) {
		t.Fatalf("replayed exchange failed: %v", err)
	}
	if n := r.echo.conns.Load(); n != 1 {
		t.Fatalf("destination saw %d connections, want exactly 1", n)
	}
	if rec := r.echo.received(); !bytes.Equal(rec, clientHello) {
		t.Fatalf("destination received %d bytes, want the ClientHello exactly once", len(rec))
	}
}

func TestNeverReplaysDataThatIsNotSafeToRepeat(t *testing.T) {
	m0 := newFakeSocks(t, "ok", time.Millisecond)
	m1 := newFakeSocks(t, "ok", 40*time.Millisecond)
	r := newRig(t, `"initial":"m0"`, m0, m1)
	r.waitFor("both measured", 5*time.Second, func(s autoselect.GroupStatus) bool {
		return s.Selected == "m0" && member(s, "m1").Samples > 0 && member(s, "m0").Samples > 0
	})
	m0.set("drop", 0)
	post := []byte("POST /pay HTTP/1.1\r\nHost: shop\r\nContent-Length: 0\r\n\r\n")
	_, _, err := r.exchange(post, 4*time.Second)
	if err == nil {
		t.Fatalf("a non-idempotent request was silently retried on another member")
	}
	if n := r.echo.conns.Load(); n != 0 {
		t.Fatalf("the request reached the destination %d time(s) through another member", n)
	}
}

func TestRecoversWhenEverythingWasDown(t *testing.T) {
	m0 := newFakeSocks(t, "blackhole", 0)
	m1 := newFakeSocks(t, "blackhole", 0)
	r := newRig(t, "", m0, m1)
	r.waitFor("down", 8*time.Second, func(s autoselect.GroupStatus) bool {
		return member(s, "m0").State == "dead" && member(s, "m1").State == "dead"
	})
	m1.set("ok", time.Millisecond)
	for _, g := range autoselect.Statuses() {
		_ = g
	}
	autoselect.KickAll()
	s := r.waitFor("m1 back", 5*time.Second, func(s autoselect.GroupStatus) bool {
		return s.Selected == "m1" && member(s, "m1").State == "alive"
	})
	if s.State != "ok" {
		t.Fatalf("state = %q after recovery", s.State)
	}
}

func TestIdleStopsProbing(t *testing.T) {
	r := newRig(t, `"idleAfter":"1500ms"`,
		newFakeSocks(t, "ok", time.Millisecond),
		newFakeSocks(t, "ok", time.Millisecond),
	)
	r.waitFor("idle", 6*time.Second, func(s autoselect.GroupStatus) bool { return s.State == "idle" })
	before := r.probes.Load()
	time.Sleep(2500 * time.Millisecond)
	if after := r.probes.Load(); after != before {
		t.Fatalf("probed %d times while idle", after-before)
	}
	if _, _, err := r.exchange(clientHello, 3*time.Second); err != nil {
		t.Fatalf("exchange after idle: %v", err)
	}
	r.waitFor("probing again", 3*time.Second, func(autoselect.GroupStatus) bool { return r.probes.Load() > before })
}

func TestPinning(t *testing.T) {
	r := newRig(t, "",
		newFakeSocks(t, "ok", time.Millisecond),
		newFakeSocks(t, "ok", 80*time.Millisecond),
	)
	r.waitFor("m0 selected", 5*time.Second, func(s autoselect.GroupStatus) bool { return s.Selected == "m0" })
	if !autoselect.PinMember("auto", "m1") {
		t.Fatal("pin failed")
	}
	if s := r.status(); s.Selected != "m1" || s.Pinned != "m1" {
		t.Fatalf("after pin: selected=%q pinned=%q", s.Selected, s.Pinned)
	}
	autoselect.PinMember("auto", "")
	r.waitFor("m0 again", 3*time.Second, func(s autoselect.GroupStatus) bool { return s.Selected == "m0" })
}

func TestCutsConnectionsStuckOnADeadMember(t *testing.T) {
	defer autoselect.SetStalledAfter(time.Second)()
	m0 := newFakeSocks(t, "ok", time.Millisecond)
	m1 := newFakeSocks(t, "ok", 40*time.Millisecond)
	r := newRig(t, `"initial":"m0"`, m0, m1)
	r.waitFor("both measured", 5*time.Second, func(s autoselect.GroupStatus) bool {
		return s.Selected == "m0" && member(s, "m1").Samples > 0 && member(s, "m0").Samples > 0
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := core.Dial(ctx, r.inst, net.TCPDestination(net.LocalHostIP, net.Port(r.echo.ln.Addr().(*gonet.TCPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(clientHello)
	if _, err := io.ReadFull(c, make([]byte, len(clientHello))); err != nil {
		t.Fatalf("first exchange: %v", err)
	}

	m0.set("freeze", 0)
	start := time.Now()
	c.Write(clientHello) // never answered while frozen
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, err = io.ReadFull(c, make([]byte, len(clientHello)))
	if err == nil {
		t.Fatal("a connection on a frozen member got an answer")
	}
	if took := time.Since(start); took > 12*time.Second {
		t.Fatalf("the hung connection was only released after %v (read error: %v)", took, err)
	}
	r.waitFor("m0 dead, m1 selected", 5*time.Second, func(s autoselect.GroupStatus) bool {
		return s.Selected == "m1" && member(s, "m0").State == "dead"
	})
}

func TestLargeUploadBeforeAnyResponse(t *testing.T) {
	ln, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const size = 300 << 10
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.CopyN(io.Discard, c, size)
		c.Write([]byte("done"))
	}()
	r := newRig(t, "",
		newFakeSocks(t, "ok", time.Millisecond),
		newFakeSocks(t, "ok", 20*time.Millisecond),
	)
	r.waitFor("selected", 5*time.Second, func(s autoselect.GroupStatus) bool { return s.Selected != "" })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := core.Dial(ctx, r.inst, net.TCPDestination(net.LocalHostIP, net.Port(ln.Addr().(*gonet.TCPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(bytes.Repeat([]byte("x"), size)); err != nil {
		t.Fatalf("upload: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "done" {
		t.Fatalf("response after a %d byte upload: %q %v", size, got, err)
	}
}

func TestConcurrentConnectionsWhileAMemberFlaps(t *testing.T) {
	m0 := newFakeSocks(t, "ok", time.Millisecond)
	m1 := newFakeSocks(t, "ok", 15*time.Millisecond)
	m2 := newFakeSocks(t, "ok", 30*time.Millisecond)
	r := newRig(t, `"initial":"m0"`, m0, m1, m2)
	r.waitFor("measured", 5*time.Second, func(s autoselect.GroupStatus) bool {
		return member(s, "m0").Samples > 0 && member(s, "m1").Samples > 0 && member(s, "m2").Samples > 0
	})
	stop := make(chan struct{})
	go func() {
		modes := []string{"blackhole", "ok", "drop", "ok"}
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			case <-time.After(300 * time.Millisecond):
				m0.set(modes[i%len(modes)], time.Millisecond)
			}
		}
	}()
	defer close(stop)

	var wg sync.WaitGroup
	var failures atomic.Int32
	for w := 0; w < 24; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 6; i++ {
				got, _, err := r.exchange(clientHello, 10*time.Second)
				if err != nil || !bytes.Equal(got, clientHello) {
					failures.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if n := failures.Load(); n != 0 {
		t.Fatalf("%d of 144 replayable connections failed while one of three members flapped; status %+v", n, r.status())
	}
}

// A freedom member reached through a SOCKS inbound can splice its response straight from socket to
// socket, bypassing the group's writer. The group must still see the connection as answered, or it
// abandons a healthy stream at its budget and replays it elsewhere.
func TestLongStreamThroughARealInboundIsNotAbandoned(t *testing.T) {
	streamer, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer streamer.Close()
	var streamConns atomic.Int32
	go func() {
		for {
			c, err := streamer.Accept()
			if err != nil {
				return
			}
			streamConns.Add(1)
			go func() {
				defer c.Close()
				c.Read(make([]byte, 1024))
				for i := 0; i < 20; i++ {
					if _, err := c.Write(bytes.Repeat([]byte{byte(i)}, 1024)); err != nil {
						return
					}
					time.Sleep(150 * time.Millisecond)
				}
			}()
		}
	}()
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer probe.Close()
	portLn, _ := gonet.Listen("tcp", "127.0.0.1:0")
	inPort := portLn.Addr().(*gonet.TCPAddr).Port
	portLn.Close()

	config := fmt.Sprintf(`{
	  "log": {"loglevel": "none"},
	  "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": %d, "protocol": "socks", "settings": {"udp": false}}],
	  "outbounds": [
	    {"tag": "auto", "protocol": "autoselect", "settings": {
	      "outbounds": ["direct-a", "dead-b"], "initial": "direct-a", "probeURL": %q,
	      "probeTimeout": "1s", "attemptBudget": "600ms"}},
	    {"tag": "direct-a", "protocol": "freedom"},
	    {"tag": "dead-b", "protocol": "socks", "settings": {"servers": [{"address": "127.0.0.1", "port": 1}]}}
	  ]}`, inPort, probe.URL+"/generate_204")
	cfg, err := serial.LoadJSONConfig(strings.NewReader(config))
	if err != nil {
		t.Fatal(err)
	}
	inst, err := core.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	defer inst.Close()

	c, err := gonet.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", inPort), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, make([]byte, 2))
	sp := streamer.Addr().(*gonet.TCPAddr).Port
	c.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, byte(sp >> 8), byte(sp)})
	if _, err := io.ReadFull(c, make([]byte, 10)); err != nil {
		t.Fatalf("socks handshake: %v", err)
	}
	c.Write(clientHello)
	got, err := io.ReadAll(c)
	if len(got) != 20*1024 {
		t.Fatalf("stream delivered %d of %d bytes (err %v); the connection was cut or replayed", len(got), 20*1024, err)
	}
	if n := streamConns.Load(); n != 1 {
		t.Fatalf("the destination saw %d connections, want 1", n)
	}
}
