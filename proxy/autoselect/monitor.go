package autoselect

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/transport/internet/tagged"
)

// monitor schedules probes. Each member carries its own next-probe time, set from its role and
// health (see nextProbeLocked); this loop only launches whatever is due.
func (g *Group) monitor() {
	t := time.NewTicker(monitorTick)
	defer t.Stop()
	for {
		g.tick()
		select {
		case <-g.ctx.Done():
			return
		case <-t.C:
		case <-g.wake:
		}
	}
}

func (g *Group) tick() {
	now := g.now()
	g.mu.Lock()
	g.refreshMembersLocked(now)
	g.sampleCountersLocked(now)
	if now.Sub(time.Unix(0, g.lastTraffic.Load())) >= g.cfg.idleAfter {
		// Nobody is using the tunnel, so nobody benefits from fresh numbers; probing would only
		// spend the battery and the data plan. noteTraffic brings the probes back.
		g.idle.Store(true)
		g.mu.Unlock()
		return
	}
	var due []*member
	for _, m := range g.members {
		if m.probing || now.Before(m.nextProbeAt) {
			continue
		}
		if m == g.selected && m.state == stateAlive &&
			(now.Sub(m.lastPassiveOK) < g.cfg.activeInterval || now.Sub(m.lastBytesAt) < g.cfg.activeInterval) {
			// Real traffic already proved it works; a probe would add nothing but bytes.
			m.nextProbeAt = now.Add(g.cfg.activeInterval)
			continue
		}
		m.probing = true
		m.probeStarted = now
		due = append(due, m)
	}
	g.mu.Unlock()
	for _, m := range due {
		select {
		case g.sem <- struct{}{}:
			go func(m *member) {
				defer func() { <-g.sem }()
				d, err := g.probe(m)
				if g.ctx.Err() != nil {
					return
				}
				g.recordProbe(m, d, err)
			}(m)
		default:
			// Too many probes in flight; it stays due and goes out on a later tick.
			g.mu.Lock()
			m.probing = false
			g.mu.Unlock()
		}
	}
}

func (g *Group) probe(m *member) (time.Duration, error) {
	d, err := g.probeURL(m, g.cfg.probeURL)
	if err != nil && g.cfg.fallbackProbeURL != "" && g.ctx.Err() == nil {
		if d2, err2 := g.probeURL(m, g.cfg.fallbackProbeURL); err2 == nil {
			return d2, nil
		}
	}
	return d, err
}

// probeURL measures one request through m on a fresh connection: the "real delay" a new
// application connection would see, handshake included. Any HTTP response counts — getting one
// at all proves the path through the member works.
func (g *Group) probeURL(m *member, url string) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(g.ctx, g.cfg.probeTimeout)
	defer cancel()
	collector := &errorCollector{}
	// The dial context is derived from ctx rather than taken from net/http, because it must carry
	// the Xray instance; cancelling it when the probe ends also stops the member's dial retries.
	dialCtx := session.TrackedConnectionError(ctx, collector)
	tr := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			dest, err := net.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, err
			}
			return tagged.Dialer(dialCtx, g.dispatcher, dest, m.tag)
		},
		TLSHandshakeTimeout:   g.cfg.probeTimeout,
		ResponseHeaderTimeout: g.cfg.probeTimeout,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		Timeout:   g.cfg.probeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	utils.TryDefaultHeadersWith(req.Header, "nav")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		// The member's own report ("dial tcp …: i/o timeout", a REALITY rejection) says far more
		// than the client's "context deadline exceeded".
		if inner := collector.get(); inner != nil {
			return 0, inner
		}
		return 0, err
	}
	d := time.Since(start)
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	return d, nil
}

type errorCollector struct {
	mu  sync.Mutex
	err error
}

func (c *errorCollector) SubmitError(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.mu.Unlock()
}

func (c *errorCollector) get() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}
