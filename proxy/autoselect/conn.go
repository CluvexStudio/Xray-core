package autoselect

import (
	"context"
	goerrors "errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

// linkProcessor runs one connection through an outbound without taking ownership of the link: the
// link is neither closed nor interrupted when it returns, and the error comes back to the caller.
// app/proxyman/outbound.Handler implements it in this fork; it is what lets one client connection
// be moved to another member after a failure.
type linkProcessor interface {
	ProcessLink(ctx context.Context, link *transport.Link) error
}

// step is one member of a connection's plan, with its handler resolved while the group was locked.
type step struct {
	m  *member
	lp linkProcessor
}

var errNoResponse = errors.New("no response in time")

// payloadKind classifies the first bytes a client sent, which decides whether they may be sent
// again through another member.
type payloadKind uint8

const (
	payloadNone payloadKind = iota
	// Anything we cannot prove harmless to repeat, e.g. a plaintext HTTP request.
	payloadOpaque
	// A TLS ClientHello: no application data can precede the server's reply, so repeating it on
	// a fresh connection is invisible to the application.
	payloadTLSHello
	// QUIC long-header packets: the handshake, which a server always answers.
	payloadQUIC
	// DNS queries, which are idempotent and always answered.
	payloadDNS
)

func (k payloadKind) replaySafe() bool {
	return k == payloadTLSHello || k == payloadQUIC || k == payloadDNS
}

func classifyPayload(target net.Destination, head []byte) payloadKind {
	if target.Port == 53 {
		return payloadDNS
	}
	if target.Network == net.Network_UDP {
		// Long header bit set and a non-zero version: an Initial/0-RTT/Handshake packet.
		if len(head) >= 5 && head[0]&0x80 != 0 && (head[1]|head[2]|head[3]|head[4]) != 0 {
			return payloadQUIC
		}
		return payloadOpaque
	}
	// TLS record header (type 22 = handshake) followed by handshake type 1 = ClientHello.
	if len(head) >= 6 && head[0] == 0x16 && head[5] == 0x01 {
		return payloadTLSHello
	}
	return payloadOpaque
}

type eventKind uint8

const (
	evWon eventKind = iota
	evDone
	evBudget
	evHedge
)

type event struct {
	kind eventKind
	a    *attempt
}

// conn is one client connection being forwarded through the group.
type conn struct {
	g   *Group
	ctx context.Context
	// The group's own outbound metadata. Its CanSpliceCopy gates kernel splicing for every
	// attempt: a spliced response goes from socket to socket and never passes the attempt's writer,
	// so the connection would never count as answered and would be abandoned at its budget while
	// data flowed. Splicing is held back until an attempt has won, then allowed.
	group  *session.Outbound
	src    buf.Reader
	srcT   buf.TimeoutReader
	dst    buf.Writer
	target net.Destination
	events chan event

	winner atomic.Pointer[attempt]

	// Held by whoever is reading the client while no attempt has won, so chunks enter the
	// history in the order the client sent them.
	readMu sync.Mutex

	mu           sync.Mutex
	history      buf.MultiBuffer // everything the client sent before an attempt won; owned here
	historyBytes int32
	head         []byte
	kind         payloadKind
	overflow     bool
	srcErr       error
	// With data that must not reach two servers, only this attempt may consume it.
	owner    *attempt
	released bool
}

type attempt struct {
	c       *conn
	m       *member
	index   int
	ctx     context.Context
	cancel  context.CancelFunc
	started time.Time
	budget  *time.Timer

	pos     int  // history entries already handed over (guarded by c.mu)
	drained bool // winner only, touched by its reading goroutine alone

	consumed atomic.Bool
	aborted  atomic.Bool
	lastDown atomic.Int64

	won      chan struct{}
	done     chan struct{}
	late     chan struct{}
	lateOnce sync.Once
	err      error
}

func (c *conn) send(ev event) {
	select {
	case c.events <- ev:
	default:
		// The buffer holds every event a plan can produce; running out means forward has
		// already returned and nobody is listening any more.
	}
}

// forward sends one connection through plan, moving it to the next member when that is both
// needed and safe.
func (g *Group) forward(ctx context.Context, link *transport.Link, ob *session.Outbound, plan []step) error {
	srcT, canTime := link.Reader.(buf.TimeoutReader)
	if !g.cfg.retry || !canTime || len(plan) < 2 {
		return g.single(ctx, link, plan[0])
	}
	pristine := *ob
	pristine.CanSpliceCopy = 0
	// 2 = "not yet, but maybe later": CopyRawConnIfExist re-reads it on every round, where 3 would
	// rule splicing out for the whole connection.
	ob.CanSpliceCopy = 2
	c := &conn{
		g:      g,
		ctx:    ctx,
		group:  ob,
		src:    link.Reader,
		srcT:   srcT,
		dst:    link.Writer,
		target: ob.Target,
		events: make(chan event, 4*len(plan)+4),
	}
	defer c.release()

	var (
		live    []*attempt
		next    int
		lastErr error
	)
	launch := func() *attempt {
		st := plan[next]
		a := c.begin(st, pristine, next)
		next++
		live = append(live, a)
		if next < len(plan) {
			// The last member gets no budget: there is nowhere left to move the connection to,
			// so it may take as long as it takes.
			budget, _ := g.timings(st.m)
			a.budget = time.AfterFunc(budget, func() { c.send(event{evBudget, a}) })
		}
		return a
	}
	drop := func(a *attempt) {
		for i, x := range live {
			if x == a {
				live = append(live[:i], live[i+1:]...)
				break
			}
		}
		if a.budget != nil {
			a.budget.Stop()
		}
	}
	isLive := func(a *attempt) bool {
		for _, x := range live {
			if x == a {
				return true
			}
		}
		return false
	}

	primary := launch()
	_, hedgeDelay := g.timings(primary.m)
	hedge := time.AfterFunc(hedgeDelay, func() { c.send(event{evHedge, primary}) })
	defer hedge.Stop()

	for {
		var ev event
		select {
		case ev = <-c.events:
		case <-ctx.Done():
			for _, a := range live {
				c.abort(a)
			}
			return ctx.Err()
		}
		a := ev.a
		switch ev.kind {
		case evWon:
			hedge.Stop()
			for _, other := range append([]*attempt(nil), live...) {
				if other == a {
					continue
				}
				drop(other)
				if other.index == 0 {
					// The first member lost a race it was given a head start in. Whether it was
					// merely slow or dead is worth knowing, and costs nothing but a short wait.
					go g.shadow(other)
				} else {
					c.abort(other)
				}
			}
			drop(a)
			g.recordOutcome(a.m, outcomeSuccess, nil)
			g.track(a)
			<-a.done
			g.untrack(a)
			return a.err

		case evDone:
			if !isLive(a) || c.winner.Load() == a {
				continue
			}
			drop(a)
			if c.clientGone() {
				// The client ended the connection; whatever the member did is not its fault.
				for _, other := range live {
					c.abort(other)
				}
				return a.err
			}
			if a.err == nil || isBenign(a.err) {
				if !c.expectsResponse() {
					// Finished cleanly without answering, and nothing about the traffic says it
					// should have: a legitimate end, not a failure.
					if len(live) == 0 {
						return a.err
					}
					continue
				}
				a.err = errNoResponse
			}
			g.recordOutcome(a.m, failureKind(a), a.err)
			lastErr = a.err
			if c.isOwner(a) {
				// It consumed data that must not reach a second server; nobody else can take over.
				for _, other := range live {
					c.abort(other)
				}
				return lastErr
			}
			if len(live) > 0 {
				continue
			}
			if next >= len(plan) || !c.retryable(a) {
				return lastErr
			}
			errors.LogInfo(ctx, "autoselect: ", a.m.tag, " failed (", shortError(a.err), "), moving the connection to ", plan[next].m.tag)
			launch()

		case evBudget:
			if !isLive(a) || c.winner.Load() == a || !c.abortable(a) {
				continue
			}
			c.abort(a)
			drop(a)
			g.recordOutcome(a.m, outcomeStall, errNoResponse)
			lastErr = errNoResponse
			if len(live) > 0 {
				continue
			}
			if next >= len(plan) {
				return lastErr
			}
			errors.LogInfo(ctx, "autoselect: ", a.m.tag, " did not answer in time, moving the connection to ", plan[next].m.tag)
			launch()

		case evHedge:
			if len(live) != 1 || live[0] != a || next >= len(plan) || c.winner.Load() != nil {
				continue
			}
			if !c.hedgeable() || !g.canHedgeTo(plan[next].m) {
				continue
			}
			launch()
		}
	}
}

// single forwards without the ability to retry, still learning from the outcome.
func (g *Group) single(ctx context.Context, link *transport.Link, st step) error {
	if st.lp == nil {
		err := errors.New("autoselect: outbound [", st.m.tag, "] is unavailable")
		g.recordOutcome(st.m, outcomeDialFailure, err)
		return err
	}
	w := &observedWriter{Writer: link.Writer, onFirst: func() { g.recordOutcome(st.m, outcomeSuccess, nil) }}
	err := st.lp.ProcessLink(ctx, &transport.Link{Reader: link.Reader, Writer: w})
	if !w.wrote.Load() && err != nil && !isBenign(err) && ctx.Err() == nil {
		if isDialFailure(err) {
			g.recordOutcome(st.m, outcomeDialFailure, err)
		} else {
			g.recordOutcome(st.m, outcomeFailure, err)
		}
	}
	return err
}

// shadow keeps a losing first attempt alive for the rest of its budget to learn why it lost.
func (g *Group) shadow(a *attempt) {
	budget, _ := g.timings(a.m)
	left := budget - time.Since(a.started)
	if left < 0 {
		left = 0
	}
	t := time.NewTimer(left)
	defer t.Stop()
	select {
	case <-a.late:
		g.recordOutcome(a.m, outcomeSlow, nil)
	case <-a.done:
		if a.err != nil && !isBenign(a.err) {
			g.recordOutcome(a.m, failureKind(a), a.err)
		}
	case <-t.C:
		g.recordOutcome(a.m, outcomeStall, errNoResponse)
	case <-g.ctx.Done():
	}
	a.c.abort(a)
}

func (c *conn) begin(st step, pristine session.Outbound, index int) *attempt {
	// Each attempt runs as a further hop after the group, with its own copy of the metadata as it
	// was before anyone touched it: proxies write to their outbound (Name, Conn, CanSpliceCopy), an
	// earlier attempt may still be unwinding, and the group's entry must stay the group's so it can
	// gate splicing (see conn.group).
	outbounds := session.OutboundsFromContext(c.ctx)
	hops := make([]*session.Outbound, len(outbounds), len(outbounds)+1)
	copy(hops, outbounds)
	cp := pristine
	ctx := session.ContextWithOutbounds(c.ctx, append(hops, &cp))
	ctx, cancel := context.WithCancel(ctx)
	a := &attempt{
		c:       c,
		m:       st.m,
		index:   index,
		ctx:     ctx,
		cancel:  cancel,
		started: time.Now(),
		won:     make(chan struct{}),
		done:    make(chan struct{}),
		late:    make(chan struct{}),
	}
	go func() {
		defer func() {
			cancel()
			close(a.done)
			c.send(event{evDone, a})
		}()
		if st.lp == nil {
			a.err = errors.New("autoselect: outbound [", st.m.tag, "] is unavailable")
			return
		}
		a.err = st.lp.ProcessLink(ctx, &transport.Link{Reader: &attemptReader{a}, Writer: &attemptWriter{a}})
	}()
	return a
}

// commit makes a the winner: from now on it owns the client connection.
func (c *conn) commit(a *attempt) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.commitLocked(a)
}

func (c *conn) commitLocked(a *attempt) bool {
	if w := c.winner.Load(); w != nil {
		return w == a
	}
	if a.aborted.Load() || c.released {
		return false
	}
	c.winner.Store(a)
	// From here on nothing will be retried, so the winner may splice. This runs on the attempt's
	// downlink goroutine, which is also the one that decides whether to splice.
	c.group.CanSpliceCopy = 1
	close(a.won)
	c.send(event{evWon, a})
	return true
}

func (c *conn) abort(a *attempt) {
	c.mu.Lock()
	if c.winner.Load() == a {
		c.mu.Unlock()
		return
	}
	a.aborted.Store(true)
	c.mu.Unlock()
	a.cancel()
}

func (c *conn) release() {
	c.mu.Lock()
	c.released = true
	buf.ReleaseMulti(c.history)
	c.history = nil
	c.mu.Unlock()
}

func (c *conn) isOwner(a *attempt) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.owner == a
}

func (c *conn) expectsResponse() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.kind.replaySafe()
}

// clientGone reports that the client side ended the connection (as opposed to merely finishing
// sending, which is io.EOF and still expects an answer).
func (c *conn) clientGone() bool {
	if c.ctx.Err() != nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.clientGoneLocked()
}

func (c *conn) clientGoneLocked() bool {
	return c.srcErr != nil && !goerrors.Is(c.srcErr, io.EOF)
}

// retryable reports whether a connection whose attempt a failed may be moved to another member.
func (c *conn) retryable(a *attempt) bool {
	if c.ctx.Err() != nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.overflow || c.winner.Load() != nil || c.clientGoneLocked() {
		return false
	}
	if !a.consumed.Load() || isDialFailure(a.err) {
		return true
	}
	return c.kind.replaySafe()
}

// abortable reports whether attempt a, still running, may be given up on.
func (c *conn) abortable(a *attempt) bool {
	if c.ctx.Err() != nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.overflow || c.clientGoneLocked() {
		return false
	}
	return !a.consumed.Load() || c.kind.replaySafe()
}

// hedgeable reports whether a second attempt may run beside the current one.
func (c *conn) hedgeable() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.overflow || c.clientGoneLocked() {
		return false
	}
	return len(c.history) == 0 || c.kind.replaySafe()
}

// pull reads the client once on behalf of a while nobody has won. Every chunk enters the history
// before anyone sees it, so a chunk read by an attempt that is abandoned the next moment is still
// there for the one that replaces it.
func (c *conn) pull(a *attempt, wait time.Duration) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.winner.Load() != nil || a.aborted.Load() {
		return
	}
	c.mu.Lock()
	pending := a.pos < len(c.history) || c.srcErr != nil
	c.mu.Unlock()
	if pending {
		return
	}
	mb, err := c.srcT.ReadMultiBufferTimeout(wait)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released {
		buf.ReleaseMulti(mb)
		return
	}
	if !mb.IsEmpty() {
		c.recordLocked(mb, a)
	}
	if err != nil && err != buf.ErrReadTimeout {
		c.srcErr = err
	}
}

func (c *conn) recordLocked(mb buf.MultiBuffer, puller *attempt) {
	if c.kind == payloadNone {
		for _, b := range mb {
			need := 6 - len(c.head)
			if need <= 0 {
				break
			}
			bs := b.Bytes()
			if len(bs) > need {
				bs = bs[:need]
			}
			c.head = append(c.head, bs...)
		}
		if c.target.Network == net.Network_UDP || len(c.head) >= 6 || c.target.Port == 53 {
			c.kind = classifyPayload(c.target, c.head)
		}
	}
	c.history = append(c.history, mb...)
	c.historyBytes += mb.Len()
	if c.historyBytes > c.g.cfg.maxReplayBytes && !c.overflow {
		// Too much to keep for a replay. The attempt reading right now is the only one this
		// connection will get, so it wins immediately and reads the client directly from here on.
		c.overflow = true
		c.commitLocked(puller)
	}
}

type attemptReader struct{ a *attempt }

func (r *attemptReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.a.read(-1)
}

func (r *attemptReader) ReadMultiBufferTimeout(d time.Duration) (buf.MultiBuffer, error) {
	return r.a.read(d)
}

// Interrupt only reaches the client when it comes from the winner.
func (r *attemptReader) Interrupt() {
	if r.a.c.winner.Load() == r.a {
		common.Interrupt(r.a.c.src)
	}
}

func (a *attempt) read(timeout time.Duration) (buf.MultiBuffer, error) {
	c := a.c
	if c.winner.Load() == a {
		if !a.drained {
			if mb := a.drain(); !mb.IsEmpty() {
				return mb, nil
			}
		}
		if timeout < 0 {
			return c.src.ReadMultiBuffer()
		}
		return c.srcT.ReadMultiBufferTimeout(timeout)
	}
	var deadline time.Time
	if timeout >= 0 {
		deadline = time.Now().Add(timeout)
	}
	for {
		if a.aborted.Load() {
			return nil, io.ErrClosedPipe
		}
		mb, err, ok, blocked := a.fromHistory()
		if ok {
			return mb, err
		}
		if w := c.winner.Load(); w != nil {
			if w == a {
				return a.read(remaining(deadline, timeout))
			}
			return nil, io.ErrClosedPipe
		}
		wait := pollInterval
		if timeout >= 0 {
			left := time.Until(deadline)
			if left <= 0 {
				return nil, buf.ErrReadTimeout
			}
			if left < wait {
				wait = left
			}
		}
		if !blocked && a.mayConsume() {
			c.pull(a, wait)
		} else {
			time.Sleep(wait)
		}
	}
}

func remaining(deadline time.Time, timeout time.Duration) time.Duration {
	if timeout < 0 {
		return -1
	}
	left := time.Until(deadline)
	if left < 0 {
		return 0
	}
	return left
}

// fromHistory hands over client data a has not seen, as a copy: the history must stay intact for a
// replay. blocked means data exists but belongs to another attempt.
func (a *attempt) fromHistory() (mb buf.MultiBuffer, err error, ok bool, blocked bool) {
	c := a.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if a.pos < len(c.history) {
		if !c.kind.replaySafe() && c.owner != nil && c.owner != a {
			return nil, nil, false, true
		}
		if !c.kind.replaySafe() {
			c.owner = a
		}
		mb = copyMulti(c.history[a.pos:])
		a.pos = len(c.history)
		a.consumed.Store(true)
		return mb, nil, true, false
	}
	if c.srcErr != nil {
		return nil, c.srcErr, true, false
	}
	return nil, nil, false, false
}

// mayConsume reports whether a may read new client data: always, unless another attempt already
// holds data that must not be sent twice.
func (a *attempt) mayConsume() bool {
	c := a.c
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.owner == nil || c.owner == a || c.kind.replaySafe()
}

// drain is the winner's switch to reading the client directly: it waits out a read another
// attempt may still have in flight, takes whatever it has not been handed yet, and frees the rest.
func (a *attempt) drain() buf.MultiBuffer {
	c := a.c
	c.readMu.Lock()
	c.mu.Lock()
	if c.released {
		// forward already returned (the client went away while this attempt was winning) and
		// freed the history; there is nothing left to hand over.
		a.drained = true
		c.mu.Unlock()
		c.readMu.Unlock()
		return nil
	}
	var mb buf.MultiBuffer
	if a.pos < len(c.history) {
		mb = append(mb, c.history[a.pos:]...)
	}
	buf.ReleaseMulti(c.history[:a.pos])
	c.history = nil
	c.historyBytes = 0
	a.pos = 0
	a.drained = true
	if !mb.IsEmpty() {
		a.consumed.Store(true)
	}
	c.mu.Unlock()
	c.readMu.Unlock()
	return mb
}

func copyMulti(src buf.MultiBuffer) buf.MultiBuffer {
	out := make(buf.MultiBuffer, 0, len(src))
	for _, b := range src {
		nb := buf.New()
		if b.Len() > nb.Cap() {
			nb.Release()
			nb = buf.NewWithSize(b.Len())
		}
		nb.Write(b.Bytes())
		if b.UDP != nil {
			dest := *b.UDP
			nb.UDP = &dest
		}
		out = append(out, nb)
	}
	return out
}

type attemptWriter struct{ a *attempt }

func (w *attemptWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	a := w.a
	c := a.c
	if c.winner.Load() == a {
		a.lastDown.Store(time.Now().UnixNano())
		return c.dst.WriteMultiBuffer(mb)
	}
	if mb.IsEmpty() {
		return nil
	}
	if !c.commit(a) {
		buf.ReleaseMulti(mb)
		a.lateOnce.Do(func() { close(a.late) })
		return io.ErrClosedPipe
	}
	a.lastDown.Store(time.Now().UnixNano())
	return c.dst.WriteMultiBuffer(mb)
}

// Close and Interrupt reach the client only from the winner; a losing attempt ending is not the
// client's business.
func (w *attemptWriter) Close() error {
	if w.a.c.winner.Load() == w.a {
		return common.Close(w.a.c.dst)
	}
	return nil
}

func (w *attemptWriter) Interrupt() {
	if w.a.c.winner.Load() == w.a {
		common.Interrupt(w.a.c.dst)
	}
}

// interrupt cuts a won connection whose member was found dead.
func (a *attempt) interrupt() {
	a.cancel()
	common.Interrupt(a.c.dst)
	common.Interrupt(a.c.src)
}

// observedWriter reports the first response byte of a connection that cannot be retried.
type observedWriter struct {
	buf.Writer
	onFirst func()
	wrote   atomic.Bool
}

func (w *observedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if !mb.IsEmpty() && w.wrote.CompareAndSwap(false, true) {
		w.onFirst()
	}
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *observedWriter) Close() error { return common.Close(w.Writer) }

func (w *observedWriter) Interrupt() { common.Interrupt(w.Writer) }

func failureKind(a *attempt) outcome {
	if !a.consumed.Load() || isDialFailure(a.err) {
		return outcomeDialFailure
	}
	return outcomeFailure
}

// isDialFailure recognises the error every proxy in this core returns when it could not reach its
// own server — before any client data was sent anywhere.
func isDialFailure(err error) bool {
	return err != nil && strings.Contains(err.Error(), "failed to find an available destination")
}

func isBenign(err error) bool {
	cause := errors.Cause(err)
	return goerrors.Is(cause, io.EOF) || goerrors.Is(cause, io.ErrClosedPipe) || goerrors.Is(cause, context.Canceled)
}
