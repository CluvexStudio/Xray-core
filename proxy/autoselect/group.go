package autoselect

import (
	"context"
	"math"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// Why the selection changed. Surfaced to the app, so these are part of the status format.
const (
	reasonStartup   = "startup"
	reasonFailover  = "failover"
	reasonFaster    = "faster"
	reasonPinned    = "pinned"
	reasonRecovered = "recovered"
)

// Group is the autoselect outbound.
type Group struct {
	cfg        settings
	ctx        context.Context
	cancel     context.CancelFunc
	tag        string
	ohm        outbound.Manager
	dispatcher routing.Dispatcher
	stats      stats.Manager
	now        func() time.Time

	mu                sync.Mutex
	members           []*member
	byTag             map[string]*member
	membersResolvedAt time.Time
	selected          *member
	pinned            string
	graceStart        time.Time
	lastSwitch        time.Time
	switches          int
	events            []SwitchEvent
	hedgeTokens       float64
	hedgeRefill       time.Time

	lastTraffic atomic.Int64 // unix nanos of the last connection
	idle        atomic.Bool

	wake     chan struct{}
	sem      chan struct{}
	startOne sync.Once
}

// New creates the group. Probing starts together with the Xray instance.
func New(ctx context.Context, config *Config) (*Group, error) {
	g := &Group{
		cfg:   newSettings(config),
		now:   time.Now,
		byTag: make(map[string]*member),
		wake:  make(chan struct{}, 1),
	}
	g.sem = make(chan struct{}, g.cfg.concurrency)
	if h := session.FullHandlerFromContext(ctx); h != nil {
		g.tag = h.Tag()
	}
	if err := core.RequireFeatures(ctx, func(om outbound.Manager, d routing.Dispatcher) error {
		g.ohm = om
		g.dispatcher = d
		return nil
	}); err != nil {
		return nil, errors.New("autoselect: missing features").Base(err)
	}
	core.OptionalFeatures(ctx, func(sm stats.Manager) {
		g.stats = sm
	})
	g.ctx, g.cancel = context.WithCancel(ctx)
	now := g.now()
	g.graceStart = now
	g.hedgeTokens = hedgeBurst
	g.hedgeRefill = now
	g.lastTraffic.Store(now.UnixNano())
	// The members are other outbounds of the same instance, and probing them means dispatching
	// through it, so nothing may run before the instance has started. A feature is the one hook
	// the instance offers for that; it is also closed together with the instance.
	if err := core.MustFromContext(ctx).AddFeature(&starter{g: g}); err != nil {
		return nil, err
	}
	return g, nil
}

// starter ties the group's background work to the instance lifecycle.
type starter struct{ g *Group }

func (s *starter) Type() interface{} { return (*starter)(nil) }

func (s *starter) Start() error {
	s.g.start()
	return nil
}

func (s *starter) Close() error { return s.g.Close() }

func (g *Group) start() {
	g.startOne.Do(func() {
		register(g)
		go g.monitor()
	})
}

// Close stops probing and forgets the group.
func (g *Group) Close() error {
	unregister(g)
	if g.cancel != nil {
		g.cancel()
	}
	return nil
}

// Process implements proxy.Outbound.
func (g *Group) Process(ctx context.Context, link *transport.Link, _ internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified").AtError()
	}
	ob.Name = "autoselect"
	g.noteTraffic()
	plan := g.plan()
	if len(plan) == 0 {
		return errors.New("autoselect: no member outbound is configured").AtWarning()
	}
	return g.forward(ctx, link, ob, plan)
}

// noteTraffic marks the group busy. Leaving idle restarts the probes of the members that matter
// right now, so a network that changed while nobody was using it is re-measured immediately.
func (g *Group) noteTraffic() {
	now := g.now()
	g.lastTraffic.Store(now.UnixNano())
	if !g.idle.Load() {
		return
	}
	g.mu.Lock()
	if g.idle.CompareAndSwap(true, false) {
		for _, m := range g.members {
			if m == g.selected || g.isStandbyLocked(m, now) || m.state == stateUnknown {
				m.nextProbeAt = now
			}
		}
	}
	g.mu.Unlock()
	g.poke()
}

func (g *Group) poke() {
	select {
	case g.wake <- struct{}{}:
	default:
	}
}

// plan returns the members to try for one connection, best first.
func (g *Group) plan() []step {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	g.refreshMembersLocked(now)
	if len(g.members) == 0 {
		return nil
	}
	sel := g.selectLocked(now)
	out := make([]step, 0, g.cfg.maxAttempts)
	add := func(m *member) {
		lp, _ := m.handler.(linkProcessor)
		out = append(out, step{m: m, lp: lp})
	}
	add(sel)
	for _, m := range g.alternativesLocked(now, sel) {
		if len(out) >= g.cfg.maxAttempts {
			break
		}
		add(m)
	}
	return out
}

// refreshMembersLocked keeps the member list in step with the outbound manager. Handlers can be
// added after the group is created (it is usually the first outbound) or replaced through the API.
func (g *Group) refreshMembersLocked(now time.Time) {
	if len(g.members) > 0 && now.Sub(g.membersResolvedAt) < membersRefreshEvery {
		return
	}
	if g.ohm == nil {
		return
	}
	g.membersResolvedAt = now
	var tags []string
	seen := make(map[string]bool)
	add := func(tag string) {
		if tag == "" || tag == g.tag || seen[tag] {
			return
		}
		seen[tag] = true
		tags = append(tags, tag)
	}
	for _, t := range g.cfg.outbounds {
		add(t)
	}
	if len(g.cfg.selectors) > 0 {
		if hs, ok := g.ohm.(outbound.HandlerSelector); ok {
			for _, t := range hs.Select(g.cfg.selectors) {
				add(t)
			}
		}
	}
	members := make([]*member, 0, len(tags))
	byTag := make(map[string]*member, len(tags))
	for i, t := range tags {
		m := g.byTag[t]
		if m == nil {
			m = newMember(t, i)
		}
		m.order = i
		m.handler = g.ohm.GetHandler(t)
		members = append(members, m)
		byTag[t] = m
	}
	if g.selected != nil && byTag[g.selected.tag] == nil {
		g.selected = nil
	}
	g.members = members
	g.byTag = byTag
}

func (g *Group) inGraceLocked(now time.Time) bool {
	return now.Sub(g.graceStart) < startupGrace
}

// selectLocked applies the selection policy and returns the member new connections go to.
func (g *Group) selectLocked(now time.Time) *member {
	if len(g.members) == 0 {
		return nil
	}
	if g.pinned != "" {
		if m := g.byTag[g.pinned]; m != nil {
			g.setSelectedLocked(m, reasonPinned, now)
			return m
		}
	}
	cur := g.selected
	best := g.bestAliveLocked(now)
	switch {
	case cur == nil:
		pick := g.byTag[g.cfg.initial]
		if pick != nil && pick.state == stateDead {
			pick = nil
		}
		if pick == nil {
			pick = best
		}
		if pick == nil {
			pick = g.firstUsableLocked(nil)
		}
		g.setSelectedLocked(pick, reasonStartup, now)
	case cur.state == stateDead || cur.state == stateSuspect:
		if best != nil && best != cur {
			g.setSelectedLocked(best, reasonFailover, now)
		} else if cur.state == stateDead {
			// Nothing measured alive: move to a member not known dead, if there is one. When
			// every member is dead the selection stays put rather than rotating among them.
			if alt := g.firstUsableLocked(cur); alt != nil && alt.state != stateDead {
				g.setSelectedLocked(alt, reasonFailover, now)
			}
		}
	case best != nil && best != cur && g.shouldPreferLocked(cur, best, now):
		reason := reasonFaster
		if _, ok := cur.score(now); !ok {
			reason = reasonStartup
		} else if cur.failStreak > 0 {
			// Its failures are what cost it the lead, so that is the reason worth telling.
			reason = reasonFailover
		}
		g.setSelectedLocked(best, reason, now)
	}
	return g.selected
}

// shouldPreferLocked is the hysteresis: a working selection is only replaced by a member that is
// faster by a real margin, and not more often than min_dwell — otherwise two similar servers would
// trade places on every probe and the exit address would keep changing under the user.
func (g *Group) shouldPreferLocked(cur, best *member, now time.Time) bool {
	bestScore, ok := best.score(now)
	if !ok {
		return false
	}
	grace := g.inGraceLocked(now)
	curScore, curRanked := cur.score(now)
	if !curRanked {
		// The current pick was a guess that has not been measured yet. Give its own first probe
		// the chance to answer before trading it for whoever answered first.
		if cur.probing && now.Sub(cur.probeStarted) < g.cfg.probeTimeout {
			return false
		}
		return true
	}
	if len(best.delays) < 2 && !grace {
		return false
	}
	if bestScore > curScore*(1-g.cfg.switchRatio) {
		return false
	}
	if curScore-bestScore < float64(g.cfg.switchMinGain)/float64(time.Millisecond) {
		return false
	}
	if !grace && now.Sub(g.lastSwitch) < g.cfg.minDwell {
		return false
	}
	return true
}

func (g *Group) bestAliveLocked(now time.Time) *member {
	var best *member
	bestScore := math.Inf(1)
	for _, m := range g.members {
		if m.state != stateAlive {
			continue
		}
		s, ok := m.score(now)
		if !ok {
			continue
		}
		if s < bestScore || (s == bestScore && best != nil && m.order < best.order) {
			best, bestScore = m, s
		}
	}
	return best
}

// firstUsableLocked picks a member when nothing has been measured alive: the first one that is not
// known dead, else the dead one that worked most recently.
func (g *Group) firstUsableLocked(except *member) *member {
	for _, m := range g.members {
		if m != except && m.state != stateDead {
			return m
		}
	}
	var pick *member
	for _, m := range g.members {
		if m == except {
			continue
		}
		if pick == nil || m.lastSuccessAt.After(pick.lastSuccessAt) {
			pick = m
		}
	}
	return pick
}

// alternativesLocked orders the members a failing connection falls back to: measured alive ones by
// score, then never measured ones in configured order, then suspects. Dead members are only
// offered when nothing else is left.
func (g *Group) alternativesLocked(now time.Time, sel *member) []*member {
	type ranked struct {
		m     *member
		tier  int
		score float64
	}
	var list []ranked
	for _, m := range g.members {
		if m == sel {
			continue
		}
		s, ok := m.score(now)
		switch {
		case m.state == stateAlive && ok:
			list = append(list, ranked{m, 0, s})
		case m.state == stateAlive || m.state == stateUnknown:
			list = append(list, ranked{m, 1, float64(m.order)})
		case m.state == stateSuspect:
			list = append(list, ranked{m, 2, s})
		}
	}
	if len(list) == 0 {
		for _, m := range g.members {
			if m != sel {
				list = append(list, ranked{m, 3, -float64(m.lastSuccessAt.UnixNano())})
			}
		}
	}
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].tier != list[j].tier {
			return list[i].tier < list[j].tier
		}
		return list[i].score < list[j].score
	})
	out := make([]*member, len(list))
	for i, r := range list {
		out[i] = r.m
	}
	return out
}

func (g *Group) isStandbyLocked(m *member, now time.Time) bool {
	if m == g.selected || m.state == stateDead {
		return false
	}
	for i, alt := range g.alternativesLocked(now, g.selected) {
		if i >= g.cfg.standbyCount {
			break
		}
		if alt == m {
			return true
		}
	}
	return false
}

func (g *Group) setSelectedLocked(m *member, reason string, now time.Time) {
	if m == nil || m == g.selected {
		return
	}
	from := ""
	if g.selected != nil {
		from = g.selected.tag
	}
	if reason == reasonFailover && from == "" {
		reason = reasonStartup
	}
	g.selected = m
	g.lastSwitch = now
	g.switches++
	g.events = append(g.events, SwitchEvent{From: from, To: m.tag, Reason: reason, AtMs: now.UnixMilli()})
	if len(g.events) > eventsKept {
		g.events = g.events[len(g.events)-eventsKept:]
	}
	errors.LogInfo(g.ctx, "autoselect[", g.tag, "]: ", reason, " -> ", m.tag, " (was ", from, ")")
	// A change of selection changes who counts as standby, so bring the new neighbours forward.
	m.nextProbeAt = minTime(m.nextProbeAt, now.Add(g.cfg.activeInterval))
}

// recordOutcome feeds what a real connection taught about a member back into the selection.
func (g *Group) recordOutcome(m *member, o outcome, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	switch o {
	case outcomeSuccess:
		m.pushOutcome(now, 0)
		m.lastSuccessAt, m.lastPassiveOK = now, now
		m.failStreak = 0
		if m.state != stateAlive {
			// Real traffic just went through, which outranks any probe verdict. It carries no
			// delay sample, though, so measure it again soon.
			wasDown := m.state == stateDead
			m.state = stateAlive
			m.probeFailStreak = 0
			m.nextProbeAt = now
			if wasDown && g.selected != nil && g.selected.state == stateDead {
				g.setSelectedLocked(m, reasonRecovered, now)
			}
			g.poke()
		}
		return
	case outcomeSlow:
		m.pushOutcome(now, 0.5)
		g.selectLocked(now)
		return
	}
	m.pushOutcome(now, 1)
	m.failStreak++
	if err != nil {
		m.lastError = shortError(err)
	}
	recent := m.noteHardFailure(now)
	switch m.state {
	case stateAlive, stateUnknown:
		if recent >= 2 {
			m.state = stateSuspect
			m.nextProbeAt = now
		} else if now.Before(m.nextProbeAt) {
			// One failure is not a verdict, but it is a reason not to wait for the schedule.
			m.nextProbeAt = now
		}
		g.poke()
	case stateSuspect:
		if recent >= 3 {
			g.markDeadLocked(m, now)
		}
	}
	g.selectLocked(now)
}

// recordProbe folds one probe result into the member.
func (g *Group) recordProbe(m *member, d time.Duration, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	m.probing = false
	m.lastProbeAt = now
	if err == nil {
		m.addDelay(d)
		m.lastProbeOKAt, m.lastSuccessAt = now, now
		m.failStreak, m.probeFailStreak = 0, 0
		m.recentFailures = m.recentFailures[:0]
		m.lastError = ""
		wasDown := m.state == stateDead
		m.state = stateAlive
		if wasDown && g.selected != nil && g.selected.state == stateDead {
			g.setSelectedLocked(m, reasonRecovered, now)
		}
	} else {
		m.probeFailStreak++
		m.failStreak++
		m.lastError = shortError(err)
		switch m.state {
		case stateAlive:
			m.state = stateSuspect
		case stateSuspect, stateUnknown:
			// Real traffic that went through moments ago says the probe host is the problem, not
			// the member, so stop short of declaring it dead.
			if !m.lastPassiveOK.IsZero() && now.Sub(m.lastPassiveOK) < g.cfg.activeInterval {
				m.state = stateSuspect
			} else {
				g.markDeadLocked(m, now)
			}
		}
	}
	m.nextProbeAt = g.nextProbeLocked(m, now)
	g.selectLocked(now)
}

func (g *Group) markDeadLocked(m *member, now time.Time) {
	if m.state == stateDead {
		return
	}
	if !m.lastBytesAt.IsZero() && now.Sub(m.lastBytesAt) < stalledAfter {
		// Data is still arriving through it, so whatever just failed, the member is not dead.
		m.state = stateSuspect
		return
	}
	m.state = stateDead
	if !g.cfg.interruptStalled {
		return
	}
	// The member has delivered nothing for stalledAfter, so every connection still open on it is
	// hanging — spliced ones included, since their bytes would have shown in the counter. Cut
	// them, so their applications reconnect through the new selection instead of waiting for a
	// timeout. Connections that did receive something recently are left alone.
	for a := range m.active {
		if now.Sub(time.Unix(0, a.lastDown.Load())) >= stalledAfter {
			a.interrupt()
		}
	}
}

// sampleCountersLocked notes when bytes last arrived through each member. The app reads and
// resets the counters, so any non-zero value that differs from the last sample is new traffic.
func (g *Group) sampleCountersLocked(now time.Time) {
	if g.stats == nil {
		return
	}
	for _, m := range g.members {
		if m.downCounter == nil {
			m.downCounter = g.stats.GetCounter("outbound>>>" + m.tag + ">>>traffic>>>downlink")
			if m.downCounter == nil {
				continue
			}
		}
		if v := m.downCounter.Value(); v != m.counterValue {
			if v > 0 {
				m.lastBytesAt = now
			}
			m.counterValue = v
		}
	}
}

func (g *Group) nextProbeLocked(m *member, now time.Time) time.Time {
	switch {
	case m.state == stateUnknown:
		return now
	case m.state == stateSuspect:
		return now.Add(suspectRecheck)
	case m.state == stateDead:
		table := deadBackoff
		if g.allDownLocked() {
			table = allDownBackoff
		}
		i := m.probeFailStreak - 1
		if i < 0 {
			i = 0
		}
		if i >= len(table) {
			i = len(table) - 1
		}
		return now.Add(jittered(table[i]))
	case m == g.selected:
		return now.Add(g.cfg.activeInterval)
	case g.isStandbyLocked(m, now):
		return now.Add(jittered(g.cfg.standbyInterval))
	default:
		return now.Add(jittered(g.cfg.sweepInterval))
	}
}

func (g *Group) allDownLocked() bool {
	for _, m := range g.members {
		if m.state == stateAlive || m.state == stateSuspect {
			return false
		}
	}
	return true
}

// timings returns how long an attempt on m may go without a response before it is abandoned, and
// after how long a second attempt is raced against it.
func (g *Group) timings(m *member) (budget, hedge time.Duration) {
	g.mu.Lock()
	d := m.typicalDelay()
	g.mu.Unlock()
	budget = g.cfg.attemptBudget
	if budget <= 0 {
		budget = defaultAttemptBudget
		if d > 0 {
			budget = clampDuration(time.Duration(float64(d)*2.5)+time.Second, minAttemptBudget, maxAttemptBudget)
		}
	}
	hedge = defaultHedgeDelay
	if d > 0 {
		hedge = clampDuration(d+300*time.Millisecond, minHedgeDelay, maxHedgeDelay)
	}
	if hedge >= budget {
		hedge = budget / 2
	}
	return budget, hedge
}

// canHedgeTo reports whether a racing attempt may be started on m, spending one hedge token. Races
// are only run against members measured alive, and at a bounded rate, so a slow network does not
// turn every connection into two.
func (g *Group) canHedgeTo(m *member) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if m.state != stateAlive {
		return false
	}
	now := g.now()
	g.hedgeTokens = math.Min(hedgeBurst, g.hedgeTokens+now.Sub(g.hedgeRefill).Seconds()*hedgeRate)
	g.hedgeRefill = now
	if g.hedgeTokens < 1 {
		return false
	}
	g.hedgeTokens--
	return true
}

func (g *Group) track(a *attempt) {
	g.mu.Lock()
	a.m.active[a] = struct{}{}
	g.mu.Unlock()
}

func (g *Group) untrack(a *attempt) {
	g.mu.Lock()
	delete(a.m.active, a)
	g.mu.Unlock()
}

// Kick tells the group the network changed: every member is re-measured now, dead ones included,
// and the next pick may be made on fresh data without waiting out min_dwell.
func (g *Group) Kick() {
	g.mu.Lock()
	now := g.now()
	g.graceStart = now
	for _, m := range g.members {
		m.nextProbeAt = now
		if m.state == stateDead {
			m.probeFailStreak = 0
		}
	}
	g.lastTraffic.Store(now.UnixNano())
	g.idle.Store(false)
	g.mu.Unlock()
	g.poke()
}

// Pin forces every new connection onto one member; an empty tag returns to automatic selection.
func (g *Group) Pin(tag string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if tag != "" && g.byTag[tag] == nil {
		return false
	}
	g.pinned = tag
	g.selectLocked(g.now())
	return true
}

// shortError reduces an Xray error chain to the part that names the cause. Errors nest every layer
// ("failed to process outbound traffic > … > dial tcp …: connection refused"), so the innermost
// segment is usually it — except for wrappers like the retry helper's sentinel, which are skipped.
func shortError(err error) string {
	parts := strings.Split(err.Error(), " > ")
	s := parts[len(parts)-1]
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.TrimSpace(parts[i])
		if p == "" || strings.HasSuffix(p, "all retry attempts failed") {
			continue
		}
		s = p
		break
	}
	// Drop the package prefix ("common/retry: ") and the brackets the retry helper puts around
	// the errors it collected.
	if i := strings.Index(s, ": "); i > 0 && strings.Contains(s[:i], "/") && !strings.Contains(s[:i], " ") {
		s = s[i+2:]
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func jittered(d time.Duration) time.Duration {
	return d + time.Duration((rand.Float64()*0.2-0.1)*float64(d))
}

func clampDuration(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}

func minTime(a, b time.Time) time.Time {
	if a.IsZero() || b.Before(a) {
		return b
	}
	return a
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
