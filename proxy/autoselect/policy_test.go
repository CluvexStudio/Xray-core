package autoselect

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time           { return c.t }
func (c *fakeClock) advance(d time.Duration)  { c.t = c.t.Add(d) }
func ms(v int) time.Duration                  { return time.Duration(v) * time.Millisecond }
func probeOK(g *Group, tag string, delay int) { g.recordProbe(g.byTag[tag], ms(delay), nil) }
func probeFail(g *Group, tag string) {
	g.recordProbe(g.byTag[tag], 0, errors.New("dial tcp: i/o timeout"))
}
func (g *Group) selectedTag() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.selected == nil {
		return ""
	}
	return g.selected.tag
}

func newPolicyGroup(t *testing.T, cfg *Config, tags ...string) (*Group, *fakeClock) {
	t.Helper()
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	g := &Group{
		cfg:   newSettings(cfg),
		ctx:   context.Background(),
		now:   clock.now,
		byTag: make(map[string]*member),
		wake:  make(chan struct{}, 1),
		tag:   "auto",
	}
	for i, tag := range tags {
		m := newMember(tag, i)
		g.members = append(g.members, m)
		g.byTag[tag] = m
	}
	g.membersResolvedAt = clock.t
	g.graceStart = clock.t
	g.hedgeTokens = hedgeBurst
	g.hedgeRefill = clock.t
	return g, clock
}

func (g *Group) pick() string {
	plan := g.plan()
	if len(plan) == 0 {
		return ""
	}
	return plan[0].m.tag
}

func TestStartsOnInitialAndWaitsForItsOwnProbe(t *testing.T) {
	g, clock := newPolicyGroup(t, &Config{Initial: "b"}, "a", "b")
	if got := g.pick(); got != "b" {
		t.Fatalf("first pick = %q, want the initial hint b", got)
	}
	// Both are being probed; a answers first.
	g.byTag["b"].probing = true
	g.byTag["b"].probeStarted = clock.t
	clock.advance(ms(100))
	probeOK(g, "a", 100)
	if got := g.selectedTag(); got != "b" {
		t.Fatalf("switched to %q before the initial member's own probe answered", got)
	}
	clock.advance(ms(200))
	probeOK(g, "b", 300)
	if got := g.selectedTag(); got != "a" {
		t.Fatalf("selected %q, want a: 100ms beats 300ms by a wide margin", got)
	}
}

func TestHysteresisKeepsAWorkingSelection(t *testing.T) {
	g, clock := newPolicyGroup(t, &Config{Initial: "a"}, "a", "b")
	for i := 0; i < 3; i++ {
		probeOK(g, "a", 100)
		probeOK(g, "b", 85)
	}
	g.pick()
	clock.advance(time.Hour) // past grace and min_dwell
	probeOK(g, "a", 100)
	probeOK(g, "b", 85)
	if got := g.selectedTag(); got != "a" {
		t.Fatalf("switched to %q for a 15%% gain", got)
	}

	// 60ms is 40% faster but only 40ms better: under the absolute margin.
	for i := 0; i < delaySamples; i++ {
		probeOK(g, "b", 60)
	}
	if got := g.selectedTag(); got != "a" {
		t.Fatalf("switched to %q for a 40ms gain", got)
	}

	for i := 0; i < delaySamples; i++ {
		probeOK(g, "b", 20)
	}
	if got := g.selectedTag(); got != "b" {
		t.Fatalf("selected %q, want b once it is clearly faster", got)
	}

	// A 10ms gain never justifies moving back, however long we wait.
	for i := 0; i < delaySamples; i++ {
		probeOK(g, "a", 10)
	}
	clock.advance(2 * time.Minute)
	probeOK(g, "a", 10)
	if got := g.selectedTag(); got != "b" {
		t.Fatalf("selected %q for a 10ms gain", got)
	}

	// A big gain does — but not within min_dwell of the previous switch.
	g.mu.Lock()
	g.lastSwitch = clock.t
	g.mu.Unlock()
	for i := 0; i < delaySamples; i++ {
		probeOK(g, "b", 200)
	}
	probeOK(g, "a", 10)
	if got := g.selectedTag(); got != "b" {
		t.Fatalf("selected %q right after a switch; min_dwell should hold", got)
	}
	clock.advance(2 * time.Minute)
	probeOK(g, "a", 10)
	probeOK(g, "b", 200)
	if got := g.selectedTag(); got != "a" {
		t.Fatalf("selected %q, want a once min_dwell has passed", got)
	}
}

func TestTwoFailedConnectionsFailOverImmediately(t *testing.T) {
	g, clock := newPolicyGroup(t, &Config{Initial: "a"}, "a", "b")
	probeOK(g, "a", 50)
	probeOK(g, "b", 80)
	clock.advance(time.Hour)
	if got := g.pick(); got != "a" {
		t.Fatalf("pick = %q, want a", got)
	}
	a := g.byTag["a"]
	g.recordOutcome(a, outcomeStall, errNoResponse)
	if got := g.selectedTag(); got != "a" {
		t.Fatalf("one failure moved the selection to %q", got)
	}
	if a.nextProbeAt.After(clock.t) {
		t.Fatalf("one failure should make a's probe due now, not at %v", a.nextProbeAt)
	}
	clock.advance(ms(300))
	g.recordOutcome(a, outcomeDialFailure, errors.New("failed to find an available destination"))
	if a.state != stateSuspect {
		t.Fatalf("a is %v after two failures, want suspect", a.state)
	}
	if got := g.selectedTag(); got != "b" {
		t.Fatalf("selected %q after two failures, want failover to b", got)
	}
	g.mu.Lock()
	last := g.events[len(g.events)-1]
	g.mu.Unlock()
	if last.Reason != reasonFailover || last.From != "a" || last.To != "b" {
		t.Fatalf("last event = %+v, want failover a -> b", last)
	}
}

func TestProbeVerdicts(t *testing.T) {
	g, clock := newPolicyGroup(t, &Config{}, "a", "b")
	probeOK(g, "a", 50)
	probeOK(g, "b", 60)
	a := g.byTag["a"]

	probeFail(g, "a")
	if a.state != stateSuspect {
		t.Fatalf("one failed probe left a %v, want suspect", a.state)
	}
	if !a.nextProbeAt.Equal(clock.t.Add(suspectRecheck)) {
		t.Fatalf("suspect a is not re-probed quickly")
	}
	probeFail(g, "a")
	if a.state != stateDead {
		t.Fatalf("two failed probes left a %v, want dead", a.state)
	}

	// Bytes still arriving through b make a failed probe mean "probe host blocked", not dead.
	b := g.byTag["b"]
	b.lastBytesAt = clock.t
	probeFail(g, "b")
	probeFail(g, "b")
	if b.state != stateSuspect {
		t.Fatalf("b is %v while its traffic flows, want suspect", b.state)
	}
}

func TestRealTrafficRevivesAndRecovers(t *testing.T) {
	g, clock := newPolicyGroup(t, &Config{Initial: "a"}, "a", "b")
	g.pick()
	probeFail(g, "a")
	probeFail(g, "b")
	if !g.allDownLocked() {
		t.Fatalf("expected every member down")
	}
	switches := g.switches
	for i := 0; i < 5; i++ {
		clock.advance(ms(100))
		g.pick()
	}
	if g.switches != switches {
		t.Fatalf("selection rotated among dead members: %d switches", g.switches-switches)
	}
	g.recordOutcome(g.byTag["b"], outcomeSuccess, nil)
	if got := g.selectedTag(); got != "b" {
		t.Fatalf("selected %q, want b the moment its traffic went through", got)
	}
	if g.byTag["b"].state != stateAlive {
		t.Fatalf("b not alive after carrying traffic")
	}
}

func TestPinOverridesAndReleases(t *testing.T) {
	g, _ := newPolicyGroup(t, &Config{}, "a", "b", "c")
	probeOK(g, "a", 10)
	probeOK(g, "b", 200)
	probeOK(g, "c", 300)
	g.pick()
	if !g.Pin("c") {
		t.Fatalf("pin rejected")
	}
	if got := g.pick(); got != "c" {
		t.Fatalf("pick = %q while pinned to c", got)
	}
	if g.Pin("nope") {
		t.Fatalf("pinning an unknown member must fail")
	}
	g.Pin("")
	if got := g.pick(); got != "a" {
		t.Fatalf("pick = %q after unpinning, want the best member a", got)
	}
}

func TestPlanOrdersAlternatives(t *testing.T) {
	g, clock := newPolicyGroup(t, &Config{Initial: "a", MaxAttempts: 4}, "a", "b", "c", "d", "e")
	probeOK(g, "a", 50)
	probeOK(g, "b", 400)
	probeOK(g, "c", 100)
	probeFail(g, "d") // unknown -> dead
	clock.advance(time.Second)
	plan := g.plan()
	var got []string
	for _, st := range plan {
		got = append(got, st.m.tag)
	}
	want := []string{"a", "c", "b", "e"} // selected, alive by score, then never measured; dead d left out
	if len(got) != len(want) {
		t.Fatalf("plan = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("plan = %v, want %v", got, want)
		}
	}
}

func TestTimingsFollowMeasuredDelay(t *testing.T) {
	g, _ := newPolicyGroup(t, &Config{}, "a", "b", "c")
	budget, hedge := g.timings(g.byTag["a"])
	if budget != defaultAttemptBudget || hedge != defaultHedgeDelay {
		t.Fatalf("unmeasured timings = %v/%v", budget, hedge)
	}
	probeOK(g, "b", 400)
	budget, hedge = g.timings(g.byTag["b"])
	if budget != minAttemptBudget || hedge != minHedgeDelay {
		t.Fatalf("400ms member timings = %v/%v, want %v/%v", budget, hedge, minAttemptBudget, minHedgeDelay)
	}
	probeOK(g, "c", 2000)
	budget, hedge = g.timings(g.byTag["c"])
	if budget != 6*time.Second || hedge != 2300*time.Millisecond {
		t.Fatalf("2s member timings = %v/%v", budget, hedge)
	}
}

func TestClassifyPayload(t *testing.T) {
	tcp443 := net.TCPDestination(net.LocalHostIP, 443)
	udp443 := net.UDPDestination(net.LocalHostIP, 443)
	cases := []struct {
		name string
		dest net.Destination
		head []byte
		want payloadKind
	}{
		{"tls client hello", tcp443, []byte{0x16, 0x03, 0x01, 0x01, 0x2c, 0x01}, payloadTLSHello},
		{"tls but not a hello", tcp443, []byte{0x16, 0x03, 0x01, 0x00, 0x10, 0x02}, payloadOpaque},
		{"plain http", net.TCPDestination(net.LocalHostIP, 80), []byte("GET / "), payloadOpaque},
		{"dns over tcp", net.TCPDestination(net.LocalHostIP, 53), []byte{0, 1}, payloadDNS},
		{"dns over udp", net.UDPDestination(net.LocalHostIP, 53), []byte{0xab}, payloadDNS},
		{"quic initial", udp443, []byte{0xc3, 0, 0, 0, 1}, payloadQUIC},
		{"udp short header", udp443, []byte{0x43, 1, 2, 3, 4}, payloadOpaque},
	}
	for _, c := range cases {
		if got := classifyPayload(c.dest, c.head); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFailRatioNeedsEvidence(t *testing.T) {
	m := newMember("a", 0)
	now := time.Now()
	m.pushOutcome(now, 1)
	if r := m.failRatio(now); r != 0.25 {
		t.Fatalf("one failure alone rates %v, want 0.25", r)
	}
	for i := 0; i < 7; i++ {
		m.pushOutcome(now, 0)
	}
	if r := m.failRatio(now); r != 0.125 {
		t.Fatalf("ratio = %v, want 0.125", r)
	}
	if r := m.failRatio(now.Add(outcomeLifetime + time.Second)); r != 0 {
		t.Fatalf("expired outcomes still count: %v", r)
	}
}
