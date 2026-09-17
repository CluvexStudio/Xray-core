package autoselect

import (
	"math"
	"sort"
	"time"

	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/stats"
)

type memberState uint8

const (
	// Never measured and never carried traffic.
	stateUnknown memberState = iota
	stateAlive
	// Recent failures; still usable, but anything alive is preferred and a confirming probe is due.
	stateSuspect
	stateDead
)

func (s memberState) String() string {
	switch s {
	case stateAlive:
		return "alive"
	case stateSuspect:
		return "suspect"
	case stateDead:
		return "dead"
	default:
		return "unknown"
	}
}

// outcome is what one real connection attempt taught us about a member.
type outcome uint8

const (
	outcomeSuccess outcome = iota
	// The member never took the connection: it could not reach its server at all.
	outcomeDialFailure
	// The member took the connection but produced no response within its budget.
	outcomeStall
	// The member failed after taking the connection.
	outcomeFailure
	// The member did respond, only later than another member racing it. A soft signal: it lowers
	// the member's standing without making it suspect.
	outcomeSlow
)

func (o outcome) hard() bool {
	return o == outcomeDialFailure || o == outcomeStall || o == outcomeFailure
}

type outcomeRecord struct {
	at     time.Time
	weight float64 // 0 success, 1 hard failure, 0.5 slow
}

// member is one outbound of the group together with everything learned about it. All fields are
// guarded by Group.mu.
type member struct {
	tag     string
	order   int
	handler outbound.Handler

	state memberState

	delays        []time.Duration // recent successful probe delays, oldest first
	lastDelay     time.Duration
	lastProbeAt   time.Time
	lastProbeOKAt time.Time
	probeStarted  time.Time
	probing       bool
	nextProbeAt   time.Time

	lastSuccessAt time.Time // probe or real traffic
	lastPassiveOK time.Time // real traffic only

	// The member's downlink traffic counter. Bytes arriving through a member are the most direct
	// proof it works — including on spliced connections, which bypass the group's own writers.
	downCounter  stats.Counter
	counterValue int64
	lastBytesAt  time.Time

	failStreak      int // hard failures, probe or traffic, since the last success
	probeFailStreak int
	recentFailures  []time.Time
	outcomes        []outcomeRecord
	lastError       string

	active map[*attempt]struct{}
}

func newMember(tag string, order int) *member {
	return &member{tag: tag, order: order, active: make(map[*attempt]struct{})}
}

func (m *member) addDelay(d time.Duration) {
	m.lastDelay = d
	m.delays = append(m.delays, d)
	if len(m.delays) > delaySamples {
		m.delays = m.delays[len(m.delays)-delaySamples:]
	}
}

func (m *member) pushOutcome(now time.Time, weight float64) {
	m.outcomes = append(m.outcomes, outcomeRecord{at: now, weight: weight})
	if len(m.outcomes) > outcomeSamples {
		m.outcomes = m.outcomes[len(m.outcomes)-outcomeSamples:]
	}
}

// noteHardFailure records a failure and reports how many happened inside failureWindow.
func (m *member) noteHardFailure(now time.Time) int {
	kept := m.recentFailures[:0]
	for _, t := range m.recentFailures {
		if now.Sub(t) < failureWindow {
			kept = append(kept, t)
		}
	}
	m.recentFailures = append(kept, now)
	return len(m.recentFailures)
}

// failRatio is the share of recent outcomes that went wrong. It never reaches 1 on thin evidence:
// the denominator is at least four, so a single failed connection costs a member standing, not
// its place.
func (m *member) failRatio(now time.Time) float64 {
	var total, bad float64
	for _, o := range m.outcomes {
		if now.Sub(o.at) > outcomeLifetime {
			continue
		}
		total++
		bad += o.weight
	}
	if total == 0 {
		return 0
	}
	return bad / math.Max(total, 4)
}

// typicalDelay is the median of the recent probe delays, or 0 when none is known.
func (m *member) typicalDelay() time.Duration {
	if len(m.delays) == 0 {
		return 0
	}
	return time.Duration(medianMs(m.delays) * float64(time.Millisecond))
}

func (m *member) jitter() time.Duration {
	if len(m.delays) < 2 {
		return 0
	}
	return time.Duration(meanAbsDevMs(m.delays, medianMs(m.delays)) * float64(time.Millisecond))
}

// score is the expected cost, in milliseconds, of sending the next connection through m. ok is
// false when m cannot be ranked at all: it is dead or has never been measured.
func (m *member) score(now time.Time) (float64, bool) {
	if m.state == stateDead || len(m.delays) == 0 {
		return math.Inf(1), false
	}
	med := medianMs(m.delays)
	s := med + 0.5*meanAbsDevMs(m.delays, med)
	s += 800 * m.failRatio(now)
	if m.state == stateSuspect {
		s += 1500
	}
	// Old numbers are trusted a little less than fresh ones — but evidence of any kind counts as
	// fresh: a selection that carried traffic all along skips its probes and must not look stale
	// next to an idle alternative that was just measured.
	fresh := m.lastProbeOKAt
	if m.lastPassiveOK.After(fresh) {
		fresh = m.lastPassiveOK
	}
	if m.lastBytesAt.After(fresh) {
		fresh = m.lastBytesAt
	}
	if now.Sub(fresh) > staleAfter {
		s += 150
	}
	return s, true
}

func medianMs(ds []time.Duration) float64 {
	v := make([]float64, len(ds))
	for i, d := range ds {
		v[i] = float64(d) / float64(time.Millisecond)
	}
	sort.Float64s(v)
	n := len(v)
	if n%2 == 1 {
		return v[n/2]
	}
	return (v[n/2-1] + v[n/2]) / 2
}

func meanAbsDevMs(ds []time.Duration, center float64) float64 {
	if len(ds) == 0 {
		return 0
	}
	var sum float64
	for _, d := range ds {
		sum += math.Abs(float64(d)/float64(time.Millisecond) - center)
	}
	return sum / float64(len(ds))
}
