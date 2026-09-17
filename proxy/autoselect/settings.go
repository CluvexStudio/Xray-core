// Package autoselect implements the "autoselect" outbound: a group of member outbounds that sends
// each connection through the healthiest member, retries a failed connection on the next member
// without the client noticing, and keeps probing the members so the next choice is ready before it
// is needed.
//
// Where it differs from the balancers in app/router:
//   - It is an outbound, so routing rules, DNS and the default handler keep pointing at one tag and
//     never learn that a group exists.
//   - Real traffic is evidence. A member whose connections fail is suspected immediately and the
//     failing connection itself is moved to another member, instead of waiting for the next probe.
//   - A healthy selection is sticky: it is only replaced by a member that is clearly faster, so the
//     exit address does not flap between two similar servers.
//   - Switching never closes working connections. Only connections that stopped receiving data on
//     a member that was found dead are cut, so their applications reconnect at once.
package autoselect

import "time"

const (
	defaultProbeURL        = "https://www.gstatic.com/generate_204"
	defaultProbeTimeout    = 5 * time.Second
	defaultActiveInterval  = 30 * time.Second
	defaultStandbyInterval = 2 * time.Minute
	defaultStandbyCount    = 2
	defaultSweepInterval   = 10 * time.Minute
	defaultIdleAfter       = 3 * time.Minute
	defaultSwitchRatio     = 0.3
	defaultSwitchMinGain   = 60 * time.Millisecond
	defaultMinDwell        = time.Minute
	defaultMaxAttempts     = 3
	defaultMaxReplayBytes  = 64 << 10
	defaultConcurrency     = 8

	// A connection is given this long to produce its first response byte before it is abandoned
	// for the next member, when nothing better is known about the member.
	defaultAttemptBudget = 5 * time.Second
	minAttemptBudget     = 2500 * time.Millisecond
	maxAttemptBudget     = 8 * time.Second

	// A second attempt is raced against a slow first one after roughly the member's usual latency.
	defaultHedgeDelay = 1500 * time.Millisecond
	minHedgeDelay     = 700 * time.Millisecond
	maxHedgeDelay     = 3 * time.Second
	hedgeRate         = 4 // hedges per second, sustained
	hedgeBurst        = 8

	// Until this long after start (or after a network change) the first pick is known to be a
	// guess, so better information replaces it without waiting out min_dwell.
	startupGrace = 20 * time.Second

	// Two hard failures inside this window make a member suspect.
	failureWindow = 30 * time.Second
	// A suspect member is re-probed this soon, to confirm or clear the suspicion.
	suspectRecheck = 1500 * time.Millisecond
	// Probe results older than this are trusted a little less than fresh ones.
	staleAfter = 15 * time.Minute

	delaySamples    = 6
	outcomeSamples  = 12
	outcomeLifetime = 5 * time.Minute
	eventsKept      = 16

	monitorTick         = 500 * time.Millisecond
	membersRefreshEvery = 10 * time.Second
	pollInterval        = 200 * time.Millisecond
)

// A committed connection that has received nothing for this long on a dead member is cut. A
// variable only so tests can shorten it.
var stalledAfter = 8 * time.Second

// Backoff between probes of a dead member. When every member is down the network itself is the
// likely culprit, so members are retried much sooner to notice the moment it comes back.
var (
	deadBackoff    = []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute}
	allDownBackoff = []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second}
)

// settings is Config with every default applied, in the units the code works with.
type settings struct {
	outbounds        []string
	selectors        []string
	probeURL         string
	fallbackProbeURL string
	probeTimeout     time.Duration
	activeInterval   time.Duration
	standbyInterval  time.Duration
	standbyCount     int
	sweepInterval    time.Duration
	idleAfter        time.Duration
	switchRatio      float64
	switchMinGain    time.Duration
	minDwell         time.Duration
	retry            bool
	maxAttempts      int
	maxReplayBytes   int32
	attemptBudget    time.Duration // 0 = derived from the member's measured delay
	initial          string
	interruptStalled bool
	concurrency      int
}

func newSettings(c *Config) settings {
	ms := func(v int64, def time.Duration) time.Duration {
		if v <= 0 {
			return def
		}
		return time.Duration(v) * time.Millisecond
	}
	s := settings{
		outbounds:        c.GetOutbounds(),
		selectors:        c.GetSelector(),
		probeURL:         c.GetProbeUrl(),
		fallbackProbeURL: c.GetFallbackProbeUrl(),
		probeTimeout:     ms(c.GetProbeTimeoutMs(), defaultProbeTimeout),
		activeInterval:   ms(c.GetActiveIntervalMs(), defaultActiveInterval),
		standbyInterval:  ms(c.GetStandbyIntervalMs(), defaultStandbyInterval),
		standbyCount:     int(c.GetStandbyCount()),
		sweepInterval:    ms(c.GetSweepIntervalMs(), defaultSweepInterval),
		idleAfter:        ms(c.GetIdleAfterMs(), defaultIdleAfter),
		switchRatio:      float64(c.GetSwitchRatio()),
		switchMinGain:    ms(c.GetSwitchMinGainMs(), defaultSwitchMinGain),
		minDwell:         ms(c.GetMinDwellMs(), defaultMinDwell),
		retry:            !c.GetDisableRetry(),
		maxAttempts:      int(c.GetMaxAttempts()),
		maxReplayBytes:   c.GetMaxReplayBytes(),
		initial:          c.GetInitial(),
		interruptStalled: !c.GetDisableInterruptStalled(),
		concurrency:      int(c.GetConcurrency()),
	}
	if c.GetAttemptBudgetMs() > 0 {
		s.attemptBudget = time.Duration(c.GetAttemptBudgetMs()) * time.Millisecond
	}
	if s.probeURL == "" {
		s.probeURL = defaultProbeURL
	}
	if s.standbyCount <= 0 {
		s.standbyCount = defaultStandbyCount
	}
	if s.switchRatio <= 0 || s.switchRatio >= 1 {
		s.switchRatio = defaultSwitchRatio
	}
	if s.maxAttempts <= 0 {
		s.maxAttempts = defaultMaxAttempts
	}
	if s.maxReplayBytes <= 0 {
		s.maxReplayBytes = defaultMaxReplayBytes
	}
	if s.concurrency <= 0 {
		s.concurrency = defaultConcurrency
	}
	return s
}
