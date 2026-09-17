package autoselect

import (
	"encoding/json"
	"math"
	"sort"
	"sync"
	"time"
)

// SwitchEvent records one change of selection.
type SwitchEvent struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`
	AtMs   int64  `json:"atMs"`
}

// MemberStatus is what the group currently knows about one member.
type MemberStatus struct {
	Tag              string  `json:"tag"`
	State            string  `json:"state"`
	DelayMs          int64   `json:"delayMs"`
	LastDelayMs      int64   `json:"lastDelayMs"`
	JitterMs         int64   `json:"jitterMs"`
	Samples          int     `json:"samples"`
	Score            float64 `json:"score"`
	FailRatio        float64 `json:"failRatio"`
	Connections      int     `json:"connections"`
	LastProbeAgoMs   int64   `json:"lastProbeAgoMs"`
	LastSuccessAgoMs int64   `json:"lastSuccessAgoMs"`
	LastError        string  `json:"lastError,omitempty"`
}

// GroupStatus is a snapshot of one autoselect outbound.
type GroupStatus struct {
	Tag      string `json:"tag"`
	Selected string `json:"selected"`
	Pinned   string `json:"pinned,omitempty"`
	// starting | ok | degraded | down | idle
	State    string         `json:"state"`
	Switches int            `json:"switches"`
	Events   []SwitchEvent  `json:"events"`
	Members  []MemberStatus `json:"members"`
}

// Status returns a snapshot of the group.
func (g *Group) Status() GroupStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	st := GroupStatus{
		Tag:      g.tag,
		Pinned:   g.pinned,
		Switches: g.switches,
		Events:   append([]SwitchEvent{}, g.events...),
		Members:  make([]MemberStatus, 0, len(g.members)),
		State:    g.stateLocked(now),
	}
	if g.selected != nil {
		st.Selected = g.selected.tag
	}
	ago := func(t time.Time) int64 {
		if t.IsZero() {
			return -1
		}
		return now.Sub(t).Milliseconds()
	}
	for _, m := range g.members {
		ms := MemberStatus{
			Tag:              m.tag,
			State:            m.state.String(),
			DelayMs:          -1,
			LastDelayMs:      -1,
			JitterMs:         m.jitter().Milliseconds(),
			Samples:          len(m.delays),
			Score:            -1,
			FailRatio:        math.Round(m.failRatio(now)*100) / 100,
			Connections:      len(m.active),
			LastProbeAgoMs:   ago(m.lastProbeAt),
			LastSuccessAgoMs: ago(m.lastSuccessAt),
			LastError:        m.lastError,
		}
		if d := m.typicalDelay(); d > 0 {
			ms.DelayMs = d.Milliseconds()
			ms.LastDelayMs = m.lastDelay.Milliseconds()
		}
		if s, ok := m.score(now); ok {
			ms.Score = math.Round(s)
		}
		st.Members = append(st.Members, ms)
	}
	return st
}

func (g *Group) stateLocked(now time.Time) string {
	if g.idle.Load() {
		return "idle"
	}
	if g.selected == nil {
		return "starting"
	}
	if g.allDownLocked() {
		if g.inGraceLocked(now) {
			for _, m := range g.members {
				if m.state == stateUnknown {
					return "starting"
				}
			}
		}
		return "down"
	}
	if g.selected.state == stateSuspect || g.selected.state == stateDead {
		return "degraded"
	}
	if _, ok := g.selected.score(now); !ok && g.inGraceLocked(now) {
		return "starting"
	}
	return "ok"
}

var registry = struct {
	sync.Mutex
	groups []*Group
}{}

func register(g *Group) {
	registry.Lock()
	defer registry.Unlock()
	registry.groups = append(registry.groups, g)
}

func unregister(g *Group) {
	registry.Lock()
	defer registry.Unlock()
	for i, x := range registry.groups {
		if x == g {
			registry.groups = append(registry.groups[:i], registry.groups[i+1:]...)
			return
		}
	}
}

func groups() []*Group {
	registry.Lock()
	defer registry.Unlock()
	return append([]*Group(nil), registry.groups...)
}

// Statuses snapshots every running autoselect outbound in the process, ordered by tag.
func Statuses() []GroupStatus {
	var out []GroupStatus
	for _, g := range groups() {
		out = append(out, g.Status())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tag < out[j].Tag })
	return out
}

// StatusJSON is Statuses as JSON, for callers across a language boundary.
func StatusJSON() string {
	data, err := json.Marshal(Statuses())
	if err != nil || data == nil {
		return "[]"
	}
	return string(data)
}

// KickAll tells every group the network changed.
func KickAll() {
	for _, g := range groups() {
		g.Kick()
	}
}

// PinMember pins member on the group tagged group (empty member unpins). It reports whether such a
// group and member exist.
func PinMember(group, member string) bool {
	ok := false
	for _, g := range groups() {
		if g.tag == group && g.Pin(member) {
			ok = true
		}
	}
	return ok
}
