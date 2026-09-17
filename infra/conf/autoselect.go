package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/infra/conf/cfgcommon/duration"
	"github.com/xtls/xray-core/proxy/autoselect"
	"google.golang.org/protobuf/proto"
)

// AutoSelectConfig is the JSON form of the "autoselect" outbound settings.
//
//	{ "tag": "proxy", "protocol": "autoselect",
//	  "settings": { "outbounds": ["proxy@0", "proxy@1"], "probeURL": "https://…/generate_204" } }
type AutoSelectConfig struct {
	Outbounds        []string          `json:"outbounds"`
	Selector         []string          `json:"selector"`
	ProbeURL         string            `json:"probeURL"`
	FallbackProbeURL string            `json:"fallbackProbeURL"`
	ProbeTimeout     duration.Duration `json:"probeTimeout"`
	ActiveInterval   duration.Duration `json:"activeInterval"`
	StandbyInterval  duration.Duration `json:"standbyInterval"`
	StandbyCount     int32             `json:"standbyCount"`
	SweepInterval    duration.Duration `json:"sweepInterval"`
	IdleAfter        duration.Duration `json:"idleAfter"`
	SwitchRatio      float32           `json:"switchRatio"`
	SwitchMinGain    duration.Duration `json:"switchMinGain"`
	MinDwell         duration.Duration `json:"minDwell"`
	Retry            *bool             `json:"retry"`
	MaxAttempts      int32             `json:"maxAttempts"`
	MaxReplayBytes   int32             `json:"maxReplayBytes"`
	AttemptBudget    duration.Duration `json:"attemptBudget"`
	Initial          string            `json:"initial"`
	InterruptStalled *bool             `json:"interruptStalled"`
	Concurrency      int32             `json:"concurrency"`
}

func (c *AutoSelectConfig) Build() (proto.Message, error) {
	if len(c.Outbounds) == 0 && len(c.Selector) == 0 {
		return nil, errors.New("autoselect: no member outbounds (set outbounds or selector)")
	}
	if c.SwitchRatio < 0 || c.SwitchRatio >= 1 {
		return nil, errors.New("autoselect: switchRatio must be in [0, 1)")
	}
	ms := func(d duration.Duration) int64 {
		if d < 0 {
			return 0
		}
		return int64(d) / 1e6
	}
	return &autoselect.Config{
		Outbounds:               c.Outbounds,
		Selector:                c.Selector,
		ProbeUrl:                c.ProbeURL,
		FallbackProbeUrl:        c.FallbackProbeURL,
		ProbeTimeoutMs:          ms(c.ProbeTimeout),
		ActiveIntervalMs:        ms(c.ActiveInterval),
		StandbyIntervalMs:       ms(c.StandbyInterval),
		StandbyCount:            c.StandbyCount,
		SweepIntervalMs:         ms(c.SweepInterval),
		IdleAfterMs:             ms(c.IdleAfter),
		SwitchRatio:             c.SwitchRatio,
		SwitchMinGainMs:         ms(c.SwitchMinGain),
		MinDwellMs:              ms(c.MinDwell),
		DisableRetry:            c.Retry != nil && !*c.Retry,
		MaxAttempts:             c.MaxAttempts,
		MaxReplayBytes:          c.MaxReplayBytes,
		AttemptBudgetMs:         ms(c.AttemptBudget),
		Initial:                 c.Initial,
		DisableInterruptStalled: c.InterruptStalled != nil && !*c.InterruptStalled,
		Concurrency:             c.Concurrency,
	}, nil
}
