package conf

import (
	"bytes"
	"encoding/json"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/singbox"
	"google.golang.org/protobuf/proto"
)

// SingboxConfig is the JSON form of the "singbox" outbound settings: the sing-box outbounds and
// endpoints that carry this outbound's traffic.
//
//	{ "tag": "proxy", "protocol": "singbox",
//	  "settings": { "outbound": { "type": "tuic", "server": "…", "server_port": 443, … } } }
//
// `outbound` is the usual single entry; `outbounds` and `endpoints` add what it depends on (a
// `detour` chain, a group's members). `config` takes a whole fragment instead — also box-wide
// options such as `dns` or `ntp` — as an object or a JSON string; the other fields are merged into
// it. `use` names the carrier when there is more than one candidate, and `viaXray` sends sing-box's
// own dials through this outbound's `streamSettings.sockopt` (and its `dialerProxy` chain).
type SingboxConfig struct {
	Outbound  json.RawMessage   `json:"outbound"`
	Outbounds []json.RawMessage `json:"outbounds"`
	Endpoints []json.RawMessage `json:"endpoints"`
	Config    json.RawMessage   `json:"config"`
	Use       string            `json:"use"`
	ViaXray   bool              `json:"viaXray"`
}

func (c *SingboxConfig) Build() (proto.Message, error) {
	fragment := map[string]json.RawMessage{}
	if raw := bytes.TrimSpace(c.Config); len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
		if raw[0] == '"' {
			var text string
			if err := json.Unmarshal(raw, &text); err != nil {
				return nil, errors.New("singbox: config").Base(err)
			}
			raw = []byte(text)
		}
		if err := json.Unmarshal(raw, &fragment); err != nil {
			return nil, errors.New("singbox: config must be a JSON object").Base(err)
		}
	}

	var outbounds []json.RawMessage
	if raw := bytes.TrimSpace(c.Outbound); len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
		outbounds = append(outbounds, raw)
	}
	outbounds = append(outbounds, c.Outbounds...)
	if existing, found := fragment["outbounds"]; found {
		var more []json.RawMessage
		if err := json.Unmarshal(existing, &more); err != nil {
			return nil, errors.New("singbox: config.outbounds").Base(err)
		}
		outbounds = append(outbounds, more...)
	}
	if len(outbounds) > 0 {
		encoded, err := json.Marshal(outbounds)
		if err != nil {
			return nil, err
		}
		fragment["outbounds"] = encoded
	}

	endpoints := append([]json.RawMessage{}, c.Endpoints...)
	if existing, found := fragment["endpoints"]; found {
		var more []json.RawMessage
		if err := json.Unmarshal(existing, &more); err != nil {
			return nil, errors.New("singbox: config.endpoints").Base(err)
		}
		endpoints = append(endpoints, more...)
	}
	if len(endpoints) > 0 {
		encoded, err := json.Marshal(endpoints)
		if err != nil {
			return nil, err
		}
		fragment["endpoints"] = encoded
	}

	if len(outbounds) == 0 && len(endpoints) == 0 {
		return nil, errors.New("singbox: no sing-box outbound or endpoint (set outbound, outbounds, endpoints or config)")
	}
	encoded, err := json.Marshal(fragment)
	if err != nil {
		return nil, err
	}
	return &singbox.Config{
		Config:  string(encoded),
		Use:     c.Use,
		ViaXray: c.ViaXray,
	}, nil
}
