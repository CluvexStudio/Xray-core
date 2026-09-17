package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/wireguard"
)

func build(t *testing.T, raw string) *wireguard.DeviceConfig {
	t.Helper()
	c := &conf.WireGuardConfig{}
	if err := json.Unmarshal([]byte(raw), c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	c.IsClient = true
	m, err := c.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return m.(*wireguard.DeviceConfig)
}

const peer = `"secretKey":"aGVsbG8gd29ybGQgdGhpcyBpcyAzMiBieXRlcyEh","peers":[{"publicKey":"aGVsbG8gd29ybGQgdGhpcyBpcyAzMiBieXRlcyEh","endpoint":"1.2.3.4:51820"}]`

func TestPlainWireGuardHasNoAwg(t *testing.T) {
	if got := build(t, "{"+peer+"}"); got.Awg != nil {
		t.Fatalf("plain WireGuard config produced a non-nil Awg: %v", got.Awg)
	}
}

// Real .conf files and share links write capitalised keys with bare numbers.
func TestInlineDotConfSpellingsAndNumbers(t *testing.T) {
	got := build(t, `{`+peer+`,"Jc":5,"Jmin":40,"Jmax":70,"S1":15,"S2":37,"H1":1234567890,"H4":"2468013579","I1":"<b 0xf1>","DisableCookies":true}`)
	if got.Awg == nil {
		t.Fatal("Awg not populated from inline .conf-style keys")
	}
	lines := got.Awg.UAPILines()
	t.Logf("UAPI lines: %v", lines)
	want := map[string]bool{"jc=5": true, "jmin=40": true, "jmax=70": true, "s1=15": true,
		"s2=37": true, "h1=1234567890": true, "h4=2468013579": true, "i1=<b 0xf1>": true,
		"disable_cookies=true": true}
	for _, l := range lines {
		delete(want, l)
	}
	if len(want) != 0 {
		t.Fatalf("missing UAPI lines: %v", want)
	}
	if len(lines) != 9 {
		t.Fatalf("expected exactly 9 lines, got %d: %v", len(lines), lines)
	}
}

func TestNestedAwgObjectWinsOverInline(t *testing.T) {
	got := build(t, `{`+peer+`,"Jc":5,"awg":{"jc":"9","jmin":"20"}}`)
	lines := got.Awg.UAPILines()
	if len(lines) != 2 || lines[0] != "jc=9" || lines[1] != "jmin=20" {
		t.Fatalf("nested awg should win, got %v", lines)
	}
}
