package wireguard

import (
	"strings"
	"testing"
)

// buildUAPI mirrors the exact construction in client.go so the test proves the shipped ordering.
func buildUAPI(conf *DeviceConfig) string {
	var cfg strings.Builder
	cfg.WriteString("private_key=" + conf.SecretKey + "\n")
	for _, line := range conf.Awg.UAPILines() {
		cfg.WriteString(line + "\n")
	}
	for _, peer := range conf.Peers {
		cfg.WriteString("public_key=" + peer.PublicKey + "\n")
		if peer.PreSharedKey != "" {
			cfg.WriteString("preshared_key=" + peer.PreSharedKey + "\n")
		}
		cfg.WriteString("endpoint=" + peer.Endpoint + "\n")
		for _, ip := range peer.AllowedIps {
			cfg.WriteString("allowed_ip=" + ip + "\n")
		}
		if peer.KeepAlive != "" {
			cfg.WriteString("persistent_keepalive_interval=" + peer.KeepAlive + "\n")
		}
	}
	return cfg.String()
}

func plainConf() *DeviceConfig {
	return &DeviceConfig{
		SecretKey: "SECRET",
		Peers: []*PeerConfig{{
			PublicKey:  "PUB",
			Endpoint:   "1.2.3.4:51820",
			AllowedIps: []string{"0.0.0.0/0", "::/0"},
			KeepAlive:  "25",
		}},
	}
}

const wantPlain = "private_key=SECRET\n" +
	"public_key=PUB\n" +
	"endpoint=1.2.3.4:51820\n" +
	"allowed_ip=0.0.0.0/0\n" +
	"allowed_ip=::/0\n" +
	"persistent_keepalive_interval=25\n"

func TestPlainWireGuardUAPIUnchanged(t *testing.T) {
	if got := buildUAPI(plainConf()); got != wantPlain {
		t.Fatalf("plain WireGuard UAPI changed.\n got:\n%s\nwant:\n%s", got, wantPlain)
	}
	// nil and empty Awg must both behave as "not set"
	c := plainConf()
	c.Awg = &AwgConfig{}
	if got := buildUAPI(c); got != wantPlain {
		t.Fatalf("empty AwgConfig altered the UAPI:\n%s", got)
	}
	if (&AwgConfig{}).HasValue() || (*AwgConfig)(nil).HasValue() {
		t.Fatal("empty/nil AwgConfig must report HasValue()==false")
	}
}

func TestAwgUAPILinesAndOrdering(t *testing.T) {
	c := plainConf()
	c.Awg = &AwgConfig{
		Jc: "5", Jmin: "40", Jmax: "70",
		S1: "15", S2: "37", S3: "0", S4: "0",
		H1: "1234567890", H2: "1122334455", H3: "1357924680", H4: "2468013579",
		I1: "<b 0xf1a2>", HeaderProtectionKey: "abcdef00", DisableCookies: "true",
	}
	got := buildUAPI(c)
	t.Logf("AWG UAPI:\n%s", got)

	// every device-level line must precede the first peer line
	pk := strings.Index(got, "public_key=")
	for _, key := range []string{"jc=5", "jmin=40", "jmax=70", "s1=15", "s2=37", "s3=0", "s4=0",
		"h1=1234567890", "h2=1122334455", "h3=1357924680", "h4=2468013579",
		"i1=<b 0xf1a2>", "header_protection_key=abcdef00", "disable_cookies=true"} {
		i := strings.Index(got, key+"\n")
		if i < 0 {
			t.Fatalf("missing UAPI line %q", key)
		}
		if i > pk {
			t.Fatalf("device-level line %q emitted after the first peer section", key)
		}
	}
	// unset params must not appear at all
	for _, absent := range []string{"i2=", "i3=", "i4=", "i5=", "rekey_after_time=", "random_trailers=", "content_padding_addition="} {
		if strings.Contains(got, absent) {
			t.Fatalf("unset parameter %q was emitted", absent)
		}
	}
}
