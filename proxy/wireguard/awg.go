package wireguard

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
)

// awgUAPIKeys maps each AmneziaWG parameter to its UAPI key, in the order the device expects to
// receive them. These are device-level settings, so every line produced here must be written before
// the first "public_key=" line: that key is what switches the UAPI parser from the device section to
// a peer section (see amneziawg-go device/uapi.go IpcSetOperation).
func (x *AwgConfig) uapiPairs() [][2]string {
	if x == nil {
		return nil
	}
	return [][2]string{
		{"jc", x.Jc},
		{"jmin", x.Jmin},
		{"jmax", x.Jmax},
		{"s1", x.S1},
		{"s2", x.S2},
		{"s3", x.S3},
		{"s4", x.S4},
		{"h1", x.H1},
		{"h2", x.H2},
		{"h3", x.H3},
		{"h4", x.H4},
		{"i1", x.I1},
		{"i2", x.I2},
		{"i3", x.I3},
		{"i4", x.I4},
		{"i5", x.I5},
		{"header_protection_key", x.HeaderProtectionKey},
		{"content_padding_addition", x.ContentPaddingAddition},
		{"rekey_after_time", x.RekeyAfterTime},
		{"rekey_timeout", x.RekeyTimeout},
		{"reject_after_time", x.RejectAfterTime},
		{"keepalive_timeout", x.KeepaliveTimeout},
		{"max_handshake_attempts", x.MaxHandshakeAttempts},
		{"random_trailers", x.RandomTrailers},
		{"disable_cookies", x.DisableCookies},
	}
}

// UAPILines returns the "key=value" lines for the parameters that are actually set. An unset
// parameter is skipped entirely, so a plain WireGuard peer yields no lines at all and its UAPI
// string is byte-identical to what it was before AmneziaWG support was added.
func (x *AwgConfig) UAPILines() []string {
	var lines []string
	for _, kv := range x.uapiPairs() {
		if v := strings.TrimSpace(kv[1]); v != "" {
			lines = append(lines, kv[0]+"="+awgUAPIValue(kv[0], v))
		}
	}
	return lines
}

var legacyCounterTag = regexp.MustCompile(`<\s*c\s*>`)
var legacyWaitTag = regexp.MustCompile(`<\s*wt(\s+[^>]*)?>`)

func awgUAPIValue(key, value string) string {
	switch key {
	case "header_protection_key":
		return keyHex(value)
	case "random_trailers", "disable_cookies":
		switch strings.ToLower(value) {
		case "on", "yes", "y", "enable", "enabled":
			return "true"
		case "off", "no", "n", "disable", "disabled":
			return "false"
		}
	case "i1", "i2", "i3", "i4", "i5":
		value = legacyCounterTag.ReplaceAllString(value, "<r 4>")
		return legacyWaitTag.ReplaceAllString(value, "")
	}
	return value
}

func keyHex(value string) string {
	if raw, err := hex.DecodeString(value); err == nil && len(raw) == 32 {
		return strings.ToLower(value)
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := encoding.DecodeString(value); err == nil && len(raw) == 32 {
			return hex.EncodeToString(raw)
		}
	}
	return value
}

// HasValue reports whether any AmneziaWG parameter is set.
func (x *AwgConfig) HasValue() bool { return len(x.UAPILines()) > 0 }

func (x *AwgConfig) CustomHeader() bool {
	if x == nil {
		return false
	}
	for i, h := range []string{x.H1, x.H2, x.H3, x.H4} {
		if v := strings.TrimSpace(h); v != "" && v != strconv.Itoa(i+1) {
			return true
		}
	}
	return strings.TrimSpace(x.HeaderProtectionKey) != ""
}
