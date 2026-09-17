package conf

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/proxy/wireguard"
	"google.golang.org/protobuf/proto"
)

type WireGuardPeerConfig struct {
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey"`
	Endpoint     string   `json:"endpoint"`
	KeepAlive    uint32   `json:"keepAlive"`
	AllowedIPs   []string `json:"allowedIPs,omitempty"`

	Level uint32 `json:"level"`
	Email string `json:"email"`
}

func (c *WireGuardPeerConfig) Build() (*wireguard.PeerConfig, error) {
	var err error
	config := new(wireguard.PeerConfig)

	if c.PublicKey != "" {
		config.PublicKey, err = ParseWireGuardKey(c.PublicKey)
		if err != nil {
			return nil, err
		}
	}

	if c.PreSharedKey != "" {
		config.PreSharedKey, err = ParseWireGuardKey(c.PreSharedKey)
		if err != nil {
			return nil, err
		}
	}

	config.Endpoint = c.Endpoint
	if c.KeepAlive != 0 {
		config.KeepAlive = strconv.FormatUint(uint64(c.KeepAlive), 10)
	}
	if c.AllowedIPs == nil {
		config.AllowedIps = []string{"0.0.0.0/0", "::0/0"}
	} else {
		config.AllowedIps = c.AllowedIPs
	}

	return config, nil
}

// AwgValue is an AmneziaWG parameter. Real .conf files and share links write these as bare numbers
// ("Jc = 5"), while ranges and obfuscation chains are strings, so accept a JSON string, number or
// bool and keep the value verbatim for the device's UAPI. Empty means "not set" and is not emitted.
type AwgValue string

func (v *AwgValue) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*v = AwgValue(s)
		return nil
	}
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		*v = AwgValue(strconv.FormatBool(b))
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(data, &n); err == nil {
		*v = AwgValue(n.String())
		return nil
	}
	return errors.New("invalid AmneziaWG value: ", string(data))
}

// WireGuardAwgConfig carries the AmneziaWG obfuscation parameters. Field names follow the .conf
// spellings (Jc, Jmin, Jmax, S1-S4, H1-H4, I1-I5); encoding/json matches keys case-insensitively,
// so "Jc", "JC" and "jc" all bind to the same field.
type WireGuardAwgConfig struct {
	Jc   AwgValue `json:"jc"`
	Jmin AwgValue `json:"jmin"`
	Jmax AwgValue `json:"jmax"`
	S1   AwgValue `json:"s1"`
	S2   AwgValue `json:"s2"`
	S3   AwgValue `json:"s3"`
	S4   AwgValue `json:"s4"`
	H1   AwgValue `json:"h1"`
	H2   AwgValue `json:"h2"`
	H3   AwgValue `json:"h3"`
	H4   AwgValue `json:"h4"`
	I1   AwgValue `json:"i1"`
	I2   AwgValue `json:"i2"`
	I3   AwgValue `json:"i3"`
	I4   AwgValue `json:"i4"`
	I5   AwgValue `json:"i5"`

	HeaderProtectionKey    AwgValue `json:"headerProtectionKey"`
	ContentPaddingAddition AwgValue `json:"contentPaddingAddition"`
	RekeyAfterTime         AwgValue `json:"rekeyAfterTime"`
	RekeyTimeout           AwgValue `json:"rekeyTimeout"`
	RejectAfterTime        AwgValue `json:"rejectAfterTime"`
	KeepaliveTimeout       AwgValue `json:"keepaliveTimeout"`
	MaxHandshakeAttempts   AwgValue `json:"maxHandshakeAttempts"`
	RandomTrailers         AwgValue `json:"randomTrailers"`
	DisableCookies         AwgValue `json:"disableCookies"`
}

// Build returns the protobuf form, or nil when no parameter is set — a plain WireGuard peer then
// produces exactly the same device config it did before AmneziaWG support existed.
func (c *WireGuardAwgConfig) Build() *wireguard.AwgConfig {
	if c == nil {
		return nil
	}
	out := &wireguard.AwgConfig{
		Jc: string(c.Jc), Jmin: string(c.Jmin), Jmax: string(c.Jmax),
		S1: string(c.S1), S2: string(c.S2), S3: string(c.S3), S4: string(c.S4),
		H1: string(c.H1), H2: string(c.H2), H3: string(c.H3), H4: string(c.H4),
		I1: string(c.I1), I2: string(c.I2), I3: string(c.I3), I4: string(c.I4), I5: string(c.I5),
		HeaderProtectionKey:    string(c.HeaderProtectionKey),
		ContentPaddingAddition: string(c.ContentPaddingAddition),
		RekeyAfterTime:         string(c.RekeyAfterTime),
		RekeyTimeout:           string(c.RekeyTimeout),
		RejectAfterTime:        string(c.RejectAfterTime),
		KeepaliveTimeout:       string(c.KeepaliveTimeout),
		MaxHandshakeAttempts:   string(c.MaxHandshakeAttempts),
		RandomTrailers:         string(c.RandomTrailers),
		DisableCookies:         string(c.DisableCookies),
	}
	if !out.HasValue() {
		return nil
	}
	return out
}

type WireGuardConfig struct {
	IsClient bool `json:""`

	NoKernelTun    bool                   `json:"noKernelTun"`
	SecretKey      string                 `json:"secretKey"`
	Address        []string               `json:"address"`
	Peers          []*WireGuardPeerConfig `json:"peers"`
	MTU            int32                  `json:"mtu"`
	Reserved       []byte                 `json:"reserved"`
	DomainStrategy string                 `json:"domainStrategy"`
	DNS            []string               `json:"remoteDNS"`

	// AmneziaWG parameters, accepted both nested under "awg" and inline alongside the WireGuard
	// keys, because .conf files and share links carry them flat next to PrivateKey/Address.
	Awg *WireGuardAwgConfig `json:"awg"`
	WireGuardAwgConfig
}

func (c *WireGuardConfig) Build() (proto.Message, error) {
	config := new(wireguard.DeviceConfig)

	var err error
	config.SecretKey, err = ParseWireGuardKey(c.SecretKey)
	if err != nil {
		return nil, errors.New("invalid WireGuard secret key: %w", err)
	}

	if c.Address == nil {
		// bogon ips
		config.Endpoint = []string{"10.0.0.1", "fd59:7153:2388:b5fd:0000:0000:0000:0001"}
	} else {
		config.Endpoint = c.Address
	}

	if c.IsClient {
		config.Peers = make([]*wireguard.PeerConfig, len(c.Peers))
		for i, p := range c.Peers {
			msg, err := p.Build()
			if err != nil {
				return nil, err
			}
			config.Peers[i] = msg
		}
	} else {
		config.Users = make([]*protocol.User, len(c.Peers))
		processUser := func(idx int) error {
			p := c.Peers[idx]
			m, err := p.Build()
			if err != nil {
				return err
			}
			config.Users[idx] = &protocol.User{
				Email:   p.Email,
				Level:   p.Level,
				Account: serial.ToTypedMessage(m),
			}
			return nil
		}
		if err := task.ParallelForN(len(c.Peers), processUser); err != nil {
			return nil, err
		}
	}

	if c.MTU == 0 {
		config.Mtu = 1420
	} else {
		config.Mtu = c.MTU
	}

	if len(c.Reserved) != 0 && len(c.Reserved) != 3 {
		return nil, errors.New(`"reserved" should be empty or 3 bytes`)
	}
	config.Reserved = c.Reserved

	switch strings.ToLower(c.DomainStrategy) {
	case "forceip", "":
		config.DomainStrategy = wireguard.DeviceConfig_FORCE_IP
	case "forceipv4":
		config.DomainStrategy = wireguard.DeviceConfig_FORCE_IP4
	case "forceipv6":
		config.DomainStrategy = wireguard.DeviceConfig_FORCE_IP6
	case "forceipv4v6":
		config.DomainStrategy = wireguard.DeviceConfig_FORCE_IP46
	case "forceipv6v4":
		config.DomainStrategy = wireguard.DeviceConfig_FORCE_IP64
	default:
		return nil, errors.New("unsupported domain strategy: ", c.DomainStrategy)
	}

	config.IsClient = c.IsClient
	config.NoKernelTun = c.NoKernelTun
	config.DNS = c.DNS

	// AmneziaWG: the nested "awg" object wins over the inline keys when both are present. Build()
	// returns nil when nothing is set, leaving config.Awg nil so an ordinary WireGuard peer is
	// untouched.
	if awg := c.Awg.Build(); awg != nil {
		config.Awg = awg
	} else {
		config.Awg = c.WireGuardAwgConfig.Build()
	}

	return config, nil
}

func ParseWireGuardKey(str string) (string, error) {
	var err error

	if str == "" {
		return "", errors.New("key must not be empty")
	}

	if len(str) == 64 {
		_, err = hex.DecodeString(str)
		if err == nil {
			return str, nil
		}
	}

	var dat []byte
	str = strings.TrimSuffix(str, "=")
	if strings.ContainsRune(str, '+') || strings.ContainsRune(str, '/') {
		dat, err = base64.RawStdEncoding.DecodeString(str)
	} else {
		dat, err = base64.RawURLEncoding.DecodeString(str)
	}
	if err == nil {
		return hex.EncodeToString(dat), nil
	}

	return "", errors.New("failed to deserialize key").Base(err)
}
