package singbox_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	gonet "net"
	gonethttp "net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"golang.org/x/crypto/curve25519"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy/singbox"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
)

// ---- test environment -------------------------------------------------------------------------

func xor(b []byte) []byte {
	r := make([]byte, len(b))
	for i, v := range b {
		r[i] = v ^ 'c'
	}
	return r
}

type env struct {
	t        *testing.T
	certPath string
	keyPath  string
	echoTCP  uint16
	echoUDP  uint16
	port     uint16 // the sing-box server's port for this case
	aux      uint16 // a second port, for cases that need one
	uuid     string
	password string
	ss2022   string
	wgServer [2]string // private, public
	wgClient [2]string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	certPath, keyPath := writeCertificate(t)

	tcpServer := tcp.Server{MsgProcessor: xor}
	tcpDest, err := tcpServer.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcpServer.Close() })
	udpServer := udp.Server{MsgProcessor: xor}
	udpDest, err := udpServer.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udpServer.Close() })

	key := make([]byte, 16)
	rand.Read(key)
	return &env{
		t:        t,
		certPath: certPath,
		keyPath:  keyPath,
		echoTCP:  uint16(tcpDest.Port),
		echoUDP:  uint16(udpDest.Port),
		uuid:     "b831381d-6324-4d53-ad4f-8cda48b30811",
		password: "zed-test-password",
		ss2022:   base64.StdEncoding.EncodeToString(key),
		wgServer: wireguardKeys(t),
		wgClient: wireguardKeys(t),
	}
}

func writeCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		DNSNames:              []string{"example.com"},
		IPAddresses:           []gonet.IP{gonet.IPv4(127, 0, 0, 1)},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	return certPath, keyPath
}

func wireguardKeys(t *testing.T) [2]string {
	t.Helper()
	private := make([]byte, 32)
	rand.Read(private)
	private[0] &= 248
	private[31] = (private[31] & 127) | 64
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return [2]string{base64.StdEncoding.EncodeToString(private), base64.StdEncoding.EncodeToString(public)}
}

// serverTLS is the inbound TLS block every TLS server case uses.
func (e *env) serverTLS(alpn ...string) string {
	extra := ""
	if len(alpn) > 0 {
		extra = fmt.Sprintf(`,"alpn":["%s"]`, strings.Join(alpn, `","`))
	}
	return fmt.Sprintf(`{"enabled":true,"server_name":"example.com","certificate_path":%q,"key_path":%q%s}`, e.certPath, e.keyPath, extra)
}

// clientTLS trusts the test certificate explicitly rather than skipping verification, so the tests
// also prove the certificate options reach sing-box.
func (e *env) clientTLS(alpn ...string) string {
	extra := ""
	if len(alpn) > 0 {
		extra = fmt.Sprintf(`,"alpn":["%s"]`, strings.Join(alpn, `","`))
	}
	return fmt.Sprintf(`{"enabled":true,"server_name":"example.com","certificate_path":%q%s}`, e.certPath, extra)
}

// startSingBoxServer runs a sing-box instance from a full config, skipping the test when the protocol
// it needs was not compiled in (build tags).
func startSingBoxServer(t *testing.T, config string) {
	t.Helper()
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	if err != nil {
		t.Fatalf("server config: %v\n%s", err, config)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		skipIfNotBuilt(t, err)
		t.Fatalf("server: %v", err)
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		skipIfNotBuilt(t, err)
		t.Fatalf("server start: %v", err)
	}
	t.Cleanup(func() { instance.Close() })
}

// requireClientBuilt skips when the client side of a case needs something not compiled in: the
// outbound only fails once Xray starts it, which would read as a broken bridge instead.
func requireClientBuilt(t *testing.T, fragment string) {
	t.Helper()
	config := fragment
	if !strings.Contains(fragment, `"endpoints"`) && !strings.Contains(fragment, `"outbounds"`) {
		config = fmt.Sprintf(`{"outbounds":[%s]}`, fragment)
	}
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	if err != nil {
		t.Fatalf("client config: %v\n%s", err, config)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		skipIfNotBuilt(t, err)
		return
	}
	instance.Close()
}

func skipIfNotBuilt(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), "not included in this build") {
		t.Skipf("not compiled in: %v", err)
	}
}

// xrayClient is an Xray instance whose only outbound is the singbox outbound under test, fronted
// by two dokodemo-door inbounds that forward to the echo servers.
type xrayClient struct {
	instance *core.Instance
	tcpPort  uint16
	udpPort  uint16
}

func startXray(t *testing.T, e *env, settings string, extraOutbounds ...string) *xrayClient {
	t.Helper()
	return startXrayTo(t, e, "127.0.0.1", settings, extraOutbounds...)
}

func startXrayTo(t *testing.T, e *env, target, settings string, extraOutbounds ...string) *xrayClient {
	t.Helper()
	tcpPort := uint16(tcp.PickPort())
	udpPort := uint16(udp.PickPort())
	outbounds := []string{fmt.Sprintf(`{"tag":"proxy","protocol":"singbox","settings":%s}`, settings)}
	outbounds = append(outbounds, extraOutbounds...)
	config := fmt.Sprintf(`{
		"log": {"loglevel": "warning"},
		"stats": {},
		"policy": {"system": {"statsOutboundUplink": true, "statsOutboundDownlink": true}},
		"inbounds": [
			{"tag": "tcp-in", "listen": "127.0.0.1", "port": %d, "protocol": "dokodemo-door",
			 "settings": {"address": %q, "port": %d, "network": "tcp"}},
			{"tag": "udp-in", "listen": "127.0.0.1", "port": %d, "protocol": "dokodemo-door",
			 "settings": {"address": %q, "port": %d, "network": "udp"}}
		],
		"outbounds": [%s],
		"routing": {"rules": [{"type": "field", "inboundTag": ["tcp-in", "udp-in"], "outboundTag": "proxy"}]}
	}`, tcpPort, target, e.echoTCP, udpPort, target, e.echoUDP, strings.Join(outbounds, ","))
	coreConfig, err := serial.LoadJSONConfig(strings.NewReader(config))
	if err != nil {
		t.Fatalf("xray config: %v\n%s", err, config)
	}
	instance, err := core.New(coreConfig)
	if err != nil {
		t.Fatalf("xray: %v", err)
	}
	if err := instance.Start(); err != nil {
		t.Fatalf("xray start: %v", err)
	}
	t.Cleanup(func() { instance.Close() })
	return &xrayClient{instance: instance, tcpPort: tcpPort, udpPort: udpPort}
}

func (c *xrayClient) counter(t *testing.T, name string) int64 {
	t.Helper()
	manager := c.instance.GetFeature(stats.ManagerType()).(stats.Manager)
	counter := manager.GetCounter(name)
	if counter == nil {
		return 0
	}
	return counter.Value()
}

func roundTripTCP(port uint16, size int) error {
	conn, err := gonet.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	payload := make([]byte, size)
	rand.Read(payload)
	go func() {
		conn.Write(payload)
	}()
	response := make([]byte, size)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("read echo: %w", err)
	}
	if !bytes.Equal(response, xor(payload)) {
		return fmt.Errorf("echo mismatch")
	}
	return nil
}

func roundTripUDP(port uint16) error {
	conn, err := gonet.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	defer conn.Close()
	var lastErr error
	// UDP is lossy by definition and the first datagram also sets the tunnel up: retry a few times.
	for attempt := 0; attempt < 8; attempt++ {
		payload := make([]byte, 1024)
		rand.Read(payload)
		if _, err := conn.Write(payload); err != nil {
			return err
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		response := make([]byte, 2048)
		n, err := conn.Read(response)
		if err != nil {
			lastErr = err
			continue
		}
		if !bytes.Equal(response[:n], xor(payload)) {
			lastErr = fmt.Errorf("udp echo mismatch")
			continue
		}
		return nil
	}
	return fmt.Errorf("no udp echo: %v", lastErr)
}

// ---- every protocol, end to end -----------------------------------------------------------------

type protocolCase struct {
	name string
	// target is the address the client asks for; empty means the echo servers' 127.0.0.1. A
	// userspace netstack drops loopback destinations, so tunnels ask for an address of theirs and the
	// server rewrites it.
	target string
	// udpPort says the server listens on UDP (QUIC protocols, WireGuard); it only changes how the
	// port is picked.
	udpPort bool
	udp     bool
	server  func(e *env) string
	client  func(e *env) string
}

func directOutbound() string { return `"outbounds":[{"type":"direct","tag":"direct"}]` }

var protocolCases = []protocolCase{
	{
		name: "shadowsocks-2022", udp: true,
		server: func(e *env) string {
			return fmt.Sprintf(`{"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":%d,"method":"2022-blake3-aes-128-gcm","password":%q}],%s}`, e.port, e.ss2022, directOutbound())
		},
		client: func(e *env) string {
			return fmt.Sprintf(`{"type":"shadowsocks","server":"127.0.0.1","server_port":%d,"method":"2022-blake3-aes-128-gcm","password":%q}`, e.port, e.ss2022)
		},
	},
	{
		name: "shadowsocks-aead", udp: true,
		server: func(e *env) string {
			return fmt.Sprintf(`{"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":%d,"method":"aes-128-gcm","password":%q}],%s}`, e.port, e.password, directOutbound())
		},
		client: func(e *env) string {
			return fmt.Sprintf(`{"type":"shadowsocks","server":"127.0.0.1","server_port":%d,"method":"aes-128-gcm","password":%q}`, e.port, e.password)
		},
	},
	{
		name: "shadowsocks-none",
		server: func(e *env) string {
			return fmt.Sprintf(`{"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":%d,"method":"none"}],%s}`, e.port, directOutbound())
		},
		client: func(e *env) string {
			return fmt.Sprintf(`{"type":"shadowsocks","server":"127.0.0.1","server_port":%d,"method":"none"}`, e.port)
		},
	},
	{
		name: "vmess",
		server: func(e *env) string {
			return fmt.Sprintf(`{"inbounds":[{"type":"vmess","listen":"127.0.0.1","listen_port":%d,"users":[{"uuid":%q}]}],%s}`, e.port, e.uuid, directOutbound())
		},
		client: func(e *env) string {
			return fmt.Sprintf(`{"type":"vmess","server":"127.0.0.1","server_port":%d,"uuid":%q,"security":"aes-128-gcm"}`, e.port, e.uuid)
		},
	},
	{
		name: "vmess-websocket",
		server: func(e *env) string {
			return fmt.Sprintf(`{"inbounds":[{"type":"vmess","listen":"127.0.0.1","listen_port":%d,"users":[{"uuid":%q}],"transport":{"type":"ws","path":"/zed"}}],%s}`, e.port, e.uuid, directOutbound())
		},
		client: func(e *env) string {
			return fmt.Sprintf(`{"type":"vmess","server":"127.0.0.1","server_port":%d,"uuid":%q,"transport":{"type":"ws","path":"/zed"}}`, e.port, e.uuid)
		},
	},
	{
		name: "trojan-tls",
		server: func(e *env) string {
			return fmt.Sprintf(`{"inbounds":[{"type":"trojan","listen":"127.0.0.1","listen_port":%d,"users":[{"password":%q}],"tls":%s}],%s}`, e.port, e.password, e.serverTLS(), directOutbound())
		},
		client: func(e *env) string {
			return fmt.Sprintf(`{"type":"trojan","server":"127.0.0.1","server_port":%d,"password":%q,"tls":%s}`, e.port, e.password, e.clientTLS())
		},
	},
	{
		name: "trojan-tls-fragment",
		server: func(e *env) string {
			return fmt.Sprintf(`{"inbounds":[{"type":"trojan","listen":"127.0.0.1","listen_port":%d,"users":[{"password":%q}],"tls":%s}],%s}`, e.port, e.password, e.serverTLS(), directOutbound())
		},
		client: func(e *env) string {
			tlsOptions := strings.TrimSuffix(e.clientTLS(), "}") + `,"fragment":true,"record_fragment":true}`
			return fmt.Sprintf(`{"type":"trojan","server":"127.0.0.1","server_port":%d,"password":%q,"tls":%s}`, e.port, e.password, tlsOptions)
		},
	},
	{
		name: "trojan-grpc",
		server: func(e *env) string {
			return fmt.Sprintf(`{"inbounds":[{"type":"trojan","listen":"127.0.0.1","listen_port":%d,"users":[{"password":%q}],"tls":%s,"transport":{"type":"grpc","service_name":"zed"}}],%s}`, e.port, e.password, e.serverTLS("h2"), directOutbound())
		},
		client: func(e *env) string {
			return fmt.Sprintf(`{"type":"trojan","server":"127.0.0.1","server_port":%d,"password":%q,"tls":%s,"transport":{"type":"grpc","service_name":"zed"}}`, e.port, e.password, e.clientTLS("h2"))
		},
	},
	{
		name: "vless-tls-h2mux-padding",
		server: func(e *env) string {
			return fmt.Sprintf(`{"inbounds":[{"type":"vless","listen":"127.0.0.1","listen_port":%d,"users":[{"uuid":%q}],"tls":%s,"multiplex":{"enabled":true,"padding":true}}],%s}`, e.port, e.uuid, e.serverTLS(), directOutbound())
		},
		client: func(e *env) string {
			return fmt.Sprintf(`{"type":"vless","server":"127.0.0.1","server_port":%d,"uuid":%q,"tls":%s,"multiplex":{"enabled":true,"protocol":"h2mux","padding":true}}`, e.port, e.uuid, e.clientTLS())
		},
	},
	{
		name: "socks5", udp: true,
		server: func(e *env) string {
			return fmt.Sprintf(`{"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":%d}],%s}`, e.port, directOutbound())
		},
		client: func(e *env) string {
			return fmt.Sprintf(`{"type":"socks","server":"127.0.0.1","server_port":%d,"version":"5"}`, e.port)
		},
	},
	{
		name: "socks4",
		server: func(e *env) string {
			return fmt.Sprintf(`{"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":%d}],%s}`, e.port, directOutbound())
		},
		client: func(e *env) string {
			return fmt.Sprintf(`{"type":"socks","server":"127.0.0.1","server_port":%d,"version":"4"}`, e.port)
		},
	},
	{
		name: "http",
		server: func(e *env) string {
			return fmt.Sprintf(`{"inbounds":[{"type":"http","listen":"127.0.0.1","listen_port":%d}],%s}`, e.port, directOutbound())
		},
		client: func(e *env) string {
			return fmt.Sprintf(`{"type":"http","server":"127.0.0.1","server_port":%d}`, e.port)
		},
	},
	{
		name: "anytls", udp: true,
		server: func(e *env) string {
			return fmt.Sprintf(`{"inbounds":[{"type":"anytls","listen":"127.0.0.1","listen_port":%d,"users":[{"password":%q}],"tls":%s}],%s}`, e.port, e.password, e.serverTLS(), directOutbound())
		},
		client: func(e *env) string {
			return fmt.Sprintf(`{"type":"anytls","server":"127.0.0.1","server_port":%d,"password":%q,"tls":%s}`, e.port, e.password, e.clientTLS())
		},
	},
	{
		name: "tuic", udpPort: true, udp: true,
		server: func(e *env) string {
			return fmt.Sprintf(`{"inbounds":[{"type":"tuic","listen":"127.0.0.1","listen_port":%d,"users":[{"uuid":%q,"password":%q}],"congestion_control":"bbr","tls":%s}],%s}`, e.port, e.uuid, e.password, e.serverTLS("h3"), directOutbound())
		},
		client: func(e *env) string {
			return fmt.Sprintf(`{"type":"tuic","server":"127.0.0.1","server_port":%d,"uuid":%q,"password":%q,"congestion_control":"bbr","udp_relay_mode":"native","tls":%s}`, e.port, e.uuid, e.password, e.clientTLS("h3"))
		},
	},
	{
		name: "hysteria", udpPort: true, udp: true,
		server: func(e *env) string {
			return fmt.Sprintf(`{"inbounds":[{"type":"hysteria","listen":"127.0.0.1","listen_port":%d,"up_mbps":100,"down_mbps":100,"users":[{"auth_str":%q}],"obfs":"zed-obfs","tls":%s}],%s}`, e.port, e.password, e.serverTLS("h3"), directOutbound())
		},
		client: func(e *env) string {
			return fmt.Sprintf(`{"type":"hysteria","server":"127.0.0.1","server_port":%d,"up_mbps":100,"down_mbps":100,"auth_str":%q,"obfs":"zed-obfs","tls":%s}`, e.port, e.password, e.clientTLS("h3"))
		},
	},
	{
		name: "hysteria2", udpPort: true, udp: true,
		server: func(e *env) string {
			return fmt.Sprintf(`{"inbounds":[{"type":"hysteria2","listen":"127.0.0.1","listen_port":%d,"users":[{"password":%q}],"obfs":{"type":"salamander","password":"zed"},"tls":%s}],%s}`, e.port, e.password, e.serverTLS("h3"), directOutbound())
		},
		client: func(e *env) string {
			return fmt.Sprintf(`{"type":"hysteria2","server":"127.0.0.1","server_port":%d,"password":%q,"obfs":{"type":"salamander","password":"zed"},"tls":%s}`, e.port, e.password, e.clientTLS("h3"))
		},
	},
	{
		name: "snell-v6",
		server: func(e *env) string {
			return fmt.Sprintf(`{"inbounds":[{"type":"snell","version":6,"listen":"127.0.0.1","listen_port":%d,"psk":%q}],%s}`, e.port, e.password, directOutbound())
		},
		client: func(e *env) string {
			return fmt.Sprintf(`{"type":"snell","version":6,"server":"127.0.0.1","server_port":%d,"psk":%q}`, e.port, e.password)
		},
	},
	{
		name: "naive",
		server: func(e *env) string {
			return fmt.Sprintf(`{"inbounds":[{"type":"naive","listen":"127.0.0.1","listen_port":%d,"users":[{"username":"zed","password":%q}],"tls":%s}],%s}`, e.port, e.password, e.serverTLS(), directOutbound())
		},
		client: func(e *env) string {
			return fmt.Sprintf(`{"type":"naive","server":"127.0.0.1","server_port":%d,"username":"zed","password":%q,"tls":%s}`, e.port, e.password, e.clientTLS())
		},
	},
	{
		name: "wireguard", udpPort: true, udp: true, target: "10.77.0.9",
		server: func(e *env) string {
			return fmt.Sprintf(`{"endpoints":[{"type":"wireguard","tag":"wg-in","address":["10.77.0.1/32"],"private_key":%q,"listen_port":%d,"peers":[{"public_key":%q,"allowed_ips":["10.77.0.2/32"]}]}],%s,"route":{"rules":[{"inbound":"wg-in","action":"route-options","override_address":"127.0.0.1"}],"final":"direct"}}`, e.wgServer[0], e.port, e.wgClient[1], directOutbound())
		},
		client: func(e *env) string {
			return fmt.Sprintf(`{"endpoints":[{"type":"wireguard","tag":"wg-out","address":["10.77.0.2/32"],"private_key":%q,"peers":[{"address":"127.0.0.1","port":%d,"public_key":%q,"allowed_ips":["0.0.0.0/0"]}]}]}`, e.wgClient[0], e.port, e.wgServer[1])
		},
	},
}

// clientSettings wraps a client-side sing-box fragment as the settings of the Xray outbound. An
// object with "type" is a single outbound; anything else is taken as a whole fragment.
func clientSettings(fragment string, viaXray bool) string {
	if strings.Contains(fragment, `"endpoints"`) || strings.Contains(fragment, `"outbounds"`) {
		return fmt.Sprintf(`{"config":%s,"viaXray":%t}`, fragment, viaXray)
	}
	return fmt.Sprintf(`{"outbound":%s,"viaXray":%t}`, fragment, viaXray)
}

func TestEveryProtocolEndToEnd(t *testing.T) {
	for _, viaXray := range []bool{false, true} {
		for _, c := range protocolCases {
			c := c
			name := c.name
			if viaXray {
				name += "/via-xray"
			}
			t.Run(name, func(t *testing.T) {
				e := newEnv(t)
				if c.udpPort {
					e.port = uint16(udp.PickPort())
				} else {
					e.port = uint16(tcp.PickPort())
				}
				requireClientBuilt(t, c.client(e))
				startSingBoxServer(t, c.server(e))
				// sing-box starts its listeners asynchronously for some protocols.
				time.Sleep(150 * time.Millisecond)
				target := c.target
				if target == "" {
					target = "127.0.0.1"
				}
				client := startXrayTo(t, e, target, clientSettings(c.client(e), viaXray))

				if err := roundTripTCP(client.tcpPort, 256*1024); err != nil {
					t.Fatalf("tcp: %v", err)
				}
				if c.udp {
					if err := roundTripUDP(client.udpPort); err != nil {
						t.Fatalf("udp: %v", err)
					}
				}
				if up := client.counter(t, "outbound>>>proxy>>>traffic>>>uplink"); up <= 0 {
					t.Errorf("uplink counter did not move (%d)", up)
				}
				if down := client.counter(t, "outbound>>>proxy>>>traffic>>>downlink"); down <= 0 {
					t.Errorf("downlink counter did not move (%d)", down)
				}
			})
		}
	}
}

// A sing-box protocol reached through another Xray outbound: the path the app uses for fragmenting
// and proxy chains. The hop must see the traffic, and QUIC must survive the trip through Xray's
// buffered pipes, which is where datagram boundaries could be lost.
func TestViaXrayUsesTheDialerProxyChain(t *testing.T) {
	for _, c := range []protocolCase{protocolCases[5], protocolCases[15]} { // trojan-tls, hysteria2
		c := c
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			if c.udpPort {
				e.port = uint16(udp.PickPort())
			} else {
				e.port = uint16(tcp.PickPort())
			}
			startSingBoxServer(t, c.server(e))
			time.Sleep(150 * time.Millisecond)
			settings := clientSettings(c.client(e), true)
			hop := `{"tag":"hop","protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]}}`
			client := startXrayWithSockopt(t, e, settings, `{"sockopt":{"dialerProxy":"hop"}}`, hop)
			if err := roundTripTCP(client.tcpPort, 128*1024); err != nil {
				t.Fatalf("tcp: %v", err)
			}
			if c.udp {
				if err := roundTripUDP(client.udpPort); err != nil {
					t.Fatalf("udp: %v", err)
				}
			}
			if down := client.counter(t, "outbound>>>hop>>>traffic>>>downlink"); down <= 0 {
				t.Errorf("the dialer proxy hop carried nothing (%d)", down)
			}
		})
	}
}

func startXrayWithSockopt(t *testing.T, e *env, settings, streamSettings string, extraOutbounds ...string) *xrayClient {
	t.Helper()
	tcpPort := uint16(tcp.PickPort())
	udpPort := uint16(udp.PickPort())
	outbounds := []string{fmt.Sprintf(`{"tag":"proxy","protocol":"singbox","settings":%s,"streamSettings":%s}`, settings, streamSettings)}
	outbounds = append(outbounds, extraOutbounds...)
	config := fmt.Sprintf(`{
		"log": {"loglevel": "warning"},
		"stats": {},
		"policy": {"system": {"statsOutboundUplink": true, "statsOutboundDownlink": true}},
		"inbounds": [
			{"tag": "tcp-in", "listen": "127.0.0.1", "port": %d, "protocol": "dokodemo-door",
			 "settings": {"address": "127.0.0.1", "port": %d, "network": "tcp"}},
			{"tag": "udp-in", "listen": "127.0.0.1", "port": %d, "protocol": "dokodemo-door",
			 "settings": {"address": "127.0.0.1", "port": %d, "network": "udp"}}
		],
		"outbounds": [%s],
		"routing": {"rules": [{"type": "field", "inboundTag": ["tcp-in", "udp-in"], "outboundTag": "proxy"}]}
	}`, tcpPort, e.echoTCP, udpPort, e.echoUDP, strings.Join(outbounds, ","))
	coreConfig, err := serial.LoadJSONConfig(strings.NewReader(config))
	if err != nil {
		t.Fatalf("xray config: %v", err)
	}
	instance, err := core.New(coreConfig)
	if err != nil {
		t.Fatalf("xray: %v", err)
	}
	if err := instance.Start(); err != nil {
		t.Fatalf("xray start: %v", err)
	}
	t.Cleanup(func() { instance.Close() })
	return &xrayClient{instance: instance, tcpPort: tcpPort, udpPort: udpPort}
}

// ShadowTLS wraps another outbound: the carrier is the Shadowsocks outbound, which dials through the
// ShadowTLS one by its own detour — a chain inside the fragment that viaXray must leave alone.
func TestShadowTLSChainInsideTheFragment(t *testing.T) {
	for _, viaXray := range []bool{false, true} {
		t.Run(fmt.Sprintf("viaXray=%t", viaXray), func(t *testing.T) {
			e := newEnv(t)
			handshake := startTLSHandshakeServer(t, e)
			e.port = uint16(tcp.PickPort())
			e.aux = uint16(tcp.PickPort())
			server := fmt.Sprintf(`{"inbounds":[
				{"type":"shadowtls","listen":"127.0.0.1","listen_port":%d,"version":3,"users":[{"password":%q}],
				 "handshake":{"server":"127.0.0.1","server_port":%d},"detour":"ss-in"},
				{"type":"shadowsocks","tag":"ss-in","listen":"127.0.0.1","listen_port":%d,"method":"2022-blake3-aes-128-gcm","password":%q}
			],%s}`, e.port, e.password, handshake, e.aux, e.ss2022, directOutbound())
			startSingBoxServer(t, server)
			time.Sleep(150 * time.Millisecond)
			fragment := fmt.Sprintf(`{"outbounds":[
				{"type":"shadowsocks","tag":"ss","method":"2022-blake3-aes-128-gcm","password":%q,"detour":"stls"},
				{"type":"shadowtls","tag":"stls","server":"127.0.0.1","server_port":%d,"version":3,"password":%q,
				 "tls":%s}
			]}`, e.ss2022, e.port, e.password, e.clientTLS())
			client := startXray(t, e, fmt.Sprintf(`{"config":%s,"use":"ss","viaXray":%t}`, fragment, viaXray))
			if err := roundTripTCP(client.tcpPort, 128*1024); err != nil {
				t.Fatalf("tcp: %v", err)
			}
		})
	}
}

// startTLSHandshakeServer is the "real website" ShadowTLS borrows its handshake from.
func startTLSHandshakeServer(t *testing.T, e *env) uint16 {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(e.certPath, e.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	return uint16(listener.Addr().(*gonet.TCPAddr).Port)
}

// ---- configuration --------------------------------------------------------------------------------

func buildFails(t *testing.T, settings string, want string) {
	t.Helper()
	config := fmt.Sprintf(`{"outbounds":[{"tag":"proxy","protocol":"singbox","settings":%s}]}`, settings)
	coreConfig, err := serial.LoadJSONConfig(strings.NewReader(config))
	if err == nil {
		var instance *core.Instance
		instance, err = core.New(coreConfig)
		if err == nil {
			instance.Close()
		}
	}
	if err == nil {
		t.Fatalf("expected an error containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not mention %q", err, want)
	}
}

func TestConfigThatWouldListenIsRefused(t *testing.T) {
	buildFails(t, `{"config":{"inbounds":[{"type":"mixed","listen_port":1080}],"outbounds":[{"type":"direct"}]}}`, "inbounds are not allowed")
	buildFails(t, `{"config":{"outbounds":[{"type":"direct"}],"experimental":{"clash_api":{"external_controller":"127.0.0.1:9090"}}}}`, "experimental")
	buildFails(t, `{"config":{"services":[{"type":"resolved"}],"outbounds":[{"type":"direct"}]}}`, "services are not allowed")
}

func TestConfigErrorsAreClear(t *testing.T) {
	buildFails(t, `{}`, "no sing-box outbound or endpoint")
	buildFails(t, `{"outbound":{"type":"nonexistent-protocol","server":"x"}}`, "decode config")
	buildFails(t, `{"outbound":{"type":"trojan","tag":"a","server":"127.0.0.1","server_port":1,"password":"p"},"use":"b"}`, "no outbound or endpoint tagged b")
	buildFails(t, `{"outbound":{"type":"direct","tag":"zed-xray-dialer"}}`, "reserved")
}

// The JSON forms all end up as one fragment: a single outbound, extra outbounds, endpoints, and a
// config given as an object or as a string.
func TestConfigFormsMerge(t *testing.T) {
	e := newEnv(t)
	e.port = uint16(tcp.PickPort())
	c := protocolCases[5] // trojan-tls
	startSingBoxServer(t, c.server(e))
	time.Sleep(150 * time.Millisecond)

	asString, _ := json.Marshal(fmt.Sprintf(`{"outbounds":[%s]}`, c.client(e)))
	for name, settings := range map[string]string{
		"outbound":        fmt.Sprintf(`{"outbound":%s}`, c.client(e)),
		"outbounds":       fmt.Sprintf(`{"outbounds":[%s]}`, c.client(e)),
		"config-object":   fmt.Sprintf(`{"config":{"outbounds":[%s]}}`, c.client(e)),
		"config-string":   fmt.Sprintf(`{"config":%s}`, asString),
		"merged-with-use": fmt.Sprintf(`{"outbound":{"type":"block","tag":"nothing"},"outbounds":[%s],"use":"t"}`, strings.Replace(c.client(e), `"type":"trojan"`, `"type":"trojan","tag":"t"`, 1)),
		"direct-skipped":  fmt.Sprintf(`{"outbounds":[{"type":"direct","tag":"d"},%s]}`, c.client(e)),
	} {
		t.Run(name, func(t *testing.T) {
			client := startXray(t, e, settings)
			if err := roundTripTCP(client.tcpPort, 16*1024); err != nil {
				t.Fatalf("tcp: %v", err)
			}
		})
	}
}

// A server that is down fails the connection — quickly and with Xray's dial-failure wording, which
// is what auto-select keys its retry on — and does not stop the Xray instance.
func TestUnreachableServerFailsTheConnectionOnly(t *testing.T) {
	e := newEnv(t)
	dead := uint16(tcp.PickPort())
	client := startXray(t, e, fmt.Sprintf(`{"outbound":{"type":"trojan","server":"127.0.0.1","server_port":%d,"password":"p","tls":%s}}`, dead, e.clientTLS()))
	started := time.Now()
	err := roundTripTCP(client.tcpPort, 1024)
	if err == nil {
		t.Fatal("expected the connection to fail")
	}
	if elapsed := time.Since(started); elapsed > 15*time.Second {
		t.Fatalf("failing took %v", elapsed)
	}
}

// Auto-select over sing-box members: a dead one and a live one. Traffic has to reach the echo server
// through the live member, however the group starts.
func TestAutoSelectOverSingboxMembers(t *testing.T) {
	e := newEnv(t)
	e.port = uint16(udp.PickPort())
	live := protocolCases[15] // hysteria2
	startSingBoxServer(t, live.server(e))
	time.Sleep(150 * time.Millisecond)
	dead := uint16(tcp.PickPort())
	probe := httptest.NewServer(gonethttp.HandlerFunc(func(w gonethttp.ResponseWriter, r *gonethttp.Request) {
		w.WriteHeader(gonethttp.StatusNoContent)
	}))
	defer probe.Close()

	tcpPort := uint16(tcp.PickPort())
	config := fmt.Sprintf(`{
		"log": {"loglevel": "warning"},
		"inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": %d, "protocol": "dokodemo-door",
		              "settings": {"address": "127.0.0.1", "port": %d, "network": "tcp"}}],
		"outbounds": [
			{"tag": "proxy", "protocol": "autoselect", "settings": {"outbounds": ["proxy@0", "proxy@1"], "initial": "proxy@0",
			  "probeURL": %q, "probeTimeout": "2s"}},
			{"tag": "proxy@0", "protocol": "singbox", "settings": {"outbound": {"type":"trojan","server":"127.0.0.1","server_port":%d,"password":"p","tls":%s}}},
			{"tag": "proxy@1", "protocol": "singbox", "settings": {"outbound": %s}}
		]
	}`, tcpPort, e.echoTCP, probe.URL+"/generate_204", dead, e.clientTLS(), live.client(e))
	coreConfig, err := serial.LoadJSONConfig(strings.NewReader(config))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := core.New(coreConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.Close()

	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if lastErr = roundTripTCP(tcpPort, 64*1024); lastErr == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("auto-select never got through the live sing-box member: %v", lastErr)
}

// Starting a group of many sing-box members does not wait for their instances: Xray's own start returns
// while every one of them is still held back, and traffic flows once they may start.
func TestManySingboxMembersDoNotHoldXrayStart(t *testing.T) {
	e := newEnv(t)
	e.port = uint16(tcp.PickPort())
	c := protocolCases[0]
	startSingBoxServer(t, c.server(e))
	time.Sleep(150 * time.Millisecond)

	release := make(chan struct{})
	defer singbox.HoldStarts(release)()

	const members = 24
	var tags, outbounds []string
	for i := 0; i < members; i++ {
		tags = append(tags, fmt.Sprintf("%q", fmt.Sprintf("proxy@%d", i)))
		outbounds = append(outbounds, fmt.Sprintf(`{"tag": "proxy@%d", "protocol": "singbox", "settings": %s}`, i, clientSettings(c.client(e), false)))
	}
	tcpPort := uint16(tcp.PickPort())
	config := fmt.Sprintf(`{
		"log": {"loglevel": "warning"},
		"inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": %d, "protocol": "dokodemo-door",
		              "settings": {"address": "127.0.0.1", "port": %d, "network": "tcp"}}],
		"outbounds": [{"tag": "proxy", "protocol": "autoselect", "settings": {"outbounds": [%s], "initial": "proxy@0"}}, %s]
	}`, tcpPort, e.echoTCP, strings.Join(tags, ","), strings.Join(outbounds, ","))
	coreConfig, err := serial.LoadJSONConfig(strings.NewReader(config))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := core.New(coreConfig)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan error, 1)
	go func() { started <- instance.Start() }()
	select {
	case err := <-started:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("Xray's start waited for the sing-box instances")
	}
	defer instance.Close()

	close(release)
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if lastErr = roundTripTCP(tcpPort, 64*1024); lastErr == nil {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("no traffic once the members could start: %v", lastErr)
}

// Closing Xray closes the sing-box instances: a new instance can take the same server port straight
// away, and the old outbound refuses work instead of leaking.
func TestCloseStopsTheInstance(t *testing.T) {
	e := newEnv(t)
	e.port = uint16(tcp.PickPort())
	c := protocolCases[0]
	startSingBoxServer(t, c.server(e))
	time.Sleep(150 * time.Millisecond)
	client := startXray(t, e, clientSettings(c.client(e), false))
	if err := roundTripTCP(client.tcpPort, 1024); err != nil {
		t.Fatal(err)
	}
	if err := client.instance.Close(); err != nil {
		t.Fatal(err)
	}
	if err := roundTripTCP(client.tcpPort, 1024); err == nil {
		t.Fatal("the closed instance still carried traffic")
	}
}
