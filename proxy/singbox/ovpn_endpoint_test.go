package singbox_test

import (
	"context"
	"os"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func TestOpenVPNEndpointBuilds(t *testing.T) {
	raw, err := os.ReadFile("/tmp/ovpn-fragment.json")
	if err != nil {
		t.Skip("no fragment to check")
	}
	ctx := box.Context(context.Background(),
		include.InboundRegistry(),
		include.OutboundRegistry(),
		include.EndpointRegistry(),
		include.DNSTransportRegistry(),
		include.ServiceRegistry(),
		include.CertificateProviderRegistry(),
	)
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	options.Log = &option.LogOptions{Level: "warn"}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatalf("box.New: %v", err)
	}
	defer instance.Close()
	if err := instance.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, found := instance.Endpoint().Get("ovpn-test"); !found {
		t.Fatal("the endpoint is not registered under its tag")
	}
	t.Log("openvpn endpoint built and started")
}
