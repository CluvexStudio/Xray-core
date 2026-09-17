package singbox

import (
	"context"
	"reflect"
	"strings"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	sboutbound "github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

// xrayDialerType is the outbound type, private to these instances, that dials through the Xray
// outbound hosting them.
const xrayDialerType = "zed-xray-dialer"

// xrayDialerTag is the tag that outbound gets. sing-box tags live in the instance's own namespace,
// so it cannot collide with anything in the user's config unless they copy it on purpose.
const xrayDialerTag = "zed-xray-dialer"

// newBoxContext is sing-box's usual registry context plus the Xray dialer outbound. xrayDialer may
// be nil when the outbound is not asked to dial through Xray.
func newBoxContext(xrayDialer internet.Dialer) context.Context {
	outboundRegistry := include.OutboundRegistry()
	sboutbound.Register[option.StubOptions](outboundRegistry, xrayDialerType,
		func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, _ option.StubOptions) (adapter.Outbound, error) {
			if xrayDialer == nil {
				return nil, errors.New("singbox: no Xray dialer to dial through")
			}
			return newXrayDialerOutbound(tag, xrayDialer), nil
		})
	return box.Context(context.Background(),
		include.InboundRegistry(),
		outboundRegistry,
		include.EndpointRegistry(),
		include.DNSTransportRegistry(),
		include.ServiceRegistry(),
		include.CertificateProviderRegistry(),
	)
}

// prepareOptions parses the config's sing-box fragment and shapes it for use as an outbound: what
// may not run here is refused, the carrying outbound is picked, and — with via_xray — dials are
// pointed at Xray. It returns the options and the carrier's tag.
func prepareOptions(ctx context.Context, config *Config) (option.Options, string, error) {
	raw := strings.TrimSpace(config.Config)
	if raw == "" {
		return option.Options{}, "", errors.New("singbox: empty config")
	}
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(raw))
	if err != nil {
		return option.Options{}, "", errors.New("singbox: decode config").Base(err)
	}

	// This instance only ever dials out. Anything that would listen or serve on the device from
	// inside an Xray outbound is refused rather than silently started.
	if len(options.Inbounds) > 0 {
		return option.Options{}, "", errors.New("singbox: inbounds are not allowed in an outbound")
	}
	if len(options.Services) > 0 {
		return option.Options{}, "", errors.New("singbox: services are not allowed in an outbound")
	}
	if experimental := options.Experimental; experimental != nil &&
		(experimental.ClashAPI != nil || experimental.V2RayAPI != nil || experimental.CacheFile != nil) {
		return option.Options{}, "", errors.New("singbox: experimental APIs and cache files are not allowed in an outbound")
	}
	if len(options.Endpoints) == 0 && len(options.Outbounds) == 0 {
		return option.Options{}, "", errors.New("singbox: the config has no outbound or endpoint")
	}

	for _, outbound := range options.Outbounds {
		if outbound.Tag == xrayDialerTag || outbound.Type == xrayDialerType {
			return option.Options{}, "", errors.New("singbox: ", xrayDialerTag, " is reserved")
		}
	}
	for _, endpoint := range options.Endpoints {
		if endpoint.Tag == xrayDialerTag {
			return option.Options{}, "", errors.New("singbox: ", xrayDialerTag, " is reserved")
		}
	}

	carrier, err := pickCarrier(&options, config.Use)
	if err != nil {
		return option.Options{}, "", err
	}

	if config.ViaXray {
		for i := range options.Endpoints {
			setDetour(options.Endpoints[i].Options, xrayDialerTag)
		}
		for i := range options.Outbounds {
			setDetour(options.Outbounds[i].Options, xrayDialerTag)
		}
		options.Outbounds = append(options.Outbounds, option.Outbound{
			Type:    xrayDialerType,
			Tag:     xrayDialerTag,
			Options: &option.StubOptions{},
		})
	}

	if options.Log == nil {
		options.Log = &option.LogOptions{Level: "warn"}
	}
	return options, carrier, nil
}

// pickCarrier returns the tag of the outbound or endpoint that carries traffic, naming untagged
// entries the way sing-box would so a config without tags still works.
func pickCarrier(options *option.Options, use string) (string, error) {
	for i := range options.Endpoints {
		if options.Endpoints[i].Tag == "" {
			options.Endpoints[i].Tag = "endpoint-" + itoa(i)
		}
	}
	for i := range options.Outbounds {
		if options.Outbounds[i].Tag == "" {
			options.Outbounds[i].Tag = "outbound-" + itoa(i)
		}
	}
	if use != "" {
		for _, endpoint := range options.Endpoints {
			if endpoint.Tag == use {
				return use, nil
			}
		}
		for _, outbound := range options.Outbounds {
			if outbound.Tag == use {
				return use, nil
			}
		}
		return "", errors.New("singbox: no outbound or endpoint tagged ", use)
	}
	if len(options.Endpoints) > 0 {
		return options.Endpoints[0].Tag, nil
	}
	for _, outbound := range options.Outbounds {
		switch outbound.Type {
		case C.TypeDirect, C.TypeBlock, C.TypeDNS:
			continue
		}
		return outbound.Tag, nil
	}
	return options.Outbounds[0].Tag, nil
}

// dialerOptionsType is the option struct every dialing outbound and endpoint embeds.
var dialerOptionsType = reflect.TypeOf(option.DialerOptions{})

// setDetour points the dialer of one outbound's or endpoint's typed options at tag, unless it
// already dials through something of its own (a chain inside the fragment) or does not dial at all
// (groups, block, dns). It reports whether it changed anything.
func setDetour(options any, tag string) bool {
	value := reflect.ValueOf(options)
	if !value.IsValid() || value.Kind() != reflect.Pointer || value.IsNil() {
		return false
	}
	dialer := findDialerOptions(value.Elem(), 0)
	if !dialer.IsValid() {
		return false
	}
	detour := dialer.FieldByName("Detour")
	if !detour.CanSet() || detour.String() != "" {
		return false
	}
	detour.SetString(tag)
	return true
}

// findDialerOptions looks for an embedded option.DialerOptions, following embedded structs only:
// a named field holding dialer options belongs to something else (a nested transport's own dial).
func findDialerOptions(value reflect.Value, depth int) reflect.Value {
	if depth > 4 || value.Kind() != reflect.Struct {
		return reflect.Value{}
	}
	if value.Type() == dialerOptionsType {
		return value
	}
	for i := 0; i < value.NumField(); i++ {
		field := value.Type().Field(i)
		if !field.Anonymous {
			continue
		}
		inner := value.Field(i)
		if inner.Kind() == reflect.Pointer {
			if inner.IsNil() {
				continue
			}
			inner = inner.Elem()
		}
		if found := findDialerOptions(inner, depth+1); found.IsValid() {
			return found
		}
	}
	return reflect.Value{}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}
