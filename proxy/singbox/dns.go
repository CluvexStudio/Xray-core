package singbox

import (
	"context"
	goerrors "errors"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	boxDNS "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/xtls/xray-core/common/errors"
	xdns "github.com/xtls/xray-core/features/dns"
)

const (
	xrayDNSType   = "zed-xray-dns"
	xrayDNSTag    = "zed-xray-dns"
	systemDNSType = "zed-system-dns"
	systemDNSTag  = "zed-system-dns"
	answerTTL     = 60
)

type resolverOptions struct{}

type xrayClient struct{ xdns.Client }

type xrayResolver struct {
	client atomic.Pointer[xrayClient]
}

func (r *xrayResolver) set(client xdns.Client) {
	if client != nil {
		r.client.Store(&xrayClient{client})
	}
}

func (r *xrayResolver) lookup(_ context.Context, domain string, ipv6 bool) ([]netip.Addr, uint32, error) {
	client := r.client.Load()
	if client == nil {
		return nil, 0, errors.New("singbox: Xray DNS is not ready")
	}
	ips, ttl, err := client.LookupIP(domain, xdns.IPOption{IPv4Enable: !ipv6, IPv6Enable: ipv6})
	if err != nil {
		if ipv6 || goerrors.Is(err, xdns.ErrEmptyResponse) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	addresses := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if address, ok := netip.AddrFromSlice(ip); ok {
			addresses = append(addresses, address.Unmap())
		}
	}
	return addresses, ttl, nil
}

func systemLookup(ctx context.Context, domain string, ipv6 bool) ([]netip.Addr, uint32, error) {
	network := "ip4"
	if ipv6 {
		network = "ip6"
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, network, domain)
	if err != nil {
		var dnsErr *net.DNSError
		if ipv6 || goerrors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	return addresses, 0, nil
}

type lookupTransport struct {
	boxDNS.TransportAdapter
	lookup func(ctx context.Context, domain string, ipv6 bool) ([]netip.Addr, uint32, error)
}

func (t *lookupTransport) Start(adapter.StartStage) error { return nil }

func (t *lookupTransport) Close() error { return nil }

func (t *lookupTransport) Reset() {}

func (t *lookupTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	response := new(mDNS.Msg)
	response.SetReply(message)
	if len(message.Question) == 0 {
		return response, nil
	}
	question := message.Question[0]
	if question.Qtype != mDNS.TypeA && question.Qtype != mDNS.TypeAAAA {
		return response, nil
	}
	ipv6 := question.Qtype == mDNS.TypeAAAA
	addresses, ttl, err := t.lookup(ctx, strings.TrimSuffix(question.Name, "."), ipv6)
	if err != nil {
		return nil, err
	}
	if ttl == 0 {
		ttl = answerTTL
	}
	header := mDNS.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: mDNS.ClassINET, Ttl: ttl}
	for _, address := range addresses {
		switch {
		case !ipv6 && address.Is4():
			response.Answer = append(response.Answer, &mDNS.A{Hdr: header, A: net.IP(address.AsSlice())})
		case ipv6 && address.Is6():
			response.Answer = append(response.Answer, &mDNS.AAAA{Hdr: header, AAAA: net.IP(address.AsSlice())})
		}
	}
	return response, nil
}

func (t *lookupTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	callback(t.Exchange(ctx, message))
}

func registerResolvers(registry *boxDNS.TransportRegistry, resolver *xrayResolver) {
	boxDNS.RegisterTransport[resolverOptions](registry, xrayDNSType,
		func(_ context.Context, _ log.ContextLogger, tag string, _ resolverOptions) (adapter.DNSTransport, error) {
			return &lookupTransport{TransportAdapter: boxDNS.NewTransportAdapter(xrayDNSType, tag, nil), lookup: resolver.lookup}, nil
		})
	boxDNS.RegisterTransport[resolverOptions](registry, systemDNSType,
		func(_ context.Context, _ log.ContextLogger, tag string, _ resolverOptions) (adapter.DNSTransport, error) {
			return &lookupTransport{TransportAdapter: boxDNS.NewTransportAdapter(systemDNSType, tag, nil), lookup: systemLookup}, nil
		})
}

func addResolvers(options *option.Options) {
	if options.DNS != nil && len(options.DNS.Servers) > 0 {
		return
	}
	if options.DNS == nil {
		options.DNS = &option.DNSOptions{}
	}
	options.DNS.Servers = append(options.DNS.Servers,
		option.DNSServerOptions{Type: xrayDNSType, Tag: xrayDNSTag, Options: &resolverOptions{}},
		option.DNSServerOptions{Type: systemDNSType, Tag: systemDNSTag, Options: &resolverOptions{}},
	)
	if options.DNS.Final == "" {
		options.DNS.Final = xrayDNSTag
	}
	if options.Route == nil {
		options.Route = &option.RouteOptions{}
	}
	if options.Route.DefaultDomainResolver == nil {
		options.Route.DefaultDomainResolver = &option.DomainResolveOptions{Server: systemDNSTag}
	}
	for i := range options.Endpoints {
		setDomainResolver(options.Endpoints[i].Options, systemDNSTag)
	}
}

func setDomainResolver(options any, tag string) bool {
	value := reflect.ValueOf(options)
	if !value.IsValid() || value.Kind() != reflect.Pointer || value.IsNil() {
		return false
	}
	dialer := findDialerOptions(value.Elem(), 0)
	if !dialer.IsValid() {
		return false
	}
	field := dialer.FieldByName("DomainResolver")
	if !field.CanSet() || !field.IsNil() {
		return false
	}
	field.Set(reflect.ValueOf(&option.DomainResolveOptions{Server: tag}))
	return true
}
