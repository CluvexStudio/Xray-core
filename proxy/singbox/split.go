package singbox

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

var fullTunnelProbes = []netip.Addr{
	netip.MustParseAddr("1.1.1.1"),
	netip.MustParseAddr("64.0.0.1"),
	netip.MustParseAddr("129.0.0.1"),
	netip.MustParseAddr("200.0.0.1"),
}

var readinessProbe = M.ParseSocksaddrHostPort("1.1.1.1", 53)

func (o *Outbound) routeFor(ctx context.Context, carrier N.Dialer, destination net.Destination) N.Dialer {
	o.mu.Lock()
	routes, direct := o.routes, o.direct
	o.mu.Unlock()
	if routes == nil || direct == nil {
		return carrier
	}
	if !tunnelReady(ctx, carrier) || fullTunnel(routes) {
		return carrier
	}
	if destination.Address.Family().IsDomain() {
		domain := destination.Address.Domain()
		if routes.PreferredDomain(nil, domain) {
			return carrier
		}
		if content := session.ContentFromContext(ctx); content != nil && content.SkipDNSResolve {
			return direct
		}
		addresses := o.lookupAll(ctx, domain)
		if len(addresses) == 0 {
			return direct
		}
		for _, address := range addresses {
			if routes.PreferredAddress(nil, address) {
				return carrier
			}
		}
		return direct
	}
	address, ok := netip.AddrFromSlice(destination.Address.IP())
	if !ok || routes.PreferredAddress(nil, address.Unmap()) {
		return carrier
	}
	return direct
}

func fullTunnel(routes adapter.OutboundWithPreferredRoutes) bool {
	for _, probe := range fullTunnelProbes {
		if !routes.PreferredAddress(nil, probe) {
			return false
		}
	}
	return true
}

func tunnelReady(ctx context.Context, carrier N.Dialer) bool {
	deadline := time.Now().Add(readyWait)
	for {
		conn, err := carrier.DialContext(ctx, N.NetworkUDP, readinessProbe)
		if err == nil {
			conn.Close()
			return true
		}
		if !notReadyYet(err) || time.Now().After(deadline) {
			return false
		}
		if sleepOrDone(ctx, readyRetry) != nil {
			return false
		}
	}
}

func (o *Outbound) lookupAll(ctx context.Context, domain string) []netip.Addr {
	if o.resolver == nil {
		return nil
	}
	v4, _, _ := o.resolver.lookup(ctx, domain, false)
	v6, _, _ := o.resolver.lookup(ctx, domain, true)
	return append(v4, v6...)
}
