package wireguard

import (
	"context"
	"net/netip"
	"strings"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

var fullTunnelProbes = []netip.Addr{
	netip.MustParseAddr("1.1.1.1"),
	netip.MustParseAddr("64.0.0.1"),
	netip.MustParseAddr("129.0.0.1"),
	netip.MustParseAddr("200.0.0.1"),
}

type allowedRoutes []netip.Prefix

func splitRoutes(peers []*PeerConfig) allowedRoutes {
	var routes allowedRoutes
	for _, peer := range peers {
		for _, value := range peer.AllowedIps {
			value = strings.TrimSpace(value)
			if prefix, err := netip.ParsePrefix(value); err == nil {
				routes = append(routes, prefix.Masked())
			} else if addr, err := netip.ParseAddr(value); err == nil {
				routes = append(routes, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
			}
		}
	}
	if len(routes) == 0 {
		return nil
	}
	for _, probe := range fullTunnelProbes {
		if !routes.contains(probe) {
			return routes
		}
	}
	return nil
}

func (r allowedRoutes) contains(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range r {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (r allowedRoutes) containsIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	return ok && r.contains(addr)
}

func (h *Handler) outside(ctx context.Context, dest net.Destination) (bool, net.Destination) {
	if h.routes == nil {
		return false, dest
	}
	if !dest.Address.Family().IsDomain() {
		return !h.routes.containsIP(dest.Address.IP()), dest
	}
	if content := session.ContentFromContext(ctx); content != nil && content.SkipDNSResolve {
		return true, dest
	}
	if h.dns == nil {
		return true, dest
	}
	ips, _, err := h.dns.LookupIP(dest.Address.Domain(), dns.IPOption{IPv4Enable: true, IPv6Enable: true})
	if err != nil || len(ips) == 0 {
		return true, dest
	}
	for _, ip := range ips {
		if h.routes.containsIP(ip) {
			return false, dest
		}
	}
	pick := ips[0]
	for _, ip := range ips {
		if ip.To4() != nil {
			pick = ip
			break
		}
	}
	return true, net.Destination{Network: dest.Network, Address: net.IPAddress(pick), Port: dest.Port}
}

func (h *Handler) directSockopt(dest net.Destination) *internet.SocketConfig {
	if h.sockopt == nil || !dest.Address.Family().IsDomain() || !h.sockopt.DomainStrategy.HasStrategy() {
		return h.sockopt
	}
	sockopt := proto.Clone(h.sockopt).(*internet.SocketConfig)
	sockopt.DomainStrategy = internet.DomainStrategy_AS_IS
	return sockopt
}
