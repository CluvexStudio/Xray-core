package singbox

import (
	"context"
	"io"
	gonet "net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	sboutbound "github.com/sagernet/sing-box/adapter/outbound"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// singAddr is sing's address type, named here to keep signatures readable next to Xray's.
type singAddr = M.Socksaddr

// xrayDialerOutbound is the sing-box outbound that dials through the Xray outbound hosting the
// instance, so the connections sing-box makes to its servers get that outbound's sockopt, its
// `dialerProxy` chain (fragmenting, proxy chains) and its traffic counters.
type xrayDialerOutbound struct {
	sboutbound.Adapter
	dialer internet.Dialer
}

func newXrayDialerOutbound(tag string, dialer internet.Dialer) adapter.Outbound {
	return &xrayDialerOutbound{
		Adapter: sboutbound.NewAdapter(xrayDialerType, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		dialer:  dialer,
	}
}

func (d *xrayDialerOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	dest, err := singbridge.ToDestination(destination, singbridge.ToNetwork(network))
	if err != nil {
		return nil, err
	}
	return d.dialer.Dial(ctx, dest)
}

func (d *xrayDialerOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return newXrayPacketConn(ctx, d.dialer), nil
}

// xrayPacketConn is an unconnected packet socket made of Xray's connected ones: one per remote
// address, dialed on first write. sing-box's QUIC protocols expect to write to a server address —
// several, with port hopping — while Xray's dialer hands out a connection per destination.
type xrayPacketConn struct {
	ctx    context.Context
	cancel context.CancelFunc
	dialer internet.Dialer

	mu      sync.Mutex
	conns   map[string]*udpFlow
	closed  bool
	packets chan udpPacket
	local   net.Addr

	deadlineMu sync.Mutex
	deadline   time.Time
}

type udpFlow struct {
	conn net.Conn
	addr M.Socksaddr
}

type udpPacket struct {
	data []byte
	from M.Socksaddr
	err  error
}

func newXrayPacketConn(ctx context.Context, dialer internet.Dialer) *xrayPacketConn {
	ctx, cancel := context.WithCancel(ctx)
	return &xrayPacketConn{
		ctx:     ctx,
		cancel:  cancel,
		dialer:  dialer,
		conns:   make(map[string]*udpFlow),
		packets: make(chan udpPacket, 256),
		local:   &net.UDPAddr{IP: gonet.IPv4zero, Port: 0},
	}
}

func (c *xrayPacketConn) flow(addr M.Socksaddr) (*udpFlow, error) {
	key := addr.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, gonet.ErrClosed
	}
	if flow, found := c.conns[key]; found {
		return flow, nil
	}
	dest, err := singbridge.ToDestination(addr, net.Network_UDP)
	if err != nil {
		return nil, err
	}
	conn, err := c.dialer.Dial(c.ctx, dest)
	if err != nil {
		return nil, err
	}
	flow := &udpFlow{conn: conn, addr: addr}
	c.conns[key] = flow
	go c.readLoop(flow)
	return flow, nil
}

// readLoop keeps datagram boundaries. A connection through a `dialerProxy` chain is a pipe of
// buffers, and reading it as a byte stream would glue datagrams together — fatal to QUIC — so it
// is read buffer by buffer when it can be.
func (c *xrayPacketConn) readLoop(flow *udpFlow) {
	conn := flow.conn
	var counter stats.Counter
	if counted, ok := conn.(*stat.CounterConnection); ok {
		if reader, isBufReader := counted.Connection.(buf.Reader); isBufReader {
			counter = counted.ReadCounter
			c.readBuffers(flow, reader, counter)
			return
		}
	}
	if reader, isBufReader := conn.(buf.Reader); isBufReader {
		c.readBuffers(flow, reader, nil)
		return
	}
	for {
		data := make([]byte, 65535)
		n, err := conn.Read(data)
		if err != nil {
			c.deliver(udpPacket{from: flow.addr, err: err})
			return
		}
		c.deliver(udpPacket{data: data[:n], from: flow.addr})
	}
}

func (c *xrayPacketConn) readBuffers(flow *udpFlow, reader buf.Reader, counter stats.Counter) {
	for {
		mb, err := reader.ReadMultiBuffer()
		for _, b := range mb {
			if b == nil {
				continue
			}
			data := make([]byte, b.Len())
			copy(data, b.Bytes())
			if counter != nil {
				counter.Add(int64(len(data)))
			}
			from := flow.addr
			if b.UDP != nil {
				from = singbridge.ToSocksaddr(*b.UDP)
			}
			c.deliver(udpPacket{data: data, from: from})
		}
		buf.ReleaseMulti(mb)
		if err != nil {
			c.deliver(udpPacket{from: flow.addr, err: err})
			return
		}
	}
}

func (c *xrayPacketConn) deliver(packet udpPacket) {
	select {
	case c.packets <- packet:
	case <-c.ctx.Done():
	}
}

func (c *xrayPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var timeout <-chan time.Time
	c.deadlineMu.Lock()
	deadline := c.deadline
	c.deadlineMu.Unlock()
	if !deadline.IsZero() {
		wait := time.Until(deadline)
		if wait <= 0 {
			return 0, nil, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(wait)
		defer timer.Stop()
		timeout = timer.C
	}
	for {
		select {
		case packet := <-c.packets:
			if packet.err != nil {
				c.drop(packet.from)
				if packet.err == io.EOF {
					continue
				}
				// One flow failing (a hop closed its port) is not the end of the socket; only
				// losing every flow is.
				if c.flowCount() > 0 {
					continue
				}
				return 0, nil, packet.err
			}
			n := copy(p, packet.data)
			// The address the flow was dialed with, so a write back to it finds the same flow — a
			// server named by domain has no IP here to rebuild it from.
			return n, packet.from, nil
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-c.ctx.Done():
			return 0, nil, gonet.ErrClosed
		}
	}
}

func (c *xrayPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	flow, err := c.flow(M.SocksaddrFromNet(addr))
	if err != nil {
		return 0, err
	}
	n, err := flow.conn.Write(p)
	if err != nil {
		c.drop(flow.addr)
	}
	return n, err
}

func (c *xrayPacketConn) drop(addr M.Socksaddr) {
	c.mu.Lock()
	flow, found := c.conns[addr.String()]
	if found {
		delete(c.conns, addr.String())
	}
	c.mu.Unlock()
	if found {
		flow.conn.Close()
	}
}

func (c *xrayPacketConn) flowCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.conns)
}

func (c *xrayPacketConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	conns := c.conns
	c.conns = nil
	c.mu.Unlock()
	c.cancel()
	for _, flow := range conns {
		flow.conn.Close()
	}
	return nil
}

func (c *xrayPacketConn) LocalAddr() net.Addr { return c.local }

func (c *xrayPacketConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

func (c *xrayPacketConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.deadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *xrayPacketConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.PacketConn = (*xrayPacketConn)(nil)
