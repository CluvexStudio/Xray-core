// Package singbox is the "singbox" outbound: traffic Xray routes to it is carried by a sing-box
// outbound or endpoint running in-process.
//
// It is how every protocol sing-box speaks — AnyTLS, TUIC, Hysteria, ShadowTLS, Naive, Snell, SSH,
// WireGuard and Tailscale endpoints, its multiplexing and TLS options — becomes usable from an Xray
// config while Xray keeps doing everything around it: routing, DNS, balancers, auto-select and
// chaining. Each outbound runs its own small sing-box instance that holds only outbounds and
// endpoints; it never listens.
package singbox

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

// Outbound carries Xray connections over a sing-box outbound or endpoint.
type Outbound struct {
	config  *Config
	options option.Options
	boxCtx  context.Context
	carrier string

	// counters are this handler's traffic counters. When sing-box dials its servers itself they are
	// updated here, from the payload; through Xray's dialer the handler counts the wire instead.
	uplink, downlink stats.Counter

	startOnce sync.Once
	mu        sync.Mutex
	instance  *box.Box
	dialer    N.Dialer
	startErr  error
	closed    bool
}

// New validates the sing-box fragment and prepares the instance. Nothing dials until Xray starts.
func New(ctx context.Context, config *Config) (*Outbound, error) {
	o := &Outbound{config: config}

	var xrayDialer internet.Dialer
	if handler := session.FullHandlerFromContext(ctx); handler != nil {
		xrayDialer, _ = handler.(internet.Dialer)
		if config.ViaXray && xrayDialer == nil {
			return nil, errors.New("singbox: viaXray needs an outbound handler to dial through")
		}
		if !config.ViaXray {
			o.uplink, o.downlink = handlerCounters(ctx, handler.Tag())
		}
	} else if config.ViaXray {
		return nil, errors.New("singbox: viaXray needs an outbound handler to dial through")
	}

	o.boxCtx = newBoxContext(xrayDialer)
	options, carrier, err := prepareOptions(o.boxCtx, config)
	if err != nil {
		return nil, err
	}
	o.options = options
	o.carrier = carrier

	// sing-box instances open sockets and start background work as soon as they start, and a
	// config is also loaded just to be checked. So the instance starts with Xray, not here.
	if instance := core.FromContext(ctx); instance != nil {
		if err := instance.AddFeature(&starter{o: o}); err != nil {
			return nil, err
		}
	}
	return o, nil
}

// starter ties the sing-box instance to the Xray instance's lifecycle.
type starter struct{ o *Outbound }

func (s *starter) Type() interface{} { return (*starter)(nil) }

// warmUps bounds how many sing-box instances start in the background at once. Creating and starting
// one takes milliseconds (several times that on a phone), and an auto-select group can hold dozens.
var warmUps = make(chan struct{}, 4)

// beforeBoxStart, when set, runs as an instance begins to start. Tests use it to hold starts back.
var beforeBoxStart atomic.Pointer[func()]

func (s *starter) Start() error {
	// In the background, so the instance does not wait for them: started one by one here, a group of
	// many sing-box servers held Xray's start — and with it the connection — until the last one was up.
	// A connection that needs an outbound before its turn comes starts it on the spot (see Process).
	// An outbound that cannot start (a bad key, an endpoint that cannot bind) must not take the whole
	// Xray instance down with it either way: the error is reported on every connection instead.
	go func() {
		warmUps <- struct{}{}
		defer func() { <-warmUps }()
		if err := s.o.start(); err != nil {
			errors.LogWarning(context.Background(), "singbox: ", err)
		}
	}()
	return nil
}

func (s *starter) Close() error { return s.o.Close() }

func (o *Outbound) start() error {
	o.startOnce.Do(func() {
		if hook := beforeBoxStart.Load(); hook != nil {
			(*hook)()
		}
		o.mu.Lock()
		defer o.mu.Unlock()
		if o.closed {
			o.startErr = errors.New("singbox: closed")
			return
		}
		instance, err := box.New(box.Options{Context: o.boxCtx, Options: o.options})
		if err != nil {
			o.startErr = errors.New("singbox: create instance").Base(err)
			return
		}
		if err := instance.Start(); err != nil {
			instance.Close()
			o.startErr = errors.New("singbox: start instance").Base(err)
			return
		}
		dialer, err := findCarrier(instance, o.carrier)
		if err != nil {
			instance.Close()
			o.startErr = err
			return
		}
		o.instance = instance
		o.dialer = dialer
	})
	return o.startErr
}

func findCarrier(instance *box.Box, tag string) (N.Dialer, error) {
	if endpoint, found := instance.Endpoint().Get(tag); found {
		return endpoint, nil
	}
	if outbound, found := instance.Outbound().Outbound(tag); found {
		return outbound, nil
	}
	return nil, errors.New("singbox: no outbound or endpoint tagged ", tag)
}

// Close stops the sing-box instance.
func (o *Outbound) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed = true
	if o.instance != nil {
		err := o.instance.Close()
		o.instance = nil
		o.dialer = nil
		return err
	}
	return nil
}

// Process implements proxy.Outbound.
func (o *Outbound) Process(ctx context.Context, link *transport.Link, _ internet.Dialer) error {
	if err := o.start(); err != nil {
		return err
	}
	o.mu.Lock()
	dialer := o.dialer
	o.mu.Unlock()
	if dialer == nil {
		return errors.New("singbox: closed")
	}

	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "singbox"
	// sing-box writes through its own connections; nothing here can be spliced.
	ob.CanSpliceCopy = 3
	destination := ob.Target

	var inboundConn net.Conn
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		inboundConn = inbound.Conn
	}
	if session.TimeoutOnlyFromContext(ctx) {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(context.Background())
		defer cancel()
	}

	errors.LogInfo(ctx, "tunneling request to ", destination, " via sing-box ", o.carrier)

	if destination.Network == net.Network_TCP {
		conn, err := dialer.DialContext(ctx, N.NetworkTCP, singbridge.ToSocksaddr(destination))
		if err != nil {
			// Nothing of the client's data has been read yet, so this is a failure to reach the
			// destination in Xray's terms — the wording retry logic (auto-select) keys on.
			return errors.New("failed to find an available destination").Base(err)
		}
		if read, write := o.countFuncs(); read != nil || write != nil {
			// sing's own counting wrapper, not Xray's: it passes the connection's extended
			// capabilities through, so copying keeps its fast paths.
			conn = bufio.NewCounterConn(conn, read, write)
		}
		return singbridge.CopyConn(ctx, inboundConn, link, conn)
	}

	packetConn, err := dialer.ListenPacket(ctx, singbridge.ToSocksaddr(destination))
	if err != nil {
		return errors.New("failed to find an available destination").Base(err)
	}
	var serverConn N.PacketConn = bufio.NewPacketConn(packetConn)
	if read, write := o.countFuncs(); read != nil || write != nil {
		// A wrapper that hides the inner connection's header room makes the copy allocate buffers
		// without it, and the first protocol that prepends a header panics. sing's counter
		// exposes its upstream, so the room is still found.
		serverConn = bufio.NewCounterPacketConn(serverConn, read, write)
	}

	var clientConn N.PacketConn
	if pc, isPacketConn := inboundConn.(N.PacketConn); isPacketConn {
		clientConn = pc
	} else if nc, isNetPacket := inboundConn.(net.PacketConn); isNetPacket {
		clientConn = bufio.NewPacketConn(nc)
	} else {
		clientConn = &singbridge.PacketConnWrapper{
			Reader: link.Reader,
			Writer: link.Writer,
			Conn:   inboundConn,
			Dest:   destination,
			T: signal.CancelAfterInactivity(ctx, func() {
				common.Interrupt(link.Reader)
				common.Close(packetConn)
			}, 300*time.Second),
		}
	}
	defer packetConn.Close()
	return singbridge.ReturnError(bufio.CopyPacketConn(ctx, clientConn, serverConn))
}

// handlerCounters returns the traffic counters Xray keeps for the outbound tagged tag, when the
// policy asks for them.
func handlerCounters(ctx context.Context, tag string) (uplink, downlink stats.Counter) {
	instance := core.FromContext(ctx)
	if instance == nil || tag == "" {
		return nil, nil
	}
	policyManager, _ := instance.GetFeature(policy.ManagerType()).(policy.Manager)
	statsManager, _ := instance.GetFeature(stats.ManagerType()).(stats.Manager)
	if policyManager == nil || statsManager == nil {
		return nil, nil
	}
	system := policyManager.ForSystem()
	if system.Stats.OutboundUplink {
		uplink, _ = statsManager.GetOrRegisterCounter("outbound>>>" + tag + ">>>traffic>>>uplink")
	}
	if system.Stats.OutboundDownlink {
		downlink, _ = statsManager.GetOrRegisterCounter("outbound>>>" + tag + ">>>traffic>>>downlink")
	}
	return uplink, downlink
}

// countFuncs are the handler's traffic counters in the form sing's counting wrappers take; nil when
// Xray's dialer already counts this outbound's traffic.
func (o *Outbound) countFuncs() (read, write []N.CountFunc) {
	if o.downlink != nil {
		counter := o.downlink
		read = []N.CountFunc{func(n int64) { counter.Add(n) }}
	}
	if o.uplink != nil {
		counter := o.uplink
		write = []N.CountFunc{func(n int64) { counter.Add(n) }}
	}
	return read, write
}

var _ adapter.Outbound = (*xrayDialerOutbound)(nil)
