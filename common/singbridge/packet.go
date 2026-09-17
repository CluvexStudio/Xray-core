package singbridge

import (
	"context"
	"sync"
	"time"

	B "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
)

func CopyPacketConn(ctx context.Context, inboundConn net.Conn, link *transport.Link, destination net.Destination, serverConn net.PacketConn) error {
	cancel := func() {
		common.Interrupt(link.Reader)
		common.Interrupt(serverConn)
	}
	conn := &PacketConnWrapper{
		Reader: link.Reader,
		Writer: link.Writer,
		Dest:   destination,
		Conn:   inboundConn,
		T:      signal.CancelAfterInactivity(ctx, cancel, 300*time.Second),
	}
	return ReturnError(bufio.CopyPacketConn(ctx, conn, bufio.NewPacketConn(serverConn)))
}

type PacketConnWrapper struct {
	buf.Reader
	buf.Writer
	net.Conn
	Dest net.Destination

	// cached holds the datagrams of a multi-buffer read that did not fit in one ReadPacket. Close
	// runs on the copy's other goroutine while a read is in flight, so both go through mu.
	mu     sync.Mutex
	cached buf.MultiBuffer
	closed bool

	// A simple patch to avoid goroutine leak since sing infra cannot awake read block by write err
	T *signal.ActivityTimer
}

func (w *PacketConnWrapper) ReadPacket(buffer *B.Buffer) (addr M.Socksaddr, err error) {
	w.T.Update()
	defer func() {
		if err != nil {
			// uplinkonly
			w.T.SetTimeout(2 * time.Second)
		}
	}()
	if destination, ok := w.takeCached(buffer); ok {
		return destination, nil
	}
	mb, err := w.ReadMultiBuffer()
	nb, bb := buf.SplitFirst(mb)
	if bb == nil {
		// A failed read with nothing in it used to come back as an empty packet and no error,
		// which left the copy loop spinning on a closed link.
		if err != nil {
			return M.Socksaddr{}, err
		}
		return M.Socksaddr{}, nil
	}
	buffer.Write(bb.Bytes())
	destination := w.Dest
	if bb.UDP != nil {
		destination = *bb.UDP
	}
	bb.Release()
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		buf.ReleaseMulti(nb)
	} else {
		w.cached = nb
		w.mu.Unlock()
	}
	return ToSocksaddr(destination), nil
}

// takeCached moves the next cached datagram into buffer.
func (w *PacketConnWrapper) takeCached(buffer *B.Buffer) (M.Socksaddr, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cached == nil {
		return M.Socksaddr{}, false
	}
	mb, bb := buf.SplitFirst(w.cached)
	if bb == nil {
		w.cached = nil
		return M.Socksaddr{}, false
	}
	buffer.Write(bb.Bytes())
	w.cached = mb
	destination := w.Dest
	if bb.UDP != nil {
		destination = *bb.UDP
	}
	bb.Release()
	return ToSocksaddr(destination), true
}

func (w *PacketConnWrapper) WritePacket(buffer *B.Buffer, destination M.Socksaddr) (err error) {
	w.T.Update()
	defer func() {
		if err != nil {
			// downlinkonly
			w.T.SetTimeout(5 * time.Second)
		}
	}()
	endpoint, err := ToDestination(destination, net.Network_UDP)
	if err != nil {
		return err
	}
	vBuf := buf.New()
	vBuf.Write(buffer.Bytes())
	vBuf.UDP = &endpoint
	return w.WriteMultiBuffer(buf.MultiBuffer{vBuf})
}

func (w *PacketConnWrapper) Close() error {
	w.mu.Lock()
	cached := w.cached
	w.cached = nil
	w.closed = true
	w.mu.Unlock()
	buf.ReleaseMulti(cached)
	return nil
}
