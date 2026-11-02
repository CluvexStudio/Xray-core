package wireguard

import (
	"context"
	"net"
	"net/netip"
	"time"
)

const attemptDelay = 250 * time.Millisecond

func interleaveAddrs(first, second []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(first)+len(second))
	for i := 0; i < len(first) || i < len(second); i++ {
		if i < len(first) {
			out = append(out, first[i])
		}
		if i < len(second) {
			out = append(out, second[i])
		}
	}
	return out
}

type tcpAttempt struct {
	conn net.Conn
	err  error
}

func (tnet *Net) raceTCP(ctx context.Context, addrs []netip.AddrPort) (net.Conn, error) {
	results := make(chan tcpAttempt, len(addrs))
	cancels := make([]context.CancelFunc, 0, len(addrs))
	defer func() {
		for _, cancel := range cancels {
			cancel()
		}
	}()
	next, running := 0, 0
	launch := func() {
		attemptCtx, cancel := context.WithCancel(ctx)
		cancels = append(cancels, cancel)
		addr := addrs[next]
		next++
		running++
		go func() {
			conn, err := tnet.DialContextTCPAddrPort(attemptCtx, addr)
			results <- tcpAttempt{conn, err}
		}()
	}
	launch()
	timer := time.NewTimer(attemptDelay)
	defer timer.Stop()
	var firstErr error
	for running > 0 {
		select {
		case result := <-results:
			running--
			if result.err == nil {
				if running > 0 {
					go closeLate(results, running)
				}
				return result.conn, nil
			}
			if firstErr == nil {
				firstErr = result.err
			}
			if next < len(addrs) {
				launch()
				timer.Reset(attemptDelay)
			}
		case <-timer.C:
			if next < len(addrs) {
				launch()
				timer.Reset(attemptDelay)
			}
		}
	}
	if firstErr == nil {
		firstErr = &net.OpError{Op: "dial", Err: errMissingAddress}
	}
	return nil, firstErr
}

func closeLate(results <-chan tcpAttempt, pending int) {
	for ; pending > 0; pending-- {
		if result := <-results; result.conn != nil {
			result.conn.Close()
		}
	}
}
