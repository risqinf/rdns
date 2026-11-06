package tunnel

import (
	"io"
	"net"
	"sync"
	"time"
)

// idleReadDeadline is the read silence budget for one relay direction;
// refreshed on every non-empty read. It catches stuck/half-open relays
// that neither peer keepalive nor TCP keepalive will.
const idleReadDeadline = 30 * time.Minute

// Relayer is the surface Relay pumps between. Both net.Conn and
// *yamux.Stream satisfy it: Close() is a graceful FIN on yamux and a
// full close on TCP — both correct at end-of-relay.
type Relayer interface {
	io.ReadWriteCloser
	SetReadDeadline(t time.Time) error
}

const relayBuf = 32 * 1024

// Relay pumps bytes between a and b in both directions until either side
// closes or errors, then closes both. Each direction ends with a clean
// half-close (FIN) so the peer sees EOF, not a RST. Returns bytes moved
// a→b and b→a (for logging/metrics).
func Relay(a, b Relayer) (toB, toA int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); toB = pump(b, a) }() // a → b
	go func() { defer wg.Done(); toA = pump(a, b) }() // b → a
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
	return toB, toA
}

// RelayUDP pumps length-prefixed datagrams between a stream and a UDP connection.
// It enforces an idle timeout (default 30s) since UDP has no EOF.
func RelayUDP(stream Relayer, udp *net.UDPConn, idleTimeout time.Duration) (toUDP, toStream int64) {
	if idleTimeout <= 0 {
		idleTimeout = 30 * time.Second
	}
	var wg sync.WaitGroup
	wg.Add(2)

	// Stream -> UDP
	go func() {
		defer wg.Done()
		buf := make([]byte, MaxDatagramSize)
		for {
			_ = stream.SetReadDeadline(time.Now().Add(idleTimeout))
			n, err := ReadDatagram(stream, buf)
			if err != nil {
				break
			}
			if n > 0 {
				nw, err := udp.Write(buf[:n])
				if nw > 0 {
					toUDP += int64(nw)
				}
				if err != nil {
					break
				}
			}
		}
		_ = udp.Close()
	}()

	// UDP -> Stream
	go func() {
		defer wg.Done()
		buf := make([]byte, MaxDatagramSize)
		for {
			_ = udp.SetReadDeadline(time.Now().Add(idleTimeout))
			n, err := udp.Read(buf)
			if err != nil {
				break
			}
			if n > 0 {
				if err := WriteDatagram(stream, buf[:n]); err != nil {
					break
				}
				toStream += int64(n)
			}
		}
		_ = stream.Close()
	}()

	wg.Wait()
	_ = stream.Close()
	_ = udp.Close()
	return toUDP, toStream
}

// pump reads src and writes dst until src is exhausted or an error occurs,
// then closes dst to advertise EOF to the far side. Returns bytes written.
func pump(dst, src Relayer) int64 {
	var written int64
	buf := make([]byte, relayBuf)
	_ = src.SetReadDeadline(time.Now().Add(idleReadDeadline))
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			_ = src.SetReadDeadline(time.Now().Add(idleReadDeadline))
			nw, werr := dst.Write(buf[:nr])
			written += int64(nw)
			if werr != nil {
				break
			}
		}
		if rerr != nil {
			break
		}
		// nr==0 with nil error is legal (partial read); keep going.
	}
	_ = dst.Close()
	return written
}
