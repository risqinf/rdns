// Package tunnel implements the rdns-client ⇄ rdns-server protocol
// (PRD §10): a yamux session over mTLS, where each stream
// is one relayed connection (TCP or UDP). Streams carry a protocol and
// destination header followed by payload bytes.
package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Proto identifies the transport protocol of the relayed connection.
type Proto byte

const (
	ProtoTCP Proto = 0x01
	ProtoUDP Proto = 0x02
)

// maxHostLen is the byte budget for the destination host. It matches the
// DNS name limit, so any resolvable domain fits.
const maxHostLen = 255

// ErrHostTooLong — destination host exceeds maxHostLen bytes.
var ErrHostTooLong = errors.New("tunnel: destination host too long")

// ErrBadHost — malformed or empty destination header.
var ErrBadHost = errors.New("tunnel: malformed destination header")

// ErrBadProto — unknown or unsupported transport protocol.
var ErrBadProto = errors.New("tunnel: unsupported protocol")

// writeDest writes the stream header:
// [1 byte proto][1 byte hostLen][host][2 byte port BE].
// A trailing dot on the host is stripped (FQDN normalization).
func writeDest(w io.Writer, proto Proto, host string, port uint16) error {
	if proto != ProtoTCP && proto != ProtoUDP {
		return fmt.Errorf("%w: %#x", ErrBadProto, proto)
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return errors.New("tunnel: empty destination host")
	}
	if len(host) > maxHostLen {
		return fmt.Errorf("%w: %d > %d", ErrHostTooLong, len(host), maxHostLen)
	}
	var head [4]byte
	head[0] = byte(proto)
	head[1] = byte(len(host))
	binary.BigEndian.PutUint16(head[2:4], port)
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err := io.WriteString(w, host)
	return err
}

// readDest reads and validates the stream header:
// [1 byte proto][1 byte hostLen][host][2 byte port BE].
func readDest(r io.Reader) (proto Proto, host string, port uint16, err error) {
	var head [4]byte
	if _, err = io.ReadFull(r, head[:]); err != nil {
		return 0, "", 0, err
	}
	proto = Proto(head[0])
	if proto != ProtoTCP && proto != ProtoUDP {
		return 0, "", 0, fmt.Errorf("%w: %#x", ErrBadProto, proto)
	}
	n := int(head[1])
	port = binary.BigEndian.Uint16(head[2:4])
	if n == 0 || n > maxHostLen {
		return 0, "", 0, ErrBadHost
	}
	buf := make([]byte, n)
	if _, err = io.ReadFull(r, buf); err != nil {
		return 0, "", 0, err
	}
	host = string(buf)
	if host == "" {
		return 0, "", 0, ErrBadHost
	}
	return proto, host, port, nil
}
