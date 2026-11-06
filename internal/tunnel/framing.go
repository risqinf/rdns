package tunnel

import (
	"encoding/binary"
	"io"
)

// MaxDatagramSize is the maximum size of a single datagram forwarded over a yamux stream (64KB).
const MaxDatagramSize = 65535

// WriteDatagram writes a length-prefixed datagram: [2-byte uint16 length BE][payload].
func WriteDatagram(w io.Writer, p []byte) error {
	if len(p) > MaxDatagramSize {
		p = p[:MaxDatagramSize]
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(p)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}

// ReadDatagram reads a length-prefixed datagram from r into buf.
// Returns the number of bytes read.
func ReadDatagram(r io.Reader, buf []byte) (int, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, err
	}
	length := int(binary.BigEndian.Uint16(lenBuf[:]))
	if len(buf) < length {
		tmp := make([]byte, length)
		if _, err := io.ReadFull(r, tmp); err != nil {
			return 0, err
		}
		return copy(buf, tmp), nil
	}
	if _, err := io.ReadFull(r, buf[:length]); err != nil {
		return 0, err
	}
	return length, nil
}
