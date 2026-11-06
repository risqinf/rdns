// Package quicx extracts the Server Name Indication (SNI) from QUIC Initial
// packets without terminating or proxying the QUIC handshake (RFC 9001/9000).
//
// It implements:
//   - QUIC v1 (RFC 9000 / RFC 9001) and QUIC v2 (RFC 9369) Initial key derivation
//   - Header protection removal (AES-ECB sampling)
//   - Packet payload decryption (AES-128-GCM)
//   - Frame parsing (CRYPTO frames, ACK, PADDING, PING)
//   - Multi-packet CRYPTO frame reassembly for fragmented ClientHello messages
//   - TLS 1.3 ClientHello server_name extension extraction
package quicx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Standard QUIC Initial salts.
var (
	// RFC 9001 §5.2 for QUIC v1 (0x00000001).
	saltV1 = []byte{
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
		0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
		0xcc, 0xbb, 0x7f, 0x0a,
	}
	// RFC 9369 §5.2 for QUIC v2 (0x6b3343cf).
	saltV2 = []byte{
		0x0d, 0xbe, 0xe3, 0x7b, 0x0e, 0x97, 0x43, 0xf4,
		0xfb, 0x34, 0x61, 0xf8, 0xb3, 0x80, 0xc2, 0xe8,
		0xb2, 0xa3, 0x25, 0x29,
	}
)

const (
	Version1 = uint32(0x00000001)
	Version2 = uint32(0x6b3343cf)
)

var (
	ErrNotQUIC          = errors.New("quicx: not a QUIC packet")
	ErrNotInitial       = errors.New("quicx: not a QUIC Initial packet")
	ErrUnsupportedVer   = errors.New("quicx: unsupported QUIC version")
	ErrPacketTooShort   = errors.New("quicx: packet too short")
	ErrDecryptFailed    = errors.New("quicx: payload decryption failed")
	ErrNoCryptoFrame    = errors.New("quicx: no CRYPTO frame found")
	ErrClientHelloSplit = errors.New("quicx: ClientHello fragmented, needs more packets")
	ErrNoSNI            = errors.New("quicx: no SNI in ClientHello")
)

// InitialKeys holds the derived secrets for protecting/unprotecting Initial packets.
type InitialKeys struct {
	ClientKey []byte
	ClientIV  []byte
	ClientHP  []byte
}

// DeriveInitialKeys derives the client Initial secrets from the DCID.
func DeriveInitialKeys(version uint32, dcid []byte) (*InitialKeys, error) {
	var salt []byte
	switch version {
	case Version1:
		salt = saltV1
	case Version2:
		salt = saltV2
	default:
		return nil, fmt.Errorf("%w: %#x", ErrUnsupportedVer, version)
	}

	// initial_secret = HKDF-Extract(salt, dcid)
	h := hkdf.Extract(sha256.New, dcid, salt)

	// client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
	clientSecret, err := hkdfExpandLabel(h, "client in", nil, 32)
	if err != nil {
		return nil, err
	}

	// key = HKDF-Expand-Label(client_initial_secret, "quic key", "", 16)
	key, err := hkdfExpandLabel(clientSecret, "quic key", nil, 16)
	if err != nil {
		return nil, err
	}

	// iv = HKDF-Expand-Label(client_initial_secret, "quic iv", "", 12)
	iv, err := hkdfExpandLabel(clientSecret, "quic iv", nil, 12)
	if err != nil {
		return nil, err
	}

	// hp = HKDF-Expand-Label(client_initial_secret, "quic hp", "", 16)
	hp, err := hkdfExpandLabel(clientSecret, "quic hp", nil, 16)
	if err != nil {
		return nil, err
	}

	return &InitialKeys{
		ClientKey: key,
		ClientIV:  iv,
		ClientHP:  hp,
	}, nil
}

// hkdfExpandLabel implements RFC 8446 / RFC 9001 §5.1:
//
//	HKDF-Expand-Label(Secret, Label, Context, Length) =
//	    HKDF-Expand(Secret, HkdfLabel, Length)
//
//	struct {
//	    uint16 length = Length;
//	    opaque label<7..255> = "tls13 " + Label;
//	    opaque context<0..255> = Context;
//	} HkdfLabel;
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	fullLabel := "tls13 " + label
	hkdfLabel := make([]byte, 2+1+len(fullLabel)+1+len(context))
	binary.BigEndian.PutUint16(hkdfLabel[0:2], uint16(length))
	hkdfLabel[2] = byte(len(fullLabel))
	copy(hkdfLabel[3:], fullLabel)
	hkdfLabel[3+len(fullLabel)] = byte(len(context))
	copy(hkdfLabel[4+len(fullLabel):], context)

	r := hkdf.Expand(sha256.New, secret, hkdfLabel)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// PacketInfo contains basic parsed fields from a QUIC Initial packet.
type PacketInfo struct {
	Version uint32
	DCID    []byte
	SCID    []byte
	Payload []byte // decrypted payload frames
}

// ParseAndDecryptInitial parses a QUIC Initial packet, unprotects its header,
// and decrypts its payload.
func ParseAndDecryptInitial(pkt []byte) (*PacketInfo, error) {
	if len(pkt) < 22 {
		return nil, ErrPacketTooShort
	}
	b0 := pkt[0]
	// Check Long Header form (bit 7) and Fixed Bit (bit 6).
	if (b0 & 0x80) == 0 {
		return nil, ErrNotQUIC
	}
	if (b0 & 0x40) == 0 {
		return nil, ErrNotQUIC
	}

	version := binary.BigEndian.Uint32(pkt[1:5])
	if version == 0 {
		return nil, ErrNotInitial // Version negotiation
	}

	// Long Packet Type: bits 4-5
	packetType := (b0 & 0x30) >> 4
	switch version {
	case Version1:
		if packetType != 0x00 { // Initial = 0x00 in v1
			return nil, ErrNotInitial
		}
	case Version2:
		if packetType != 0x01 { // Initial = 0x01 in v2
			return nil, ErrNotInitial
		}
	default:
		return nil, fmt.Errorf("%w: %#x", ErrUnsupportedVer, version)
	}

	dcidLen := int(pkt[5])
	if dcidLen > 20 || 6+dcidLen > len(pkt) {
		return nil, ErrPacketTooShort
	}
	dcid := pkt[6 : 6+dcidLen]

	scidOffset := 6 + dcidLen
	if scidOffset >= len(pkt) {
		return nil, ErrPacketTooShort
	}
	scidLen := int(pkt[scidOffset])
	if scidLen > 20 || scidOffset+1+scidLen > len(pkt) {
		return nil, ErrPacketTooShort
	}
	scid := pkt[scidOffset+1 : scidOffset+1+scidLen]

	tokenOffset := scidOffset + 1 + scidLen
	tokenLen, n, err := readVarint(pkt[tokenOffset:])
	if err != nil {
		return nil, err
	}
	tokenEnd := tokenOffset + n + int(tokenLen)
	if tokenEnd > len(pkt) {
		return nil, ErrPacketTooShort
	}

	lengthOffset := tokenEnd
	payloadLen, n, err := readVarint(pkt[lengthOffset:])
	if err != nil {
		return nil, err
	}
	pnOffset := lengthOffset + n
	totalRemaining := int(payloadLen)
	if pnOffset+totalRemaining > len(pkt) {
		return nil, ErrPacketTooShort
	}

	// Header protection sample is 16 bytes starting at pnOffset + 4.
	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(pkt) {
		return nil, ErrPacketTooShort
	}
	sample := pkt[sampleOffset : sampleOffset+16]

	keys, err := DeriveInitialKeys(version, dcid)
	if err != nil {
		return nil, err
	}

	// Unprotect header using AES-ECB with hp key
	block, err := aes.NewCipher(keys.ClientHP)
	if err != nil {
		return nil, err
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, sample)

	// Long header mask applies to lowest 4 bits of byte 0
	unprotectedB0 := b0 ^ (mask[0] & 0x0f)
	pnLen := int(unprotectedB0&0x03) + 1
	if pnOffset+pnLen > len(pkt) {
		return nil, ErrPacketTooShort
	}

	// Recover packet number
	unprotectedPN := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		unprotectedPN[i] = pkt[pnOffset+i] ^ mask[1+i]
	}

	var pn uint64
	for _, b := range unprotectedPN {
		pn = (pn << 8) | uint64(b)
	}

	// Construct Associated Data (unprotected header including packet number)
	ad := make([]byte, pnOffset+pnLen)
	copy(ad, pkt[:pnOffset+pnLen])
	ad[0] = unprotectedB0
	copy(ad[pnOffset:pnOffset+pnLen], unprotectedPN)

	// Build AEAD Nonce: IV XOR'd with 64-bit packet number in the last 8 bytes
	nonce := make([]byte, 12)
	copy(nonce, keys.ClientIV)
	var pnBytes [8]byte
	binary.BigEndian.PutUint64(pnBytes[:], pn)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= pnBytes[i]
	}

	// Decrypt payload
	aeadBlock, err := aes.NewCipher(keys.ClientKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(aeadBlock, 12)
	if err != nil {
		return nil, err
	}

	ciphertextStart := pnOffset + pnLen
	ciphertextEnd := pnOffset + totalRemaining
	ciphertext := pkt[ciphertextStart:ciphertextEnd]

	plaintext, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptFailed, err)
	}

	return &PacketInfo{
		Version: version,
		DCID:    append([]byte(nil), dcid...),
		SCID:    append([]byte(nil), scid...),
		Payload: plaintext,
	}, nil
}

// CryptoChunk represents a segment of crypto stream data.
type CryptoChunk struct {
	Offset uint64
	Data   []byte
}

// ExtractCryptoChunks extracts all CRYPTO frame chunks from decrypted payload.
func ExtractCryptoChunks(payload []byte) ([]CryptoChunk, error) {
	var chunks []CryptoChunk
	p := 0
	for p < len(payload) {
		frameType, n, err := readVarint(payload[p:])
		if err != nil {
			break
		}
		p += n

		switch frameType {
		case 0x00: // PADDING
			continue
		case 0x01: // PING
			continue
		case 0x02, 0x03: // ACK
			// Skip ACK frame
			_, n, err := readVarint(payload[p:]) // Largest Acknowledged
			if err != nil {
				return chunks, nil
			}
			p += n
			_, n, err = readVarint(payload[p:]) // ACK Delay
			if err != nil {
				return chunks, nil
			}
			p += n
			ackRangeCount, n, err := readVarint(payload[p:]) // ACK Range Count
			if err != nil {
				return chunks, nil
			}
			p += n
			_, n, err = readVarint(payload[p:]) // First ACK Range
			if err != nil {
				return chunks, nil
			}
			p += n
			for i := uint64(0); i < ackRangeCount; i++ {
				_, n, err = readVarint(payload[p:]) // Gap
				if err != nil {
					return chunks, nil
				}
				p += n
				_, n, err = readVarint(payload[p:]) // ACK Range Length
				if err != nil {
					return chunks, nil
				}
				p += n
			}
			if frameType == 0x03 { // ACK with ECN
				_, n, _ = readVarint(payload[p:])
				p += n
				_, n, _ = readVarint(payload[p:])
				p += n
				_, n, _ = readVarint(payload[p:])
				p += n
			}
		case 0x06: // CRYPTO
			offset, n, err := readVarint(payload[p:])
			if err != nil {
				return chunks, nil
			}
			p += n
			length, n, err := readVarint(payload[p:])
			if err != nil {
				return chunks, nil
			}
			p += n
			end := p + int(length)
			if end > len(payload) {
				return chunks, nil
			}
			data := payload[p:end]
			chunks = append(chunks, CryptoChunk{
				Offset: offset,
				Data:   append([]byte(nil), data...),
			})
			p = end
		default:
			// Unknown or unhandled frame, try to stop gracefully
			return chunks, nil
		}
	}
	return chunks, nil
}

// ParseClientHelloSNI parses raw TLS 1.3 Handshake ClientHello (starting with 0x01)
// and extracts the SNI server_name.
func ParseClientHelloSNI(data []byte) (string, error) {
	// Handshake header: type(1) length(3)
	if len(data) < 4 {
		return "", ErrPacketTooShort
	}
	if data[0] != 0x01 { // 0x01 = ClientHello
		return "", errors.New("quicx: not a ClientHello handshake message")
	}
	msgLen := int(uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3]))
	if len(data) < 4+msgLen {
		return "", ErrClientHelloSplit
	}

	body := data[4 : 4+msgLen]
	p := 0
	take := func(n int) bool {
		if p+n > len(body) {
			return false
		}
		p += n
		return true
	}

	// legacy_version(2) + random(32)
	if !take(2 + 32) {
		return "", ErrPacketTooShort
	}

	// legacy_session_id<0..32>
	if !take(1) {
		return "", ErrPacketTooShort
	}
	sidLen := int(body[p-1])
	if !take(sidLen) {
		return "", ErrPacketTooShort
	}

	// cipher_suites<2..2^16-2>
	if !take(2) {
		return "", ErrPacketTooShort
	}
	csLen := int(binary.BigEndian.Uint16(body[p-2 : p]))
	if !take(csLen) {
		return "", ErrPacketTooShort
	}

	// legacy_compression_methods<1..2^8-1>
	if !take(1) {
		return "", ErrPacketTooShort
	}
	cmLen := int(body[p-1])
	if !take(cmLen) {
		return "", ErrPacketTooShort
	}

	// extensions<0..2^16-1>
	if !take(2) {
		return "", ErrNoSNI
	}
	extLen := int(binary.BigEndian.Uint16(body[p-2 : p]))
	extEnd := p + extLen
	if extEnd > len(body) {
		return "", ErrPacketTooShort
	}

	for p+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[p : p+2])
		el := int(binary.BigEndian.Uint16(body[p+2 : p+4]))
		dataStart := p + 4
		if dataStart+el > extEnd {
			break
		}
		if extType == 0x0000 { // server_name
			sni := parseSNIExtension(body[dataStart : dataStart+el])
			if sni != "" {
				return sni, nil
			}
		}
		p = dataStart + el
	}

	return "", ErrNoSNI
}

func parseSNIExtension(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(b[0:2]))
	p := 2
	end := p + listLen
	if end > len(b) {
		return ""
	}
	for p+3 <= end {
		nameType := b[p]
		p++
		nameLen := int(binary.BigEndian.Uint16(b[p : p+2]))
		p += 2
		if p+nameLen > end {
			break
		}
		if nameType == 0x00 { // host_name
			return string(b[p : p+nameLen])
		}
		p += nameLen
	}
	return ""
}

// Sniffer provides stateful SNI extraction with CRYPTO frame reassembly.
type Sniffer struct {
	mu      sync.Mutex
	flows   map[string]*flowBuffer
	timeout time.Duration
}

type flowBuffer struct {
	chunks     []CryptoChunk
	lastActive time.Time
}

// NewSniffer creates a Sniffer with an idle timeout for fragmented packet reassembly.
func NewSniffer(timeout time.Duration) *Sniffer {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	s := &Sniffer{
		flows:   make(map[string]*flowBuffer),
		timeout: timeout,
	}
	go s.janitor()
	return s
}

// Feed processes a single packet for a flow key.
// Returns (sni, complete, err).
// If the packet is complete and an SNI is found, complete is true and sni is populated.
// If the packet has CRYPTO data but needs more fragments, complete is false and err is nil.
func (s *Sniffer) Feed(flowKey string, pkt []byte) (string, bool, error) {
	info, err := ParseAndDecryptInitial(pkt)
	if err != nil {
		return "", false, err
	}

	chunks, err := ExtractCryptoChunks(info.Payload)
	if err != nil || len(chunks) == 0 {
		return "", false, ErrNoCryptoFrame
	}

	s.mu.Lock()
	fb, ok := s.flows[flowKey]
	if !ok {
		fb = &flowBuffer{}
		s.flows[flowKey] = fb
	}
	fb.lastActive = time.Now()
	fb.chunks = append(fb.chunks, chunks...)
	assembled := assembleCrypto(fb.chunks)
	s.mu.Unlock()

	sni, err := ParseClientHelloSNI(assembled)
	if err == nil && sni != "" {
		s.mu.Lock()
		delete(s.flows, flowKey)
		s.mu.Unlock()
		return sni, true, nil
	}
	if errors.Is(err, ErrClientHelloSplit) {
		// Fragmented, wait for next packet
		return "", false, nil
	}

	// If it's a permanent error (e.g. no SNI or malformed)
	if errors.Is(err, ErrNoSNI) {
		s.mu.Lock()
		delete(s.flows, flowKey)
		s.mu.Unlock()
		return "", true, ErrNoSNI
	}

	return "", false, err
}

func (s *Sniffer) janitor() {
	ticker := time.NewTicker(s.timeout)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for k, fb := range s.flows {
			if now.Sub(fb.lastActive) > s.timeout {
				delete(s.flows, k)
			}
		}
		s.mu.Unlock()
	}
}

// assembleCrypto joins contiguous chunks starting at offset 0.
func assembleCrypto(chunks []CryptoChunk) []byte {
	var buf bytes.Buffer
	currentOffset := uint64(0)

	// Simple sort or loop: since Initial fragmentation is usually 2 packets,
	// find the contiguous range starting at 0.
	for {
		found := false
		for _, c := range chunks {
			if c.Offset == currentOffset && len(c.Data) > 0 {
				buf.Write(c.Data)
				currentOffset += uint64(len(c.Data))
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	return buf.Bytes()
}

// SniffPacket is a convenience one-shot helper for single-packet Initial extraction.
func SniffPacket(pkt []byte) (string, error) {
	info, err := ParseAndDecryptInitial(pkt)
	if err != nil {
		return "", err
	}
	chunks, err := ExtractCryptoChunks(info.Payload)
	if err != nil || len(chunks) == 0 {
		return "", ErrNoCryptoFrame
	}
	assembled := assembleCrypto(chunks)
	return ParseClientHelloSNI(assembled)
}

func readVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	prefix := b[0] >> 6
	length := 1 << prefix
	if len(b) < length {
		return 0, 0, io.ErrUnexpectedEOF
	}
	var val uint64
	val = uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		val = (val << 8) | uint64(b[i])
	}
	return val, length, nil
}
