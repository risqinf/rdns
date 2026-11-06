package quicx

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// RFC 9001 Appendix A.1 & A.2 test vectors
func TestRFC9001AppendixA_KeyDerivation(t *testing.T) {
	dcid, err := hex.DecodeString("8394c8f03e515708")
	if err != nil {
		t.Fatal(err)
	}

	keys, err := DeriveInitialKeys(Version1, dcid)
	if err != nil {
		t.Fatalf("DeriveInitialKeys failed: %v", err)
	}

	expectedKey := "1f369613dd76d5467730efcbe3b1a22d"
	expectedIV := "fa044b2f42a3fd3b46fb255c"
	expectedHP := "9f50449e04a0e810283a1e9933adedd2"

	if hex.EncodeToString(keys.ClientKey) != expectedKey {
		t.Errorf("ClientKey mismatch: got %x, want %s", keys.ClientKey, expectedKey)
	}
	if hex.EncodeToString(keys.ClientIV) != expectedIV {
		t.Errorf("ClientIV mismatch: got %x, want %s", keys.ClientIV, expectedIV)
	}
	if hex.EncodeToString(keys.ClientHP) != expectedHP {
		t.Errorf("ClientHP mismatch: got %x, want %s", keys.ClientHP, expectedHP)
	}
}

func TestRFC9001AppendixA_DecryptAndSNI(t *testing.T) {
	// 1200-byte protected Client Initial packet from RFC 9001 Appendix A.2
	rawHex := strings.Join([]string{
		"c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11",
		"d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399",
		"1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c",
		"8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212",
		"30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5",
		"457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208",
		"4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec",
		"4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3",
		"485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db",
		"059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c",
		"7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8",
		"9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556",
		"be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74",
		"68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a",
		"c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00",
		"f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632",
		"291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964",
		"25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd",
		"14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff",
		"ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198",
		"e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd",
		"c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73",
		"203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f",
		"cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e",
		"fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade",
		"a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047",
		"90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2",
		"162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4",
		"40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0",
		"6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e",
		"8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0",
		"be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400",
		"54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab",
		"760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9",
		"f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4",
		"056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064",
		"7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241",
		"e221af44860018ab0856972e194cd934",
	}, "")

	pkt, err := hex.DecodeString(rawHex)
	if err != nil {
		t.Fatal(err)
	}

	info, err := ParseAndDecryptInitial(pkt)
	if err != nil {
		t.Fatalf("ParseAndDecryptInitial failed: %v", err)
	}

	if info.Version != Version1 {
		t.Errorf("Version mismatch: got %#x, want %#x", info.Version, Version1)
	}
	if hex.EncodeToString(info.DCID) != "8394c8f03e515708" {
		t.Errorf("DCID mismatch: got %x", info.DCID)
	}

	chunks, err := ExtractCryptoChunks(info.Payload)
	if err != nil {
		t.Fatalf("ExtractCryptoChunks failed: %v", err)
	}
	if len(chunks) == 0 {
		t.Fatal("No CRYPTO frames extracted")
	}

	sni, err := ParseClientHelloSNI(chunks[0].Data)
	if err != nil {
		t.Fatalf("ParseClientHelloSNI failed: %v", err)
	}
	if sni != "example.com" {
		t.Fatalf("SNI mismatch: got %q, want %q", sni, "example.com")
	}

	// Also verify the one-shot SniffPacket helper
	oneShotSNI, err := SniffPacket(pkt)
	if err != nil {
		t.Fatalf("SniffPacket failed: %v", err)
	}
	if oneShotSNI != "example.com" {
		t.Fatalf("SniffPacket SNI mismatch: got %q, want %q", oneShotSNI, "example.com")
	}
}

func TestSniffer_FragmentedClientHello(t *testing.T) {
	// Build a valid synthetic TLS 1.3 ClientHello with SNI "streaming.service.com"
	ch := buildSyntheticClientHello("streaming.service.com")

	// Split ClientHello into 2 chunks
	splitAt := len(ch) / 2
	chunk1 := ch[:splitAt]
	chunk2 := ch[splitAt:]

	s := NewSniffer(100 * time.Millisecond)
	if s.timeout != 100*time.Millisecond {
		t.Errorf("Unexpected timeout: %v", s.timeout)
	}

	// Simulate feeding chunk 1 directly via assembleCrypto
	c1 := []CryptoChunk{{Offset: 0, Data: chunk1}}
	assembled1 := assembleCrypto(c1)
	_, err := ParseClientHelloSNI(assembled1)
	if err != ErrClientHelloSplit {
		t.Errorf("Expected ErrClientHelloSplit on partial chunk, got: %v", err)
	}

	// Combine chunk 1 and chunk 2
	c2 := []CryptoChunk{
		{Offset: 0, Data: chunk1},
		{Offset: uint64(splitAt), Data: chunk2},
	}
	assembled2 := assembleCrypto(c2)
	sni, err := ParseClientHelloSNI(assembled2)
	if err != nil {
		t.Fatalf("ParseClientHelloSNI failed on reassembled chunks: %v", err)
	}
	if sni != "streaming.service.com" {
		t.Errorf("SNI mismatch: got %q, want %q", sni, "streaming.service.com")
	}
}

func TestNonQUICPackets(t *testing.T) {
	// Random DNS query or plaintext UDP packet
	junk := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	_, err := SniffPacket(junk)
	if err == nil {
		t.Fatal("Expected error on junk packet, got nil")
	}
}

// buildSyntheticClientHello constructs a minimal valid TLS 1.3 ClientHello with an SNI.
func buildSyntheticClientHello(sni string) []byte {
	// server_name extension:
	// Type (2B) = 0x0000
	// Length (2B) = 2 + 1 + 2 + len(sni)
	// ServerNameList length (2B) = 1 + 2 + len(sni)
	// NameType (1B) = 0x00 (host_name)
	// HostName length (2B) = len(sni)
	// HostName = sni bytes
	sniExt := make([]byte, 4+2+1+2+len(sni))
	sniExt[0], sniExt[1] = 0x00, 0x00 // ext type: server_name
	extLen := 2 + 1 + 2 + len(sni)
	sniExt[2] = byte(extLen >> 8)
	sniExt[3] = byte(extLen)
	listLen := 1 + 2 + len(sni)
	sniExt[4] = byte(listLen >> 8)
	sniExt[5] = byte(listLen)
	sniExt[6] = 0x00 // host_name
	sniExt[7] = byte(len(sni) >> 8)
	sniExt[8] = byte(len(sni))
	copy(sniExt[9:], sni)

	// Body:
	// version: 0x0303 (2B)
	// random: 32B
	// session ID: 0 (1B)
	// cipher suites: 2B len + 2B suite (0x1301)
	// compression: 1B len + 1B (0x00)
	// extensions: 2B len + extensions
	bodyLen := 2 + 32 + 1 + 4 + 2 + 2 + len(sniExt)
	body := make([]byte, bodyLen)
	body[0], body[1] = 0x03, 0x03
	// random: leave as zeroes
	p := 34
	body[p] = 0x00 // session ID len 0
	p++
	body[p], body[p+1] = 0x00, 0x02 // cipher suites len 2
	body[p+2], body[p+3] = 0x13, 0x01
	p += 4
	body[p] = 0x01 // compression len 1
	body[p+1] = 0x00
	p += 2
	body[p] = byte(len(sniExt) >> 8)
	body[p+1] = byte(len(sniExt))
	p += 2
	copy(body[p:], sniExt)

	// Wrap in Handshake header: 0x01 + 3B length
	ch := make([]byte, 4+len(body))
	ch[0] = 0x01 // ClientHello
	ch[1] = byte(len(body) >> 16)
	ch[2] = byte(len(body) >> 8)
	ch[3] = byte(len(body))
	copy(ch[4:], body)

	return ch
}
