package quicintercept

import (
	"context"
	"net"
	"testing"
	"time"

	"encoding/json"
	"os"
	"path/filepath"
	"rdns/internal/markdial"
	"rdns/internal/rules"
)

func rulesFrom(t *testing.T, m map[string][]string) *rules.Store {
	t.Helper()
	b, _ := json.Marshal(m)
	f := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(f, b, 0600); err != nil {
		t.Fatal(err)
	}
	rs, err := rules.LoadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	return rules.NewStore(rs)
}

func TestService_InitAndJanitor(t *testing.T) {
	store := rulesFrom(t, map[string][]string{
		"my": {"netflix.com"},
	})
	dialer := markdial.New(0)
	svc := New(nil, store, nil, dialer, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f := &Flow{
		key:        "127.0.0.1:1234->1.1.1.1:443",
		cid:        "deadbeef",
		lastActive: time.Now().Add(-100 * time.Millisecond),
		service:    svc,
	}
	svc.registerFlow(f)

	if len(svc.flows) != 1 {
		t.Errorf("expected 1 flow, got %d", len(svc.flows))
	}
	if len(svc.cidMap) != 1 {
		t.Errorf("expected 1 cid entry, got %d", len(svc.cidMap))
	}

	go svc.janitor(ctx)
	time.Sleep(100 * time.Millisecond)

	svc.mu.RLock()
	flowCount := len(svc.flows)
	cidCount := len(svc.cidMap)
	svc.mu.RUnlock()

	if flowCount != 0 || cidCount != 0 {
		t.Errorf("expected idle flows to be evicted; got %d flows, %d cids", flowCount, cidCount)
	}
}

func TestNewClientSenderFallback(t *testing.T) {
	svc := New(nil, nil, nil, markdial.New(0), 30*time.Second)

	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	clientAddr := clientConn.LocalAddr().(*net.UDPAddr)

	sender, closeFn := svc.newClientSender(clientAddr, net.ParseIP("127.0.0.1"), 443, serverConn.(*net.UDPConn))
	defer closeFn()

	testMsg := []byte("ping from sender")
	if err := sender(testMsg); err != nil {
		t.Fatalf("sender failed: %v", err)
	}

	buf := make([]byte, 1024)
	clientConn.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := clientConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("client failed to read: %v", err)
	}
	if string(buf[:n]) != string(testMsg) {
		t.Errorf("got %q, want %q", buf[:n], testMsg)
	}
}
