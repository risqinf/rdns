package acme

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	m, err := New(Config{
		Domain:   "exit.example",
		CacheDir: filepath.Join(dir, "acme"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestHTTPHandlerNonChallengeIs404(t *testing.T) {
	t.Setenv("ACME_SERVER", "https://pebble.invalid/dir")
	m := newTestManager(t)
	h := m.HTTPHandler()

	for _, path := range []string{"/", "/index.html", "/api/status", "/foo/bar"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s → %d; want 404 (no relay on :80)", path, w.Code)
		}
	}
}

func TestHTTPHandlerChallengePathNot405(t *testing.T) {
	t.Setenv("ACME_SERVER", "https://pebble.invalid/dir")
	m := newTestManager(t)
	h := m.HTTPHandler()

	// A GET on the challenge path for an unknown token: autocert will not
	// return 405 (method not allowed). It returns 404 (token unknown) or
	// a key-auth value — both acceptable here; the point is the path is
	// recognized as a challenge route, not a generic 404 handler that
	// would also 404 POSTs with 405.
	req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/deadbeef", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code == http.StatusMethodNotAllowed {
		t.Error("challenge path returned 405; should be recognized")
	}
}

func TestNewRequiresDomain(t *testing.T) {
	if _, err := New(Config{CacheDir: t.TempDir()}); err == nil {
		t.Error("New with empty domain: want error")
	}
}

func TestDefaultCacheDir(t *testing.T) {
	// CacheDir default should not panic; just verify New succeeds with a
	// writable temp override (we can't write to /var/lib in tests).
	_ = os.Getenv
	dir := t.TempDir()
	if _, err := New(Config{Domain: "x.example", CacheDir: dir}); err != nil {
		t.Errorf("New: %v", err)
	}
}
