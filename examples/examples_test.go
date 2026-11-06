// Package examples validates the shipped example configs against the real
// loaders, so a broken example fails CI instead of a production deploy.
package examples

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rdns/internal/config"
	"rdns/internal/rules"
)

// rootDir walks up from the package dir to the repo root (where internal/
// lives), so the test works from any working directory.
func rootDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5 && filepath.Base(dir) != "rdns" && filepath.Base(dir) != ""; i++ {
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("cannot locate repo root from %s", dir)
		}
		dir = parent
	}
	if _, err := os.Stat(filepath.Join(dir, "internal")); err != nil {
		t.Fatalf("internal/ not found under %s", dir)
	}
	return dir
}

// fakeCert writes a non-empty placeholder so checkFile passes. The
// loaders in this test only validate paths + YAML shape (parsing real
// certs is covered by internal/certstore tests).
func fakeCert(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("placeholder cert for example validation\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestClientExampleIsValid(t *testing.T) {
	root := rootDir(t)
	src := filepath.Join(root, "examples", "client", "client.example.yaml")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}

	// The example points at /etc/rdns paths; remap them to a temp tree and
	// stub the files the loader checks for existence.
	tmp := t.TempDir()
	etc := filepath.Join(tmp, "etc")
	out := replaceAll(string(data), "/etc/rdns/", filepath.Join(etc, "rdns")+string(os.PathSeparator))
	cfgPath := filepath.Join(tmp, "client.yaml")
	if err := os.WriteFile(cfgPath, []byte(out), 0600); err != nil {
		t.Fatal(err)
	}

	// Stub the cert + rules files the loader requires to exist.
	fakeCert(t, filepath.Join(etc, "rdns", "ca.crt"))
	fakeCert(t, filepath.Join(etc, "rdns", "certs", "node-sg.crt"))
	fakeCert(t, filepath.Join(etc, "rdns", "certs", "node-sg.key"))
	rulesPath := filepath.Join(etc, "rdns", "rules.json")
	if err := os.WriteFile(rulesPath, []byte(`{"my":["x.com"]}`), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.LoadClient(cfgPath)
	if err != nil {
		t.Fatalf("client.example.yaml did not pass validation: %v", err)
	}
	if len(cfg.Profiles) != 2 {
		t.Errorf("profiles = %d; want 2 (my, id)", len(cfg.Profiles))
	}
	// The example relies on auto-detection (correct for dynamic/residential
	// IPs), so local_ips may be empty — but auto must be on, OR a static
	// list provided. Otherwise the node's own endpoints would be hijacked.
	if !cfg.AutoLocalEnabled() && len(cfg.LocalIPs) == 0 {
		t.Error("neither auto_local_ips nor local_ips set; the node's own endpoints would be hijacked")
	}
	if cfg.LocalIPRefresh == 0 {
		t.Error("local_ip_refresh missing; dynamic IPs need the refresh timer")
	}
	if cfg.TunnelMark == 0 {
		t.Error("tunnel_mark missing; must match the nftables SO_MARK filter")
	}
}

func TestServerExampleIsValid(t *testing.T) {
	root := rootDir(t)
	src := filepath.Join(root, "examples", "server", "server.example.yaml")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	etc := filepath.Join(tmp, "etc")
	out := replaceAll(string(data), "/etc/rdns/", filepath.Join(etc, "rdns")+"/")
	cfgPath := filepath.Join(tmp, "server.yaml")
	if err := os.WriteFile(cfgPath, []byte(out), 0600); err != nil {
		t.Fatal(err)
	}
	fakeCert(t, filepath.Join(etc, "rdns", "ca.crt"))

	cfg, err := config.LoadServer(cfgPath)
	if err != nil {
		t.Fatalf("server.example.yaml did not pass validation: %v", err)
	}
	if len(cfg.ACL.Allowed) == 0 {
		t.Error("acl.allowed empty; the public udp/53 must have an allowlist")
	}
	if cfg.TLS.Domain == "" {
		t.Error("tls.domain empty; the example must show LE mode (or a static pair)")
	}
	// Exactly three public ports, per PRD §7.
	ports := []string{cfg.Listen.DNS, cfg.Listen.Tunnel, cfg.Listen.ACME}
	for _, p := range ports {
		if p == "" {
			t.Error("a listen address is empty; the exit node needs all 3 ports")
		}
	}
}

func TestRulesExampleIsValid(t *testing.T) {
	root := rootDir(t)
	src := filepath.Join(root, "examples", "client", "rules.example.json")
	rs, err := rules.LoadFile(src)
	if err != nil {
		t.Fatalf("rules.example.json did not pass the rules loader: %v", err)
	}
	profs := rs.Profiles()
	if len(profs) == 0 {
		t.Fatal("no profiles in rules.example.json")
	}
	// The example's whole point is quick-test domains — verify the headline
	// ones actually match through the real engine.
	cases := []struct{ domain, want string }{
		{"ipinfo.io", "my"},
		{"api.ipinfo.io", "my"}, // suffix match
		{"netflix.com", "my"},
		{"assets.nflxvideo.net", "my"},
		{"speed.cloudflare.com", "my"},
		{"example.com", ""}, // unmatched → direct
	}
	for _, c := range cases {
		got, ok := rs.Match(c.domain)
		if c.want == "" {
			if ok {
				t.Errorf("Match(%q) = %q; want no match (direct)", c.domain, got)
			}
			continue
		}
		if got != c.want || !ok {
			t.Errorf("Match(%q) = (%q,%v); want (%q,true)", c.domain, got, ok, c.want)
		}
	}
}

// replaceAll rewrites every occurrence of old with new.
func replaceAll(s, old, new string) string {
	return strings.ReplaceAll(s, old, new)
}

// remapAndWrite copies a config file to a temp dir with /etc/rdns/ paths
// rewritten into the temp tree, and stubs every cert/rules file the loader
// requires to exist. Returns the temp config path and the temp etc root.
func remapAndWrite(t *testing.T, srcPath string, certFiles []string, rulesFile string) (cfgPath, etcRoot string) {
	t.Helper()
	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	etcRoot = filepath.Join(tmp, "etc")
	out := replaceAll(string(data), "/etc/rdns/", filepath.Join(etcRoot, "rdns")+string(os.PathSeparator))
	cfgPath = filepath.Join(tmp, filepath.Base(srcPath))
	if err := os.WriteFile(cfgPath, []byte(out), 0600); err != nil {
		t.Fatal(err)
	}
	for _, cf := range certFiles {
		fakeCert(t, filepath.Join(etcRoot, "rdns", cf))
	}
	if rulesFile != "" {
		if err := os.WriteFile(filepath.Join(etcRoot, "rdns", rulesFile), []byte(`{"my":["x.com"]}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return cfgPath, etcRoot
}

// The etc/ files are what SETUP.md §C tells operators to copy verbatim, so
// they must pass the real loaders too (not just the examples/ variants).

func TestEtcClientIsValid(t *testing.T) {
	root := rootDir(t)
	src := filepath.Join(root, "etc", "client.yaml")
	cfgPath, _ := remapAndWrite(t, src,
		[]string{"ca.crt", "certs/node-sg.crt", "certs/node-sg.key"}, "rules.json")
	cfg, err := config.LoadClient(cfgPath)
	if err != nil {
		t.Fatalf("etc/client.yaml did not pass validation: %v", err)
	}
	if len(cfg.Profiles) == 0 {
		t.Error("etc/client.yaml has no profiles")
	}
	if !cfg.AutoLocalEnabled() {
		t.Error("etc/client.yaml should default to auto_local_ips (residential-safe)")
	}
}

func TestEtcServerIsValid(t *testing.T) {
	root := rootDir(t)
	src := filepath.Join(root, "etc", "server.yaml")
	// etc/server.yaml is STATIC-cert mode (SETUP.md §C quick-test): it names
	// cert_file/key_file, not a domain. Stub those + the CA.
	cfgPath, _ := remapAndWrite(t, src,
		[]string{"ca.crt", "certs/exit-my.crt", "certs/exit-my.key"}, "")
	cfg, err := config.LoadServer(cfgPath)
	if err != nil {
		t.Fatalf("etc/server.yaml did not pass validation: %v", err)
	}
	if len(cfg.ACL.Allowed) == 0 {
		t.Error("etc/server.yaml has an empty acl.allowed")
	}
	if cfg.TLS.CertFile == "" || cfg.TLS.KeyFile == "" {
		t.Error("etc/server.yaml should be static-cert mode (cert_file+key_file set)")
	}
}
