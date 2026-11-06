package rules

import (
	"testing"
)

func mustParse(t *testing.T, s string) *Ruleset {
	t.Helper()
	r, err := parse([]byte(s))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return r
}

func TestParseAndMatch(t *testing.T) {
	r := mustParse(t, `{
		"my": ["maybank2u.com.my", "astro.com.my", "iflix.com"],
		"id": ["bri.co.id", "vidio.com"]
	}`)

	cases := []struct {
		domain   string
		wantProf string
		wantOK   bool
	}{
		{"bri.co.id", "id", true},
		{"mobile.bri.co.id", "id", true}, // suffix
		{"BRI.CO.ID", "id", true},        // case-insensitive
		{"bri.co.id.", "id", true},       // trailing dot
		{"  bri.co.id  ", "id", true},    // whitespace
		{"notbri.co.id", "", false},      // no dot-boundary match
		{"xmaybank2u.com.my", "", false}, // ^ must be a label
		{"iflix.com", "my", true},
		{"static.iflix.com/cdn.js", "my", true},
		{"bri.co.id:443", "id", true},           // host:port (HTTP Host / dest)
		{"static.iflix.com/cdn.js", "my", true}, // stray path
		{"example.com", "", false},
		{"", "", false},
		{".", "", false},
	}
	for _, c := range cases {
		p, ok := r.Match(c.domain)
		if p != c.wantProf || ok != c.wantOK {
			t.Errorf("Match(%q) = (%q,%v); want (%q,%v)", c.domain, p, ok, c.wantProf, c.wantOK)
		}
	}

	if got := r.Size(); got != 5 {
		t.Errorf("Size() = %d; want 5", got)
	}
	profs := r.Profiles()
	if len(profs) != 2 || profs[0] != "id" || profs[1] != "my" {
		t.Errorf("Profiles() = %v; want [id my]", profs)
	}
}

func TestLongestSuffixWins(t *testing.T) {
	r := mustParse(t, `{
		"my": ["iflix.com"],
		"id": ["com"]
	}`)
	if p, _ := r.Match("iflix.com"); p != "my" {
		t.Errorf("iflix.com → %q; want my (exact rule beats broader)", p)
	}
	if p, _ := r.Match("google.com"); p != "id" {
		t.Errorf("google.com → %q; want id (broad rule)", p)
	}
}

func TestNormalization(t *testing.T) {
	// Uppercase profile names are normalized, not rejected: a "My" vs "my"
	// typo must not silently fail-closed every rule in that profile.
	r := mustParse(t, `{ "MY": ["EXAMPLE.COM."] }`)
	if p, ok := r.Match("example.com"); p != "my" || !ok {
		t.Errorf("Match(example.com) = (%q,%v); want (my,true) — profiles also lowercase", p, ok)
	}
	profs := r.Profiles()
	if len(profs) != 1 || profs[0] != "my" {
		t.Errorf("Profiles() = %v; want [my]", profs)
	}
}

func TestLoadFileRejectsInvalid(t *testing.T) {
	bad := []string{
		``,                                     // empty
		`{}`,                                   // no profiles
		`{ "my": [] }`,                         // profile without domains
		`{ "my 2": ["example.com"] }`,          // bad profile charset
		`{ "my": ["EXAMPLE$COM"] }`,            // bad label
		`{ "my": ["x..com"] }`,                 // empty label
		`{ "my": ["a.b.c"], "id": ["A.B.C"] }`, // duplicate pattern across profiles
		`{ "my": ["a.com"], "My": ["b.com"] }`, // duplicate profile, case-insensitive
		`not json`,
	}
	for _, s := range bad {
		if _, err := parse([]byte(s)); err == nil {
			t.Errorf("parse(%q) = nil error; want error", s)
		}
	}

	// Missing file.
	if _, err := LoadFile("no-such-file.json"); err == nil {
		t.Error("LoadFile(missing) = nil; want error")
	}
}

func TestStoreSwap(t *testing.T) {
	a := mustParse(t, `{"my": ["a.com"]}`)
	b := mustParse(t, `{"id": ["b.com"]}`)

	s := NewStore(a)
	if p, _ := s.Match("a.com"); p != "my" {
		t.Fatalf("before swap: Match(a.com) = %q; want my", p)
	}
	s.Swap(b)
	if p, ok := s.Match("a.com"); ok {
		t.Errorf("after swap: Match(a.com) = %q; want no match", p)
	}
	if p, _ := s.Match("b.com"); p != "id" {
		t.Errorf("after swap: Match(b.com) = %q; want id", p)
	}
}
