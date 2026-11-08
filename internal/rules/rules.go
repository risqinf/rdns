// Package rules implements the domain→profile rule engine (PRD §9).
//
// A rule maps a domain pattern to a country profile ("my", "id", ...).
// Matching is suffix-based and case-insensitive: a rule for "bri.co.id"
// matches "bri.co.id" and "mobile.bri.co.id", but never "notbri.co.id".
//
// On lookup the LONGEST matching suffix wins, so a specific rule
// ("iflix.com" → my) can override a broader one ("com" → id). A pattern
// claimed by two different profiles is a load error — explicit beats
// implicit.
//
// A Ruleset is an immutable snapshot; reload is a whole-snapshot swap
// (see rules.Store), so readers never block on the reloader and a bad
// file leaves the old ruleset in force.
package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
)

var (
	profileRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	labelRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
)

// Ruleset is an immutable snapshot of domain rules.
type Ruleset struct {
	bySuffix map[string]string // normalized pattern -> profile
	profiles []string          // sorted profile names, for diagnostics
	size     int               // total number of patterns
}

// Match returns the profile for domain, applying longest-suffix-wins.
// An empty result means "no rule matches — direct".
//
// Inputs are normalized before lookup: an optional "/path" suffix is
// dropped, a "host:port" port is dropped (net.SplitHostPort also handles
// IPv6), and a trailing dot is stripped. This makes Match robust whether
// it's fed a bare QNAME, an SNI, or an HTTP Host header.
func (r *Ruleset) Match(domain string) (string, bool) {
	d := strings.TrimSpace(domain)
	if i := strings.IndexByte(d, '/'); i >= 0 {
		d = d[:i]
	}
	if h, _, err := net.SplitHostPort(d); err == nil {
		d = h
	}
	d = strings.ToLower(strings.TrimSuffix(d, "."))
	if d == "" {
		return "", false
	}
	for {
		if p, ok := r.bySuffix[d]; ok {
			return p, true
		}
		i := strings.Index(d, ".")
		if i < 0 {
			return "", false
		}
		d = d[i+1:] // drop the left-most label, try the next suffix
	}
}

// Profiles returns the sorted list of profile names present in the set.
func (r *Ruleset) Profiles() []string { return append([]string(nil), r.profiles...) }

// Size returns the number of domain patterns in the set.
func (r *Ruleset) Size() int { return r.size }

// parse builds a Ruleset from the canonical JSON format:
//
//	{ "my": ["maybank2u.com.my", "astro.com.my"], "id": ["bri.co.id"] }
//
// It validates every profile name and domain, rejects a pattern claimed
// by two profiles, and normalizes (lowercase, trailing-dot stripped).
func parse(data []byte) (*Ruleset, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return &Ruleset{bySuffix: make(map[string]string), profiles: make([]string, 0)}, nil
	}
	var raw map[string][]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	r := &Ruleset{bySuffix: make(map[string]string, 64), profiles: make([]string, 0)}
	if len(raw) == 0 {
		return r, nil
	}

	// Deterministic iteration order so error messages are stable.
	profiles := make([]string, 0, len(raw))
	for p := range raw {
		profiles = append(profiles, p)
	}
	sort.Strings(profiles)

	seen := make(map[string]bool, len(profiles))
	for _, p := range profiles {
		norm := strings.ToLower(p)
		if !profileRe.MatchString(norm) {
			return nil, fmt.Errorf("rules: invalid profile name %q (want [a-z0-9][a-z0-9-]{0,31})", p)
		}
		if seen[norm] {
			return nil, fmt.Errorf("rules: profile %q listed twice (case-insensitive)", p)
		}
		seen[norm] = true
		if len(raw[p]) == 0 {
			continue
		}
		for _, pat := range raw[p] {
			n, err := normalize(pat)
			if err != nil {
				return nil, fmt.Errorf("rules: profile %q: %w", norm, err)
			}
			if prev, dup := r.bySuffix[n]; dup {
				return nil, fmt.Errorf("rules: pattern %q claimed by both %q and %q", n, prev, norm)
			}
			r.bySuffix[n] = norm
			r.size++
		}
	}
	r.profiles = make([]string, 0, len(seen))
	for p := range seen {
		r.profiles = append(r.profiles, p)
	}
	sort.Strings(r.profiles)
	return r, nil
}

// normalize lowercases, strips one trailing dot, and validates as a DNS name.
func normalize(pat string) (string, error) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pat), "."))
	if d == "" {
		return "", fmt.Errorf("empty domain pattern")
	}
	for _, label := range strings.Split(d, ".") {
		if len(label) > 63 || !labelRe.MatchString(label) {
			return "", fmt.Errorf("invalid domain pattern %q (label %q)", pat, label)
		}
	}
	return d, nil
}

// LoadFile reads and parses a rules file (JSON).
func LoadFile(path string) (*Ruleset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("rules: read %s: %w", path, err)
	}
	r, err := parse(data)
	if err != nil {
		return nil, err
	}
	return r, nil
}
