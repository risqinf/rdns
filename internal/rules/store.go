package rules

import "sync"

// Store holds the currently-active Ruleset and supports atomic swap on
// reload (SIGHUP). Match never takes the write lock, so the reloader can
// run on any goroutine without stalling the data path.
type Store struct {
	mu  sync.RWMutex
	cur *Ruleset
}

// NewStore returns a Store initialized with rs.
func NewStore(rs *Ruleset) *Store { return &Store{cur: rs} }

// Match delegates to the current snapshot.
func (s *Store) Match(domain string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur.Match(domain)
}

// Current returns the active snapshot.
func (s *Store) Current() *Ruleset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur
}

// Swap atomically replaces the active snapshot.
func (s *Store) Swap(rs *Ruleset) {
	s.mu.Lock()
	s.cur = rs
	s.mu.Unlock()
}
