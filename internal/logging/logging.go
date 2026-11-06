// Package logging builds the slog handlers both roles use (PRD §6:
// structured logging via log/slog). Output goes to stderr and, optionally,
// a file.
//
// Two debug granularities are exposed via the --debug flag:
//
//	--debug simple   app-level detail: tunnel connect/close, rule reload,
//	                 and the per-connection decision (tunnel-vs-direct,
//	                 DNS forward-vs-local). The day-to-day "what is
//	                 happening" view — one line per connection.
//	--debug full     everything, including wire-level traces (yamux stream
//	                 open/close, per-relay byte counts, every dropped DNS
//	                 packet). Very chatty — use when diagnosing why a
//	                 specific connection misroutes.
//
// The distinction is real, not cosmetic: important events log at Debug,
// noisy per-packet/per-stream events log at Trace (see LevelTrace). simple
// sets the handler to Debug (hides Trace); full sets it to Trace (shows all).
// When --debug is absent, the config's logging.level is the baseline.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// LevelTrace is below slog.LevelDebug. Events at this level are the noisy,
// wire-level traces that only --debug full should surface.
const LevelTrace = slog.Level(-8)

// Mode selects the debug granularity (from the --debug flag).
type Mode int

const (
	// ModeNone: --debug not given; fall back to config logging.level.
	ModeNone Mode = iota
	// ModeSimple: Debug and above (app-level detail).
	ModeSimple
	// ModeFull: Trace and above (everything).
	ModeFull
)

// ParseMode maps a --debug flag value to a Mode. Accepts "", "none",
// "false", "off", "0" (no debug); "simple", "true", "on", "1", "yes"
// (simple); and "full", "all", "trace" (full).
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none", "false", "off", "0":
		return ModeNone, nil
	case "simple", "true", "on", "1", "yes":
		return ModeSimple, nil
	case "full", "all", "trace":
		return ModeFull, nil
	default:
		return ModeNone, fmt.Errorf("logging: unknown debug mode %q (want simple|full)", s)
	}
}

// levelFor maps a Mode to the minimum slog level the handler emits.
func levelFor(m Mode) slog.Level {
	switch m {
	case ModeFull:
		return LevelTrace
	case ModeSimple:
		return slog.LevelDebug
	default:
		return slog.LevelInfo
	}
}

// parseConfigLevel maps a config logging.level string to a slog.Level.
func parseConfigLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trace":
		return LevelTrace, nil
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("logging: unknown level %q", s)
	}
}

// Setup returns a *slog.Logger writing to stderr plus an optional file
// (empty file = stderr only). The --debug mode overrides the config level
// when non-empty; otherwise configLevel (logging.level) is the baseline.
func Setup(mode Mode, configLevel, file string) (*slog.Logger, error) {
	lvl, err := parseConfigLevel(configLevel)
	if err != nil {
		return nil, err
	}
	if mode != ModeNone {
		lvl = levelFor(mode)
	}
	var out *os.File
	if file != "" {
		f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			return nil, fmt.Errorf("logging: open %s: %w", file, err)
		}
		out = f
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var w slog.Handler
	if out != nil {
		w = slog.NewJSONHandler(io.MultiWriter(os.Stderr, out), opts)
	} else {
		w = slog.NewJSONHandler(os.Stderr, opts)
	}
	return slog.New(w), nil
}
