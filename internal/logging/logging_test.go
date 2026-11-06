package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestParseMode(t *testing.T) {
	cases := []struct {
		in   string
		want Mode
		err  bool
	}{
		{"", ModeNone, false},
		{"none", ModeNone, false},
		{"false", ModeNone, false},
		{"off", ModeNone, false},
		{"simple", ModeSimple, false},
		{"SIMPLE", ModeSimple, false},
		{" true", ModeSimple, false},
		{"on", ModeSimple, false},
		{"full", ModeFull, false},
		{"all", ModeFull, false},
		{"trace", ModeFull, false},
		{"bogus", ModeNone, true},
	}
	for _, c := range cases {
		got, err := ParseMode(c.in)
		if (err != nil) != c.err {
			t.Errorf("ParseMode(%q) err = %v; want err=%v", c.in, err, c.err)
		}
		if got != c.want {
			t.Errorf("ParseMode(%q) = %v; want %v", c.in, got, c.want)
		}
	}
}

// capture returns a logger writing JSON to buf at the given mode.
func capture(t *testing.T, mode Mode) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	lvl := parseConfigLevelDefault()
	if mode != ModeNone {
		lvl = levelFor(mode)
	}
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: lvl})
	return slog.New(h), &buf
}

func parseConfigLevelDefault() slog.Level { return slog.LevelInfo }

// TestSimpleHidesTrace is the core guarantee: --debug simple shows Debug but
// NOT Trace; --debug full shows both.
func TestSimpleHidesTrace(t *testing.T) {
	// simple: Debug visible, Trace hidden.
	logS, bufS := capture(t, ModeSimple)
	logS.Debug("app-level")
	logS.Log(t.Context(), LevelTrace, "wire-level")
	if !strings.Contains(bufS.String(), "app-level") {
		t.Error("simple: Debug line should be emitted")
	}
	if strings.Contains(bufS.String(), "wire-level") {
		t.Error("simple: Trace line should be HIDDEN")
	}

	// full: both visible.
	logF, bufF := capture(t, ModeFull)
	logF.Debug("app-level")
	logF.Log(t.Context(), LevelTrace, "wire-level")
	if !strings.Contains(bufF.String(), "app-level") {
		t.Error("full: Debug line should be emitted")
	}
	if !strings.Contains(bufF.String(), "wire-level") {
		t.Error("full: Trace line should be VISIBLE")
	}
}

// TestNoneShowsNoDebug: with no --debug, Debug and Trace are both hidden.
func TestNoneShowsNoDebug(t *testing.T) {
	logN, bufN := capture(t, ModeNone)
	logN.Debug("app-level")
	logN.Log(t.Context(), LevelTrace, "wire-level")
	if strings.Contains(bufN.String(), "app-level") || strings.Contains(bufN.String(), "wire-level") {
		t.Error("none: neither Debug nor Trace should be emitted")
	}
}
