// MW_OAUTH_STEP_01
package config

import (
	"log/slog"
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"", slog.LevelInfo},
		{"debug", slog.LevelDebug},
		{"INFO", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
	}

	for _, tt := range tests {
		got, err := parseLogLevel(tt.input)
		if err != nil {
			t.Fatalf("parseLogLevel(%q): %v", tt.input, err)
		}
		if got != tt.want {
			t.Fatalf("parseLogLevel(%q) = %v; want %v", tt.input, got, tt.want)
		}
	}
}

func TestParseLogLevelRejectsInvalid(t *testing.T) {
	if _, err := parseLogLevel("verbose"); err == nil {
		t.Fatal("expected invalid LOG_LEVEL to fail")
	}
}
