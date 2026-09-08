package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// captureLogger builds a logger writing into an in-memory buffer.
func captureLogger(t *testing.T, env string) (*bytes.Buffer, *slog.Logger) {
	t.Helper()
	var buf bytes.Buffer
	l := New(Options{Service: "risksignal-test", Version: "1.2.3", Environment: env, Writer: &buf})
	return &buf, l
}

// jsonRecord logs one record through a fresh JSON-mode logger with the given
// context and returns the decoded JSON object.
func jsonRecord(t *testing.T, ctx context.Context, msg string, args ...any) map[string]any {
	t.Helper()
	buf, l := captureLogger(t, EnvDemo)
	l.Log(ctx, slog.LevelInfo, msg, args...)

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("record is not valid JSON: %v\n%s", err, buf.String())
	}
	return rec
}

func TestNewJSONForOnlineEnvironments(t *testing.T) {
	for _, env := range []string{EnvDemo, EnvProduction} {
		buf, l := captureLogger(t, env)
		l.Info("hello")
		var out map[string]any
		if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
			t.Fatalf("env %s: output is not JSON: %v\n%s", env, err, buf.String())
		}
		if out["environment"] != env {
			t.Errorf("env %s: environment field = %v, want %s", env, out["environment"], env)
		}
	}
}

func TestNewTextForLocal(t *testing.T) {
	buf, l := captureLogger(t, EnvLocal)
	l.Info("hello")
	if !strings.HasPrefix(strings.TrimSpace(buf.String()), "timestamp=") {
		t.Fatalf("local mode output is not text: %q", buf.String())
	}
}

// TestUniformFieldsOnline proves every record carries the uniform fields of
// concept ch. 16.1 — timestamp, level, service, version, environment and
// correlation_id (taken from the request context) — in online (JSON) mode.
func TestUniformFieldsOnline(t *testing.T) {
	ctx := WithCorrelationID(context.Background(), "corr-42")
	rec := jsonRecord(t, ctx, "event")

	for _, key := range []string{"timestamp", "level", "service", "version", "environment", "correlation_id"} {
		if _, ok := rec[key]; !ok {
			t.Errorf("record lacks uniform field %q: %v", key, rec)
		}
	}
	if rec["service"] != "risksignal-test" || rec["version"] != "1.2.3" ||
		rec["environment"] != "demo" || rec["correlation_id"] != "corr-42" {
		t.Errorf("unexpected uniform field values: %v", rec)
	}
}

// TestNoCorrelationIDWithoutContext proves correlation_id appears only when
// the context carries one; non-request records (startup, worker) are not
// forced into a fake correlation scope.
func TestNoCorrelationIDWithoutContext(t *testing.T) {
	rec := jsonRecord(t, context.Background(), "startup")
	if _, ok := rec["correlation_id"]; ok {
		t.Errorf("record without correlation context carries correlation_id: %v", rec)
	}
}

// TestCorrelationHelpersRoundtrip covers WithCorrelationID/CorrelationIDFrom.
func TestCorrelationHelpersRoundtrip(t *testing.T) {
	if _, ok := CorrelationIDFrom(context.Background()); ok {
		t.Fatal("CorrelationIDFrom on a plain context reports a present ID")
	}
	ctx := WithCorrelationID(context.Background(), "abc")
	id, ok := CorrelationIDFrom(ctx)
	if !ok || id != "abc" {
		t.Fatalf("CorrelationIDFrom = %q, %v; want abc, true", id, ok)
	}
}

// TestSecurityCategory proves security events carry their own category
// (concept ch. 16.1) so they can be filtered and retained separately.
func TestSecurityCategory(t *testing.T) {
	ctx := WithCorrelationID(context.Background(), "corr-7")
	rec := jsonRecordWith(t, ctx, func(l *slog.Logger) {
		Security(ctx, l, "login_failed", "authentication failed", slog.Int("attempts", 3))
	})

	if rec["category"] != SecurityCategory {
		t.Errorf("category = %v, want %q", rec["category"], SecurityCategory)
	}
	if rec["event"] != "login_failed" {
		t.Errorf("event = %v, want login_failed", rec["event"])
	}
	if rec["msg"] != "authentication failed" {
		t.Errorf("msg = %v, want the human description", rec["msg"])
	}
	if rec["correlation_id"] != "corr-7" {
		t.Errorf("correlation_id = %v, want corr-7", rec["correlation_id"])
	}
	if rec["attempts"] != float64(3) {
		t.Errorf("attempts = %v, want 3", rec["attempts"])
	}
}

// jsonRecordWith logs one record via the given emit function through a fresh
// JSON-mode logger and returns the decoded JSON object.
func jsonRecordWith(t *testing.T, ctx context.Context, emit func(*slog.Logger)) map[string]any {
	t.Helper()
	buf, l := captureLogger(t, EnvDemo)
	emit(l)

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("record is not valid JSON: %v\n%s", err, buf.String())
	}
	return rec
}
