package logging

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// This file is the automated redaction test of WP-1a.08 / TR-013: log
// records deliberately constructed to contain tokens, secrets, free text and
// complete payloads must not surface any of them — in either output format.
// The redaction rules under test are documented in redact.go.

// envs are the two supported output formats: JSON (demo/production) and text
// (local).
func envs() []string {
	return []string{EnvDemo, EnvLocal}
}

// TestRedactionAutomated is the TR-013 gate: no token, secret or complete
// payload reaches the log. Every secret is logged under a key that is either
// obviously secret, innocent-looking (shape detection) or a payload object
// (whole-object rule), and the assertion is the same: none of the original
// values appears anywhere in the output.
func TestRedactionAutomated(t *testing.T) {
	const (
		token    = "tok_9f8e7d6c5b4a39281706f5e4d3c2b1a0"
		password = "hunter2-super-secret"
		payload  = `{"assets":[{"id":"a-1","cve":"CVE-2024-0001","evidence":"full detail"}],"pagination":{"total":1}}`
		freeText = "please triage this finding urgently, signed Alice"
		secret   = "sk-live-0123456789abcdef"
	)

	for _, env := range envs() {
		t.Run(env, func(t *testing.T) {
			buf, l := captureLogger(t, env)
			l.Info("suspicious event",
				slog.String("token", token),       // sensitive key
				slog.String("password", password), // sensitive key
				slog.String("secret", secret),     // sensitive key
				slog.String("payload", payload),   // free-text/payload key
				slog.String("comment", freeText),  // free-text key
				slog.Any("evidence", map[string]any{ // whole object
					"cve": "CVE-2024-0001", "detail": token,
				}),
				slog.String("note", "Authorization: Bearer "+token), // embedded token shape
			)

			out := buf.String()
			t.Logf("redaction sample (%s mode): %s", env, strings.TrimSpace(out))
			for _, leak := range []string{token, password, payload, freeText, secret, "CVE-2024-0001"} {
				if strings.Contains(out, leak) {
					t.Errorf("%s mode: output leaks %q:\n%s", env, leak, out)
				}
			}
			if !strings.Contains(out, redacted) {
				t.Errorf("%s mode: output contains no redaction marker:\n%s", env, out)
			}
		})
	}
}

// TestRedactionEmbeddedShapes proves token-shaped content is caught even
// outside sensitive keys: in the record message, in string attributes with
// innocent keys, and in error text.
func TestRedactionEmbeddedShapes(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.signature_value_123"
	for _, env := range envs() {
		t.Run(env, func(t *testing.T) {
			buf, l := captureLogger(t, env)
			l.Info("request failed with Authorization: Bearer "+jwt, // message scan
				slog.String("status_message", "upstream answered 401; refresh_token="+jwt),
				slog.Any("cause", errors.New("probe denied: Basic dXNlcjpwYXNzd29yZA==")),
				slog.String("redirect", "https://issuer.example/authorize?client_id=abc&token="+jwt),
			)
			out := buf.String()
			if strings.Contains(out, jwt) {
				t.Errorf("%s mode: output leaks the JWT:\n%s", env, out)
			}
			for _, fragment := range []string{"dXNlcjpwYXNzd29yZA==", "Bearer ", "refresh_token="} {
				if strings.Contains(out, fragment) {
					t.Errorf("%s mode: output leaks credential fragment %q:\n%s", env, fragment, out)
				}
			}
			if !strings.Contains(out, redacted) {
				t.Errorf("%s mode: output contains no redaction marker:\n%s", env, out)
			}
		})
	}
}

// TestRedactionAllowsSafeValues is the counterpart that keeps the log
// operational: object IDs (32-char hex strings are indistinguishable from
// tokens by shape and are the sanctioned way to log objects), errors with
// technical causes, and request metadata all survive redaction.
func TestRedactionAllowsSafeValues(t *testing.T) {
	uuid := "550e8400e29b41d4a716446655440000" // internal object ID
	for _, env := range envs() {
		t.Run(env, func(t *testing.T) {
			buf, l := captureLogger(t, env)
			ctx := WithCorrelationID(context.Background(), "req-1234567890")
			l.InfoContext(ctx, "access",
				slog.String("method", "GET"),
				slog.String("path", "/api/v1/signals/"+uuid),
				slog.Int("status", 404),
				slog.String("duration", "1.234ms"),
				slog.Any("error", errors.New("dial tcp 127.0.0.1:5432: connection refused")),
			)
			out := buf.String()
			for _, want := range []string{"GET", "/api/v1/signals/", uuid, "404", "1.234ms", "connection refused", "req-1234567890"} {
				if !strings.Contains(out, want) {
					t.Errorf("%s mode: safe value %q was redacted or lost:\n%s", env, want, out)
				}
			}
			if strings.Contains(out, redacted) {
				t.Errorf("%s mode: safe record was redacted:\n%s", env, out)
			}
		})
	}
}

// TestRedactValueClassifiesKeys pins the key classification table down so a
// refactor cannot silently widen or narrow redaction.
func TestRedactValueClassifiesKeys(t *testing.T) {
	sensitive := []string{
		"password", "passwd", "pwd", "secret", "token", "authorization",
		"api_key", "apiKey", "client-secret", "refresh_token", "access_token",
		"private_key", "apikey", "credential", "cookie", "auth",
		"x_api_key", "X-Authorization",
	}
	freeText := []string{
		"payload", "request_body", "content", "body", "comment", "note",
		"queue_name", "description", "subject", "message", "details", "email",
	}
	safe := []string{
		"correlation_id", "author_id", "context", "monkey", "status_message",
		"error_message", "method", "path", "status", "duration", "version",
		"stack", "category", "event", "error", "addr", "grace_period",
		"signal_id", "asset_uuid", "attempts", "service", "environment",
	}
	for _, key := range sensitive {
		if got := classifyKey(key); got != keySensitive {
			t.Errorf("classifyKey(%q) = %v, want keySensitive", key, got)
		}
	}
	for _, key := range freeText {
		if got := classifyKey(key); got != keyFreeText {
			t.Errorf("classifyKey(%q) = %v, want keyFreeText", key, got)
		}
	}
	for _, key := range safe {
		if got := classifyKey(key); got != keyOK {
			t.Errorf("classifyKey(%q) = %v, want keyOK", key, got)
		}
	}
}

// TestRedactionPreservesGroupChildren proves redaction recurses into groups
// without dropping the safe siblings.
func TestRedactionPreservesGroupChildren(t *testing.T) {
	var buf bytes.Buffer
	l := New(Options{Service: "risksignal-test", Version: "1.2.3", Environment: EnvDemo, Writer: &buf})
	l.Info("job finished",
		slog.Group("result",
			slog.String("job_id", "job-17"),
			slog.String("token", "rt_9876543210"),
			slog.Int("processed", 5),
		),
	)
	out := buf.String()
	if strings.Contains(out, "rt_9876543210") || !strings.Contains(out, redacted) {
		t.Fatalf("secret inside group not redacted:\n%s", out)
	}
	for _, want := range []string{"job-17", `"processed":5`} {
		if !strings.Contains(out, want) {
			t.Errorf("safe group child %q lost:\n%s", want, out)
		}
	}
}
