package logging

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// This file implements the redaction component of WP-1a.08 (concept ch. 16.1,
// TR-013): a slog.Handler wrapper that every RiskSignal log record passes
// through before it is written. The rules below are the deterministic,
// testable contract — see redact_test.go. They err on the side of redaction:
// over-redacting a safe value only costs log detail, under-redacting leaks a
// secret.
//
//  1. Sensitive keys. Any attribute whose key contains one of the words in
//     sensitiveWords (password, secret, token, authorization, key, ...) is
//     replaced entirely by the redaction marker, whatever its value. Keys are
//     matched as word parts, so "refresh_token", "refreshToken" and
//     "client-secret" are all caught while unrelated keys such as
//     "author_id" or "correlation_id" are not.
//
//  2. Free-text and payload keys. Any attribute whose key names user or
//     payload content (payload, body, content, text, comment, note, email,
//     name, title, description, ...) is replaced entirely. Whole objects and
//     complete payloads must never reach the log; log the internal ID
//     instead. Keys ending in "message" are exempt except for the bare key
//     "message", so technical error texts (e.g. "error_message") survive.
//
//  3. Token-shaped content. String values and the record message are scanned
//     for credential shapes (authorization headers, JWTs, key=value secret
//     assignments). A match replaces the whole value or message, because a
//     partial replacement could still leak the secret. This catches secrets
//     embedded in free text that did not come in under a sensitive key.
//     Opaque high-entropy runs are deliberately not matched: a 32-character
//     hex string is indistinguishable from a token and is a legitimate
//     internal object ID (concept ch. 16.1 logs objects by internal ID).
//
//  4. Whole objects. Any slog value that is an object (struct, map, slice,
//     pointer, ...) is replaced unless it is nil, a time.Time or an error.
//     Errors keep their message — concept ch. 16.1 sanctions the technical
//     cause in the log — but the message is still scanned for token shapes.
//     slog.LogValuer values are resolved and then classified.
//
// Redaction never drops or reorders safe content: the attribute key stays in
// place so operators see which field was withheld, and only the classified
// secret is replaced by the redaction marker.
//
// Log-injection neutralisation (concept ch. 12.3, WP-6.08 / DEV-120): every
// string field value and the record message additionally pass through
// neutralizeControl, which turns a CR or LF into its escaped form (\r, \n).
// A value can therefore never forge a second log record or break the one
// record/one line guarantee — independent of the output handler.

// redacted is the value replacing every redacted attribute or message.
const redacted = "[REDACTED]"

// keyClass classifies an attribute key for redaction.
type keyClass int

const (
	keyOK keyClass = iota
	keySensitive
	keyFreeText
)

// sensitiveWords are word parts that mark an attribute key as secret. Keys
// are split on separators and camelCase boundaries first (splitKeyParts), so
// both "api_key" and "apiKey" yield the part "key". Concatenated forms
// without any boundary ("apikey", "clientsecret") are listed explicitly.
var sensitiveWords = map[string]bool{
	"password": true, "passwd": true, "pwd": true,
	"secret":        true,
	"token":         true,
	"auth":          true,
	"authorization": true,
	"credential":    true, "credentials": true,
	"cookie": true,
	"key":    true,
	// Boundary-free concatenations.
	"apikey":       true,
	"passphrase":   true,
	"clientsecret": true,
	"privatekey":   true,
	"accesskey":    true,
	"secretkey":    true,
	"accesstoken":  true,
	"authtoken":    true,
	"refreshtoken": true,
	"idtoken":      true,
	"sessiontoken": true,
}

// freeTextWords mark an attribute key as free text or payload content whose
// value must not be logged verbatim. Matching is on the last word part, so
// "request_body", "queue_name" and "comment" are all caught. "message" is
// the exception: it is only caught as a bare key, so "error_message" (a
// technical cause, concept ch. 16.1) survives while a bare "message"
// attribute carrying user text is redacted.
var freeTextWords = map[string]bool{
	"payload": true, "body": true, "content": true, "contents": true,
	"text": true, "comment": true, "comments": true, "note": true, "notes": true,
	"message": true,
	"email":   true, "emails": true, "mail": true, "subject": true,
	"description": true, "summary": true, "detail": true, "details": true,
	"answer": true, "reply": true, "name": true, "title": true, "label": true,
	"heading": true, "prompt": true, "question": true, "snippet": true,
}

// secretShape matches credential shapes anywhere in a string value or the
// record message:
//
//   - authorization headers ("Bearer <token>", "Basic <base64>"),
//   - JWTs (the header is always the base64url of a JSON object, hence the
//     "eyJ" prefix; case-insensitive),
//   - secret assignments in free text or URLs ("password=...",
//     "?api_key=...", "Authorization: Bearer ..." would already match above).
var secretShape = regexp.MustCompile(`(?i)` +
	`\b(bearer|basic)\s+[a-z0-9._~+/=-]{8,}` +
	`|\beyj[a-z0-9_-]{9,}\.[a-z0-9_-]{3,}\.[a-z0-9_-]{3,}` +
	`|\b(password|passwd|pwd|secret|token|api[_-]?key|auth(?:orization)?|access[_-]?(?:key|token)|refresh[_-]?token|client[_-]?secret)\s*=\s*[^&\s"',;]{4,}`)

// redactHandler is the slog.Handler wrapper of WP-1a.08. Every record is
// redacted (redactRecord) before the wrapped handler writes it out.
// WithAttrs attributes (the uniform fields service, version, environment)
// and the correlation ID from the record context are attached before
// redaction, so they are covered by the same rules.
type redactHandler struct {
	next  slog.Handler
	attrs []slog.Attr // attributes attached via WithAttrs
}

// Enabled delegates the level gate to the wrapped handler.
func (h *redactHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

// Handle attaches the correlation ID from ctx (when present) and the
// WithAttrs attributes, redacts the record, then hands it to the wrapped
// handler.
func (h *redactHandler) Handle(ctx context.Context, r slog.Record) error {
	if id, ok := CorrelationIDFrom(ctx); ok {
		r.AddAttrs(slog.String("correlation_id", id))
	}
	r.AddAttrs(h.attrs...)
	return h.next.Handle(ctx, redactRecord(r))
}

// WithAttrs accumulates attributes. Merging into one list keeps a single
// redaction layer; slog semantics of later attributes overriding earlier ones
// with the same key are preserved because the built-in handlers deduplicate
// on write.
func (h *redactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &redactHandler{next: h.next, attrs: merged}
}

// WithGroup passes the group down to the wrapped handler.
func (h *redactHandler) WithGroup(name string) slog.Handler {
	return &redactHandler{next: h.next.WithGroup(name), attrs: h.attrs}
}

// redactRecord returns a copy of r whose message and attributes are redacted.
// When nothing changed, r itself is returned.
func redactRecord(r slog.Record) slog.Record {
	msgRedacted := secretShape.MatchString(r.Message)
	msg := r.Message
	if msgRedacted {
		msg = redacted
	}
	// Log injection: a CR/LF in the message is neutralised (escaped) so it
	// can never terminate the record early.
	if n := neutralizeControl(msg); n != msg {
		msg = n
	}
	changed := msg != r.Message

	var attrs []slog.Attr
	if n := r.NumAttrs(); n > 0 {
		attrs = make([]slog.Attr, 0, n)
		r.Attrs(func(a slog.Attr) bool {
			ra := redactAttr(a)
			if !ra.Equal(a) {
				changed = true
			}
			attrs = append(attrs, ra)
			return true
		})
	}
	if !changed {
		return r
	}

	nr := slog.NewRecord(r.Time, r.Level, msg, r.PC)
	nr.AddAttrs(attrs...)
	return nr
}

// redactAttr redacts one attribute (or group) by key classification and
// value inspection.
func redactAttr(a slog.Attr) slog.Attr {
	if a.Key == "" {
		return a
	}
	if classifyKey(a.Key) != keyOK {
		return slog.String(a.Key, redacted)
	}
	v, changed := redactValue(a.Value)
	if !changed {
		return a
	}
	return slog.Attr{Key: a.Key, Value: v}
}

// redactValue inspects one attribute value. It returns the replacement value
// and whether anything changed.
func redactValue(v slog.Value) (slog.Value, bool) {
	switch v.Kind() {
	case slog.KindString:
		s := v.String()
		if secretShape.MatchString(s) {
			return slog.StringValue(redacted), true
		}
		if n := neutralizeControl(s); n != s {
			return slog.StringValue(n), true
		}
	case slog.KindGroup:
		group := v.Group()
		out := make([]slog.Attr, 0, len(group))
		changed := false
		for _, child := range group {
			rc := redactAttr(child)
			if !rc.Equal(child) {
				changed = true
			}
			out = append(out, rc)
		}
		if changed {
			return slog.GroupValue(out...), true
		}
	case slog.KindLogValuer:
		// Resolve once (slog caps runaway LogValue chains) and classify the
		// result.
		return redactValue(v.Resolve())
	case slog.KindAny:
		switch x := v.Any().(type) {
		case nil, time.Time:
			// Nothing to leak.
		case error:
			// Errors carry the technical cause (concept ch. 16.1), but their
			// text is still scanned for token shapes.
			if secretShape.MatchString(x.Error()) {
				return slog.StringValue(redacted), true
			}
		default:
			// Any other object (struct, map, slice, pointer, ...) could be a
			// complete payload. Log objects by internal ID only; whole
			// objects never reach the log.
			return slog.StringValue(redacted), true
		}
	}
	return v, false
}

// neutralizeControl replaces a carriage return or line feed in a log string
// with its escaped form (\r, \n), neutralising log injection (concept
// ch. 12.3, WP-6.08 / DEV-120): a crafted value can never terminate a record
// early or forge a second one. Every other character passes through
// unchanged, so a legitimate value is never altered.
func neutralizeControl(s string) string {
	if !strings.ContainsAny(s, "\r\n") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 2)
	for _, r := range s {
		switch r {
		case '\r':
			b.WriteString(`\r`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// classifyKey classifies an attribute key. Keys are matched as word parts so
// that "refresh_token" and "refreshToken" are handled identically while
// unrelated keys sharing characters ("author_id", "correlation_id",
// "context") are not affected.
func classifyKey(key string) keyClass {
	parts := splitKeyParts(key)
	for _, p := range parts {
		if sensitiveWords[p] {
			return keySensitive
		}
	}
	last := parts[len(parts)-1]
	if freeTextWords[last] && (last != "message" || len(parts) == 1) {
		return keyFreeText
	}
	return keyOK
}

// splitKeyParts splits an attribute key into lowercase word parts.
// Separators (space, -, _, ., /) end a part, as does a lowercase-to-uppercase
// boundary, so "refreshToken", "refresh_token" and "Refresh-Token" all split
// to [refresh token]. Consecutive capitals stay in one part, so "APIKey"
// splits to [api key].
func splitKeyParts(key string) []string {
	var parts []string
	var cur []rune
	for _, r := range key {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			if len(cur) > 0 && unicode.IsLower(cur[len(cur)-1]) && unicode.IsUpper(r) {
				parts = append(parts, strings.ToLower(string(cur)))
				cur = cur[:0]
			}
			cur = append(cur, r)
		default:
			if len(cur) > 0 {
				parts = append(parts, strings.ToLower(string(cur)))
				cur = cur[:0]
			}
		}
	}
	if len(cur) > 0 {
		parts = append(parts, strings.ToLower(string(cur)))
	}
	return parts
}
