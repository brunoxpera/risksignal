package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
)

// signatureHeader is the request header carrying the HMAC-SHA256 signature of
// the request body, formatted "sha256=<lowercase hex>".
const signatureHeader = "X-RiskSignal-Signature"

// Sign returns the HMAC-SHA256 signature of body under secret, formatted as
// the signatureHeader value ("sha256=<hex>"). It is exported so a receiver
// (and the tests) can verify with the exact scheme the adapter signs with.
func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature reports whether signature is the valid HMAC-SHA256 tag of
// body under secret, compared in constant time. A malformed or foreign
// signature returns false.
func VerifySignature(secret string, body []byte, signature string) bool {
	want := Sign(secret, body)
	return hmac.Equal([]byte(want), []byte(signature))
}

// webhookPayload is the minimal JSON body posted to the webhook target: the
// outbox event identity (the idempotency key), the signal identity, the
// channel/kind and the insert instant. Content is minimised per ch. 3.3 —
// identities and enums only, never free text or secrets.
type webhookPayload struct {
	EventID    string `json:"event_id"`
	SignalID   string `json:"signal_id"`
	Channel    string `json:"channel"`
	Kind       string `json:"kind"`
	OccurredAt string `json:"occurred_at"`
}

// WebhookPort is the signed webhook notification channel (ARCH-004 §6.1): it
// POSTs a minimal JSON body to the configured target and signs it with
// HMAC-SHA256 so the receiver can authenticate the delivery. It is the
// "signed fake webhook" of I4 — the target is a local test server, never a
// production endpoint.
type WebhookPort struct {
	url    string
	secret string
	client *http.Client
}

// NewWebhookPort assembles the webhook channel. url and secret are mandatory;
// a nil client falls back to a client with a 10s timeout so a hung target
// cannot pin the relay drain forever.
func NewWebhookPort(url, secret string, client *http.Client) (*WebhookPort, error) {
	if strings.TrimSpace(url) == "" {
		return nil, fmt.Errorf("notify: webhook channel: url must not be empty")
	}
	if strings.TrimSpace(secret) == "" {
		return nil, fmt.Errorf("notify: webhook channel: secret must not be empty")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &WebhookPort{url: url, secret: secret, client: client}, nil
}

// Deliver posts the signed body for n. A transport failure or a 5xx reply is
// a temporary (retryable) error; a 4xx reply is permanent (the endpoint
// refused the request — retrying the identical request cannot help).
func (p *WebhookPort) Deliver(ctx context.Context, n application.Notification) (DeliveryReceipt, error) {
	body, err := json.Marshal(webhookPayload{
		EventID:    n.OutboxEventID,
		SignalID:   n.SignalID,
		Channel:    n.Channel,
		Kind:       n.Kind,
		OccurredAt: n.CreatedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return DeliveryReceipt{Channel: ChannelWebhook, Attempts: 1, Error: err.Error()}, Permanent(err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(body))
	if err != nil {
		return DeliveryReceipt{Channel: ChannelWebhook, Attempts: 1, Error: err.Error()}, Permanent(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(signatureHeader, Sign(p.secret, body))

	resp, err := p.client.Do(req)
	if err != nil {
		return DeliveryReceipt{Channel: ChannelWebhook, Attempts: 1, Error: err.Error()}, err // transport: temporary
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return DeliveryReceipt{Channel: ChannelWebhook, Delivered: true, Attempts: 1}, nil
	}
	deliveryErr := fmt.Errorf("notify: webhook: target returned status %d", resp.StatusCode)
	receipt := DeliveryReceipt{Channel: ChannelWebhook, Attempts: 1, Error: deliveryErr.Error()}
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return receipt, Permanent(deliveryErr)
	}
	return receipt, deliveryErr // 5xx: temporary
}
