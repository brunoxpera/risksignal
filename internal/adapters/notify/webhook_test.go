package notify

// Tests of the webhook channel (webhook.go): the HMAC-SHA256 signing scheme
// and the adapter's delivery against httptest servers — a 2xx target is
// delivered, a 4xx target is a permanent failure, a 5xx target is temporary.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application"
)

func TestSignAndVerify(t *testing.T) {
	body := []byte(`{"signal_id":"sig-1"}`)
	sig := Sign("s3cr3t", body)
	if sig[:7] != "sha256=" {
		t.Fatalf("Sign = %q, want the sha256= prefix", sig)
	}
	if !VerifySignature("s3cr3t", body, sig) {
		t.Error("VerifySignature rejected a valid signature")
	}
	if VerifySignature("other", body, sig) {
		t.Error("VerifySignature accepted a wrong secret")
	}
	if VerifySignature("s3cr3t", []byte(`{}`), sig) {
		t.Error("VerifySignature accepted a tampered body")
	}
	if VerifySignature("s3cr3t", body, "sha256=deadbeef") {
		t.Error("VerifySignature accepted a bogus signature")
	}
}

func TestWebhookPortSignsAndDelivers(t *testing.T) {
	const secret = "s3cr3t"
	var gotBody []byte
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get(signatureHeader)
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	port, err := NewWebhookPort(srv.URL, secret, nil)
	if err != nil {
		t.Fatalf("NewWebhookPort: %v", err)
	}
	receipt, err := port.Deliver(context.Background(), application.Notification{
		Channel: "webhook", Kind: "signal.escalated", SignalID: "sig-1", OutboxEventID: "evt-1",
	})
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if !receipt.Delivered {
		t.Fatalf("receipt = %+v, want delivered", receipt)
	}
	if !VerifySignature(secret, gotBody, gotSig) {
		t.Fatalf("delivered body does not verify against its signature header %q", gotSig)
	}
}

func TestWebhookPortClassifiesStatus(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		permanent bool
	}{
		{"bad_request", http.StatusBadRequest, true},
		{"not_found", http.StatusNotFound, true},
		{"server_error", http.StatusInternalServerError, false},
		{"bad_gateway", http.StatusBadGateway, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			port, err := NewWebhookPort(srv.URL, "s3cr3t", nil)
			if err != nil {
				t.Fatalf("NewWebhookPort: %v", err)
			}
			receipt, err := port.Deliver(context.Background(), application.Notification{Channel: "webhook", SignalID: "sig-1"})
			if err == nil {
				t.Fatalf("Deliver on %d returned no error", tc.status)
			}
			if receipt.Delivered {
				t.Fatalf("receipt = %+v, want not delivered", receipt)
			}
			if IsPermanent(err) != tc.permanent {
				t.Fatalf("IsPermanent(%d) = %v, want %v", tc.status, IsPermanent(err), tc.permanent)
			}
		})
	}
}

func TestWebhookPortRequiresConfiguration(t *testing.T) {
	if _, err := NewWebhookPort("", "s3cr3t", nil); err == nil {
		t.Error("empty url accepted")
	}
	if _, err := NewWebhookPort("http://example.test/hook", "", nil); err == nil {
		t.Error("empty secret accepted")
	}
}
