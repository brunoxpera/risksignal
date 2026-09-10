package application_test

import (
	"context"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// TestGetSignalReturnsJoinedView verifies the getSignal detail view: the
// signal carries the joined asset (id/name/type/criticality/exposure) and
// product (vendor/product/version) fields of the ARCH-001 §4 Signal schema.
func TestGetSignalReturnsJoinedView(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	want := application.Signal{
		ID:         "sig-1",
		MatchID:    "match-1",
		CveID:      "CVE-2024-0001",
		Priority:   domain.PriorityP1,
		Status:     domain.SignalStatusNew,
		Confidence: domain.ConfidenceHigh,
		Method:     domain.MatchMethodCanonicalProductRange,
		Asset: application.SignalAsset{
			ID:          "asset-1",
			Name:        "acme portal",
			Type:        domain.AssetTypeApplicationFramework,
			Criticality: domain.CriticalityCritical,
			Exposure:    domain.ExposureInternet,
		},
		Product:   application.SignalProduct{Vendor: "acme", Product: "portal", Version: "2.4.4"},
		Summary:   "synthetic case one",
		CreatedAt: fixedNow,
		Version:   1,
	}
	h.db.signalViews = append(h.db.signalViews, want)

	got, err := h.svc.GetSignal(ctx, "sig-1")
	if err != nil {
		t.Fatalf("GetSignal: %v", err)
	}
	if got != want {
		t.Fatalf("GetSignal = %+v, want %+v", got, want)
	}
	if got.Asset.ID != "asset-1" || got.Asset.Name != "acme portal" ||
		got.Asset.Type != domain.AssetTypeApplicationFramework ||
		got.Asset.Criticality != domain.CriticalityCritical || got.Asset.Exposure != domain.ExposureInternet {
		t.Fatalf("joined asset = %+v, want id/name/type/criticality/exposure", got.Asset)
	}
	if got.Product.Vendor != "acme" || got.Product.Product != "portal" || got.Product.Version != "2.4.4" {
		t.Fatalf("joined product = %+v, want vendor/product/version", got.Product)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) || got.Version != 1 {
		t.Fatalf("created_at/version = %v/%d, want %v/1", got.CreatedAt, got.Version, want.CreatedAt)
	}
}

// TestGetSignalUnknownIDIsNotFound: an unknown signal id maps to the
// not-found error class (the HTTP layer turns that into a 404).
func TestGetSignalUnknownIDIsNotFound(t *testing.T) {
	h := newHarness(t)
	h.db.signalViews = append(h.db.signalViews, application.Signal{ID: "sig-1", Priority: domain.PriorityP4, Status: domain.SignalStatusNew})

	_, err := h.svc.GetSignal(context.Background(), "sig-missing")
	if err == nil {
		t.Fatal("GetSignal of an unknown id succeeded, want a not-found error")
	}
	if kind, _ := application.ErrorKindOf(err); kind != application.KindNotFound {
		t.Fatalf("error kind = %s, want not_found", kind)
	}
}

// TestGetSignalEmptyIDIsRejected: an empty id is a caller mistake.
func TestGetSignalEmptyIDIsRejected(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.GetSignal(context.Background(), "")
	if err == nil {
		t.Fatal("GetSignal of an empty id succeeded, want a validation error")
	}
	if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
		t.Fatalf("error kind = %s, want validation", kind)
	}
}

// TestSignalDueAtNullRoundTrip: I1b signals have a NULL due_at (SLA clocks
// are I4); the view carries the nil pointer.
func TestSignalDueAtNullRoundTrip(t *testing.T) {
	h := newHarness(t)
	view := application.Signal{
		ID: "sig-1", MatchID: "match-1", CveID: "CVE-2024-0001",
		Priority: domain.PriorityP4, Status: domain.SignalStatusNew,
		Confidence: domain.ConfidenceMedium, Method: domain.MatchMethodProductUncertainVersion,
		Product: application.SignalProduct{Vendor: "acme", Product: "api", Version: "1.0.3"},
		Summary: "informational", CreatedAt: time.Now(),
	}
	h.db.signalViews = append(h.db.signalViews, view)

	got, err := h.svc.GetSignal(context.Background(), "sig-1")
	if err != nil {
		t.Fatalf("GetSignal: %v", err)
	}
	if got.DueAt != nil {
		t.Fatalf("due_at = %v, want nil in I1b", *got.DueAt)
	}
}
