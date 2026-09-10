package application_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// This file tests the ARCH-004 §5 priority.recompute fan-in (WP-4.05):
// PublishPriorityRules enqueues the batched recompute over the open signals,
// and the matching.recompute fan-in enqueues a per-signal job for the affected
// signals — both dedupe-checked so a re-enqueue with identical inputs is a
// no-op.

// priorityRecomputeSignals returns the signal ids carried by the committed
// priority.recompute outbox payloads.
func priorityRecomputeSignals(h *harness) map[string]int {
	counts := map[string]int{}
	for _, ev := range h.db.outboxEvents {
		if ev.Type != application.EventTypePriorityRecompute {
			continue
		}
		var p application.PriorityRecomputePayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			continue
		}
		counts[p.SignalID]++
	}
	return counts
}

// TestPublishPriorityRulesEnqueuesOpenSignalRecomputes proves the batched
// fan-in: a ruleset publish enqueues a priority.recompute for every open
// signal at the new rule version, and never for a closed one.
func TestPublishPriorityRulesEnqueuesOpenSignalRecomputes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	openNew := domain.RiskSignal{
		ID: "sig-open-new", MatchID: testMatchID, Priority: domain.PriorityP1,
		Status: domain.SignalStatusNew, Version: 1, RuleVersion: "i1b-1", Factors: p1Factors(),
	}
	openReview := domain.RiskSignal{
		ID: "sig-open-review", MatchID: "match-2", Priority: domain.PriorityP3,
		Status: domain.SignalStatusInReview, Version: 2, RuleVersion: "i1b-1", Factors: p3Factors(),
	}
	closed := domain.RiskSignal{
		ID: "sig-closed", MatchID: "match-3", Priority: domain.PriorityP2,
		Status: domain.SignalStatusResolved, Version: 3, RuleVersion: "i1b-1", Factors: p3Factors(),
	}
	seedStoredSignal(h, openNew)
	seedStoredSignal(h, openReview)
	seedStoredSignal(h, closed)

	pub, err := h.svc.PublishPriorityRules(ctx, application.PublishPriorityRulesInput{
		Reason: "fan-in test", Actor: systemActor("admin-1"),
	})
	if err != nil {
		t.Fatalf("PublishPriorityRules: %v", err)
	}
	if pub.RuleVersion != "p0000000001" {
		t.Fatalf("rule version = %q, want p0000000001", pub.RuleVersion)
	}

	got := priorityRecomputeSignals(h)
	if len(got) != 2 || got["sig-open-new"] != 1 || got["sig-open-review"] != 1 {
		t.Fatalf("priority.recompute signals = %v, want the two open signals once each", got)
	}
	if got["sig-closed"] != 0 {
		t.Fatalf("a closed signal was enqueued for recompute: %v", got)
	}
	// The payloads carry the published rule version.
	for _, ev := range h.db.outboxEvents {
		if ev.Type != application.EventTypePriorityRecompute {
			continue
		}
		var p application.PriorityRecomputePayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if p.RuleVersion != pub.RuleVersion || p.InputHash == "" {
			t.Fatalf("payload = %+v, want rule_version %s and an input hash", p, pub.RuleVersion)
		}
	}
}

// TestEnqueuePriorityRecomputeForVulnerabilitiesEnqueuesAffectedSignals proves
// the matching.recompute fan-in: one priority.recompute per signal whose match
// references a batch vulnerability, dedupe-checked so a re-run appends
// nothing.
func TestEnqueuePriorityRecomputeForVulnerabilitiesEnqueuesAffectedSignals(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedRulesetV1(h)

	h.db.matchRows = []storedMatch{
		{id: "match-a", rec: application.MatchRecord{VulnerabilityID: "vuln-1"}},
		{id: "match-b", rec: application.MatchRecord{VulnerabilityID: "vuln-2"}},
	}
	seedStoredSignal(h, domain.RiskSignal{
		ID: "sig-a", MatchID: "match-a", Priority: domain.PriorityP1,
		Status: domain.SignalStatusNew, Version: 1, RuleVersion: "i1b-1", Factors: p1Factors(),
	})
	seedStoredSignal(h, domain.RiskSignal{
		ID: "sig-b", MatchID: "match-b", Priority: domain.PriorityP3,
		Status: domain.SignalStatusInReview, Version: 1, RuleVersion: "i1b-1", Factors: p3Factors(),
	})

	// Only vuln-1's signal is affected by the batch.
	n, err := h.svc.EnqueuePriorityRecomputeForVulnerabilities(ctx, []string{"vuln-1"})
	if err != nil {
		t.Fatalf("EnqueuePriorityRecomputeForVulnerabilities: %v", err)
	}
	if n != 1 {
		t.Fatalf("enqueued = %d, want 1", n)
	}
	got := priorityRecomputeSignals(h)
	if got["sig-a"] != 1 || got["sig-b"] != 0 {
		t.Fatalf("priority.recompute signals = %v, want only sig-a", got)
	}
	for _, ev := range h.db.outboxEvents {
		if ev.Type != application.EventTypePriorityRecompute {
			continue
		}
		var p application.PriorityRecomputePayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if p.RuleVersion != "p0000000001" {
			t.Fatalf("payload rule_version = %q, want the effective p0000000001", p.RuleVersion)
		}
	}

	// A re-run with the same batch is a deduped no-op.
	n, err = h.svc.EnqueuePriorityRecomputeForVulnerabilities(ctx, []string{"vuln-1"})
	if err != nil {
		t.Fatalf("EnqueuePriorityRecomputeForVulnerabilities (rerun): %v", err)
	}
	if n != 0 {
		t.Fatalf("rerun enqueued = %d, want 0 (deduped)", n)
	}
	if got := priorityRecomputeSignals(h); got["sig-a"] != 1 {
		t.Fatalf("rerun appended a duplicate: %v", got)
	}
}
