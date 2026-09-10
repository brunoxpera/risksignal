package application_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// This file tests the DEV-086 configurable priority-rules publication: an
// operator-supplied ruleset is validated (domain.ValidateRuleset), published
// as the new effective snapshot and used by the recompute; a malformed /
// degenerate one is rejected before any write (no transaction, no audit, no
// outbox).

// customPublishRuleset is an operator-style ruleset distinct from the seed,
// still distinguishing all four classes: P1 = high confidence AND KEV, P2 =
// high confidence AND cvss >= 8.0, P3 = high/medium confidence, P4 =
// low/none. On a high/no-KEV/cvss 8.5 cell it resolves to P2 where the seed
// resolves to P3.
func customPublishRuleset() []domain.PriorityRule {
	ids := []domain.Priority{domain.PriorityP1, domain.PriorityP2, domain.PriorityP3, domain.PriorityP4}
	defs := []domain.RuleDefinition{
		{AllOf: []domain.RuleDefinition{
			{Op: domain.RuleOpIn, Field: domain.FieldConfidence, Values: []string{string(domain.ConfidenceHigh)}},
			{Op: domain.RuleOpEq, Field: domain.FieldKEV, Value: domain.BoolValue(true)},
		}},
		{AllOf: []domain.RuleDefinition{
			{Op: domain.RuleOpIn, Field: domain.FieldConfidence, Values: []string{string(domain.ConfidenceHigh)}},
			{Op: domain.RuleOpGe, Field: domain.FieldCVSS, Value: domain.NumberValue(8.0)},
		}},
		{AllOf: []domain.RuleDefinition{
			{Op: domain.RuleOpIn, Field: domain.FieldConfidence, Values: []string{string(domain.ConfidenceHigh), string(domain.ConfidenceMedium)}},
		}},
		{AllOf: []domain.RuleDefinition{
			{Op: domain.RuleOpIn, Field: domain.FieldConfidence, Values: []string{string(domain.ConfidenceLow), string(domain.ConfidenceNone)}},
		}},
	}
	rules := make([]domain.PriorityRule, 4)
	for i := range ids {
		rules[i] = domain.PriorityRule{RuleID: ids[i], Version: 1, Enabled: true, Definition: defs[i]}
	}
	return rules
}

// customCellFactors is the high/no-KEV/cvss 8.5 factor cell the custom
// ruleset resolves to P2 (the seed resolves it to P3).
func customCellFactors() domain.PriorityFactors {
	return domain.PriorityFactors{
		Method:      domain.MatchMethodExactIdentifier,
		Confidence:  domain.ConfidenceHigh,
		KEV:         false,
		CVSS:        8.5,
		EPSS:        0.5,
		Criticality: domain.CriticalityNormal,
		Exposure:    domain.ExposureInternal,
	}
}

// TestPublishPriorityRulesCustomRulesetIsEffectiveAndUsed proves the operator
// path: a validated custom ruleset is published as the new effective snapshot
// (version advances, reason/actor stamped on every row) and the recompute
// evaluates against it.
func TestPublishPriorityRulesCustomRulesetIsEffectiveAndUsed(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedRulesetV1(h) // version 1 = the seed

	custom := customPublishRuleset()
	res, err := h.svc.PublishPriorityRules(ctx, application.PublishPriorityRulesInput{
		Reason: "operator-tuned thresholds",
		Actor:  systemActor("admin-1"),
		Rules:  custom,
	})
	if err != nil {
		t.Fatalf("PublishPriorityRules(custom): %v", err)
	}
	if res.Version != 2 || res.RuleVersion != "p0000000002" {
		t.Fatalf("publish result = %+v, want version 2 / p0000000002", res)
	}

	// The effective snapshot is the custom ruleset, with reason/actor stamped
	// on every row.
	effective, err := h.priorityRules.Effective(ctx)
	if err != nil {
		t.Fatalf("effective: %v", err)
	}
	if len(effective) != 4 {
		t.Fatalf("effective rules = %d, want 4", len(effective))
	}
	if !reflect.DeepEqual(effective[1].Definition, custom[1].Definition) {
		t.Fatalf("effective P2 definition = %+v, want the published custom predicate", effective[1].Definition)
	}
	for _, r := range effective {
		if r.Reason != "operator-tuned thresholds" || r.ActorID != "admin-1" {
			t.Fatalf("rule %s reason/actor = %q/%q, want the stamp", r.RuleID, r.Reason, r.ActorID)
		}
	}

	// Sanity: the seed would have classified the cell as P3.
	if got := domain.ComputePriority(customCellFactors()); got != domain.PriorityP3 {
		t.Fatalf("seed ComputePriority(cell) = %s, want P3 (the pre-publish baseline)", got)
	}

	// A signal stored under the seed is recomputed under the custom ruleset:
	// the cell now resolves to P2 and the signal re-stamps to the new version.
	sig := domain.RiskSignal{
		ID: "sig-custom", MatchID: testMatchID, Priority: domain.PriorityP3,
		Status: domain.SignalStatusNew, Version: 1, RuleVersion: "p0000000001", Factors: p3Factors(),
	}
	seedStoredSignal(h, sig)
	h.factorSource.rebuilds[sig.ID] = application.PriorityFactorRebuild{CVEID: testCveID, Factors: customCellFactors()}

	out, err := h.svc.RecomputePriority(ctx, application.RecomputePriorityInput{SignalID: sig.ID, Actor: systemActor("recompute-worker")})
	if err != nil {
		t.Fatalf("RecomputePriority: %v", err)
	}
	if !out.Changed || out.Priority != domain.PriorityP2 || out.RuleVersion != "p0000000002" {
		t.Fatalf("recompute result = %+v, want Changed P2 under p0000000002", out)
	}
	row, ok := h.db.signalRowByID(sig.ID)
	if !ok || row.sig.Priority != domain.PriorityP2 || row.sig.RuleVersion != "p0000000002" {
		t.Fatalf("stored signal = %+v (ok=%v), want P2 under p0000000002", row.sig, ok)
	}
}

// TestPublishPriorityRulesEmptyRulesDefaultsToSeed pins the backward-compatible
// default: an absent/empty Rules still publishes the seed.
func TestPublishPriorityRulesEmptyRulesDefaultsToSeed(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	res, err := h.svc.PublishPriorityRules(ctx, application.PublishPriorityRulesInput{
		Reason: "default publish",
		Actor:  systemActor("admin-1"),
	})
	if err != nil {
		t.Fatalf("PublishPriorityRules(default): %v", err)
	}
	if res.Version != 1 {
		t.Fatalf("version = %d, want 1", res.Version)
	}
	effective, err := h.priorityRules.Effective(ctx)
	if err != nil {
		t.Fatalf("effective: %v", err)
	}
	if !reflect.DeepEqual(effective, stampForCompare(domain.SeedPriorityRules(), "default publish", "admin-1")) {
		t.Fatalf("effective rules = %+v, want the stamped seed", effective)
	}
}

// stampForCompare mirrors the application's per-row stamping for the seed
// comparison in the default-publish test.
func stampForCompare(rules []domain.PriorityRule, reason, actorID string) []domain.PriorityRule {
	out := make([]domain.PriorityRule, len(rules))
	for i, r := range rules {
		r.Reason = reason
		r.ActorID = actorID
		out[i] = r
	}
	return out
}

// TestPublishPriorityRulesRejectsInvalidRuleset proves a malformed, empty
// (wrong-length) or degenerate operator ruleset is refused with a validation
// error and publishes nothing: no transaction is opened, no snapshot is
// written and no audit/outbox event is appended (no audit noise).
func TestPublishPriorityRulesRejectsInvalidRuleset(t *testing.T) {
	alwaysMatching := func(def domain.RuleDefinition) []domain.PriorityRule {
		rules := customPublishRuleset()
		rules[0].Definition = def
		return rules
	}
	allConfidences := domain.RuleDefinition{AllOf: []domain.RuleDefinition{
		{Op: domain.RuleOpIn, Field: domain.FieldConfidence, Values: []string{
			string(domain.ConfidenceHigh), string(domain.ConfidenceMedium), string(domain.ConfidenceLow), string(domain.ConfidenceNone),
		}},
	}}
	emptyDefinition := customPublishRuleset()
	emptyDefinition[1].Definition = domain.RuleDefinition{}

	dupIDs := customPublishRuleset()
	dupIDs[1].RuleID = domain.PriorityP1

	reordered := customPublishRuleset()
	reordered[0], reordered[1] = reordered[1], reordered[0]

	tests := []struct {
		name  string
		rules []domain.PriorityRule
	}{
		{"too few rules", customPublishRuleset()[:3]},
		{"duplicate id", dupIDs},
		{"reordered", reordered},
		{"empty definition", emptyDefinition},
		{"always-matching rule", alwaysMatching(allConfidences)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			_, err := h.svc.PublishPriorityRules(context.Background(), application.PublishPriorityRulesInput{
				Reason: "bad ruleset",
				Actor:  systemActor("admin-1"),
				Rules:  tc.rules,
			})
			if err == nil {
				t.Fatalf("PublishPriorityRules(%s): want a validation error, got nil", tc.name)
			}
			if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
				t.Fatalf("error kind = %s, want validation", kind)
			}
			if len(h.runner.txs) != 0 {
				t.Fatalf("opened %d transactions, want 0", len(h.runner.txs))
			}
			if len(h.db.auditEvents) != 0 || len(h.db.outboxEvents) != 0 {
				t.Fatalf("wrote audit=%d outbox=%d, want 0/0 (no audit noise)", len(h.db.auditEvents), len(h.db.outboxEvents))
			}
			if v, err := h.priorityRules.EffectiveVersion(context.Background()); err != nil || v != 0 {
				t.Fatalf("effective version = %d (err %v), want 0 (nothing published)", v, err)
			}
		})
	}
}
