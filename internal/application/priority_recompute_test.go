package application_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// This file tests the WP-4.04b / DEV-077 use cases against the in-memory
// fakes (ARCH-004 §1/§5): PublishPriorityRules (versioned snapshot publish,
// audit + outbox in one transaction) and RecomputePriority (changed-only
// persist, closed-signal reopen proposal emitted exactly once).

// fakePriorityRuleRepo is the in-memory application.PriorityRuleRepo: the
// copy-on-write snapshot store keyed by version, published on commit.
type fakePriorityRuleRepo struct{ db *fakeDB }

func (f *fakePriorityRuleRepo) maxVersion() int {
	max := 0
	for v := range f.db.priorityRulesets {
		if v > max {
			max = v
		}
	}
	return max
}

func (f *fakePriorityRuleRepo) EffectiveVersion(ctx context.Context) (int, error) {
	return f.maxVersion(), nil
}

func (f *fakePriorityRuleRepo) Effective(ctx context.Context) ([]domain.PriorityRule, error) {
	rules := f.db.priorityRulesets[f.maxVersion()]
	out := make([]domain.PriorityRule, len(rules))
	copy(out, rules)
	return out, nil
}

func (f *fakePriorityRuleRepo) Publish(ctx context.Context, tx application.Tx, rules []domain.PriorityRule, effectiveFrom time.Time, reason, actorID string, createdAt time.Time) (int, error) {
	const op = "priority_rules.publish"
	if len(rules) != 4 {
		return 0, application.Validationf(op, "want exactly 4 rules, got %d", len(rules))
	}
	if actorID == "" {
		return 0, application.Validationf(op, "actor_id is mandatory")
	}
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return 0, err
	}
	ftx.record("priority_rules.publish")
	v := f.maxVersion() + 1
	staged := make([]domain.PriorityRule, len(rules))
	copy(staged, rules)
	ftx.staged.priorityRulesets = append(ftx.staged.priorityRulesets, storedRuleset{version: v, rules: staged})
	return v, nil
}

// fakePriorityFactorRepo is the in-memory application.PriorityFactorRepo: a
// per-signal fixture map (and optional forced errors).
type fakePriorityFactorRepo struct {
	rebuilds map[string]application.PriorityFactorRebuild
	errs     map[string]error
}

func (f *fakePriorityFactorRepo) Rebuild(ctx context.Context, signalID string) (application.PriorityFactorRebuild, error) {
	if err, ok := f.errs[signalID]; ok {
		return application.PriorityFactorRebuild{}, err
	}
	r, ok := f.rebuilds[signalID]
	if !ok {
		return application.PriorityFactorRebuild{}, application.NotFoundError("priority_factors.rebuild", fmt.Errorf("no rebuild fixture for signal %s", signalID))
	}
	return r, nil
}

// p3Factors is a fresh factor set the seeded ch. 9.3 rules resolve to P3: a
// high-confidence assignment with no urgency indicator (no KEV, CVSS < 9,
// EPSS < 0.95) on a low, internal asset.
func p3Factors() domain.PriorityFactors {
	return domain.PriorityFactors{
		Method:      domain.MatchMethodExactIdentifier,
		Confidence:  domain.ConfidenceHigh,
		KEV:         false,
		CVSS:        5.0,
		EPSS:        0.1,
		Criticality: domain.CriticalityLow,
		Exposure:    domain.ExposureInternal,
	}
}

// seedRulesetV1 installs the ch. 9.3 seed ruleset at version 1 (the snapshot
// the production migration seeds), so RecomputePriority has an effective
// ruleset to evaluate.
func seedRulesetV1(h *harness) {
	h.db.priorityRulesets = map[int][]domain.PriorityRule{domain.SeedPriorityRulesVersion: domain.SeedPriorityRules()}
}

// seedStoredSignal commits one signal row directly (the fixtures seed the
// exact rule_version/status the recompute assertions need, which the
// CreateSignal path — stamping the I1b version — cannot produce).
func seedStoredSignal(h *harness, sig domain.RiskSignal) {
	h.db.signalRows = append(h.db.signalRows, storedSignal{sig: sig})
}

// TestPublishPriorityRulesBumpsVersionAndWritesAuditOutbox is the publish
// happy path: the snapshot is written at MAX(version)+1 with the audit and
// the outbox event on one committed transaction, and a second publish bumps
// the version again.
func TestPublishPriorityRulesBumpsVersionAndWritesAuditOutbox(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if v, err := h.priorityRules.EffectiveVersion(ctx); err != nil || v != 0 {
		t.Fatalf("effective version before publish = %d (err %v), want 0", v, err)
	}

	res, err := h.svc.PublishPriorityRules(ctx, application.PublishPriorityRulesInput{
		Reason: "annual rules review",
		Actor:  systemActor("admin-1"),
	})
	if err != nil {
		t.Fatalf("PublishPriorityRules: %v", err)
	}
	if res.Version != 1 || res.RuleVersion != "p0000000001" {
		t.Fatalf("publish result = %+v, want version 1 / p0000000001", res)
	}

	// One command, one committed transaction with the three writes in order.
	tx := h.runner.last()
	if tx == nil || !tx.committed || tx.rolledBack {
		t.Fatalf("transaction committed=%v rolledBack=%v, want a committed one", tx, tx)
	}
	if want := []string{"priority_rules.publish", "audit", "outbox"}; !equalStrings(tx.log, want) {
		t.Fatalf("write order = %v, want %v", tx.log, want)
	}

	// The effective snapshot is the four published rules.
	rules, err := h.priorityRules.Effective(ctx)
	if err != nil {
		t.Fatalf("effective: %v", err)
	}
	if len(rules) != 4 || rules[0].RuleID != domain.PriorityP1 || rules[3].RuleID != domain.PriorityP4 {
		t.Fatalf("effective rules = %+v, want P1..P4", rules)
	}

	// The audit event names the priority_rules aggregate and the snapshot.
	audit := h.db.auditEvents[len(h.db.auditEvents)-1]
	if audit.Action != application.EventTypePriorityRulesPublished || audit.AggregateType != application.AuditAggregatePriorityRules {
		t.Fatalf("audit = %s/%s, want %s/%s", audit.Action, audit.AggregateType, application.EventTypePriorityRulesPublished, application.AuditAggregatePriorityRules)
	}
	if audit.AggregateID == "" {
		t.Fatal("audit aggregate id is empty, want a uuid")
	}
	var auditAfter map[string]any
	if err := json.Unmarshal(audit.After, &auditAfter); err != nil {
		t.Fatalf("decode audit after: %v", err)
	}
	if auditAfter["rule_version"] != res.RuleVersion {
		t.Fatalf("audit after = %v, want rule_version %s", auditAfter, res.RuleVersion)
	}

	// The outbox event carries the published version.
	out := h.db.outboxEvents[len(h.db.outboxEvents)-1]
	if out.Type != application.EventTypePriorityRulesPublished {
		t.Fatalf("outbox type = %q, want %q", out.Type, application.EventTypePriorityRulesPublished)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Payload, &payload); err != nil {
		t.Fatalf("decode outbox payload: %v", err)
	}
	if payload["rule_version"] != res.RuleVersion {
		t.Fatalf("outbox payload = %v, want rule_version %s", payload, res.RuleVersion)
	}

	// A second publish bumps the version to 2.
	res2, err := h.svc.PublishPriorityRules(ctx, application.PublishPriorityRulesInput{
		Reason: "tighten P2",
		Actor:  systemActor("admin-1"),
	})
	if err != nil {
		t.Fatalf("second PublishPriorityRules: %v", err)
	}
	if res2.Version != 2 {
		t.Fatalf("second publish version = %d, want 2", res2.Version)
	}
}

// TestPublishPriorityRulesRequiresReason rejects a blank reason before any
// write.
func TestPublishPriorityRulesRequiresReason(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.PublishPriorityRules(context.Background(), application.PublishPriorityRulesInput{
		Reason: "   ",
		Actor:  systemActor("admin-1"),
	})
	if err == nil {
		t.Fatal("blank reason accepted, want a validation error")
	}
	if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
		t.Fatalf("error kind = %s, want validation", kind)
	}
	if len(h.runner.txs) != 0 {
		t.Fatalf("opened %d transactions, want 0", len(h.runner.txs))
	}
}

// TestRecomputePriorityNoOpOnIdenticalInputs proves the changed-only persist:
// a recompute that reproduces the stored factors, the effective rule version
// and the same result opens no transaction and writes nothing.
func TestRecomputePriorityNoOpOnIdenticalInputs(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedRulesetV1(h)

	factors := p1Factors()
	sig := domain.RiskSignal{
		ID: "sig-noop", MatchID: testMatchID, Priority: domain.PriorityP1,
		Status: domain.SignalStatusNew, Version: 3, RuleVersion: "p0000000001", Factors: factors,
	}
	seedStoredSignal(h, sig)
	h.factorSource.rebuilds[sig.ID] = application.PriorityFactorRebuild{CVEID: testCveID, Factors: factors}

	res, err := h.svc.RecomputePriority(ctx, application.RecomputePriorityInput{SignalID: sig.ID, Actor: systemActor("recompute-worker")})
	if err != nil {
		t.Fatalf("RecomputePriority: %v", err)
	}
	if res.Changed {
		t.Fatalf("recompute reported Changed, want a no-op")
	}
	if res.Priority != domain.PriorityP1 || res.RuleVersion != "p0000000001" || res.InputHash == "" {
		t.Fatalf("recompute result = %+v, want P1 under p0000000001 with an input hash", res)
	}
	if len(h.runner.txs) != 0 {
		t.Fatalf("no-op recompute opened %d transactions, want 0", len(h.runner.txs))
	}
	if len(h.db.auditEvents) != 0 || len(h.db.outboxEvents) != 0 {
		t.Fatalf("no-op recompute wrote audit=%d outbox=%d, want 0/0", len(h.db.auditEvents), len(h.db.outboxEvents))
	}
	row, ok := h.db.signalRowByID(sig.ID)
	if !ok || row.sig.Version != 3 {
		t.Fatalf("stored signal version = %d (ok=%v), want unchanged 3", row.sig.Version, ok)
	}
}

// TestRecomputePriorityPersistsOnChange updates the effective priority when
// the rebuilt factors evaluate to a different class, and preserves the human
// decision for an overridden signal (auto_priority only).
func TestRecomputePriorityPersistsOnChange(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedRulesetV1(h)

	// Purely computed: P1 -> P3 on the rebuilt factors.
	sig := domain.RiskSignal{
		ID: "sig-change", MatchID: testMatchID, Priority: domain.PriorityP1,
		Status: domain.SignalStatusNew, Version: 1, RuleVersion: "p0000000001", Factors: p1Factors(),
	}
	seedStoredSignal(h, sig)
	h.factorSource.rebuilds[sig.ID] = application.PriorityFactorRebuild{CVEID: testCveID, Factors: p3Factors()}

	res, err := h.svc.RecomputePriority(ctx, application.RecomputePriorityInput{SignalID: sig.ID, Actor: systemActor("recompute-worker")})
	if err != nil {
		t.Fatalf("RecomputePriority: %v", err)
	}
	if !res.Changed || res.Priority != domain.PriorityP3 {
		t.Fatalf("recompute result = %+v, want Changed P3", res)
	}
	tx := h.runner.last()
	if want := []string{"signal.recompute", "audit"}; !equalStrings(tx.log, want) {
		t.Fatalf("write order = %v, want %v", tx.log, want)
	}
	row, _ := h.db.signalRowByID(sig.ID)
	if row.sig.Priority != domain.PriorityP3 || row.sig.Version != 2 {
		t.Fatalf("stored signal = %s v%d, want P3 v2", row.sig.Priority, row.sig.Version)
	}
	if row.sig.Factors != p3Factors() {
		t.Fatalf("stored factors = %+v, want the rebuilt set", row.sig.Factors)
	}
	if row.sig.RuleVersion != "p0000000001" {
		t.Fatalf("stored rule_version = %q, want p0000000001", row.sig.RuleVersion)
	}
	if audit := h.db.auditEvents[len(h.db.auditEvents)-1]; audit.Action != application.EventTypeSignalPriorityRecomputed {
		t.Fatalf("audit action = %q, want %q", audit.Action, application.EventTypeSignalPriorityRecomputed)
	}

	// Overridden: the effective priority stays the human decision; only
	// auto_priority moves.
	auto := domain.PriorityP2
	over := domain.RiskSignal{
		ID: "sig-over", MatchID: testMatchID, Priority: domain.PriorityP2,
		Status: domain.SignalStatusInReview, Version: 1, RuleVersion: "p0000000001", Factors: p1Factors(),
		AutoPriority: &auto, OverrideReason: "accepted risk", OverrideActorID: "analyst", OverrideAt: fixedNow,
	}
	seedStoredSignal(h, over)
	h.factorSource.rebuilds[over.ID] = application.PriorityFactorRebuild{CVEID: testCveID, Factors: p3Factors()}

	res2, err := h.svc.RecomputePriority(ctx, application.RecomputePriorityInput{SignalID: over.ID, Actor: systemActor("recompute-worker")})
	if err != nil {
		t.Fatalf("RecomputePriority (overridden): %v", err)
	}
	if !res2.Changed {
		t.Fatal("overridden recompute reported unchanged, want a write")
	}
	orow, _ := h.db.signalRowByID(over.ID)
	if orow.sig.Priority != domain.PriorityP2 {
		t.Fatalf("effective priority = %s, want the human decision P2", orow.sig.Priority)
	}
	if orow.sig.AutoPriority == nil || *orow.sig.AutoPriority != domain.PriorityP3 {
		t.Fatalf("auto_priority = %v, want the recomputed P3", orow.sig.AutoPriority)
	}
}

// TestRecomputePriorityClosedSignalProposesReopenOnce proves a closed signal
// is never mutated and the reopen proposal is emitted exactly once, however
// often the recompute re-runs over the unchanged input.
func TestRecomputePriorityClosedSignalProposesReopenOnce(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedRulesetV1(h)

	sig := domain.RiskSignal{
		ID: "sig-closed", MatchID: testMatchID, Priority: domain.PriorityP2,
		Status: domain.SignalStatusResolved, Version: 5, RuleVersion: "p0000000001", Factors: p3Factors(),
	}
	seedStoredSignal(h, sig)
	// The rebuilt factors now resolve to P1 — a difference worth proposing.
	h.factorSource.rebuilds[sig.ID] = application.PriorityFactorRebuild{CVEID: testCveID, Factors: p1Factors()}

	res, err := h.svc.RecomputePriority(ctx, application.RecomputePriorityInput{SignalID: sig.ID, Actor: systemActor("recompute-worker")})
	if err != nil {
		t.Fatalf("RecomputePriority: %v", err)
	}
	if res.Changed {
		t.Fatal("closed-signal recompute reported Changed, want no mutation")
	}
	if !res.ReopenProposed {
		t.Fatal("closed-signal recompute did not report a reopen proposal")
	}
	// No signal mutation.
	row, _ := h.db.signalRowByID(sig.ID)
	if row.sig.Status != domain.SignalStatusResolved || row.sig.Version != 5 || row.sig.Priority != domain.PriorityP2 {
		t.Fatalf("closed signal mutated: %s v%d %s", row.sig.Status, row.sig.Version, row.sig.Priority)
	}
	// Exactly one reopen-proposal event (and its audit).
	if n := countOutboxType(h, application.EventTypeSignalReopenProposed); n != 1 {
		t.Fatalf("reopen_proposed events = %d, want 1", n)
	}
	if n := countAuditAction(h, application.EventTypeSignalReopenProposed); n != 1 {
		t.Fatalf("reopen_proposed audits = %d, want 1", n)
	}
	out := h.db.outboxEvents[len(h.db.outboxEvents)-1]
	var payload map[string]any
	if err := json.Unmarshal(out.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload["signal_id"] != sig.ID || payload["from"] != "P2" || payload["to"] != "P1" {
		t.Fatalf("reopen payload = %v, want signal %s P2->P1", payload, sig.ID)
	}

	// A re-run over the unchanged input is a no-op: still exactly one event.
	res2, err := h.svc.RecomputePriority(ctx, application.RecomputePriorityInput{SignalID: sig.ID, Actor: systemActor("recompute-worker")})
	if err != nil {
		t.Fatalf("RecomputePriority (rerun): %v", err)
	}
	if res2.ReopenProposed {
		t.Fatal("rerun reported a reopen proposal, want the exactly-once no-op")
	}
	if n := countOutboxType(h, application.EventTypeSignalReopenProposed); n != 1 {
		t.Fatalf("reopen_proposed events after rerun = %d, want 1", n)
	}
	if n := countAuditAction(h, application.EventTypeSignalReopenProposed); n != 1 {
		t.Fatalf("reopen_proposed audits after rerun = %d, want 1", n)
	}
}

func countOutboxType(h *harness, evtType string) int {
	n := 0
	for _, ev := range h.db.outboxEvents {
		if ev.Type == evtType {
			n++
		}
	}
	return n
}

func countAuditAction(h *harness, action string) int {
	n := 0
	for _, ev := range h.db.auditEvents {
		if ev.Action == action {
			n++
		}
	}
	return n
}
