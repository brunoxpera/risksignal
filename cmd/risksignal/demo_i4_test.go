package main

// Unit tests of the deterministic I4 demo fixture (WP-4.08 / DEV-083). They
// need no database: the fixture table and its derivation
// (demoFixturePlan) are pure, so the coverage (P1–P4, all six statuses), the
// priority-vs-seeded-ruleset agreement and the clock/audit consistency are
// pinned without PostgreSQL. The end-to-end seed and scenario are covered by
// demo_integration_test.go against a real database.

import (
	"sort"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// TestDemoFixtureCoversEveryPriorityAndStatus pins the demo fixture's breadth:
// every priority P1–P4 and every ch. 6.3 status appears, with unique fixed
// ids (the reproducibility guarantee — a duplicate id would make the seed
// non-deterministic).
func TestDemoFixtureCoversEveryPriorityAndStatus(t *testing.T) {
	priorities := map[domain.Priority]bool{}
	statuses := map[domain.SignalStatus]bool{}
	ids := map[string]bool{}
	for _, sig := range demoFixtureSignals() {
		if ids[sig.ID] {
			t.Fatalf("duplicate fixture signal id %s", sig.ID)
		}
		ids[sig.ID] = true
		priorities[domain.ComputePriority(sig.Factors)] = true
		statuses[sig.Status] = true
	}
	for _, p := range []domain.Priority{domain.PriorityP1, domain.PriorityP2, domain.PriorityP3, domain.PriorityP4} {
		if !priorities[p] {
			t.Errorf("fixture has no %s signal", p)
		}
	}
	for _, s := range []domain.SignalStatus{
		domain.SignalStatusNew, domain.SignalStatusInReview, domain.SignalStatusActionPlanned,
		domain.SignalStatusResolved, domain.SignalStatusAccepted, domain.SignalStatusNotAffected,
	} {
		if !statuses[s] {
			t.Errorf("fixture has no %s signal", s)
		}
	}
}

// TestDemoFixturePrioritiesMatchSeededRuleset is the ARCH-004 §1.1
// behaviour-preservation check applied to the fixture: each signal's stored
// priority is exactly what the seeded ruleset v1 evaluates its factors to
// (and what the I1b compatibility entry point returns).
func TestDemoFixturePrioritiesMatchSeededRuleset(t *testing.T) {
	want := map[string]domain.Priority{
		demoFixtureSignalP1New:       domain.PriorityP1,
		demoFixtureSignalP1Planned:   domain.PriorityP1,
		demoFixtureSignalP2InReview:  domain.PriorityP2,
		demoFixtureSignalP2Resolved:  domain.PriorityP2,
		demoFixtureSignalP3Accepted:  domain.PriorityP3,
		demoFixtureSignalP3NotAffect: domain.PriorityP3,
		demoFixtureSignalP4New:       domain.PriorityP4,
		demoFixtureSignalP4Resolved:  domain.PriorityP4,
	}
	rules := domain.SeedPriorityRules()
	for _, sig := range demoFixtureSignals() {
		got, err := domain.EvaluatePriority(rules, sig.Factors)
		if err != nil {
			t.Fatalf("EvaluatePriority(%s): %v", sig.ID, err)
		}
		if got != want[sig.ID] {
			t.Errorf("%s seeded ruleset yields %s, want %s", sig.ID, got, want[sig.ID])
		}
		if c := domain.ComputePriority(sig.Factors); c != got {
			t.Errorf("%s ComputePriority = %s, want %s (the ruleset and the I1b entry point disagree)", sig.ID, c, got)
		}
	}
}

// TestDemoFixtureClocksAreConsistentWithStatus pins the derived clock state:
// a clock exists for exactly the targets the ch. 9.4 default profile defines
// at the priority; its window is started_at < deadline_at; it is fulfilled
// exactly where the journey met it (notification on delivery, acknowledgement
// on the ack step, assessment/decision on the qualifying transition) and open
// where the status has not reached it yet.
func TestDemoFixtureClocksAreConsistentWithStatus(t *testing.T) {
	profile := domain.DefaultSLATimeProfile()
	t0 := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	for _, sig := range demoFixtureSignals() {
		priority, _, _, clocks, _, err := demoFixturePlan(sig, t0)
		if err != nil {
			t.Fatalf("demoFixturePlan(%s): %v", sig.ID, err)
		}
		byTarget := map[domain.SLATarget]demoFixtureClock{}
		for _, c := range clocks {
			byTarget[c.Target] = c
			if !c.DeadlineAt.After(c.StartedAt) {
				t.Errorf("%s %s: deadline %v not after start %v", sig.ID, c.Target, c.DeadlineAt, c.StartedAt)
			}
			if want := profile.Duration(priority, c.Target); c.DeadlineAt.Sub(c.StartedAt) != want {
				t.Errorf("%s %s: window %s, want %s", sig.ID, c.Target, c.DeadlineAt.Sub(c.StartedAt), want)
			}
			if !c.FulfilledAt.IsZero() && c.FulfilledAt.Before(c.StartedAt) {
				t.Errorf("%s %s: fulfilled %v before start %v", sig.ID, c.Target, c.FulfilledAt, c.StartedAt)
			}
		}
		// Exactly the profile's targets at the priority exist.
		wantTargets := profile.Targets(priority)
		if len(clocks) != len(wantTargets) {
			t.Errorf("%s: %d clocks, want %d (%v)", sig.ID, len(clocks), len(wantTargets), wantTargets)
		}
		// P3/P4 carry no notification clock; P3/P4 no decision clock.
		if priority == domain.PriorityP3 || priority == domain.PriorityP4 {
			if _, ok := byTarget[domain.SLATargetNotification]; ok {
				t.Errorf("%s (%s): unexpected notification clock", sig.ID, priority)
			}
			if _, ok := byTarget[domain.SLATargetDecision]; ok {
				t.Errorf("%s (%s): unexpected decision clock", sig.ID, priority)
			}
		}
		// A `new` signal has every defined clock open.
		if sig.Status == domain.SignalStatusNew {
			for _, c := range clocks {
				if !c.FulfilledAt.IsZero() {
					t.Errorf("%s new: %s clock fulfilled, want open", sig.ID, c.Target)
				}
			}
		}
		// A closed signal has closed_at derived and no open assessment clock
		// (a closed state always documents an assessment).
	}
}

// TestDemoFixtureAuditsMatchJourney pins the derived audit rows: one creation
// (with a NULL before) plus one row per guarded journey step, in order, with
// the exact production actions.
func TestDemoFixtureAuditsMatchJourney(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	for _, sig := range demoFixtureSignals() {
		_, version, closedAt, _, audits, err := demoFixturePlan(sig, t0)
		if err != nil {
			t.Fatalf("demoFixturePlan(%s): %v", sig.ID, err)
		}
		steps := demoFixtureSteps(sig.Status)
		if len(audits) != 1+len(steps) {
			t.Fatalf("%s: %d audits, want %d (creation + journey)", sig.ID, len(audits), 1+len(steps))
		}
		if audits[0].Action != application.EventTypeSignalCreated || audits[0].Before != nil {
			t.Errorf("%s: first audit = %s before=%v, want a creation with NULL before", sig.ID, audits[0].Action, audits[0].Before)
		}
		for i, step := range steps {
			if audits[i+1].Action != step.Action {
				t.Errorf("%s audit %d = %s, want %s", sig.ID, i+1, audits[i+1].Action, step.Action)
			}
		}
		if int(version) != 1+len(steps) {
			t.Errorf("%s version = %d, want %d", sig.ID, version, 1+len(steps))
		}
		if sig.Status.IsClosed() != !closedAt.IsZero() {
			t.Errorf("%s closed_at = %v, want set exactly for a closed status (%s)", sig.ID, closedAt, sig.Status)
		}
	}
}

// TestDemoFixtureClockCounts pins the derived census the seed payload reports
// (so the payload, the tests and the seed cannot drift).
func TestDemoFixtureClockCounts(t *testing.T) {
	census := demoFixtureCensus(len(demoFixtureSignals()))
	if census.Signals != 8 {
		t.Errorf("fixture signals = %d, want 8", census.Signals)
	}
	if census.Clocks != 22 {
		t.Errorf("fixture clocks = %d, want 22", census.Clocks)
	}
	if census.Audits != 21 {
		t.Errorf("fixture audits = %d, want 21", census.Audits)
	}
	if census.AlreadyPresent {
		t.Error("census marked already_present on a full seed")
	}
	// A re-seed writes nothing and reports already_present.
	re := demoFixtureCensus(0)
	if !re.AlreadyPresent || re.Signals != 0 {
		t.Errorf("re-seed census = %+v, want already_present with 0 signals", re)
	}
}

// TestDemoFixtureStatusOrderIsCanonical keeps the fixture table's order
// stable (the seed writes in slice order; a reorder is a deliberate change,
// not a shuffle).
func TestDemoFixtureStatusOrderIsCanonical(t *testing.T) {
	got := make([]string, 0, 8)
	for _, sig := range demoFixtureSignals() {
		got = append(got, sig.CVEID)
	}
	sorted := append([]string(nil), got...)
	sort.Strings(sorted)
	for i := range got {
		if got[i] != sorted[i] {
			t.Fatalf("fixture CVEs %v are not in sorted order", got)
		}
	}
}
