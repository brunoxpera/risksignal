// I4 demo extension (WP-4.08 / DEV-083, ARCH-004 §8, UC-08): the
// deterministic P1–P4 signal fixture `demo seed` adds on top of the I1b
// synthetic source, and the accelerated end-to-end SLA scenario `demo run`
// drives.
//
// Two halves, both dev-only operator tooling of the demo command (the
// production write paths are untouched — the create path stays
// CreateSignal/InsertRiskSignal, ARCH-001 §2):
//
//   - seedDemoFixture writes a fixed set of eight risk signals covering
//     P1–P4 and every ch. 6.3 status (new, in_review, action_planned,
//     resolved, accepted, not_affected). The ids are fixed UUIDs, so a
//     re-seed is byte-for-byte reproducible; the SLA clocks are derived
//     from the same tree the production use cases apply (a progression
//     fulfils exactly the targets its transitions complete, ARCH-004 §4.3)
//     and every signal carries the audit rows of its journey. The factors
//     are chosen so the seeded ruleset v1 (SeedPriorityRules) yields the
//     intended class — pinned by TestDemoFixturePrioritiesAreSeededRuleset.
//
//   - runDemoScenario (UC-08) drives the REAL application use cases
//     (CreateSignal, AcknowledgeSignal, TransitionSignal, OverridePriority)
//     and the REAL worker pieces (the outbox relay + notify handler, the
//     sla.evaluate scheduler) on a scaled SLATimeProfile and an injected
//     FakeClock: a P1 create → deliver (notification clock) → acknowledge →
//     action_planned (assessment + decision) → resolve; a P3→P1 upgrade
//     (missing clocks created, existing clocks tightened); and an
//     unacknowledged P1 that escalates exactly once. The machine-readable
//     --output json result reports the observed state at each step.
//
// Determinism: the fixture is a fixed table with fixed ids (no random) and
// the scenario is driven on the injected clock (no wall-clock waiting); the
// only non-fixed values are the ids the production create path assigns
// (gen_random_uuid) and the timestamps derived from the injected instant.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/adapters/notify"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/repo"
	"github.com/brunoxpera/risksignal/internal/adapters/worker"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

// Stable identities of the I4 demo fixture and the UC-08 scenario. The
// fixture asset carries its own inventory source tag ("demo-i4"), so the
// existing synthetic-reference assertions can scope to the synthetic source
// ("demo") without the fixture noise; the scenario uses "demo-uc08".
const (
	demoI4Source          = "demo-i4"
	demoI4AssetExternalID = "asset-i4-fixture"
	demoI4AssetName       = "I4 Fixture"
	demoFixtureActorID    = "demo-fixture"

	demoScenarioSource          = "demo-uc08"
	demoScenarioAssetExternalID = "asset-uc08"
	demoScenarioAssetName       = "UC-08 Scenario"
	demoScenarioActorID         = "demo-scenario"
)

// Fixed fixture signal ids (deterministic: the same eight ids on every seed).
// They live under the RFC 4122 variant/version-4 layout but are constants,
// not generated — the reproducibility guarantee of the demo seed (ARCH-001
// §3).
const (
	demoFixtureSignalP1New       = "d3f10000-0000-4000-8000-000000000001"
	demoFixtureSignalP1Planned   = "d3f10000-0000-4000-8000-000000000002"
	demoFixtureSignalP2InReview  = "d3f10000-0000-4000-8000-000000000003"
	demoFixtureSignalP2Resolved  = "d3f10000-0000-4000-8000-000000000004"
	demoFixtureSignalP3Accepted  = "d3f10000-0000-4000-8000-000000000005"
	demoFixtureSignalP3NotAffect = "d3f10000-0000-4000-8000-000000000006"
	demoFixtureSignalP4New       = "d3f10000-0000-4000-8000-000000000007"
	demoFixtureSignalP4Resolved  = "d3f10000-0000-4000-8000-000000000008"
)

// demoFixtureSignal is one deterministic fixture signal: a fixed id, the
// CVE and factors it is built from, its target status and whether its
// notification was already delivered (the one clock state that no status
// transition expresses — delivery is the notify handler's fulfilment,
// ARCH-004 §6.3). Everything else (clocks, audits, version, closed_at) is
// derived from the target status by demoFixturePlan, so the fixture can
// never carry an internally inconsistent clock or a missing audit.
type demoFixtureSignal struct {
	ID       string
	CVEID    string
	Summary  string
	Factors  domain.PriorityFactors
	Status   domain.SignalStatus
	Notified bool
}

// demoFixtureSignals returns the fixed eight-signal fixture (one P1, two P2,
// two P3, two P4 with distinct statuses; every ch. 6.3 status is covered).
// Order is the seed order and never changes.
func demoFixtureSignals() []demoFixtureSignal {
	return []demoFixtureSignal{
		{
			ID:      demoFixtureSignalP1New,
			CVEID:   "CVE-2026-9001",
			Summary: "Remote code execution in acme/i4-fixture (new P1)",
			Factors: domain.PriorityFactors{
				Method: domain.MatchMethodExactIdentifier, Confidence: domain.ConfidenceHigh,
				KEV: true, CVSS: 9.8, EPSS: 0.9, Criticality: domain.CriticalityCritical, Exposure: domain.ExposureInternet,
			},
			Status: domain.SignalStatusNew,
		},
		{
			ID:      demoFixtureSignalP1Planned,
			CVEID:   "CVE-2026-9002",
			Summary: "Remote code execution in acme/i4-fixture (action planned P1)",
			Factors: domain.PriorityFactors{
				Method: domain.MatchMethodExactIdentifier, Confidence: domain.ConfidenceHigh,
				KEV: true, CVSS: 9.5, EPSS: 0.8, Criticality: domain.CriticalityHigh, Exposure: domain.ExposureInternal,
			},
			Status:   domain.SignalStatusActionPlanned,
			Notified: true,
		},
		{
			ID:      demoFixtureSignalP2InReview,
			CVEID:   "CVE-2026-9003",
			Summary: "Critical CVSS in acme/i4-fixture (in review P2)",
			Factors: domain.PriorityFactors{
				Method: domain.MatchMethodCanonicalProductRange, Confidence: domain.ConfidenceHigh,
				KEV: false, CVSS: 9.4, EPSS: 0.5, Criticality: domain.CriticalityNormal, Exposure: domain.ExposureInternal,
			},
			Status:   domain.SignalStatusInReview,
			Notified: true,
		},
		{
			ID:      demoFixtureSignalP2Resolved,
			CVEID:   "CVE-2026-9004",
			Summary: "High EPSS in acme/i4-fixture (resolved P2)",
			Factors: domain.PriorityFactors{
				Method: domain.MatchMethodAliasExactVersion, Confidence: domain.ConfidenceHigh,
				KEV: false, CVSS: 6.0, EPSS: 0.97, Criticality: domain.CriticalityLow, Exposure: domain.ExposureInternal,
			},
			Status:   domain.SignalStatusResolved,
			Notified: true,
		},
		{
			ID:      demoFixtureSignalP3Accepted,
			CVEID:   "CVE-2026-9005",
			Summary: "Plausible assignment in acme/i4-fixture (accepted P3)",
			Factors: domain.PriorityFactors{
				Method: domain.MatchMethodExactIdentifier, Confidence: domain.ConfidenceHigh,
				KEV: false, CVSS: 7.0, EPSS: 0.3, Criticality: domain.CriticalityHigh, Exposure: domain.ExposureInternal,
			},
			Status: domain.SignalStatusAccepted,
		},
		{
			ID:      demoFixtureSignalP3NotAffect,
			CVEID:   "CVE-2026-9006",
			Summary: "Uncertain version in acme/i4-fixture (not affected P3)",
			Factors: domain.PriorityFactors{
				Method: domain.MatchMethodProductUncertainVersion, Confidence: domain.ConfidenceMedium,
				KEV: false, CVSS: 8.0, EPSS: 0.5, Criticality: domain.CriticalityCritical, Exposure: domain.ExposureInternal,
			},
			Status: domain.SignalStatusNotAffected,
		},
		{
			ID:      demoFixtureSignalP4New,
			CVEID:   "CVE-2026-9007",
			Summary: "Low-confidence candidate in acme/i4-fixture (new P4)",
			Factors: domain.PriorityFactors{
				Method: domain.MatchMethodCandidate, Confidence: domain.ConfidenceLow,
				KEV: true, CVSS: 10.0, EPSS: 1.0, Criticality: domain.CriticalityCritical, Exposure: domain.ExposureInternet,
			},
			Status: domain.SignalStatusNew,
		},
		{
			ID:      demoFixtureSignalP4Resolved,
			CVEID:   "CVE-2026-9008",
			Summary: "No-match fallback in acme/i4-fixture (resolved P4)",
			Factors: domain.PriorityFactors{
				Method: domain.MatchMethodNoMatch, Confidence: domain.ConfidenceNone,
				KEV: true, CVSS: 10.0, EPSS: 1.0, Criticality: domain.CriticalityCritical, Exposure: domain.ExposureInternet,
			},
			Status: domain.SignalStatusResolved,
		},
	}
}

// demoFixtureStep is one guarded step of a fixture signal's canonical journey
// (a new signal is created, then acknowledged, then transitioned). The action
// is the exact audit action the production command writes.
type demoFixtureStep struct {
	Action string
	To     domain.SignalStatus
	Reason string
}

// demoFixtureSteps returns the canonical journey from new to the target
// status: a direct ch. 6.3 path that visits every intermediate status the
// state machine requires and whose transitions are exactly the ones whose
// clock fulfilments the fixture clocks below encode. The ack step is the
// AcknowledgeSignal command (new → in_review), the rest are TransitionSignal.
func demoFixtureSteps(status domain.SignalStatus) []demoFixtureStep {
	const acknowledge = application.EventTypeSignalAcknowledged
	const transition = application.EventTypeSignalTransitioned
	switch status {
	case domain.SignalStatusNew:
		return nil
	case domain.SignalStatusInReview:
		return []demoFixtureStep{{Action: acknowledge, To: domain.SignalStatusInReview}}
	case domain.SignalStatusActionPlanned:
		return []demoFixtureStep{
			{Action: acknowledge, To: domain.SignalStatusInReview},
			{Action: transition, To: domain.SignalStatusActionPlanned},
		}
	case domain.SignalStatusAccepted:
		return []demoFixtureStep{
			{Action: acknowledge, To: domain.SignalStatusInReview},
			{Action: transition, To: domain.SignalStatusAccepted, Reason: "accepted by the demo fixture"},
		}
	case domain.SignalStatusNotAffected:
		return []demoFixtureStep{
			{Action: acknowledge, To: domain.SignalStatusInReview},
			{Action: transition, To: domain.SignalStatusNotAffected, Reason: "not affected per the demo fixture"},
		}
	case domain.SignalStatusResolved:
		return []demoFixtureStep{
			{Action: acknowledge, To: domain.SignalStatusInReview},
			{Action: transition, To: domain.SignalStatusActionPlanned},
			{Action: transition, To: domain.SignalStatusResolved, Reason: "verified resolved by the demo fixture"},
		}
	default:
		return nil
	}
}

// demoFixtureClock is one derived fixture clock: the frozen window plus the
// fulfilment instant (zero = open).
type demoFixtureClock struct {
	Target      domain.SLATarget
	StartedAt   time.Time
	DeadlineAt  time.Time
	FulfilledAt time.Time
}

// demoFixtureAudit is one derived fixture audit row (the minimised before/
// after snapshots, nil before on the creation).
type demoFixtureAudit struct {
	Action     string
	OccurredAt time.Time
	Before     []byte
	After      []byte
}

// demoFixturePlan derives the whole observable state of one fixture signal
// from its target status and the injected instant t0: the priority (the
// seeded ruleset's class), the optimistic-lock version, the closed_at stamp,
// the SLA clocks and the audit rows.
//
// The clock windows start at the creation instant (t0 − 3m) and freeze
// deadline = start + duration(priority, target) of the ch. 9.4 default
// profile — so an open clock of every fixture signal sits comfortably in the
// future (the fixture never tears a running SLA window) while a fulfilled
// clock records the instant its target was met. The fulfilment rules mirror
// the production treatment (ARCH-004 §4.3): acknowledgement on the ack step,
// assessment on the first transition into action_planned/not_affected/
// accepted/resolved, decision on the first into action_planned/accepted/
// resolved, notification on technical delivery (the Notified flag). The
// journey's instants are created t0−3m, ack t0−2m, transition i at t0−(1−i)
// minutes.
func demoFixturePlan(sig demoFixtureSignal, t0 time.Time) (priority domain.Priority, version int32, closedAt time.Time, clocks []demoFixtureClock, audits []demoFixtureAudit, err error) {
	priority = domain.ComputePriority(sig.Factors)
	steps := demoFixtureSteps(sig.Status)
	version = int32(1 + len(steps)) //nolint:gosec // 1..4: the fixed fixture journey length
	created := t0.Add(-3 * time.Minute)
	stepAt := func(i int) time.Time { return t0.Add(time.Duration(-2+i) * time.Minute) }

	// Audits: the creation, then one row per journey step, before/after the
	// minimised state snapshots the production commands write.
	createdAfter, err := demoFixtureSnapshot(sig.ID, domain.SignalStatusNew, priority, 1, "")
	if err != nil {
		return "", 0, time.Time{}, nil, nil, err
	}
	audits = append(audits, demoFixtureAudit{Action: application.EventTypeSignalCreated, OccurredAt: created, After: createdAfter})
	from := domain.SignalStatusNew
	for i, step := range steps {
		before, err := demoFixtureSnapshot(sig.ID, from, priority, 1+i, "")
		if err != nil {
			return "", 0, time.Time{}, nil, nil, err
		}
		after, err := demoFixtureSnapshot(sig.ID, step.To, priority, 2+i, step.Reason)
		if err != nil {
			return "", 0, time.Time{}, nil, nil, err
		}
		audits = append(audits, demoFixtureAudit{Action: step.Action, OccurredAt: stepAt(i), Before: before, After: after})
		from = step.To
	}
	if sig.Status.IsClosed() && len(steps) > 0 {
		closedAt = stepAt(len(steps) - 1)
	}

	// Clocks: every target the profile defines at the priority, fulfilled
	// exactly where the journey (or the delivery flag) met it.
	ackStep, assessmentAt, decisionAt := -1, time.Time{}, time.Time{}
	for i, step := range steps {
		if step.Action == application.EventTypeSignalAcknowledged {
			ackStep = i
		}
		switch step.To {
		case domain.SignalStatusActionPlanned, domain.SignalStatusAccepted, domain.SignalStatusResolved:
			if assessmentAt.IsZero() {
				assessmentAt = stepAt(i)
			}
			if decisionAt.IsZero() {
				decisionAt = stepAt(i)
			}
		case domain.SignalStatusNotAffected:
			if assessmentAt.IsZero() {
				assessmentAt = stepAt(i)
			}
		}
	}
	profile := domain.DefaultSLATimeProfile()
	for _, target := range profile.Targets(priority) {
		clock := demoFixtureClock{
			Target:     target,
			StartedAt:  created,
			DeadlineAt: created.Add(profile.Duration(priority, target)),
		}
		switch target {
		case domain.SLATargetNotification:
			if sig.Notified {
				clock.FulfilledAt = stepAt(0) // delivered before the first journey step
			}
		case domain.SLATargetAcknowledgement:
			if ackStep >= 0 {
				clock.FulfilledAt = stepAt(ackStep)
			}
		case domain.SLATargetAssessment:
			clock.FulfilledAt = assessmentAt
		case domain.SLATargetDecision:
			clock.FulfilledAt = decisionAt
		}
		clocks = append(clocks, clock)
	}
	return priority, version, closedAt, clocks, audits, nil
}

// demoFixtureSnapshot is the minimised before/after audit snapshot of a
// fixture signal — the exact shape the production commands' snapshots use
// (ch. 13.5): identity, status, effective priority, optimistic-lock version
// and the documented reason.
func demoFixtureSnapshot(id string, status domain.SignalStatus, priority domain.Priority, version int, reason string) ([]byte, error) {
	return json.Marshal(struct {
		ID       string `json:"id"`
		Status   string `json:"status"`
		Priority string `json:"priority"`
		Version  int    `json:"version"`
		Reason   string `json:"reason,omitempty"`
	}{ID: id, Status: string(status), Priority: string(priority), Version: version, Reason: reason})
}

// seedDemoFixture writes the deterministic I4 fixture set under the dedicated
// "demo-i4" inventory asset in one transaction and returns the number of
// signals written (0 when the fixture is already present — a re-seed is an
// idempotent no-op, so the fixed ids, statuses and clocks never drift). The
// asset/component/vulnerability/match upserts are natural-key safe; the
// signal rows carry the fixed fixture ids and the derived clocks and audits.
func seedDemoFixture(ctx context.Context, pool *pgxpool.Pool, now time.Time) (int, error) {
	written := 0
	err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		qtx := gen.New(pool).WithTx(tx)

		assetID, err := qtx.UpsertAsset(ctx, gen.UpsertAssetParams{
			ExternalID:  demoI4AssetExternalID,
			Source:      demoI4Source,
			Type:        string(domain.AssetTypeServerVM),
			Name:        demoI4AssetName,
			Environment: string(domain.EnvironmentProduction),
			Criticality: string(domain.CriticalityCritical),
			Exposure:    string(domain.ExposureInternet),
			Owner:       demoTextOpt("ops"),
		})
		if err != nil {
			return err
		}

		// Idempotency: the fixture is present as soon as its asset carries a
		// signal. A re-seed then writes nothing — the fixed rows stay exactly
		// as the first seed wrote them.
		var existing int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM risk_signals rs
			 JOIN matches m ON m.id = rs.match_id
			 JOIN components c ON c.id = m.component_id
			 WHERE c.asset_id = $1`, assetID).Scan(&existing); err != nil {
			return err
		}
		if existing > 0 {
			return nil
		}

		componentID, err := qtx.InsertComponent(ctx, gen.InsertComponentParams{
			AssetID:       assetID,
			Vendor:        "acme",
			Product:       "i4-fixture",
			Version:       "1.0",
			VendorNorm:    "acme",
			ProductNorm:   "i4-fixture",
			VersionScheme: string(domain.VersionSchemeUnknown),
			NaturalKey:    demoFixtureComponentNaturalKey(),
			UpdatedAt:     pgtype.Timestamptz{Time: now, Valid: true},
		})
		if err != nil {
			return err
		}

		for _, sig := range demoFixtureSignals() {
			priority, version, closedAt, clocks, audits, err := demoFixturePlan(sig, now)
			if err != nil {
				return err
			}
			vulnID, err := qtx.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
				CveID:       sig.CVEID,
				Summary:     sig.Summary,
				PublishedAt: pgtype.Timestamptz{Time: now.AddDate(0, 0, -30), Valid: true},
				ModifiedAt:  pgtype.Timestamptz{Time: now.AddDate(0, 0, -1), Valid: true},
			})
			if err != nil {
				return err
			}
			matchID, err := qtx.InsertMatch(ctx, gen.InsertMatchParams{
				VulnerabilityID: vulnID,
				ComponentID:     componentID,
				Method:          string(sig.Factors.Method),
				Score:           demoFixtureRank(sig.Factors.Confidence),
				Confidence:      string(sig.Factors.Confidence),
				RuleVersion:     domain.MatchRuleVersion,
				CreatedAt:       pgtype.Timestamptz{Time: now, Valid: true},
				Reasons:         []byte("[]"),
			})
			if err != nil {
				return err
			}
			factors, err := json.Marshal(sig.Factors)
			if err != nil {
				return err
			}
			if _, err := qtx.InsertDemoRiskSignal(ctx, gen.InsertDemoRiskSignalParams{
				ID:          demoUUIDMust(sig.ID),
				MatchID:     matchID,
				Priority:    string(priority),
				Status:      string(sig.Status),
				ClosedAt:    demoTimeOpt(closedAt),
				Version:     version,
				RuleVersion: domain.PriorityRuleVersionI1b,
				Factors:     factors,
				CreatedAt:   pgtype.Timestamptz{Time: now.Add(-3 * time.Minute), Valid: true},
			}); err != nil {
				return err
			}
			for _, clk := range clocks {
				if _, err := qtx.UpsertSlaClock(ctx, gen.UpsertSlaClockParams{
					SignalID:    demoUUIDMust(sig.ID),
					Target:      string(clk.Target),
					StartedAt:   pgtype.Timestamptz{Time: clk.StartedAt, Valid: true},
					DeadlineAt:  pgtype.Timestamptz{Time: clk.DeadlineAt, Valid: true},
					FulfilledAt: demoTimeOpt(clk.FulfilledAt),
				}); err != nil {
					return err
				}
			}
			for _, audit := range audits {
				if _, err := qtx.InsertAuditEvent(ctx, gen.InsertAuditEventParams{
					AggregateType: application.AuditAggregateRiskSignal,
					AggregateID:   demoUUIDMust(sig.ID),
					ActorType:     application.ActorTypeSystem,
					ActorID:       demoFixtureActorID,
					Action:        audit.Action,
					OccurredAt:    pgtype.Timestamptz{Time: audit.OccurredAt, Valid: true},
					Before:        audit.Before,
					After:         audit.After,
					CorrelationID: "demo-fixture:" + sig.ID + ":" + audit.Action,
				}); err != nil {
					return err
				}
			}
			written++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return written, nil
}

// demoFixtureComponentNaturalKey derives the fixture component's import
// idempotency key exactly as the seed write path does (the vendor/product/
// version fallback of the domain, no CPE/purl/digest identity in the demo).
func demoFixtureComponentNaturalKey() string {
	key, err := domain.ComponentNaturalKey(domain.ComponentIdentifiers{
		Vendor: "acme", Product: "i4-fixture", Version: "1.0",
	}, "acme", "i4-fixture", "")
	if err != nil {
		panic("demo: fixture component natural key: " + err.Error())
	}
	return key
}

// demoFixtureRank is the ADR-015 sort-rank placeholder of a fixture match
// (the same shape the reference-matrix test seeds: high 100, medium 60,
// lower confidence 0 — the value is fixture noise, the method stays
// authoritative). It returns the stored int32 directly (the matches.score
// column type), so no lossy conversion is needed at the call sites.
func demoFixtureRank(confidence domain.Confidence) int32 {
	switch confidence {
	case domain.ConfidenceHigh:
		return 100
	case domain.ConfidenceMedium:
		return 60
	default:
		return 0
	}
}

// demoFixtureSummary is the machine-readable census of the seeded fixture
// (the demo seed payload reports it alongside the synthetic run).
type demoFixtureSummary struct {
	Signals        int  `json:"signals"`
	Clocks         int  `json:"sla_clocks"`
	Audits         int  `json:"audits"`
	AlreadyPresent bool `json:"already_present"`
}

// demoFixtureCensus derives the fixture census from the same table the seed
// writes, so the payload, the tests and the seed can never disagree.
func demoFixtureCensus(written int) demoFixtureSummary {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var clocks, audits int
	for _, sig := range demoFixtureSignals() {
		_, _, _, cl, au, err := demoFixturePlan(sig, now)
		if err != nil {
			continue
		}
		clocks += len(cl)
		audits += len(au)
	}
	return demoFixtureSummary{Signals: written, Clocks: clocks, Audits: audits, AlreadyPresent: written == 0}
}

// --- UC-08 accelerated scenario -----------------------------------------

// demoScenarioReminderCadence is the scaled escalation reminder cadence of
// the accelerated scenario (the production default is one hour; ARCH-004
// §4.4 keeps the cadence a config value, never table state).
const demoScenarioReminderCadence = 2 * time.Second

// demoScenarioCadence is the scaled sla.evaluate cadence of the scenario run.
const demoScenarioCadence = time.Second

// scaledDemoProfile is the accelerated (priority, target) → duration profile:
// the ch. 9.4 shape at second scale (P1 pages + decides, P2 per FR-023,
// P3/P4 carry only the ack/assessment clocks), so the whole lifecycle runs
// instantly on the injected clock (FR-032, NFR-015).
func scaledDemoProfile() (domain.SLATimeProfile, error) {
	return domain.NewSLATimeProfile(map[domain.Priority]map[domain.SLATarget]time.Duration{
		domain.PriorityP1: {
			domain.SLATargetNotification:    1 * time.Second,
			domain.SLATargetAcknowledgement: 2 * time.Second,
			domain.SLATargetAssessment:      5 * time.Second,
			domain.SLATargetDecision:        8 * time.Second,
		},
		domain.PriorityP2: {
			domain.SLATargetNotification:    1 * time.Second,
			domain.SLATargetAcknowledgement: 3 * time.Second,
			domain.SLATargetAssessment:      6 * time.Second,
			domain.SLATargetDecision:        10 * time.Second,
		},
		domain.PriorityP3: {
			domain.SLATargetAcknowledgement: 4 * time.Second,
			domain.SLATargetAssessment:      7 * time.Second,
		},
		domain.PriorityP4: {
			domain.SLATargetAssessment: 9 * time.Second,
		},
	})
}

// demoScenarioClockState is the JSON shape of one read-back SLA clock.
type demoScenarioClockState struct {
	StartedAt   time.Time  `json:"started_at"`
	DeadlineAt  time.Time  `json:"deadline_at"`
	FulfilledAt *time.Time `json:"fulfilled_at"`
}

// demoScenarioLifecycle is the P1 create → deliver → acknowledge →
// action_planned → resolve half of the scenario.
type demoScenarioLifecycle struct {
	SignalID              string                            `json:"signal_id"`
	Priority              string                            `json:"priority"`
	StatusHistory         []string                          `json:"status_history"`
	Version               int                               `json:"version"`
	NotificationDelivered bool                              `json:"notification_delivered"`
	ClosedAt              *time.Time                        `json:"closed_at"`
	Clocks                map[string]demoScenarioClockState `json:"clocks"`
}

// demoTightenedClock is one clock tightened by the P3→P1 upgrade.
type demoTightenedClock struct {
	Target      string    `json:"target"`
	OldDeadline time.Time `json:"old_deadline_at"`
	NewDeadline time.Time `json:"new_deadline_at"`
}

// demoScenarioUpgrade is the P3→P1 upgrade half: the created clocks, the
// tightened clocks (old→new deadline) and the per-mutation audit counts.
type demoScenarioUpgrade struct {
	SignalID        string               `json:"signal_id"`
	FromPriority    string               `json:"from_priority"`
	ToPriority      string               `json:"to_priority"`
	ClocksCreated   []string             `json:"clocks_created"`
	ClocksTightened []demoTightenedClock `json:"clocks_tightened"`
	CreatedAudits   int                  `json:"created_audits"`
	TightenedAudits int                  `json:"tightened_audits"`
}

// demoScenarioEscalation is the unacknowledged-P1 half: the set-once
// escalation instant, the escalation count and the cadence reminders.
type demoScenarioEscalation struct {
	SignalID    string     `json:"signal_id"`
	EscalatedAt *time.Time `json:"escalated_at"`
	Escalations int        `json:"escalations"`
	Reminders   int        `json:"reminders"`
}

// demoScenarioResult is the machine-readable result of `demo run`.
type demoScenarioResult struct {
	Scenario   string                 `json:"scenario"`
	Lifecycle  demoScenarioLifecycle  `json:"lifecycle"`
	Upgrade    demoScenarioUpgrade    `json:"upgrade"`
	Escalation demoScenarioEscalation `json:"escalation"`
}

// runDemoScenario is UC-08: it drives the real use cases and worker pieces on
// a scaled profile and the injected clock, then returns the machine-readable
// result. It requires the demo to be seeded (the caller checks) and resets
// its own scenario rows first, so it is re-runnable.
func runDemoScenario(ctx context.Context, pool *pgxpool.Pool) (demoScenarioResult, error) {
	profile, err := scaledDemoProfile()
	if err != nil {
		return demoScenarioResult{}, err
	}
	// The scenario instant sits an hour in the past, so every scaled deadline
	// the scenario creates is already past the database's now() — the
	// sla.evaluate breach scan sees it (the scan compares against now()),
	// while the injected clock keeps the escalation instant deterministic.
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	clk := clock.NewFakeClock(base)
	svc := newDemoScenarioService(pool, clk, profile)

	if err := resetDemoScenario(ctx, pool); err != nil {
		return demoScenarioResult{}, err
	}
	matches, err := seedDemoScenarioChain(ctx, pool, base)
	if err != nil {
		return demoScenarioResult{}, err
	}
	relay, err := newDemoNotifyRelay(pool, clk)
	if err != nil {
		return demoScenarioResult{}, err
	}
	sched, err := worker.NewSlaSchedule(svc, clk, demoScenarioCadence, nil)
	if err != nil {
		return demoScenarioResult{}, err
	}
	actor := application.Actor{Type: application.ActorTypeSystem, ID: demoScenarioActorID}

	lifecycle, err := runDemoLifecycle(ctx, svc, relay, pool, clk, matches.lifecycle, actor)
	if err != nil {
		return demoScenarioResult{}, err
	}
	upgrade, err := runDemoUpgrade(ctx, svc, pool, clk, matches.upgrade, actor)
	if err != nil {
		return demoScenarioResult{}, err
	}
	escalation, err := runDemoEscalation(ctx, svc, relay, sched, pool, clk, matches.escalation, actor)
	if err != nil {
		return demoScenarioResult{}, err
	}
	return demoScenarioResult{
		Scenario:   "uc-08-accelerated-sla-lifecycle",
		Lifecycle:  lifecycle,
		Upgrade:    upgrade,
		Escalation: escalation,
	}, nil
}

// runDemoLifecycle drives the full P1 lifecycle: create (all four clocks),
// deliver (the notify handler fulfils the notification clock), acknowledge
// (ack clock, → in_review), action_planned (assessment + decision), resolve
// (closed_at). Every instant comes from the injected clock.
func runDemoLifecycle(ctx context.Context, svc *application.Service, relay *worker.Relay, pool *pgxpool.Pool, clk *clock.FakeClock, matchID string, actor application.Actor) (demoScenarioLifecycle, error) {
	created, err := svc.CreateSignal(ctx, application.CreateSignalInput{
		MatchID: matchID, CveID: demoScenarioCVELifecycle, Factors: demoScenarioP1Factors(), Actor: actor,
	})
	if err != nil {
		return demoScenarioLifecycle{}, err
	}
	sig := created.Signal
	history := []string{string(sig.Status)}

	if err := relay.Drain(ctx); err != nil {
		return demoScenarioLifecycle{}, err
	}
	notified, err := demoNotificationDelivered(ctx, pool, sig.ID)
	if err != nil {
		return demoScenarioLifecycle{}, err
	}

	clk.Advance(500 * time.Millisecond)
	acked, err := svc.AcknowledgeSignal(ctx, application.AcknowledgeSignalInput{
		SignalID: sig.ID, ExpectedVersion: sig.Version, Actor: actor,
	})
	if err != nil {
		return demoScenarioLifecycle{}, err
	}
	history = append(history, string(acked.Status))

	clk.Advance(500 * time.Millisecond)
	planned, err := svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusActionPlanned, ExpectedVersion: acked.Version, Actor: actor,
	})
	if err != nil {
		return demoScenarioLifecycle{}, err
	}
	history = append(history, string(planned.Status))

	clk.Advance(500 * time.Millisecond)
	resolved, err := svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusResolved, Reason: "patch verified by the demo scenario",
		ExpectedVersion: planned.Version, Actor: actor,
	})
	if err != nil {
		return demoScenarioLifecycle{}, err
	}
	history = append(history, string(resolved.Status))

	clocks, closedAt, err := demoReadClocks(ctx, pool, sig.ID)
	if err != nil {
		return demoScenarioLifecycle{}, err
	}
	return demoScenarioLifecycle{
		SignalID:              sig.ID,
		Priority:              string(sig.Priority),
		StatusHistory:         history,
		Version:               resolved.Version,
		NotificationDelivered: notified,
		ClosedAt:              closedAt,
		Clocks:                clocks,
	}, nil
}

// runDemoUpgrade drives the P3→P1 upgrade: create a P3 signal, then override
// to P1 through the real command — the missing notification/decision clocks
// are created from the upgrade instant and the existing acknowledgement/
// assessment deadlines tightened (audited per mutation).
func runDemoUpgrade(ctx context.Context, svc *application.Service, pool *pgxpool.Pool, clk *clock.FakeClock, matchID string, actor application.Actor) (demoScenarioUpgrade, error) {
	created, err := svc.CreateSignal(ctx, application.CreateSignalInput{
		MatchID: matchID, CveID: demoScenarioCVEUpgrade, Factors: demoScenarioP3Factors(), Actor: actor,
	})
	if err != nil {
		return demoScenarioUpgrade{}, err
	}
	sig := created.Signal
	before, err := demoReadClockRow(ctx, pool, sig.ID, domain.SLATargetAcknowledgement)
	if err != nil {
		return demoScenarioUpgrade{}, err
	}
	assessmentBefore, err := demoReadClockRow(ctx, pool, sig.ID, domain.SLATargetAssessment)
	if err != nil {
		return demoScenarioUpgrade{}, err
	}
	hadNotification, err := demoClockExists(ctx, pool, sig.ID, domain.SLATargetNotification)
	if err != nil {
		return demoScenarioUpgrade{}, err
	}
	hadDecision, err := demoClockExists(ctx, pool, sig.ID, domain.SLATargetDecision)
	if err != nil {
		return demoScenarioUpgrade{}, err
	}

	clk.Advance(time.Second)
	if _, err := svc.OverridePriority(ctx, application.OverridePriorityInput{
		SignalID: sig.ID, Priority: domain.PriorityP1, Reason: "KEV added by the demo scenario",
		ExpectedVersion: sig.Version, Actor: actor,
	}); err != nil {
		return demoScenarioUpgrade{}, err
	}

	ackAfter, err := demoReadClockRow(ctx, pool, sig.ID, domain.SLATargetAcknowledgement)
	if err != nil {
		return demoScenarioUpgrade{}, err
	}
	assessmentAfter, err := demoReadClockRow(ctx, pool, sig.ID, domain.SLATargetAssessment)
	if err != nil {
		return demoScenarioUpgrade{}, err
	}
	hasNotification, err := demoClockExists(ctx, pool, sig.ID, domain.SLATargetNotification)
	if err != nil {
		return demoScenarioUpgrade{}, err
	}
	hasDecision, err := demoClockExists(ctx, pool, sig.ID, domain.SLATargetDecision)
	if err != nil {
		return demoScenarioUpgrade{}, err
	}

	var clocksCreated []string
	if !hadNotification && hasNotification {
		clocksCreated = append(clocksCreated, string(domain.SLATargetNotification))
	}
	if !hadDecision && hasDecision {
		clocksCreated = append(clocksCreated, string(domain.SLATargetDecision))
	}
	tightened := []demoTightenedClock{}
	if ackAfter.Before(before) {
		tightened = append(tightened, demoTightenedClock{Target: string(domain.SLATargetAcknowledgement), OldDeadline: before, NewDeadline: ackAfter})
	}
	if assessmentAfter.Before(assessmentBefore) {
		tightened = append(tightened, demoTightenedClock{Target: string(domain.SLATargetAssessment), OldDeadline: assessmentBefore, NewDeadline: assessmentAfter})
	}

	createdAudits, tightenedAudits, err := demoCountAudits(ctx, pool, sig.ID)
	if err != nil {
		return demoScenarioUpgrade{}, err
	}
	return demoScenarioUpgrade{
		SignalID:        sig.ID,
		FromPriority:    string(domain.PriorityP3),
		ToPriority:      string(domain.PriorityP1),
		ClocksCreated:   clocksCreated,
		ClocksTightened: tightened,
		CreatedAudits:   createdAudits,
		TightenedAudits: tightenedAudits,
	}, nil
}

// runDemoEscalation drives the unacknowledged-P1 escalation: create a P1,
// deliver it, then let the real sla.evaluate scheduler breach the ack clock —
// the escalation fires exactly once and a later cadence window emits one
// reminder.
func runDemoEscalation(ctx context.Context, svc *application.Service, relay *worker.Relay, sched *worker.SlaSchedule, pool *pgxpool.Pool, clk *clock.FakeClock, matchID string, actor application.Actor) (demoScenarioEscalation, error) {
	created, err := svc.CreateSignal(ctx, application.CreateSignalInput{
		MatchID: matchID, CveID: demoScenarioCVEEscalation, Factors: demoScenarioP1Factors(), Actor: actor,
	})
	if err != nil {
		return demoScenarioEscalation{}, err
	}
	sig := created.Signal
	if err := relay.Drain(ctx); err != nil { // deliver the signal.created notification
		return demoScenarioEscalation{}, err
	}
	clk.Advance(2500 * time.Millisecond) // cross the scaled 2s ack deadline
	if err := sched.Tick(ctx); err != nil {
		return demoScenarioEscalation{}, err
	}
	at, err := demoEscalatedAt(ctx, pool, sig.ID)
	if err != nil {
		return demoScenarioEscalation{}, err
	}
	escalations, err := demoCountOutboxType(ctx, pool, application.EventTypeSignalEscalated, sig.ID)
	if err != nil {
		return demoScenarioEscalation{}, err
	}
	// A later due tick (the cadence gate has elapsed) must not re-escalate:
	// the set-once marker sends the already-escalated signal down the reminder
	// path instead, keeping the escalation exactly-once.
	clk.Advance(1500 * time.Millisecond)
	if err := sched.Tick(ctx); err != nil {
		return demoScenarioEscalation{}, err
	}
	escalationsAgain, err := demoCountOutboxType(ctx, pool, application.EventTypeSignalEscalated, sig.ID)
	if err != nil {
		return demoScenarioEscalation{}, err
	}
	if escalationsAgain != escalations {
		return demoScenarioEscalation{}, fmt.Errorf("demo scenario: escalation is not exactly-once (%d then %d)", escalations, escalationsAgain)
	}
	// A later cadence window emits one reminder.
	clk.Advance(2 * time.Second)
	if err := sched.Tick(ctx); err != nil {
		return demoScenarioEscalation{}, err
	}
	reminders, err := demoCountOutboxType(ctx, pool, application.EventTypeSignalReminder, sig.ID)
	if err != nil {
		return demoScenarioEscalation{}, err
	}
	return demoScenarioEscalation{SignalID: sig.ID, EscalatedAt: at, Escalations: escalations, Reminders: reminders}, nil
}

// --- scenario wiring + helpers ------------------------------------------

// demoScenarioMatches is the resolved match ids of the three scenario
// signals.
type demoScenarioMatches struct {
	lifecycle  string
	upgrade    string
	escalation string
}

// Stable CVE ids of the scenario signals.
const (
	demoScenarioCVELifecycle  = "CVE-2026-9101"
	demoScenarioCVEUpgrade    = "CVE-2026-9102"
	demoScenarioCVEEscalation = "CVE-2026-9103"
)

// newDemoScenarioService wires the application service against the real
// postgres repositories with the scaled profile, the scaled reminder cadence
// and the injected clock — the accelerated composition the scenario drives.
func newDemoScenarioService(pool *pgxpool.Pool, clk clock.Clock, profile domain.SLATimeProfile) *application.Service {
	q := gen.New(pool)
	return application.NewService(application.ServiceDeps{
		Signals:            repo.NewSignalRepo(q),
		Audit:              repo.NewAuditRepo(q),
		Outbox:             repo.NewOutboxRepo(q),
		Vulnerabilities:    repo.NewVulnerabilityRepo(q),
		Matches:            repo.NewMatchRepo(q),
		SourceRuns:         repo.NewSourceRunRepo(q),
		RawRecords:         repo.NewRawRecordRepo(q),
		Sources:            repo.NewSourceRepo(q),
		Quarantine:         repo.NewQuarantineRepo(q),
		Components:         repo.NewComponentRepo(q),
		Inventory:          repo.NewInventoryRepo(q),
		SignalTriage:       repo.NewSignalRepo(q),
		Comments:           repo.NewCommentRepo(q),
		SlaClocks:          repo.NewSlaClockRepo(q),
		PriorityRules:      repo.NewPriorityRuleRepo(q),
		FactorSource:       repo.NewPriorityFactorRepo(q),
		SlaTimeProfile:     &profile,
		SLAReminderCadence: demoScenarioReminderCadence,
		Clock:              clk,
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
	})
}

// newDemoNotifyRelay wires the notify handler (in-app only — no SMTP/webhook
// target, so the accelerated run is network-free) on the real outbox relay,
// exactly as the worker root does.
func newDemoNotifyRelay(pool *pgxpool.Pool, clk clock.Clock) (*worker.Relay, error) {
	q := gen.New(pool)
	jobs, err := worker.NewNotifyJobs(worker.NotifyJobsDeps{
		Notifications: repo.NewNotificationRepo(q),
		SlaClocks:     repo.NewSlaClockRepo(q),
		Port: notify.NewDispatcher(map[notify.NotifyChannel]notify.NotifyPort{
			notify.ChannelInApp: notify.NewInAppPort(),
		}),
		Policy: worker.NotifyPolicy{}, // in-app only
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
		Clock: clk,
	})
	if err != nil {
		return nil, err
	}
	relay, err := worker.NewRelay(repo.NewOutboxRelay(q), nil)
	if err != nil {
		return nil, err
	}
	if err := jobs.RegisterHandlers(relay); err != nil {
		return nil, err
	}
	return relay, nil
}

// seedDemoScenarioChain upserts the dedicated scenario inventory and the
// three (vulnerability, match) pairs the scenario creates its signals on, and
// returns their match ids. Natural-key upserts keep a re-run from
// duplicating the inventory; the matches are stable (UQ vulnerability_id,
// component_id, rule_version).
func seedDemoScenarioChain(ctx context.Context, pool *pgxpool.Pool, at time.Time) (demoScenarioMatches, error) {
	var out demoScenarioMatches
	err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		qtx := gen.New(pool).WithTx(tx)
		assetID, err := qtx.UpsertAsset(ctx, gen.UpsertAssetParams{
			ExternalID:  demoScenarioAssetExternalID,
			Source:      demoScenarioSource,
			Type:        string(domain.AssetTypeServerVM),
			Name:        demoScenarioAssetName,
			Environment: string(domain.EnvironmentProduction),
			Criticality: string(domain.CriticalityCritical),
			Exposure:    string(domain.ExposureInternet),
			Owner:       demoTextOpt("ops"),
		})
		if err != nil {
			return err
		}
		componentID, err := qtx.InsertComponent(ctx, gen.InsertComponentParams{
			AssetID:       assetID,
			Vendor:        "acme",
			Product:       "uc08-scenario",
			Version:       "1.0",
			VendorNorm:    "acme",
			ProductNorm:   "uc08-scenario",
			VersionScheme: string(domain.VersionSchemeUnknown),
			NaturalKey:    demoScenarioComponentNaturalKey(),
			UpdatedAt:     pgtype.Timestamptz{Time: at, Valid: true},
		})
		if err != nil {
			return err
		}
		cves := []struct {
			cve    string
			factor domain.PriorityFactors
			dst    *string
		}{
			{demoScenarioCVELifecycle, demoScenarioP1Factors(), &out.lifecycle},
			{demoScenarioCVEUpgrade, demoScenarioP3Factors(), &out.upgrade},
			{demoScenarioCVEEscalation, demoScenarioP1Factors(), &out.escalation},
		}
		for _, c := range cves {
			vulnID, err := qtx.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
				CveID:       c.cve,
				Summary:     "UC-08 accelerated scenario signal",
				PublishedAt: pgtype.Timestamptz{Time: at.AddDate(0, 0, -30), Valid: true},
				ModifiedAt:  pgtype.Timestamptz{Time: at.AddDate(0, 0, -1), Valid: true},
			})
			if err != nil {
				return err
			}
			matchID, err := qtx.InsertMatch(ctx, gen.InsertMatchParams{
				VulnerabilityID: vulnID,
				ComponentID:     componentID,
				Method:          string(c.factor.Method),
				Score:           demoFixtureRank(c.factor.Confidence),
				Confidence:      string(c.factor.Confidence),
				RuleVersion:     domain.MatchRuleVersion,
				CreatedAt:       pgtype.Timestamptz{Time: at, Valid: true},
				Reasons:         []byte("[]"),
			})
			if err != nil {
				return err
			}
			*c.dst = demoUUID(matchID)
		}
		return nil
	})
	if err != nil {
		return demoScenarioMatches{}, err
	}
	return out, nil
}

// resetDemoScenario removes the scenario's own signals (and their dependent
// clocks, notifications, comments and audit rows) so the UC-08 run is
// re-runnable. Dev-only demo tooling: only rows reachable from the scenario
// asset are touched.
func resetDemoScenario(ctx context.Context, pool *pgxpool.Pool) error {
	return postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		const signalIDs = `SELECT rs.id FROM risk_signals rs
			JOIN matches m ON m.id = rs.match_id
			JOIN components c ON c.id = m.component_id
			JOIN assets a ON a.id = c.asset_id
			WHERE a.external_id = $1 AND a.source = $2`
		for _, stmt := range []string{
			`DELETE FROM notifications WHERE signal_id IN (` + signalIDs + `)`,
			`DELETE FROM comments WHERE signal_id IN (` + signalIDs + `)`,
			`DELETE FROM sla_clocks WHERE signal_id IN (` + signalIDs + `)`,
			`DELETE FROM audit_events WHERE aggregate_id IN (` + signalIDs + `)`,
			`DELETE FROM risk_signals WHERE id IN (` + signalIDs + `)`,
		} {
			if _, err := tx.Exec(ctx, stmt, demoScenarioAssetExternalID, demoScenarioSource); err != nil {
				return err
			}
		}
		return nil
	})
}

// demoScenarioComponentNaturalKey is the scenario component's import
// idempotency key.
func demoScenarioComponentNaturalKey() string {
	key, err := domain.ComponentNaturalKey(domain.ComponentIdentifiers{
		Vendor: "acme", Product: "uc08-scenario", Version: "1.0",
	}, "acme", "uc08-scenario", "")
	if err != nil {
		panic("demo: scenario component natural key: " + err.Error())
	}
	return key
}

// demoScenarioP1Factors / demoScenarioP3Factors are the ch. 9.3 factor sets
// the scenario creates its signals from (P1: high + KEV + critical/internet;
// P3: high with no strong urgency).
func demoScenarioP1Factors() domain.PriorityFactors {
	return domain.PriorityFactors{
		Method: domain.MatchMethodExactIdentifier, Confidence: domain.ConfidenceHigh,
		KEV: true, CVSS: 9.8, EPSS: 0.99, Criticality: domain.CriticalityCritical, Exposure: domain.ExposureInternet,
	}
}

func demoScenarioP3Factors() domain.PriorityFactors {
	return domain.PriorityFactors{
		Method: domain.MatchMethodExactIdentifier, Confidence: domain.ConfidenceHigh,
		KEV: false, CVSS: 5.0, EPSS: 0.1, Criticality: domain.CriticalityLow, Exposure: domain.ExposureInternal,
	}
}

// demoReadClocks reads the full clock set of a signal plus its closed_at.
func demoReadClocks(ctx context.Context, pool *pgxpool.Pool, signalID string) (map[string]demoScenarioClockState, *time.Time, error) {
	rows, err := pool.Query(ctx,
		`SELECT target, started_at, deadline_at, fulfilled_at FROM sla_clocks WHERE signal_id = $1 ORDER BY target`,
		demoUUIDMust(signalID))
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	out := map[string]demoScenarioClockState{}
	for rows.Next() {
		var target string
		var started, deadline time.Time
		var fulfilled pgtype.Timestamptz
		if err := rows.Scan(&target, &started, &deadline, &fulfilled); err != nil {
			return nil, nil, err
		}
		state := demoScenarioClockState{StartedAt: started, DeadlineAt: deadline}
		if fulfilled.Valid {
			at := fulfilled.Time
			state.FulfilledAt = &at
		}
		out[target] = state
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	var closed pgtype.Timestamptz
	if err := pool.QueryRow(ctx, `SELECT closed_at FROM risk_signals WHERE id = $1`, demoUUIDMust(signalID)).Scan(&closed); err != nil {
		return nil, nil, err
	}
	var closedAt *time.Time
	if closed.Valid {
		at := closed.Time
		closedAt = &at
	}
	return out, closedAt, nil
}

// demoReadClockRow reads one clock's deadline (zero when the clock is
// missing).
func demoReadClockRow(ctx context.Context, pool *pgxpool.Pool, signalID string, target domain.SLATarget) (time.Time, error) {
	var deadline time.Time
	err := pool.QueryRow(ctx,
		`SELECT deadline_at FROM sla_clocks WHERE signal_id = $1 AND target = $2`,
		demoUUIDMust(signalID), string(target)).Scan(&deadline)
	if err != nil {
		if err == pgx.ErrNoRows {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	return deadline, nil
}

// demoClockExists reports whether a signal has a clock for the target.
func demoClockExists(ctx context.Context, pool *pgxpool.Pool, signalID string, target domain.SLATarget) (bool, error) {
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM sla_clocks WHERE signal_id = $1 AND target = $2`,
		demoUUIDMust(signalID), string(target)).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// demoNotificationDelivered reports whether the signal's in-app signal.created
// notification was delivered (the notification clock was fulfilled by the
// notify handler).
func demoNotificationDelivered(ctx context.Context, pool *pgxpool.Pool, signalID string) (bool, error) {
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM notifications
		 WHERE signal_id = $1 AND channel = 'in_app' AND kind = $2 AND status = 'delivered'`,
		demoUUIDMust(signalID), application.EventTypeSignalCreated).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// demoCountAudits returns the signal's SLA-clock-created and -tightened audit
// rows (the per-mutation evidence of the upgrade).
func demoCountAudits(ctx context.Context, pool *pgxpool.Pool, signalID string) (created, tightened int, err error) {
	row := pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE action = $2), count(*) FILTER (WHERE action = $3)
		 FROM audit_events WHERE aggregate_id = $1`,
		demoUUIDMust(signalID), application.EventTypeSignalSLAClockCreated, application.EventTypeSignalSLAClockTightened)
	if err := row.Scan(&created, &tightened); err != nil {
		return 0, 0, err
	}
	return created, tightened, nil
}

// demoEscalatedAt reads the signal's escalation instant (nil when never
// escalated).
func demoEscalatedAt(ctx context.Context, pool *pgxpool.Pool, signalID string) (*time.Time, error) {
	var escalated pgtype.Timestamptz
	if err := pool.QueryRow(ctx, `SELECT escalated_at FROM risk_signals WHERE id = $1`, demoUUIDMust(signalID)).Scan(&escalated); err != nil {
		return nil, err
	}
	if !escalated.Valid {
		return nil, nil
	}
	at := escalated.Time
	return &at, nil
}

// demoCountOutboxType counts a signal's outbox rows of one type (the
// escalation/reminder exactly-once evidence; the payload carries the signal
// id).
func demoCountOutboxType(ctx context.Context, pool *pgxpool.Pool, typ, signalID string) (int, error) {
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE type = $1 AND payload->>'signal_id' = $2`,
		typ, signalID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// demoUUIDMust parses a canonical uuid constant into the pgtype.UUID the
// generated queries use. The fixture ids are fixed constants, so a malformed
// one is a programming error and fails loudly (mirrors uuid.New's contract).
func demoUUIDMust(s string) pgtype.UUID {
	u := demoUUIDParse(s)
	if !u.Valid {
		panic("demo: invalid uuid constant: " + s)
	}
	return u
}

// demoUUIDParse parses a canonical uuid string; an invalid value yields the
// zero (invalid) pgtype.UUID.
func demoUUIDParse(s string) pgtype.UUID {
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		return pgtype.UUID{}
	}
	return u
}

// demoTimeOpt maps an instant onto a nullable timestamptz; the zero time is
// NULL.
func demoTimeOpt(t time.Time) pgtype.Timestamptz {
	if t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: t, Valid: true}
}
