package main

// Integration test of the WP-4.07 (DEV-082) I4 exit-criterion proof (a)
// (ARCH-004 §8a): the P1–P4 reference matrix with audit evidence.
//
// It runs against a real, short-lived PostgreSQL through the production
// composition root (cmd/risksignal): the embedded migration set seeds the
// priority_rules ruleset version 1 (ARCH-004 §1.1/§7), and every reference
// cell — one signal per (method, confidence, KEV, CVSS, EPSS, criticality,
// exposure) combination covering P1..P4 — is created by the real CreateSignal
// command behind the postgres repositories and postgres.WithTx, exactly as
// production writes it. The injected FakeClock supplies every timestamp, so
// the rows are deterministic.
//
// Two halves:
//
//   (i) P1–P4 is deterministic: per signal the stored priority equals the
//       I1b reference (domain.ComputePriority) and — the exit-criterion half —
//       the priority_rules snapshot the migration seeded, read back through
//       the port, evaluates the stored factors to the exact same class for
//       every cell. Replacing the I1b switch with the versioned ruleset is
//       therefore behaviour-preserving.
//   (ii) it is auditable: every created signal carries exactly one immutable
//       audit_events row (ch. 13.2) — action signal.created, aggregate
//       risk_signal, the minimised `after` snapshot with the stored priority/
//       status/rule_version and a NULL `before` (a creation) — plus the exact
//       stored priority, rule_version and contributing factors.
//
// The database server is the compose `db` service (make up) or any PostgreSQL
// reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is reachable the
// test skips (newMigratedTestPool), so `go test ./...` stays green on machines
// without the environment.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/repo"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

// refExitClockTime is the single instant the reference-matrix clock reads, so
// every created_at / occurred_at is exact and reproducible.
var refExitClockTime = time.Date(2026, 9, 10, 7, 0, 0, 0, time.UTC)

// refExitCell is one row of the P1–P4 reference matrix: a factor set and the
// priority the ch. 9.3 rules must derive from it. together the cells cover
// every PriorityFactor dimension (method/confidence, KEV, CVSS, EPSS,
// criticality, exposure) and every priority class.
type refExitCell struct {
	name    string
	factors domain.PriorityFactors
	want    domain.Priority
}

// refExitCells is the seeded reference set: one cell per priority plus the
// boundary cells that separate the classes (the exactly-at-threshold CVSS 9.0
// and EPSS 0.95 P2 cells, the confidence-dominates P4 cells, and the
// criticality-vs-exposure disjuncts of P1/P2).
func refExitCells() []refExitCell {
	return []refExitCell{
		// P1: high confidence AND KEV AND (criticality critical/high OR exposure internet).
		{
			name: "p1-kev-critical",
			factors: domain.PriorityFactors{
				Method: domain.MatchMethodExactIdentifier, Confidence: domain.ConfidenceHigh,
				KEV: true, CVSS: 0, EPSS: 0, Criticality: domain.CriticalityCritical, Exposure: domain.ExposureInternal,
			},
			want: domain.PriorityP1,
		},
		{
			name: "p1-kev-high-internal",
			factors: domain.PriorityFactors{
				Method: domain.MatchMethodCanonicalProductRange, Confidence: domain.ConfidenceHigh,
				KEV: true, CVSS: 5.0, EPSS: 0.1, Criticality: domain.CriticalityHigh, Exposure: domain.ExposureInternal,
			},
			want: domain.PriorityP1,
		},
		{
			name: "p1-kev-internet-low",
			factors: domain.PriorityFactors{
				Method: domain.MatchMethodContainerDigest, Confidence: domain.ConfidenceHigh,
				KEV: true, CVSS: 5.0, EPSS: 0.1, Criticality: domain.CriticalityLow, Exposure: domain.ExposureInternet,
			},
			want: domain.PriorityP1,
		},
		// P2: high AND (kev OR cvss>=9.0 OR epss>=0.95), or medium AND kev AND (critical/high OR internet).
		{
			name: "p2-cvss-threshold",
			factors: domain.PriorityFactors{
				Method: domain.MatchMethodExactIdentifier, Confidence: domain.ConfidenceHigh,
				KEV: false, CVSS: 9.0, EPSS: 0, Criticality: domain.CriticalityLow, Exposure: domain.ExposureInternal,
			},
			want: domain.PriorityP2,
		},
		{
			name: "p2-epss-threshold",
			factors: domain.PriorityFactors{
				Method: domain.MatchMethodAliasExactVersion, Confidence: domain.ConfidenceHigh,
				KEV: false, CVSS: 5.0, EPSS: 0.95, Criticality: domain.CriticalityLow, Exposure: domain.ExposureInternal,
			},
			want: domain.PriorityP2,
		},
		{
			name: "p2-medium-kev-critical",
			factors: domain.PriorityFactors{
				Method: domain.MatchMethodProductUncertainVersion, Confidence: domain.ConfidenceMedium,
				KEV: true, CVSS: 5.0, EPSS: 0.1, Criticality: domain.CriticalityCritical, Exposure: domain.ExposureInternal,
			},
			want: domain.PriorityP2,
		},
		{
			name: "p2-medium-kev-internet",
			factors: domain.PriorityFactors{
				Method: domain.MatchMethodControlledAliasOnly, Confidence: domain.ConfidenceMedium,
				KEV: true, CVSS: 5.0, EPSS: 0.1, Criticality: domain.CriticalityLow, Exposure: domain.ExposureInternet,
			},
			want: domain.PriorityP2,
		},
		// P3: a plausible assignment reaching the rule (high/medium with no
		// strong urgency indicator left after P1/P2 were consumed).
		{
			name: "p3-high-quiet",
			factors: domain.PriorityFactors{
				Method: domain.MatchMethodExactIdentifier, Confidence: domain.ConfidenceHigh,
				KEV: false, CVSS: 5.0, EPSS: 0.1, Criticality: domain.CriticalityLow, Exposure: domain.ExposureInternal,
			},
			want: domain.PriorityP3,
		},
		{
			name: "p3-medium-quiet",
			factors: domain.PriorityFactors{
				Method: domain.MatchMethodProductUncertainVersion, Confidence: domain.ConfidenceMedium,
				KEV: false, CVSS: 7.0, EPSS: 0.5, Criticality: domain.CriticalityHigh, Exposure: domain.ExposureInternal,
			},
			want: domain.PriorityP3,
		},
		// P4: no confirmed inventory assignment — confidence dominates every
		// urgency indicator (low/none never claim impact).
		{
			name: "p4-candidate",
			factors: domain.PriorityFactors{
				Method: domain.MatchMethodCandidate, Confidence: domain.ConfidenceLow,
				KEV: true, CVSS: 10.0, EPSS: 1.0, Criticality: domain.CriticalityCritical, Exposure: domain.ExposureInternet,
			},
			want: domain.PriorityP4,
		},
		{
			name: "p4-no-match",
			factors: domain.PriorityFactors{
				Method: domain.MatchMethodNoMatch, Confidence: domain.ConfidenceNone,
				KEV: true, CVSS: 10.0, EPSS: 1.0, Criticality: domain.CriticalityCritical, Exposure: domain.ExposureInternet,
			},
			want: domain.PriorityP4,
		},
	}
}

// seedRefExitAssetComponent inserts the shared asset + component backing every
// reference cell (the FK chain risk_signals.match_id -> matches -> components
// -> assets) and returns their ids.
func seedRefExitAssetComponent(t *testing.T, ctx context.Context, q *gen.Queries, at time.Time) (pgtype.UUID, pgtype.UUID) {
	t.Helper()
	assetID, err := q.UpsertAsset(ctx, gen.UpsertAssetParams{
		ExternalID: "refexit-asset", Source: "demo", Type: "server_vm", Name: "Reference Exit",
		Environment: "production", Criticality: "critical", Exposure: "internet", Owner: pgtype.Text{},
	})
	if err != nil {
		t.Fatalf("UpsertAsset: %v", err)
	}
	vendorNorm, productNorm, naturalKey, err := seededComponentKey("acme", "refexit", "1.0")
	if err != nil {
		t.Fatalf("seededComponentKey: %v", err)
	}
	componentID, err := q.InsertComponent(ctx, gen.InsertComponentParams{
		AssetID: assetID, Vendor: "acme", Product: "refexit", Version: "1.0",
		VendorNorm: vendorNorm, ProductNorm: productNorm,
		VersionScheme: string(domain.VersionSchemeUnknown), NaturalKey: naturalKey,
		UpdatedAt: pgtype.Timestamptz{Time: at, Valid: true},
	})
	if err != nil {
		t.Fatalf("InsertComponent: %v", err)
	}
	return assetID, componentID
}

// seedRefExitMatch inserts one vulnerability + match for a reference cell and
// returns the match id (risk_signals is UQ on match_id, so every cell needs
// its own match).
func seedRefExitMatch(t *testing.T, ctx context.Context, q *gen.Queries, at time.Time, componentID pgtype.UUID, method domain.MatchMethod, confidence domain.Confidence, cveID string) string {
	t.Helper()
	vulnID, err := q.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
		CveID:       cveID,
		Summary:     "reference-exit cell",
		PublishedAt: pgtype.Timestamptz{Time: at.AddDate(0, 0, -30), Valid: true},
		ModifiedAt:  pgtype.Timestamptz{Time: at.AddDate(0, 0, -1), Valid: true},
	})
	if err != nil {
		t.Fatalf("UpsertVulnerability(%s): %v", cveID, err)
	}
	// The stored match mirrors the cell's method/confidence (the signal's
	// priority reads the input factors, but a realistic row keeps the match
	// consistent with ADR-015); the rank is only fixture noise.
	rank := 0
	if derived, ok := method.Confidence(); ok && derived == confidence {
		switch confidence {
		case domain.ConfidenceHigh:
			rank = 100
		case domain.ConfidenceMedium:
			rank = 60
		}
	}
	matchID, err := q.InsertMatch(ctx, gen.InsertMatchParams{
		VulnerabilityID: vulnID, ComponentID: componentID, Method: string(method),
		Score: int32(rank), Confidence: string(confidence), RuleVersion: domain.MatchRuleVersion,
		CreatedAt: pgtype.Timestamptz{Time: at, Valid: true}, Reasons: []byte("[]"),
	})
	if err != nil {
		t.Fatalf("InsertMatch(%s): %v", cveID, err)
	}
	return demoUUID(matchID)
}

// countSignalAudits returns the audit-row census of one signal aggregate.
func countSignalAudits(t *testing.T, ctx context.Context, pool *pgxpool.Pool, signalID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE aggregate_id = $1`, mustUUID(t, signalID)).Scan(&n); err != nil {
		t.Fatalf("count audits of %s: %v", signalID, err)
	}
	return n
}

// TestI4ExitCriteriaReferenceMatrix is the ARCH-004 §8a exit-criterion proof
// (a): the P1–P4 reference matrix reproduces the I1b ComputePriority outputs
// for every cell through the DB-seeded priority_rules snapshot, and every
// created signal keeps the exact priority/rule_version/factors plus its
// audit row.
func TestI4ExitCriteriaReferenceMatrix(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	at := refExitClockTime
	clk := clock.NewFakeClock(at)
	q := gen.New(pool)
	svc := newTriageService(pool, clk)

	// The migration seeded ruleset version 1; the textual version follows the
	// zero-padded ordering contract (ARCH-004 §1).
	rulesRepo := repo.NewPriorityRuleRepo(q)
	if v, err := rulesRepo.EffectiveVersion(ctx); err != nil || v != domain.SeedPriorityRulesVersion {
		t.Fatalf("effective ruleset version = %d (err %v), want %d (the migration seed)", v, err, domain.SeedPriorityRulesVersion)
	}
	wantVersionStr, err := domain.PriorityRuleVersion(domain.SeedPriorityRulesVersion)
	if err != nil {
		t.Fatalf("PriorityRuleVersion(%d): %v", domain.SeedPriorityRulesVersion, err)
	}
	if wantVersionStr != "p0000000001" {
		t.Fatalf("seed ruleset version string = %q, want p0000000001", wantVersionStr)
	}
	effective, err := rulesRepo.Effective(ctx)
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	if len(effective) != 4 {
		t.Fatalf("effective snapshot rows = %d, want 4 (P1..P4)", len(effective))
	}

	_, componentID := seedRefExitAssetComponent(t, ctx, q, at)

	cells := refExitCells()
	covered := map[domain.Priority]int{}
	for i, cell := range cells {
		cell := cell
		i := i
		t.Run(cell.name, func(t *testing.T) {
			cveID := "CVE-2026-8" + refExitCellSuffix(i)
			matchID := seedRefExitMatch(t, ctx, q, at, componentID, cell.factors.Method, cell.factors.Confidence, cveID)

			res, err := svc.CreateSignal(ctx, application.CreateSignalInput{
				MatchID: matchID,
				CveID:   cveID,
				Factors: cell.factors,
				Actor:   p1TestActor,
			})
			if err != nil {
				t.Fatalf("CreateSignal(%s): %v", cell.name, err)
			}
			sig := res.Signal

			// The stored priority equals the ch. 9.3 reference (the I1b
			// compatibility entry point) and the cell's expected class.
			if want := domain.ComputePriority(cell.factors); want != cell.want {
				t.Fatalf("ComputePriority reference = %s, want cell %s (the matrix and the reference disagree)", want, cell.want)
			}
			if sig.Priority != cell.want {
				t.Fatalf("created priority = %s, want %s", sig.Priority, cell.want)
			}
			if sig.RuleVersion != domain.PriorityRuleVersionI1b {
				t.Fatalf("created rule_version = %q, want the I1b tag %q (the create path stamps history; recompute re-stamps)", sig.RuleVersion, domain.PriorityRuleVersionI1b)
			}

			// The DB-seeded snapshot (version 1) evaluates the stored factors
			// to the exact same class — replacing the I1b switch with the
			// versioned ruleset is behaviour-preserving for this cell.
			got, err := domain.EvaluatePriority(effective, cell.factors)
			if err != nil {
				t.Fatalf("EvaluatePriority(stored snapshot, %s): %v", cell.name, err)
			}
			if got != cell.want {
				t.Fatalf("seeded snapshot evaluated %s to %s, want %s", cell.name, got, cell.want)
			}

			// Read the row back: priority, rule_version and the contributing
			// factors round-trip exactly.
			var priority, ruleVersion string
			var factorsJSON []byte
			var status string
			var version int
			if err := pool.QueryRow(ctx,
				`SELECT priority, rule_version, factors, status, version FROM risk_signals WHERE id = $1`,
				sig.ID).Scan(&priority, &ruleVersion, &factorsJSON, &status, &version); err != nil {
				t.Fatalf("read signal %s: %v", sig.ID, err)
			}
			if priority != string(cell.want) || ruleVersion != domain.PriorityRuleVersionI1b || status != string(domain.SignalStatusNew) || version != 1 {
				t.Fatalf("stored signal = %s/%s/%s/v%d, want %s/%s/new/1", priority, ruleVersion, status, version, cell.want, domain.PriorityRuleVersionI1b)
			}
			var storedFactors domain.PriorityFactors
			if err := json.Unmarshal(factorsJSON, &storedFactors); err != nil {
				t.Fatalf("decode stored factors: %v", err)
			}
			if storedFactors != cell.factors {
				t.Fatalf("stored factors = %+v, want the input %+v", storedFactors, cell.factors)
			}

			// Audit evidence: exactly one immutable row for the creation, the
			// minimised after-snapshot carrying the stored class, a NULL
			// before.
			if n := countSignalAudits(t, ctx, pool, sig.ID); n != 1 {
				t.Fatalf("audit rows for %s = %d, want exactly 1", sig.ID, n)
			}
			var action, aggType, actorType, actorID, corrID string
			var beforeIsNull bool
			var afterJSON []byte
			var occurredAt time.Time
			if err := pool.QueryRow(ctx,
				`SELECT action, aggregate_type, actor_type, actor_id, occurred_at, before IS NULL, after, correlation_id
				 FROM audit_events WHERE aggregate_id = $1`, mustUUID(t, sig.ID)).
				Scan(&action, &aggType, &actorType, &actorID, &occurredAt, &beforeIsNull, &afterJSON, &corrID); err != nil {
				t.Fatalf("read audit of %s: %v", sig.ID, err)
			}
			if action != application.EventTypeSignalCreated || aggType != application.AuditAggregateRiskSignal {
				t.Fatalf("audit = %s/%s, want %s/%s", action, aggType, application.EventTypeSignalCreated, application.AuditAggregateRiskSignal)
			}
			if actorType != application.ActorTypeSystem || actorID != p1TestActor.ID {
				t.Fatalf("audit actor = %s/%s, want system/%s", actorType, actorID, p1TestActor.ID)
			}
			if corrID != res.CorrelationID {
				t.Fatalf("audit correlation_id = %q, want the command's %q", corrID, res.CorrelationID)
			}
			if !beforeIsNull {
				t.Fatal("audit before is not NULL, want NULL for a creation")
			}
			assertUTCTimestamp(t, "audit occurred_at", occurredAt, at)
			var afterMap map[string]any
			if err := json.Unmarshal(afterJSON, &afterMap); err != nil {
				t.Fatalf("decode audit after: %v", err)
			}
			if afterMap["id"] != sig.ID || afterMap["priority"] != string(cell.want) ||
				afterMap["status"] != string(domain.SignalStatusNew) || afterMap["rule_version"] != domain.PriorityRuleVersionI1b {
				t.Fatalf("audit after = %v, want the %s signal snapshot", afterMap, cell.want)
			}

			covered[cell.want]++
		})
	}

	// The matrix must exercise every priority class (P1..P4 demonstrable).
	for _, p := range []domain.Priority{domain.PriorityP1, domain.PriorityP2, domain.PriorityP3, domain.PriorityP4} {
		if covered[p] == 0 {
			t.Fatalf("reference matrix has no cell resolving to %s", p)
		}
	}
}

// refExitCellSuffix returns a stable 3-digit decimal suffix for a cell index,
// so every cell's CVE id is unique and readable.
func refExitCellSuffix(i int) string {
	const digits = "0123456789"
	if i < 0 {
		i = 0
	}
	return string([]byte{digits[(i/100)%10], digits[(i/10)%10], digits[i%10]})
}
