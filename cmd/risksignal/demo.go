// demo subcommands (WP-1b.05 / DEV-019, ARCH-001 §3 "Trigger"): `demo seed`
// registers the synthetic source row, seeds the demo inventory (assets and
// components) and runs the synthetic source once; `demo run` re-runs the
// source (an idempotent no-op on re-run); `demo reset` truncates the demo
// tables (the I1b chain plus quarantine since I2; dev-only, requires --yes
// per concept ch. 11.3). Production of the
// signal is a CLI/operator action — the API only reads the result
// (ARCH-001 §3).
//
// Composition: cmd/risksignal is the composition root of the demo path. It
// wires the postgres repositories behind the application ports
// (application.NewService) and executes the seed writes that have no
// application port (sources, assets, components — the demo seed is operator
// tooling, not a domain command) on the sqlc query set directly, inside one
// transaction with the other seed writes.
//
// Determinism: the run path never reads the wall clock (the service receives
// clock.RealClock through the Clock port; timestamps, content hashes and
// dedupe keys are deterministic functions of the fixture and the rule
// version, ARCH-001 §3). Every write the seed and the run perform is
// idempotent: sources/assets upsert by natural key and component rows upsert
// on UQ (asset_id, natural_key) — the I3 import idempotency key the seed
// derives from each row's identity (naturalkey.go) — behind an in-
// transaction existence check that keeps pre-I3 rows with NULL keys
// duplicate-free too (00005's Expand phase), so `demo seed` twice yields no
// duplicates.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/repo"
	"github.com/brunoxpera/risksignal/internal/adapters/sources/synthetic"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
	"github.com/brunoxpera/risksignal/internal/platform/config"
)

// demoRunTimeout bounds one demo command (seeding, a synthetic run or the
// reset). The deterministic fixture finishes far below it; the bound keeps
// automation from hanging on a stalled database.
const demoRunTimeout = 5 * time.Minute

// demoSource is the fixed inventory source tag of the seeded demo assets
// (ARCH-001 §1 assets.source; the I1b demo seeds its own inventory rows).
const demoSource = "demo"

// demoResetTables are the demo tables `demo reset` truncates (ARCH-001 §1:
// the walking-skeleton chain sources … risk_signals plus audit_events and
// outbox, which the demo's signal creation writes; quarantine, which since
// I2 (00004) holds foreign keys into that set; comments / sla_clocks, which
// since I4 (00007) hold foreign keys into risk_signals; and notifications,
// which since I4 (00008) holds a foreign key into risk_signals — PostgreSQL
// refuses a TRUNCATE of a table referenced by an untruncated table, so the
// reset must include every referrer). The reset is dev-only and requires
// --yes; it never touches the migration bookkeeping (schema_migration_log)
// or the seeded priority_rules config (00007) — those are not demo data.
var demoResetTables = []string{
	"risk_signals",
	"comments",
	"sla_clocks",
	"notifications",
	"matches",
	"evidences",
	"quarantine",
	"vulnerabilities",
	"raw_records",
	"source_runs",
	"components",
	"assets",
	"sources",
	"audit_events",
	"outbox",
}

// demoTruncateSQL truncates every demo table in one statement. PostgreSQL
// resolves the foreign keys among the listed tables internally, so the
// order is irrelevant; no table outside the list references one of them,
// hence no CASCADE (a later table with a foreign key into this set would
// fail loudly instead of silently truncating).
const demoTruncateSQL = `TRUNCATE TABLE risk_signals, comments, sla_clocks, notifications, matches, evidences, quarantine, vulnerabilities, raw_records, source_runs, components, assets, sources, audit_events, outbox`

// runDemo dispatches `risksignal demo ...`.
func runDemo(e *cmdEnv, args []string) int {
	if len(args) < 1 {
		return e.emit("demo", e.fail(exitValidation, classValidation,
			"missing subcommand (supported: seed, run, reset)"))
	}
	command := "demo " + args[0]
	switch args[0] {
	case "seed":
		return e.emit(command, e.cmdDemoSeed(args[1:]))
	case "run":
		return e.emit(command, e.cmdDemoRun(args[1:]))
	case "reset":
		return e.emit(command, e.cmdDemoReset(args[1:]))
	default:
		return e.emit(command, e.fail(exitValidation, classValidation,
			"unknown subcommand (supported: seed, run, reset)"))
	}
}

// cmdDemoSeed seeds the synthetic source and the demo inventory, then runs
// the synthetic source once. Failure classes: invalid arguments or
// configuration are exit 2, an unreachable database is exit 6 and any other
// runtime failure is classified by its application error kind
// (demoErrorOutcome). The run itself completes even when the malformed E1
// case is counted — its status (failed) and errors are part of the result,
// not of the command verdict.
func (e *cmdEnv) cmdDemoSeed(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal demo seed")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return outcome{}
		}
		return e.fail(exitValidation, classValidation, "%v", err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	fix, err := synthetic.Load()
	if err != nil {
		return e.fail(exitGeneric, classGeneric, "%v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), demoRunTimeout)
	defer cancel()

	pool, svc, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()

	sourceID, counts, err := seedDemoInventory(ctx, pool, fix, clock.RealClock{}.Now())
	if err != nil {
		return demoErrorOutcome(err)
	}

	res, err := svc.RunSyntheticSource(ctx, syntheticRunInput(sourceID, fix))
	if err != nil {
		return demoErrorOutcome(err)
	}
	run := demoRunPayloadFromResult(res)

	if e.format == formatText {
		fmt.Fprintf(e.stdout, "registered source type %s, name %s\n", synthetic.SourceType, synthetic.SourceName)
		fmt.Fprintf(e.stdout, "seeded inventory: %d asset(s), %d component(s)\n", counts.assets, counts.components)
		printDemoRun(e.stdout, run)
	}
	return e.ok(demoSeedResult{
		SourceType: synthetic.SourceType,
		SourceName: synthetic.SourceName,
		Assets:     counts.assets,
		Components: counts.components,
		Run:        run,
	})
}

// cmdDemoRun re-runs the synthetic source against the seeded inventory
// (idempotent: re-runs create no duplicate rows and no new signals). A
// missing source row means the demo was never seeded.
func (e *cmdEnv) cmdDemoRun(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal demo run")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return outcome{}
		}
		return e.fail(exitValidation, classValidation, "%v", err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	fix, err := synthetic.Load()
	if err != nil {
		return e.fail(exitGeneric, classGeneric, "%v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), demoRunTimeout)
	defer cancel()

	pool, svc, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()

	source, err := gen.New(pool).GetSourceByTypeAndName(ctx, gen.GetSourceByTypeAndNameParams{
		Type: synthetic.SourceType,
		Name: synthetic.SourceName,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return e.fail(exitGeneric, classGeneric,
				"demo is not seeded yet — run 'risksignal demo seed' first")
		}
		return e.fail(exitInfrastructure, classInfrastructure, "%v", err)
	}

	res, err := svc.RunSyntheticSource(ctx, syntheticRunInput(demoUUID(source.ID), fix))
	if err != nil {
		return demoErrorOutcome(err)
	}
	run := demoRunPayloadFromResult(res)

	if e.format == formatText {
		printDemoRun(e.stdout, run)
	}
	return e.ok(demoRunResult{Run: run})
}

// cmdDemoReset truncates the demo tables (the I1b chain plus the I2
// quarantine, which references it). It is dev-only: without the
// explicit --yes confirmation the command fails as a validation error
// before any configuration or database access.
func (e *cmdEnv) cmdDemoReset(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal demo reset\n"+
		"  --yes  confirm the truncation of the demo tables (dev-only)")
	yes := fs.Bool("yes", false, "confirm the truncation of the demo tables (dev-only)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return outcome{}
		}
		return e.fail(exitValidation, classValidation, "%v", err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	if !*yes {
		return e.fail(exitValidation, classValidation,
			"demo reset truncates the demo tables (sources, source runs, raw records, vulnerabilities, evidences, matches, risk signals, assets, components, audit events, outbox, quarantine) — pass --yes to confirm")
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}

	ctx, cancel := context.WithTimeout(context.Background(), demoRunTimeout)
	defer cancel()

	pool, _, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()

	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, demoTruncateSQL)
		return err
	}); err != nil {
		return e.fail(exitInfrastructure, classInfrastructure, "%v", err)
	}

	if e.format == formatText {
		fmt.Fprintf(e.stdout, "truncated %d demo table(s): %v\n", len(demoResetTables), demoResetTables)
		fmt.Fprintln(e.stdout, "demo reset is a dev-only command; the next 'risksignal demo seed' rebuilds the demo state")
	}
	return e.ok(demoResetResult{Tables: demoResetTables})
}

// dbService opens the database pool and wires the application service
// behind the postgres repositories — the composition the database-backed
// CLI commands (demo, source) share, with the real clock through the Clock
// port and postgres.WithTx as the transaction boundary. An unreachable
// database is an infrastructure failure (exit 6).
func (e *cmdEnv) dbService(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, *application.Service, outcome) {
	pool, err := postgres.OpenPool(ctx, cfg.Database.URL)
	if err != nil {
		return nil, nil, e.fail(exitInfrastructure, classInfrastructure, "%v", err)
	}
	return pool, newAppService(pool, clock.RealClock{}), outcome{}
}

// newAppService wires the postgres repositories behind the application
// ports on one pool — the composition every database-backed CLI command
// (demo, source) shares, with the given clock through the Clock port and
// postgres.WithTx as the transaction boundary.
func newAppService(pool *pgxpool.Pool, clk clock.Clock) *application.Service {
	q := gen.New(pool)
	return application.NewService(application.ServiceDeps{
		Signals:         repo.NewSignalRepo(q),
		Audit:           repo.NewAuditRepo(q),
		Outbox:          repo.NewOutboxRepo(q),
		Vulnerabilities: repo.NewVulnerabilityRepo(q),
		Matches:         repo.NewMatchRepo(q),
		SourceRuns:      repo.NewSourceRunRepo(q),
		RawRecords:      repo.NewRawRecordRepo(q),
		Sources:         repo.NewSourceRepo(q),
		Quarantine:      repo.NewQuarantineRepo(q),
		Components:      repo.NewComponentRepo(q),
		Inventory:       repo.NewInventoryRepo(q),
		Clock:           clk,
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
	})
}

// seedDemoInventory registers the synthetic source and seeds the demo
// assets/components in one transaction and returns the source id plus the
// counts of seeded assets and components. Sources and assets upsert by
// natural key (UQ (type, name); UQ (source, external_id)); component rows
// are written through the I3 write path — InsertComponent upserts on the
// import idempotency key UQ (asset_id, natural_key), supplied together
// with the normalised comparison keys and the version scheme (ARCH-003
// §1.2/§1.3) — and stay guarded by an in-transaction existence check on
// (asset_id, version) that also keeps pre-I3 rows with NULL keys
// duplicate-free across sequential seeds (the Expand phase of 00005). The
// updated_at stamp of every seed write comes from the given clock instant.
func seedDemoInventory(ctx context.Context, pool *pgxpool.Pool, fix *synthetic.Fixture, now time.Time) (sourceID string, counts struct {
	assets, components int
}, err error) {
	seedErr := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		qtx := gen.New(pool).WithTx(tx)

		id, err := qtx.UpsertSource(ctx, gen.UpsertSourceParams{
			Type:    synthetic.SourceType,
			Name:    synthetic.SourceName,
			Enabled: true,
		})
		if err != nil {
			return err
		}
		sourceID = demoUUID(id)

		for _, asset := range fix.Inventory.Assets {
			assetID, err := qtx.UpsertAsset(ctx, gen.UpsertAssetParams{
				ExternalID:  asset.ExternalID,
				Source:      demoSource,
				Type:        string(asset.Type),
				Name:        asset.Name,
				Environment: string(asset.Environment),
				Criticality: string(asset.Criticality),
				Exposure:    string(asset.Exposure),
				Owner:       demoTextOpt(asset.Owner),
			})
			if err != nil {
				return err
			}
			for _, comp := range asset.Components {
				rows, err := qtx.ListComponentsByVendorProduct(ctx, gen.ListComponentsByVendorProductParams{
					Vendor:  comp.Vendor,
					Product: comp.Product,
				})
				if err != nil {
					return err
				}
				already := false
				for _, row := range rows {
					if row.AssetID == assetID && row.Version == comp.Version {
						already = true
						break
					}
				}
				if already {
					continue
				}
				// The I3 write path (WP-3.03a / DEV-056): the demo inventory
				// carries no CPE/purl/image/digest identity, so the write
				// supplies NULL originals plus the vendor/product/version
				// comparison keys, the 'unknown' scheme (no fabricated
				// ordering — version inference is WP-3.04's) and the domain-
				// derived natural key. version_norm stays NULL: 'unknown'
				// normalises nothing.
				vendorNorm, productNorm, key, err := seededComponentKey(comp.Vendor, comp.Product, comp.Version)
				if err != nil {
					return err
				}
				if _, err := qtx.InsertComponent(ctx, gen.InsertComponentParams{
					AssetID:       assetID,
					Vendor:        comp.Vendor,
					Product:       comp.Product,
					Version:       comp.Version,
					VendorNorm:    vendorNorm,
					ProductNorm:   productNorm,
					VersionScheme: string(domain.VersionSchemeUnknown),
					NaturalKey:    key,
					UpdatedAt:     pgtype.Timestamptz{Time: now, Valid: true},
				}); err != nil {
					return err
				}
				counts.components++
			}
			counts.assets++
		}
		return nil
	})
	if seedErr != nil {
		return "", counts, seedErr
	}
	return sourceID, counts, nil
}

// syntheticRunInput assembles the run input of one synthetic run from the
// fixture: the source row resolved by the seed, the fixture document
// identity and the reference cases, with the demo-seed audit actor.
func syntheticRunInput(sourceID string, fix *synthetic.Fixture) application.RunSyntheticSourceInput {
	return application.RunSyntheticSourceInput{
		SourceID:   sourceID,
		ExternalID: fix.ExternalID,
		Cases:      fix.RunCases(),
		ActorID:    synthetic.SourceActor,
	}
}

// demoRunPayload is the machine-readable payload of one synthetic run
// (demo seed and demo run): the run row identity, its terminal status and
// the committed counters. A failed status means the malformed E1 case was
// counted (its error text is in Errors); the run itself completed.
type demoRunPayload struct {
	RunID    string       `json:"run_id"`
	Status   string       `json:"status"`
	Counters demoCounters `json:"counters"`
	Errors   []string     `json:"errors"`
}

// demoCounters mirrors application.SourceRunCounters with fixed keys
// (records, matched, signals).
type demoCounters struct {
	Records int `json:"records"`
	Matched int `json:"matched"`
	Signals int `json:"signals"`
}

// demoRunPayloadFromResult maps the application result onto the payload.
func demoRunPayloadFromResult(res application.RunSyntheticSourceResult) demoRunPayload {
	errs := res.Errors
	if errs == nil {
		errs = []string{}
	}
	return demoRunPayload{
		RunID:  res.RunID,
		Status: string(res.Status),
		Counters: demoCounters{
			Records: res.Counters.Records,
			Matched: res.Counters.Matched,
			Signals: res.Counters.Signals,
		},
		Errors: errs,
	}
}

// demoSeedResult is the machine-readable payload of demo seed.
type demoSeedResult struct {
	SourceType string         `json:"source_type"`
	SourceName string         `json:"source_name"`
	Assets     int            `json:"assets"`
	Components int            `json:"components"`
	Run        demoRunPayload `json:"run"`
}

// demoRunResult is the machine-readable payload of demo run.
type demoRunResult struct {
	Run demoRunPayload `json:"run"`
}

// demoResetResult is the machine-readable payload of demo reset.
type demoResetResult struct {
	Tables []string `json:"tables"`
}

// printDemoRun renders the outcome of one synthetic run as text.
func printDemoRun(w io.Writer, run demoRunPayload) {
	fmt.Fprintf(w, "synthetic run %s status %s — counters {records %d, matched %d, signals %d}\n",
		run.RunID, run.Status, run.Counters.Records, run.Counters.Matched, run.Counters.Signals)
	if len(run.Errors) > 0 {
		for _, msg := range run.Errors {
			fmt.Fprintf(w, "  counted case error: %s\n", msg)
		}
	}
}

// demoErrorOutcome maps an application-layer error onto the CLI exit-code
// contract (WP-1a.09, ch. 5.2): validation → 2, conflict → 5,
// infrastructure → 6, not-found and bare errors → 1 (generic). The message
// is the full typed error, which carries the operation and the cause.
func demoErrorOutcome(err error) outcome {
	var appErr *application.Error
	if errors.As(err, &appErr) {
		switch appErr.Kind {
		case application.KindValidation:
			return outcome{code: exitValidation, class: classValidation, message: err.Error()}
		case application.KindConflict:
			return outcome{code: exitConflict, class: classConflict, message: err.Error()}
		case application.KindInfra:
			return outcome{code: exitInfrastructure, class: classInfrastructure, message: err.Error()}
		default: // KindNotFound and anything unknown: no dedicated exit code
			return outcome{code: exitGeneric, class: classGeneric, message: err.Error()}
		}
	}
	return outcome{code: exitGeneric, class: classGeneric, message: err.Error()}
}

// seededComponentKey derives the normalised comparison keys and the import
// idempotency natural key of one vendor/product/version-only inventory row
// (the I3 write path, WP-3.03a / DEV-056): the demo inventory and the seed
// fixtures carry no CPE/purl/image/digest identity, so the derivation
// falls back to the vendor/product/version key of the domain (naturalkey.go
// — ComponentNaturalKey is the same derivation NewComponent applies). The
// comparison keys are the ASCII trim + lowercase fold of the originals,
// mirroring how migration 00005 backfilled the pre-I3 rows; full NFKC
// normalisation is the WP-3.04 import function. version_norm is not part
// of the fold here: rows with the 'unknown' scheme are not normalisable.
func seededComponentKey(vendor, product, version string) (vendorNorm, productNorm, naturalKey string, err error) {
	vendorNorm = strings.ToLower(strings.TrimSpace(vendor))
	productNorm = strings.ToLower(strings.TrimSpace(product))
	key, err := domain.ComponentNaturalKey(domain.ComponentIdentifiers{
		Vendor:  vendor,
		Product: product,
		Version: version,
	}, vendorNorm, productNorm, "")
	if err != nil {
		return "", "", "", err
	}
	return vendorNorm, productNorm, key, nil
}

// demoTextOpt maps an optional string onto the nullable text column of the
// generated queries; "" means NULL (the convention of
// repo.dbmap.toTextOpt, which is unexported).
func demoTextOpt(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

// demoUUID formats a pgtype.UUID canonically (mirrors the mapper in
// repo.dbmap.uuidString, which is unexported).
func demoUUID(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	b := u.Bytes
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
