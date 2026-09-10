package application_test

// Unit tests of the WP-3.05 inventory commit use case (DEV-060, ARCH-003
// §1.3 step 3): the one-transaction commit — classification of every
// clean asset group against the current state, the additive upserts of
// the changed rows (UQ (source, external_id); UQ (asset_id,
// natural_key)), the inventory.import audit event and the single
// matching.rebuild outbox job with the ARCH-003 §5 dedupe key
// (rule_version + inventory_snapshot) — plus the idempotency (re-commit
// no-op), the atomicity (a failing outbox append rolls the audit and the
// rows back) and the natural-key agreement with the preview
// classification.
//
// The fakes mirror the production wiring one level down (fakes_test.go):
// the fakeInventoryWriter stages the commit's inventory writes on the
// fake transaction (copy-on-write overlay of the committed assets) and
// the commit publishes them — a test observes exactly what a caller of
// the real stack observes: rows exist only after the transaction
// committed, and a rollback leaves no trace. The natural keys every
// assertion compares are derived through the exact domain call of the
// parser (domain.ComponentNaturalKey over the normalised comparison
// keys) — the derivation validate/preview/commit share.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/application/normalise"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// commitHeader is the canonical ARCH-003 §1.3 inventory CSV header (same
// column set the parser locks).
const commitHeader = "source,external_id,type,name,environment,criticality,exposure,owner,vendor,product,version,cpe,purl,image,digest"

// commitCSV joins the canonical header with the given data rows.
func commitCSV(rows ...string) string {
	return strings.Join(append([]string{commitHeader}, rows...), "\n") + "\n"
}

// commitRow renders one data row from its 15 canonical-order fields.
func commitRow(f ...string) string {
	if len(f) != 15 {
		panic(fmt.Sprintf("commitRow: got %d fields, want 15", len(f)))
	}
	return strings.Join(f, ",")
}

// commitAssetRow renders one vendor/product/version-only row of one asset.
func commitAssetRow(source, external, name, vendor, product, version string) string {
	return commitRow(source, external, "server_vm", name, "production", "high", "internet", "", vendor, product, version, "", "", "", "")
}

// commitKey derives the natural key of a persisted component the same way
// the import parser derives it (naturalkey.go priority, normalised
// comparison keys) — assertions compare against the exact domain call of
// the write path.
func commitKey(ids domain.ComponentIdentifiers) string {
	key, err := domain.ComponentNaturalKey(ids, normalise.NormaliseKey(ids.Vendor), normalise.NormaliseKey(ids.Product), "")
	if err != nil {
		panic("commitKey: " + err.Error())
	}
	return key
}

// ---------------------------------------------------------------------------
// fake inventory writer (the InventoryWriter port implementation of the
// commit tests)

// fakeStoredAsset is one committed inventory asset of the fake database:
// the asset fields as plain strings (the persisted vocabulary values the
// commit classification compares) plus its components and the lifecycle
// stamps the ARCH-003 §5 snapshot aggregates.
type fakeStoredAsset struct {
	id            string
	source        string
	externalID    string
	typ           string
	name          string
	environment   string
	criticality   string
	exposure      string
	owner         string
	updatedAt     time.Time
	deactivatedAt time.Time
	components    []fakeStoredComponent
}

// fakeStoredComponent is one committed component row of the fake: the raw
// identifiers verbatim, the parser-derived comparison keys and natural
// key, the inferred scheme and the clock stamp.
type fakeStoredComponent struct {
	ids         domain.ComponentIdentifiers
	vendorNorm  string
	productNorm string
	versionNorm string
	scheme      domain.VersionScheme
	naturalKey  string
	updatedAt   time.Time
}

// fakeInventoryWriter is the fake InventoryWriter (commit write path):
// every method stages on the fake transaction's copy-on-write overlay of
// the committed assets — reads and writes see the transaction's own
// uncommitted state, and commit publishes the overlay wholesale.
type fakeInventoryWriter struct {
	db *fakeDB
}

var _ application.InventoryWriter = (*fakeInventoryWriter)(nil)

// overlay returns the transaction's asset overlay, cloning the committed
// assets on first touch (copy-on-write).
func (f *fakeInventoryWriter) overlay(ftx *fakeTx) []fakeStoredAsset {
	if ftx.staged.assets == nil {
		ftx.staged.assets = cloneFakeAssets(f.db.assets)
	}
	return ftx.staged.assets
}

// cloneFakeAssets deep-copies the committed assets (the component slices
// must not alias the committed state: a staged upsert must never mutate
// a committed row before commit).
func cloneFakeAssets(in []fakeStoredAsset) []fakeStoredAsset {
	out := make([]fakeStoredAsset, len(in))
	for i, a := range in {
		out[i] = a
		out[i].components = append([]fakeStoredComponent(nil), a.components...)
	}
	return out
}

func (f *fakeInventoryWriter) CurrentAssetOnTx(_ context.Context, tx application.Tx, source, externalID string) (application.CurrentInventoryAsset, bool, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return application.CurrentInventoryAsset{}, false, err
	}
	for _, a := range f.overlay(ftx) {
		if a.source == source && a.externalID == externalID {
			return storedAssetView(a), true, nil
		}
	}
	return application.CurrentInventoryAsset{}, false, nil
}

func (f *fakeInventoryWriter) UpsertAsset(_ context.Context, tx application.Tx, asset application.InventoryAsset, now time.Time) (string, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return "", err
	}
	ftx.record("inventory.upsert_asset")
	assets := f.overlay(ftx)
	for i := range assets {
		if assets[i].source == asset.Source && assets[i].externalID == asset.ExternalID {
			assets[i].typ = string(asset.Type)
			assets[i].name = asset.Name
			assets[i].environment = string(asset.Environment)
			assets[i].criticality = string(asset.Criticality)
			assets[i].exposure = string(asset.Exposure)
			assets[i].owner = asset.Owner
			assets[i].updatedAt = now
			ftx.staged.assets = assets
			return assets[i].id, nil
		}
	}
	// New asset: the fake id generator assigns a fresh canonical id
	// (monotonic over the test, rolled-back transactions included).
	f.db.nextAssetID++
	id := fmt.Sprintf("asset-%d", f.db.nextAssetID)
	assets = append(assets, fakeStoredAsset{
		id:          id,
		source:      asset.Source,
		externalID:  asset.ExternalID,
		typ:         string(asset.Type),
		name:        asset.Name,
		environment: string(asset.Environment),
		criticality: string(asset.Criticality),
		exposure:    string(asset.Exposure),
		owner:       asset.Owner,
		updatedAt:   now,
	})
	ftx.staged.assets = assets
	return id, nil
}

func (f *fakeInventoryWriter) UpsertComponent(_ context.Context, tx application.Tx, assetID string, comp application.InventoryComponent, now time.Time) error {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return err
	}
	ftx.record("inventory.upsert_component")
	assets := f.overlay(ftx)
	for i := range assets {
		if assets[i].id != assetID {
			continue
		}
		stored := fakeStoredComponent{
			ids:         comp.IDs,
			vendorNorm:  comp.VendorNorm,
			productNorm: comp.ProductNorm,
			versionNorm: comp.VersionNorm,
			scheme:      comp.Scheme,
			naturalKey:  comp.NaturalKey,
			updatedAt:   now,
		}
		for j := range assets[i].components {
			if assets[i].components[j].naturalKey == comp.NaturalKey {
				assets[i].components[j] = stored
				ftx.staged.assets = assets
				return nil
			}
		}
		assets[i].components = append(assets[i].components, stored)
		ftx.staged.assets = assets
		return nil
	}
	return application.InfraError("inventory.upsert_component",
		fmt.Errorf("asset %s not found", assetID))
}

func (f *fakeInventoryWriter) InventorySnapshot(_ context.Context, tx application.Tx) (application.InventorySnapshot, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return application.InventorySnapshot{}, err
	}
	assets := f.overlay(ftx)
	snap := application.InventorySnapshot{}
	for _, a := range assets {
		snap.AssetsCount++
		if a.updatedAt.After(snap.AssetsMaxUpdatedAt) {
			snap.AssetsMaxUpdatedAt = a.updatedAt
		}
		if a.deactivatedAt.After(snap.MaxDeactivatedAt) {
			snap.MaxDeactivatedAt = a.deactivatedAt
		}
		for _, c := range a.components {
			snap.ComponentsCount++
			if c.updatedAt.After(snap.ComponentsMaxUpdatedAt) {
				snap.ComponentsMaxUpdatedAt = c.updatedAt
			}
		}
	}
	return snap, nil
}

func (f *fakeInventoryWriter) RuleVersions(_ context.Context, tx application.Tx) (int, int, error) {
	if _, err := fakeTxOf(tx); err != nil {
		return 0, 0, err
	}
	return f.db.aliasVersion, f.db.decisionVersion, nil
}

// storedAssetView renders one stored asset onto the current-state shape
// of the preview/commit classification (the same projection the postgres
// adapter performs).
func storedAssetView(a fakeStoredAsset) application.CurrentInventoryAsset {
	view := application.CurrentInventoryAsset{
		ID:          a.id,
		Source:      a.source,
		ExternalID:  a.externalID,
		Type:        a.typ,
		Name:        a.name,
		Environment: a.environment,
		Criticality: a.criticality,
		Exposure:    a.exposure,
		Owner:       a.owner,
	}
	for _, c := range a.components {
		view.Components = append(view.Components, application.CurrentInventoryComponent{
			IDs:        c.ids,
			NaturalKey: c.naturalKey,
		})
	}
	return view
}

// fakeInventoryReader is the read-only InventoryRepo port over the
// committed fake state (pool-scoped read of the preview) — the commit
// tests use it to prove that a preview after a commit classifies the
// same file as fully unchanged: commit and preview agree on the natural
// keys.
type fakeInventoryReader struct{ db *fakeDB }

var _ application.InventoryRepo = (*fakeInventoryReader)(nil)

func (f *fakeInventoryReader) CurrentAsset(_ context.Context, source, externalID string) (application.CurrentInventoryAsset, bool, error) {
	for _, a := range f.db.assets {
		if a.source == source && a.externalID == externalID {
			return storedAssetView(a), true, nil
		}
	}
	return application.CurrentInventoryAsset{}, false, nil
}

// storedAssetOf returns the committed asset of one (source, external_id).
func storedAssetOf(t *testing.T, h *harness, source, externalID string) fakeStoredAsset {
	t.Helper()
	for _, a := range h.db.assets {
		if a.source == source && a.externalID == externalID {
			return a
		}
	}
	t.Fatalf("no committed asset (%s, %s) in the fake database", source, externalID)
	return fakeStoredAsset{}
}

// ---------------------------------------------------------------------------
// tests

func TestCommitInventoryCreatesWritesAuditAndEnqueuesOneRebuild(t *testing.T) {
	h := newHarness(t)
	csv := commitCSV(commitAssetRow("cmdb", "a1", "portal-host", "Acme", "Portal", "1.0.0"))

	res, err := h.svc.CommitInventory(context.Background(), application.CommitInventoryInput{File: []byte(csv)})
	if err != nil {
		t.Fatalf("CommitInventory: %v", err)
	}
	if !res.Changed {
		t.Fatal("commit of a fresh file must report changed")
	}
	if res.Rows != 1 || res.ErrorCount != 0 || len(res.Errors) != 0 {
		t.Fatalf("rows=%d errors=%d", res.Rows, res.ErrorCount)
	}
	if res.AssetsCreated != 1 || res.AssetsUpdated != 0 || res.AssetsUnchanged != 0 {
		t.Fatalf("assets created=%d updated=%d unchanged=%d", res.AssetsCreated, res.AssetsUpdated, res.AssetsUnchanged)
	}
	if res.ComponentsCreated != 1 || res.ComponentsUpdated != 0 || res.ComponentsUnchanged != 0 {
		t.Fatalf("components created=%d updated=%d unchanged=%d", res.ComponentsCreated, res.ComponentsUpdated, res.ComponentsUnchanged)
	}
	if res.ImportID == "" || res.CorrelationID == "" {
		t.Fatalf("import/correlation id: %q / %q", res.ImportID, res.CorrelationID)
	}
	if res.RuleVersion != "a0000000000d0000000000" {
		t.Fatalf("rule_version = %q, want a0000000000d0000000000 (no rules configured)", res.RuleVersion)
	}
	if len(res.InventorySnapshot) != 64 {
		t.Fatalf("inventory_snapshot = %q, want a 64-hex sha-256", res.InventorySnapshot)
	}

	// The committed state: one asset with one component carrying the
	// parser-derived natural key (the exact derivation of the write path).
	if len(h.db.assets) != 1 {
		t.Fatalf("committed assets = %d, want 1", len(h.db.assets))
	}
	stored := h.db.assets[0]
	if stored.source != "cmdb" || stored.externalID != "a1" || stored.name != "portal-host" {
		t.Fatalf("stored asset = %+v", stored)
	}
	if len(stored.components) != 1 {
		t.Fatalf("stored components = %d, want 1", len(stored.components))
	}
	ids := domain.ComponentIdentifiers{Vendor: "Acme", Product: "Portal", Version: "1.0.0"}
	comp := stored.components[0]
	if comp.ids != ids {
		t.Fatalf("stored component ids = %+v, want the verbatim raw identifiers %+v", comp.ids, ids)
	}
	if comp.naturalKey != commitKey(ids) {
		t.Fatalf("stored natural_key = %q, want the parser derivation %q", comp.naturalKey, commitKey(ids))
	}
	if comp.scheme != normalise.InferVersionScheme(ids, domain.VersionSchemeUnknown) {
		t.Fatalf("stored scheme = %q, want the parser inference %q", comp.scheme, normalise.InferVersionScheme(ids, domain.VersionSchemeUnknown))
	}
	if !stored.updatedAt.Equal(fixedNow) || !comp.updatedAt.Equal(fixedNow) {
		t.Fatalf("stored updated_at = %v/%v, want the injected clock %v", stored.updatedAt, comp.updatedAt, fixedNow)
	}

	// The audit event: one inventory.import row, aggregate id = import id,
	// correlation id shared with the outbox row.
	if len(h.db.auditEvents) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(h.db.auditEvents))
	}
	audit := h.db.auditEvents[0]
	if audit.AggregateType != application.AuditAggregateInventory || audit.Action != application.AuditActionInventoryImport {
		t.Fatalf("audit = %+v, want inventory/inventory.import", audit)
	}
	if audit.AggregateID != res.ImportID || audit.CorrelationID != res.CorrelationID {
		t.Fatalf("audit aggregate/correlation = %s/%s, want %s/%s", audit.AggregateID, audit.CorrelationID, res.ImportID, res.CorrelationID)
	}
	if audit.ActorType != application.ActorTypeSystem || audit.ActorID != "operator" {
		t.Fatalf("audit actor = %s/%s, want system/operator", audit.ActorType, audit.ActorID)
	}
	if audit.Before != nil {
		t.Fatalf("audit before = %s, want nil (import has no prior aggregate state)", audit.Before)
	}

	// The outbox: exactly one matching.rebuild row with the §5 dedupe key
	// "matching.rebuild:<rule_version>:<inventory_snapshot>".
	if len(h.db.outboxEvents) != 1 {
		t.Fatalf("outbox rows = %d, want exactly 1 matching.rebuild", len(h.db.outboxEvents))
	}
	job := h.db.outboxEvents[0]
	if job.Type != application.EventTypeMatchingRebuild {
		t.Fatalf("outbox type = %q, want matching.rebuild", job.Type)
	}
	wantKey := "matching.rebuild:a0000000000d0000000000:" + res.InventorySnapshot
	if job.DedupeKey != wantKey {
		t.Fatalf("outbox dedupe_key = %q, want %q (rule_version + inventory_snapshot)", job.DedupeKey, wantKey)
	}
	if !job.CreatedAt.Equal(fixedNow) {
		t.Fatalf("outbox created_at = %v, want the injected clock %v", job.CreatedAt, fixedNow)
	}
}

func TestCommitInventoryRecommitIsANoop(t *testing.T) {
	h := newHarness(t)
	csv := commitCSV(commitAssetRow("cmdb", "a1", "portal-host", "Acme", "Portal", "1.0.0"))
	ctx := context.Background()

	first, err := h.svc.CommitInventory(ctx, application.CommitInventoryInput{File: []byte(csv)})
	if err != nil {
		t.Fatalf("first commit: %v", err)
	}
	storedBefore := storedAssetOf(t, h, "cmdb", "a1")

	second, err := h.svc.CommitInventory(ctx, application.CommitInventoryInput{File: []byte(csv)})
	if err != nil {
		t.Fatalf("re-commit: %v", err)
	}
	if second.Changed {
		t.Fatal("re-commit of identical content must be a no-op (Changed false)")
	}
	if second.AssetsCreated != 0 || second.AssetsUpdated != 0 || second.AssetsUnchanged != 1 {
		t.Fatalf("re-commit tallies: created=%d updated=%d unchanged=%d", second.AssetsCreated, second.AssetsUpdated, second.AssetsUnchanged)
	}
	if second.ComponentsCreated != 0 || second.ComponentsUpdated != 0 || second.ComponentsUnchanged != 1 {
		t.Fatalf("re-commit component tallies: created=%d updated=%d unchanged=%d", second.ComponentsCreated, second.ComponentsUpdated, second.ComponentsUnchanged)
	}
	if second.RuleVersion != "" || second.InventorySnapshot != "" {
		t.Fatalf("no-op re-commit must not describe a rebuild (rule_version=%q snapshot=%q)", second.RuleVersion, second.InventorySnapshot)
	}

	// No row was rewritten: the transaction of the re-commit staged no
	// upsert and the stored updated_at stayed at the first commit's stamp.
	for _, op := range h.runner.txs[1].log {
		if strings.HasPrefix(op, "inventory.upsert") {
			t.Fatalf("re-commit staged an unexpected write %q", op)
		}
	}
	storedAfter := storedAssetOf(t, h, "cmdb", "a1")
	if !storedAfter.updatedAt.Equal(storedBefore.updatedAt) {
		t.Fatalf("re-commit moved updated_at from %v to %v", storedBefore.updatedAt, storedAfter.updatedAt)
	}

	// No second matching.rebuild job: exactly one row stays in the outbox.
	if len(h.db.outboxEvents) != 1 {
		t.Fatalf("outbox rows after re-commit = %d, want 1 (no rebuild for a no-op)", len(h.db.outboxEvents))
	}
	// The commit attempt is still audited (ch. 13.2: an import action is
	// recorded with the accurate counts — here: changed nothing).
	if len(h.db.auditEvents) != 2 {
		t.Fatalf("audit rows after re-commit = %d, want 2 (one per commit attempt)", len(h.db.auditEvents))
	}
	if got := first.ImportID; got == second.ImportID {
		t.Fatalf("re-commit reuses the import id %s, want a fresh one per commit", got)
	}
}

func TestCommitInventoryUpdateWritesAndEnqueuesFreshRebuild(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	firstCSV := commitCSV(commitAssetRow("cmdb", "a1", "portal-host", "Acme", "Portal", "1.0.0"))
	if _, err := h.svc.CommitInventory(ctx, application.CommitInventoryInput{File: []byte(firstCSV)}); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	firstJob := h.db.outboxEvents[0]

	// An asset-field change (rename) plus a case-only component change
	// (same natural key, divergent raw original — the update case of the
	// preview). The clock advances so the fresh commit stamps a newer
	// updated_at and derives a fresh snapshot (the rebuild dedupe key
	// must differ from the first enqueue).
	h.clock.Advance(time.Hour)
	secondCSV := commitCSV(commitRow("cmdb", "a1", "server_vm", "portal-host-renamed", "production", "high", "internet", "", "acme", "Portal", "1.0.0", "", "", "", ""))

	res, err := h.svc.CommitInventory(ctx, application.CommitInventoryInput{File: []byte(secondCSV)})
	if err != nil {
		t.Fatalf("second commit: %v", err)
	}
	if !res.Changed {
		t.Fatal("changed commit must report changed")
	}
	if res.AssetsCreated != 0 || res.AssetsUpdated != 1 || res.AssetsUnchanged != 0 {
		t.Fatalf("assets created=%d updated=%d unchanged=%d", res.AssetsCreated, res.AssetsUpdated, res.AssetsUnchanged)
	}
	if res.ComponentsCreated != 0 || res.ComponentsUpdated != 1 || res.ComponentsUnchanged != 0 {
		t.Fatalf("components created=%d updated=%d unchanged=%d", res.ComponentsCreated, res.ComponentsUpdated, res.ComponentsUnchanged)
	}

	stored := storedAssetOf(t, h, "cmdb", "a1")
	if stored.name != "portal-host-renamed" {
		t.Fatalf("stored name = %q, want the committed rename", stored.name)
	}
	if !stored.updatedAt.Equal(fixedNow.Add(time.Hour)) {
		t.Fatalf("stored updated_at = %v, want the advanced clock stamp", stored.updatedAt)
	}
	if stored.components[0].ids.Vendor != "acme" {
		t.Fatalf("stored component vendor = %q, want the committed raw original", stored.components[0].ids.Vendor)
	}
	if stored.components[0].naturalKey != commitKey(domain.ComponentIdentifiers{Vendor: "Acme", Product: "Portal", Version: "1.0.0"}) {
		t.Fatal("case-only change must keep the natural key (folded comparison keys)")
	}

	// The changed commit enqueues exactly one fresh rebuild with a
	// different dedupe key (the inventory snapshot moved).
	if len(h.db.outboxEvents) != 2 {
		t.Fatalf("outbox rows = %d, want 2 (one per changed commit)", len(h.db.outboxEvents))
	}
	secondJob := h.db.outboxEvents[1]
	if secondJob.DedupeKey == firstJob.DedupeKey {
		t.Fatalf("fresh rebuild dedupe key %q equals the first enqueue — the snapshot did not move", secondJob.DedupeKey)
	}
	if secondJob.DedupeKey != "matching.rebuild:a0000000000d0000000000:"+res.InventorySnapshot {
		t.Fatalf("second dedupe key = %q, want matching.rebuild:a0000000000d0000000000:%s", secondJob.DedupeKey, res.InventorySnapshot)
	}
	if len(h.db.auditEvents) != 2 {
		t.Fatalf("audit rows = %d, want 2", len(h.db.auditEvents))
	}
}

func TestCommitInventoryAtomicRollbackOnOutboxFailure(t *testing.T) {
	// The ARCH-003 §1.3 fault seam (mirror of the ARCH-001 §5 proof): a
	// failing matching.rebuild enqueue rolls the audit event AND the
	// inventory rows back with the transaction — no
	// inventory-without-audit, audit-without-job or
	// job-without-inventory half-state (TR-004).
	h := newHarness(t)
	h.outbox.failpoint = errors.New("outbox append failed (injected)")
	csv := commitCSV(commitAssetRow("cmdb", "a1", "portal-host", "Acme", "Portal", "1.0.0"))

	_, err := h.svc.CommitInventory(context.Background(), application.CommitInventoryInput{File: []byte(csv)})
	if err == nil {
		t.Fatal("commit with a failing outbox append must error")
	}
	if len(h.db.assets) != 0 {
		t.Fatalf("committed assets = %d, want 0 (rolled back)", len(h.db.assets))
	}
	if len(h.db.auditEvents) != 0 {
		t.Fatalf("committed audit rows = %d, want 0 (rolled back with the state)", len(h.db.auditEvents))
	}
	if len(h.db.outboxEvents) != 0 {
		t.Fatalf("committed outbox rows = %d, want 0", len(h.db.outboxEvents))
	}
}

func TestCommitInventoryProblemRowsNeverWrite(t *testing.T) {
	h := newHarness(t)
	csv := commitCSV(
		commitAssetRow("cmdb", "a1", "portal-host", "Acme", "Portal", "1.0.0"),
		commitRow("cmdb", "a2", "car", "bad-host", "production", "high", "internet", "", "Acme", "Legacy", "0.9.0", "", "", "", ""), // bad type
	)

	res, err := h.svc.CommitInventory(context.Background(), application.CommitInventoryInput{File: []byte(csv)})
	if err != nil {
		t.Fatalf("CommitInventory: %v", err)
	}
	if res.Rows != 2 || res.ErrorCount != 1 || len(res.Errors) != 1 {
		t.Fatalf("rows=%d errors=%d", res.Rows, res.ErrorCount)
	}
	if p := res.Errors[0]; p.Line != 3 || p.Column != "type" {
		t.Fatalf("problem = %s, want line 3, column type", p)
	}
	// The clean row committed, the problem row never wrote.
	if len(h.db.assets) != 1 || h.db.assets[0].externalID != "a1" {
		t.Fatalf("committed assets = %+v, want only the clean row a1", h.db.assets)
	}
	if res.AssetsCreated != 1 || res.ComponentsCreated != 1 {
		t.Fatalf("tallies: assets created=%d components created=%d", res.AssetsCreated, res.ComponentsCreated)
	}
	if !res.Changed || len(h.db.outboxEvents) != 1 {
		t.Fatalf("clean row commit must enqueue the rebuild (changed=%v outbox=%d)", res.Changed, len(h.db.outboxEvents))
	}
}

func TestCommitInventoryPreviewAgreesAfterCommit(t *testing.T) {
	// Preview/commit natural-key agreement (DEV-059 cross-check): after a
	// commit, the preview of the same file classifies every row as
	// unchanged — the commit upserted exactly the keys the preview
	// compares, so preview and commit can never disagree.
	h := newHarness(t)
	csv := commitCSV(commitAssetRow("cmdb", "a1", "portal-host", "Acme", "Portal", "1.0.0"))

	if _, err := h.svc.CommitInventory(context.Background(), application.CommitInventoryInput{File: []byte(csv)}); err != nil {
		t.Fatalf("CommitInventory: %v", err)
	}

	res, err := application.PreviewInventoryCSV(context.Background(), strings.NewReader(csv), &fakeInventoryReader{db: h.db})
	if err != nil {
		t.Fatalf("PreviewInventoryCSV: %v", err)
	}
	if res.AssetsCreated != 0 || res.AssetsUpdated != 0 || res.AssetsUnchanged != 1 {
		t.Fatalf("preview after commit: created=%d updated=%d unchanged=%d, want all unchanged",
			res.AssetsCreated, res.AssetsUpdated, res.AssetsUnchanged)
	}
	if res.ComponentsCreated != 0 || res.ComponentsUpdated != 0 || res.ComponentsUnchanged != 1 {
		t.Fatalf("preview components after commit: created=%d updated=%d unchanged=%d, want all unchanged",
			res.ComponentsCreated, res.ComponentsUpdated, res.ComponentsUnchanged)
	}
}

func TestCommitInventoryRejectsOversizedFileBeforeAnyWrite(t *testing.T) {
	h := newHarness(t)
	oversized := make([]byte, application.InventoryMaxBytes+1)
	for i := range oversized {
		oversized[i] = 'a'
	}

	_, err := h.svc.CommitInventory(context.Background(), application.CommitInventoryInput{File: oversized})
	if err == nil || !errors.Is(err, application.ErrInventoryTooLarge) {
		t.Fatalf("err = %v, want ErrInventoryTooLarge", err)
	}
	if len(h.runner.txs) != 0 {
		t.Fatalf("an oversized file must be rejected before any transaction, opened %d", len(h.runner.txs))
	}
}
