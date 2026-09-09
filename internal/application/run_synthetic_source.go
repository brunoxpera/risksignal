package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/xpera/risksignal/internal/domain"
)

// Terminal statuses of a source run (ARCH-001 §1 source_runs.status; the
// CHECK constraint allows 'running', 'succeeded' and 'failed').
const (
	SourceRunStatusSucceeded SourceRunStatus = "succeeded"
	SourceRunStatusFailed    SourceRunStatus = "failed"
)

// SourceRunStatus is the end state of a source run (ARCH-001 §1 source_runs:
// exactly one end state per run, counters advanced only on success).
type SourceRunStatus string

// defaultRunActorID is the audit actor of the signals a run creates unless
// the caller overrides it (ARCH-001 §1 audit_events.actor_id: the synthetic
// source itself; demo seed passes 'demo-seed').
const defaultRunActorID = "synthetic-source"

// Product is the affected product of a synthetic case in the terms of the
// seeded inventory (ARCH-001 §3 case table: vendor/product plus the affected
// version as stated by the source, e.g. "acme" / "portal" / "2.4").
type Product struct {
	Vendor  string
	Product string
	// Version is the affected version statement of the source. The I1b
	// matcher resolves it against the seeded component versions
	// (affectedVersionMethod): an exact match is an exact_identifier, a
	// dotted-prefix range (2.4 covers 2.4.4) a canonical_product_range.
	Version string
}

// SyntheticCase is one raw case of the synthetic document (ARCH-001 §3). It
// is the typed input of the ingest → normalise → match → signal chain: the
// source adapter fixture (WP-1b.05) maps its reference cases C1–C6 + E1 onto
// this shape. CVEID empty marks the malformed E1 case: the run counts it as
// an error without aborting the other cases. CVSS/KEV/EPSS carry the factor
// evidence values; Criticality/Exposure carry the asset context of the case
// (I1b seeds one inventory asset per case context; full asset-joined
// matching replaces this seam with I3).
type SyntheticCase struct {
	CVEID     string
	Summary   string
	Statement string // synthetic_statement evidence text
	Product   Product
	CVSS      float64
	KEV       bool
	EPSS      float64
	Asset     SyntheticAsset
}

// SyntheticAsset is the inventory context of a case (ARCH-001 §3 "asset
// context": the criticality/exposure the ch. 9.3 rules read).
type SyntheticAsset struct {
	Criticality domain.Criticality
	Exposure    domain.Exposure
}

// RunSyntheticSourceInput drives one synthetic source run (ARCH-001 §3).
// SourceID is the resolved sources row (the CLI loads it by (type, name),
// WP-1b.05); ExternalID is the stable raw-record document name.
type RunSyntheticSourceInput struct {
	SourceID   string
	ExternalID string
	Cases      []SyntheticCase
	// ActorID names the audit actor of the created signals; empty defaults
	// to "synthetic-source".
	ActorID string
}

// RunSyntheticSourceResult reports a completed run. Errors holds the
// per-case errors (the E1 class) that were counted without aborting the
// run; the run's terminal status is failed when any occurred (concept
// ch. 8.1 step 5, ARCH-001 §3 step 6).
type RunSyntheticSourceResult struct {
	RunID    string
	Status   SourceRunStatus
	Counters SourceRunCounters
	Errors   []string
}

// syntheticDocument is the canonical raw payload of one run: the unchanged
// source document stored in raw_records (ADR-013) and hashed for the
// natural-key idempotency (UQ (source_id, external_id, content_hash)). The
// struct marshal is deterministic — fixed field order, no maps — so the same
// input produces byte-identical payloads and hashes (ARCH-001 §3
// reproducibility guarantee).
type syntheticDocument struct {
	ExternalID string                  `json:"external_id"`
	Cases      []syntheticDocumentCase `json:"cases"`
}

type syntheticDocumentCase struct {
	CVEID       string  `json:"cve_id"`
	Summary     string  `json:"summary"`
	Statement   string  `json:"statement"`
	Vendor      string  `json:"vendor"`
	Product     string  `json:"product"`
	Version     string  `json:"version"`
	CVSS        float64 `json:"cvss"`
	KEV         bool    `json:"kev"`
	EPSS        float64 `json:"epss"`
	Criticality string  `json:"criticality"`
	Exposure    string  `json:"exposure"`
}

// Case evidence value shapes (ARCH-001 §1 evidences: one synthetic_statement
// plus the typed factor evidences cvss/kev/epss per case). Each value
// carries the cve_id, which both mirrors what the I2 source adapters will
// feed and keeps the natural key (raw_record_id, type, value_hash) distinct
// between the cases of one document. The structs are the canonical form the
// value_hash is computed over.
type statementEvidence struct {
	CveID     string `json:"cve_id"`
	Statement string `json:"statement"`
}

type cvssEvidence struct {
	CveID     string  `json:"cve_id"`
	BaseScore float64 `json:"base_score"`
}

type kevEvidence struct {
	CveID          string `json:"cve_id"`
	KnownExploited bool   `json:"known_exploited"`
}

type epssEvidence struct {
	CveID      string  `json:"cve_id"`
	Percentile float64 `json:"percentile"`
}

// evidenceValue assembles one evidence value payload and its canonical
// SHA-256 hash (UQ (raw_record_id, type, value_hash)).
func evidenceValue(v any) (value []byte, hash string, err error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:]), nil
}

// contentHash returns the SHA-256 hex digest of a canonical payload.
func contentHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// affectedVersionMethod is the minimal I1b matcher decision (ARCH-001 §3:
// a canonical_product_range/exact_identifier matcher with the ADR-015
// mapping hard-coded, rule_version "i1b-1"; the real version semantics and
// the normalised product index replace it with I3). One seeded component
// version is affected when it equals the affected version (exact_identifier)
// or when the affected version is a dotted-segment prefix of it — "2.4"
// covers "2.4.4" (canonical_product_range). ok is false when the version is
// provably not in range.
func affectedVersionMethod(componentVersion, affected string) (method domain.MatchMethod, ok bool) {
	cv := strings.TrimSpace(componentVersion)
	av := strings.TrimSpace(affected)
	if cv == "" || av == "" {
		return "", false
	}
	if cv == av {
		return domain.MatchMethodExactIdentifier, true
	}
	component := strings.Split(cv, ".")
	affectedSegs := strings.Split(av, ".")
	if len(component) <= len(affectedSegs) {
		return "", false
	}
	for i := range affectedSegs {
		if component[i] != affectedSegs[i] {
			return "", false
		}
	}
	return domain.MatchMethodCanonicalProductRange, true
}

// matchedPair is one confirmed vulnerability-component match of the run,
// recorded during ingest and materialised into a signal afterwards.
type matchedPair struct {
	CaseIndex  int
	MatchID    string
	Method     domain.MatchMethod
	Confidence domain.Confidence
}

// RunSyntheticSource drives the ARCH-001 §3 run mechanics: open the run,
// ingest the deterministic document (raw record + per-case vulnerability,
// evidence and match upserts, idempotent by natural key), run CreateSignal
// for every match that has no signal yet, and commit the counters with the
// terminal status. A malformed case (E1: missing cve_id) is counted as a run
// error and does not abort the other cases; infrastructure failures abort
// the run (status failed, error recorded) and surface as the returned error.
//
// The use case is deterministic: no randomness, no wall clock — every
// timestamp comes from the injected clock, payloads and hashes from the
// canonical marshal below — so a re-run with the same fixture and clock is a
// no-op at every level (ARCH-001 §3 reproducibility guarantee).
func (s *Service) RunSyntheticSource(ctx context.Context, in RunSyntheticSourceInput) (RunSyntheticSourceResult, error) {
	const op = "run_synthetic_source"

	if in.SourceID == "" {
		return RunSyntheticSourceResult{}, Validationf(op, "source id must not be empty")
	}
	if in.ExternalID == "" {
		return RunSyntheticSourceResult{}, Validationf(op, "external id must not be empty")
	}
	actorID := in.ActorID
	if actorID == "" {
		actorID = defaultRunActorID
	}
	actor := Actor{Type: ActorTypeSystem, ID: actorID}

	now := s.clock.Now()

	// 1) open the run (status running). The synthetic source has no cursor.
	var runID string
	if err := s.runTx(ctx, func(tx Tx) error {
		id, err := s.runs.Open(ctx, tx, in.SourceID, nil, now)
		if err != nil {
			return err
		}
		runID = id
		return nil
	}); err != nil {
		return RunSyntheticSourceResult{}, err
	}

	counters := SourceRunCounters{Records: len(in.Cases)}
	var runErrors []string

	// 2)–4) ingest transaction: store the document, then per case upsert
	// the vulnerability, insert its evidences and insert the matches of the
	// seeded components the case is affected in. All writes are idempotent
	// by natural key; the whole ingest phase is one transaction of its own,
	// independent of signal creation (ARCH-001 §3 step 3).
	doc := syntheticDocument{ExternalID: in.ExternalID}
	for _, c := range in.Cases {
		doc.Cases = append(doc.Cases, syntheticDocumentCase{
			CVEID:       c.CVEID,
			Summary:     c.Summary,
			Statement:   c.Statement,
			Vendor:      c.Product.Vendor,
			Product:     c.Product.Product,
			Version:     c.Product.Version,
			CVSS:        c.CVSS,
			KEV:         c.KEV,
			EPSS:        c.EPSS,
			Criticality: string(c.Asset.Criticality),
			Exposure:    string(c.Asset.Exposure),
		})
	}
	payload, err := json.Marshal(doc)
	if err != nil {
		return RunSyntheticSourceResult{}, InfraError(op, err)
	}

	var pairs []matchedPair
	ingestErr := s.runTx(ctx, func(tx Tx) error {
		rawID, err := s.raws.Insert(ctx, tx, in.SourceID, in.ExternalID, payload, contentHash(payload), "", now)
		if err != nil {
			return err
		}
		for i := range in.Cases {
			c := in.Cases[i]
			if c.CVEID == "" {
				// E1: malformed case — counted, does not abort the others
				// (concept ch. 8.1 step 5).
				runErrors = append(runErrors, fmt.Sprintf("case %d: missing cve_id", i))
				continue
			}
			if !c.Asset.Criticality.Valid() {
				runErrors = append(runErrors, fmt.Sprintf("case %d: invalid asset criticality %q", i, c.Asset.Criticality))
				continue
			}
			if !c.Asset.Exposure.Valid() {
				runErrors = append(runErrors, fmt.Sprintf("case %d: invalid asset exposure %q", i, c.Asset.Exposure))
				continue
			}

			// Normalise: vulnerability by natural key.
			vulnID, err := s.vulns.Upsert(ctx, tx, VulnerabilityRecord{CVEID: c.CVEID, Summary: c.Summary}, now, timeZero)
			if err != nil {
				return err
			}

			// Normalise: the immutable source statements of the case.
			if err := s.insertCaseEvidences(ctx, tx, vulnID, rawID, c, now); err != nil {
				return err
			}

			// Match: resolve the affected version range over the seeded
			// components of the case's product.
			comps, err := s.comps.ListByVendorProduct(ctx, c.Product.Vendor, c.Product.Product)
			if err != nil {
				return err
			}
			for _, comp := range comps {
				method, affected := affectedVersionMethod(comp.Version, c.Product.Version)
				if !affected {
					continue
				}
				conf, score, err := method.Derive(0)
				if err != nil {
					return InfraError(op, err)
				}
				matchID, err := s.matches.Insert(ctx, tx, MatchRecord{
					VulnerabilityID: vulnID,
					ComponentID:     comp.ID,
					Method:          method,
					Confidence:      conf,
					Score:           score,
					RuleVersion:     domain.MatchRuleVersion,
				}, now)
				if err != nil {
					return err
				}
				pairs = append(pairs, matchedPair{
					CaseIndex:  i,
					MatchID:    matchID,
					Method:     method,
					Confidence: conf,
				})
				counters.Matched++
			}
		}
		return nil
	})
	if ingestErr != nil {
		// Nothing of the ingest phase committed — the counters of a failed
		// transaction must not be reported (concept ch. 6.1: counters
		// advance only on success). The malformed-case notes stay recorded
		// as information for the operator.
		return RunSyntheticSourceResult{}, s.failRun(ctx, op, runID, SourceRunCounters{}, ingestErr, runErrors)
	}

	// 5) per match without a signal: run the CreateSignal command — the
	// atomic signal + audit + outbox transaction (ARCH-001 §2). The signal
	// creation order is deterministic: cases in document order, matches in
	// component version order.
	for _, p := range pairs {
		exists, err := s.signals.ExistsByMatchID(ctx, p.MatchID)
		if err != nil {
			return RunSyntheticSourceResult{}, s.failRun(ctx, op, runID, counters, err, runErrors)
		}
		if exists {
			continue // re-run: the match already has its signal
		}
		c := in.Cases[p.CaseIndex]
		_, err = s.CreateSignal(ctx, CreateSignalInput{
			MatchID: p.MatchID,
			CveID:   c.CVEID,
			Factors: domain.PriorityFactors{
				Method:      p.Method,
				Confidence:  p.Confidence,
				KEV:         c.KEV,
				CVSS:        c.CVSS,
				EPSS:        c.EPSS,
				Criticality: c.Asset.Criticality,
				Exposure:    c.Asset.Exposure,
			},
			CorrelationID: runID,
			Actor:         actor,
		})
		if err != nil {
			kind, _ := ErrorKindOf(err)
			switch kind {
			case KindConflict:
				// A concurrent command created the signal between the
				// existence check and this insert: nothing to do, the
				// signal exists (UQ match_id).
				continue
			case KindValidation:
				// A data-level rejection of one signal (e.g. factor
				// inconsistency of this case): counted like E1, the other
				// cases continue.
				runErrors = append(runErrors, fmt.Sprintf("case %d: %v", p.CaseIndex, err))
				continue
			default:
				// Infrastructure failure: abort the run with status failed.
				return RunSyntheticSourceResult{}, s.failRun(ctx, op, runID, counters, err, runErrors)
			}
		}
		counters.Signals++
	}

	// 6) commit the counters with the terminal status: failed when any case
	// error was counted, succeeded otherwise (concept ch. 8.1 step 5).
	status := SourceRunStatusSucceeded
	if len(runErrors) > 0 {
		status = SourceRunStatusFailed
	}
	if err := s.completeRun(ctx, op, runID, status, counters, nil, strings.Join(runErrors, "; ")); err != nil {
		return RunSyntheticSourceResult{}, err
	}
	return RunSyntheticSourceResult{RunID: runID, Status: status, Counters: counters, Errors: runErrors}, nil
}

// timeZero is the sentinel for "no modified_at" (a NULL timestamptz); I1b
// never refreshes it.
var timeZero = time.Time{}

// insertCaseEvidences stores the four immutable source statements of one
// case (synthetic_statement + cvss + kev + epss; ARCH-001 §1 evidences).
func (s *Service) insertCaseEvidences(ctx context.Context, tx Tx, vulnID, rawID string, c SyntheticCase, now time.Time) error {
	statements := []struct {
		typ   domain.EvidenceType
		value any
	}{
		{domain.EvidenceTypeSyntheticStatement, statementEvidence{CveID: c.CVEID, Statement: c.Statement}},
		{domain.EvidenceTypeCVSS, cvssEvidence{CveID: c.CVEID, BaseScore: c.CVSS}},
		{domain.EvidenceTypeKEV, kevEvidence{CveID: c.CVEID, KnownExploited: c.KEV}},
		{domain.EvidenceTypeEPSS, epssEvidence{CveID: c.CVEID, Percentile: c.EPSS}},
	}
	for _, st := range statements {
		value, hash, err := evidenceValue(st.value)
		if err != nil {
			return InfraError("run_synthetic_source", err)
		}
		if _, err := s.vulns.AddEvidence(ctx, tx, EvidenceRecord{
			VulnerabilityID: vulnID,
			RawRecordID:     rawID,
			Type:            st.typ,
			Value:           value,
			ValueHash:       hash,
		}, now); err != nil {
			return err
		}
	}
	return nil
}

// failRun closes a run that aborted on an infrastructure error: status
// failed with the error text and the counters so far, then returns the
// original error (unwrapped) for the caller. A failed run never advances
// the cursor — the persistence layer guards cursor_after on the succeeded
// status (ch. 6.1, ARCH-002 §1) — so cursorAfter is always nil here.
func (s *Service) failRun(ctx context.Context, op, runID string, counters SourceRunCounters, cause error, runErrors []string) error {
	text := cause.Error()
	if len(runErrors) > 0 {
		text = text + "; " + strings.Join(runErrors, "; ")
	}
	_ = s.completeRun(ctx, op, runID, SourceRunStatusFailed, counters, nil, text)
	return cause
}

// completeRun closes a run with its terminal state inside one transaction.
// cursorAfter is committed with a successful run only; pass nil for failed
// runs and cursor-less sources.
func (s *Service) completeRun(ctx context.Context, op, runID string, status SourceRunStatus, counters SourceRunCounters, cursorAfter json.RawMessage, errText string) error {
	return s.runTx(ctx, func(tx Tx) error {
		return s.runs.Complete(ctx, tx, runID, status, counters, cursorAfter, errText, s.clock.Now())
	})
}
