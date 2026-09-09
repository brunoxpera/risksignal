package kev

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/domain"
)

// Stable RecordError reason codes of the normaliser (ch. 5.2: error_code +
// human message). A code identifies the failure class on the quarantine
// row; the message adds the payload position and the concrete detail.
const (
	// reasonDocumentJSON: the stored payload does not decode as a catalog
	// document. Defensive — the fetch half already gates every stored
	// document through the metadata probe.
	reasonDocumentJSON = "kev.normalize.document_json"
	// reasonEntryJSON: a vulnerabilities[] element is valid JSON but does
	// not decode into the catalog entry shape.
	reasonEntryJSON = "kev.normalize.entry_json"
	// reasonMissingID: a decodable entry carries no cveID — the natural
	// key (UQ (cve_id)) would be unaddressable.
	reasonMissingID = "kev.normalize.missing_id"
	// reasonInvalidDate: an entry carries a date (dateAdded or a non-empty
	// dueDate) that is not a parseable catalog date — the canonical value
	// would not be reproducible.
	reasonInvalidDate = "kev.normalize.invalid_date"
)

// Normalize is the normalise half of the KEV port (ARCH-002 §2.2): it
// parses the stored catalog document and emits, per vulnerabilities[]
// entry, one skeleton domain.Vulnerability plus its kev evidence, and —
// after the entries — one kev_removed evidence per CVE of the previous
// set (NormalizeInput.PreviousKEVCVEs) that is absent from the new
// catalog (ch. 8.3: removals are historised, never silently dropped). Per-
// entry failures are isolated through sink.RecordError and never abort the
// pass (ch. 8.1 step 5); only a failing sink write — an infrastructure
// failure — returns an error.
func (*Adapter) Normalize(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
	res := application.NormalizeResult{}

	var doc catalogDocument
	if err := json.Unmarshal(in.Payload, &doc); err != nil {
		// A payload that is not a catalog document cannot be streamed
		// further — the whole document is isolated (position "document",
		// hashed) and the pass ends as a counted, non-fatal error.
		if serr := sink.RecordError(ctx, application.RecordError{
			Position:    "document",
			Reason:      fmt.Sprintf("%s: the payload is not a decodable KEV catalog: %v", reasonDocumentJSON, err),
			PayloadHash: sha256Hex(in.Payload),
		}); serr != nil {
			return res, fmt.Errorf("kev: normalize: isolate document: %w", serr)
		}
		res.Errors++
		return res, nil
	}

	for i, raw := range doc.Vulnerabilities {
		if err := normalizeEntry(ctx, sink, &res, i, raw); err != nil {
			return res, err
		}
	}

	// Removals (ch. 8.3, ARCH-002 §2.2): every CVE of the previous
	// catalog's set that the new catalog no longer carries is historised
	// as a kev_removed evidence — a new evidence version, never an in-place
	// edit (ch. 6.1). Each removal first re-upserts its skeleton
	// vulnerability: the sink attributes an evidence to a vulnerability
	// this pass upserted (the emission contract of normalize_sink), and the
	// skeleton is the coupling point for the CVE that the previous import
	// created (or that a wiped/partial run left missing) — the
	// read-before-upsert of the ingester keeps it from ever clobbering an
	// existing full NVD row.
	removed := removedCVEs(in.PreviousKEVCVEs, doc)
	for _, cve := range removed {
		if err := sink.Vulnerability(ctx, domain.Vulnerability{CVEID: cve}); err != nil {
			return res, fmt.Errorf("kev: normalize: emit removal skeleton of %s: %w", cve, err)
		}
		res.Records++
		if err := sink.Evidence(ctx, domain.Evidence{Type: domain.EvidenceTypeKEVRemoved, Value: kevRemovedValue{CveID: cve}}); err != nil {
			return res, fmt.Errorf("kev: normalize: emit kev_removed evidence of %s: %w", cve, err)
		}
		res.Records++
	}
	return res, nil
}

// normalizeEntry normalises one vulnerabilities[] element of the catalog:
// emit the skeleton vulnerability (cve_id, summary = shortDescription) and
// its kev evidence carrying the full catalog field set (ARCH-002 §2.2). An
// element that does not decode into the entry shape, carries no cveID or
// holds an unparsable date (dateAdded, or a non-empty dueDate) is isolated
// through sink.RecordError (position + reason + the SHA-256 of the
// offending element) and skipped; the other entries keep flowing.
func normalizeEntry(ctx context.Context, sink application.NormalizeSink, res *application.NormalizeResult, i int, raw json.RawMessage) error {
	pos := fmt.Sprintf("vulnerabilities[%d]", i)

	var e kevEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return emitRecordError(ctx, sink, res, application.RecordError{
			Position:    pos,
			Reason:      fmt.Sprintf("%s: %v", reasonEntryJSON, err),
			PayloadHash: sha256Hex(raw),
		})
	}
	if e.CveID == "" {
		return emitRecordError(ctx, sink, res, application.RecordError{
			Position:    pos,
			Reason:      fmt.Sprintf("%s: the entry carries no cveID", reasonMissingID),
			PayloadHash: sha256Hex(raw),
		})
	}

	// Canonical dates: dateAdded is required (a catalog entry is dated by
	// definition); dueDate is optional — an empty one is recorded as
	// absent, a present-but-unparsable one is a malformed entry.
	dateAdded, ok := parseCatalogDate(e.DateAdded)
	if !ok {
		return emitRecordError(ctx, sink, res, application.RecordError{
			Position:    pos,
			Reason:      fmt.Sprintf("%s: dateAdded %q is not a catalog date", reasonInvalidDate, e.DateAdded),
			PayloadHash: sha256Hex(raw),
		})
	}
	dueDate := ""
	if e.DueDate != "" {
		dueDate, ok = parseCatalogDate(e.DueDate)
		if !ok {
			return emitRecordError(ctx, sink, res, application.RecordError{
				Position:    pos,
				Reason:      fmt.Sprintf("%s: dueDate %q is not a catalog date", reasonInvalidDate, e.DueDate),
				PayloadHash: sha256Hex(raw),
			})
		}
	}

	// 1) the skeleton vulnerability (ARCH-002 §2.2): cve_id plus the
	// summary — the persistence upsert keeps it a skeleton and never
	// clobbers an existing full NVD row (the ingester's read-before-upsert
	// only creates the skeleton when the CVE is not yet present).
	if err := sink.Vulnerability(ctx, domain.Vulnerability{CVEID: e.CveID, Summary: e.ShortDescription}); err != nil {
		return fmt.Errorf("kev: normalize: emit skeleton vulnerability %s: %w", e.CveID, err)
	}
	res.Records++

	// 2) the kev evidence — the full field set as the canonical value
	// (ARCH-002 §2.2). Presence in the catalog is the statement "known
	// exploited", hence known_exploited: true; the shape is a superset of
	// the I1b kev evidence value ({cve_id, known_exploited}), so the I1b
	// rows stay valid.
	if err := sink.Evidence(ctx, domain.Evidence{Type: domain.EvidenceTypeKEV, Value: kevEvidenceValue{
		CveID:             e.CveID,
		Vendor:            e.VendorProject,
		Product:           e.Product,
		VulnerabilityName: e.VulnerabilityName,
		DateAdded:         dateAdded,
		KnownExploited:    true,
		RequiredAction:    e.RequiredAction,
		DueDate:           dueDate,
		KnownRansomware:   e.KnownRansomwareCampaignUse,
	}}); err != nil {
		return fmt.Errorf("kev: normalize: emit kev evidence of %s: %w", e.CveID, err)
	}
	res.Records++
	return nil
}

// emitRecordError isolates one failed record through the sink and counts it
// (ch. 8.6): an isolated error is counted, not fatal.
func emitRecordError(ctx context.Context, sink application.NormalizeSink, res *application.NormalizeResult, e application.RecordError) error {
	if err := sink.RecordError(ctx, e); err != nil {
		return fmt.Errorf("kev: normalize: isolate record: %w", err)
	}
	res.Errors++
	return nil
}

// removedCVEs is the removal diff of one pass (ch. 8.3): the CVE ids of
// the previous catalog's set that the new catalog document no longer
// carries. The previous set is deduplicated (it may repeat ids) and the
// result is sorted — one previous set yields one deterministic removal
// stream regardless of the input order.
func removedCVEs(previous []string, doc catalogDocument) []string {
	present := make(map[string]bool, len(doc.Vulnerabilities))
	for _, raw := range doc.Vulnerabilities {
		var e kevEntry
		if err := json.Unmarshal(raw, &e); err == nil && e.CveID != "" {
			present[e.CveID] = true
		}
	}
	seen := make(map[string]bool, len(previous))
	removed := make([]string, 0, len(previous))
	for _, cve := range previous {
		if cve == "" || present[cve] || seen[cve] {
			continue
		}
		seen[cve] = true
		removed = append(removed, cve)
	}
	sort.Strings(removed)
	return removed
}

// kevEntry is the DTO of one vulnerabilities[] element of the catalog
// (ARCH-002 §2.2: cveID, vendorProject, product, vulnerabilityName,
// dateAdded, shortDescription, requiredAction, dueDate,
// knownRansomwareCampaignUse, notes). Notes is parsed for completeness of
// the DTO; the canonical kev evidence value carries the ARCH-002 §2.2
// field set (notes is not part of the locked value shape).
type kevEntry struct {
	CveID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse bool   `json:"knownRansomwareCampaignUse"`
	Notes                      string `json:"notes"`
}

// kevEvidenceValue is the canonical value of a kev evidence — the full
// catalog field set of one entry (ARCH-002 §2.2). The fixed field order is
// the canonical serialisation the value hash is computed over (no maps —
// determinism). The shape is a superset of the I1b kev evidence value
// ({cve_id, known_exploited}), so the I1b rows and the prioritisation
// reads that look at them stay valid. Dates are stored in their canonical
// YYYY-MM-DD form.
type kevEvidenceValue struct {
	CveID             string `json:"cve_id"`
	Vendor            string `json:"vendor"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerability_name"`
	DateAdded         string `json:"date_added"`
	KnownExploited    bool   `json:"known_exploited"`
	RequiredAction    string `json:"required_action"`
	DueDate           string `json:"due_date"`
	KnownRansomware   bool   `json:"known_ransomware"`
}

// kevRemovedValue is the canonical value of a kev_removed evidence: the
// statement that one CVE of the previous catalog is absent from the new
// one (ARCH-002 §2.2, ch. 8.3). cve_id both names the subject and lets the
// sink attribute the evidence to its vulnerability; the raw record the
// evidence attaches to identifies the catalog revision that observed the
// removal.
type kevRemovedValue struct {
	CveID string `json:"cve_id"`
}

// sha256Hex hashes the canonical bytes of an offending record/slice
// (RecordError.PayloadHash — a hash, never the payload itself).
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
