package nvd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/domain"
)

// Stable RecordError reason codes of the normaliser (ch. 5.2: error_code +
// human message). A code identifies the failure class on the quarantine
// row; the message adds the payload position and the concrete detail.
const (
	// reasonPageJSON: a payload document (page) does not parse as the API
	// 2.0 envelope. Defensive — the fetch half already gates every stored
	// page through the same envelope decode.
	reasonPageJSON = "nvd.normalize.page_json"
	// reasonEntryJSON: a vulnerabilities[] element is valid JSON but does
	// not decode into the {"cve": …} entry shape.
	reasonEntryJSON = "nvd.normalize.entry_json"
	// reasonMissingID: a decodable CVE record carries no cve.id — the
	// natural key (UQ (cve_id)) would be unaddressable.
	reasonMissingID = "nvd.normalize.missing_id"
)

// Normalize is the normalise half of the NVD port (ARCH-002 §2.1): it
// streams the stored raw payload — the verbatim pages of one fetch,
// '\n'-joined — apart again with a json.Decoder (JSON documents are
// self-delimiting) and, for every vulnerabilities[] element of every page,
// emits one domain.Vulnerability plus its nvd_statement and cvss
// evidences. Per-record failures are isolated through sink.RecordError and
// never abort the pass (ch. 8.1 step 5); only a failing sink write — an
// infrastructure failure — returns an error.
func (*Adapter) Normalize(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
	res := application.NormalizeResult{}

	dec := json.NewDecoder(bytes.NewReader(in.Payload))
	for pageNo := 1; ; pageNo++ {
		pageStart := dec.InputOffset()
		var p page
		if err := dec.Decode(&p); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// Defensive isolation of a corrupted page. The decoder cannot
			// resync after a top-level syntax error, so the pass stops
			// here — the failure is isolated and counted, never fatal.
			// Fetch-verified payloads (every page passed the envelope
			// decode before storage) never take this branch.
			end := dec.InputOffset()
			if end <= pageStart {
				end = int64(len(in.Payload))
			}
			if serr := sink.RecordError(ctx, application.RecordError{
				Position:    fmt.Sprintf("page %d (byte offset %d)", pageNo, pageStart),
				Reason:      fmt.Sprintf("%s: page %d is not decodable JSON: %v", reasonPageJSON, pageNo, err),
				PayloadHash: sha256Hex(in.Payload[pageStart:end]),
			}); serr != nil {
				return res, fmt.Errorf("nvd: normalize: isolate page %d: %w", pageNo, serr)
			}
			res.Errors++
			return res, nil
		}

		for i, raw := range p.Vulnerabilities {
			if err := normalizeEntry(ctx, in, sink, &res, pageNo, i, raw); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}

// normalizeEntry normalises one vulnerabilities[] element: emit the CVE's
// domain.Vulnerability, its nvd_statement evidence and — when the record
// carries CVSS metrics — its cvss evidence. A record that does not decode
// into the entry shape or carries no id is isolated through
// sink.RecordError (position + reason + the SHA-256 of the offending
// element) and skipped; the other records keep flowing.
func normalizeEntry(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink, res *application.NormalizeResult, pageNo, i int, raw json.RawMessage) error {
	pos := fmt.Sprintf("page %d vulnerabilities[%d]", pageNo, i)

	var entry nvdEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return emitRecordError(ctx, sink, res, application.RecordError{
			Position:    pos,
			Reason:      fmt.Sprintf("%s: %v", reasonEntryJSON, err),
			PayloadHash: sha256Hex(raw),
		})
	}
	cve := entry.CVE
	if cve.ID == "" {
		return emitRecordError(ctx, sink, res, application.RecordError{
			Position:    pos,
			Reason:      fmt.Sprintf("%s: the record carries no cve.id", reasonMissingID),
			PayloadHash: sha256Hex(raw),
		})
	}

	summary, description := cve.englishDescription()
	cvss := cve.cvssMetrics()
	cpe := cpeConfig(cve)

	vuln := domain.Vulnerability{
		CVEID:       cve.ID,
		Summary:     summary,
		Description: description,
		CVSS:        cvss,
		References:  cve.references(),
		CPECfg:      cpe,
	}
	if err := sink.Vulnerability(ctx, vuln); err != nil {
		return fmt.Errorf("nvd: normalize: emit vulnerability %s: %w", cve.ID, err)
	}
	res.Records++

	// nvd_statement: the canonical record excerpt — the CVE element
	// compacted (insignificant whitespace removed, every field preserved),
	// so the value — and with it the evidence's value hash — is stable for
	// one canonical record regardless of the source's formatting.
	var canonical bytes.Buffer
	if err := json.Compact(&canonical, raw); err != nil {
		// raw already decoded inside the page envelope: it is valid JSON,
		// so Compact cannot fail; keep the pass honest if it ever does.
		return emitRecordError(ctx, sink, res, application.RecordError{
			Position:    pos,
			Reason:      fmt.Sprintf("%s: canonicalise the record: %v", reasonEntryJSON, err),
			PayloadHash: sha256Hex(raw),
		})
	}
	statement := domain.Evidence{
		Type:  domain.EvidenceTypeNVDStatement,
		Value: nvdStatementValue{CveID: cve.ID, Statement: canonical.String()},
	}
	if err := sink.Evidence(ctx, statement); err != nil {
		return fmt.Errorf("nvd: normalize: emit nvd_statement evidence of %s: %w", cve.ID, err)
	}
	res.Records++

	if cvss != nil {
		cvssEvidence := domain.Evidence{
			Type:  domain.EvidenceTypeCVSS,
			Value: cvssEvidenceValue{CveID: cve.ID, BaseScore: cvss.BaseScore, Severity: cvss.BaseSeverity, Vector: cvss.Vector, Version: cvss.Version},
		}
		if err := sink.Evidence(ctx, cvssEvidence); err != nil {
			return fmt.Errorf("nvd: normalize: emit cvss evidence of %s: %w", cve.ID, err)
		}
		res.Records++
	}
	return nil
}

// emitRecordError isolates one failed record through the sink and counts it
// (ch. 8.6): an isolated error is counted, not fatal.
func emitRecordError(ctx context.Context, sink application.NormalizeSink, res *application.NormalizeResult, e application.RecordError) error {
	if err := sink.RecordError(ctx, e); err != nil {
		return fmt.Errorf("nvd: normalize: isolate record: %w", err)
	}
	res.Errors++
	return nil
}

// sha256Hex hashes the canonical bytes of an offending record/slice
// (RecordError.PayloadHash — a hash, never the payload itself).
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// cpeConfig is the cve.configurations block carried unchanged into
// vulnerabilities.cpe_config (ARCH-002 §2.1: the raw block; I3 normalises
// it into the product index, which is why the domain gives it no shape).
// Absent configurations yield nil (the column stays NULL).
func cpeConfig(cve nvdCVE) any {
	if len(cve.Configurations) == 0 {
		return nil
	}
	return cve.Configurations
}

// englishDescription picks the canonical English statement of the record:
// the value of the lang=="en" description, falling back to the first entry
// when the source carries no English one. The same text is both the
// vulnerability's summary (its short statement) and its full description
// (ARCH-002 §2.1). Both are "" when the record carries no descriptions.
func (c nvdCVE) englishDescription() (summary, description string) {
	if len(c.Descriptions) == 0 {
		return "", ""
	}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			return d.Value, d.Value
		}
	}
	return c.Descriptions[0].Value, c.Descriptions[0].Value
}

// references maps the advisory links of the record onto the domain
// references (url/source/tags). A link without an URL is meaningless
// (domain.Reference: url is the one required field) and is dropped — the
// published list is preserved in order otherwise.
func (c nvdCVE) references() []domain.Reference {
	refs := make([]domain.Reference, 0, len(c.References))
	for _, r := range c.References {
		if r.URL == "" {
			continue
		}
		refs = append(refs, domain.Reference{URL: r.URL, Source: r.Source, Tags: r.Tags})
	}
	if len(refs) == 0 {
		return nil
	}
	return refs
}

// cvssMetrics builds the {version, base_score, base_severity, vector}
// summary from the first CVSS metric of the record (cvssMetricV31 first,
// falling back to V30 and then V2; ARCH-002 §2.1). The severity token is
// normalised to the domain's lowercase vocabulary (none|low|medium|high|
// critical); V2 publishes it on the metric object, V3 on cvssData — both
// are read. A record without a usable metric (none present, or the first
// entry carrying no version) yields nil: the summary is complete or absent.
func (c nvdCVE) cvssMetrics() *domain.CVSSMetrics {
	if c.Metrics == nil {
		return nil
	}
	metric, ok := c.Metrics.first()
	if !ok {
		return nil
	}
	d := metric.CVSSData
	if d.Version == "" {
		return nil
	}
	severity := d.BaseSeverity
	if severity == "" {
		severity = metric.BaseSeverity
	}
	return &domain.CVSSMetrics{
		Version:      d.Version,
		BaseScore:    d.BaseScore,
		BaseSeverity: strings.ToLower(severity),
		Vector:       d.VectorString,
	}
}

// nvdEntry is one element of page.vulnerabilities: the CVE record wrapped
// in the "cve" envelope of the API 2.0 response format ({"cve": {…}}).
type nvdEntry struct {
	CVE nvdCVE `json:"cve"`
}

// nvdCVE is the DTO of one CVE record (ARCH-002 §2.1): identity, the
// multilingual descriptions, the CVSS metric lists, the configurations
// block (kept raw — cpe_config carries it unchanged) and the advisory
// references. published/lastModified are deliberately not read: the
// timestamps of the vulnerabilities row are clock-stamped by the sink
// (WP-2.05 forward-note, no source-date passthrough).
type nvdCVE struct {
	ID             string           `json:"id"`
	Descriptions   []nvdDescription `json:"descriptions"`
	Metrics        *nvdMetrics      `json:"metrics"`
	Configurations json.RawMessage  `json:"configurations"`
	References     []nvdReference   `json:"references"`
}

// nvdDescription is one localized description text of the record.
type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// nvdMetrics holds the CVSS metric lists of the record. The lists are
// versioned (cvssMetricV31 / cvssMetricV30 / cvssMetricV2); the normaliser
// reads the first entry of the highest version present.
type nvdMetrics struct {
	CVSSMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdCVSSMetric `json:"cvssMetricV2"`
}

// first returns the first metric entry of the record: V31, then V30, then
// V2 (ARCH-002 §2.1) — a metric of a higher version wins over a lower one.
func (m *nvdMetrics) first() (nvdCVSSMetric, bool) {
	for _, list := range [][]nvdCVSSMetric{m.CVSSMetricV31, m.CVSSMetricV30, m.CVSSMetricV2} {
		if len(list) > 0 {
			return list[0], true
		}
	}
	return nvdCVSSMetric{}, false
}

// nvdCVSSMetric is one scored metric entry. V3 publishes the severity
// inside cvssData; V2 publishes baseSeverity on the metric object itself —
// the DTO keeps both so the normaliser can read either.
type nvdCVSSMetric struct {
	BaseSeverity string      `json:"baseSeverity"`
	CVSSData     nvdCVSSData `json:"cvssData"`
}

// nvdCVSSData is the core cvssData block of one metric: version, vector,
// base score and (V3) base severity.
type nvdCVSSData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// nvdReference is one advisory link of the record.
type nvdReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

// nvdStatementValue is the canonical value of an nvd_statement evidence:
// the cve_id plus the canonical record excerpt (the compacted CVE
// element). The shape mirrors the synthetic statement evidence
// ({cve_id, statement}) and carries cve_id at the top level — the sink
// resolves the evidence's vulnerability by it.
type nvdStatementValue struct {
	CveID     string `json:"cve_id"`
	Statement string `json:"statement"`
}

// cvssEvidenceValue is the canonical value of a cvss evidence — the same
// cvss shape I1b already reads for prioritisation (ARCH-002 §2.1:
// {cve_id, base_score, severity, vector, version}).
type cvssEvidenceValue struct {
	CveID     string  `json:"cve_id"`
	BaseScore float64 `json:"base_score"`
	Severity  string  `json:"severity"`
	Vector    string  `json:"vector"`
	Version   string  `json:"version"`
}
