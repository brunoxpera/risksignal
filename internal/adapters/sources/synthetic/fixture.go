// Package synthetic is the deterministic reference source of the I1b
// walking skeleton (ARCH-001 §3, WP-1b.05): one embedded fixture document
// (fixtures/reference.json) defines the demo inventory and the reference
// cases C1–C6 + E1 with stable identities, run factors and the expected
// outcome of every case.
//
// The package is a pure data adapter: it loads and validates the embedded
// fixture and maps it onto the application-level run input
// (application.SyntheticCase) and the seed inventory. It performs no I/O
// and no wall-clock access — the demo CLI (cmd/risksignal) registers the
// source, seeds the inventory and runs the application use case, so the
// whole chain stays deterministic (ARCH-001 §3 reproducibility guarantee:
// same fixture + same rule version + same clock ⇒ byte-identical hashes,
// dedupe keys and rows).
//
// The I2 source adapters (nvd, kev, epss) sit next to this package and stay
// empty in I1b; the synthetic source implements the same adapter contract
// they will implement later (ch. 8.5: one configured source row, here of
// type 'synthetic').
package synthetic

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/domain"
)

// Stable identities of the synthetic source and its document (ARCH-001 §1
// sources / raw_records). The demo CLI registers the source row under
// SourceType + SourceName and runs the document under ExternalID; the
// fixture JSON must declare the same external id (Load validates).
const (
	// SourceType is the sources.type of the synthetic source.
	SourceType = "synthetic"
	// SourceName is the sources.name of the synthetic source.
	SourceName = "synthetic-source"
	// SourceActor is the audit actor of demo-driven runs (ARCH-001 §1
	// audit_events.actor_id: 'synthetic-source' | 'demo-seed'). The demo
	// CLI acts as the operator, so its runs are stamped 'demo-seed'; the
	// default actor of RunSyntheticSource ('synthetic-source') is what a
	// later scheduler-driven run would use.
	SourceActor = "demo-seed"
	// ExternalID is the stable raw-record document name of a synthetic run
	// (ARCH-001 §1 raw_records.external_id). The fixture JSON declares the
	// same value; Load validates the match.
	ExternalID = "synthetic-reference"
)

// Expected outcome vocabulary of a fixture case (the expect block of
// reference.json): signal (a confirmed match produces a risk signal),
// no_signal (no confirmed inventory assignment — the case is ingested but
// produces no match and no signal), error (malformed case, counted as a run
// error, ARCH-001 §3 E1).
const (
	OutcomeSignal   = "signal"
	OutcomeNoSignal = "no_signal"
	OutcomeError    = "error"
)

// Fixture is the parsed reference document: the demo inventory plus the
// reference cases, both with their declared expectations. Load returns the
// singleton parsed from the embedded JSON.
type Fixture struct {
	Version    int       `json:"version"`
	ExternalID string    `json:"external_id"`
	Inventory  Inventory `json:"inventory"`
	Cases      []Case    `json:"cases"`
}

// Inventory is the demo inventory the fixture cases match against
// (ARCH-001 §3: seeded assets/components — acme/portal 2.4.4 in the
// critical/internet context of C1–C3, acme/api 1.0 in the normal/internal
// context of C4).
type Inventory struct {
	Assets []Asset `json:"assets"`
}

// Asset is one demo inventory asset (ARCH-001 §1 assets/components): the
// I1b seed fields plus the components the asset runs. Enum columns hold the
// domain enum values.
type Asset struct {
	ExternalID  string             `json:"external_id"`
	Type        domain.AssetType   `json:"type"`
	Name        string             `json:"name"`
	Environment domain.Environment `json:"environment"`
	Criticality domain.Criticality `json:"criticality"`
	Exposure    domain.Exposure    `json:"exposure"`
	Owner       string             `json:"owner"`
	Note        string             `json:"note"`
	Components  []Component        `json:"components"`
}

// Component is one seeded component of an asset (vendor/product/version
// only in I1b; CPE, purl and digests arrive with I3).
type Component struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Version string `json:"version"`
}

// Case is one reference case of the fixture (ARCH-001 §3 table): the run
// factors of the case plus the declared expected outcome. CVEID empty marks
// the malformed E1 case (outcome error). CVSS is a base score in [0,10],
// EPSS a probability/percentile in [0,1].
type Case struct {
	ID          string             `json:"id"`
	CVEID       string             `json:"cve_id"`
	Summary     string             `json:"summary"`
	Statement   string             `json:"statement"`
	Vendor      string             `json:"vendor"`
	Product     string             `json:"product"`
	Version     string             `json:"version"`
	CVSS        float64            `json:"cvss"`
	KEV         bool               `json:"kev"`
	EPSS        float64            `json:"epss"`
	Criticality domain.Criticality `json:"criticality"`
	Exposure    domain.Exposure    `json:"exposure"`
	Expect      Expectation        `json:"expect"`
}

// Expectation is the declared outcome of one case, used as the oracle of
// the fixture tests and as documentation of the ARCH-001 §3 annotations
// (including the reconciliations, see the note fields in reference.json).
type Expectation struct {
	// Outcome is one of OutcomeSignal, OutcomeNoSignal, OutcomeError.
	Outcome string `json:"outcome"`
	// Priority is the expected priority of the case (P1–P4). It is set for
	// signal cases (the produced signal's priority) and for no_signal
	// cases (the ch. 9.3 classification of the informational row, which
	// I1b does not materialise); empty for error cases.
	Priority domain.Priority `json:"priority"`
	// Note documents the expectation and any reconciliation against the
	// DEV-015 priority function (ch. 9.3).
	Note string `json:"note"`
}

// Load reads and validates the embedded reference document. The fixture is
// static, so a load error is a programming error (a broken fixture) that
// the demo CLI reports as a generic failure and the tests pin.
func Load() (*Fixture, error) {
	f, err := fixtureFS.Open("fixtures/reference.json")
	if err != nil {
		return nil, fmt.Errorf("synthetic: open embedded fixture: %w", err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields() // a typo in the fixture JSON is a bug, not data
	var fix Fixture
	if err := dec.Decode(&fix); err != nil {
		return nil, fmt.Errorf("synthetic: decode embedded fixture: %w", err)
	}
	if err := fix.validate(); err != nil {
		return nil, fmt.Errorf("synthetic: invalid embedded fixture: %w", err)
	}
	return &fix, nil
}

// validate checks the fixture invariants that the demo and the tests rely
// on: the document identity, the seed inventory and the per-case enum
// values and expectations. Errors name the offending case/asset.
func (f *Fixture) validate() error {
	if f.Version != 1 {
		return fmt.Errorf("unsupported fixture version %d", f.Version)
	}
	if f.ExternalID != ExternalID {
		return fmt.Errorf("external_id %q, want %q", f.ExternalID, ExternalID)
	}
	if len(f.Inventory.Assets) == 0 {
		return errors.New("inventory declares no assets")
	}
	seenAssets := make(map[string]bool, len(f.Inventory.Assets))
	for _, a := range f.Inventory.Assets {
		if a.ExternalID == "" {
			return errors.New("inventory asset without external_id")
		}
		if seenAssets[a.ExternalID] {
			return fmt.Errorf("duplicate inventory asset external_id %q", a.ExternalID)
		}
		seenAssets[a.ExternalID] = true
		if !a.Type.Valid() {
			return fmt.Errorf("asset %s: invalid type %q", a.ExternalID, a.Type)
		}
		if a.Name == "" {
			return fmt.Errorf("asset %s: empty name", a.ExternalID)
		}
		if !a.Environment.Valid() {
			return fmt.Errorf("asset %s: invalid environment %q", a.ExternalID, a.Environment)
		}
		if !a.Criticality.Valid() {
			return fmt.Errorf("asset %s: invalid criticality %q", a.ExternalID, a.Criticality)
		}
		if !a.Exposure.Valid() {
			return fmt.Errorf("asset %s: invalid exposure %q", a.ExternalID, a.Exposure)
		}
		if len(a.Components) == 0 {
			return fmt.Errorf("asset %s: no components", a.ExternalID)
		}
		for _, c := range a.Components {
			if c.Vendor == "" || c.Product == "" || c.Version == "" {
				return fmt.Errorf("asset %s: incomplete component %+v", a.ExternalID, c)
			}
		}
	}
	if len(f.Cases) == 0 {
		return errors.New("fixture declares no cases")
	}
	seenCases := make(map[string]bool, len(f.Cases))
	for i, c := range f.Cases {
		if c.ID == "" {
			return fmt.Errorf("case %d: no id", i)
		}
		if seenCases[c.ID] {
			return fmt.Errorf("duplicate case id %q", c.ID)
		}
		seenCases[c.ID] = true
		if c.Expect.Outcome == "" {
			return fmt.Errorf("case %s: no expected outcome", c.ID)
		}
		switch c.Expect.Outcome {
		case OutcomeSignal, OutcomeNoSignal:
			if c.CVEID == "" {
				return fmt.Errorf("case %s: outcome %s but no cve_id", c.ID, c.Expect.Outcome)
			}
			if !c.Expect.Priority.Valid() {
				return fmt.Errorf("case %s: invalid expected priority %q", c.ID, c.Expect.Priority)
			}
			if c.Criticality == "" || !c.Criticality.Valid() {
				return fmt.Errorf("case %s: invalid criticality %q", c.ID, c.Criticality)
			}
			if c.Exposure == "" || !c.Exposure.Valid() {
				return fmt.Errorf("case %s: invalid exposure %q", c.ID, c.Exposure)
			}
		case OutcomeError:
			if c.CVEID != "" {
				return fmt.Errorf("case %s: outcome error must have no cve_id", c.ID)
			}
		default:
			return fmt.Errorf("case %s: unknown outcome %q", c.ID, c.Expect.Outcome)
		}
		if c.Summary == "" {
			return fmt.Errorf("case %s: empty summary", c.ID)
		}
		if c.Vendor == "" || c.Product == "" {
			return fmt.Errorf("case %s: incomplete product", c.ID)
		}
		if c.CVSS < 0 || c.CVSS > 10 {
			return fmt.Errorf("case %s: cvss %v outside [0,10]", c.ID, c.CVSS)
		}
		if c.EPSS < 0 || c.EPSS > 1 {
			return fmt.Errorf("case %s: epss %v outside [0,1]", c.ID, c.EPSS)
		}
	}
	return nil
}

// RunCases maps the fixture cases onto the typed run input of the
// application use case (RunSyntheticSource), in document order (C1…C6, E1
// last). Load validated every enum, so the mapping is total.
func (f *Fixture) RunCases() []application.SyntheticCase {
	out := make([]application.SyntheticCase, 0, len(f.Cases))
	for _, c := range f.Cases {
		out = append(out, application.SyntheticCase{
			CVEID:     c.CVEID,
			Summary:   c.Summary,
			Statement: c.Statement,
			Product: application.Product{
				Vendor:  c.Vendor,
				Product: c.Product,
				Version: c.Version,
			},
			CVSS: c.CVSS,
			KEV:  c.KEV,
			EPSS: c.EPSS,
			Asset: application.SyntheticAsset{
				Criticality: c.Criticality,
				Exposure:    c.Exposure,
			},
		})
	}
	return out
}
