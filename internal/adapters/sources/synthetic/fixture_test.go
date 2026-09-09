package synthetic

// Unit tests of the embedded reference fixture (WP-1b.05 / DEV-019,
// ARCH-001 §3): the fixture loads and validates, its declared expectations
// cover the annotated matrix, and every fixture case maps to its expected
// priority through the ch. 9.3 priority function with the confidence the
// I1b matcher derives over the fixture's own inventory. These tests need no
// database.

import (
	"strings"
	"testing"

	"github.com/xpera/risksignal/internal/domain"
)

// fixtureCaseIDs is the expected stable case set in document order: the
// reference cases C1–C6 plus the malformed E1 case (ARCH-001 §3).
var fixtureCaseIDs = []string{"C1", "C2", "C3", "C4", "C5", "C6", "E1"}

// signalCaseIDs are the fixture cases that produce a confirmed match and a
// risk signal; noSignalCaseIDs are the informational cases without a
// confirmed inventory assignment (C5: affected version not deployed; C6:
// product not in inventory).
var (
	signalCaseIDs   = []string{"C1", "C2", "C3", "C4"}
	noSignalCaseIDs = []string{"C5", "C6"}
)

// TestLoadReferenceFixture verifies the document identity and the shape of
// the embedded fixture: the stable case set in document order with unique
// ids, the malformed E1 case last, and the inventory the cases match
// against.
func TestLoadReferenceFixture(t *testing.T) {
	fix, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if fix.Version != 1 {
		t.Errorf("version = %d, want 1", fix.Version)
	}
	if fix.ExternalID != ExternalID {
		t.Errorf("external_id = %q, want %q", fix.ExternalID, ExternalID)
	}

	// Inventory: one portal asset (critical + internet, acme/portal 2.4.4)
	// and one api asset (normal + internal, acme/api 1.0).
	if len(fix.Inventory.Assets) != 2 {
		t.Fatalf("assets = %d, want 2", len(fix.Inventory.Assets))
	}
	portal := fix.Inventory.Assets[0]
	if portal.ExternalID != "asset-portal" || portal.Criticality != domain.CriticalityCritical ||
		portal.Exposure != domain.ExposureInternet || len(portal.Components) != 1 ||
		portal.Components[0] != (Component{Vendor: "acme", Product: "portal", Version: "2.4.4"}) {
		t.Errorf("portal asset = %+v, want critical/internet acme/portal 2.4.4", portal)
	}
	api := fix.Inventory.Assets[1]
	if api.ExternalID != "asset-api" || api.Criticality != domain.CriticalityNormal ||
		api.Exposure != domain.ExposureInternal || len(api.Components) != 1 ||
		api.Components[0] != (Component{Vendor: "acme", Product: "api", Version: "1.0"}) {
		t.Errorf("api asset = %+v, want normal/internal acme/api 1.0", api)
	}

	// Cases: the stable set in order, unique ids, E1 malformed and last.
	if len(fix.Cases) != len(fixtureCaseIDs) {
		t.Fatalf("cases = %d, want %d", len(fix.Cases), len(fixtureCaseIDs))
	}
	seen := make(map[string]bool, len(fix.Cases))
	for i, c := range fix.Cases {
		if c.ID != fixtureCaseIDs[i] {
			t.Errorf("case %d id = %q, want %q (document order)", i, c.ID, fixtureCaseIDs[i])
		}
		if seen[c.ID] {
			t.Errorf("duplicate case id %q", c.ID)
		}
		seen[c.ID] = true
	}
	e1 := fix.Cases[len(fix.Cases)-1]
	if e1.ID != "E1" || e1.CVEID != "" || e1.Expect.Outcome != OutcomeError || e1.Expect.Priority != "" {
		t.Errorf("E1 case = %+v, want the malformed case (no cve_id, outcome error)", e1)
	}
	if len(fix.RunCases()) != len(fix.Cases) {
		t.Errorf("RunCases() = %d cases, want %d", len(fix.RunCases()), len(fix.Cases))
	}
}

// deriveFixtureMatch mirrors the I1b matcher of the application layer
// (application.affectedVersionMethod, ARCH-001 §3: an equal version is an
// exact_identifier match, a dotted-prefix containment a
// canonical_product_range match). The copy is test-local on purpose: the
// application owns the matcher (pinned by the DEV-018 run tests), and this
// copy only derives the confidence the fixture expectations are computed
// with — a drift between the two surfaces here as a wrong expected
// priority.
func deriveFixtureMatch(componentVersion, affected string) (domain.MatchMethod, bool) {
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

// firstFixtureMatch resolves whether the case would match a seeded
// inventory component (the run iterates the seeded components of the
// case's product in version order and matches every affected one; the
// fixture inventory holds one component per product, so the resolution is
// unambiguous) and returns the derived method. The method's confidence
// follows from the ADR-015 mapping (method.Confidence).
func firstFixtureMatch(fix *Fixture, c Case) (method domain.MatchMethod, ok bool) {
	for _, a := range fix.Inventory.Assets {
		for _, comp := range a.Components {
			if comp.Vendor != c.Vendor || comp.Product != c.Product {
				continue
			}
			m, affected := deriveFixtureMatch(comp.Version, c.Version)
			if !affected {
				continue
			}
			return m, true
		}
	}
	return "", false
}

// mustMatchConfidence returns the ADR-015 confidence of a derived match
// method. The I1b matcher emits only exact_identifier and
// canonical_product_range, both of which the mapping table always carries.
func mustMatchConfidence(t *testing.T, method domain.MatchMethod) domain.Confidence {
	t.Helper()
	conf, ok := method.Confidence()
	if !ok {
		t.Fatalf("derived method %q has no confidence in the ADR-015 mapping", method)
	}
	return conf
}

// fixtureFactors assembles the ch. 9.3 factors of a case with the given
// match-derived confidence — the exact factor set the CreateSignal command
// stores when the run matches the case (ARCH-001 §1 risk_signals.factors).
func fixtureFactors(c Case, method domain.MatchMethod, conf domain.Confidence) domain.PriorityFactors {
	return domain.PriorityFactors{
		Method:      method,
		Confidence:  conf,
		KEV:         c.KEV,
		CVSS:        c.CVSS,
		EPSS:        c.EPSS,
		Criticality: c.Criticality,
		Exposure:    c.Exposure,
	}
}

// TestFixtureCaseExpectedPriorities is the required fixture mapping test:
// every case of the embedded reference document maps to its expected
// priority. Signal cases (C1–C4) must hit the fixture inventory with the
// documented method and ComputePriority over their factors must yield the
// declared P-level; no_signal cases (C5, C6) must provably have no
// confirmed match and classify as P4 (ch. 9.3: no confirmed inventory
// assignment); the malformed E1 case is an error, not a signal.
func TestFixtureCaseExpectedPriorities(t *testing.T) {
	fix, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// The declared outcome matrix pins the spread: signals span P1–P3, the
	// informational cases classify as P4, the malformed case is an error.
	byID := make(map[string]Case, len(fix.Cases))
	gotSignals := map[domain.Priority]string{}
	for _, c := range fix.Cases {
		byID[c.ID] = c
	}
	for _, id := range signalCaseIDs {
		c := byID[id]
		if c.Expect.Outcome != OutcomeSignal {
			t.Errorf("case %s outcome = %s, want signal", id, c.Expect.Outcome)
		}
		gotSignals[c.Expect.Priority] = id
	}
	for _, want := range []domain.Priority{domain.PriorityP1, domain.PriorityP2, domain.PriorityP3} {
		if gotSignals[want] == "" {
			t.Errorf("no signal case expects priority %s, want the P1–P3 spread", want)
		}
	}
	for _, id := range noSignalCaseIDs {
		if byID[id].Expect.Outcome != OutcomeNoSignal || byID[id].Expect.Priority != domain.PriorityP4 {
			t.Errorf("case %s = outcome %s priority %s, want no_signal/P4", id, byID[id].Expect.Outcome, byID[id].Expect.Priority)
		}
	}

	for _, c := range fix.Cases {
		t.Run(c.ID, func(t *testing.T) {
			switch c.Expect.Outcome {
			case OutcomeSignal:
				method, ok := firstFixtureMatch(fix, c)
				if !ok {
					t.Fatalf("case %s declares a signal but matches no fixture component", c.ID)
				}
				conf := mustMatchConfidence(t, method)
				if got := domain.ComputePriority(fixtureFactors(c, method, conf)); got != c.Expect.Priority {
					t.Errorf("ComputePriority(%s, %s) = %s, want %s", method, conf, got, c.Expect.Priority)
				}
			case OutcomeNoSignal:
				if _, ok := firstFixtureMatch(fix, c); ok {
					t.Fatalf("case %s declares no signal but matches a fixture component", c.ID)
				}
				// No confirmed assignment ⇒ ch. 9.3 classifies the case as
				// P4 (none confidence; candidate/no_match never claim
				// confirmed impact). Validate accepts the no_match factor
				// shape (domain test TestPriorityFactorsValidate).
				class := domain.PriorityFactors{
					Method:      domain.MatchMethodNoMatch,
					Confidence:  domain.ConfidenceNone,
					KEV:         c.KEV,
					CVSS:        c.CVSS,
					EPSS:        c.EPSS,
					Criticality: c.Criticality,
					Exposure:    c.Exposure,
				}
				if got := domain.ComputePriority(class); got != c.Expect.Priority {
					t.Errorf("ComputePriority(no confirmed assignment) = %s, want %s", got, c.Expect.Priority)
				}
			case OutcomeError:
				if c.CVEID != "" {
					t.Fatalf("case %s is an error but carries cve_id %q", c.ID, c.CVEID)
				}
			default:
				t.Fatalf("case %s has unknown outcome %q", c.ID, c.Expect.Outcome)
			}
		})
	}
}

// TestFixtureSignalMethods pins the match method of every signal case: the
// portal cases (C1–C3) are canonical_product_range over acme/portal 2.4.4,
// the api case (C4) is exact_identifier on acme/api 1.0 — and therefore
// every confirmed signal is high confidence (the I1b matcher emits only
// high-confidence methods, ADR-015).
func TestFixtureSignalMethods(t *testing.T) {
	fix, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := map[string]domain.MatchMethod{
		"C1": domain.MatchMethodCanonicalProductRange,
		"C2": domain.MatchMethodCanonicalProductRange,
		"C3": domain.MatchMethodCanonicalProductRange,
		"C4": domain.MatchMethodExactIdentifier,
	}
	for _, c := range fix.Cases {
		if c.Expect.Outcome != OutcomeSignal {
			continue
		}
		method, ok := firstFixtureMatch(fix, c)
		if !ok {
			t.Fatalf("case %s matches no fixture component", c.ID)
		}
		conf := mustMatchConfidence(t, method)
		if method != want[c.ID] {
			t.Errorf("case %s method = %s, want %s", c.ID, method, want[c.ID])
		}
		if conf != domain.ConfidenceHigh {
			t.Errorf("case %s confidence = %s, want high (ADR-015)", c.ID, conf)
		}
	}
}
