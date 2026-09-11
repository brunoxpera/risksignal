package export

// I6 exit-criteria consolidation (ARCH-007 §1.3/§12, WP-6.12 / DEV-134): the
// AT-014 CSV/formula-injection neutralisation and the export writer contract
// as one `I6ExitCriteria`-named gate. Each subtest delegates to the landed
// fixture (WP-6.03 / DEV-113) — the proof itself is not re-implemented.

import "testing"

// TestI6ExitCriteriaAT014CSVNeutralisation is the AT-014 acceptance case: no
// dangerous cell prefix survives the CSV writer, the header is deterministic,
// the provenance is stamped and the JSON writer round-trips the same frozen
// field set.
func TestI6ExitCriteriaAT014CSVNeutralisation(t *testing.T) {
	t.Run("no dangerous prefix survives", func(t *testing.T) {
		TestAT014CSVNeutralisesDangerousPrefixes(t)
	})
	t.Run("header is deterministic", func(t *testing.T) {
		TestCSVHeaderIsDeterministic(t)
	})
	t.Run("provenance is stamped", func(t *testing.T) {
		TestCSVStampsProvenance(t)
	})
	t.Run("empty export renders the header only", func(t *testing.T) {
		TestCSVEmptyExport(t)
	})
	t.Run("json field set and order", func(t *testing.T) {
		TestWriteJSONFieldSetAndOrder(t)
	})
	t.Run("json round-trips", func(t *testing.T) {
		TestJSONRoundTrips(t)
	})
	t.Run("empty json export", func(t *testing.T) {
		TestJSONEmptyExport(t)
	})
	t.Run("writer dispatch by format", func(t *testing.T) {
		TestWriteDispatches(t)
	})
}
