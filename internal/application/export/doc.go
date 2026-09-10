// Package export materialises the I6 CSV/JSON export artifacts (ARCH-007
// §1.3, WP-6.03 / DEV-114).
//
// It owns the pure formatting half of the export pipeline: given a frozen
// generation stamp set (schema/rule version, creation instant) and the
// materialised signal rows, it renders the artifact a download streams. It
// adds no business logic — the filter predicate, the row scope and the
// generation stamps come from the use case and the worker job (WP-6.04/
// WP-6.06); this package only serialises.
//
// The two writers share one field set and one deterministic column order
// (the row struct is the single source of truth — the CSV writer reflects
// over it, the JSON writer marshals it):
//
//   - WriteCSV renders a plain CSV table and neutralises *every* cell — the
//     header row and each data row — through domain.NeutralizeCSVField
//     (ARCH-007 §1.3), so a user-controlled product/CVE/owner/free-text
//     value can never survive as a spreadsheet formula.
//   - WriteJSON renders the same field set with encoding/json, without
//     neutralisation: JSON is not a spreadsheet vector, so its escaping is
//     the only transformation (ARCH-007 §1.3).
//
// Both formats stamp schema_version and rule_version (plus the frozen
// created_at and the row count) so a downloaded artifact is self-describing.
// The package imports only the standard library and domain — never an
// adapter or a generated package (.go-arch-lint.yml, TR-001); it lives in
// the application layer because it formats materialised application rows and
// must stay importable without pulling in the domain's outward layers.
package export
