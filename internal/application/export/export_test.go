package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// expectedColumns is the frozen, deterministic column order and field set of
// an export artifact (both formats). It pins the public contract: a reordered
// or renamed row field breaks this test.
var expectedColumns = []string{
	"id", "cve_id", "priority", "status", "confidence", "method", "owner",
	"vendor", "product", "component_version", "asset_id", "asset_external_id",
	"asset_name", "asset_type", "asset_environment", "asset_criticality",
	"asset_exposure", "summary", "created_at", "due_at", "closed_at",
}

// dangerousPrefixes is the ARCH-007 §1.3 / AT-014 prefix set a materialised
// cell must never begin with.
const dangerousPrefixes = "=+-@\t\r"

// dangerousOrigins are the exact dangerous cell values of the AT-014
// reference fixture (ARCH-007 §1.3).
var dangerousOrigins = []string{
	"=cmd|' /C calc'!A0",
	"+1+1",
	"@SUM(1+9)",
	"-2+3",
	"\tleading tab summary",
	"\rleading CR vendor",
}

var fixtureCreatedAt = time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)

// at014Fixture is the ARCH-007 §1.3 / AT-014 reference signal set: rows whose
// user-controlled cells (cve, summary, product, owner, vendor) carry every
// dangerous spreadsheet prefix the neutraliser must defuse.
func at014Fixture() []Row {
	return []Row{
		{
			ID:               "11111111-1111-1111-1111-111111111111",
			CveID:            "=cmd|' /C calc'!A0",
			Priority:         "P1",
			Status:           "new",
			Confidence:       "high",
			Method:           "cpe",
			Owner:            "user-1",
			Vendor:           "acme",
			Product:          "widget",
			ComponentVersion: "1.2.3",
			AssetID:          "22222222-2222-2222-2222-222222222222",
			AssetExternalID:  "asset-1",
			AssetName:        "prod-web",
			AssetType:        "service",
			AssetEnvironment: "production",
			AssetCriticality: "high",
			AssetExposure:    "internet",
			Summary:          "+1+1",
			CreatedAt:        fixtureCreatedAt,
		},
		{
			ID:               "33333333-3333-3333-3333-333333333333",
			CveID:            "CVE-2021-44228",
			Priority:         "P2",
			Status:           "triaged",
			Confidence:       "medium",
			Method:           "purl",
			Owner:            "-2+3",
			Vendor:           "acme",
			Product:          "@SUM(1+9)",
			ComponentVersion: "2.0.0",
			AssetID:          "44444444-4444-4444-4444-444444444444",
			AssetExternalID:  "asset-2",
			AssetName:        "prod-db",
			AssetType:        "service",
			AssetEnvironment: "production",
			AssetCriticality: "critical",
			AssetExposure:    "internal",
			Summary:          "\tleading tab summary",
			CreatedAt:        fixtureCreatedAt.Add(time.Hour),
		},
		{
			ID:               "55555555-5555-5555-5555-555555555555",
			CveID:            "CVE-2023-0001",
			Priority:         "P3",
			Status:           "closed",
			Confidence:       "low",
			Method:           "vendor_product",
			Owner:            "",
			Vendor:           "\rleading CR vendor",
			Product:          "widget",
			ComponentVersion: "3.1.0",
			AssetID:          "66666666-6666-6666-6666-666666666666",
			AssetExternalID:  "asset-3",
			AssetName:        "dev-box",
			AssetType:        "host",
			AssetEnvironment: "development",
			AssetCriticality: "low",
			AssetExposure:    "internal",
			Summary:          "safe summary",
			CreatedAt:        fixtureCreatedAt.Add(2 * time.Hour),
			ClosedAt:         timePtr(fixtureCreatedAt.Add(48 * time.Hour)),
		},
	}
}

func timePtr(t time.Time) *time.Time { return &t }

// TestAT014CSVNeutralisesDangerousPrefixes is the ARCH-007 §1.3 reference
// fixture assertion for AT-014: every dangerous cell of the exported CSV is
// prefixed and no cell of the artifact begins with a dangerous rune.
func TestAT014CSVNeutralisesDangerousPrefixes(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, Document{RuleVersion: "a1d1", CreatedAt: fixtureCreatedAt, Rows: at014Fixture()}); err != nil {
		t.Fatalf("WriteCSV: unexpected error: %v", err)
	}
	records := parseCSV(t, buf.String())
	if len(records) != 1+len(at014Fixture()) { // header + data rows
		t.Fatalf("got %d CSV records, want header + %d data rows", len(records), len(at014Fixture()))
	}

	// No cell — header or data, at any column — may begin with a dangerous
	// rune once written.
	for r, rec := range records {
		for c, cell := range rec {
			if hasDangerousPrefix(cell) {
				t.Errorf("record %d column %d = %q begins with a dangerous prefix", r, c, cell)
			}
		}
	}

	// Every dangerous original is present, but only in its neutralised form.
	fields := allFields(records)
	for _, origin := range dangerousOrigins {
		if containsString(fields, origin) {
			t.Errorf("a cell %q survived un-neutralised", origin)
		}
		if !containsString(fields, "'"+origin) {
			t.Errorf("no cell carries the neutralised %q", "'"+origin)
		}
	}
}

// TestCSVHeaderIsDeterministic pins the column order and field set and
// asserts the header is neutralised like every other cell.
func TestCSVHeaderIsDeterministic(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, Document{RuleVersion: "a1d1", CreatedAt: fixtureCreatedAt, Rows: at014Fixture()}); err != nil {
		t.Fatalf("WriteCSV: unexpected error: %v", err)
	}
	records := parseCSV(t, buf.String())
	if got := records[0]; !equalStrings(got, expectedColumns) {
		t.Errorf("CSV header = %v, want %v", got, expectedColumns)
	}
}

// TestCSVStampsProvenance asserts the schema/rule version and the frozen
// creation instant are stamped into the artifact.
func TestCSVStampsProvenance(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, Document{RuleVersion: "a1d1", CreatedAt: fixtureCreatedAt, Rows: at014Fixture()}); err != nil {
		t.Fatalf("WriteCSV: unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"# schema_version=" + SchemaVersion,
		"# rule_version=a1d1",
		"# created_at=" + formatTime(fixtureCreatedAt),
		"# row_count=3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("CSV artifact misses %q\n%s", want, out)
		}
	}
}

// TestCSVEmptyExport writes the header only and stamps row_count=0.
func TestCSVEmptyExport(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, Document{RuleVersion: "a1d1", CreatedAt: fixtureCreatedAt}); err != nil {
		t.Fatalf("WriteCSV: unexpected error: %v", err)
	}
	records := parseCSV(t, buf.String())
	if len(records) != 1 {
		t.Fatalf("got %d CSV records, want only the header", len(records))
	}
	if !strings.Contains(buf.String(), "# row_count=0") {
		t.Errorf("missing row_count=0 stamp:\n%s", buf.String())
	}
}

// TestWriteJSONFieldSetAndOrder asserts the JSON artifact carries the same
// field set and deterministic column order as the CSV artifact, and that the
// dangerous values are NOT neutralised (JSON is not a spreadsheet vector).
func TestWriteJSONFieldSetAndOrder(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, Document{RuleVersion: "a1d1", CreatedAt: fixtureCreatedAt, Rows: at014Fixture()}); err != nil {
		t.Fatalf("WriteJSON: unexpected error: %v", err)
	}
	keys := jsonObjectKeyOrder(t, buf.Bytes(), "rows", 0)
	if !equalStrings(keys, expectedColumns) {
		t.Errorf("JSON row keys = %v, want %v", keys, expectedColumns)
	}

	var doc jsonDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("JSON artifact does not unmarshal: %v", err)
	}
	if doc.SchemaVersion != SchemaVersion || doc.RuleVersion != "a1d1" || doc.RowCount != 3 {
		t.Errorf("JSON stamps = %+v, want schema=%s rule=a1d1 rows=3", doc, SchemaVersion)
	}
	// No neutralisation: the dangerous values are carried verbatim.
	if doc.Rows[0].CveID != "=cmd|' /C calc'!A0" {
		t.Errorf("JSON cve_id = %q, want the verbatim dangerous value (no neutralisation)", doc.Rows[0].CveID)
	}
	if doc.Rows[0].Summary != "+1+1" {
		t.Errorf("JSON summary = %q, want the verbatim dangerous value", doc.Rows[0].Summary)
	}
}

// TestJSONRoundTrips proves the artifact is stable: decode → re-encode yields
// the identical bytes (deterministic marshalling, no lossy fields).
func TestJSONRoundTrips(t *testing.T) {
	var first bytes.Buffer
	if err := WriteJSON(&first, Document{RuleVersion: "a1d1", CreatedAt: fixtureCreatedAt, Rows: at014Fixture()}); err != nil {
		t.Fatalf("WriteJSON: unexpected error: %v", err)
	}
	var doc jsonDocument
	if err := json.Unmarshal(first.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	reencoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(reencoded), bytes.TrimSpace(first.Bytes())) {
		t.Errorf("JSON round-trip diverged:\n first: %s\n again: %s", first.Bytes(), reencoded)
	}
}

// TestJSONEmptyExport marshals rows as [] rather than null.
func TestJSONEmptyExport(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, Document{RuleVersion: "a1d1", CreatedAt: fixtureCreatedAt}); err != nil {
		t.Fatalf("WriteJSON: unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), `"rows":[]`) {
		t.Errorf("empty JSON export = %s, want rows:[]", buf.String())
	}
}

// TestWriteDispatches asserts the format dispatcher and its rejection of an
// unknown format.
func TestWriteDispatches(t *testing.T) {
	for _, f := range []Format{FormatCSV, FormatJSON} {
		var buf bytes.Buffer
		if err := Write(&buf, f, Document{RuleVersion: "a1d1", CreatedAt: fixtureCreatedAt, Rows: at014Fixture()}); err != nil {
			t.Errorf("Write(%q): unexpected error: %v", f, err)
		}
		if buf.Len() == 0 {
			t.Errorf("Write(%q) produced nothing", f)
		}
	}
	if err := Write(&bytes.Buffer{}, Format("xml"), Document{}); err == nil {
		t.Errorf("Write(xml): want error, got nil")
	}
}

// parseCSV parses a CSV artifact, skipping the "# "-prefixed provenance
// header lines (the convention documented on WriteCSV).
func parseCSV(t *testing.T, out string) [][]string {
	t.Helper()
	r := csv.NewReader(strings.NewReader(out))
	r.Comment = '#'
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("CSV artifact does not parse: %v\n%s", err, out)
	}
	return records
}

// hasDangerousPrefix reports whether a cell begins with a dangerous
// spreadsheet prefix.
func hasDangerousPrefix(s string) bool {
	if s == "" {
		return false
	}
	r, _ := utf8.DecodeRuneInString(s)
	return strings.ContainsRune(dangerousPrefixes, r)
}

// allFields flattens every cell of every record.
func allFields(records [][]string) []string {
	var out []string
	for _, rec := range records {
		out = append(out, rec...)
	}
	return out
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// jsonObjectKeyOrder returns the key order of the n-th element of a top-level
// JSON array field of the document, decoded from the raw bytes — an
// independent check of the marshalled order.
func jsonObjectKeyOrder(t *testing.T, data []byte, arrayField string, n int) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		t.Fatalf("expected a JSON object, got %v (err %v)", tok, err)
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		key, _ := keyTok.(string)
		if key != arrayField {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				t.Fatalf("skip %q: %v", key, err)
			}
			continue
		}
		// Descend into the array and pick the n-th object.
		arrTok, err := dec.Token()
		if err != nil || arrTok != json.Delim('[') {
			t.Fatalf("expected array for %q, got %v (err %v)", arrayField, arrTok, err)
		}
		for i := 0; dec.More(); i++ {
			if i == n {
				objTok, err := dec.Token()
				if err != nil || objTok != json.Delim('{') {
					t.Fatalf("expected object, got %v (err %v)", objTok, err)
				}
				var keys []string
				for dec.More() {
					k, err := dec.Token()
					if err != nil {
						t.Fatalf("key token: %v", err)
					}
					keys = append(keys, k.(string))
					var skip json.RawMessage
					if err := dec.Decode(&skip); err != nil {
						t.Fatalf("skip value: %v", err)
					}
				}
				return keys
			}
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				t.Fatalf("skip element: %v", err)
			}
		}
		t.Fatalf("array %q has no element %d", arrayField, n)
	}
	t.Fatalf("field %q not found", arrayField)
	return nil
}
