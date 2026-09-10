package application

// Table tests of the WP-3.05 inventory CSV parser and the validate use
// case (DEV-059, ARCH-003 §1.3): header variants, malformed rows with
// exact line/column positions, enum errors via the domain parsers,
// identifier syntax errors via the DEV-047 parsers, intra-file conflicts
// (asset-field divergence, natural-key duplicates and divergence) and the
// row/error counts of validate. Every case asserts the full problem list
// (line, column, reason, input) so a regression in positioning — the
// acceptance criterion — fails loudly.

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// inventoryCSV joins the canonical header with the given data rows.
func inventoryCSV(rows ...string) string {
	return strings.Join(append([]string{strings.Join(inventoryHeaderColumns, ",")}, rows...), "\n") + "\n"
}

// inventoryHeaderCSV builds a header from a column list in the given order.
func inventoryHeaderCSV(columns []string, rows ...string) string {
	return strings.Join(append([]string{strings.Join(columns, ",")}, rows...), "\n") + "\n"
}

// inventoryRow renders one data row from its 15 canonical-order fields.
func inventoryRow(f ...string) string {
	if len(f) != len(inventoryHeaderColumns) {
		panic(fmt.Sprintf("inventoryRow: got %d fields, want %d", len(f), len(inventoryHeaderColumns)))
	}
	return strings.Join(f, ",")
}

// digest64 is a syntactically valid sha256 digest for tests.
func digest64() string { return "sha256:" + strings.Repeat("ab", 32) }

// cpe23 is a syntactically valid CPE 2.3 formatted string for tests.
func cpe23() string { return "cpe:2.3:a:acme:portal:1.0.0:*:*:*:*:*:*:*" }

func formatProblems(ps []InventoryProblem) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.String()
	}
	return strings.Join(parts, " | ")
}

// wantProblems asserts the exact positioned problem list of a parse.
func wantProblems(t *testing.T, got []InventoryProblem, want ...InventoryProblem) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("problems: got %d\n  %s\nwant %d\n  %s",
			len(got), formatProblems(got), len(want), formatProblems(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("problem %d: got %v, want %v", i, got[i], want[i])
		}
	}
}

func problem(line int, column, reason, input string) InventoryProblem {
	return InventoryProblem{Line: line, Column: column, Reason: reason, Input: input}
}

func TestParseInventoryCSVHeaderVariants(t *testing.T) {
	t.Run("canonical order", func(t *testing.T) {
		file, err := ParseInventoryCSV(strings.NewReader(inventoryCSV(
			inventoryRow("cmdb", "host-1", "server_vm", "web-1", "production", "high", "internet", "", "acme", "portal", "1.0.0", "", "", "", ""),
		)))
		if err != nil {
			t.Fatal(err)
		}
		if file.Rows != 1 || len(file.Problems) != 0 {
			t.Fatalf("rows=%d problems=%v", file.Rows, file.Problems)
		}
		if len(file.Assets) != 1 {
			t.Fatalf("assets=%d, want 1", len(file.Assets))
		}
		a := file.Assets[0]
		if a.Source != "cmdb" || a.ExternalID != "host-1" || a.Name != "web-1" {
			t.Errorf("asset identity: %+v", a)
		}
		if a.Type != domain.AssetTypeServerVM || a.Environment != domain.EnvironmentProduction ||
			a.Criticality != domain.CriticalityHigh || a.Exposure != domain.ExposureInternet {
			t.Errorf("asset vocab: %+v", a)
		}
		if len(a.Components) != 1 {
			t.Fatalf("components=%d, want 1", len(a.Components))
		}
		c := a.Components[0]
		if c.IDs.Vendor != "acme" || c.IDs.Product != "portal" || c.IDs.Version != "1.0.0" {
			t.Errorf("component ids: %+v", c.IDs)
		}
		if c.Scheme != domain.VersionSchemeGeneric {
			t.Errorf("scheme=%s, want generic (plain 1.0.0 version shape)", c.Scheme)
		}
		if c.NaturalKey == "" || c.VendorNorm != "acme" || c.ProductNorm != "portal" {
			t.Errorf("derived keys: norm=(%q,%q) key=%q", c.VendorNorm, c.ProductNorm, c.NaturalKey)
		}
		if len(a.Lines) != 1 || a.Lines[0] != 2 {
			t.Errorf("lines=%v, want [2]", a.Lines)
		}
	})

	t.Run("order insensitive and BOM tolerant", func(t *testing.T) {
		// A shuffled column order plus a UTF-8 BOM before the first name.
		columns := []string{"digest", "name", "owner", "product", "cpe", "type", "purl",
			"source", "version", "environment", "external_id", "vendor", "criticality", "exposure", "image"}
		fields := map[string]string{
			"digest": digest64(), "name": "img-2", "owner": "", "product": "nginx", "cpe": "",
			"type": "container_image", "purl": "", "source": "cmdb", "version": "",
			"environment": "production", "external_id": "img-2", "vendor": "",
			"criticality": "high", "exposure": "internal", "image": "registry/x/nginx",
		}
		ordered := make([]string, len(columns))
		for i, name := range columns {
			ordered[i] = fields[name]
		}
		csv := "\ufeff" + inventoryHeaderCSV(columns, strings.Join(ordered, ","))
		file, err := ParseInventoryCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatal(err)
		}
		if len(file.Problems) != 0 {
			t.Fatalf("problems: %s", formatProblems(file.Problems))
		}
		if len(file.Assets) != 1 || len(file.Assets[0].Components) != 1 {
			t.Fatalf("assets/components: %+v", file.Assets)
		}
		a := file.Assets[0]
		if a.Source != "cmdb" || a.ExternalID != "img-2" {
			t.Errorf("asset identity: source=%q external=%q", a.Source, a.ExternalID)
		}
		if a.Type != domain.AssetTypeContainerImage || a.Name != "img-2" ||
			a.Criticality != domain.CriticalityHigh || a.Exposure != domain.ExposureInternal {
			t.Errorf("asset: %+v", a)
		}
		// digest is the strongest identifier; the image stays raw.
		c := a.Components[0]
		if c.IDs.Image != "registry/x/nginx" {
			t.Errorf("image raw: %q", c.IDs.Image)
		}
		if c.Scheme != domain.VersionSchemeUnknown {
			t.Errorf("scheme=%s want unknown (no version, no purl/cpe hint)", c.Scheme)
		}
	})

	t.Run("header only is a valid empty import", func(t *testing.T) {
		file, err := ParseInventoryCSV(strings.NewReader(inventoryCSV()))
		if err != nil {
			t.Fatal(err)
		}
		if file.Rows != 0 || len(file.Problems) != 0 || len(file.Assets) != 0 {
			t.Errorf("empty import: rows=%d problems=%v", file.Rows, file.Problems)
		}
	})

	t.Run("empty file", func(t *testing.T) {
		file, err := ParseInventoryCSV(strings.NewReader(""))
		if err != nil {
			t.Fatal(err)
		}
		wantProblems(t, file.Problems, problem(1, "", "file is empty — the header row (line 1) is missing", ""))
	})

	t.Run("missing column", func(t *testing.T) {
		columns := append([]string{}, inventoryHeaderColumns...)
		columns = columns[:len(columns)-1] // digest dropped
		file, err := ParseInventoryCSV(strings.NewReader(inventoryHeaderCSV(columns)))
		if err != nil {
			t.Fatal(err)
		}
		if file.Rows != 0 {
			t.Errorf("rows=%d, want 0 (no parse without a valid header)", file.Rows)
		}
		wantProblems(t, file.Problems, problem(1, "digest", "header is missing the column digest", ""))
	})

	t.Run("unknown column", func(t *testing.T) {
		columns := append([]string{}, inventoryHeaderColumns...)
		columns = append(columns, "bogus")
		file, err := ParseInventoryCSV(strings.NewReader(inventoryHeaderCSV(columns)))
		if err != nil {
			t.Fatal(err)
		}
		wantProblems(t, file.Problems, problem(1, "bogus", "unknown column bogus", ""))
	})

	t.Run("duplicate column name", func(t *testing.T) {
		columns := append([]string{}, inventoryHeaderColumns...)
		columns = append(columns, "cpe")
		file, err := ParseInventoryCSV(strings.NewReader(inventoryHeaderCSV(columns)))
		if err != nil {
			t.Fatal(err)
		}
		wantProblems(t, file.Problems, problem(1, "cpe", "header repeats the column cpe", ""))
	})

	t.Run("header names are case sensitive", func(t *testing.T) {
		columns := append([]string{}, inventoryHeaderColumns...)
		columns[0] = "Source"
		csv := inventoryHeaderCSV(columns)
		file, err := ParseInventoryCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, p := range file.Problems {
			got[p.Column] = true
		}
		for _, want := range []string{"source", "Source"} {
			if !got[want] {
				t.Errorf("missing problem for column %q: %s", want, formatProblems(file.Problems))
			}
		}
	})

	t.Run("malformed quoted record is positioned and does not abort", func(t *testing.T) {
		good := inventoryRow("cmdb", "a1", "server_vm", "n1", "production", "high", "internet", "", "acme", "p2", "1.0.0", "", "", "", "")
		// The unterminated quote on line 3 makes the record structurally
		// unreadable: it is reported positioned, is not counted as a row
		// and does not abort the parse of the earlier row.
		csv := inventoryCSV(good, `cmdb,a1,server_vm,n1,production,high,internet,,acme,p1,,"unterminated`)
		file, err := ParseInventoryCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatal(err)
		}
		if len(file.Problems) != 1 || file.Problems[0].Line != 3 {
			t.Fatalf("problems: %s", formatProblems(file.Problems))
		}
		if !strings.Contains(file.Problems[0].Reason, "malformed CSV record") {
			t.Errorf("reason: %q", file.Problems[0].Reason)
		}
		if file.Rows != 1 || len(file.Assets) != 1 || len(file.Assets[0].Components) != 1 {
			t.Errorf("rows=%d assets=%d", file.Rows, len(file.Assets))
		}
	})

	t.Run("multiline quoted field counts its record start line", func(t *testing.T) {
		// A quoted vendor cell spanning two physical lines: the record
		// starts on line 2 and every position inside it must report 2.
		quotedVendor := "\"multi\nline\""
		row := inventoryRow("cmdb", "a1", "server_vm", "n1", "production", "high", "internet", "", quotedVendor, "p1", "1.0.0", "", "", "", "")
		file, err := ParseInventoryCSV(strings.NewReader(inventoryCSV(row)))
		if err != nil {
			t.Fatal(err)
		}
		if len(file.Problems) != 0 {
			t.Fatalf("problems: %s", formatProblems(file.Problems))
		}
		if len(file.Assets) != 1 {
			t.Fatalf("assets=%d", len(file.Assets))
		}
		if got := file.Assets[0].Components[0].Line; got != 2 {
			t.Errorf("component line=%d, want 2 (record start)", got)
		}
	})
}

func TestParseInventoryCSVGroupingAndConflicts(t *testing.T) {
	row := func(source, external, version string) string {
		return inventoryRow(source, external, "server_vm", "n1", "production", "high", "internet", "", "acme", "p1", version, "", "", "", "")
	}
	t.Run("grouping by source and external id", func(t *testing.T) {
		file, err := ParseInventoryCSV(strings.NewReader(inventoryCSV(
			row("cmdb", "a1", "1.0.0"),
			inventoryRow("cmdb", "a1", "server_vm", "n1", "production", "high", "internet", "", "acme", "p2", "2.0.0", "", "", "", ""),
			row("cmdb", "a2", "1.0.0"),
			row("other", "a1", "1.0.0"),
		)))
		if err != nil {
			t.Fatal(err)
		}
		if len(file.Problems) != 0 {
			t.Fatalf("problems: %s", formatProblems(file.Problems))
		}
		if len(file.Assets) != 3 {
			t.Fatalf("assets=%d, want 3 ((cmdb,a1),(cmdb,a2),(other,a1))", len(file.Assets))
		}
		if got := len(file.Assets[0].Components); got != 2 {
			t.Errorf("(cmdb,a1) components=%d, want 2", got)
		}
		if got := len(file.Assets[1].Components); got != 1 {
			t.Errorf("(cmdb,a2) components=%d, want 1", got)
		}
		if got := len(file.Assets[2].Components); got != 1 {
			t.Errorf("(other,a1) components=%d, want 1", got)
		}
		if file.Rows != 4 {
			t.Errorf("rows=%d, want 4", file.Rows)
		}
	})

	t.Run("asset field divergence excludes the divergent row", func(t *testing.T) {
		file, err := ParseInventoryCSV(strings.NewReader(inventoryCSV(
			row("cmdb", "a1", "1.0.0"),
			inventoryRow("cmdb", "a1", "server_vm", "n1", "production", "low", "internet", "", "acme", "p2", "2.0.0", "", "", "", ""), // criticality diverges
			inventoryRow("cmdb", "a1", "server_vm", "n1", "production", "high", "internet", "", "acme", "p3", "3.0.0", "", "", "", ""),
		)))
		if err != nil {
			t.Fatal(err)
		}
		if len(file.Assets) != 1 {
			t.Fatalf("assets=%d, want 1", len(file.Assets))
		}
		asset := file.Assets[0]
		if asset.Criticality != domain.CriticalityHigh {
			t.Errorf("asset criticality=%s, want high (first row authoritative)", asset.Criticality)
		}
		if len(asset.Components) != 2 {
			t.Fatalf("components=%d, want 2 (divergent row excluded)", len(asset.Components))
		}
		if got := asset.Components[1].IDs.Version; got != "3.0.0" {
			t.Errorf("second component version=%q", got)
		}
		wantProblems(t, file.Problems,
			problem(3, "criticality", `asset column criticality ("low") conflicts with the row on line 2 ("high"); all rows of one asset must agree`, "low"),
		)
	})

	t.Run("natural key duplicate excludes the later row", func(t *testing.T) {
		file, err := ParseInventoryCSV(strings.NewReader(inventoryCSV(
			row("cmdb", "a1", "1.0.0"),
			row("cmdb", "a1", "1.0.0"), // identical component row
		)))
		if err != nil {
			t.Fatal(err)
		}
		if len(file.Assets[0].Components) != 1 {
			t.Fatalf("components=%d, want 1 (duplicate excluded)", len(file.Assets[0].Components))
		}
		wantProblems(t, file.Problems,
			problem(3, "", "duplicate of the component on line 2 (same natural key)", ""),
		)
	})

	t.Run("same natural key with divergent fields conflicts", func(t *testing.T) {
		// Identical cpe on both rows: identical natural key; the version
		// cells diverge, so the rows conflict (a commit would silently
		// overwrite the first row's version with the second's).
		cpe := cpe23()
		file, err := ParseInventoryCSV(strings.NewReader(inventoryCSV(
			inventoryRow("cmdb", "a1", "server_vm", "n1", "production", "high", "internet", "", "", "", "1.0.0", cpe, "", "", ""),
			inventoryRow("cmdb", "a1", "server_vm", "n1", "production", "high", "internet", "", "", "", "2.0.0", cpe, "", "", ""),
		)))
		if err != nil {
			t.Fatal(err)
		}
		if len(file.Assets[0].Components) != 1 {
			t.Fatalf("components=%d, want 1 (conflicting row excluded)", len(file.Assets[0].Components))
		}
		wantProblems(t, file.Problems,
			problem(3, "cpe", "component natural key conflicts with the component on line 2 (same natural key, divergent fields)", ""),
		)
	})

	t.Run("cells are trimmed", func(t *testing.T) {
		row := inventoryRow(" cmdb ", " a1 ", " server_vm ", " n1 ", " production ", " high ", " internet ", "", " acme ", " p1 ", " 1.0.0 ", "", "", "", "")
		csv := "source, external_id , type , name , environment , criticality , exposure , owner , vendor , product , version , cpe , purl , image , digest \n" + row + "\n"
		file, err := ParseInventoryCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatal(err)
		}
		if len(file.Problems) != 0 {
			t.Fatalf("problems: %s", formatProblems(file.Problems))
		}
		a := file.Assets[0]
		if a.Source != "cmdb" || a.Name != "n1" || a.Components[0].IDs.Vendor != "acme" {
			t.Errorf("trim failed: %+v %+v", a, a.Components[0].IDs)
		}
	})
}

func TestParseInventoryCSVRowErrors(t *testing.T) {
	t.Run("wrong field count", func(t *testing.T) {
		file, err := ParseInventoryCSV(strings.NewReader(inventoryCSV(
			"cmdb,a1,server_vm,n1,production,high,internet,,acme,p1\n", // 10 fields
		)))
		if err != nil {
			t.Fatal(err)
		}
		if file.Rows != 1 || len(file.Assets) != 0 {
			t.Fatalf("rows=%d assets=%d", file.Rows, len(file.Assets))
		}
		wantProblems(t, file.Problems,
			problem(2, "", "expected 15 fields (source, external_id, type, name, environment, criticality, exposure, owner, vendor, product, version, cpe, purl, image, digest), got 10", ""),
		)
	})

	t.Run("required asset cells empty", func(t *testing.T) {
		file, err := ParseInventoryCSV(strings.NewReader(inventoryCSV(
			inventoryRow("cmdb", "", "server_vm", "n1", "", "high", "internet", "", "acme", "p1", "1.0.0", "", "", "", ""), // external_id + environment empty
		)))
		if err != nil {
			t.Fatal(err)
		}
		wantProblems(t, file.Problems,
			problem(2, "external_id", "required asset column is empty", ""),
			problem(2, "environment", "required asset column is empty", ""),
		)
	})

	t.Run("enum errors positioned by column", func(t *testing.T) {
		file, err := ParseInventoryCSV(strings.NewReader(inventoryCSV(
			inventoryRow("cmdb", "a1", "car", "n1", "prod", "hig", "internet", "", "acme", "p1", "1.0.0", "", "", "", ""), // type/environment/criticality invalid
		)))
		if err != nil {
			t.Fatal(err)
		}
		if len(file.Assets) != 0 {
			t.Fatalf("assets=%d, want 0", len(file.Assets))
		}
		// Sorted by column order: type (2) < environment (4) < criticality (5).
		wantProblems(t, file.Problems,
			problem(2, "type", `invalid AssetType "car"`, "car"),
			problem(2, "environment", `invalid Environment "prod"`, "prod"),
			problem(2, "criticality", `invalid Criticality "hig"`, "hig"),
		)
	})

	t.Run("unknown criticality and exposure are valid values", func(t *testing.T) {
		file, err := ParseInventoryCSV(strings.NewReader(inventoryCSV(
			inventoryRow("cmdb", "a1", "server_vm", "n1", "production", "unknown", "unknown", "", "acme", "p1", "1.0.0", "", "", "", ""),
		)))
		if err != nil {
			t.Fatal(err)
		}
		if len(file.Problems) != 0 {
			t.Fatalf("problems: %s", formatProblems(file.Problems))
		}
		if file.Assets[0].Criticality != domain.CriticalityUnknown || file.Assets[0].Exposure != domain.ExposureUnknown {
			t.Errorf("asset: %+v", file.Assets[0])
		}
		if len(file.Warnings) != 2 {
			t.Fatalf("warnings=%d, want 2", len(file.Warnings))
		}
		if w := file.Warnings[0]; w.Field != "criticality" || w.Line != 2 {
			t.Errorf("warning 0: %+v", w)
		}
	})

	t.Run("identifier syntax errors", func(t *testing.T) {
		// vendor/product empty: the identity must come from an
		// identifier, and every identifier column fails its syntax check.
		badCPE := "cpe:2.3:x:acme:p1:1.0:*:*:*:*:*:*:*"
		badPURL := "pkg:npm/@acme/"
		badImage := "registry/NGINX:tag"
		badDigest := "sha256:XYZ"
		file, err := ParseInventoryCSV(strings.NewReader(inventoryCSV(
			inventoryRow("cmdb", "a1", "container_image", "n1", "production", "high", "internet", "", "", "", "", badCPE, badPURL, badImage, badDigest),
		)))
		if err != nil {
			t.Fatal(err)
		}
		if len(file.Assets) != 0 {
			t.Fatalf("assets=%d, want 0", len(file.Assets))
		}
		wantProblems(t, file.Problems,
			problem(2, "cpe", `part must be "a", "h" or "o"`, badCPE),
			problem(2, "purl", "name must not be empty", badPURL),
			problem(2, "image", `repository components must be lowercase letters/digits separated by '.', '_', '-' or '/' (component "NGINX" is malformed)`, badImage),
			problem(2, "digest", "digest must be \"algorithm:lowercase-hex\" with at least 32 hex digits (e.g. sha256:...)", badDigest),
		)
	})

	t.Run("no component identity", func(t *testing.T) {
		file, err := ParseInventoryCSV(strings.NewReader(inventoryCSV(
			inventoryRow("cmdb", "a1", "server_vm", "n1", "production", "high", "internet", "", "acme", "", "1.0.0", "", "", "", ""), // product empty, no identifier
			inventoryRow("cmdb", "a2", "server_vm", "n2", "production", "high", "internet", "", "", "", "", "", "", "", ""),          // nothing at all
		)))
		if err != nil {
			t.Fatal(err)
		}
		if len(file.Assets) != 0 {
			t.Fatalf("assets=%d, want 0", len(file.Assets))
		}
		wantProblems(t, file.Problems,
			problem(2, "", "row carries no component identity: vendor and product are required unless cpe, purl, digest or image is present", ""),
			problem(3, "", "row carries no component identity: vendor and product are required unless cpe, purl, digest or image is present", ""),
		)
	})

	t.Run("cell length cap", func(t *testing.T) {
		long := strings.Repeat("x", inventoryMaxCellBytes+1)
		file, err := ParseInventoryCSV(strings.NewReader(inventoryCSV(
			inventoryRow("cmdb", "a1", "server_vm", long, "production", "high", "internet", "", "acme", "p1", "1.0.0", "", "", "", ""),
		)))
		if err != nil {
			t.Fatal(err)
		}
		wantProblems(t, file.Problems,
			problem(2, "name", fmt.Sprintf("cell exceeds the %d-byte limit", inventoryMaxCellBytes), long),
		)
	})

	t.Run("empty lines between rows are skipped", func(t *testing.T) {
		csv := inventoryCSV(
			inventoryRow("cmdb", "a1", "server_vm", "n1", "production", "high", "internet", "", "acme", "p1", "1.0.0", "", "", "", ""),
			"",
			inventoryRow("cmdb", "a2", "server_vm", "n2", "production", "high", "internet", "", "acme", "p2", "1.0.0", "", "", "", ""),
		)
		file, err := ParseInventoryCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatal(err)
		}
		if len(file.Problems) != 0 {
			t.Fatalf("problems: %s", formatProblems(file.Problems))
		}
		if file.Rows != 2 || len(file.Assets) != 2 {
			t.Errorf("rows=%d assets=%d", file.Rows, len(file.Assets))
		}
	})
}

func TestParseInventoryCSVNaturalKeyPriority(t *testing.T) {
	t.Run("cpe outranks vendor product version", func(t *testing.T) {
		file, err := ParseInventoryCSV(strings.NewReader(inventoryCSV(
			inventoryRow("cmdb", "a1", "server_vm", "n1", "production", "high", "internet", "", "acme", "p1", "1.0.0", "", "", "", ""),
			inventoryRow("cmdb", "a2", "server_vm", "n2", "production", "high", "internet", "", "acme", "p1", "1.0.0", cpe23(), "", "", ""),
		)))
		if err != nil {
			t.Fatal(err)
		}
		if len(file.Problems) != 0 {
			t.Fatalf("problems: %s", formatProblems(file.Problems))
		}
		keyVPP := file.Assets[0].Components[0].NaturalKey
		keyCPE := file.Assets[1].Components[0].NaturalKey
		if keyVPP == keyCPE {
			t.Fatal("vendor/product key must differ from the cpe key of the same product")
		}
	})

	t.Run("digest outranks image", func(t *testing.T) {
		digest := digest64()
		file, err := ParseInventoryCSV(strings.NewReader(inventoryCSV(
			inventoryRow("cmdb", "a1", "container_image", "n1", "production", "high", "internet", "", "", "", "", "", "", "registry/x/img:v1", digest),
			inventoryRow("cmdb", "a2", "container_image", "n2", "production", "high", "internet", "", "", "", "", "", "", "registry/x/img:v2", digest),
		)))
		if err != nil {
			t.Fatal(err)
		}
		if len(file.Problems) != 0 {
			t.Fatalf("problems: %s", formatProblems(file.Problems))
		}
		// Same digest on both rows: identical natural key even though the
		// image tags differ — digest is the immutable, stronger identity.
		key1 := file.Assets[0].Components[0].NaturalKey
		key2 := file.Assets[1].Components[0].NaturalKey
		if key1 != key2 {
			t.Errorf("digest must be the strongest identifier: keys %q vs %q", key1, key2)
		}
	})
}

func TestParseInventoryCSVLimits(t *testing.T) {
	t.Run("row cap is positioned", func(t *testing.T) {
		var b strings.Builder
		b.WriteString(strings.Join(inventoryHeaderColumns, ",") + "\n")
		for i := 0; i < InventoryMaxRows+1; i++ {
			fmt.Fprintf(&b, "cmdb,a%d,server_vm,n%d,production,high,internet,,acme,p%d,1.0.0,,,,\n", i, i, i)
		}
		file, err := ParseInventoryCSV(strings.NewReader(b.String()))
		if err != nil {
			t.Fatal(err)
		}
		if file.Rows != InventoryMaxRows {
			t.Errorf("rows=%d, want %d", file.Rows, InventoryMaxRows)
		}
		// The first row beyond the cap sits on data line %d (header line 1
		// + %d data rows before it).
		wantProblems(t, file.Problems,
			problem(InventoryMaxRows+2, "", fmt.Sprintf("file exceeds the %d data-row limit", InventoryMaxRows), ""),
		)
		if len(file.Assets) != InventoryMaxRows {
			t.Errorf("assets=%d, want %d", len(file.Assets), InventoryMaxRows)
		}
	})

	t.Run("byte cap rejects the file before parsing", func(t *testing.T) {
		big := strings.NewReader(strings.Repeat("x", InventoryMaxBytes+1))
		_, err := ParseInventoryCSV(big)
		if !errors.Is(err, ErrInventoryTooLarge) {
			t.Fatalf("err=%v, want ErrInventoryTooLarge", err)
		}
	})

	t.Run("nil reader", func(t *testing.T) {
		if _, err := ParseInventoryCSV(nil); err == nil {
			t.Fatal("nil reader must error")
		}
	})
}

func TestValidateCSVInventory(t *testing.T) {
	t.Run("valid file", func(t *testing.T) {
		res, err := ValidateCSVInventory(strings.NewReader(inventoryCSV(
			inventoryRow("cmdb", "a1", "server_vm", "n1", "production", "high", "internet", "", "acme", "p1", "1.0.0", "", "", "", ""),
			inventoryRow("cmdb", "a2", "server_vm", "n2", "production", "high", "internet", "", "acme", "p2", "1.0.0", "", "", "", ""),
		)))
		if err != nil {
			t.Fatal(err)
		}
		if res.Rows != 2 || res.ErrorCount != 0 || len(res.Errors) != 0 {
			t.Errorf("rows=%d errors=%d", res.Rows, res.ErrorCount)
		}
	})

	t.Run("errors are counted and positioned", func(t *testing.T) {
		res, err := ValidateCSVInventory(strings.NewReader(inventoryCSV(
			inventoryRow("cmdb", "a1", "car", "n1", "production", "high", "internet", "", "acme", "p1", "1.0.0", "", "", "", ""),         // bad type, line 2
			inventoryRow("cmdb", "a2", "server_vm", "n2", "production", "high", "internet", "", "acme", "p2", "", "pkg:bad", "", "", ""), // bad purl, line 3
		)))
		if err != nil {
			t.Fatal(err)
		}
		if res.Rows != 2 || res.ErrorCount != 2 {
			t.Fatalf("rows=%d errors=%d", res.Rows, res.ErrorCount)
		}
		if res.Errors[0].Line != 2 || res.Errors[1].Line != 3 {
			t.Errorf("positions: %s", formatProblems(res.Errors))
		}
	})

	t.Run("too large propagates", func(t *testing.T) {
		_, err := ValidateCSVInventory(strings.NewReader(strings.Repeat("x", InventoryMaxBytes+1)))
		if !errors.Is(err, ErrInventoryTooLarge) {
			t.Fatalf("err=%v, want ErrInventoryTooLarge", err)
		}
	})
}
