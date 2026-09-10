package application

// This file implements the CSV half of the WP-3.05 inventory import
// (ARCH-003 §1.3 step 1, DEV-059): the parser that reads one flat
// inventory CSV — one row per component, asset columns repeated — and
// turns it into typed asset groups ready for validate, preview (this
// task) and commit (DEV-060).
//
// Shape (ARCH-003 §1.3): the header is the fixed 15-column snake_case
// English set
//
//	source, external_id, type, name, environment, criticality, exposure,
//	owner, vendor, product, version, cpe, purl, image, digest
//
// and is order-insensitive. Rows are grouped by (source, external_id)
// into assets; the component columns of each row nest under its asset.
// Asset columns source/external_id/type/name/environment/criticality/
// exposure are required per row, owner is nullable; the component columns
// version/cpe/purl/image/digest are optional and vendor/product are
// required unless cpe/purl/digest/image carries the identity.
//
// The parser is pure (no writes, no current-state reads) and defensive in
// the quarantine sense (concept ch. 8.1 step 5): every failure is a
// positioned problem — 1-based line, column name, reason — and a failing
// row never aborts the file. Only rows that pass every check (local cell
// checks, asset-field agreement within their group, natural-key agreement
// within their group) contribute to the parsed assets; every rejected row
// is reported, so validate and preview show exactly what a commit of the
// file would change.
//
// Resource limits (concept ch. 12.3 "Strikte Eingabegrenzen", ARCH-003
// §1.3 "row-count/size limits"): the input is bounded by
// InventoryMaxBytes — a whole-file cap; exceeding it rejects the file
// before any row is read (mirroring the HTTP body limit of the API layer)
// — and by InventoryMaxRows, enforced while reading and positioned at the
// first row beyond the limit. Cells are trimmed of surrounding whitespace
// on read (RFC 4180 treats such spaces as data, but leading/trailing
// whitespace in inventory cells is a file artifact; the trimmed value is
// what validate, preview and commit see) and bounded by
// inventoryMaxCellBytes.
//
// Value validation delegates to the locked vocabularies: enum validity
// (type/environment/criticality/exposure) through the domain parsers of
// internal/domain/asset.go (DEV-044); identifier syntax (cpe/purl/image)
// through the strict parsers of internal/application/normalise (DEV-047);
// and the digest column through the same "algorithm:lowercase-hex"
// grammar the image parser enforces for @digest. The per-component
// natural key is the domain derivation of naturalkey.go (DEV-044:
// ComponentNaturalKey, priority cpe > purl > digest > image >
// vendor/product/version) — the identical key commit will upsert on
// (UQ (asset_id, natural_key), ARCH-003 §1.2) — and the normalised
// comparison keys come from normalise.NormaliseKey (NFKC + Unicode trim
// + case fold, ARCH-003 §2). The version ordering scheme is inferred
// through normalise.InferVersionScheme (purl type → CPE → version shape;
// the CSV carries no explicit scheme column).

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/brunoxpera/risksignal/internal/application/normalise"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// Inventory limits (concept ch. 12.3 strict input limits; ARCH-003 §1.3
// "row-count/size limits"): the import file is bounded in bytes and the
// data rows in count. The byte cap is the same resource guard the API
// layer applies to request bodies (httpapi.LimitBody) — an oversized file
// is rejected up front, before any parsing; the row cap is enforced while
// reading, positioned at the first row beyond the limit.
const (
	// InventoryMaxBytes caps one inventory CSV at 16 MiB. A full
	// inventory at the reference scale (10 000 assets, concept
	// performance section) with several components per asset stays far
	// below this; the cap exists so an accidental or malicious upload
	// cannot force an unbounded parse.
	InventoryMaxBytes = 16 << 20 // 16 MiB

	// InventoryMaxRows caps the data rows of one inventory CSV at
	// 100 000. Rows are the parser's memory unit (the whole file is
	// grouped in memory), so the cap bounds both work and memory.
	InventoryMaxRows = 100_000

	// inventoryMaxCellBytes caps a single cell at 4096 bytes (concept
	// ch. 12.3 "Freitext" limits). No inventory identifier or free-text
	// column legitimately approaches this; a longer cell is a data error
	// and is reported positioned, never truncated silently.
	inventoryMaxCellBytes = 4096
)

// ErrInventoryTooLarge reports an import file at or above
// InventoryMaxBytes. It is the whole-file resource rejection of concept
// ch. 12.3: the file is refused before any row is read, so no line can be
// blamed — callers surface it as a validation-class failure (the API
// layer's 413 analogue).
var ErrInventoryTooLarge = errors.New("inventory: file exceeds the 16 MiB import size limit")

// inventoryHeaderColumns is the canonical, locked column set of the
// inventory CSV (ARCH-003 §1.3). The header may appear in any order; this
// canonical order is what every column-name position below refers to.
var inventoryHeaderColumns = []string{
	"source", "external_id", "type", "name", "environment", "criticality", "exposure",
	"owner", "vendor", "product", "version", "cpe", "purl", "image", "digest",
}

// inventoryRequiredAssetColumns are the asset columns that must carry a
// value on every data row (ARCH-003 §1.3); owner is nullable and the
// component columns are optional.
var inventoryRequiredAssetColumns = []string{
	"source", "external_id", "type", "name", "environment", "criticality", "exposure",
}

// InventoryProblem is one positioned failure of an inventory CSV
// (ARCH-003 §1.3: "Every failure is positioned (line, column) and
// reported like a quarantine position/reason pair"). Line is the 1-based
// physical line of the file (1 = the header); Column names the offending
// column — the order-insensitive header makes the name the stable
// identity — and is "" for problems that span a whole row or the header
// itself. Reason is human-readable; Input carries the offending cell
// verbatim ("" when no single cell is at fault).
type InventoryProblem struct {
	Line   int
	Column string
	Reason string
	Input  string
}

// String renders the positioned problem for logs and text output.
func (p InventoryProblem) String() string {
	switch {
	case p.Column == "" && p.Input == "":
		return fmt.Sprintf("line %d: %s", p.Line, p.Reason)
	case p.Column == "":
		return fmt.Sprintf("line %d: %s (%q)", p.Line, p.Reason, p.Input)
	case p.Input == "":
		return fmt.Sprintf("line %d, column %s: %s", p.Line, p.Column, p.Reason)
	default:
		return fmt.Sprintf("line %d, column %s: %s (%q)", p.Line, p.Column, p.Reason, p.Input)
	}
}

// InventoryWarning is a data-quality note on a parsed asset (ARCH-003
// §1.3 preview: "data-quality warnings (unknown criticality/exposure)").
// The unknown criticality/exposure values are valid vocabulary members —
// they are not errors — but they flag an asset the operator should review
// before committing. Line is the first contributing data line of the
// asset.
type InventoryWarning struct {
	Line   int
	Field  string // "criticality" | "exposure"
	Value  string // the unknown value, e.g. "unknown"
	Reason string
}

// InventoryComponent is one parsed component of an asset (ARCH-003 §1.2/
// §1.3): the raw identifiers of one clean data row plus the derived
// write-time keys — the normalised comparison keys (vendor_norm /
// product_norm: NFKC + Unicode trim + case fold, ARCH-003 §2 item 1;
// version_norm stays empty — no version normaliser exists yet), the
// inferred ordering scheme (ARCH-003 §2 item 6) and the natural key
// (naturalkey.go: SHA-256 of the strongest identifier, priority
// cpe > purl > digest > image > vendor/product/version). Commit (DEV-060)
// upserts exactly these values on UQ (asset_id, natural_key). Line is the
// data line the component came from.
type InventoryComponent struct {
	Line int

	IDs domain.ComponentIdentifiers // raw originals (trimmed of cell whitespace)

	VendorNorm  string
	ProductNorm string
	VersionNorm string // "" — the CSV carries no version normaliser yet
	Scheme      domain.VersionScheme
	NaturalKey  string
}

// InventoryAsset is one parsed asset group of the file (ARCH-003 §1.3:
// rows grouped by (source, external_id)), built exclusively from rows
// that passed every check. The asset fields are the values all surviving
// rows of the group agree on — the first surviving row is authoritative
// and diverging rows are reported and excluded, never silently merged
// (resolveConflicts). Components holds one entry per surviving row in
// file order; Lines the corresponding data lines.
type InventoryAsset struct {
	Source      string
	ExternalID  string
	Type        domain.AssetType
	Name        string
	Environment domain.Environment
	Criticality domain.Criticality
	Exposure    domain.Exposure
	Owner       string // "" when the file carries no owner

	Lines      []int
	Components []InventoryComponent
}

// InventoryFile is the full parse result of one inventory CSV: every
// readable data row is counted (Rows — records the CSV reader could
// delimit; a structurally unreadable record is reported positioned and
// not counted), every failure is positioned (Problems), the assets built
// from the clean rows are in Assets and the data-quality warnings in
// Warnings. Validate reports Problems and the counts; preview diffs
// Assets against the persisted state and reports the rest.
type InventoryFile struct {
	Rows     int
	Assets   []InventoryAsset
	Problems []InventoryProblem
	Warnings []InventoryWarning
}

// ParseInventoryCSV reads, validates and groups one inventory CSV
// (ARCH-003 §1.3). It is pure: no writes, no current-state reads. All
// content failures — header problems, malformed records, enum violations,
// identifier syntax errors, intra-file conflicts — are positioned
// InventoryProblem values on the returned file; a failing row never
// aborts the file. A non-nil error is reserved for problems that make
// parsing impossible: an input at or above InventoryMaxBytes
// (ErrInventoryTooLarge) or an underlying read failure.
func ParseInventoryCSV(r io.Reader) (InventoryFile, error) {
	if r == nil {
		return InventoryFile{}, ValidationError("inventory_parse", fmt.Errorf("input must not be nil"))
	}

	data, err := io.ReadAll(io.LimitReader(r, InventoryMaxBytes+1))
	if err != nil {
		return InventoryFile{}, InfraError("inventory_parse", fmt.Errorf("reading inventory CSV: %w", err))
	}
	if len(data) > InventoryMaxBytes {
		return InventoryFile{}, ValidationError("inventory_parse", ErrInventoryTooLarge)
	}

	p := &inventoryParser{rd: csv.NewReader(bytes.NewReader(data))}
	p.rd.FieldsPerRecord = -1 // ragged records are checked by hand so every failure is positioned
	return p.parse()
}

// inventoryParser holds the state of one parse pass.
type inventoryParser struct {
	rd *csv.Reader

	header   map[string]int // canonical column name -> position in the actual header
	rows     int            // data rows read
	groups   []*rowGroup    // assets under construction, first-seen order
	byKey    map[string]*rowGroup
	problems []InventoryProblem
	warnings []InventoryWarning
}

// rowGroup is one (source, external_id) group under construction. The
// first surviving row is authoritative for the asset fields; rows that
// diverge are reported and excluded, never merged.
type rowGroup struct {
	source     string
	externalID string

	// authoritative asset fields (first surviving row)
	typeVal domain.AssetType
	envVal  domain.Environment
	critVal domain.Criticality
	expVal  domain.Exposure
	name    string
	owner   string

	rows []*cleanRow // surviving rows, file order
}

// cleanRow is one row that passed its local checks; it still has to pass
// the intra-file passes (asset-field agreement, natural-key agreement)
// before it contributes a component.
type cleanRow struct {
	line int
	comp InventoryComponent
	// asset field values of this row (validated)
	typeVal domain.AssetType
	envVal  domain.Environment
	critVal domain.Criticality
	expVal  domain.Exposure
	name    string
	owner   string
}

// parse runs the pass over the prepared reader.
func (p *inventoryParser) parse() (InventoryFile, error) {
	for {
		rec, err := p.rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			if pe, ok := err.(*csv.ParseError); ok {
				// Structural CSV failure (bare quote, stray quote, ...):
				// the record cannot be recovered, but the file can —
				// report it positioned and continue with the next record.
				l := pe.StartLine
				if l == 0 {
					l = pe.Line
				}
				p.problems = append(p.problems, InventoryProblem{
					Line:   l,
					Reason: "malformed CSV record: " + pe.Err.Error(),
				})
				continue
			}
			return InventoryFile{}, InfraError("inventory_parse", fmt.Errorf("reading inventory CSV: %w", err))
		}
		line, _ := p.rd.FieldPos(0)

		if p.header == nil {
			// First record: the header. When it is invalid, no
			// trustworthy row -> column mapping exists; report the
			// positioned header problems (line 1) and stop — an invalid
			// header is a whole-file shape problem, not a row problem.
			if ok := p.readHeader(rec, line); !ok {
				return p.file(), nil
			}
			continue
		}

		stop, err := p.dataRow(rec, line)
		if err != nil {
			return InventoryFile{}, err
		}
		if stop {
			break
		}
	}

	if p.header == nil {
		// Zero records read: the file is empty. The header is expected
		// at line 1.
		p.problems = append(p.problems, InventoryProblem{
			Line:   1,
			Reason: "file is empty — the header row (line 1) is missing",
		})
	}

	// Intra-file passes over the surviving rows of every group: asset
	// field agreement, then natural-key agreement, then the groups are
	// finalised into assets (finishGroups emits the data-quality
	// warnings).
	p.resolveConflicts()
	p.finishGroups()
	return p.file(), nil
}

// readHeader validates the first record against the canonical column set
// (ARCH-003 §1.3: snake_case, English, order-insensitive) and returns
// whether a usable mapping exists. Every deviation is reported at line 1
// with the offending column name: unknown columns, missing canonical
// columns and duplicated names. Header cells are trimmed and a UTF-8 BOM
// in front of the first cell is stripped (Excel exports).
func (p *inventoryParser) readHeader(rec []string, line int) bool {
	seen := make(map[string]int, len(rec))
	dupes := make(map[string]bool)
	var problems []InventoryProblem
	for i, raw := range rec {
		name := strings.TrimSpace(raw)
		if i == 0 {
			name = strings.TrimPrefix(name, "\ufeff")
		}
		switch {
		case name == "":
			problems = append(problems, InventoryProblem{
				Line: line, Reason: "header contains an empty column name",
			})
		case seen[name] > 0:
			if !dupes[name] {
				dupes[name] = true
				problems = append(problems, InventoryProblem{
					Line: line, Column: name, Reason: "header repeats the column " + name,
				})
			}
		default:
			seen[name] = i + 1
		}
	}
	for _, name := range inventoryHeaderColumns {
		if seen[name] == 0 {
			problems = append(problems, InventoryProblem{
				Line: line, Column: name, Reason: "header is missing the column " + name,
			})
		}
	}
	for name := range seen {
		if columnIndexOf(name) == len(inventoryHeaderColumns) {
			problems = append(problems, InventoryProblem{
				Line: line, Column: name, Reason: "unknown column " + name,
			})
		}
	}
	if len(problems) > 0 {
		p.problems = append(p.problems, problems...)
		return false
	}
	// Position map in canonical order: canonical name -> actual index.
	p.header = make(map[string]int, len(seen))
	for name, pos := range seen {
		p.header[name] = pos - 1
	}
	return true
}

// dataRow validates one data record and joins it to its (source,
// external_id) group when it survives every local check. It returns
// stop=true once the row cap is reached (the cap row is reported
// positioned and reading ends — no unbounded parse).
func (p *inventoryParser) dataRow(rec []string, line int) (stop bool, err error) {
	if p.rows >= InventoryMaxRows {
		p.problems = append(p.problems, InventoryProblem{
			Line:   line,
			Reason: fmt.Sprintf("file exceeds the %d data-row limit", InventoryMaxRows),
		})
		return true, nil
	}
	p.rows++

	if len(rec) != len(inventoryHeaderColumns) {
		p.problems = append(p.problems, InventoryProblem{
			Line:   line,
			Reason: fmt.Sprintf("expected %d fields (%s), got %d", len(inventoryHeaderColumns), strings.Join(inventoryHeaderColumns, ", "), len(rec)),
		})
		return false, nil
	}

	// Cell read: trim surrounding whitespace once here (grouping,
	// validation and the derived keys all see the same value) and
	// enforce the per-cell length bound.
	cells := make([]string, len(inventoryHeaderColumns))
	var rowProblems []InventoryProblem
	for i, name := range inventoryHeaderColumns {
		cell := strings.TrimSpace(rec[p.header[name]])
		if len(cell) > inventoryMaxCellBytes {
			rowProblems = append(rowProblems, InventoryProblem{
				Line: line, Column: name,
				Reason: fmt.Sprintf("cell exceeds the %d-byte limit", inventoryMaxCellBytes),
				Input:  cell,
			})
			continue
		}
		cells[i] = cell
	}
	if len(rowProblems) > 0 {
		p.problems = append(p.problems, rowProblems...)
		return false, nil
	}
	cell := func(name string) string { return cells[columnIndexOf(name)] }

	// Required asset cells (ARCH-003 §1.3): source/external_id/type/
	// name/environment/criticality/exposure must carry a value; owner is
	// nullable.
	for _, name := range inventoryRequiredAssetColumns {
		if cell(name) == "" {
			rowProblems = append(rowProblems, InventoryProblem{
				Line: line, Column: name, Reason: "required asset column is empty",
			})
		}
	}

	ids := domain.ComponentIdentifiers{
		Vendor:  cell("vendor"),
		Product: cell("product"),
		Version: cell("version"),
		CPE:     cell("cpe"),
		PURL:    cell("purl"),
		Image:   cell("image"),
		Digest:  cell("digest"),
	}

	// Enum validity via the domain parsers (asset.go, DEV-044). The
	// unknown members of environment/criticality/exposure are valid
	// vocabulary values and parse cleanly; they surface as data-quality
	// warnings instead of errors (finishGroups).
	typeVal, typeErr := domain.ParseAssetType(cell("type"))
	envVal, envErr := domain.ParseEnvironment(cell("environment"))
	critVal, critErr := domain.ParseCriticality(cell("criticality"))
	expVal, expErr := domain.ParseExposure(cell("exposure"))
	for _, c := range []struct {
		column string
		err    error
		input  string
	}{
		{"type", typeErr, cell("type")},
		{"environment", envErr, cell("environment")},
		{"criticality", critErr, cell("criticality")},
		{"exposure", expErr, cell("exposure")},
	} {
		if c.err != nil && c.input != "" {
			rowProblems = append(rowProblems, InventoryProblem{
				Line: line, Column: c.column,
				Reason: strings.TrimPrefix(c.err.Error(), "domain: "),
				Input:  c.input,
			})
		}
	}

	// Identifier syntax via the strict DEV-047 parsers (cpe/purl/image)
	// and the digest grammar of the image parser's @digest rule.
	if ids.CPE != "" {
		if _, err := normalise.ParseCPE23(ids.CPE); err != nil {
			rowProblems = append(rowProblems, syntaxProblem(line, "cpe", ids.CPE, err))
		}
	}
	if ids.PURL != "" {
		if _, err := normalise.ParsePURL(ids.PURL); err != nil {
			rowProblems = append(rowProblems, syntaxProblem(line, "purl", ids.PURL, err))
		}
	}
	if ids.Image != "" {
		if _, err := normalise.ParseImageRef(ids.Image); err != nil {
			rowProblems = append(rowProblems, syntaxProblem(line, "image", ids.Image, err))
		}
	}
	if ids.Digest != "" && !inventoryDigestRe.MatchString(ids.Digest) {
		rowProblems = append(rowProblems, InventoryProblem{
			Line: line, Column: "digest",
			Reason: "digest must be \"algorithm:lowercase-hex\" with at least 32 hex digits (e.g. sha256:...)",
			Input:  ids.Digest,
		})
	}

	// Identity presence (ARCH-003 §1.3): vendor/product are required
	// unless cpe/purl/digest/image carries the identity.
	if ids.CPE == "" && ids.PURL == "" && ids.Digest == "" && ids.Image == "" &&
		(ids.Vendor == "" || ids.Product == "") {
		rowProblems = append(rowProblems, InventoryProblem{
			Line:   line,
			Reason: "row carries no component identity: vendor and product are required unless cpe, purl, digest or image is present",
		})
	}

	if len(rowProblems) > 0 {
		p.problems = append(p.problems, rowProblems...)
		return false, nil
	}

	// Derive the write-time keys of the row: the normalised comparison
	// keys (ARCH-003 §2 item 1), the natural key (naturalkey.go — the
	// strongest present identifier wins) and the inferred ordering
	// scheme (ARCH-003 §2 item 6). version_norm stays empty — the import
	// layer has no version normaliser yet.
	vendorNorm := normalise.NormaliseKey(ids.Vendor)
	productNorm := normalise.NormaliseKey(ids.Product)
	scheme := normalise.InferVersionScheme(ids, domain.VersionSchemeUnknown)
	naturalKey, err := domain.ComponentNaturalKey(ids, vendorNorm, productNorm, "")
	if err != nil {
		// Unreachable after the identity-presence check above; kept as
		// a defensive positioned report instead of a panic.
		p.problems = append(p.problems, InventoryProblem{
			Line:   line,
			Reason: fmt.Sprintf("component natural key derivation failed: %v", err),
		})
		return false, nil
	}

	// Join the row's (source, external_id) group, creating it on first
	// sight (the grouping key of ARCH-003 §1.3, UQ (source, external_id)).
	source := cell("source")
	externalID := cell("external_id")
	key := keyOf(source, externalID)
	g := p.byKey[key]
	if g == nil {
		g = &rowGroup{source: source, externalID: externalID}
		if p.byKey == nil {
			p.byKey = make(map[string]*rowGroup)
		}
		p.byKey[key] = g
		p.groups = append(p.groups, g)
	}
	g.rows = append(g.rows, &cleanRow{
		line: line,
		comp: InventoryComponent{
			Line:        line,
			IDs:         ids,
			VendorNorm:  vendorNorm,
			ProductNorm: productNorm,
			Scheme:      scheme,
			NaturalKey:  naturalKey,
		},
		typeVal: typeVal,
		envVal:  envVal,
		critVal: critVal,
		expVal:  expVal,
		name:    cell("name"),
		owner:   cell("owner"),
	})
	return false, nil
}

// resolveConflicts runs the two intra-file passes over the surviving rows
// of every group (ARCH-003 §1.3 intra-file conflict detection). Rows
// rejected by either pass never contribute a component to the preview or
// a later commit — the report names each rejection, so the operator sees
// exactly which rows of the file are not importable as written.
//
// Pass 1 — asset-field agreement: all surviving rows of one asset must
// carry identical asset fields. The first row is authoritative; every
// later row whose type/name/environment/criticality/exposure/owner
// diverges is reported (positioned at the differing column, naming the
// authoritative line) and excluded — a file that disagrees with itself
// about an asset is a data error, and guessing which row wins would
// silently drop the operator's intent.
//
// Pass 2 — natural-key agreement: two rows of one asset with the same
// natural key (the strongest identifier they carry, naturalkey.go) must
// be identical rows. The first row is authoritative; a later row with the
// same key but divergent component fields conflicts and an identical
// later row is a duplicate — both are reported (positioned at the
// identity column when the key has one, naming the authoritative line)
// and excluded.
func (p *inventoryParser) resolveConflicts() {
	for _, g := range p.groups {
		first := g.rows[0]
		survivors := make([]*cleanRow, 0, len(g.rows))
		for _, row := range g.rows {
			if row == first {
				survivors = append(survivors, row)
				continue
			}
			if problem := assetFieldConflict(row, first); problem != nil {
				p.problems = append(p.problems, *problem)
				continue
			}
			survivors = append(survivors, row)
		}
		g.rows = survivors

		// Pass 2: natural-key agreement among the survivors.
		keySurvivors := make([]*cleanRow, 0, len(survivors))
		seen := make(map[string]*cleanRow, len(survivors))
		for _, row := range survivors {
			if firstWithKey, ok := seen[row.comp.NaturalKey]; ok {
				p.problems = append(p.problems, InventoryProblem{
					Line:   row.line,
					Column: naturalKeyColumn(row.comp),
					Reason: inventoryKeyConflictReason(firstWithKey, row),
				})
				continue
			}
			seen[row.comp.NaturalKey] = row
			keySurvivors = append(keySurvivors, row)
		}
		g.rows = keySurvivors
	}
}

// assetFieldConflict reports the positioned conflict of row against the
// authoritative first row of its group, or nil when the row agrees.
func assetFieldConflict(row, first *cleanRow) *InventoryProblem {
	switch {
	case row.typeVal != first.typeVal:
		return assetFieldConflictProblem(row, first, "type", string(row.typeVal), string(first.typeVal))
	case row.name != first.name:
		return assetFieldConflictProblem(row, first, "name", row.name, first.name)
	case row.envVal != first.envVal:
		return assetFieldConflictProblem(row, first, "environment", string(row.envVal), string(first.envVal))
	case row.critVal != first.critVal:
		return assetFieldConflictProblem(row, first, "criticality", string(row.critVal), string(first.critVal))
	case row.expVal != first.expVal:
		return assetFieldConflictProblem(row, first, "exposure", string(row.expVal), string(first.expVal))
	case row.owner != first.owner:
		return assetFieldConflictProblem(row, first, "owner", row.owner, first.owner)
	}
	return nil
}

func assetFieldConflictProblem(row, first *cleanRow, column, value, authoritative string) *InventoryProblem {
	return &InventoryProblem{
		Line:   row.line,
		Column: column,
		Input:  value,
		Reason: fmt.Sprintf("asset column %s (%q) conflicts with the row on line %d (%q); all rows of one asset must agree", column, value, first.line, authoritative),
	}
}

// finishGroups stamps the authoritative asset fields (from the first
// surviving row) onto each group and emits the data-quality warnings of
// ARCH-003 §1.3 (unknown criticality/exposure).
func (p *inventoryParser) finishGroups() {
	for _, g := range p.groups {
		if len(g.rows) == 0 {
			continue
		}
		first := g.rows[0]
		g.typeVal = first.typeVal
		g.envVal = first.envVal
		g.critVal = first.critVal
		g.expVal = first.expVal
		g.name = first.name
		g.owner = first.owner

		if g.critVal == domain.CriticalityUnknown {
			p.warnings = append(p.warnings, InventoryWarning{
				Line: first.line, Field: "criticality", Value: string(g.critVal),
				Reason: "asset criticality is unknown — review the value before committing the import",
			})
		}
		if g.expVal == domain.ExposureUnknown {
			p.warnings = append(p.warnings, InventoryWarning{
				Line: first.line, Field: "exposure", Value: string(g.expVal),
				Reason: "asset exposure is unknown — review the value before committing the import",
			})
		}
	}
}

// file assembles the final result in deterministic order: problems sorted
// by line, row-level problems of one line first, then column order.
func (p *inventoryParser) file() InventoryFile {
	sort.SliceStable(p.problems, func(i, j int) bool {
		if p.problems[i].Line != p.problems[j].Line {
			return p.problems[i].Line < p.problems[j].Line
		}
		return inventoryColumnOrder(p.problems[i].Column) < inventoryColumnOrder(p.problems[j].Column)
	})
	assets := make([]InventoryAsset, 0, len(p.groups))
	for _, g := range p.groups {
		if len(g.rows) == 0 {
			continue
		}
		asset := InventoryAsset{
			Source:      g.source,
			ExternalID:  g.externalID,
			Type:        g.typeVal,
			Name:        g.name,
			Environment: g.envVal,
			Criticality: g.critVal,
			Exposure:    g.expVal,
			Owner:       g.owner,
		}
		for _, row := range g.rows {
			asset.Lines = append(asset.Lines, row.line)
			asset.Components = append(asset.Components, row.comp)
		}
		assets = append(assets, asset)
	}
	return InventoryFile{
		Rows:     p.rows,
		Assets:   assets,
		Problems: p.problems,
		Warnings: p.warnings,
	}
}

// inventoryKeyConflictReason phrases the natural-key rejection of the
// later row against the authoritative first row: divergent rows conflict,
// identical rows duplicate.
func inventoryKeyConflictReason(first, later *cleanRow) string {
	if first.comp.IDs == later.comp.IDs {
		return fmt.Sprintf("duplicate of the component on line %d (same natural key)", first.line)
	}
	return fmt.Sprintf("component natural key conflicts with the component on line %d (same natural key, divergent fields)", first.line)
}

// naturalKeyColumn names the column the row's natural key derives from —
// the strongest identifier present (naturalkey.go priority) — or "" for
// the vendor/product(/version) fallback.
func naturalKeyColumn(c InventoryComponent) string {
	switch {
	case c.IDs.CPE != "":
		return "cpe"
	case c.IDs.PURL != "":
		return "purl"
	case c.IDs.Digest != "":
		return "digest"
	case c.IDs.Image != "":
		return "image"
	}
	return ""
}

// syntaxProblem positions one normalise syntax failure (cpe/purl/image):
// the *SyntaxError of DEV-047 carries the machine-readable field/position
// pair; the CSV problem surfaces the human half plus the row's line and
// column.
func syntaxProblem(line int, column, input string, err error) InventoryProblem {
	var se *normalise.SyntaxError
	if errors.As(err, &se) {
		return InventoryProblem{Line: line, Column: column, Reason: se.Reason, Input: input}
	}
	return InventoryProblem{Line: line, Column: column, Reason: err.Error(), Input: input}
}

// columnIndexOf returns the canonical position of one column name; names
// outside the canonical set map to the end (unknown columns, used for
// stable problem ordering).
func columnIndexOf(name string) int {
	for i, c := range inventoryHeaderColumns {
		if c == name {
			return i
		}
	}
	return len(inventoryHeaderColumns)
}

// inventoryColumnOrder is the sort key of problem columns: row-level
// problems ("") sort first on their line, then canonical column order,
// then unknown columns.
func inventoryColumnOrder(column string) int {
	if column == "" {
		return -1
	}
	return columnIndexOf(column)
}

// keyOf renders the (source, external_id) grouping key. A NUL separator
// keeps the two halves unambiguous.
func keyOf(source, externalID string) string {
	return source + "\x00" + externalID
}

// inventoryDigestRe is the digest grammar of the digest column (ARCH-003
// §1.2: "immutable digest (sha256:…)"). It is the exact grammar the image
// parser of internal/application/normalise enforces for @digest
// (image.go: "algorithm:lowercase-hex" with at least 32 hex digits), kept
// here as the column-level validator of the standalone digest cell so the
// two accept exactly the same digest strings.
var inventoryDigestRe = regexp.MustCompile(`^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[0-9a-f]{32,}$`)
