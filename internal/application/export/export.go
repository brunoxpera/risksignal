package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"time"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// Format is the export serialisation format — the exports.format vocabulary
// of ARCH-007 §1.2.
type Format string

const (
	// FormatCSV is the neutralised spreadsheet format (ARCH-007 §1.3).
	FormatCSV Format = "csv"
	// FormatJSON is the encoding/json format (ARCH-007 §1.3).
	FormatJSON Format = "json"
)

// SchemaVersion is the export document schema version stamped on every
// artifact (exports.schema_version, ARCH-007 §1.2/§1.3). It names the
// exported field set of this package; bump it whenever a column is added,
// removed or renamed so a consumer can detect the change.
const SchemaVersion = "1"

// Row is one materialised signal row of an export artifact — the readable
// field set of the SignalExportSource read (ARCH-007 §1.2). Timestamps are
// rendered as RFC 3339 UTC; a nil optional time renders as an empty cell.
type Row struct {
	ID               string // signal uuid
	CveID            string
	Priority         string
	Status           string
	Confidence       string
	Method           string
	Owner            string // owner principal; "" when unassigned
	Vendor           string
	Product          string
	ComponentVersion string
	AssetID          string
	AssetExternalID  string
	AssetName        string
	AssetType        string
	AssetEnvironment string
	AssetCriticality string
	AssetExposure    string
	Summary          string // vulnerability summary (free text)
	CreatedAt        time.Time
	DueAt            *time.Time
	ClosedAt         *time.Time
}

// Document is one export artifact to materialise: the frozen generation
// stamps and the rows. RuleVersion is the priority-rule version at
// generation time (MAX(priority_rules.version), ARCH-007 §1.2) and CreatedAt
// the frozen export creation instant; both are stamped verbatim into the
// artifact.
type Document struct {
	RuleVersion string
	CreatedAt   time.Time
	Rows        []Row
}

// row is the wire shape of one exported signal row: the single source of
// truth for the exported field set — the CSV writer reflects over it and the
// JSON writer marshals it directly, so the two formats can never diverge.
// The json tags are the CSV header names too and fix the deterministic
// column order (struct declaration order). Every field is a string; the
// timestamps were pre-rendered, so the two formats render identical values.
type row struct {
	ID               string `json:"id"`
	CveID            string `json:"cve_id"`
	Priority         string `json:"priority"`
	Status           string `json:"status"`
	Confidence       string `json:"confidence"`
	Method           string `json:"method"`
	Owner            string `json:"owner"`
	Vendor           string `json:"vendor"`
	Product          string `json:"product"`
	ComponentVersion string `json:"component_version"`
	AssetID          string `json:"asset_id"`
	AssetExternalID  string `json:"asset_external_id"`
	AssetName        string `json:"asset_name"`
	AssetType        string `json:"asset_type"`
	AssetEnvironment string `json:"asset_environment"`
	AssetCriticality string `json:"asset_criticality"`
	AssetExposure    string `json:"asset_exposure"`
	Summary          string `json:"summary"`
	CreatedAt        string `json:"created_at"`
	DueAt            string `json:"due_at"`
	ClosedAt         string `json:"closed_at"`
}

// jsonDocument is the top-level JSON artifact: the generation stamps plus the
// row array. The field order is deterministic (struct declaration order) and
// Rows is always non-nil, so an empty export marshals "rows":[] rather than
// null.
type jsonDocument struct {
	SchemaVersion string `json:"schema_version"`
	RuleVersion   string `json:"rule_version"`
	CreatedAt     string `json:"created_at"`
	RowCount      int    `json:"row_count"`
	Rows          []row  `json:"rows"`
}

// wireRow maps one application row onto its wire shape, rendering the
// timestamps as RFC 3339 UTC (empty for a zero/nil time).
func wireRow(r Row) row {
	return row{
		ID:               r.ID,
		CveID:            r.CveID,
		Priority:         r.Priority,
		Status:           r.Status,
		Confidence:       r.Confidence,
		Method:           r.Method,
		Owner:            r.Owner,
		Vendor:           r.Vendor,
		Product:          r.Product,
		ComponentVersion: r.ComponentVersion,
		AssetID:          r.AssetID,
		AssetExternalID:  r.AssetExternalID,
		AssetName:        r.AssetName,
		AssetType:        r.AssetType,
		AssetEnvironment: r.AssetEnvironment,
		AssetCriticality: r.AssetCriticality,
		AssetExposure:    r.AssetExposure,
		Summary:          r.Summary,
		CreatedAt:        formatTime(r.CreatedAt),
		DueAt:            formatTimePtr(r.DueAt),
		ClosedAt:         formatTimePtr(r.ClosedAt),
	}
}

// formatTime renders an instant as RFC 3339 in UTC; a zero time renders as
// the empty string so an absent value is an empty cell, not a sentinel date.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// formatTimePtr is formatTime for an optional instant.
func formatTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return formatTime(*t)
}

// WriteCSV renders the document as a CSV artifact to w (ARCH-007 §1.3).
//
// Layout (UTF-8, LF line endings, RFC 4180 quoting by encoding/csv):
//
//	# schema_version=<SchemaVersion>
//	# rule_version=<doc.RuleVersion>
//	# created_at=<doc.CreatedAt>
//	# row_count=<len(doc.Rows)>
//	<header row>
//	<data rows…>
//
// The leading "# " lines are a fixed provenance header, not tabular records —
// a consumer skips every line starting with '#' — so the table below them is
// a uniform header row plus data rows. Every cell of that table (the header
// names and each data value) is passed through domain.NeutralizeCSVField;
// the provenance values are neutralised too, defensively, though they carry
// no user input. The column order is the declaration order of the row struct
// — deterministic across runs.
func WriteCSV(w io.Writer, doc Document) error {
	for _, meta := range csvMeta(doc) {
		if _, err := io.WriteString(w, "# "+meta[0]+"="+domain.NeutralizeCSVField(meta[1])+"\n"); err != nil {
			return err
		}
	}

	cw := csv.NewWriter(w)
	if err := cw.Write(neutraliseAll(csvHeader())); err != nil {
		return err
	}
	for _, r := range doc.Rows {
		if err := cw.Write(neutraliseAll(csvCells(wireRow(r)))); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteJSON renders the document as a JSON artifact to w (ARCH-007 §1.3):
// one object with the generation stamps and a "rows" array, marshalled with
// encoding/json. There is no neutralisation — JSON is not a spreadsheet
// vector, so the writer's escaping is the whole transformation — but the
// field set is exactly the CSV writer's (the row struct is shared), so the
// two formats cannot diverge.
func WriteJSON(w io.Writer, doc Document) error {
	rows := make([]row, len(doc.Rows))
	for i, r := range doc.Rows {
		rows[i] = wireRow(r)
	}
	out := jsonDocument{
		SchemaVersion: SchemaVersion,
		RuleVersion:   doc.RuleVersion,
		CreatedAt:     formatTime(doc.CreatedAt),
		RowCount:      len(rows),
		Rows:          rows,
	}
	return json.NewEncoder(w).Encode(out)
}

// Write dispatches on the export format; an unknown format is rejected.
func Write(w io.Writer, format Format, doc Document) error {
	switch format {
	case FormatCSV:
		return WriteCSV(w, doc)
	case FormatJSON:
		return WriteJSON(w, doc)
	default:
		return fmt.Errorf("export: unknown format %q", format)
	}
}

// csvMeta returns the provenance header in its fixed order.
func csvMeta(doc Document) [][2]string {
	return [][2]string{
		{"schema_version", SchemaVersion},
		{"rule_version", doc.RuleVersion},
		{"created_at", formatTime(doc.CreatedAt)},
		{"row_count", strconv.Itoa(len(doc.Rows))},
	}
}

// csvHeader returns the CSV header names — the json tags of the row struct,
// in declaration order.
func csvHeader() []string {
	t := reflect.TypeOf(row{})
	names := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		names = append(names, t.Field(i).Tag.Get("json"))
	}
	return names
}

// csvCells returns one wire row's cells, in declaration order.
func csvCells(r row) []string {
	v := reflect.ValueOf(r)
	cells := make([]string, 0, v.NumField())
	for i := 0; i < v.NumField(); i++ {
		cells = append(cells, fmt.Sprint(v.Field(i).Interface()))
	}
	return cells
}

// neutraliseAll maps domain.NeutralizeCSVField over a cell slice.
func neutraliseAll(cells []string) []string {
	out := make([]string, len(cells))
	for i, c := range cells {
		out[i] = domain.NeutralizeCSVField(c)
	}
	return out
}
