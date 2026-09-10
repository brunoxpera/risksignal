// View models and presentation helpers of the server-rendered web adapter
// (ARCH-006 §3.1/§3.2, ADR-004).
//
// The templates carry NO business logic: every label, symbol and derived
// display value is computed here on the application-layer data the use cases
// returned. The mapping is strictly presentational — it never decides rights,
// status or priority; the use cases remain the gate of record (ARCH-006 §6).
package web

import (
	"fmt"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// chrome is the shared page chrome every view embeds: the document title, the
// role-dependent navigation, the authenticated principal, the flash and the
// per-session CSRF token (ARCH-006 §3.1/§3.2).
type chrome struct {
	Title     string
	Nav       []navItem
	Principal principalView
	Flash     *flashMessage
	CSRFToken string
}

// navItem is one role-dependent navigation entry.
type navItem struct {
	Label  string
	Href   string
	Active bool
}

// principalView is the presentation view of the authenticated principal.
type principalView struct {
	Authenticated bool
	UserID        string
	DisplayName   string
	Roles         []domain.Role
}

// flashMessage is a one-shot status message rendered by _flash.html.
type flashMessage struct {
	Kind    string // info | success | error
	Message string
}

// priorityCount / statusCount back the dashboard aggregate panels.
type priorityCount struct {
	Priority domain.Priority
	Symbol   string
	Count    int
}

type statusCount struct {
	Status      domain.SignalStatus
	StatusLabel string
	Count       int
}

// slaView is the presentation view of one signal's SLA countdown (ARCH-006 §4
// row 6). RemainingSeconds is machine-readable; Remaining is the text.
type slaView struct {
	SignalID         string
	Priority         domain.Priority
	Symbol           string
	Remaining        string
	RemainingSeconds int
	Breached         bool
	DueISO           string
}

// signalRow is one triage-list row.
type signalRow struct {
	ID              string
	CVEID           string
	Summary         string
	AssetName       string
	Priority        domain.Priority
	Symbol          string
	Confidence      domain.Confidence
	ConfidenceLabel string
	Status          domain.SignalStatus
	StatusLabel     string
	Href            string
	SLA             slaView
}

// filterBarView / filterField / filterOption back the reusable _filter_bar
// partial (ARCH-006 §4 row 4).
type filterBarView struct {
	Action       string
	Fields       []filterField
	CanonicalURL string
	Summary      string
}

type filterField struct {
	Name    string
	Label   string
	Value   string
	Select  bool
	Options []filterOption
}

type filterOption struct {
	Value    string
	Label    string
	Selected bool
}

// option is a generic <select> option used by the command forms.
type option struct {
	Value    string
	Label    string
	Selected bool
}

// --- page data -------------------------------------------------------------

type dashboardView struct {
	chrome
	SignalTotal            int
	PriorityCounts         []priorityCount
	StatusCounts           []statusCount
	AssetTotal             int
	AssetOwned             int
	SLARows                []slaView
	SLAEndpoint            string
	SourceMonitorAvailable bool
	SourceSummary          []sourceRow
}

type triageView struct {
	chrome
	FilterBar   filterBarView
	Signals     []signalRow
	NextCursor  string
	NextHref    string
	SLARows     []slaView
	SLAEndpoint string
}

type signalDetailView struct {
	chrome
	ID                string
	CVEID             string
	Summary           string
	Priority          domain.Priority
	Symbol            string
	Status            domain.SignalStatus
	StatusLabel       string
	Confidence        domain.Confidence
	ConfidenceLabel   string
	Method            domain.MatchMethod
	Owner             string
	Version           int
	CreatedAt         string
	Asset             signalAssetView
	Product           signalProductView
	Components        []componentRow
	SLA               slaView
	Conflict          bool
	ConflictMessage   string
	Statuses          []option
	Priorities        []option
	SLATargets        []option
	ConfirmTransition string
	ConfirmOverride   string
	ConfirmRevert     string
	ConfirmPause      string
}

type signalAssetView struct {
	Name        string
	Type        domain.AssetType
	Criticality domain.Criticality
}

type signalProductView struct {
	Vendor  string
	Product string
	Version string
}

type componentRow struct {
	Vendor  string
	Product string
	Version string
}

type sourceRow struct {
	ID             string
	Name           string
	Type           string
	Status         string
	StatusLabel    string
	LastRunAt      string
	DataAge        string
	ErrorCount     int
	OpenQuarantine int
	Degraded       bool
}

type sourceMonitorView struct {
	chrome
	MonitorAvailable bool
	Sources          []sourceRow
}

type inventoryView struct {
	chrome
	FilterBar  filterBarView
	Assets     []assetRow
	NextCursor string
	NextHref   string
	Import     importPanel
}

type importPanel struct {
	Manage bool
}

type assetRow struct {
	ID          string
	Name        string
	Type        string
	Environment string
	Criticality domain.Criticality
	Exposure    string
	Owner       string
	Source      string
}

type inventoryImportView struct {
	chrome
	Import        *importView
	ConfirmCommit string
}

type importView struct {
	ID                string
	Status            string
	Rows              int
	ErrorCount        int
	WarningCount      int
	AssetsCreated     int
	AssetsUpdated     int
	ComponentsCreated int
	ComponentsUpdated int
	Problems          []problemRow
	Committable       bool
}

type problemRow struct {
	Row     int
	Column  string
	Message string
}

type adminUsersView struct {
	chrome
	Users      []userRow
	Roles      []option
	NextCursor string
	NextHref   string
}

type userRow struct {
	ID                string
	DisplayName       string
	Email             string
	Roles             []domain.Role
	Active            bool
	StateLabel        string
	ConfirmRevoke     string
	ConfirmDeactivate string
}

type adminRolesView struct {
	chrome
	Roles []roleRow
}

type roleRow struct {
	Role        domain.Role
	Label       string
	Permissions []permissionRow
}

type permissionRow struct {
	Permission string
	Scope      string
}

type errorView struct {
	chrome
	Status  int
	Message string
}

// --- template helpers ------------------------------------------------------

// prioritySymbol returns the colour-independent symbol of a priority (ARCH-006
// §4 row 1): the badge always renders text (P1–P4) AND this symbol.
func prioritySymbol(p domain.Priority) string {
	switch p {
	case domain.PriorityP1:
		return "▲"
	case domain.PriorityP2:
		return "◆"
	case domain.PriorityP3:
		return "●"
	case domain.PriorityP4:
		return "○"
	default:
		return "?"
	}
}

// confidenceLabel maps the stored Confidence onto the explicit vocabulary
// (ARCH-006 §4 row 2): high=confirmed, medium=probable, low=possible,
// none=not established. No unqualified "affected" wording is ever rendered.
func confidenceLabel(c domain.Confidence) string {
	switch c {
	case domain.ConfidenceHigh:
		return "confirmed"
	case domain.ConfidenceMedium:
		return "probable"
	case domain.ConfidenceLow:
		return "possible"
	case domain.ConfidenceNone:
		return "not established"
	default:
		return string(c)
	}
}

// statusLabel is the human-readable label of a signal status.
func statusLabel(s domain.SignalStatus) string {
	switch s {
	case domain.SignalStatusNew:
		return "New"
	case domain.SignalStatusInReview:
		return "In review"
	case domain.SignalStatusActionPlanned:
		return "Action planned"
	case domain.SignalStatusResolved:
		return "Resolved"
	case domain.SignalStatusAccepted:
		return "Accepted"
	case domain.SignalStatusNotAffected:
		return "Not affected"
	default:
		return string(s)
	}
}

// roleLabel is the operator-facing label of a role (ARCH-005 §3).
func roleLabel(r domain.Role) string {
	switch r {
	case domain.RoleSecurityAnalyst:
		return "Security Analyst"
	case domain.RoleSystemResponsible:
		return "Systemverantwortliche"
	case domain.RoleAdministrator:
		return "Administrator"
	case domain.RoleAuditor:
		return "Auditor / Reviewer"
	case domain.RoleProductOwner:
		return "Product Owner"
	default:
		return string(r)
	}
}

// hasPermission reports whether the role set grants perm at any scope. This is
// the presentation-only membership check behind the role-dependent navigation
// (ARCH-006 §3.1) — the use cases remain the authorisation gate of record.
func hasPermission(roles []domain.Role, perm domain.Permission) bool {
	for _, r := range roles {
		if _, ok := r.Permissions()[perm]; ok {
			return true
		}
	}
	return false
}

// buildNav renders the role-dependent navigation (ARCH-006 §3.1): the entries
// a principal may exercise, per the role→permission matrix.
func buildNav(roles []domain.Role, active string) []navItem {
	items := []navItem{{Label: "Dashboard", Href: "/"}}
	if hasPermission(roles, domain.PermissionSignalsRead) {
		items = append(items, navItem{Label: "Triage", Href: "/signals"})
	}
	if hasPermission(roles, domain.PermissionSourcesManage) {
		items = append(items, navItem{Label: "Sources", Href: "/sources"})
	}
	if hasPermission(roles, domain.PermissionInventoryRead) {
		items = append(items, navItem{Label: "Inventory", Href: "/inventory"})
	}
	if hasPermission(roles, domain.PermissionInventoryManage) {
		items = append(items, navItem{Label: "Import", Href: "/inventory/imports"})
	}
	if hasPermission(roles, domain.PermissionUsersRolesManage) {
		items = append(items, navItem{Label: "Users", Href: "/admin/users"})
		items = append(items, navItem{Label: "Roles", Href: "/admin/roles"})
	}
	for i := range items {
		items[i].Active = items[i].Href == active
	}
	return items
}

// --- builders --------------------------------------------------------------

func toSignalRow(s application.Signal, now time.Time) signalRow {
	return signalRow{
		ID:              s.ID,
		CVEID:           s.CveID,
		Summary:         s.Summary,
		AssetName:       s.Asset.Name,
		Priority:        s.Priority,
		Symbol:          prioritySymbol(s.Priority),
		Confidence:      s.Confidence,
		ConfidenceLabel: confidenceLabel(s.Confidence),
		Status:          s.Status,
		StatusLabel:     statusLabel(s.Status),
		Href:            "/signals/" + s.ID,
		SLA:             toSLAView(s, now),
	}
}

func toSLAView(s application.Signal, now time.Time) slaView {
	v := slaView{
		SignalID: s.ID,
		Priority: s.Priority,
		Symbol:   prioritySymbol(s.Priority),
	}
	if s.DueAt == nil {
		v.Remaining = "no deadline"
		return v
	}
	due := *s.DueAt
	v.DueISO = due.UTC().Format(time.RFC3339)
	rem := due.Sub(now)
	if rem <= 0 {
		v.Breached = true
		v.Remaining = "breached by " + humanDuration(-rem)
		v.RemainingSeconds = int(rem.Seconds())
		return v
	}
	v.RemainingSeconds = int(rem.Seconds())
	v.Remaining = "in " + humanDuration(rem)
	return v
}

// humanDuration renders a coarse, operator-facing duration.
func humanDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 48*time.Hour {
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// slaRows filters the time-critical (P1/P2) signals for the countdown fragment
// and the dashboard/triage panels (ARCH-006 §4 row 6).
func slaRows(signals []application.Signal, now time.Time) []slaView {
	rows := make([]slaView, 0, len(signals))
	for _, s := range signals {
		if s.Priority == domain.PriorityP1 || s.Priority == domain.PriorityP2 {
			rows = append(rows, toSLAView(s, now))
		}
	}
	return rows
}

// priorityCounts / statusCounts aggregate a page of signals for the dashboard.
func priorityCounts(signals []application.Signal) []priorityCount {
	var out []priorityCount
	for _, p := range []domain.Priority{domain.PriorityP1, domain.PriorityP2, domain.PriorityP3, domain.PriorityP4} {
		n := 0
		for _, s := range signals {
			if s.Priority == p {
				n++
			}
		}
		out = append(out, priorityCount{Priority: p, Symbol: prioritySymbol(p), Count: n})
	}
	return out
}

func statusCounts(signals []application.Signal) []statusCount {
	order := []domain.SignalStatus{
		domain.SignalStatusNew, domain.SignalStatusInReview, domain.SignalStatusActionPlanned,
		domain.SignalStatusResolved, domain.SignalStatusAccepted, domain.SignalStatusNotAffected,
	}
	var out []statusCount
	for _, st := range order {
		n := 0
		for _, s := range signals {
			if s.Status == st {
				n++
			}
		}
		out = append(out, statusCount{Status: st, StatusLabel: statusLabel(st), Count: n})
	}
	return out
}

func toComponentRow(c application.Component) componentRow {
	return componentRow{Vendor: c.Vendor, Product: c.Product, Version: c.Version}
}

// statusOptions / priorityOptions / slaTargetOptions back the command forms.
func statusOptions(current domain.SignalStatus) []option {
	all := []domain.SignalStatus{
		domain.SignalStatusNew, domain.SignalStatusInReview, domain.SignalStatusActionPlanned,
		domain.SignalStatusResolved, domain.SignalStatusAccepted, domain.SignalStatusNotAffected,
	}
	out := make([]option, 0, len(all))
	for _, s := range all {
		out = append(out, option{Value: string(s), Label: statusLabel(s), Selected: s == current})
	}
	return out
}

func priorityOptions(current domain.Priority) []option {
	out := make([]option, 0, 4)
	for _, p := range []domain.Priority{domain.PriorityP1, domain.PriorityP2, domain.PriorityP3, domain.PriorityP4} {
		out = append(out, option{Value: string(p), Label: string(p), Selected: p == current})
	}
	return out
}

func slaTargetOptions() []option {
	return []option{
		{Value: string(domain.SLATargetNotification), Label: "Notification"},
		{Value: string(domain.SLATargetAcknowledgement), Label: "Acknowledgement"},
		{Value: string(domain.SLATargetAssessment), Label: "Assessment"},
		{Value: string(domain.SLATargetDecision), Label: "Decision"},
	}
}

func roleOptions() []option {
	out := make([]option, 0, 5)
	for _, r := range domain.AllRoles() {
		out = append(out, option{Value: string(r), Label: roleLabel(r)})
	}
	return out
}

// selectOptions builds a filter <select> from raw string values.
func selectOptions(values []string, current string) []filterOption {
	out := make([]filterOption, 0, len(values))
	for _, v := range values {
		out = append(out, filterOption{Value: v, Label: v, Selected: v == current})
	}
	return out
}

// filterSummary is the operator-facing re-statement of the active filters
// (ARCH-006 §4 row 4).
func filterSummary(fields []filterField) string {
	var parts []string
	for _, f := range fields {
		if f.Value != "" {
			parts = append(parts, f.Name+"="+f.Value)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}
