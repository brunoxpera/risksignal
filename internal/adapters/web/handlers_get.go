// GET handlers of the web adapter (ARCH-006 §3.1). Every GET resolves the
// principal, then renders from the matching application use case called
// in-process.
package web

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// triageFilterNames is the canonical filter order of the triage list — it
// drives both the round-trip URL and the re-stated summary.
var triageFilterNames = []string{"priority", "status"}

// inventoryFilterNames is the canonical filter order of the inventory list.
var inventoryFilterNames = []string{"type", "environment", "criticality", "exposure", "owner", "source"}

// handleDashboard renders GET / from ListSignals + ListAssets (+ the optional
// source monitor) (ARCH-006 §3.1).
func (w *Web) handleDashboard(rw http.ResponseWriter, r *http.Request) {
	pv, actor, err := w.principalFor(r)
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}
	csrf := w.csrfToken(rw, r)

	page, err := w.svc.ListSignals(r.Context(), application.ListSignalsInput{Limit: 100, Actor: actor})
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}
	assets, err := w.svc.ListAssets(r.Context(), application.ListAssetsInput{Limit: 100, Actor: actor})
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}
	owned := 0
	for _, a := range assets.Assets {
		if a.Owner != "" {
			owned++
		}
	}

	now := w.clock.Now()
	dv := dashboardView{
		chrome:         w.newChrome("Dashboard", "/", pv, nil, csrf),
		SignalTotal:    len(page.Signals),
		PriorityCounts: priorityCounts(page.Signals),
		StatusCounts:   statusCounts(page.Signals),
		AssetTotal:     len(assets.Assets),
		AssetOwned:     owned,
		SLARows:        slaRows(page.Signals, now),
		SLAEndpoint:    fragmentEndpoint(""),
	}
	// The source-monitor summary is best-effort: sources.manage gates the read
	// (an administrator-only grant), so a principal without it simply sees no
	// summary rather than a denied dashboard.
	if hasPermission(pv.Roles, domain.PermissionSourcesManage) {
		if status, serr := w.svc.ListSourceStatus(r.Context(), application.ListSourceStatusInput{Actor: actor}); serr == nil {
			dv.SourceMonitorAvailable = true
			dv.SourceSummary = toSourceRows(status.Sources)
		}
	}
	w.renderPage(rw, http.StatusOK, "dashboard", dv)
}

// handleTriage renders GET /signals with the filters from the query string
// (ARCH-006 §3.1/§4 row 4).
func (w *Web) handleTriage(rw http.ResponseWriter, r *http.Request) {
	pv, actor, err := w.principalFor(r)
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}
	csrf := w.csrfToken(rw, r)

	q := r.URL.Query()
	in := application.ListSignalsInput{Limit: 20, Cursor: q.Get("cursor"), Actor: actor}
	priority := q.Get("priority")
	if priority != "" {
		p, perr := domain.ParsePriority(priority)
		if perr != nil {
			w.renderErrorPage(rw, r, http.StatusBadRequest, "invalid priority filter "+priority)
			return
		}
		in.Priority = &p
	}
	status := q.Get("status")
	if status != "" {
		s, serr := domain.ParseSignalStatus(status)
		if serr != nil {
			w.renderErrorPage(rw, r, http.StatusBadRequest, "invalid status filter "+status)
			return
		}
		in.Status = &s
	}

	page, err := w.svc.ListSignals(r.Context(), in)
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}

	filters := canonicalFilters(q, triageFilterNames)
	now := w.clock.Now()
	rows := make([]signalRow, 0, len(page.Signals))
	for _, s := range page.Signals {
		rows = append(rows, toSignalRow(s, now))
	}
	tv := triageView{
		chrome:      w.newChrome("Signal triage", "/signals", pv, nil, csrf),
		FilterBar:   triageFilterBar(q),
		Signals:     rows,
		NextCursor:  page.NextCursor,
		NextHref:    pageHref("/signals", q, triageFilterNames, page.NextCursor),
		SLARows:     slaRows(page.Signals, now),
		SLAEndpoint: fragmentEndpoint(filters),
	}
	w.renderPage(rw, http.StatusOK, "triage", tv)
}

// handleSLAFragment renders the SLA-countdown fragment for the triage filter
// set (ARCH-006 §4 row 6) — no full page reload.
func (w *Web) handleSLAFragment(rw http.ResponseWriter, r *http.Request) {
	_, actor, err := w.principalFor(r)
	if err != nil {
		http.Error(rw, "forbidden", statusForError(err))
		return
	}
	q := r.URL.Query()
	in := application.ListSignalsInput{Limit: 100, Actor: actor}
	if priority := q.Get("priority"); priority != "" {
		if p, perr := domain.ParsePriority(priority); perr == nil {
			in.Priority = &p
		}
	}
	if status := q.Get("status"); status != "" {
		if s, serr := domain.ParseSignalStatus(status); serr == nil {
			in.Status = &s
		}
	}
	page, err := w.svc.ListSignals(r.Context(), in)
	if err != nil {
		http.Error(rw, "unavailable", statusForError(err))
		return
	}
	w.renderFragment(rw, slaRows(page.Signals, w.clock.Now()))
}

// handleSignalDetail renders GET /signals/{id} from GetSignal (+ the asset
// component context) (ARCH-006 §3.1).
func (w *Web) handleSignalDetail(rw http.ResponseWriter, r *http.Request) {
	pv, actor, err := w.principalFor(r)
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}
	w.renderSignalDetail(rw, r, http.StatusOK, pv, actor, r.PathValue("id"), nil, "")
}

// handleSourceMonitor renders GET /sources from the ListSourceStatus read use
// case (ARCH-006 §3.1). The use case gates on sources.manage (deny-by-
// default): a principal without it is denied with the mapped error status, a
// permitted principal sees the real per-source status.
func (w *Web) handleSourceMonitor(rw http.ResponseWriter, r *http.Request) {
	pv, actor, err := w.principalFor(r)
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}
	csrf := w.csrfToken(rw, r)
	status, err := w.svc.ListSourceStatus(r.Context(), application.ListSourceStatusInput{Actor: actor})
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}
	w.renderPage(rw, http.StatusOK, "source-monitor", sourceMonitorView{
		chrome:  w.newChrome("Source monitor", "/sources", pv, nil, csrf),
		Sources: toSourceRows(status.Sources),
	})
}

// handleInventory renders GET /inventory from ListAssets (ARCH-006 §3.1).
func (w *Web) handleInventory(rw http.ResponseWriter, r *http.Request) {
	pv, actor, err := w.principalFor(r)
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}
	csrf := w.csrfToken(rw, r)
	q := r.URL.Query()

	in := application.ListAssetsInput{Limit: 20, Cursor: q.Get("cursor"), Actor: actor}
	if v := q.Get("type"); v != "" {
		t, terr := domain.ParseAssetType(v)
		if terr != nil {
			w.renderErrorPage(rw, r, http.StatusBadRequest, "invalid type filter "+v)
			return
		}
		in.Type = &t
	}
	if v := q.Get("environment"); v != "" {
		e, eerr := domain.ParseEnvironment(v)
		if eerr != nil {
			w.renderErrorPage(rw, r, http.StatusBadRequest, "invalid environment filter "+v)
			return
		}
		in.Environment = &e
	}
	if v := q.Get("criticality"); v != "" {
		c, cerr := domain.ParseCriticality(v)
		if cerr != nil {
			w.renderErrorPage(rw, r, http.StatusBadRequest, "invalid criticality filter "+v)
			return
		}
		in.Criticality = &c
	}
	if v := q.Get("exposure"); v != "" {
		e, eerr := domain.ParseExposure(v)
		if eerr != nil {
			w.renderErrorPage(rw, r, http.StatusBadRequest, "invalid exposure filter "+v)
			return
		}
		in.Exposure = &e
	}
	if v := q.Get("owner"); v != "" {
		in.OwnerID = &v
	}
	if v := q.Get("source"); v != "" {
		in.Source = &v
	}

	page, err := w.svc.ListAssets(r.Context(), in)
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}
	rows := make([]assetRow, 0, len(page.Assets))
	for _, a := range page.Assets {
		rows = append(rows, assetRow{
			ID: a.ID, Name: a.Name, Type: string(a.Type), Environment: string(a.Environment),
			Criticality: a.Criticality, Exposure: string(a.Exposure), Owner: a.Owner, Source: a.Source,
		})
	}
	iv := inventoryView{
		chrome:     w.newChrome("Inventory", "/inventory", pv, nil, csrf),
		FilterBar:  inventoryFilterBar(q),
		Assets:     rows,
		NextCursor: page.NextCursor,
		NextHref:   pageHref("/inventory", q, inventoryFilterNames, page.NextCursor),
		Import:     importPanel{Manage: hasPermission(pv.Roles, domain.PermissionInventoryManage)},
	}
	w.renderPage(rw, http.StatusOK, "inventory", iv)
}

// handleInventoryImport renders GET /inventory/imports (ARCH-006 §3.1); with
// ?import=<id> it shows the staged record via GetInventoryImport.
func (w *Web) handleInventoryImport(rw http.ResponseWriter, r *http.Request) {
	pv, actor, err := w.principalFor(r)
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}
	csrf := w.csrfToken(rw, r)
	view := inventoryImportView{chrome: w.newChrome("Inventory import", "/inventory/imports", pv, nil, csrf)}

	if id := r.URL.Query().Get("import"); id != "" {
		imp, ierr := w.svc.GetInventoryImport(r.Context(), application.GetInventoryImportInput{ID: id, Actor: actor})
		if ierr != nil {
			w.renderErrorPage(rw, r, statusForError(ierr), errorMessage(ierr))
			return
		}
		view.Import = toImportView(imp)
		view.ConfirmCommit = confirmToken("inventory-commit", imp.ID)
	}
	w.renderPage(rw, http.StatusOK, "inventory-import", view)
}

// handleAdminUsers renders GET /admin/users from ListUsers (ARCH-006 §3.3).
func (w *Web) handleAdminUsers(rw http.ResponseWriter, r *http.Request) {
	pv, actor, err := w.principalFor(r)
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}
	csrf := w.csrfToken(rw, r)
	page, err := w.svc.ListUsers(r.Context(), application.ListUsersInput{Limit: 50, Cursor: r.URL.Query().Get("cursor"), Actor: actor})
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}
	rows := make([]userRow, 0, len(page.Users))
	for _, u := range page.Users {
		active := u.DeactivatedAt.IsZero()
		state := "active"
		if !active {
			state = "deactivated"
		}
		rows = append(rows, userRow{
			ID: u.ID, DisplayName: u.DisplayName, Email: u.Email, Roles: u.Roles,
			Active:            active,
			StateLabel:        state,
			ConfirmRevoke:     confirmToken("role-revoke", u.ID),
			ConfirmDeactivate: confirmToken("deactivate", u.ID),
		})
	}
	av := adminUsersView{
		chrome:     w.newChrome("Users", "/admin/users", pv, nil, csrf),
		Users:      rows,
		Roles:      roleOptions(),
		NextCursor: page.NextCursor,
		NextHref:   nextHref("/admin/users", page.NextCursor),
	}
	w.renderPage(rw, http.StatusOK, "admin-users", av)
}

// handleAdminRoles renders GET /admin/roles from ListRoles (ARCH-006 §3.3).
func (w *Web) handleAdminRoles(rw http.ResponseWriter, r *http.Request) {
	pv, actor, err := w.principalFor(r)
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}
	csrf := w.csrfToken(rw, r)
	roles, err := w.svc.ListRoles(r.Context(), application.ListRolesInput{Actor: actor})
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}
	rows := make([]roleRow, 0, len(roles))
	for _, rd := range roles {
		perms := make([]permissionRow, 0, len(rd.Permissions))
		for _, p := range rd.Permissions {
			perms = append(perms, permissionRow{Permission: string(p.Permission), Scope: string(p.Scope)})
		}
		rows = append(rows, roleRow{Role: rd.Role, Label: roleLabel(rd.Role), Permissions: perms})
	}
	w.renderPage(rw, http.StatusOK, "admin-roles", adminRolesView{
		chrome: w.newChrome("Roles", "/admin/roles", pv, nil, csrf),
		Roles:  rows,
	})
}

// --- shared helpers --------------------------------------------------------

// renderSignalDetail loads the signal (+ asset components) and renders the
// detail page at status, with an optional flash and stale-version notice.
func (w *Web) renderSignalDetail(rw http.ResponseWriter, r *http.Request, status int, pv principalView, actor application.Actor, signalID string, flash *flashMessage, conflict string) {
	csrf := w.csrfToken(rw, r)
	sig, err := w.svc.GetSignal(r.Context(), application.GetSignalInput{SignalID: signalID, Actor: actor})
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}
	var components []componentRow
	if sig.Asset.ID != "" {
		if ac, cerr := w.svc.GetAssetComponents(r.Context(), application.GetAssetComponentsInput{AssetID: sig.Asset.ID, Actor: actor}); cerr == nil {
			for _, c := range ac.Components {
				components = append(components, toComponentRow(c))
			}
		}
	}
	timeline, err := w.svc.ListAuditEvents(r.Context(), application.ListAuditEventsInput{SignalID: signalID, Actor: actor})
	var timelineRows []timelineRow
	timelineDenied := false
	if err != nil {
		// The timeline is the audit.read-gated companion of the
		// signals.read-gated detail page (ARCH-006 §3.1): a principal who may
		// read the signal but who does not hold audit.read for it (e.g. an
		// own/assigned-scoped grant on a signal it does not own) still sees
		// the page — the timeline is omitted with an explicit note. Any other
		// failure stays a rendered error.
		if kind, _ := application.ErrorKindOf(err); kind == application.KindForbidden {
			timelineDenied = true
		} else {
			w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
			return
		}
	} else {
		timelineRows = toTimelineRows(timeline.Events)
	}
	now := w.clock.Now()
	dv := signalDetailView{
		chrome:            w.newChrome("Signal "+sig.CveID, "/signals", pv, flash, csrf),
		ID:                sig.ID,
		CVEID:             sig.CveID,
		Summary:           sig.Summary,
		Priority:          sig.Priority,
		Symbol:            prioritySymbol(sig.Priority),
		Status:            sig.Status,
		StatusLabel:       statusLabel(sig.Status),
		Confidence:        sig.Confidence,
		ConfidenceLabel:   confidenceLabel(sig.Confidence),
		Method:            sig.Method,
		Owner:             sig.Owner,
		Version:           sig.Version,
		CreatedAt:         sig.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"),
		Asset:             signalAssetView{Name: sig.Asset.Name, Type: sig.Asset.Type, Criticality: sig.Asset.Criticality},
		Product:           signalProductView{Vendor: sig.Product.Vendor, Product: sig.Product.Product, Version: sig.Product.Version},
		Components:        components,
		Timeline:          timelineRows,
		TimelineDenied:    timelineDenied,
		SLA:               toSLAView(sig, now),
		Conflict:          conflict != "",
		ConflictMessage:   conflict,
		Statuses:          statusOptions(sig.Status),
		Priorities:        priorityOptions(sig.Priority),
		SLATargets:        slaTargetOptions(),
		ConfirmTransition: confirmToken("transition", sig.ID),
		ConfirmOverride:   confirmToken("override", sig.ID),
		ConfirmRevert:     confirmToken("revert", sig.ID),
		ConfirmPause:      confirmToken("pause-sla", sig.ID),
	}
	w.renderPage(rw, status, "signal-detail", dv)
}

// renderErrorPage renders the minimal, accessible error page.
func (w *Web) renderErrorPage(rw http.ResponseWriter, r *http.Request, status int, message string) {
	if status < 400 {
		status = http.StatusInternalServerError
	}
	// A request that cannot be authenticated at all is answered plainly — the
	// I5a middleware normally intercepts it before the web adapter runs.
	pv, _, err := w.principalFor(r)
	if status == http.StatusForbidden && err != nil {
		rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.Error(rw, "forbidden: authentication required", http.StatusForbidden)
		return
	}
	csrf := w.csrfToken(rw, r)
	view := errorView{
		chrome:  w.newChrome("Error", "", pv, &flashMessage{Kind: "error", Message: message}, csrf),
		Status:  status,
		Message: message,
	}
	w.renderPage(rw, status, "error", view)
}

// canonicalFilters returns the query string of the recognised filter names, in
// canonical order — the reproducible, shareable URL (ARCH-006 §4 row 4).
func canonicalFilters(q url.Values, names []string) string {
	vals := url.Values{}
	for _, n := range names {
		if v := strings.TrimSpace(q.Get(n)); v != "" {
			vals.Set(n, v)
		}
	}
	return vals.Encode()
}

// pageHref builds the next-page URL from the canonical filters + a cursor.
func pageHref(path string, q url.Values, names []string, cursor string) string {
	if cursor == "" {
		return path
	}
	vals := url.Values{}
	for _, n := range names {
		if v := strings.TrimSpace(q.Get(n)); v != "" {
			vals.Set(n, v)
		}
	}
	vals.Set("cursor", cursor)
	return path + "?" + vals.Encode()
}

// nextHref builds a cursor-only next-page URL.
func nextHref(path, cursor string) string {
	if cursor == "" {
		return path
	}
	return path + "?cursor=" + url.QueryEscape(cursor)
}

// triageFilterBar / inventoryFilterBar build the filter-bar view models.
func triageFilterBar(q url.Values) filterBarView {
	priority := q.Get("priority")
	status := q.Get("status")
	fields := []filterField{
		{Name: "priority", Label: "Priority", Value: priority, Select: true,
			Options: selectOptions([]string{"P1", "P2", "P3", "P4"}, priority)},
		{Name: "status", Label: "Status", Value: status, Select: true,
			Options: selectOptions([]string{"new", "in_review", "action_planned", "resolved", "accepted", "not_affected"}, status)},
	}
	return filterBarView{
		Action:       "/signals",
		Fields:       fields,
		CanonicalURL: "/signals?" + canonicalFilters(q, triageFilterNames),
		Summary:      filterSummary(fields),
	}
}

func inventoryFilterBar(q url.Values) filterBarView {
	fields := []filterField{
		{Name: "type", Label: "Type", Value: q.Get("type"), Select: true,
			Options: selectOptions([]string{"server_vm", "application_framework", "container_image", "network_security", "cloud_saas"}, q.Get("type"))},
		{Name: "environment", Label: "Environment", Value: q.Get("environment"), Select: true,
			Options: selectOptions([]string{"production", "staging", "test", "development", "unknown"}, q.Get("environment"))},
		{Name: "criticality", Label: "Criticality", Value: q.Get("criticality"), Select: true,
			Options: selectOptions([]string{"critical", "high", "normal", "low", "unknown"}, q.Get("criticality"))},
		{Name: "exposure", Label: "Exposure", Value: q.Get("exposure"), Select: true,
			Options: selectOptions([]string{"internet", "internal", "isolated", "unknown"}, q.Get("exposure"))},
		{Name: "owner", Label: "Owner id", Value: q.Get("owner")},
		{Name: "source", Label: "Source", Value: q.Get("source")},
	}
	return filterBarView{
		Action:       "/inventory",
		Fields:       fields,
		CanonicalURL: "/inventory?" + canonicalFilters(q, inventoryFilterNames),
		Summary:      filterSummary(fields),
	}
}

// toSourceRows maps the source-monitor read onto view rows (ordered by name).
func toSourceRows(sources []application.SourceStatus) []sourceRow {
	rows := make([]sourceRow, 0, len(sources))
	for _, s := range sources {
		status := s.LastRunStatus
		if status == "" {
			status = "never"
		}
		lastRun := ""
		if !s.LastRunAt.IsZero() {
			lastRun = formatTimestamp(s.LastRunAt)
		}
		dataAge := ""
		if s.HasDataAge {
			dataAge = formatDuration(s.DataAge)
		}
		rows = append(rows, sourceRow{
			ID: s.ID, Name: s.Name, Type: s.Type, Status: status, StatusLabel: status,
			LastRunAt: lastRun, DataAge: dataAge,
			ErrorCount: s.ErrorCount, OpenQuarantine: s.OpenQuarantine, Degraded: s.Degraded,
		})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows
}

// toTimelineRows maps the signal audit timeline onto view rows. The order is
// the use-case order (occurred_at then id) — presentation never re-sorts a
// timeline.
func toTimelineRows(events []application.AuditEvent) []timelineRow {
	rows := make([]timelineRow, 0, len(events))
	for _, ev := range events {
		actor := ev.ActorDisplayName
		if actor == "" {
			actor = ev.ActorID
		}
		rows = append(rows, timelineRow{
			OccurredAt: formatTimestamp(ev.OccurredAt),
			ActorType:  ev.ActorType,
			Actor:      actor,
			Action:     ev.Action,
		})
	}
	return rows
}

// formatTimestamp renders a monitor/timeline instant in the operator-facing
// UTC form (the adapter reads only the injected clock's instants).
func formatTimestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// formatDuration renders a data age in the compact Go form (e.g. "3h0m0s"),
// rounded to whole seconds.
func formatDuration(d time.Duration) string {
	return d.Round(time.Second).String()
}

// toImportView maps the application staged-import view onto the template view.
func toImportView(imp application.InventoryImport) *importView {
	problems := make([]problemRow, 0, len(imp.Problems))
	for _, p := range imp.Problems {
		problems = append(problems, problemRow{Row: p.Line, Column: p.Column, Message: p.Reason})
	}
	return &importView{
		ID:                imp.ID,
		Status:            string(imp.Status),
		Rows:              imp.Rows,
		ErrorCount:        imp.ErrorCount,
		WarningCount:      imp.WarningCount,
		AssetsCreated:     imp.AssetsCreated,
		AssetsUpdated:     imp.AssetsUpdated,
		ComponentsCreated: imp.ComponentsCreated,
		ComponentsUpdated: imp.ComponentsUpdated,
		Problems:          problems,
		Committable:       imp.Status == application.InventoryImportPending,
	}
}
