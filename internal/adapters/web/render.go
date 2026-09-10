// Template loading and rendering of the web adapter (ARCH-006 §3.2).
//
// Templates are parsed ONCE at startup from the embedded FS (web/templates via
// the webassets package) and rendered per request; production never reloads
// them. Each page is its own clone of the base layout + shared partials, so
// page-local {{define "content"}} blocks cannot collide across pages.
package web

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"time"
)

// webCSP is the restrictive content-security policy of the server-rendered
// pages (ARCH-006 §3.2 "CSP stays restrictive"): no inline styles or scripts,
// same-origin assets only. It overrides the API chain's default-src 'none' for
// HTML responses so the versioned stylesheet and progressive script load.
const webCSP = "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// pageFiles are the page templates, each rendered against the base layout.
var pageFiles = []string{
	"dashboard",
	"triage",
	"signal-detail",
	"source-monitor",
	"inventory",
	"inventory-import",
	"admin-users",
	"admin-roles",
	"error",
}

// partialGlob matches the shared partials parsed into every page.
const partialGlob = "templates/_*.html"

// templateSet holds the parsed, ready-to-execute template sets.
type templateSet struct {
	pages map[string]*template.Template
	frag  *template.Template
}

// templateFuncs are the presentation-only helpers available to templates. They
// compute labels and symbols, never rights or business rules.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"asset":           func(name string) string { return "/assets/" + name },
		"prioritySymbol":  prioritySymbol,
		"confidenceLabel": confidenceLabel,
		"statusLabel":     statusLabel,
		"roleLabel":       roleLabel,
		"utc": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.UTC().Format(time.RFC3339)
		},
	}
}

// loadTemplates parses every page against the base layout + partials, and the
// SLA fragment set separately, over the template FS supplied by the caller
// (the embedded web/templates tree in production). It is called once by New.
func loadTemplates(templatesFS fs.FS) (*templateSet, error) {
	set := &templateSet{pages: make(map[string]*template.Template, len(pageFiles))}
	for _, page := range pageFiles {
		t, err := template.New("layout").Funcs(templateFuncs()).ParseFS(
			templatesFS,
			"templates/base.html",
			partialGlob,
			"templates/"+page+".html",
		)
		if err != nil {
			return nil, fmt.Errorf("web: parse template %q: %w", page, err)
		}
		set.pages[page] = t
	}
	frag, err := template.New("fragment").Funcs(templateFuncs()).ParseFS(templatesFS, "templates/_sla_badge.html")
	if err != nil {
		return nil, fmt.Errorf("web: parse SLA fragment: %w", err)
	}
	set.frag = frag
	return set, nil
}

// assets returns the asset tree rooted at "assets" (the embedded web/assets
// tree in production).
func (w *Web) assets() fs.FS {
	sub, err := fs.Sub(w.assetsFS, "assets")
	if err != nil {
		panic("web: assets subtree: " + err.Error())
	}
	return sub
}

// renderPage renders pageName with data at the given status. It buffers the
// render first so a template error never writes a partial response.
func (w *Web) renderPage(rw http.ResponseWriter, status int, pageName string, data any) {
	t, ok := w.templates.pages[pageName]
	if !ok {
		w.logger.Error("web: unknown page", "page", pageName)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base", data); err != nil {
		w.logger.Error("web: render failed", "page", pageName, "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Content-Security-Policy", webCSP)
	rw.WriteHeader(status)
	_, _ = rw.Write(buf.Bytes())
}

// renderFragment renders the SLA-countdown fragment (ARCH-006 §4 row 6).
func (w *Web) renderFragment(rw http.ResponseWriter, rows []slaView) {
	var buf bytes.Buffer
	if err := w.templates.frag.ExecuteTemplate(&buf, "_sla_list", rows); err != nil {
		w.logger.Error("web: render SLA fragment", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Content-Security-Policy", webCSP)
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(buf.Bytes())
}
