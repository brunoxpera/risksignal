// Package webassets embeds the server-rendered web templates and the
// versioned front-end assets the risksignal-server serves (ARCH-006 §3.2,
// ADR-004).
//
// The templates and assets live at the repository root (web/templates,
// web/assets) so the build artifact is inspectable without a Go toolchain;
// this thin package makes them available to the web adapter
// (internal/adapters/web) and to cmd/risksignal-server through go:embed. The
// adapter parses the templates once at startup (template.ParseFS) and never
// reloads them in production.
package webassets

import "embed"

// Templates is the embedded template tree (web/templates/*.html): the base
// layout, the per-view templates and the shared partials.
//
//go:embed templates/*.html
var Templates embed.FS

// Assets is the embedded front-end asset tree (web/assets/*): the versioned
// stylesheet and the small progressive-enhancement script. WP-5b.07 turns the
// stylesheet into a content-hashed build artifact; the files are committed as
// the current build so the web adapter can serve them.
//
//go:embed assets/*
var Assets embed.FS
