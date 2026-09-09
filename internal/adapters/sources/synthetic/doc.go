// Synthetic source adapter — WP-1b.05 (task DEV-019).
//
// This package holds the deterministic reference fixture of the I1b
// walking skeleton; see the package comment of fixture.go for the design.
package synthetic

import "embed"

// fixtureFS embeds the reference document (fixtures/reference.json) so the
// fixture is part of the binary and the tests: one versioned source of
// truth for the demo inventory and the reference cases C1–C6 + E1
// (ARCH-001 §3).
//
//go:embed fixtures/reference.json
var fixtureFS embed.FS
