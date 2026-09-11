package main

// I6 exit-criteria consolidation (ARCH-007 §4.3/§5/§8/§12, WP-6.12 / DEV-134):
// the composition-root acceptance proofs at cmd/risksignal-server — the
// private-demo smoke (§4.4 step 5) and the observability wiring (NFR-010) — as
// `I6ExitCriteria`-named gates. Each subtest delegates to the landed proof
// (WP-6.08/6.11 / DEV-120/132); the proofs are not re-implemented.

import "testing"

// TestI6ExitCriteriaDemoSmoke is the ARCH-007 §8/§4.4 step-5 acceptance case:
// login (mock OIDC), an API read, the source monitor and one signal read run
// against the real composition root over a migrated, demo-seeded database.
func TestI6ExitCriteriaDemoSmoke(t *testing.T) {
	t.Run("demo step-5 flow (login, API, source monitor, signal read)", func(t *testing.T) {
		TestDemoSmokeStep5Flow(t)
	})
}

// TestI6ExitCriteriaObservabilityCompositionRoot is the NFR-010 acceptance
// case at the server composition root: the /metrics exposition is served on its
// own internal listener (never the public handler) and a public request records
// the HTTP families on the shared §16.2 registry.
func TestI6ExitCriteriaObservabilityCompositionRoot(t *testing.T) {
	t.Run("the metrics endpoint is not on the public handler", func(t *testing.T) {
		TestMetricsEndpointNotOnPublicHandler(t)
	})
	t.Run("a public request records the HTTP families", func(t *testing.T) {
		TestPublicRequestRecordsHTTPFamilies(t)
	})
}
