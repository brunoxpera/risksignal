package config

// I6 exit-criteria consolidation (ARCH-007 §8/§12, WP-6.12 / DEV-134): the
// private-demo bypass lockdown (§4.3) as an `I6ExitCriteria`-named gate. Each
// subtest delegates to the landed proof (WP-6.11 / DEV-131) — the validation
// is not re-implemented.

import "testing"

// TestI6ExitCriteriaDemoLockdown is the ARCH-007 §8 acceptance case: a `demo`
// environment with the auth bypass enabled fails at startup (non-zero exit),
// and the demo overlay carries no bypass env.
func TestI6ExitCriteriaDemoLockdown(t *testing.T) {
	t.Run("demo refuses the bypass at startup", func(t *testing.T) {
		TestArch007DemoStartupLockdown(t)
	})
	t.Run("demo overlay carries no bypass env", func(t *testing.T) {
		TestDemoOverlayCarriesNoBypassEnv(t)
	})
}
