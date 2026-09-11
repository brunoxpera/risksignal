package fetchguard_test

// I6 exit-criteria consolidation (ARCH-007 §7 control 1 / §12 fault injection
// (d), WP-6.12 / DEV-134): the SSRF controls of the source fetch path as one
// `I6ExitCriteria`-named gate. Each subtest delegates to the landed guard
// proof (WP-6.10 / DEV-123) — the SSRF logic is not re-implemented.

import "testing"

// TestI6ExitCriteriaSSRFRejected is the ARCH-007 §7 control-1 acceptance case:
// loopback/link-local/private/multicast/unspecified targets and a
// redirect-to-private chain are rejected (each redirect hop re-checked, the hop
// limit enforced, a nil client failing secure), while an allow-listed host and
// the explicit local private target succeed.
func TestI6ExitCriteriaSSRFRejected(t *testing.T) {
	t.Run("address classification", func(t *testing.T) {
		TestAllowedIP(t)
	})
	t.Run("blocked targets are refused", func(t *testing.T) {
		TestBlockedTargetsRefused(t)
	})
	t.Run("disallowed scheme is refused", func(t *testing.T) {
		TestSchemeNotAllowed(t)
	})
	t.Run("redirect to a blocked hop is refused", func(t *testing.T) {
		TestRedirectBlockedHopRejected(t)
	})
	t.Run("redirect hop limit is enforced", func(t *testing.T) {
		TestRedirectLimitExceeded(t)
	})
	t.Run("redirect to unspecified is refused", func(t *testing.T) {
		TestRedirectToUnspecifiedRejected(t)
	})
	t.Run("nil client fails secure", func(t *testing.T) {
		TestNilClientIsGuardedFailSecure(t)
	})
	t.Run("allowed private target succeeds (local escape hatch)", func(t *testing.T) {
		TestAllowedPrivateTargetSucceeds(t)
	})
}
