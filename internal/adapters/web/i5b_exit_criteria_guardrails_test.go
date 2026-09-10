package web

// I5b exit-criterion proof (b): the §11.2 UX-guardrail checklist, consolidated
// into one automated gate (ARCH-006 §4/§8b). Every row reuses the exact
// DEV-102 assertion (guardrails_test.go) as the gate, and the closing
// stale-version check pins the ch. 7.3 "changed by another user" surfacing that
// ARCH-006 §4 lists alongside the six rows. This is one half of the I5b exit
// criterion ("UX guardrails from ch. 11.2 met"); the channel-parity half lives
// in cmd/risksignal and the fault-injection proofs beside it.

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application"
)

// TestI5bExitCriteriaUXGuardrails runs the complete §11.2 checklist as one
// gate over the real templates/assets served by the adapter.
func TestI5bExitCriteriaUXGuardrails(t *testing.T) {
	h := newTestWeb(t, sampleFake(), allRoles())

	t.Run("row 1 priority not colour-only", func(t *testing.T) {
		assertGuardrailPriorityColourIndependent(t, h)
	})
	t.Run("row 2 confidence vocabulary", func(t *testing.T) {
		assertGuardrailConfidenceVocabulary(t, h)
	})
	t.Run("row 3 destructive confirmation", func(t *testing.T) {
		assertGuardrailDestructiveConfirmation(t, h)
	})
	t.Run("row 4 filters in the URL", func(t *testing.T) {
		assertGuardrailFiltersInURL(t, h)
	})
	t.Run("row 5 accessibility landmarks", func(t *testing.T) {
		assertGuardrailAccessibility(t, h)
	})
	t.Run("row 6 progressive SLA fragment", func(t *testing.T) {
		assertGuardrailSLACountdownFragment(t, h)
	})

	// The house rule beside the checklist: a stale expected_version is a 409
	// that re-renders the fresh state with a visible "changed by another user"
	// notice and the new version — never a silent overwrite (ch. 7.3).
	t.Run("stale version surfaces a 409 with the fresh version", func(t *testing.T) {
		svc := sampleFake()
		svc.ackErr = application.ConflictError("acknowledge_signal", errors.New("version mismatch"))
		conflict := newTestWeb(t, svc, allRoles())

		rec := get(t, conflict, "/signals/s1")
		csrf := csrfFrom(t, rec)
		rec = postForm(t, conflict, "/signals/s1/acknowledge", csrf, map[string]string{"expected_version": "1"})
		if rec.Code != http.StatusConflict {
			t.Fatalf("stale acknowledge = %d, want 409", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "changed by another user") {
			t.Errorf("409 must carry the visible conflict notice")
		}
		if !strings.Contains(body, `data-version="2"`) {
			t.Errorf("409 must re-render with the fresh version")
		}
	})
}
