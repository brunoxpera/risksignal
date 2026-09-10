package web

import (
	"net/http"
	"strings"
	"testing"
)

// §4 row 1 — priority is never conveyed by colour alone: text, a symbol and a
// machine-readable data-priority attribute are all present, and they survive
// CSS removal (they are plain text/attributes).
func TestPriorityBadgeNotColourOnly(t *testing.T) {
	h := newTestWeb(t, sampleFake(), allRoles())
	body := get(t, h, "/signals").Body.String()

	if !strings.Contains(body, `data-priority="P1"`) {
		t.Errorf("priority badge must carry data-priority")
	}
	if !strings.Contains(body, "▲") {
		t.Errorf("priority badge must carry the symbol (survives CSS removal)")
	}
	if !strings.Contains(body, "P1") {
		t.Errorf("priority badge must carry the text P1")
	}
}

// §4 row 2 — confidence uses the explicit vocabulary, never an unqualified
// "affected".
func TestConfidenceVocabulary(t *testing.T) {
	h := newTestWeb(t, sampleFake(), allRoles())
	body := get(t, h, "/signals/s1").Body.String()
	if !strings.Contains(body, "confirmed") {
		t.Errorf("high confidence must render as %q", "confirmed")
	}
	// "affected" may appear only as the qualified status "not affected"; the
	// machine value not_affected is a status enum, not a statement.
	lower := strings.ReplaceAll(strings.ToLower(body), "not_affected", "")
	for i := 0; ; {
		j := strings.Index(lower[i:], "affected")
		if j < 0 {
			break
		}
		abs := i + j
		if !strings.HasSuffix(strings.TrimRight(lower[:abs], " "), "not") {
			t.Errorf("the view must not use unqualified %q wording", "affected")
		}
		i = abs + len("affected")
	}
}

// §4 row 3 — destructive forms render target scope + a confirmation token, and
// the server rejects the POST without it.
func TestDestructiveConfirmation(t *testing.T) {
	h := newTestWeb(t, sampleFake(), allRoles())
	rec := get(t, h, "/signals/s1")
	csrf := csrfFrom(t, rec)
	page := rec.Body.String()

	if !strings.Contains(page, `data-target-scope=`) {
		t.Errorf("destructive forms must render the target scope")
	}
	if !strings.Contains(page, `name="confirm_token"`) {
		t.Errorf("destructive forms must render a confirmation token")
	}

	// A closed transition without the token is rejected server-side.
	rec = postForm(t, h, "/signals/s1/transition", csrf, map[string]string{
		"status": "resolved", "expected_version": "2", "reason": "done",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unconfirmed closed transition = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "confirmation token") {
		t.Errorf("rejection must explain the missing confirmation token")
	}

	// With the token it dispatches.
	rec = postForm(t, h, "/signals/s1/transition", csrf, map[string]string{
		"status": "resolved", "expected_version": "2", "reason": "done",
		"confirm_token": confirmToken("transition", "s1"),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed closed transition = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
}

// §4 row 4 — filters round-trip through the URL and are re-stated.
func TestFiltersRoundTrip(t *testing.T) {
	h := newTestWeb(t, sampleFake(), allRoles())
	body := get(t, h, "/signals?priority=P1&status=new").Body.String()

	if !strings.Contains(body, `<option value="P1" selected>`) {
		t.Errorf("the priority filter must round-trip into the selected option")
	}
	if !strings.Contains(body, `data-canonical-url="/signals?priority=P1&amp;status=new"`) {
		t.Errorf("the canonical URL must re-state the active filters")
	}
}

// §4 row 5 — semantic landmarks, labelled inputs and a visible-focus rule.
func TestAccessibilityLandmarks(t *testing.T) {
	h := newTestWeb(t, sampleFake(), allRoles())
	body := get(t, h, "/signals").Body.String()
	for _, want := range []string{"<main", "<nav", "<table", "<caption", "<label", "<button"} {
		if !strings.Contains(body, want) {
			t.Errorf("page must contain the semantic element %q", want)
		}
	}
	css := get(t, h, "/assets/app.css").Body.String()
	if !strings.Contains(css, ":focus") {
		t.Errorf("stylesheet must define a visible :focus style")
	}
}

// §4 row 6 — the P1/P2 SLA countdown updates via a fragment endpoint, not a
// full page reload.
func TestSLACountdownFragment(t *testing.T) {
	h := newTestWeb(t, sampleFake(), allRoles())

	// The fragment endpoint returns the partial.
	rec := get(t, h, "/signals/_sla")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /signals/_sla = %d, want 200", rec.Code)
	}
	frag := rec.Body.String()
	if !strings.Contains(frag, `id="sla-countdowns"`) || !strings.Contains(frag, `data-sla-id="s1"`) {
		t.Errorf("fragment must render the countdown container + rows: %s", frag)
	}

	// The triage page wires the endpoint for the progressive layer.
	page := get(t, h, "/signals").Body.String()
	if !strings.Contains(page, `data-sla-endpoint="/signals/_sla"`) {
		t.Errorf("triage page must expose the fragment endpoint")
	}
	if !strings.Contains(page, "/assets/app.js") {
		t.Errorf("triage page must load the progressive script")
	}
}
