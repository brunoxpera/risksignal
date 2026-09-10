// Session, CSRF and confirmation-token handling of the web adapter
// (ARCH-006 §3.2/§4 row 3).
package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// errNoIdentity marks a request whose context carries no authenticated
// identity: fail closed (403), there is never a fallback identity.
var errNoIdentity = errors.New("web: no authenticated identity")

// csrfField is the hidden form field name of the per-session CSRF token.
const csrfField = "csrf_token"

// confirmField is the hidden form field name of the destructive-action
// confirmation token (ARCH-006 §4 row 3).
const confirmField = "confirm_token"

// principalFor resolves the request's authenticated principal: the identity
// from the injected context reader, the audit actor through the application
// ResolveActor, and the principal's current roles for the role-dependent
// navigation. It never decides rights — the use cases do.
func (w *Web) principalFor(r *http.Request) (principalView, application.Actor, error) {
	ctx := r.Context()
	id, ok := w.identity(ctx)
	if !ok {
		return principalView{}, application.Actor{}, errNoIdentity
	}
	actor, err := w.svc.ResolveActor(ctx, id)
	if err != nil {
		return principalView{}, application.Actor{}, err
	}
	var roles []domain.Role
	if actor.Type == application.ActorTypeUser && actor.ID != "" {
		roles, err = w.roles.RolesByUserID(ctx, actor.ID)
		if err != nil {
			return principalView{}, application.Actor{}, err
		}
	}
	pv := principalView{
		Authenticated: true,
		UserID:        actor.ID,
		DisplayName:   actor.DisplayName,
		Roles:         roles,
	}
	return pv, actor, nil
}

// csrfToken returns the per-session CSRF token, minting and setting the
// SameSite cookie on first use (ARCH-006 §3.2).
func (w *Web) csrfToken(rw http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(w.csrfCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	token := newToken()
	http.SetCookie(rw, &http.Cookie{ //nolint:gosec // SameSite=Lax + HttpOnly; Secure is set in production
		Name:     w.csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   w.secure,
	})
	return token
}

// csrfValid reports whether the request's hidden CSRF field matches the
// per-session cookie in constant time (ARCH-006 §3.2). A missing cookie or
// field is invalid.
func (w *Web) csrfValid(r *http.Request) bool {
	c, err := r.Cookie(w.csrfCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	got := r.PostFormValue(csrfField)
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(c.Value)) == 1
}

// confirmToken is the deterministic, server-computed confirmation token of a
// destructive action (ARCH-006 §4 row 3). The rendered form carries it as a
// hidden field; a POST without the matching token is rejected server-side,
// independent of any client-side confirmation.
func confirmToken(action, target string) string {
	sum := sha256.Sum256([]byte(action + "\x00" + target))
	return hex.EncodeToString(sum[:])[:16]
}

// confirmValid reports whether the submitted confirmation token matches the
// expected one for (action, target).
func confirmValid(r *http.Request, action, target string) bool {
	got := r.PostFormValue(confirmField)
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(confirmToken(action, target))) == 1
}

// newToken returns a 256-bit opaque, URL-safe token.
func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("web: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// newChrome assembles the page chrome shared by every view.
func (w *Web) newChrome(title, active string, pv principalView, flash *flashMessage, csrf string) chrome {
	return chrome{
		Title:     title,
		Nav:       buildNav(pv.Roles, active),
		Principal: pv,
		Flash:     flash,
		CSRFToken: csrf,
	}
}

// statusForError maps an application error onto an HTTP status (ARCH-006 §3.1
// error semantics): validation→400, forbidden→403, not-found→404,
// conflict→409, anything else→500.
func statusForError(err error) int {
	if errors.Is(err, errNoIdentity) {
		return http.StatusForbidden
	}
	switch kind, _ := application.ErrorKindOf(err); kind {
	case application.KindValidation:
		return http.StatusBadRequest
	case application.KindForbidden:
		return http.StatusForbidden
	case application.KindNotFound:
		return http.StatusNotFound
	case application.KindConflict:
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

// errorMessage is the operator-facing message of an application error. The
// infrastructure class is generic — the cause never reaches the client.
func errorMessage(err error) string {
	switch kind, _ := application.ErrorKindOf(err); kind {
	case application.KindInfra:
		return "The operation failed. Please retry."
	default:
		return err.Error()
	}
}

// fragmentEndpoint is the URL of the SLA-countdown fragment endpoint, carrying
// the active triage filters so the progressive refresh keeps them (ARCH-006 §4
// rows 4 and 6).
func fragmentEndpoint(filters string) string {
	if filters == "" {
		return "/signals/_sla"
	}
	return "/signals/_sla?" + filters
}
