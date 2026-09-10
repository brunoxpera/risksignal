// `risksignal auth ...` (concept ch. 11.3/12.1, ARCH-005 §2, ARCH-006 §5,
// WP-5b.08): the CLI login plumbing for remote/API automation. It obtains an
// OIDC token set through the adapter's Device Authorization Flow (or the
// loopback Authorization Code + PKCE flow) and persists the tokens in the
// OS-user-scoped credential store (internal/platform/credstore). The tokens
// are never logged or rendered: the CLI prints only the non-secret identity
// (issuer, subject, display name, expiry) and the access/refresh tokens stay
// inside the store (NFR-006/NFR-014).
//
//	risksignal auth login  [--issuer <url>] [--flow device|loopback]
//	risksignal auth status [--issuer <url>]
//	risksignal auth logout [--issuer <url>]
//
// `auth login` is the only command that runs an interactive provider flow
// (the device code or the loopback browser callback); it prompts for nothing
// itself — the provider's approval page is the interaction. `auth status` and
// `auth logout` are non-interactive and read/remove the stored credential.
// The acting identity of the other commands comes from --as or the configured
// bypass principal; auth only manages the stored login.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/adapters/oidc"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/config"
	"github.com/brunoxpera/risksignal/internal/platform/credstore"
)

// authLoginTimeout bounds the interactive login (the device-code expiry is
// provider-driven; this only keeps a blackholed provider from hanging the
// CLI forever).
const authLoginTimeout = 5 * time.Minute

// authSubcommands lists the supported subcommands for the error message.
const authSubcommands = "login, status, logout"

// authStoreFactory opens the CLI credential store. It is a package variable so
// the tests can point the store at a temp file (or a failing fake) without a
// network or an interactive flow.
var authStoreFactory = func() (credstore.Store, error) { return credstore.Open() }

// authLoginRunner performs the interactive OIDC login and returns the token
// set. It is a package variable so the tests can substitute a deterministic,
// network-free login; runOIDCLogin is the real device/loopback implementation.
var authLoginRunner = runOIDCLogin

// runAuth dispatches `risksignal auth <subcommand>`.
func runAuth(e *cmdEnv, args []string) int {
	if len(args) == 0 {
		return e.emit("auth", e.fail(exitValidation, classValidation, "missing subcommand (supported: %s)", authSubcommands))
	}
	command := "auth " + args[0]
	switch args[0] {
	case "login":
		return e.emit(command, e.cmdAuthLogin(args[1:]))
	case "status":
		return e.emit(command, e.cmdAuthStatus(args[1:]))
	case "logout":
		return e.emit(command, e.cmdAuthLogout(args[1:]))
	default:
		return e.emit(command, e.fail(exitValidation, classValidation, "unknown subcommand (supported: %s)", authSubcommands))
	}
}

// cmdAuthLogin runs `risksignal auth login [--issuer <url>]
// [--flow device|loopback]`: it performs the provider login and stores the
// tokens. Success renders the non-secret identity only; the tokens never
// reach stdout/stderr.
func (e *cmdEnv) cmdAuthLogin(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal auth login [--issuer <url>] [--flow device|loopback]")
	issuer := fs.String("issuer", "", "OIDC issuer (default: the configured oidc.issuer)")
	flow := fs.String("flow", "device", "login flow: device (RFC 8628) or loopback (browser callback)")
	if err := fs.Parse(flagTokensFirst(args)); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	flowValue := strings.TrimSpace(*flow)
	if flowValue != "device" && flowValue != "loopback" {
		return e.fail(exitValidation, classValidation, "invalid --flow %q (device or loopback)", *flow)
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	issuerValue := strings.TrimSpace(*issuer)
	if issuerValue == "" {
		issuerValue = strings.TrimSpace(cfg.OIDC.Issuer)
	}
	if issuerValue == "" {
		return e.fail(exitValidation, classValidation, "no OIDC issuer configured; pass --issuer or set oidc.issuer")
	}
	if strings.TrimSpace(cfg.OIDC.ClientID) == "" {
		return e.fail(exitValidation, classValidation, "no OIDC client id configured (oidc.client_id is mandatory for login)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), authLoginTimeout)
	defer cancel()
	tokens, err := authLoginRunner(ctx, cfg, issuerValue, flowValue, e.stderr)
	if err != nil {
		return authLoginErrorOutcome(err)
	}

	cred := credstore.Credential{
		Issuer:       issuerValue,
		SubjectID:    tokens.Identity.SubjectID,
		DisplayName:  tokens.Identity.DisplayName,
		Email:        tokens.Identity.Email,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		IDToken:      tokens.IDToken,
		TokenType:    tokens.TokenType,
		ExpiresAt:    tokens.ExpiresAt,
		ObtainedAt:   time.Now().UTC(),
	}
	store, err := authStoreFactory()
	if err != nil {
		return e.fail(exitInfrastructure, classInfrastructure, "cannot open the credential store: %v", err)
	}
	if err := store.Save(cred); err != nil {
		return e.fail(exitInfrastructure, classInfrastructure, "cannot store the login: %v", err)
	}

	view := authLoginView{
		Issuer:      issuerValue,
		SubjectID:   tokens.Identity.SubjectID,
		DisplayName: tokens.Identity.DisplayName,
		Email:       tokens.Identity.Email,
		TokenType:   tokens.TokenType,
		ExpiresAt:   timePtr(tokens.ExpiresAt),
		Stored:      true,
	}
	if e.format == formatText {
		printAuthLogin(e.stdout, view)
	}
	return e.ok(view)
}

// cmdAuthStatus runs `risksignal auth status [--issuer <url>]`: it reports the
// stored login's non-secret identity. A missing or expired credential is an
// authentication failure (exit 3) so automation can branch without parsing
// output.
func (e *cmdEnv) cmdAuthStatus(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal auth status [--issuer <url>]")
	issuer := fs.String("issuer", "", "OIDC issuer (default: the configured oidc.issuer)")
	if err := fs.Parse(flagTokensFirst(args)); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	store, cred, out := e.loadStoredCredential(*issuer)
	if !out.ok() {
		return out
	}
	_ = store
	if cred.Expired(time.Now().UTC()) {
		return e.fail(exitAuthentication, classAuthentication, "stored login for %s expired at %s; run 'risksignal auth login'",
			cred.Issuer, cred.ExpiresAt.UTC().Format(time.RFC3339))
	}
	view := authStatusView{
		Issuer:      cred.Issuer,
		SubjectID:   cred.SubjectID,
		DisplayName: cred.DisplayName,
		Email:       cred.Email,
		ExpiresAt:   timePtr(cred.ExpiresAt),
		Expired:     false,
	}
	if e.format == formatText {
		printAuthStatus(e.stdout, view)
	}
	return e.ok(view)
}

// cmdAuthLogout runs `risksignal auth logout [--issuer <url>]`: it removes the
// stored credential (the whole store when neither --issuer nor oidc.issuer is
// configured). It is idempotent — a missing credential is a success with
// removed=0, never a prompt.
func (e *cmdEnv) cmdAuthLogout(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal auth logout [--issuer <url>]")
	issuer := fs.String("issuer", "", "OIDC issuer to forget (default: the configured oidc.issuer, else every stored login)")
	if err := fs.Parse(flagTokensFirst(args)); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	store, err := authStoreFactory()
	if err != nil {
		return e.fail(exitInfrastructure, classInfrastructure, "cannot open the credential store: %v", err)
	}
	issuerValue := strings.TrimSpace(*issuer)
	if issuerValue == "" {
		if cfg, out := loadConfig(e); out.ok() {
			issuerValue = strings.TrimSpace(cfg.OIDC.Issuer)
		}
	}

	view := authLogoutView{}
	if issuerValue != "" {
		removed, err := store.Delete(issuerValue)
		if err != nil {
			return e.fail(exitInfrastructure, classInfrastructure, "cannot update the credential store: %v", err)
		}
		if removed {
			view.Removed = 1
			view.Issuers = []string{issuerValue}
		}
	} else {
		issuers, err := store.Issuers()
		if err != nil {
			return e.fail(exitInfrastructure, classInfrastructure, "cannot read the credential store: %v", err)
		}
		for _, iss := range issuers {
			removed, err := store.Delete(iss)
			if err != nil {
				return e.fail(exitInfrastructure, classInfrastructure, "cannot update the credential store: %v", err)
			}
			if removed {
				view.Removed++
				view.Issuers = append(view.Issuers, iss)
			}
		}
	}
	if view.Issuers == nil {
		view.Issuers = []string{}
	}
	if e.format == formatText {
		printAuthLogout(e.stdout, view)
	}
	return e.ok(view)
}

// loadStoredCredential resolves the issuer and returns the stored credential.
// A missing credential is an authentication failure (exit 3): the CLI has no
// valid login. An empty issuer (no override, no configured issuer) resolves
// against the single stored login; zero or several stored logins without an
// issuer is a validation failure.
func (e *cmdEnv) loadStoredCredential(issuerFlag string) (credstore.Store, credstore.Credential, outcome) {
	store, err := authStoreFactory()
	if err != nil {
		return nil, credstore.Credential{}, e.fail(exitInfrastructure, classInfrastructure, "cannot open the credential store: %v", err)
	}
	issuerValue := strings.TrimSpace(issuerFlag)
	if issuerValue == "" {
		if cfg, out := loadConfig(e); out.ok() {
			issuerValue = strings.TrimSpace(cfg.OIDC.Issuer)
		}
	}
	if issuerValue == "" {
		issuers, err := store.Issuers()
		if err != nil {
			return nil, credstore.Credential{}, e.fail(exitInfrastructure, classInfrastructure, "cannot read the credential store: %v", err)
		}
		switch len(issuers) {
		case 0:
			return store, credstore.Credential{}, e.fail(exitAuthentication, classAuthentication, "not logged in; run 'risksignal auth login'")
		case 1:
			issuerValue = issuers[0]
		default:
			return store, credstore.Credential{}, e.fail(exitValidation, classValidation, "several logins stored; pass --issuer (one of: %s)", strings.Join(issuers, ", "))
		}
	}
	cred, ok, err := store.Load(issuerValue)
	if err != nil {
		return nil, credstore.Credential{}, e.fail(exitInfrastructure, classInfrastructure, "cannot read the credential store: %v", err)
	}
	if !ok {
		return store, credstore.Credential{}, e.fail(exitAuthentication, classAuthentication, "not logged in for %s; run 'risksignal auth login'", issuerValue)
	}
	return store, cred, outcome{}
}

// authLoginErrorOutcome maps a login failure onto the exit-code contract: a
// provider denial / expired device code / invalid token is an authentication
// failure (exit 3); everything else (unreachable provider, transport) is
// infrastructure (exit 6).
func authLoginErrorOutcome(err error) outcome {
	switch {
	case errors.Is(err, oidc.ErrAccessDenied),
		errors.Is(err, oidc.ErrExpiredToken),
		errors.Is(err, oidc.ErrInvalidToken):
		return outcome{code: exitAuthentication, class: classAuthentication, message: err.Error()}
	default:
		return outcome{code: exitInfrastructure, class: classInfrastructure, message: err.Error()}
	}
}

// runOIDCLogin is the real login runner: it builds the OIDC adapter from the
// configuration and drives the chosen flow. report receives the device-code /
// loopback progress on stderr; the tokens are returned to the caller only.
func runOIDCLogin(ctx context.Context, cfg *config.Config, issuer, flow string, progress io.Writer) (oidc.Tokens, error) {
	v, err := oidc.New(oidcConfigOf(cfg.OIDC, issuer))
	if err != nil {
		return oidc.Tokens{}, err
	}
	switch flow {
	case "loopback":
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return oidc.Tokens{}, fmt.Errorf("oidc: bind loopback listener: %w", err)
		}
		defer func() { _ = ln.Close() }()
		return v.LoopbackLoginWithTokens(ctx, ln, func(authURL string) error {
			fmt.Fprintf(progress, "Open this URL in a browser to sign in:\n%s\n", authURL)
			return nil
		})
	default: // device
		return v.DeviceLoginWithTokens(ctx, func(dev oidc.DeviceAuthorization) {
			fmt.Fprintf(progress, "To sign in, visit %s and enter the code %s\n", dev.VerificationURI, dev.UserCode)
		})
	}
}

// oidcConfigOf maps the platform oidc.* keys onto the OIDC adapter
// configuration, overriding the issuer when the operator named one. The CLI
// login is a public client: no client secret is resolved here.
func oidcConfigOf(o config.OIDC, issuer string) oidc.Config {
	var mappings map[string]domain.Role
	if len(o.RoleMappings) > 0 {
		mappings = make(map[string]domain.Role, len(o.RoleMappings))
		for claim, role := range o.RoleMappings {
			mappings[claim] = domain.Role(role)
		}
	}
	if strings.TrimSpace(issuer) != "" {
		o.Issuer = issuer
	}
	return oidc.Config{
		Issuer:       o.Issuer,
		ClientID:     o.ClientID,
		Audience:     o.Audience,
		RedirectURL:  o.RedirectURL,
		Scopes:       o.Scopes,
		RolesClaim:   o.RolesClaim,
		RoleMappings: mappings,
	}
}

// authLoginView is the machine-readable payload of a successful login: the
// non-secret identity only — never the tokens.
type authLoginView struct {
	Issuer      string     `json:"issuer"`
	SubjectID   string     `json:"subject_id"`
	DisplayName string     `json:"display_name,omitempty"`
	Email       string     `json:"email,omitempty"`
	TokenType   string     `json:"token_type,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Stored      bool       `json:"stored"`
}

// authStatusView is the machine-readable payload of a status query.
type authStatusView struct {
	Issuer      string     `json:"issuer"`
	SubjectID   string     `json:"subject_id"`
	DisplayName string     `json:"display_name,omitempty"`
	Email       string     `json:"email,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Expired     bool       `json:"expired"`
}

// authLogoutView is the machine-readable payload of a logout.
type authLogoutView struct {
	Removed int      `json:"removed"`
	Issuers []string `json:"issuers"`
}

// timePtr returns a pointer to t, or nil when t is the zero time (the wire
// null for an unstated value).
func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// printAuthLogin renders a successful login (non-secret identity only).
func printAuthLogin(w io.Writer, v authLoginView) {
	fmt.Fprintf(w, "auth login: authenticated as %s (%s)\n", v.SubjectID, v.Issuer)
	if v.ExpiresAt != nil {
		fmt.Fprintf(w, "  access token expires at %s\n", v.ExpiresAt.UTC().Format(time.RFC3339))
	}
	fmt.Fprintln(w, "  tokens stored in the OS credential store (never logged)")
}

// printAuthStatus renders a status query.
func printAuthStatus(w io.Writer, v authStatusView) {
	fmt.Fprintf(w, "auth status: logged in as %s (%s)\n", v.SubjectID, v.Issuer)
	if v.ExpiresAt != nil {
		fmt.Fprintf(w, "  access token expires at %s\n", v.ExpiresAt.UTC().Format(time.RFC3339))
	}
}

// printAuthLogout renders a logout.
func printAuthLogout(w io.Writer, v authLogoutView) {
	if v.Removed == 0 {
		fmt.Fprintln(w, "auth logout: no stored login to remove")
		return
	}
	fmt.Fprintf(w, "auth logout: removed %d stored login(s): %s\n", v.Removed, strings.Join(v.Issuers, ", "))
}
