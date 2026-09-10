package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// callbackPath is the loopback callback path of the CLI browser login.
const callbackPath = "/callback"

// AuthRequest is the per-login state the Authorization Code Flow generates
// before redirecting to the issuer and must verify on the callback
// (ARCH-005 §2): the CSRF state, the OIDC nonce and the PKCE verifier. It is
// kept server-side (or in a short-lived, integrity-protected cookie) between
// the redirect and the callback.
type AuthRequest struct {
	// RedirectURL is the callback URL registered at the issuer; it is echoed
	// in the authorization request and the code exchange.
	RedirectURL string
	// State is the opaque CSRF value the issuer returns and the callback
	// checks.
	State string
	// Nonce is the OIDC replay guard bound into the id token and checked on
	// the callback.
	Nonce string
	// CodeVerifier is the PKCE code verifier: its S256 challenge travels in
	// the authorization request and the verifier in the code exchange.
	CodeVerifier string
}

// NewAuthRequest generates a fresh login state: a random state, a random nonce
// and a random PKCE verifier. redirectURL defaults to the configured
// oidc.redirect_url when empty.
func (v *Verifier) NewAuthRequest(redirectURL string) (AuthRequest, error) {
	redirectURL = strings.TrimSpace(redirectURL)
	if redirectURL == "" {
		redirectURL = v.cfg.RedirectURL
	}
	state, err := randomToken(32)
	if err != nil {
		return AuthRequest{}, err
	}
	nonce, err := randomToken(32)
	if err != nil {
		return AuthRequest{}, err
	}
	verifier, err := randomToken(32)
	if err != nil {
		return AuthRequest{}, err
	}
	return AuthRequest{
		RedirectURL:  redirectURL,
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
	}, nil
}

// AuthorizationURL builds the authorization-endpoint URL of one login: the
// response type, client id, redirect, scopes, state, nonce and the S256 PKCE
// challenge.
func (v *Verifier) AuthorizationURL(ctx context.Context, req AuthRequest) (string, error) {
	doc, err := v.discover(ctx)
	if err != nil {
		return "", err
	}
	if doc.AuthorizationEndpoint == "" {
		return "", errors.New("oidc: discovery document has no authorization_endpoint")
	}
	u, err := url.Parse(doc.AuthorizationEndpoint)
	if err != nil {
		return "", errors.New("oidc: invalid authorization endpoint")
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", v.cfg.ClientID)
	q.Set("redirect_uri", req.RedirectURL)
	q.Set("scope", strings.Join(v.cfg.Scopes, " "))
	q.Set("state", req.State)
	q.Set("nonce", req.Nonce)
	q.Set("code_challenge", codeChallenge(req.CodeVerifier))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Exchange redeems an authorization code and returns the verified Identity
// (ARCH-005 §2). It enforces the callback checks: the returned state must
// equal the one in req (constant-time CSRF check), the id token's nonce must
// equal req.Nonce, and the token endpoint re-checks the PKCE verifier (the
// adapter sends it). A mismatch is ErrInvalidToken.
func (v *Verifier) Exchange(ctx context.Context, code, returnedState string, req AuthRequest) (Identity, error) {
	tokens, err := v.exchangeTokens(ctx, code, returnedState, req)
	if err != nil {
		return Identity{}, err
	}
	return tokens.Identity, nil
}

// exchangeTokens redeems an authorization code and returns the verified token
// set (the CLI's login plumbing persists it). It enforces the same callback
// checks as Exchange.
func (v *Verifier) exchangeTokens(ctx context.Context, code, returnedState string, req AuthRequest) (Tokens, error) {
	if req.State == "" || subtle.ConstantTimeCompare([]byte(returnedState), []byte(req.State)) != 1 {
		return Tokens{}, fmt.Errorf("%w: state mismatch", ErrInvalidToken)
	}
	if strings.TrimSpace(code) == "" {
		return Tokens{}, fmt.Errorf("%w: empty authorization code", ErrInvalidToken)
	}

	tr, err := v.tokenRequest(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {req.RedirectURL},
		"code_verifier": {req.CodeVerifier},
	})
	if err != nil {
		return Tokens{}, err
	}

	claims, err := v.verify(ctx, tr.IDToken, req.Nonce)
	if err != nil {
		return Tokens{}, err
	}
	return v.tokensFrom(tr, v.identityFrom(claims)), nil
}

// WaitForCallback serves exactly one loopback callback request on ln (the CLI
// browser login), verifies the CSRF state against req, answers the browser
// with a short confirmation page and returns the authorization code. It
// returns when the callback arrives or when ctx is cancelled.
func (v *Verifier) WaitForCallback(ctx context.Context, ln net.Listener, req AuthRequest) (string, error) {
	type callbackResult struct {
		code string
		err  error
	}
	result := make(chan callbackResult, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var res callbackResult
		switch {
		case q.Get("error") != "":
			res.err = fmt.Errorf("oidc: authorization failed: %s", q.Get("error"))
		case subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(req.State)) != 1:
			res.err = fmt.Errorf("%w: state mismatch", ErrInvalidToken)
		default:
			res.code = q.Get("code")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "Login complete. You may close this window.\n")
		select {
		case result <- res:
		default:
		}
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		_ = srv.Close()
		return "", ctx.Err()
	case res := <-result:
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return res.code, res.err
	}
}

// LoopbackLogin runs the Authorization Code + PKCE flow over a loopback
// callback for the human CLI: it binds ln (already listening on 127.0.0.1),
// starts the callback server, builds the authorization URL, hands it to open
// (the CLI opens the browser; nil skips it), waits for the callback and
// exchanges the code. It returns when the login completes or when ctx is
// cancelled.
func (v *Verifier) LoopbackLogin(ctx context.Context, ln net.Listener, open func(string) error) (Identity, error) {
	tokens, err := v.LoopbackLoginWithTokens(ctx, ln, open)
	if err != nil {
		return Identity{}, err
	}
	return tokens.Identity, nil
}

// LoopbackLoginWithTokens runs the Authorization Code + PKCE loopback flow and
// returns the verified token set (the CLI's login plumbing persists it). It
// behaves exactly like LoopbackLogin.
func (v *Verifier) LoopbackLoginWithTokens(ctx context.Context, ln net.Listener, open func(string) error) (Tokens, error) {
	redirectURL := "http://" + ln.Addr().String() + callbackPath
	req, err := v.NewAuthRequest(redirectURL)
	if err != nil {
		return Tokens{}, err
	}
	authURL, err := v.AuthorizationURL(ctx, req)
	if err != nil {
		return Tokens{}, err
	}

	type outcome struct {
		code string
		err  error
	}
	result := make(chan outcome, 1)
	go func() {
		code, err := v.WaitForCallback(ctx, ln, req)
		result <- outcome{code: code, err: err}
	}()

	if open != nil {
		if err := open(authURL); err != nil {
			return Tokens{}, fmt.Errorf("oidc: open browser: %w", err)
		}
	}

	select {
	case <-ctx.Done():
		return Tokens{}, ctx.Err()
	case res := <-result:
		if res.err != nil {
			return Tokens{}, res.err
		}
		return v.exchangeTokens(ctx, res.code, req.State, req)
	}
}

// codeChallenge computes the PKCE S256 challenge of a verifier (RFC 7636).
func codeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// randomToken returns n cryptographically random bytes as base64url text.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oidc: generate random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
