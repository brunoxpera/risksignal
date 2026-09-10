package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

// maxDocumentBytes caps the discovery and JWKS documents the adapter reads, so
// a misbehaving or hostile provider cannot exhaust memory (defensive bound).
const maxDocumentBytes = 1 << 20 // 1 MiB

// signingAlgorithm is the only JWS algorithm the adapter accepts for a
// provider token (RS256; the asymmetric default of the OIDC providers in
// scope). An "alg: none" or an HMAC token is rejected before any key is
// selected.
const signingAlgorithm = "RS256"

// ErrInvalidToken marks any failed token verification (ARCH-005 §2). The
// authentication middleware treats it as an anonymous request (HTTP 401); the
// verifier never substitutes a fallback identity.
var ErrInvalidToken = errors.New("oidc: token verification failed")

// Identity is the principal of a verified OIDC token (ARCH-005 §1, §2): the
// minimal, IdP-owned attributes — the issuer-qualified subject (the login
// key), a display name and an optional e-mail — plus the internal roles the
// configured roles claim seeds on first login. The domain layer resolves the
// internal users.id from SubjectID and owns authorisation; this adapter only
// maps the verified claims to it.
type Identity struct {
	// SubjectID is the issuer-qualified external subject ("<issuer>::<sub>")
	// — the unique login key (users.subject_id).
	SubjectID string
	// DisplayName is denormalised into audit rows at event time.
	DisplayName string
	// Email is optional and used only as a notification recipient — never as
	// the login key.
	Email string
	// Roles is the role seed mapped from the roles claim (ARCH-005 §2). It may
	// be empty: an unknown or missing claim value maps to no roles (fail
	// closed). The value seeds a first login only; authorisation re-reads the
	// current user_roles.
	Roles []domain.Role
}

// TokenVerifier validates a bearer token and maps its verified claims onto a
// RiskSignal Identity (ARCH-005 §2). It is the application-facing port: the
// authentication middleware (WP-5a.05) and the CLI login plumbing hold it. A
// failed verification is an error the caller maps to an anonymous request
// (HTTP 401) — the verifier never returns a fallback identity.
type TokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (Identity, error)
}

// Verifier is the discovery/JWKS-backed TokenVerifier (ARCH-005 §2). It
// fetches the discovery document once and caches it, caches the JWKS and
// refetches it when a token references an unknown key (rotation), and
// verifies every token against the issuer, audience, azp, validity window and
// signature. It is safe for concurrent use.
type Verifier struct {
	cfg Config
	hc  *http.Client
	clk clock.Clock
	log *slog.Logger
	// sleep is the injectable wait of the device-flow poll loop.
	sleep func(ctx context.Context, d time.Duration) error

	mu   sync.RWMutex
	doc  *discovery
	keys map[string]*rsa.PublicKey

	discoverMu sync.Mutex
	jwksMu     sync.Mutex
}

// Option configures the Verifier at construction.
type Option func(*Verifier)

// WithHTTPClient injects the HTTP client (tests point it at a stub provider;
// nil keeps the standard client).
func WithHTTPClient(hc *http.Client) Option {
	return func(v *Verifier) {
		if hc != nil {
			v.hc = hc
		}
	}
}

// WithClock injects the time source (ch. 7.2). It drives the validity-window
// checks and the device-flow expiry, so tests can drive time deterministically.
func WithClock(c clock.Clock) Option {
	return func(v *Verifier) {
		if c != nil {
			v.clk = c
		}
	}
}

// WithLogger injects the structured logger. Production wires the redacting
// logger of internal/platform/logging; the adapter itself never logs tokens
// or Authorization headers.
func WithLogger(l *slog.Logger) Option {
	return func(v *Verifier) {
		if l != nil {
			v.log = l
		}
	}
}

// WithSleep injects the wait function of the device-flow poll loop (tests
// pass a no-op so the loop runs without real waiting).
func WithSleep(fn func(ctx context.Context, d time.Duration) error) Option {
	return func(v *Verifier) {
		if fn != nil {
			v.sleep = fn
		}
	}
}

// New builds the OIDC verifier over the given configuration. The adapter is
// endpoint-less until the first verification: it discovers the issuer lazily
// and caches the result.
func New(cfg Config, opts ...Option) (*Verifier, error) {
	normalized, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	v := &Verifier{
		cfg:   normalized,
		hc:    http.DefaultClient,
		clk:   clock.RealClock{},
		log:   slog.Default(),
		sleep: sleepContext,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(v)
		}
	}
	return v, nil
}

// Verify implements TokenVerifier: it parses rawToken, validates the
// signature against the cached JWKS (refetching once on an unknown key), the
// issuer, the audience, the authorised party and the validity window, and
// maps the verified claims to an Identity. Any failure is ErrInvalidToken.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (Identity, error) {
	claims, err := v.verify(ctx, rawToken, "")
	if err != nil {
		return Identity{}, err
	}
	return v.identityFrom(claims), nil
}

// verify parses rawToken and returns its verified claims. expectedNonce is
// checked when non-empty (the browser callback's OIDC nonce).
func (v *Verifier) verify(ctx context.Context, rawToken, expectedNonce string) (jwt.MapClaims, error) {
	if strings.TrimSpace(rawToken) == "" {
		return nil, fmt.Errorf("%w: empty token", ErrInvalidToken)
	}
	doc, err := v.discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if doc.TokenEndpoint == "" && doc.JWKSUri == "" {
		return nil, fmt.Errorf("%w: discovery document is incomplete", ErrInvalidToken)
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(rawToken, claims, v.keyFunc(ctx),
		jwt.WithValidMethods([]string{signingAlgorithm}),
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithAudience(v.cfg.expectedAudience()),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(v.clk.Now),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("%w: token reported invalid", ErrInvalidToken)
	}

	// azp (OIDC Core §3.1.3.7): when present it must equal the client id.
	if azp := claimString(claims, "azp"); azp != "" && azp != v.cfg.ClientID {
		return nil, fmt.Errorf("%w: azp does not match the client id", ErrInvalidToken)
	}
	if claimString(claims, "sub") == "" {
		return nil, fmt.Errorf("%w: subject claim is missing", ErrInvalidToken)
	}
	if expectedNonce != "" && claimString(claims, "nonce") != expectedNonce {
		return nil, fmt.Errorf("%w: nonce mismatch", ErrInvalidToken)
	}
	return claims, nil
}

// keyFunc selects the JWKS public key of a token by its kid.
func (v *Verifier) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		return v.lookupKey(ctx, kid)
	}
}

// lookupKey resolves the public key of a kid from the cached JWKS. A kid the
// cached set does not carry triggers a single refetch — the JWKS may have
// rotated (ARCH-005 §2) — after which a still-unknown kid is an error.
func (v *Verifier) lookupKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if keys, err := v.keyset(ctx, false); err == nil {
		if key, ok := selectKey(keys, kid); ok {
			return key, nil
		}
	}
	keys, err := v.keyset(ctx, true)
	if err != nil {
		return nil, err
	}
	if key, ok := selectKey(keys, kid); ok {
		return key, nil
	}
	return nil, fmt.Errorf("no JWKS key for kid %q", kid)
}

// selectKey picks the key of a kid; an empty kid resolves only a single-key
// JWKS (unambiguous).
func selectKey(keys map[string]*rsa.PublicKey, kid string) (*rsa.PublicKey, bool) {
	if kid != "" {
		key, ok := keys[kid]
		return key, ok
	}
	if len(keys) == 1 {
		for _, key := range keys {
			return key, true
		}
	}
	return nil, false
}

// keyset returns the cached JWKS, fetching it on first use and when refresh is
// set. The fetch is serialised so concurrent verifications share one request.
func (v *Verifier) keyset(ctx context.Context, refresh bool) (map[string]*rsa.PublicKey, error) {
	if !refresh {
		if keys := v.cachedKeys(); keys != nil {
			return keys, nil
		}
	}
	v.jwksMu.Lock()
	defer v.jwksMu.Unlock()
	if !refresh {
		if keys := v.cachedKeys(); keys != nil {
			return keys, nil
		}
	}
	doc, err := v.discover(ctx)
	if err != nil {
		return nil, err
	}
	body, err := v.fetch(ctx, doc.JWKSUri)
	if err != nil {
		return nil, err
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	v.keys = keys
	v.mu.Unlock()
	return keys, nil
}

// cachedKeys returns the cached JWKS, or nil when none is loaded yet.
func (v *Verifier) cachedKeys() map[string]*rsa.PublicKey {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.keys
}

// discovery is the subset of the OIDC discovery document the adapter needs
// (OpenID Connect Discovery 1.0 / RFC 8414).
type discovery struct {
	Issuer                      string `json:"issuer"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	JWKSUri                     string `json:"jwks_uri"`
	UserinfoEndpoint            string `json:"userinfo_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	EndSessionEndpoint          string `json:"end_session_endpoint"`
}

// discover fetches the issuer's discovery document once and caches it. The
// document's issuer must equal the configured issuer (a provider that
// misrepresents its identity is rejected).
func (v *Verifier) discover(ctx context.Context) (*discovery, error) {
	v.mu.RLock()
	doc := v.doc
	v.mu.RUnlock()
	if doc != nil {
		return doc, nil
	}

	v.discoverMu.Lock()
	defer v.discoverMu.Unlock()
	v.mu.RLock()
	doc = v.doc
	v.mu.RUnlock()
	if doc != nil {
		return doc, nil
	}

	body, err := v.fetch(ctx, discoveryURL(v.cfg.Issuer))
	if err != nil {
		return nil, err
	}
	var d discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("oidc: parse discovery document: %w", err)
	}
	if strings.TrimRight(d.Issuer, "/") != v.cfg.Issuer {
		return nil, errors.New("oidc: discovery issuer does not match the configured issuer")
	}
	if d.JWKSUri == "" {
		return nil, errors.New("oidc: discovery document has no jwks_uri")
	}
	v.mu.Lock()
	v.doc = &d
	v.mu.Unlock()
	return &d, nil
}

// fetch performs a GET and returns the body of a 200 response. The request URL
// — which can carry a token path in the issuer — and the transport error are
// deliberately not echoed (ARCH-005 §2: the issuer URL is never rendered).
func (v *Verifier) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.New("oidc: build provider request failed")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := v.hc.Do(req)
	if err != nil {
		return nil, errors.New("oidc: provider request failed")
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: provider returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes))
	if err != nil {
		return nil, errors.New("oidc: read provider response failed")
	}
	return body, nil
}

// discoveryURL builds the discovery endpoint of an issuer.
func discoveryURL(issuer string) string {
	return strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
}

// jwk is the RSA subset of a JWK (RFC 7517/7518).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

// parseJWKS parses a JWKS document into kid → RSA public key. Non-RSA keys are
// skipped; a document without a usable key is an error.
func parseJWKS(body []byte) (map[string]*rsa.PublicKey, error) {
	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("oidc: parse JWKS: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.N == "" || k.E == "" {
			continue
		}
		key, err := rsaPublicKey(k.N, k.E)
		if err != nil {
			return nil, err
		}
		keys[k.Kid] = key
	}
	if len(keys) == 0 {
		return nil, errors.New("oidc: JWKS contains no usable RSA key")
	}
	return keys, nil
}

// rsaPublicKey rebuilds an RSA public key from the base64url JWK members.
func rsaPublicKey(nEnc, eEnc string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nEnc)
	if err != nil {
		return nil, errors.New("oidc: JWKS modulus is not base64url")
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eEnc)
	if err != nil {
		return nil, errors.New("oidc: JWKS exponent is not base64url")
	}
	n := new(big.Int).SetBytes(nBytes)
	if n.Sign() <= 0 {
		return nil, errors.New("oidc: JWKS modulus is invalid")
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e <= 0 {
		e = 65537
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

// Compile-time proof that the adapter satisfies the port.
var _ TokenVerifier = (*Verifier)(nil)
