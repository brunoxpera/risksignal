// Package fetchguard is the SSRF guard of the source-fetch path (ARCH-007 §7
// control 1, concept ch. 12.3 "SSRF-Schutz", WP-6.10 / DEV-123).
//
// Source endpoints are operator-registered (sources.endpoint), never
// user-supplied, but a compromised or mistyped endpoint — or a redirect from a
// legitimate one — must not let the fetch reach the process's own network
// neighbourhood. The guard enforces, on the fetch path only:
//
//  1. scheme allowlist: only http and https are fetched (a file://, gopher://
//     or ftp:// target is refused before any I/O);
//  2. resolve + IP check: the request host is resolved (a literal IP is
//     checked directly) and every resolved address must be a public unicast
//     address — loopback (127/8, ::1), link-local unicast (169.254/16,
//     fe80::/10), private (10/8, 172.16/12, 192.168/16, fc00::/7), multicast
//     and unspecified are refused. The check runs again on the actual dialed
//     socket (net.Dialer.Control), so a DNS rebinding between the resolve and
//     the connect still cannot reach a blocked address;
//  3. redirect limit: at most DefaultMaxRedirects (5) hops, and every hop is
//     re-checked (scheme + resolve + IP) before it is followed.
//
// sources.allow_private relaxes rule 2 for loopback, link-local unicast and
// private targets so the local environment can reach its mock sources on
// loopback; demo and production refuse the flag (config.Validate). Multicast
// and unspecified addresses are refused regardless.
//
// The guard never honours a proxy: a proxy would tunnel the request past the
// IP check (the guard would inspect the proxy address, not the target), so the
// guarded transport leaves Proxy nil and always dials the target itself.
package fetchguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"
)

const (
	// DefaultMaxRedirects is the hard redirect-hop limit of a guarded fetch
	// (ARCH-007 §7 control 1c).
	DefaultMaxRedirects = 5

	dialTimeout         = 10 * time.Second
	keepAlive           = 30 * time.Second
	tlsHandshakeTimeout = 10 * time.Second
	idleConnTimeout     = 90 * time.Second
	expectContinue      = 1 * time.Second
)

// Sentinel errors of the guard. They are stable and safe to surface (they name
// no secret), so callers and operators can classify a blocked fetch.
var (
	// ErrSchemeNotAllowed is returned for a request whose URL scheme is not
	// http or https.
	ErrSchemeNotAllowed = errors.New("fetchguard: request URL scheme is not allowed (only http and https)")
	// ErrBlockedTarget is returned when the request host resolves to — or is —
	// a blocked address (loopback, link-local, private, multicast or
	// unspecified).
	ErrBlockedTarget = errors.New("fetchguard: target host resolves to a non-public address (loopback/link-local/private/multicast/unspecified)")
	// ErrTooManyRedirects is returned when a redirect chain exceeds
	// DefaultMaxRedirects hops.
	ErrTooManyRedirects = errors.New("fetchguard: redirect limit exceeded")
)

// AllowedIP reports whether the guard may connect to ip.
//
// Multicast and unspecified addresses are always refused. Loopback
// (127/8, ::1), link-local unicast (169.254/16, fe80::/10) and private
// (10/8, 172.16/12, 192.168/16, fc00::/7) addresses are refused unless
// allowPrivate is set — the local-only sources.allow_private relaxation of
// ARCH-007 §7 control 1. Every other address (public unicast) is allowed.
func AllowedIP(ip net.IP, allowPrivate bool) bool {
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return allowPrivate
	}
	return true
}

// Transport is the SSRF-guarding http.RoundTripper. Wrap it in a *http.Client
// through Client so its redirect policy is enforced as well.
type Transport struct {
	base         *http.Transport
	allowPrivate bool
	maxRedirects int
}

// New returns a guarded transport with a fresh default base transport.
// allowPrivate relaxes the address check to loopback/link-local/private
// targets (sources.allow_private); multicast and unspecified stay blocked.
func New(allowPrivate bool) *Transport { return NewWithBase(nil, allowPrivate) }

// NewWithBase returns a guarded transport over base; nil selects a fresh
// default base transport. The base's DialContext is replaced by the guarded
// dialer (the resolve + IP check must run on the actual socket).
func NewWithBase(base *http.Transport, allowPrivate bool) *Transport {
	if base == nil {
		base = defaultBase()
	}
	t := &Transport{base: base, allowPrivate: allowPrivate, maxRedirects: DefaultMaxRedirects}
	base.DialContext = t.dialContext
	return t
}

// Client returns an *http.Client whose transport is rt and whose redirect
// policy enforces the guard.
//
//   - rt == nil installs a guarded transport with allowPrivate=false (fail
//     secure): a bare adapter client is still guarded.
//   - rt is a *Transport: its own redirect policy (limit + per-hop re-check)
//     is wired in.
//   - any other transport: the shared ≤DefaultMaxRedirects-hop, scheme-checked
//     redirect policy is wired in (the IP check is then the base transport's
//     own responsibility, e.g. an injected test transport).
func Client(rt http.RoundTripper) *http.Client {
	if rt == nil {
		g := New(false)
		return &http.Client{Transport: g, CheckRedirect: g.checkRedirect}
	}
	c := &http.Client{Transport: rt}
	if g, ok := rt.(*Transport); ok {
		c.CheckRedirect = g.checkRedirect
	} else {
		c.CheckRedirect = limitedRedirects(DefaultMaxRedirects)
	}
	return c
}

// defaultBase is the base transport of a guarded client. Proxy is nil on
// purpose (see the package doc): a proxy would bypass the IP check.
func defaultBase() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       idleConnTimeout,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ExpectContinueTimeout: expectContinue,
	}
}

// RoundTrip enforces the scheme allowlist and the resolve + IP check, then
// delegates to the base transport.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := checkScheme(req.URL); err != nil {
		return nil, err
	}
	if err := t.checkHost(req.Context(), req.URL); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

// checkRedirect is the client's redirect policy: it caps the hop count and
// re-checks the scheme and the resolved address of every hop before it is
// followed (ARCH-007 §7 control 1c).
func (t *Transport) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= t.maxRedirects {
		return fmt.Errorf("%w: stopped after %d hops", ErrTooManyRedirects, t.maxRedirects)
	}
	return t.checkRequest(req)
}

// checkRequest applies the scheme and host checks to one request.
func (t *Transport) checkRequest(req *http.Request) error {
	if err := checkScheme(req.URL); err != nil {
		return err
	}
	ctx := context.Background()
	if req != nil {
		ctx = req.Context()
	}
	return t.checkHost(ctx, req.URL)
}

// checkHost refuses a request host that is — or resolves to — a blocked
// address. A literal IP is checked directly; a name is resolved and every
// resolved address must be allowed.
func (t *Transport) checkHost(ctx context.Context, u *url.URL) error {
	if u == nil {
		return fmt.Errorf("%w: request carries no URL", ErrBlockedTarget)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: request carries an empty host", ErrBlockedTarget)
	}
	if ip := net.ParseIP(host); ip != nil {
		if !AllowedIP(ip, t.allowPrivate) {
			return fmt.Errorf("%w: %s", ErrBlockedTarget, host)
		}
		return nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("fetchguard: resolve host %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("%w: %s resolves to no address", ErrBlockedTarget, host)
	}
	for _, a := range addrs {
		if !AllowedIP(a.IP, t.allowPrivate) {
			return fmt.Errorf("%w: %s -> %s", ErrBlockedTarget, host, a.IP)
		}
	}
	return nil
}

// dialContext is the guarded dialer: the Control hook re-checks the actual
// socket address, closing the resolve-to-connect (DNS rebinding) window.
func (t *Transport) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: keepAlive,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || !AllowedIP(ip, t.allowPrivate) {
				return fmt.Errorf("%w: %s", ErrBlockedTarget, address)
			}
			return nil
		},
	}
	return d.DialContext(ctx, network, addr)
}

// checkScheme enforces the http/https allowlist.
func checkScheme(u *url.URL) error {
	if u == nil {
		return ErrSchemeNotAllowed
	}
	switch u.Scheme {
	case "http", "https":
		return nil
	default:
		return ErrSchemeNotAllowed
	}
}

// limitedRedirects is the redirect policy for non-guard transports: it caps
// the hop count and re-checks the scheme of every hop.
func limitedRedirects(max int) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= max {
			return fmt.Errorf("%w: stopped after %d hops", ErrTooManyRedirects, max)
		}
		return checkScheme(req.URL)
	}
}
