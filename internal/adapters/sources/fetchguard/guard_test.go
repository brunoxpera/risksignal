package fetchguard_test

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/brunoxpera/risksignal/internal/adapters/sources/fetchguard"
)

// TestAllowedIP pins the address classification of the guard: multicast and
// unspecified are always refused; loopback, link-local unicast and private
// only with allowPrivate (ARCH-007 §7 control 1b).
func TestAllowedIP(t *testing.T) {
	cases := []struct {
		ip           string
		allowPrivate bool
		want         bool
	}{
		{"127.0.0.1", false, false}, // loopback
		{"127.0.0.1", true, true},
		{"::1", false, false}, // loopback v6
		{"::1", true, true},
		{"169.254.1.1", false, false}, // link-local unicast
		{"169.254.1.1", true, true},
		{"fe80::1", false, false}, // link-local unicast v6
		{"fe80::1", true, true},
		{"10.0.0.1", false, false}, // private
		{"172.16.5.4", false, false},
		{"192.168.1.1", false, false},
		{"fd00::1", false, false}, // ULA
		{"10.0.0.1", true, true},
		{"192.168.1.1", true, true},
		{"224.0.0.1", false, false}, // multicast
		{"224.0.0.1", true, false},  // multicast is never allowed
		{"ff02::1", true, false},    // link-local multicast
		{"0.0.0.0", false, false},   // unspecified
		{"0.0.0.0", true, false},
		{"::", true, false},
		{"8.8.8.8", false, true}, // public unicast
		{"1.1.1.1", true, true},
		{"2001:4860:4860::8888", false, true},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test ip %q", c.ip)
		}
		if got := fetchguard.AllowedIP(ip, c.allowPrivate); got != c.want {
			t.Errorf("AllowedIP(%s, allowPrivate=%v) = %v, want %v", c.ip, c.allowPrivate, got, c.want)
		}
	}
	if fetchguard.AllowedIP(nil, true) {
		t.Error("AllowedIP(nil) = true, want false")
	}
}

// TestBlockedTargetsRefused proves the resolve + IP check refuses the SSRF
// target families before any I/O (no server is contacted).
func TestBlockedTargetsRefused(t *testing.T) {
	c := fetchguard.Client(fetchguard.New(false))
	targets := []string{
		"http://127.0.0.1:1/", "http://127.1.2.3/", "http://[::1]:1/",
		"http://169.254.1.1/", "http://[fe80::1]/",
		"http://10.0.0.1/", "http://172.16.0.1/", "http://192.168.1.1/", "http://[fd00::1]/",
		"http://224.0.0.1/", "http://0.0.0.0/",
	}
	for _, target := range targets {
		resp, err := c.Get(target)
		if resp != nil {
			resp.Body.Close()
		}
		if err == nil {
			t.Errorf("GET %s succeeded, want blocked", target)
			continue
		}
		if !errors.Is(err, fetchguard.ErrBlockedTarget) {
			t.Errorf("GET %s error = %v, want ErrBlockedTarget", target, err)
		}
	}
}

// TestSchemeNotAllowed proves the scheme allowlist refuses non-http(s).
func TestSchemeNotAllowed(t *testing.T) {
	c := fetchguard.Client(fetchguard.New(true))
	for _, target := range []string{"ftp://example.com/x", "file:///etc/passwd", "gopher://example.com/"} {
		resp, err := c.Get(target)
		if resp != nil {
			resp.Body.Close()
		}
		if !errors.Is(err, fetchguard.ErrSchemeNotAllowed) {
			t.Errorf("GET %s error = %v, want ErrSchemeNotAllowed", target, err)
		}
	}
}

// TestAllowedPrivateTargetSucceeds proves the local-only relaxation: with
// allowPrivate on, a loopback mock source is reachable (the "allowed host
// succeeds" half of the proof).
func TestAllowedPrivateTargetSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := fetchguard.Client(fetchguard.New(true))
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET %s with allow_private: %v", srv.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// TestNilClientIsGuardedFailSecure proves that an adapter client built without
// an explicit transport (fetchguard.Client(nil)) still blocks loopback.
func TestNilClientIsGuardedFailSecure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := fetchguard.Client(nil)
	resp, err := c.Get(srv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, fetchguard.ErrBlockedTarget) {
		t.Fatalf("GET %s error = %v, want ErrBlockedTarget", srv.URL, err)
	}
}

// TestRedirectBlockedHopRejected proves each redirect hop is re-checked: a
// first hop that is reachable (allow_private on, so the loopback mock server
// is allowed) that redirects to a target which must never be reached
// (multicast) is refused before the second hop is dialed.
func TestRedirectBlockedHopRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://224.0.0.1/", http.StatusFound)
	}))
	defer srv.Close()

	c := fetchguard.Client(fetchguard.New(true))
	resp, err := c.Get(srv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, fetchguard.ErrBlockedTarget) {
		t.Fatalf("redirect to multicast error = %v, want ErrBlockedTarget", err)
	}
}

// TestRedirectLimitExceeded proves the ≤5-hop limit: a self-redirecting loop
// stops with ErrTooManyRedirects.
func TestRedirectLimitExceeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer srv.Close()

	c := fetchguard.Client(fetchguard.New(true))
	resp, err := c.Get(srv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, fetchguard.ErrTooManyRedirects) {
		t.Fatalf("self-redirecting loop error = %v, want ErrTooManyRedirects", err)
	}
}

// TestRedirectToUnspecifiedRejected proves an unspecified redirect target is
// refused even when private targets are allowed (multicast/unspecified are
// always blocked).
func TestRedirectToUnspecifiedRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://0.0.0.0/", http.StatusFound)
	}))
	defer srv.Close()

	c := fetchguard.Client(fetchguard.New(true))
	resp, err := c.Get(srv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, fetchguard.ErrBlockedTarget) {
		t.Fatalf("redirect to 0.0.0.0 error = %v, want ErrBlockedTarget", err)
	}
}
