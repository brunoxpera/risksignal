package oidc

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// Defaults of the adapter configuration (ARCH-005 §2). The scopes and the
// roles claim mirror the platform configuration schema defaults; the role
// mappings have no default (an unconfigured deployment maps no claim value,
// so every login seeds zero roles — fail closed).
const (
	// DefaultRolesClaim is the claim name that carries external role values
	// when oidc.roles_claim is not configured.
	DefaultRolesClaim = "roles"
)

// DefaultScopes is the scope list requested when oidc.scopes is not
// configured (ARCH-005 §2).
var DefaultScopes = []string{"openid", "profile", "email"}

// Config is the OIDC adapter configuration (ARCH-005 §2). It mirrors the
// oidc.* keys of the platform configuration schema 1:1 so the composition
// root can map config.OIDC onto it; the platform package never imports the
// domain, so the role mappings are parsed and validated here.
type Config struct {
	// Issuer is the OIDC issuer base URL (oidc.issuer). Discovery is fetched
	// from Issuer + "/.well-known/openid-configuration"; a trailing slash is
	// tolerated.
	Issuer string
	// ClientID is the client registered at the issuer (oidc.client_id). It
	// is the expected `aud` of a token and the `azp` when that claim is
	// present.
	ClientID string
	// ClientSecret is the runtime-injected client secret (the resolved
	// oidc.client_secret_ref). It is never logged and never rendered.
	ClientSecret string
	// Audience is the expected `aud` claim value; empty defaults to
	// ClientID.
	Audience string
	// RedirectURL is the browser callback URL registered at the issuer
	// (oidc.redirect_url). It may be overridden per request.
	RedirectURL string
	// Scopes is the requested scope list (oidc.scopes); empty defaults to
	// DefaultScopes.
	Scopes []string
	// RolesClaim is the claim that carries external role values
	// (oidc.roles_claim); empty defaults to DefaultRolesClaim.
	RolesClaim string
	// RoleMappings maps an external roles-claim value onto an internal
	// domain.Role (oidc.role_mappings). A claim value absent from the map
	// maps to no role (fail closed).
	RoleMappings map[string]domain.Role
}

// normalize validates the configuration and fills the defaults. Every error
// references the configuration key only — never a value — so a client secret
// can never leak into an error message.
func (c Config) normalize() (Config, error) {
	out := c

	out.Issuer = strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	if out.Issuer == "" {
		return Config{}, fmt.Errorf("oidc: issuer is mandatory")
	}
	u, err := url.Parse(out.Issuer)
	if err != nil || u.Scheme == "" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return Config{}, fmt.Errorf("oidc: issuer must be a URL with a scheme and host")
	}

	out.ClientID = strings.TrimSpace(c.ClientID)
	if out.ClientID == "" {
		return Config{}, fmt.Errorf("oidc: client id is mandatory")
	}

	out.Audience = strings.TrimSpace(c.Audience)
	if out.Audience == "" {
		out.Audience = out.ClientID
	}

	out.RedirectURL = strings.TrimSpace(c.RedirectURL)

	out.Scopes = trimEach(c.Scopes)
	if len(out.Scopes) == 0 {
		out.Scopes = append([]string(nil), DefaultScopes...)
	}

	out.RolesClaim = strings.TrimSpace(c.RolesClaim)
	if out.RolesClaim == "" {
		out.RolesClaim = DefaultRolesClaim
	}

	if len(c.RoleMappings) > 0 {
		out.RoleMappings = make(map[string]domain.Role, len(c.RoleMappings))
		for value, role := range c.RoleMappings {
			key := strings.TrimSpace(value)
			if key == "" {
				return Config{}, fmt.Errorf("oidc: role_mappings has an empty claim value")
			}
			if _, err := domain.ParseRole(string(role)); err != nil {
				return Config{}, fmt.Errorf("oidc: role_mappings value for claim value %q is not a known role", key)
			}
			out.RoleMappings[key] = role
		}
	}

	return out, nil
}

// expectedAudience returns the audience a token must carry.
func (c Config) expectedAudience() string {
	if c.Audience != "" {
		return c.Audience
	}
	return c.ClientID
}

// trimEach trims every element and drops the empty ones.
func trimEach(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
