package oidc

import (
	"log/slog"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// identityFrom maps the verified claims of a token to an Identity: the
// issuer-qualified subject, the display name (the `name` claim, falling back
// to `preferred_username`) and the optional e-mail, plus the roles the
// configured roles claim seeds (ARCH-005 §2).
func (v *Verifier) identityFrom(claims jwt.MapClaims) Identity {
	return Identity{
		SubjectID:   issuerQualifiedSubject(v.cfg.Issuer, claimString(claims, "sub")),
		DisplayName: firstNonEmpty(claimString(claims, "name"), claimString(claims, "preferred_username")),
		Email:       claimString(claims, "email"),
		Roles:       v.mapRoles(claims),
	}
}

// mapRoles maps the configured roles claim onto internal domain.Role values
// (ARCH-005 §2). An unknown claim value grants no role — fail closed, logged,
// never fatal; a missing or empty claim yields no roles. The result is
// deduplicated and returned in the canonical role order.
func (v *Verifier) mapRoles(claims jwt.MapClaims) []domain.Role {
	if len(v.cfg.RoleMappings) == 0 {
		return nil
	}
	raw, ok := claims[v.cfg.RolesClaim]
	if !ok || raw == nil {
		return nil
	}
	values := claimValues(raw)
	if len(values) == 0 {
		return nil
	}

	seen := make(map[domain.Role]struct{}, len(values))
	for _, value := range values {
		role, ok := v.cfg.RoleMappings[value]
		if !ok {
			v.log.Warn("oidc: unknown roles claim value ignored",
				slog.String("claim", v.cfg.RolesClaim),
				slog.String("value", value))
			continue
		}
		seen[role] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}

	roles := make([]domain.Role, 0, len(seen))
	for _, role := range domain.AllRoles() {
		if _, ok := seen[role]; ok {
			roles = append(roles, role)
		}
	}
	return roles
}

// claimString reads a string claim, trimmed. A non-string or absent claim is
// the empty string.
func claimString(claims jwt.MapClaims, key string) string {
	if s, ok := claims[key].(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// claimValues normalises a roles claim to a list of non-empty strings. It
// accepts a single string and an array of strings (the two shapes OIDC
// providers emit); any other shape yields no values (fail closed).
func claimValues(raw any) []string {
	switch v := raw.(type) {
	case string:
		if s := strings.TrimSpace(v); s != "" {
			return []string{s}
		}
	case []string:
		return trimEach(v)
	case []any:
		out := make([]string, 0, len(v))
		for _, elem := range v {
			if s, ok := elem.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	}
	return nil
}

// issuerQualifiedSubject qualifies a subject with its issuer
// ("<issuer>::<sub>", ARCH-005 §1) so a provider migration can never collide
// two subjects.
func issuerQualifiedSubject(issuer, sub string) string {
	return issuer + "::" + sub
}

// firstNonEmpty returns the first non-empty argument.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
