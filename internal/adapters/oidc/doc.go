// Package oidc is the I5a OpenID Connect adapter (ARCH-005 §2, WP-5a.04): the
// TokenVerifier port and its discovery/JWKS-backed implementation, the
// Authorization Code Flow with PKCE exchange of the browser (and loopback
// CLI) login, the Device Authorization Flow of the human CLI, and the
// claims-to-identity plus roles-claim mapping the first-login user seeding
// reads.
//
// # The verified principal
//
// A token is verified against the issuer's discovery document and rotating
// JWKS: the signature (RS256/JWKS), the issuer, the audience (the configured
// client id), the authorised party (azp) and the validity window (exp/nbf)
// must all hold. Any failure is an unauthenticated request — Verify returns an
// error and never a fallback or default identity (ARCH-005 §2). Tokens are
// never logged; the redacting logger of internal/platform/logging drops
// Authorization headers and free-text payloads (NFR-006/NFR-014).
//
// # Claims to identity
//
// The verified token yields Identity{SubjectID, DisplayName, Email}, with the
// subject issuer-qualified ("<issuer>::<sub>", ARCH-005 §1) — the login key.
// The configured roles claim (roles_claim, default "roles") is mapped through
// role_mappings onto internal domain.Role values; an unknown or missing claim
// value maps to no roles (fail closed, logged, never fatal). Roles are only
// ever mapped here to seed a first login: authorisation never reads the token
// — the authorizer re-reads the current user_roles (ARCH-005 §2, §5).
//
// # Flows
//
//   - Browser / loopback: NewAuthRequest generates the per-login state, nonce
//     and PKCE (S256) verifier; AuthorizationURL builds the redirect; Exchange
//     redeems the code and verifies state, nonce and the PKCE verifier on the
//     callback.
//   - Human CLI: DeviceAuthorize / DeviceLogin run the Device Authorization
//     Flow (RFC 8628) when the provider supports it; WaitForCallback and
//     LoopbackLogin are the loopback callback helper of a browser login.
//
// The composition roots (cmd/*) wire the adapter. The HTTP authentication
// middleware and the CLI auth plumbing are WP-5a.05; the in-command
// authorisation is WP-5a.06.
package oidc
