package oidc

import "time"

// Tokens is the raw token set of one successful login (ARCH-005 §2): the
// verified Identity plus the OAuth token response the CLI's login plumbing
// persists in the OS credential store. The adapter returns it only to the
// login plumbing (DeviceLoginWithTokens / LoopbackLoginWithTokens); the
// identity-only DeviceLogin / LoopbackLogin keep their signature for the
// callers that never store tokens. Tokens are secrets and are never logged
// (NFR-006/NFR-014) — the redacting logger drops them by construction and the
// CLI renders only the non-secret identity.
type Tokens struct {
	// Identity is the verified principal of the id token.
	Identity Identity
	// AccessToken is the bearer access token the CLI presents to the API.
	AccessToken string
	// IDToken is the verified OIDC id token.
	IDToken string
	// RefreshToken is the provider's refresh token; "" when none was issued.
	RefreshToken string
	// TokenType is the OAuth token type ("Bearer"); may be empty.
	TokenType string
	// ExpiresAt is the access-token expiry derived from the token response's
	// expires_in against the injected clock; the zero time means the provider
	// stated no expiry.
	ExpiresAt time.Time
}

// tokensFrom maps an OAuth token response to Tokens, deriving the expiry from
// expires_in against the injected clock.
func (v *Verifier) tokensFrom(tr tokenResponse, ident Identity) Tokens {
	tokens := Tokens{
		Identity:     ident,
		AccessToken:  tr.AccessToken,
		IDToken:      tr.IDToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
	}
	if tr.ExpiresIn > 0 {
		tokens.ExpiresAt = v.clk.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return tokens
}
