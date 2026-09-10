package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// tokenResponse is the OAuth 2.0 token-endpoint response (RFC 6749 §5.1 /
// RFC 8628 §3.5) as far as the adapter reads it. The error members carry the
// provider's rejection code; the code is surfaced, the description is not
// (it can echo request input).
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Error        string `json:"error"`
}

// postForm posts an application/x-www-form-urlencoded form to endpoint and
// returns the raw body and the HTTP status. The form may carry the client
// secret; it is never logged, and a transport failure is reported without the
// endpoint URL (which can carry a token path in the issuer).
func (v *Verifier) postForm(ctx context.Context, endpoint string, form url.Values) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, errors.New("oidc: build provider request failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := v.hc.Do(req)
	if err != nil {
		return nil, 0, errors.New("oidc: provider request failed")
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes))
	if err != nil {
		return nil, 0, errors.New("oidc: read provider response failed")
	}
	return body, resp.StatusCode, nil
}

// tokenRequest posts an authorization_code (or refresh) form and returns the
// parsed token response. A provider rejection — an OAuth error code or a
// non-200 status — is ErrInvalidToken.
func (v *Verifier) tokenRequest(ctx context.Context, form url.Values) (tokenResponse, error) {
	doc, err := v.discover(ctx)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if doc.TokenEndpoint == "" {
		return tokenResponse{}, fmt.Errorf("%w: discovery document has no token_endpoint", ErrInvalidToken)
	}

	form.Set("client_id", v.cfg.ClientID)
	if v.cfg.ClientSecret != "" {
		form.Set("client_secret", v.cfg.ClientSecret)
	}

	body, status, err := v.postForm(ctx, doc.TokenEndpoint, form)
	if err != nil {
		return tokenResponse{}, err
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return tokenResponse{}, fmt.Errorf("oidc: parse token response: %w", err)
	}
	if tr.Error != "" || status != http.StatusOK {
		return tokenResponse{}, fmt.Errorf("%w: token endpoint rejected the request", ErrInvalidToken)
	}
	return tr, nil
}
