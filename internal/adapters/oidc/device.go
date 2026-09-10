package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Device-flow poll outcomes (RFC 8628 §3.5) and defaults.
const (
	// defaultDeviceInterval is the poll interval when the provider does not
	// state one (RFC 8628 §3.2).
	defaultDeviceInterval = 5 * time.Second
	// deviceSlowDownStep is added to the interval on a slow_down response
	// (RFC 8628 §3.5).
	deviceSlowDownStep = 5 * time.Second
	// deviceGrantType is the URN of the device-code token grant.
	deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

// Device-flow sentinel outcomes. DevicePoll returns one of these (wrapped) for
// the pollable states; DeviceLogin reacts to them.
var (
	// ErrAuthorizationPending signals the user has not approved yet — keep
	// polling.
	ErrAuthorizationPending = errors.New("oidc: authorization pending")
	// ErrSlowDown signals the client polled too fast — poll less often.
	ErrSlowDown = errors.New("oidc: slow down")
	// ErrAccessDenied signals the user refused the request.
	ErrAccessDenied = errors.New("oidc: access denied")
	// ErrExpiredToken signals the device code expired before approval.
	ErrExpiredToken = errors.New("oidc: device code expired")
)

// DeviceAuthorization is the device-flow kickoff (RFC 8628 §3.2): the device
// code the CLI polls with, the user code and verification URI it shows, and
// the polling cadence and expiry the provider set.
type DeviceAuthorization struct {
	DeviceCode      string
	UserCode        string
	VerificationURI string
	Interval        time.Duration
	ExpiresIn       time.Duration
}

// deviceAuthorizationResponse is the device-authorization endpoint response
// (RFC 8628 §3.2).
type deviceAuthorizationResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int64  `json:"expires_in"`
	Interval        int64  `json:"interval"`
	Error           string `json:"error"`
}

// DeviceAuthorize starts the Device Authorization Flow (RFC 8628 §3.1): it
// asks the provider for a device code and the user code the CLI shows. A
// provider without a device_authorization_endpoint is an error.
func (v *Verifier) DeviceAuthorize(ctx context.Context) (DeviceAuthorization, error) {
	doc, err := v.discover(ctx)
	if err != nil {
		return DeviceAuthorization{}, err
	}
	if doc.DeviceAuthorizationEndpoint == "" {
		return DeviceAuthorization{}, errors.New("oidc: provider does not support the device authorization flow")
	}

	form := url.Values{
		"client_id": {v.cfg.ClientID},
		"scope":     {strings.Join(v.cfg.Scopes, " ")},
	}
	if v.cfg.ClientSecret != "" {
		form.Set("client_secret", v.cfg.ClientSecret)
	}

	body, status, err := v.postForm(ctx, doc.DeviceAuthorizationEndpoint, form)
	if err != nil {
		return DeviceAuthorization{}, err
	}
	var dr deviceAuthorizationResponse
	if err := json.Unmarshal(body, &dr); err != nil {
		return DeviceAuthorization{}, fmt.Errorf("oidc: parse device authorization response: %w", err)
	}
	if status != http.StatusOK || dr.Error != "" || dr.DeviceCode == "" {
		return DeviceAuthorization{}, errors.New("oidc: device authorization request rejected")
	}

	interval := time.Duration(dr.Interval) * time.Second
	if interval <= 0 {
		interval = defaultDeviceInterval
	}
	return DeviceAuthorization{
		DeviceCode:      dr.DeviceCode,
		UserCode:        dr.UserCode,
		VerificationURI: dr.VerificationURI,
		Interval:        interval,
		ExpiresIn:       time.Duration(dr.ExpiresIn) * time.Second,
	}, nil
}

// DevicePoll performs one poll of the token endpoint for the device grant
// (RFC 8628 §3.4). It returns the verified Identity on approval, or a wrapped
// ErrAuthorizationPending / ErrSlowDown / ErrAccessDenied / ErrExpiredToken
// for the pollable states.
func (v *Verifier) DevicePoll(ctx context.Context, dev DeviceAuthorization) (Identity, error) {
	tokens, err := v.devicePollTokens(ctx, dev)
	if err != nil {
		return Identity{}, err
	}
	return tokens.Identity, nil
}

// devicePollTokens performs one poll of the token endpoint for the device
// grant and returns the whole verified token set (the CLI login persists it;
// DevicePoll exposes only the identity). The pollable state errors are
// identical to DevicePoll's.
func (v *Verifier) devicePollTokens(ctx context.Context, dev DeviceAuthorization) (Tokens, error) {
	doc, err := v.discover(ctx)
	if err != nil {
		return Tokens{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if doc.TokenEndpoint == "" {
		return Tokens{}, fmt.Errorf("%w: discovery document has no token_endpoint", ErrInvalidToken)
	}

	form := url.Values{
		"grant_type":  {deviceGrantType},
		"device_code": {dev.DeviceCode},
		"client_id":   {v.cfg.ClientID},
	}
	if v.cfg.ClientSecret != "" {
		form.Set("client_secret", v.cfg.ClientSecret)
	}

	body, status, err := v.postForm(ctx, doc.TokenEndpoint, form)
	if err != nil {
		return Tokens{}, err
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return Tokens{}, fmt.Errorf("oidc: parse token response: %w", err)
	}
	if tr.Error != "" {
		switch tr.Error {
		case "authorization_pending":
			return Tokens{}, ErrAuthorizationPending
		case "slow_down":
			return Tokens{}, ErrSlowDown
		case "access_denied":
			return Tokens{}, ErrAccessDenied
		case "expired_token":
			return Tokens{}, ErrExpiredToken
		default:
			return Tokens{}, fmt.Errorf("%w: device grant rejected", ErrInvalidToken)
		}
	}
	if status != http.StatusOK || tr.IDToken == "" {
		return Tokens{}, fmt.Errorf("%w: device grant rejected", ErrInvalidToken)
	}

	claims, err := v.verify(ctx, tr.IDToken, "")
	if err != nil {
		return Tokens{}, err
	}
	return v.tokensFrom(tr, v.identityFrom(claims)), nil
}

// DeviceLogin runs the whole Device Authorization Flow: DeviceAuthorize, then
// a poll loop until the user approves, the device code expires or ctx is
// cancelled. report is called once with the kickoff so the CLI can show the
// verification URI and user code; it may be nil.
func (v *Verifier) DeviceLogin(ctx context.Context, report func(DeviceAuthorization)) (Identity, error) {
	tokens, err := v.DeviceLoginWithTokens(ctx, report)
	if err != nil {
		return Identity{}, err
	}
	return tokens.Identity, nil
}

// DeviceLoginWithTokens runs the whole Device Authorization Flow and returns
// the verified token set (the CLI's login plumbing persists it). It behaves
// exactly like DeviceLogin; report is called once with the kickoff.
func (v *Verifier) DeviceLoginWithTokens(ctx context.Context, report func(DeviceAuthorization)) (Tokens, error) {
	dev, err := v.DeviceAuthorize(ctx)
	if err != nil {
		return Tokens{}, err
	}
	if report != nil {
		report(dev)
	}

	interval := dev.Interval
	if interval <= 0 {
		interval = defaultDeviceInterval
	}
	var deadline time.Time
	if dev.ExpiresIn > 0 {
		deadline = v.clk.Now().Add(dev.ExpiresIn)
	}

	for {
		tokens, err := v.devicePollTokens(ctx, dev)
		switch {
		case err == nil:
			return tokens, nil
		case errors.Is(err, ErrAuthorizationPending):
			// The user has not approved yet — keep polling.
		case errors.Is(err, ErrSlowDown):
			interval += deviceSlowDownStep
		default:
			return Tokens{}, err
		}

		if !deadline.IsZero() && v.clk.Now().After(deadline) {
			return Tokens{}, ErrExpiredToken
		}
		if err := v.sleep(ctx, interval); err != nil {
			return Tokens{}, err
		}
	}
}

// sleepContext waits for d or until ctx is cancelled — the default device-flow
// poll wait.
func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
