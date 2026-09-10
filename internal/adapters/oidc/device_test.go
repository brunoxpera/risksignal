package oidc

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/domain"
)

func TestDeviceAuthorize(t *testing.T) {
	p := newStubProvider(t)
	v := p.newVerifier(t, roleMappings)

	p.device = func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{
			"device_code":      "device-1",
			"user_code":        "ABCD-1234",
			"verification_uri": "https://provider.example/activate",
			"expires_in":       600,
			"interval":         3,
		})
	}

	dev, err := v.DeviceAuthorize(context.Background())
	if err != nil {
		t.Fatalf("DeviceAuthorize: %v", err)
	}
	if dev.DeviceCode != "device-1" || dev.UserCode != "ABCD-1234" {
		t.Errorf("DeviceAuthorization = %+v, want the device/user codes", dev)
	}
	if dev.VerificationURI != "https://provider.example/activate" {
		t.Errorf("VerificationURI = %q", dev.VerificationURI)
	}
	if dev.Interval != 3*time.Second {
		t.Errorf("Interval = %s, want 3s", dev.Interval)
	}
	if dev.ExpiresIn != 10*time.Minute {
		t.Errorf("ExpiresIn = %s, want 10m", dev.ExpiresIn)
	}
}

func TestDeviceAuthorizeUnsupportedProvider(t *testing.T) {
	p := newStubProvider(t)
	p.omitDevice = true
	v := p.newVerifier(t, roleMappings)

	if _, err := v.DeviceAuthorize(context.Background()); err == nil {
		t.Fatal("DeviceAuthorize on a provider without the device endpoint succeeded, want error")
	}
}

func TestDevicePollOutcomes(t *testing.T) {
	cases := []struct {
		code string
		want error
	}{
		{"authorization_pending", ErrAuthorizationPending},
		{"slow_down", ErrSlowDown},
		{"access_denied", ErrAccessDenied},
		{"expired_token", ErrExpiredToken},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			p := newStubProvider(t)
			v := p.newVerifier(t, roleMappings)
			p.token = func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(t, w, map[string]string{"error": tc.code})
			}
			_, err := v.DevicePoll(context.Background(), DeviceAuthorization{DeviceCode: "device-1"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("DevicePoll err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestDeviceLoginPollsUntilApproved drives the whole flow: the first poll is
// pending, the second approves; the poll loop uses the injected no-op sleep.
func TestDeviceLoginPollsUntilApproved(t *testing.T) {
	p := newStubProvider(t)
	v := p.newVerifier(t, roleMappings)
	v.sleep = func(context.Context, time.Duration) error { return nil }

	p.device = func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"device_code": "device-1", "user_code": "U", "interval": 1})
	}
	polls := 0
	p.token = func(w http.ResponseWriter, _ *http.Request) {
		polls++
		if polls == 1 {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(t, w, map[string]string{"error": "authorization_pending"})
			return
		}
		writeJSON(t, w, map[string]string{"id_token": p.sign(p.baseClaims()), "access_token": "at"})
	}

	var reported DeviceAuthorization
	ident, err := v.DeviceLogin(context.Background(), func(dev DeviceAuthorization) { reported = dev })
	if err != nil {
		t.Fatalf("DeviceLogin: %v", err)
	}
	if polls != 2 {
		t.Errorf("polls = %d, want 2", polls)
	}
	if reported.DeviceCode != "device-1" {
		t.Errorf("reported = %+v, want the device authorization", reported)
	}
	if ident.SubjectID != p.issuer()+"::user-1" {
		t.Errorf("SubjectID = %q, want the issuer-qualified subject", ident.SubjectID)
	}
	if len(ident.Roles) != 1 || ident.Roles[0] != domain.RoleSecurityAnalyst {
		t.Errorf("Roles = %v, want [%s]", ident.Roles, domain.RoleSecurityAnalyst)
	}
}

func TestDeviceLoginStopsOnAccessDenied(t *testing.T) {
	p := newStubProvider(t)
	v := p.newVerifier(t, roleMappings)
	v.sleep = func(context.Context, time.Duration) error { return nil }

	p.device = func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"device_code": "device-1", "user_code": "U"})
	}
	p.token = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(t, w, map[string]string{"error": "access_denied"})
	}

	if _, err := v.DeviceLogin(context.Background(), nil); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("DeviceLogin err = %v, want ErrAccessDenied", err)
	}
}
