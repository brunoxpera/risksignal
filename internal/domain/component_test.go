package domain

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Asset and Component lifecycle plus the natural_key derivation
// (ARCH-003 §1.1/§1.2/§1.3): explicit deactivation, verification and the
// strongest-identifier natural key with its prefix tags.

// TestNewAssetValid covers the valid minimal asset and the required
// fields/enum validation of the constructor.
func TestNewAssetValid(t *testing.T) {
	a, err := NewAsset("a1", "ext-1", "csv-import", "web-01", "ops", AssetTypeServerVM, EnvironmentProduction, CriticalityHigh, ExposureInternet)
	if err != nil {
		t.Fatalf("NewAsset: unexpected error: %v", err)
	}
	if a.ID != "a1" || a.ExternalID != "ext-1" || a.Source != "csv-import" || a.Name != "web-01" || a.Owner != "ops" {
		t.Errorf("NewAsset = %+v, want the supplied identity fields", a)
	}
	if a.Type != AssetTypeServerVM || a.Environment != EnvironmentProduction || a.Criticality != CriticalityHigh || a.Exposure != ExposureInternet {
		t.Errorf("NewAsset = %+v, want the supplied vocabulary values", a)
	}
	if a.Deactivated || a.Verified {
		t.Errorf("NewAsset: a new asset must be active and unverified, got %+v", a)
	}

	if _, err := NewAsset("", "e", "s", "n", "", AssetTypeServerVM, EnvironmentProduction, CriticalityHigh, ExposureInternet); err == nil {
		t.Error("NewAsset with empty id: want error")
	}
	if _, err := NewAsset("a", "", "s", "n", "", AssetTypeServerVM, EnvironmentProduction, CriticalityHigh, ExposureInternet); err == nil {
		t.Error("NewAsset with empty external_id: want error")
	}
	if _, err := NewAsset("a", "e", "", "n", "", AssetTypeServerVM, EnvironmentProduction, CriticalityHigh, ExposureInternet); err == nil {
		t.Error("NewAsset with empty source: want error")
	}
	if _, err := NewAsset("a", "e", "s", "", "", AssetTypeServerVM, EnvironmentProduction, CriticalityHigh, ExposureInternet); err == nil {
		t.Error("NewAsset with empty name: want error")
	}
	if _, err := NewAsset("a", "e", "s", "n", "", AssetType("vm"), EnvironmentProduction, CriticalityHigh, ExposureInternet); err == nil {
		t.Error("NewAsset with invalid type: want error")
	}
	if _, err := NewAsset("a", "e", "s", "n", "", AssetTypeServerVM, Environment("prod "), CriticalityHigh, ExposureInternet); err == nil {
		t.Error("NewAsset with invalid environment: want error")
	}
}

// TestAssetLifecycle covers the guarded lifecycle: deactivation is
// explicit and a double deactivation is not a transition; verification is
// repeatable and independent of the deactivation state.
func TestAssetLifecycle(t *testing.T) {
	a, err := NewAsset("a1", "ext-1", "csv", "web-01", "", AssetTypeServerVM, EnvironmentProduction, CriticalityHigh, ExposureInternet)
	if err != nil {
		t.Fatalf("NewAsset: unexpected error: %v", err)
	}

	verified, err := a.Verify()
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if !verified.Verified || verified.Deactivated {
		t.Errorf("Verify = %+v, want Verified true and Deactivated false", verified)
	}
	if again, err := verified.Verify(); err != nil || !again.Verified {
		t.Errorf("re-Verify: want no error and Verified true, got %v / %v", again.Verified, err)
	}

	deactivated, err := a.Deactivate()
	if err != nil {
		t.Fatalf("Deactivate: unexpected error: %v", err)
	}
	if !deactivated.Deactivated {
		t.Error("Deactivate: Deactivated = false, want true")
	}
	if _, err := deactivated.Deactivate(); err == nil {
		t.Error("double Deactivate: want error (deactivation is a guarded transition)")
	}
	if _, err := deactivated.Verify(); err != nil {
		t.Errorf("Verify on a deactivated asset: unexpected error: %v", err)
	}
	if _, err := a.Deactivate(); err != nil {
		t.Errorf("Deactivate of an active asset: unexpected error: %v", err)
	}
}

// assetIDs is a helper returning a component with the given identifier set.
func newTestComponent(id string, ids ComponentIdentifiers) (Component, error) {
	return NewComponent(id, "asset-1", ids, strings.ToLower(ids.Vendor), strings.ToLower(ids.Product), ids.Version, VersionSchemeUnknown)
}

// TestNewComponentValid covers constructor validation: identities, scheme
// validity and the identifier presence rule.
func TestNewComponentValid(t *testing.T) {
	c, err := newTestComponent("c1", ComponentIdentifiers{Vendor: "Acme", Product: "Widget", Version: "1.0"})
	if err != nil {
		t.Fatalf("NewComponent: unexpected error: %v", err)
	}
	if c.ID != "c1" || c.AssetID != "asset-1" {
		t.Errorf("NewComponent = %+v, want the supplied identities", c)
	}
	if c.VendorNorm != "acme" || c.ProductNorm != "widget" || c.VersionScheme != VersionSchemeUnknown {
		t.Errorf("NewComponent = %+v, want normalised keys and unknown scheme by default", c)
	}
	if len(c.NaturalKey) != 64 {
		t.Errorf("NaturalKey = %q, want 64 hex chars", c.NaturalKey)
	}
	if _, err := hex.DecodeString(c.NaturalKey); err != nil {
		t.Errorf("NaturalKey %q is not hex: %v", c.NaturalKey, err)
	}

	if _, err := NewComponent("", "asset-1", ComponentIdentifiers{Vendor: "a", Product: "b"}, "a", "b", "", VersionSchemeUnknown); err == nil {
		t.Error("empty id: want error")
	}
	if _, err := NewComponent("c", "", ComponentIdentifiers{Vendor: "a", Product: "b"}, "a", "b", "", VersionSchemeUnknown); err == nil {
		t.Error("empty asset_id: want error")
	}
	if _, err := NewComponent("c", "asset-1", ComponentIdentifiers{Vendor: "a", Product: "b"}, "a", "b", "", VersionScheme("purl")); err == nil {
		t.Error("invalid scheme: want error")
	}
	// No identifier at all → no natural key, rejected instead of hashing empty.
	if _, err := NewComponent("c", "asset-1", ComponentIdentifiers{}, "", "", "", VersionSchemeUnknown); err == nil {
		t.Error("identifier-less component: want error")
	}
	// Whitespace-only identifiers are empty.
	if _, err := newTestComponent("c", ComponentIdentifiers{Vendor: "   ", Product: "b"}); err == nil {
		t.Error("whitespace-only vendor: want error")
	}
	// Identity via cpe/purl/digest/image needs no vendor/product.
	for _, ids := range []ComponentIdentifiers{
		{CPE: "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"},
		{PURL: "pkg:golang/acme/widget@1.0"},
		{Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{Image: "registry.example/acme/widget:1.0"},
	} {
		if _, err := newTestComponent("c", ids); err != nil {
			t.Errorf("identity via %+v: unexpected error: %v", ids, err)
		}
	}
}

// TestComponentLifecycle covers the guarded component deactivation.
func TestComponentLifecycle(t *testing.T) {
	c, err := newTestComponent("c1", ComponentIdentifiers{Vendor: "Acme", Product: "Widget"})
	if err != nil {
		t.Fatalf("NewComponent: unexpected error: %v", err)
	}
	d, err := c.Deactivate()
	if err != nil {
		t.Fatalf("Deactivate: unexpected error: %v", err)
	}
	if !d.Deactivated {
		t.Error("Deactivate: Deactivated = false, want true")
	}
	if _, err := d.Deactivate(); err == nil {
		t.Error("double Deactivate: want error")
	}
	if c.Deactivated {
		t.Error("Deactivate must not mutate the receiver")
	}
}

// TestNaturalKeyPriority verifies the strongest-identifier rule of
// ARCH-003 §1.3 (cpe > purl > digest > image > vendor/product/version):
// the key follows the strongest present identifier and never changes when
// only a weaker identifier differs.
func TestNaturalKeyPriority(t *testing.T) {
	full := ComponentIdentifiers{
		Vendor: "Acme", Product: "Widget", Version: "1.0",
		CPE:    "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
		PURL:   "pkg:golang/acme/widget@1.0",
		Image:  "registry.example/acme/widget:1.0",
		Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	withCPE, err := newTestComponent("c1", full)
	if err != nil {
		t.Fatalf("NewComponent(cpe): unexpected error: %v", err)
	}
	// Same CPE, different weaker identifiers → identical key.
	diffLower := full
	diffLower.PURL = "pkg:maven/org.acme/widget@1.0"
	diffLower.Digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	diffLower.Image = "other.example/acme/widget:1.0"
	diffLower.Version = "2.0"
	withCPE2, err := newTestComponent("c2", diffLower)
	if err != nil {
		t.Fatalf("NewComponent(cpe2): unexpected error: %v", err)
	}
	if withCPE.NaturalKey != withCPE2.NaturalKey {
		t.Errorf("cpe must dominate: keys differ though only weaker identifiers differ:\n%q\n%q", withCPE.NaturalKey, withCPE2.NaturalKey)
	}

	// No CPE → purl dominates; the same purl as a cpe value must not
	// collide (prefix tags).
	noCPE := full
	noCPE.CPE = ""
	withPURL, err := newTestComponent("c3", noCPE)
	if err != nil {
		t.Fatalf("NewComponent(purl): unexpected error: %v", err)
	}
	withPURL2, err := newTestComponent("c4", ComponentIdentifiers{CPE: full.PURL})
	if err != nil {
		t.Fatalf("NewComponent(cpe=purl value): unexpected error: %v", err)
	}
	if withPURL.NaturalKey == withPURL2.NaturalKey {
		t.Error("prefix tags must separate identifier types: purl value == cpe value collision")
	}

	// No purl → digest dominates over image and vendor/product.
	onlyDigest, err := newTestComponent("c5", ComponentIdentifiers{Digest: full.Digest, Image: full.Image, Vendor: "Acme", Product: "Widget", Version: "9.9"})
	if err != nil {
		t.Fatalf("NewComponent(digest): unexpected error: %v", err)
	}
	digestOnly, err := newTestComponent("c6", ComponentIdentifiers{Digest: full.Digest})
	if err != nil {
		t.Fatalf("NewComponent(digest only): unexpected error: %v", err)
	}
	if onlyDigest.NaturalKey != digestOnly.NaturalKey {
		t.Error("digest must dominate image and vendor/product")
	}
	if onlyDigest.NaturalKey == withPURL.NaturalKey {
		t.Error("digest key must differ from a purl key with the same text (prefix tags)")
	}

	// No digest → image dominates; without image the vendor/product pair.
	onlyImage, err := newTestComponent("c7", ComponentIdentifiers{Image: full.Image, Vendor: "Acme", Product: "Widget"})
	if err != nil {
		t.Fatalf("NewComponent(image): unexpected error: %v", err)
	}
	imageOnly, err := newTestComponent("c8", ComponentIdentifiers{Image: full.Image})
	if err != nil {
		t.Fatalf("NewComponent(image only): unexpected error: %v", err)
	}
	if onlyImage.NaturalKey != imageOnly.NaturalKey {
		t.Error("image must dominate vendor/product")
	}
	noImage := full
	noImage.CPE, noImage.PURL, noImage.Digest, noImage.Image = "", "", "", ""
	withVPP, err := newTestComponent("c9", noImage)
	if err != nil {
		t.Fatalf("NewComponent(vpp): unexpected error: %v", err)
	}
	if withVPP.NaturalKey == onlyImage.NaturalKey {
		t.Error("vpp fallback must not collide with an image identifier")
	}
}

// TestNaturalKeyNormalisation verifies the per-type folding: cpe/digest
// are case-folded (case-insensitive forms), purl/image are not (tags are
// case-sensitive), and the vendor/product fallback uses the normalised
// comparison keys when present and a defensive fold otherwise.
func TestNaturalKeyNormalisation(t *testing.T) {
	upper, err := newTestComponent("c1", ComponentIdentifiers{CPE: "CPE:2.3:A:ACME:WIDGET:1.0:*:*:*:*:*:*:*"})
	if err != nil {
		t.Fatalf("NewComponent(upper cpe): unexpected error: %v", err)
	}
	lower, err := newTestComponent("c2", ComponentIdentifiers{CPE: "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"})
	if err != nil {
		t.Fatalf("NewComponent(lower cpe): unexpected error: %v", err)
	}
	if upper.NaturalKey != lower.NaturalKey {
		t.Error("CPE is case-insensitive: case variants must share a natural key")
	}

	// Vendor/product/version fallback: raw case variants with the same
	// normalised keys share a key.
	a, err := NewComponent("c1", "asset-1",
		ComponentIdentifiers{Vendor: "ACME Corp", Product: "Widget", Version: "1.0.0"},
		"acme corp", "widget", "1.0.0", VersionSchemeSemver)
	if err != nil {
		t.Fatalf("NewComponent(a): unexpected error: %v", err)
	}
	b, err := NewComponent("c2", "asset-1",
		ComponentIdentifiers{Vendor: "acme corp", Product: "widget", Version: "1.0.0"},
		"acme corp", "widget", "1.0.0", VersionSchemeSemver)
	if err != nil {
		t.Fatalf("NewComponent(b): unexpected error: %v", err)
	}
	if a.NaturalKey != b.NaturalKey {
		t.Error("fallback must key on the normalised vendor/product/version")
	}

	// Different versions → different keys.
	c, err := NewComponent("c3", "asset-1",
		ComponentIdentifiers{Vendor: "Acme", Product: "Widget", Version: "1.0"},
		"acme", "widget", "", VersionSchemeSemver)
	if err != nil {
		t.Fatalf("NewComponent(c): unexpected error: %v", err)
	}
	if c.NaturalKey == a.NaturalKey {
		t.Error("a versionless row must not share the key of a versioned row")
	}

	// An unparseable version (no version_norm) still distinguishes the
	// row from a versionless one — never a silent merge — and a raw
	// spelling stays distinct from its normalised spelling.
	d, err := NewComponent("c4", "asset-1",
		ComponentIdentifiers{Vendor: "Acme", Product: "Widget", Version: "1.0"},
		"acme", "widget", "", VersionSchemeUnknown)
	if err != nil {
		t.Fatalf("NewComponent(d): unexpected error: %v", err)
	}
	versionless, err := NewComponent("c5", "asset-1",
		ComponentIdentifiers{Vendor: "Acme", Product: "Widget", Version: ""},
		"acme", "widget", "", VersionSchemeUnknown)
	if err != nil {
		t.Fatalf("NewComponent(versionless): unexpected error: %v", err)
	}
	if d.NaturalKey == versionless.NaturalKey {
		t.Error("raw version must participate when no normalised version exists")
	}
	if d.NaturalKey == a.NaturalKey {
		t.Error("raw and normalised versions must not silently share a key")
	}
}

// TestNaturalKeyEmptyNeverCollides verifies the empty/NULL guarantee: an
// empty identifier is skipped to the next priority level and an all-empty
// row errors instead of hashing the empty string.
func TestNaturalKeyEmptyNeverCollides(t *testing.T) {
	// purl "x" with an empty cpe must not key like cpe "x" (already
	// covered above) nor like a row whose purl is missing entirely.
	withPURL, err := newTestComponent("c1", ComponentIdentifiers{PURL: "pkg:deb/debian/curl@7.0"})
	if err != nil {
		t.Fatalf("NewComponent: unexpected error: %v", err)
	}
	fallback, err := newTestComponent("c2", ComponentIdentifiers{Vendor: "debian", Product: "curl", Version: "7.0"})
	if err != nil {
		t.Fatalf("NewComponent: unexpected error: %v", err)
	}
	if withPURL.NaturalKey == fallback.NaturalKey {
		t.Error("an empty purl must fall through to the vendor/product key, not collide with purl text")
	}
	if _, err := NewComponent("c3", "asset-1",
		ComponentIdentifiers{CPE: "", PURL: "", Digest: "", Image: "", Vendor: "", Product: "", Version: ""},
		"", "", "", VersionSchemeUnknown); err == nil {
		t.Error("all-empty identifiers: want error, got nil (empty must never hash)")
	}
}
