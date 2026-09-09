package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// natural key derivation (ARCH-003 §1.3): components.natural_key is a
// SHA-256 of the strongest identifier in priority order
// cpe > purl > digest > image > vendor/product/version, prefix-tagged and
// normalised, so an empty/NULL identifier never collides and a value from
// one identifier type never collides with the same value from another type.
//
// The key is an identity determinism key, not a semantic-equality key:
// two spellings of the same real-world component that differ in the chosen
// identifier produce two distinct keys (both rows stay visible) rather than
// one silently overwriting the other.

// naturalKeyTag prefixes the hash input with the identifier type. The tags
// are short ASCII words; a NUL byte separates the tag from the value so a
// crafted value can never be confused with the tag boundary.
type naturalKeyTag string

const (
	naturalKeyCPE    naturalKeyTag = "cpe"
	naturalKeyPURL   naturalKeyTag = "purl"
	naturalKeyDigest naturalKeyTag = "digest"
	naturalKeyImage  naturalKeyTag = "image"
	naturalKeyVPP    naturalKeyTag = "vpp" // vendor/product(/version) fallback
)

// ComponentNaturalKey derives the natural key of one component row — the
// exported form of componentNaturalKey for callers that assemble rows
// before an id exists (the demo seed and the WP-3.05 import validate step
// derive keys per inventory row, while NewComponent applies the same
// derivation internally). The derivation is a pure function of the raw
// identifiers and the write-time comparison keys, so the exported and the
// internal form can never diverge.
func ComponentNaturalKey(ids ComponentIdentifiers, vendorNorm, productNorm, versionNorm string) (string, error) {
	return componentNaturalKey(ids, vendorNorm, productNorm, versionNorm)
}

// componentNaturalKey derives the natural key of one component row. The
// strongest present identifier wins; the per-type normalisation is:
//
//   - cpe:     trim + lowercase — CPE 2.3 is case-insensitive by spec
//   - digest:  trim + lowercase — digests are canonically lowercase
//   - purl:    trim only — purl namespace/name are case-sensitive per
//     ecosystem; folding them could silently merge distinct packages
//   - image:   trim only — tags are case-sensitive and mutable; folding
//     could silently merge distinct tags
//   - vendor/product/version: the normalised comparison keys when present
//     (already NFKC+trim+lowercase at write time, ARCH-003 §2), otherwise a
//     defensive trim + lowercase of the raw originals; the version part is
//     included only when the row carries one, so an unparseable version
//     stays distinguishable from a versionless row.
//
// An empty identifier is never hashed: the derivation skips to the next
// priority level, and a row with no identifier at all errors instead of
// hashing the empty string (empty/NULL never collides).
func componentNaturalKey(ids ComponentIdentifiers, vendorNorm, productNorm, versionNorm string) (string, error) {
	input, err := naturalKeyInput(ids, vendorNorm, productNorm, versionNorm)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:]), nil
}

// naturalKeyInput builds the prefix-tagged, normalised hash input for the
// strongest identifier present.
func naturalKeyInput(ids ComponentIdentifiers, vendorNorm, productNorm, versionNorm string) (string, error) {
	if cpe := trim(ids.CPE); cpe != "" {
		return naturalKeyTagInput(naturalKeyCPE, strings.ToLower(cpe)), nil
	}
	if purl := trim(ids.PURL); purl != "" {
		return naturalKeyTagInput(naturalKeyPURL, purl), nil
	}
	if digest := trim(ids.Digest); digest != "" {
		return naturalKeyTagInput(naturalKeyDigest, strings.ToLower(digest)), nil
	}
	if image := trim(ids.Image); image != "" {
		return naturalKeyTagInput(naturalKeyImage, image), nil
	}
	// Fallback: vendor/product(/version). Prefer the normalised comparison
	// keys (they are the canonical, already-folded spellings); fall back to
	// a defensive trim + lowercase of the raw originals when a norm column
	// is empty. The version participates only when the row carries one.
	vendor := pickNormalised(vendorNorm, ids.Vendor)
	product := pickNormalised(productNorm, ids.Product)
	if vendor == "" || product == "" {
		return "", fmt.Errorf("no identifier present (cpe, purl, digest, image, or vendor/product)")
	}
	input := naturalKeyTagInput(naturalKeyVPP, vendor)
	input += lengthPrefixed(product)
	if version := pickNormalised(versionNorm, ids.Version); version != "" {
		input += lengthPrefixed(version)
	}
	return input, nil
}

// pickNormalised returns norm when the caller provided a normalised key,
// otherwise a defensive trim + lowercase fold of the raw original.
func pickNormalised(norm, raw string) string {
	if norm != "" {
		return norm
	}
	return strings.ToLower(trim(raw))
}

// naturalKeyTagInput prefixes one value with its type tag, NUL-separated.
func naturalKeyTagInput(tag naturalKeyTag, value string) string {
	return string(tag) + "\x00" + value
}

// lengthPrefixed renders a part with its byte length so concatenated parts
// can never be re-segmented ambiguously.
func lengthPrefixed(s string) string {
	return fmt.Sprintf("\x00%d:%s", len(s), s)
}

// trim is the domain's defensive trim used before identifier checks and
// hashing; full NFKC folding of the originals happens at the boundary.
func trim(s string) string {
	return strings.TrimSpace(s)
}
