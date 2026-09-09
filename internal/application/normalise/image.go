package normalise

import (
	"regexp"
	"strings"
)

// This file implements the image-reference decomposition of ARCH-003 §2
// item 5:
//
//	[registry/]repository[:tag][@digest]
//
// (the original column stores registry/repository[:tag][@digest]) into
// registry/repository/tag/digest. A digest is immutable and stronger than
// a mutable tag — that asymmetry is exactly what the container_digest
// match method and the natural-key priority digest > image build on
// (ARCH-003 §2 item 5, ch. 9.2). A malformed reference is a positioned
// *SyntaxError, never a silent default.
//
// Grammar notes (docker reference grammar, distribution/reference):
//
//   - repository is the '/'‑joined path. A leading path component that
//     contains '.' or ':', or equals "localhost", is a registry domain
//     (possibly host:port); otherwise the reference has no explicit
//     registry and Registry stays "" — defaulting to docker.io is a
//     pull-time concern, decomposition must not invent an origin.
//   - Repository path components must be lowercase (docker rejects
//     uppercase remote names). Registry hostnames and tags keep their
//     case verbatim (tags are case-sensitive and mutable).
//   - tag, when present after the last ':', is non-empty and at most 128
//     chars of [A-Za-z0-9_][A-Za-z0-9_.-]*.
//   - digest is "algorithm:encoded" with a lowercase hex encoded part of
//     at least 32 digits (sha256:… is the common form); it is immutable
//     and never rewritten.
//
// No defaulting and no case folding: the decomposer preserves every input
// verbatim, so Parse(s).String() == s for every accepted reference.

// Registry detection: a first path component that contains '.' or ':' or
// equals "localhost" is a registry domain.
func isRegistryDomain(component string) bool {
	return component == "localhost" || strings.ContainsAny(component, ".:")
}

// ImageRef is a decomposed container image reference (ARCH-003 §2 item 5,
// components.image). All fields are verbatim; empty string means absent.
// Registry "" means the reference carries no explicit registry (the
// pull-time default docker.io is not fabricated).
type ImageRef struct {
	Registry   string // host[:port], "" when absent
	Repository string // '/'‑joined path, required, lowercase
	Tag        string // "" when absent
	Digest     string // "algorithm:hex", "" when absent
}

var (
	imageDigestRe   = regexp.MustCompile(`^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[0-9a-f]{32,}$`)
	imageTagRe      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	imageRepoPartRe = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	imageRegistryRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?(?::[0-9]+)?$`)
)

// ParseImageRef decomposes one image reference of the form
// [registry/]repository[:tag][@digest]. Structural failures (missing
// repository, empty tag/digest, uppercase or malformed repository
// components, malformed tag or digest) are positioned *SyntaxError
// values.
func ParseImageRef(input string) (ImageRef, error) {
	if input == "" {
		return ImageRef{}, wholeInputError("image", input, "empty image reference")
	}
	if hasControlChar(input) {
		return ImageRef{}, wholeInputError("image", input, "image reference contains control characters")
	}

	r := ImageRef{}
	rest := input

	// Digest: everything after the last '@'.
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		r.Digest = rest[i+1:]
		rest = rest[:i]
		if r.Digest == "" {
			return ImageRef{}, syntaxError("image", "digest", 0, input, "digest after '@' must not be empty")
		}
		if !imageDigestRe.MatchString(r.Digest) {
			return ImageRef{}, syntaxError("image", "digest", 0, input, "digest must be \"algorithm:lowercase-hex\" with at least 32 hex digits (e.g. sha256:…)")
		}
	}
	if rest == "" {
		return ImageRef{}, wholeInputError("image", input, "image reference must carry a repository")
	}

	// Tag: a ':' after the last '/' (a registry port ':' sits before the
	// last '/', so it never collides with the tag separator).
	if i := strings.LastIndexByte(rest, ':'); i >= 0 && strings.LastIndexByte(rest, '/') < i {
		r.Tag = rest[i+1:]
		rest = rest[:i]
		if r.Tag == "" {
			return ImageRef{}, syntaxError("image", "tag", 0, input, "tag after ':' must not be empty")
		}
		if !imageTagRe.MatchString(r.Tag) {
			return ImageRef{}, syntaxError("image", "tag", 0, input, "tag must match [A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
		}
	}
	if rest == "" {
		return ImageRef{}, wholeInputError("image", input, "image reference must carry a repository")
	}

	// Split the registry off the repository path.
	parts := strings.Split(rest, "/")
	if len(parts) > 1 && isRegistryDomain(parts[0]) {
		r.Registry = parts[0]
		if !imageRegistryRe.MatchString(r.Registry) {
			return ImageRef{}, syntaxError("image", "registry", 0, input, "registry must be a hostname or host:port")
		}
		rest = strings.Join(parts[1:], "/")
		if rest == "" {
			return ImageRef{}, syntaxError("image", "repository", 0, input, "repository must not be empty after the registry")
		}
	}
	// Validate the repository path: non-empty lowercase components.
	for _, seg := range strings.Split(rest, "/") {
		if !imageRepoPartRe.MatchString(seg) {
			return ImageRef{}, syntaxError("image", "repository", 0, input, "repository components must be lowercase letters/digits separated by '.', '_', '-' or '/' (component \""+seg+"\" is malformed)")
		}
	}
	r.Repository = rest
	return r, nil
}

// String reassembles the decomposed reference. For every reference
// ParseImageRef accepts, Parse(s).String() == s — no defaulting (docker.io
// is never invented), no case folding, original order preserved.
func (r ImageRef) String() string {
	var b strings.Builder
	if r.Registry != "" {
		b.WriteString(r.Registry)
		b.WriteByte('/')
	}
	b.WriteString(r.Repository)
	if r.Tag != "" {
		b.WriteByte(':')
		b.WriteString(r.Tag)
	}
	if r.Digest != "" {
		b.WriteByte('@')
		b.WriteString(r.Digest)
	}
	return b.String()
}
