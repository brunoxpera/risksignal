// Package normalise implements the product-data normalisation and
// version-semantics helpers of ARCH-003 §2 (WP-3.04 / DEV-047): the
// application layer between the raw inventory identifiers and the pure
// domain model of DEV-044.
//
// It owns:
//
//   - NormaliseKey — the write-time comparison-key fold (NFKC + Unicode
//     trim + case fold) behind components.vendor_norm / product_norm.
//     Originals are preserved verbatim by the caller; this package only
//     derives the keys (ARCH-003 §2 "Originalwerte bleiben erhalten").
//   - the CPE 2.3, purl and image-reference decomposers (ARCH-003 §2
//     items 3-5). Each parser is strict: malformed input is a positioned
//     *SyntaxError, never a silent default or a partial struct. The
//     decomposed values are verbatim (no case folding — folding is the
//     comparison-key concern and purl namespace/name are case-sensitive
//     per ecosystem); every parser round-trips exactly:
//     Parse(s).String() == s for every accepted string.
//   - the symmetric one-hop alias closure and its chain rejection
//     (ARCH-003 §2 item 2: {value} ∪ {to | from=value} ∪ {from |
//     to=value}; chains are a data error).
//   - InferVersionScheme — the ordering-scheme inference chain
//     purl type → CPE → explicit scheme column → version shape →
//     generic/unknown (ARCH-003 §2 item 6). It consumes the VersionScheme
//     vocabulary only; ordering and range evaluation stay with DEV-044's
//     domain comparators (internal/domain/version_strategy.go) — this
//     package never re-implements an ordering.
//
// Everything here is pure, deterministic and network-free: no database, no
// clock, no I/O. The only dependency beyond the standard library is
// golang.org/x/text/unicode/norm for NFKC. The package imports domain
// values (AliasScope/AliasRule, VersionScheme, ComponentIdentifiers) and is
// imported by the import and matching use cases (WP-3.05/WP-3.06); it must
// never be imported by internal/domain (architecture gate, .go-arch-lint.yml).
package normalise
