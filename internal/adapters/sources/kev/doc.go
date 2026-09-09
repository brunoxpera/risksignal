// Package kev implements the CISA KEV catalog source adapter
// (ARCH-002 §2.2, WP-2.06): both halves of the shared SourcePort for the
// "kev" source type — the versioned full-set fetch and the normaliser that
// streams the fetched catalog document into skeleton domain.Vulnerability
// records and their evidences (kev + kev_removed).
//
// # Fetch semantics
//
// Fetch reads the source descriptor and GETs the catalog document
// (known_exploited_vulnerabilities.json, ARCH-002 §1 endpoint) as one
// versioned full set (ch. 8.3): the whole document bytes are stored
// unchanged and hashed (SHA-256) into FetchOutput.ContentHash; the cursor
// stays nil — a full-set source advances none (CursorKindNone). The
// external id is the catalog version/date, derived from the document's own
// metadata (dateReleased, cveExploitabilityUpdated or catalogVersion,
// probed in that order) and normalised to "kev-YYYY-MM-DD" — stable for
// one catalog revision, so the raw-record natural key UQ (source_id,
// external_id, content_hash) dedupes re-imports.
//
// # Content-hash no-op (unchanged catalog)
//
// An unchanged catalog (the same bytes as the last committed raw record of
// the source) is a successful no-op run, not a re-store (ch. 8.3,
// FetchMeta.NoChange, counters all 0). The adapter is persistence-free and
// never reads the database: it compares the fetched document's hash
// against the content hash the fetch use case hands back through
// sources.config.last_content_hash (maintained after each committed run;
// DEV-032 wiring follow-up — absent today, every fetch returns a full
// output and the no-op signal activates with that wiring). NoChange is
// signalled via FetchMeta.NoChange on FetchOutput; the payload and its
// hash are returned either way.
//
// # Rate limits
//
// HTTP 429/503 is a rate limit, not a source fault (ch. 14.2): Fetch
// returns FetchMeta{RateLimited: true, RetryAfter: …} with no error
// (Retry-After parsed as seconds or an HTTP date; 0 when absent). Any
// other non-200 status is an error.
//
// # Normalise semantics
//
// Normalize parses the catalog document (its vulnerabilities[] array) and
// emits, per entry, in document order:
//
//  1. a skeleton domain.Vulnerability (cve_id; summary = shortDescription)
//     — the coupling point that lets KEV arrive before NVD (evidences
//     reference vulnerabilities); the persistence path only creates the
//     skeleton when the CVE is not yet present and never clobbers an
//     existing full NVD row (the read-before-upsert of the ingester, sqlc
//     GetVulnerabilityByCveID);
//  2. a domain.Evidence of type kev whose canonical value carries the full
//     catalog field set — {cve_id, vendor, product, vulnerability_name,
//     date_added, known_exploited, required_action, due_date,
//     known_ransomware} — a superset of the I1b kev evidence value
//     ({cve_id, known_exploited}), so the I1b rows stay valid and the
//     prioritisation reads keep working.
//
// After the entries, removals are historised (ch. 8.3, ARCH-002 §2.2):
// every CVE of NormalizeInput.PreviousKEVCVEs — the previous catalog's
// CVE set, supplied by the use case — that is absent from the new catalog
// gets a skeleton vulnerability (empty summary — the new catalog carries
// no statement for it) and a domain.Evidence of type kev_removed
// ({cve_id}), a new evidence version, never an in-place edit (ch. 6.1):
// nothing is silently dropped from an existing decision. The previous set
// is deduplicated and emitted in sorted order, so one previous set yields
// one deterministic removal stream.
//
// A malformed entry (not decodable, no cveID, an unparsable dateAdded or
// dueDate) is isolated through sink.RecordError — position
// ("vulnerabilities[i]"), a stable reason code and the SHA-256 of the
// offending element — and never aborts the pass (ch. 8.1 step 5); the
// healthy entries keep flowing.
//
// # Determinism
//
// Every emitted value is a fixed-field-order struct (no maps) and every
// date is stored in its canonical YYYY-MM-DD form, so the marshalled value
// — and with it the evidence value hash (UQ (raw_record_id, type,
// value_hash)) — is stable for one catalog revision: re-running one raw
// record emits the identical event stream.
package kev
