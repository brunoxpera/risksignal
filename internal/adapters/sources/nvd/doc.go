// Package nvd implements the NVD CVE API 2.0 source adapter
// (ARCH-002 §2.1, WP-2.05a, DEV-039): the fetch half of the shared
// SourcePort for the "nvd" source type.
//
// The adapter performs the bounded-window fetch only. Normalisation of the
// fetched document is the separate normalise half (DEV-040); Normalize is a
// stub here that reports "not implemented".
//
// # Fetch semantics
//
// Fetch reads the source descriptor and the bounded window of one
// source.fetch slice and walks the NVD Vulnerability API 2.0 in full:
// GET <endpoint>/rest/json/cves/2.0?lastModStartDate=…&lastModEndDate=…&
// startIndex=…&resultsPerPage=2000. The walk advances startIndex by
// resultsPerPage and terminates on a page whose vulnerabilities array is
// empty — totalResults is read into the page struct but never trusted as a
// loop bound (ARCH-002 §2.1).
//
// The window is bounded by the injected clock: To = the input window's To
// (the fetch use case stamps it with clock.Now(); no wall clock is read
// here) and From = the stored last-modified cursor minus the configured
// overlap (config.overlap, hours; 2 h default). A first run without a
// stored cursor starts at To minus the configured look-back window
// (config.window, hours or a duration string; 24 h default).
//
// One raw record per fetch slice (window). FetchOutput carries a single
// storable slice — the merged single-slice port of WP-2.04 (FetchSource
// stores exactly one raw record per Fetch call) — so the whole window is
// one record: its payload is the verbatim page bytes joined with '\n'
// (every page's bytes stay unchanged), its external id is
// "nvd:<window-from>:<window-to>" and its content hash is the SHA-256 of
// the joined bytes. A window without modified CVEs still stores its single
// empty page — the record of "no changes" — so the cursor can advance.
//
// # Rate limits
//
// HTTP 429/503 is a rate limit, not a source fault (ch. 14.2): Fetch
// returns FetchMeta{RateLimited: true, RetryAfter: …} with no error and
// stops the walk (Retry-After parsed as seconds or an HTTP date; 0 when
// absent). The fetch use case records the run rate-limited, does not
// advance the cursor, and the whole window is retried after the backoff —
// a walk interrupted mid-pagination therefore never stores a partial
// window.
//
// # API key (secret reference)
//
// sources.config.api_key_ref holds a reference — "env:RISKSIGNAL_NVD_API_KEY"
// — never the key literal (ARCH-002 §1, TR-013). Fetch resolves the
// reference at fetch time and injects the value as the apiKey query
// parameter. The resolved value never enters FetchOutput, logs, metrics or
// audit snapshots; when no reference is configured (or the environment
// variable is unset) the adapter falls back to the lower unauthenticated
// request rate.
package nvd
