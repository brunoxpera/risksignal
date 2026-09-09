# Reduced, versioned reference fixtures of the I2 isolation + fault-injection
# integration tests (DEV-036, ARCH-002 §6 / ch. 17.2). All payloads are
# small reduced shapes of the public sources, documented with their fetch
# date; they are served network-free through in-process httptest servers
# whose endpoint the source rows under test point at (the adapters take the
# base URL from the sources row, never from the network).

# nvd-window-2026-09-09.json
#   One NVD Vulnerability API 2.0 window page (fetch date 2026-09-09,
#   bounded window ending 2026-09-09T09:30:00Z): two reduced CVE records
#   (CVE-2026-0001 with V3.1 + V2 metrics, configurations and references;
#   CVE-2026-0002 with a V2 metric only and no English description). Shape
#   verified against the API 2.0 live response structure (nvd normalize
#   fixtures). Served verbatim for the window of both import runs, so the
#   twofold import of the identical window is deterministic.

# kev-catalog-2026-09-09.json
#   Reduced CISA KEV catalog revision of 2026-09-09 (dateReleased
#   2026-09-09T04:00:00.000Z -> external id kev-2026-09-09): three entries
#   (CVE-2026-0101..0103).

# kev-catalog-malformed-2026-09-09.json
#   Same catalog envelope with two entries: one healthy entry
#   (CVE-2026-3001) and one malformed entry that carries no cveID at
#   vulnerabilities[1] — the failure-isolation fixture (exit criterion 2).

# kev-catalog-corrected-2026-09-09.json
#   The corrected revision of the malformed catalog (the fixture swap
#   stands in for the parser/data fix before `quarantine reprocess`): the
#   healthy entry CVE-2026-3001 only, so the reprocess pass is clean and
#   single-vulnerability (the row resolves with resolved_vulnerability_id
#   pointing at the materialised CVE).

# epss_scores-2026-09-09.csv.gz / epss_scores-2026-09-10.csv.gz
#   Two daily EPSS sets (FIRST daily-file shape: a #model_version comment
#   line, the cve,epss,percentile header and plain data rows), gzip
#   compressed exactly as the epss fetch stores them (fetch dates
#   2026-09-09 and 2026-09-10). Day two shares CVE-2026-0001 with day one
#   and drops the other two — the atomic-replacement fixture.
