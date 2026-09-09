-- epss_history: the append-only EPSS history statements (ADR-013, ch. 8.4,
-- ARCH-003 §7, WP-3.03b / DEV-057). History is fed from the same EPSS run
-- that loads epss_current (TRUNCATE + COPY): after the current set is
-- swapped, the loader appends one row per cve_id with inventory relevance
-- (the candidate pre-filter set, ARCH-003 §4/§7), stamped
-- observed_on = run date. The natural key UQ (cve_id, observed_on) makes
-- the daily append idempotent — re-running a day appends nothing twice.
-- No foreign keys onto epss_current (ADR-013: the current set is replaced
-- whole by TRUNCATE + COPY and must stay unfettered; history survives its
-- swaps by cve_id alone).

-- AppendEpssHistory appends one observed EPSS score row for one CVE of one
-- run date. score/percentile are the raw EPSS values in [0,1] as read from
-- the daily file; model_version tags the scoring model/date of the
-- observed day. ON CONFLICT (cve_id, observed_on) DO NOTHING is the
-- append idempotency: the same (cve_id, observed_on) day is recorded
-- exactly once, even when the loader re-runs (the pre-filter relevant set
-- may overlap between runs of the same day).
-- name: AppendEpssHistory :exec
INSERT INTO epss_history (cve_id, observed_on, score, percentile, model_version)
VALUES (@cve_id, @observed_on, @score, @percentile, @model_version)
ON CONFLICT (cve_id, observed_on) DO NOTHING;
