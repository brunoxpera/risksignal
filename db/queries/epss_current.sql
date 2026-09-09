-- epss_current: the current EPSS daily set statements (ADR-013, ch. 8.4,
-- ARCH-002 §2.3/§3, WP-2.03a). The set is replaced whole: TRUNCATE +
-- COPY inside one transaction swap the loaded day atomically (a reader sees
-- either the complete old set or the complete new one). The table carries no
-- surrogate id and no per-row dedupe — cve_id is the natural primary key and
-- a malformed duplicate-cve load fails the COPY loudly; UQ (cve_id) is the
-- integrity constraint, not an idempotency mechanism (idempotency lives at
-- the raw-record level: re-running the same day's file is a no-op before any
-- of these statements run, ARCH-002 §2.3). score/percentile/model_version/
-- loaded_at are written as read from the daily file (missing values stay
-- absent, never a zero — ch. 8.4).

-- TruncateEpssCurrent empties the current set. It runs inside the load
-- transaction immediately before the COPY of the new day's rows; the
-- ACCESS EXCLUSIVE lock is accepted for the seconds-long load (ADR-013
-- consequence) and released at commit, so the swap stays atomic.
-- name: TruncateEpssCurrent :exec
TRUNCATE epss_current;

-- InsertEpssRows bulk-loads the daily set rows through a single pgx COPY
-- (ADR-009: the reason pgx was chosen) — one round trip for the whole set
-- instead of one INSERT per row. The caller hands over a slice of rows; the
-- generated method drives pgx CopyFrom with them. TRUNCATE + this COPY are
-- issued on the same transaction by the load path, committed together.
-- name: InsertEpssRows :copyfrom
INSERT INTO epss_current (cve_id, score, percentile, model_version, loaded_at)
VALUES ($1, $2, $3, $4, $5);

-- CountEpssRows returns the number of rows of the current set — the measured
-- daily row count of the I2 exit criterion (ADR-013: measured once, not
-- fixed in prose), asserted against the fixture after every load.
-- name: CountEpssRows :one
SELECT count(*)
FROM epss_current;

-- GetEpssByCveID loads the current score of one CVE, if the set contains it
-- — the prioritisation read of the bounded window (ARCH-002 §3: epss_current
-- is read by cve_id lookup; nothing foreign keys onto it).
-- name: GetEpssByCveID :one
SELECT cve_id, score, percentile, model_version, loaded_at
FROM epss_current
WHERE cve_id = @cve_id;
