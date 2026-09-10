-- outbox: the transactional outbox / job queue statements (ARCH-001 §1 and
-- §2, WP-1b.03). One physical table carries integration events (the I1b
-- case, type 'signal.created') and, from I2/I4, job types; the type column
-- discriminates. Rows are appended in the same WithTx transaction as their
-- state change (ch. 5.1); the relay (WP-1b.06) claims them with the
-- lease-based UPDATE ... FOR UPDATE SKIP LOCKED below, dispatches by type and
-- acks claimed -> done. Delivery is at-least-once by construction: an
-- expired lease makes a claimed row re-claimable (TAT-05), consumers stay
-- idempotent on the immutable outbox id (ch. 14.3/15.3), and the ack is
-- guarded by status='claimed' so a double dispatch cannot double-ack.

-- AppendOutbox appends one pending outbox row and returns it. status is
-- fixed to 'pending' (rows always enter the queue pending; the CHECK
-- constraint guards the state space, ARCH-001 §1); attempts starts at the
-- column default 0, lease_until and last_error stay NULL until the relay
-- claims the row. The UQ (dedupe_key) makes the append idempotent at the
-- schema level: a retried command that re-runs the same append cannot
-- enqueue twice (ADR-012 consequence, ch. 14.2) — a duplicate key surfaces
-- as a unique-violation error for the command layer to map. created_at and
-- available_at come from the injected clock (available_at may lie in the
-- future for scheduled rows).
-- name: AppendOutbox :one
INSERT INTO outbox (type, payload, status, available_at, dedupe_key, created_at)
VALUES (@type, @payload, 'pending', @available_at, @dedupe_key, @created_at)
RETURNING *;

-- OutboxDedupeKeyExists reports whether an outbox row with the dedupe key
-- already exists — queued, claimed or terminal: the UQ (dedupe_key) spans
-- the row's whole lifetime (ADR-012 point 4). The exactly-once enqueuers
-- (the scheduler scan, the DEV-067 full-import fan-in) pre-check on the
-- SAME transaction before they append: a duplicate INSERT would raise the
-- unique violation and abort the whole transaction, so an idempotent
-- re-enqueue is a pre-checked no-op, never a failed statement. The check
-- runs on the caller's transaction and therefore sees the transaction's
-- own uncommitted appends too.
-- name: OutboxDedupeKeyExists :one
SELECT EXISTS (SELECT 1 FROM outbox WHERE dedupe_key = @dedupe_key) AS exists;

-- ClaimOutboxBatch claims the bounded batch of rows due for delivery and
-- returns id, type, payload and the incremented attempts count of each
-- claimed row. This is the ARCH-001 §2 drain statement: pending rows whose
-- available_at has passed AND claimed rows whose lease has expired (the
-- crash-recovery path, TAT-05) are picked up in available_at order, skipped
-- when another worker instance holds them (FOR UPDATE SKIP LOCKED — several
-- workers can drain concurrently without a broker) and atomically moved to
-- claimed with a fresh 60s lease. Lease and ordering follow ARCH-001 §2;
-- id is the deterministic tie-break within one available_at.
-- name: ClaimOutboxBatch :many
UPDATE outbox SET
    status = 'claimed',
    lease_until = now() + interval '60 seconds',
    attempts = attempts + 1
WHERE id IN (
    SELECT id
    FROM outbox
    WHERE available_at <= now()
      AND (status = 'pending' OR (status = 'claimed' AND lease_until < now()))
    ORDER BY available_at, id
    LIMIT @batch_size
    FOR UPDATE SKIP LOCKED
)
RETURNING id, type, payload, attempts;

-- ReclaimExpiredOutboxLeases is the focused form of the §2 reclaim
-- predicate: it claims only rows stuck in 'claimed' with an expired lease —
-- the redelivery path after a crashed worker. Same mechanics as
-- ClaimOutboxBatch (fresh 60s lease, attempts + 1, bounded, SKIP LOCKED),
-- ordered by lease_until so the longest-expired leases are redelivered
-- first. ClaimOutboxBatch already covers this predicate in the normal drain;
-- this statement lets a drain force or expedite the redelivery of stale
-- leases on its own cadence.
-- name: ReclaimExpiredOutboxLeases :many
UPDATE outbox SET
    status = 'claimed',
    lease_until = now() + interval '60 seconds',
    attempts = attempts + 1
WHERE id IN (
    SELECT id
    FROM outbox
    WHERE status = 'claimed' AND lease_until < now()
    ORDER BY lease_until, id
    LIMIT @batch_size
    FOR UPDATE SKIP LOCKED
)
RETURNING id, type, payload, attempts;

-- AckOutbox marks a successfully delivered row done — the claimed -> done
-- terminal transition. The status='claimed' guard makes the ack idempotent
-- (ARCH-001 §2): a double dispatch after a successful delivery matches zero
-- rows, so the returned count is 1 for the ack that completed the delivery
-- and 0 for every later one. The relay treats 0 as already-terminal.
-- name: AckOutbox :execrows
UPDATE outbox SET status = 'done'
WHERE id = @id AND status = 'claimed';

-- DeadLetterOutbox marks a permanently failed delivery (or one past the
-- ch. 14.2 attempt cap) as dead_letter and records the error text. Like the
-- ack it is guarded by status='claimed' — only a row the relay currently
-- holds can be dead-lettered, so a terminal row is never overwritten.
-- name: DeadLetterOutbox :execrows
UPDATE outbox SET status = 'dead_letter', last_error = @last_error
WHERE id = @id AND status = 'claimed';
