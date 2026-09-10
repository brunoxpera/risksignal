-- comments: the append-only signal timeline statements (ARCH-004 §2.2,
-- WP-4.03 / DEV-073).
--
-- No update/delete path: a comment is never edited or deleted. Every insert
-- is also an audit event (signal.commented) written in the same transaction
-- by the command layer (WP-4.04); this file only owns the persistence.

-- InsertComment appends one comment to a signal and returns the stored row.
-- created_at comes from the injected clock; the id is the database default.
-- The signal_id FK guards the reference (a comment for an unknown signal is
-- a foreign-key violation the command layer maps to a validation error).
-- name: InsertComment :one
INSERT INTO comments (signal_id, actor_id, body, created_at)
VALUES (@signal_id, @actor_id, @body, @created_at)
RETURNING *;

-- ListCommentsBySignal returns the signal timeline ordered by created_at
-- then id (the (signal_id, created_at) index serves it). A signal without
-- comments yields no rows, never an error.
-- name: ListCommentsBySignal :many
SELECT *
FROM comments
WHERE signal_id = @signal_id
ORDER BY created_at, id;
