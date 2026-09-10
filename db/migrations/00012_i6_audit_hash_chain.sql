-- 00012_i6_audit_hash_chain.sql — optional audit hash chain (ARCH-007 §7
-- control 3b, §11; WP-6.02 / DEV-112).
--
-- Security hardening control 3b (§12.3/§12.4 "Audit-Integrität") adds an
-- *optional*, config-gated cryptographic hash chain over the append-only
-- audit trail: with retention.hash_chain_enabled on, AuditRepo.Append computes
-- row_hash = SHA-256(prev_hash ‖ canonical row bytes) inside the same
-- transaction, and a maintenance/diagnose command verifies the chain
-- end-to-end. The two columns are nullable and the chain is off by default, so
-- this migration is purely additive and no existing row (or the append path's
-- write semantics) changes (ADR-010). It is kept separate from 00011 so the
-- chain can be enabled without entangling the core retention schema.
--
-- No write-path change lands here: the columns are added and the read/verify
-- queries exist, but computing/stamping row_hash is a later I6 step (§7
-- control 3b, WP-6.10); the append path already inserts only its explicit
-- column list, so the new nullable columns are inert until then.
--
-- No Down migration: migrations are forward-only (implementation concept
-- ch. 7.4); rollbacks run the previous application image, not SQL.

-- +goose Up

-- prev_hash / row_hash are NULL until hash chaining is enabled and the row is
-- stamped (existing rows stay NULL and are simply not part of the chain). The
-- chain order is the audit trail's stable order (occurred_at then id), the
-- same order the per-aggregate timeline reads use.
ALTER TABLE audit_events
    ADD COLUMN prev_hash text NULL,
    ADD COLUMN row_hash  text NULL;

COMMENT ON COLUMN audit_events.prev_hash IS
    'row_hash of the preceding audit event in the chain order (occurred_at, id); NULL when the hash chain is disabled or the row predates it (ARCH-007 §7 control 3b)';
COMMENT ON COLUMN audit_events.row_hash IS
    'SHA-256(prev_hash ‖ canonical row bytes) of this event; NULL when the hash chain is disabled or the row predates it; verified end-to-end by the chain-verify command';
