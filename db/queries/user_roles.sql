-- user_roles: the I5a role-grant statements (ARCH-005 §1/§5, WP-5a.03 /
-- DEV-089).
--
-- user_roles is the internal role grants table (migration 00009, ARCH-005
-- §1): PK (user_id, role) permits each of the five-role vocabulary
-- (security_analyst | system_responsible | administrator | auditor |
-- product_owner) at most once per user, and the DB CHECK enforces the
-- vocabulary. Roles are internal-authoritative after first login (the IdP's
-- roles claim only seeds the first-login grants, ARCH-005 §1); grants and
-- revocations are admin/claim writes, each audited by the command layer. The
-- authorizer re-reads these rows at authorise time (ARCH-005 §5) — never the
-- token's claim.

-- GrantRole grants one role to one user (ARCH-005 §1): the first-login claim
-- sync and the admin `users.roles.manage` path share this statement.
-- granted_at is the injected clock; granted_by records the origin (an admin's
-- internal id, or 'claim'), NULL allowed. ON CONFLICT (user_id, role) DO
-- NOTHING makes the grant idempotent — re-granting a held role stores
-- nothing and rewrites no grant metadata (a re-grant is not a change, so the
-- command layer writes no audit row).
-- name: GrantRole :exec
INSERT INTO user_roles (user_id, role, granted_at, granted_by)
VALUES (@user_id, @role, @granted_at, @granted_by)
ON CONFLICT (user_id, role) DO NOTHING;

-- RevokeRole removes one role from one user (ARCH-005 §1): the admin
-- `users.roles.manage` path. It is idempotent — revoking a role the user does
-- not hold deletes zero rows and is not an error. The grant's audit trail is
-- the command layer's `users.role_revoked` event, not this row.
-- name: RevokeRole :exec
DELETE FROM user_roles
WHERE user_id = @user_id AND role = @role;

-- ListRolesByUser returns one user's current roles ordered by role — the
-- authorizer's roles re-read at authorise time (ARCH-005 §5, resolvePrincipal)
-- and the admin detail read. A user with no roles yields an empty slice, not
-- an error (zero roles ⇒ deny-by-default, ARCH-005 §3). role is unique per
-- user (the PK), so the ordering is deterministic without a tiebreaker.
-- name: ListRolesByUser :many
SELECT *
FROM user_roles
WHERE user_id = @user_id
ORDER BY role;
