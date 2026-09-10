-- 00009_i5a_users_roles.sql — I5a identity schema: users + user_roles
-- (ARCH-005 §1, WP-5a.02 / DEV-088).
--
-- Iteration I5a turns the free-string audit actor into a real, referenceable
-- identity (ARCH-005 §1/§6, ADR-014): OIDC authenticates, RiskSignal
-- authorises, and the internal user id becomes the value audit_events.actor_id
-- stores for user actors (actor_type = 'user' ⇒ actor_id = users.id). This
-- migration owns only the identity *storage*: the sqlc queries (WP-5a.03),
-- the OIDC adapter (WP-5a.04) and the permission gates (WP-5a.06) land later
-- on top of it. It is purely additive — no existing table, column or
-- constraint changes meaning, and no existing row is touched (ADR-010).
--
-- It carries (ARCH-005 §1):
--   * users — the minimal identity record (data minimisation, ch. 12,
--     FR-028/NFR-014): the issuer-qualified external subject id, a display
--     name, an optional e-mail (notifications only, never the login key), the
--     deactivation instant and the last-login instant. Passwords and MFA are
--     the IdP's concern and are never stored. Users are deactivated, never
--     deleted (ADR-014): the internal id stays permanently referenceable so
--     the audit trail stays resolvable.
--   * user_roles — the internal role grants. The five roles are a fixed
--     domain vocabulary (domain.Role, ch. 3 / §12.2), enforced here as a DB
--     CHECK; there is deliberately no separate roles catalogue table. A user
--     holds zero or more roles; zero roles means deny-by-default on
--     everything (ARCH-005 §3).
--
-- The seed below installs the local identities the role-matrix, demo and
-- bypass tests reference (ARCH-005 §4.2): the multi-role `local-developer`
-- (the ch. 11.2 "lokale Mehrrollen-Nutzung" and the default
-- `auth.bypass_principal`) and one single-role user per role. The ids are
-- fixed literal UUIDs — constants, not gen_random_uuid() — so tests and the
-- demo can reference them deterministically; `granted_by = 'seed'` marks them
-- as migration-seeded grants (a claim-synced grant would record 'claim', an
-- admin grant the admin's internal id, ARCH-005 §1).
--
-- No Down migration: migrations are forward-only (implementation concept
-- ch. 7.4); rollbacks run the previous application image, not SQL.

-- +goose Up

-- users (ARCH-005 §1, ch. 12, FR-028, NFR-014): the minimal identity record.
-- subject_id is the external OIDC `sub`, issuer-qualified "<issuer>::<sub>"
-- so a provider migration can never collide two subjects — it is the login
-- key and UQ. display_name is denormalised into audit rows at event time (the
-- field ADR-014 later clears); email is optional and a notification recipient
-- only. deactivated_at NULL = active (a deactivated user still resolves in the
-- audit trail but holds no rights); last_login_at is written from the injected
-- clock on each successful login/session/token resolution. created_at /
-- updated_at come from the injected clock. No password, no mfa_*, no further
-- profile PII (data minimisation).
CREATE TABLE users (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_id     text        NOT NULL,
    display_name   text        NOT NULL,
    email          text        NULL,
    deactivated_at timestamptz NULL,
    last_login_at  timestamptz NULL,
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    CONSTRAINT users_subject_id_key UNIQUE (subject_id)
);

COMMENT ON TABLE users IS
    'Minimal internal identity record (ARCH-005 §1, ch. 12, FR-028): OIDC subject + display name + optional e-mail + roles; deactivated, never deleted (ADR-014), so the audit actor_id stays resolvable';
COMMENT ON COLUMN users.id IS
    'Stable internal id — the value audit_events.actor_id stores for user actors and the key audit.reveal_identity resolves on (ADR-014)';
COMMENT ON COLUMN users.subject_id IS
    'External OIDC subject (issuer-qualified "<issuer>::<sub>", UQ users_subject_id_key); the login key — a provider migration can never collide two subjects';
COMMENT ON COLUMN users.display_name IS
    'Display name, denormalised into audit rows at event time (the field ADR-014 later clears)';
COMMENT ON COLUMN users.email IS
    'Optional e-mail (notification recipient only); never the login key (ch. 12 data minimisation)';
COMMENT ON COLUMN users.deactivated_at IS
    'Deactivation instant from the injected clock; NULL = active — a deactivated user still resolves in audit but holds no rights (ADR-014)';
COMMENT ON COLUMN users.last_login_at IS
    'Last successful login/session/token resolution from the injected clock; NULL = never logged in';
COMMENT ON COLUMN users.created_at IS
    'Insert instant from the injected clock';
COMMENT ON COLUMN users.updated_at IS
    'Last mutation instant from the injected clock';

-- user_roles (ARCH-005 §1, ch. 3 / §12.2): the internal role grants. The five
-- roles are a fixed domain vocabulary — a DB CHECK, not a foreign key into a
-- catalogue table (there is none; GET /roles lists the enum from code). PK
-- (user_id, role) permits each role at most once per user and covers the
-- authorizer's per-user role read (ARCH-005 §5); ON DELETE CASCADE is dormant
-- in production (users are never deleted, ADR-014) but keeps a future hard
-- delete consistent. granted_at/granted_by record an auditable grant
-- (granted_by = the admin's internal id or 'claim' for a claim-synced grant).
CREATE TABLE user_roles (
    user_id    uuid        NOT NULL,
    role       text        NOT NULL,
    granted_at timestamptz NOT NULL,
    granted_by text        NULL,
    CONSTRAINT user_roles_role_check CHECK (role IN ('security_analyst', 'system_responsible', 'administrator', 'auditor', 'product_owner')),
    CONSTRAINT user_roles_user_id_fkey FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role)
);

-- IX (role) serves the reverse read — the holders of one role (admin role
-- management, users.roles.manage, ARCH-005 §1/§3) — which PK (user_id, role)
-- does not cover.
CREATE INDEX user_roles_role_idx ON user_roles (role);

COMMENT ON TABLE user_roles IS
    'Internal role grants (ARCH-005 §1, ch. 3 / §12.2): the five-role controlled vocabulary as a DB CHECK; a user holds zero or more roles — zero roles means deny-by-default on everything';
COMMENT ON COLUMN user_roles.user_id IS
    'The user holding the role; ON DELETE CASCADE (dormant — users are deactivated, never deleted, ADR-014)';
COMMENT ON COLUMN user_roles.role IS
    'Role machine key, one of the five-role vocabulary (user_roles_role_check): security_analyst | system_responsible | administrator | auditor | product_owner';
COMMENT ON COLUMN user_roles.granted_at IS
    'Grant instant from the injected clock (auditable)';
COMMENT ON COLUMN user_roles.granted_by IS
    'Grant origin: the admin''s internal user id, or ''claim'' for a claim-synced first-login grant, or ''seed'' for the migration seed; NULL allowed';
COMMENT ON CONSTRAINT user_roles_role_check ON user_roles IS
    'The five-role controlled vocabulary (ch. 3 / §12.2): security_analyst | system_responsible | administrator | auditor | product_owner';

-- Seed the local identities (ARCH-005 §4.2). Fixed literal UUIDs (RFC 4122
-- variant/version-4 layout, constants not gen_random_uuid) so tests and the
-- demo reference them deterministically. local-developer holds all five roles
-- (the ch. 11.2 local multi-role usage and the default auth.bypass_principal);
-- the five single-role users back the role-matrix and demo tests. granted_by
-- 'seed' marks every row as a migration seed, not a claim sync or an admin
-- grant.
INSERT INTO users (id, subject_id, display_name, email, deactivated_at, last_login_at, created_at, updated_at) VALUES
    ('e5a00000-0000-4000-8000-000000000001', 'local::local-developer',    'Local Developer',    NULL, NULL, NULL, now(), now()),
    ('e5a00000-0000-4000-8000-000000000002', 'local::security-analyst',   'Security Analyst',   NULL, NULL, NULL, now(), now()),
    ('e5a00000-0000-4000-8000-000000000003', 'local::system-responsible', 'System Responsible', NULL, NULL, NULL, now(), now()),
    ('e5a00000-0000-4000-8000-000000000004', 'local::administrator',      'Administrator',      NULL, NULL, NULL, now(), now()),
    ('e5a00000-0000-4000-8000-000000000005', 'local::auditor',            'Auditor',            NULL, NULL, NULL, now(), now()),
    ('e5a00000-0000-4000-8000-000000000006', 'local::product-owner',      'Product Owner',      NULL, NULL, NULL, now(), now());

INSERT INTO user_roles (user_id, role, granted_at, granted_by) VALUES
    ('e5a00000-0000-4000-8000-000000000001', 'security_analyst',   now(), 'seed'),
    ('e5a00000-0000-4000-8000-000000000001', 'system_responsible', now(), 'seed'),
    ('e5a00000-0000-4000-8000-000000000001', 'administrator',      now(), 'seed'),
    ('e5a00000-0000-4000-8000-000000000001', 'auditor',            now(), 'seed'),
    ('e5a00000-0000-4000-8000-000000000001', 'product_owner',      now(), 'seed'),
    ('e5a00000-0000-4000-8000-000000000002', 'security_analyst',   now(), 'seed'),
    ('e5a00000-0000-4000-8000-000000000003', 'system_responsible', now(), 'seed'),
    ('e5a00000-0000-4000-8000-000000000004', 'administrator',      now(), 'seed'),
    ('e5a00000-0000-4000-8000-000000000005', 'auditor',            now(), 'seed'),
    ('e5a00000-0000-4000-8000-000000000006', 'product_owner',      now(), 'seed');
