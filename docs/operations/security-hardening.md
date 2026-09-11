# Security hardening (WP-6.10 / DEV-123)

The I6 hardening controls of ARCH-007 §7 (concept ch. 12.3/§12.4): the SSRF
guard on the source-fetch path, the audit-integrity controls (append-only DB
role + optional hash chain) and the TLS/secure-header completion. Log-injection
neutralisation is part of the logging package (WP-6.08).

## SSRF guard (source fetch)

The source-fetch path never reaches the process's own network neighbourhood.
Every fetch passes through `internal/adapters/sources/fetchguard`:

- **Scheme allowlist** — only `http` and `https`.
- **Resolve + IP check** — the request host is resolved (a literal IP is checked
  directly) and refused if it is loopback (`127/8`, `::1`), link-local unicast
  (`169.254/16`, `fe80::/10`), private (`10/8`, `172.16/12`, `192.168/16`,
  `fc00::/7`), multicast or unspecified. The check runs again on the actual
  dialed socket (`net.Dialer.Control`), so a DNS rebinding between resolve and
  connect still cannot reach a blocked address.
- **Redirect limit** — at most 5 hops; every hop is re-checked (scheme +
  resolve + IP).
- **No proxy** is honoured: a proxy would tunnel past the IP check.
- Source endpoints are operator-registered (`sources.endpoint`); no end user can
  supply an arbitrary URL.

| Key | Default | Meaning |
|---|---|---|
| `sources.allow_private` (`RISKSIGNAL_SOURCES_ALLOW_PRIVATE`) | `false` | Relaxes the address check to loopback/link-local/private so the **local** environment can reach its mock sources on loopback. Valid **only in `local` mode** — `demo` and `production` refuse it at startup (ARCH-007 §7). Multicast and unspecified stay blocked regardless. |

## Audit integrity

### Append-only database roles (§7 control 3a)

Migration `00013` creates two NOLOGIN **group** roles:

- **`risksignal_app`** — the application runtime role. On `audit_events` it has
  exactly `SELECT` + `INSERT`; `UPDATE`, `DELETE` and `TRUNCATE` are revoked, and
  every table created later defaults to `SELECT` + `INSERT` for it (least
  privilege by construction).
- **`risksignal_migrator`** — owns schema changes (`USAGE`/`CREATE` on `public`,
  `ALL` on existing tables/sequences).

Migration `00014` grants `risksignal_app` least-privilege access to the tables
that already existed when `00013` ran (the default-privilege rule only covers
objects created afterwards). The per-table matrix, traced from
`db/queries/*.sql`, is:

| Privileges | Tables |
|---|---|
| `SELECT`, `INSERT`, `UPDATE`, `DELETE` | `comments`, `notifications`, `risk_signals`, `sla_clocks` |
| `SELECT`, `INSERT`, `DELETE` | `matches`, `user_roles` |
| `SELECT`, `INSERT`, `UPDATE` | `alias_rules`, `assets`, `components`, `decision_rules`, `exports`, `inventory_imports`, `legal_holds`, `outbox`, `quarantine`, `retention_runs`, `source_runs`, `sources`, `users`, `vulnerabilities` |
| `SELECT`, `INSERT`, `TRUNCATE` | `epss_current` (the atomic `TRUNCATE` + `COPY` swap) |
| `SELECT`, `INSERT` | `evidences`, `raw_records`, `priority_rules`, `epss_history` |
| `SELECT`, `INSERT` (unchanged) | `audit_events` |
| *(none)* | `schema_migration_log` (migration bookkeeping only) |

`risksignal_app` is never granted DDL, schema `CREATE`/`USAGE`, `REFERENCES` or
`TRIGGER`; it reaches `public` through `PUBLIC`'s default `USAGE`. There are no
sequences (every primary key is a uuid via `gen_random_uuid()`). A login granted
only `risksignal_app` can therefore boot the server and worker against a fresh
schema while the audit trail stays append-only.

Neither role carries a password (credentials are runtime-injected, ch. 3.3).
The operator creates a login and grants the group to it:

```sql
CREATE ROLE risksignal_runtime LOGIN PASSWORD '…';
GRANT risksignal_app TO risksignal_runtime;
-- run `risksignal maintenance migrate` as a login granted risksignal_migrator
```

The `database.url` of the server/worker must then connect as the runtime login.
A regression that tries to rewrite the audit trail fails with SQLSTATE `42501`.

#### Dedicated retention role

Migration `00015` adds the governed retention and pseudonymisation path's own
least-privilege role (ARCH-007 §7 control 3a amendment, DEV-128). The retention
acts delete and redact rows `risksignal_app` may not touch, so widening the
runtime role would break the append-only guarantee; instead they run on a
separate connection:

- **`risksignal_retention`** — a NOLOGIN group role with the retention grants.
- **`risksignal_retention_login`** — a LOGIN role granted `risksignal_retention`
  (never the runtime login). Its password is runtime-injected; the retention
  path never uses `SET ROLE`.

| Privileges | Tables |
|---|---|
| `SELECT`, `INSERT`, `UPDATE`, `DELETE` | `audit_events` |
| `SELECT`, `UPDATE`, `DELETE` | `risk_signals`, `comments` |
| `SELECT`, `DELETE` | `sla_clocks`, `matches`, `notifications` |
| `SELECT`, `UPDATE` | `retention_runs` |
| `SELECT` | `legal_holds` |

`SELECT` is granted alongside the delete privileges because PostgreSQL checks
`SELECT` on the columns a statement reads — including those named in an
`UPDATE`/`DELETE` `WHERE` clause — so it is required, not a convenience.
Everything else is revoked: nothing on `users`, `outbox`, `epss_current` or
`schema_migration_log`; no `TRUNCATE`/`REFERENCES`/`TRIGGER`; no `CREATE` on
`public`; not a superuser.

| Key | Default | Meaning |
|---|---|---|
| `database.retention_url` (`RISKSIGNAL_DATABASE_RETENTION_URL`) | *unset* | The separate DSN the retention and pseudonymisation commits authenticate as the dedicated retention login on. Optional and credential-redacted (presence-only in `Summary`/`diagnose config`). When **unset** the commit paths fail closed: the worker's `retention.execute` handler refuses (the job dead-letters) and `risksignal maintenance identity-pseudonymize --commit` is refused, rather than falling back to the application role. |

The `retention.execute` worker job and the `identity-pseudonymize --commit`
path drive a retention-bound application service on this pool; the dry-run
preview, the monthly dry-run scheduler and every other job keep the app-role
pool. See `docs/operations/security-hardening.md` and ARCH-007 §7 control 3a.

### Optional audit hash chain (§7 control 3b)

| Key | Default | Meaning |
|---|---|---|
| `retention.hash_chain_enabled` (`RISKSIGNAL_RETENTION_HASH_CHAIN_ENABLED`) | `false` | When on, `AuditRepo.Append` stamps `prev_hash`/`row_hash` on every new row, `row_hash = SHA-256(prev_hash ‖ canonical row bytes)`, inside the same transaction (serialised by a transaction-scoped advisory lock so the chain cannot fork). Off leaves the append path unchanged. |

Verify the whole trail end-to-end:

```
risksignal diagnose audit-chain          # --output json for the envelope
```

Exit codes: `0` intact (an all-unchained trail — the chain never enabled — is
intact with `chained: 0`); `5` (conflict) on the first divergence, naming the
offending row; `6` when the database is unreachable. The chain proves internal
consistency — anchoring it against wholesale removal of its head needs the
external reference of the encrypted off-host backup (WP-6.09, §4).

## TLS / secure headers (§7 control 4)

Every response carries `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and a restrictive
`Content-Security-Policy` (`default-src 'none'; frame-ancestors 'none'`). In the
online modes (`demo`, `production`) the server additionally forces
`Strict-Transport-Security: max-age=31536000; includeSubDomains`; `local`
(plain HTTP over loopback) leaves it off. TLS itself terminates at the demo
reverse proxy (§8, WP-6.11).
