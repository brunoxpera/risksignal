# RiskSignal — private demo deployment (ARCH-007 §8, DEV-131 / WP-6.11)

The hardened single-host demo topology of the implementation concept ch. 4.3
("Private Online-Demoumgebung"). A TLS-terminating reverse proxy (Caddy) sits
in front of the application tier; the server, the worker, PostgreSQL and the
backup sidecar run in separate containers behind it.

## Topology

```
              ┌──────────────────────────────────────────────┐
   :80 ──────▶│ proxy  (Caddy, HTTP→HTTPS redirect + TLS/HSTS)│
   :443 ─────▶│        └─ reverse_proxy → server:8080         │
              └───────────────┬──────────────────────────────┘
                              │  internal service network
              ┌───────────────┼───────────────┬──────────────┐
              ▼               ▼               ▼              ▼
           server          worker         backup          (db joins
        (HTTP :8080)   (background job   (one-shot,      the data
                        loop, no inbound  off-host        segment)
                        HTTP)             volume)
              └───────────────┴───────────────┴──────────────┘
                              │  data segment (internal, no egress)
                              ▼
                             db (PostgreSQL)
```

The database sits on its own `internal: true` segment with no route off the
host; only the server, worker and backup attach to it. The application tier
keeps egress so the server can reach the mandatory OIDC issuer.

## Published-port surface

Only the proxy publishes host ports, and only the two Caddy listeners:

| Port | Service | Purpose |
|---|---|---|
| `80/tcp` | `proxy` | clear-text HTTP → HTTPS redirect |
| `443/tcp` | `proxy` | HTTPS (TLS termination, HSTS) |

Everything else is reachable **only** on the internal service network and is
never published:

- **db** — no `5432` host port (and no proxy upstream).
- **worker** — a background process; its only listener is the internal
  `/metrics` endpoint, which is neither published nor proxied.
- **server** — binds the container interface (`0.0.0.0:8080`) for the proxy;
  no host port.
- **metrics / admin** — the `observability.metrics_enabled` listener is off by
  default and never public (ARCH-007 §5/§8); the Caddy admin API is disabled
  (`admin off`).

## Runbook

```sh
cp deploy/demo/.env.example deploy/demo/.env   # then edit the placeholders
docker compose -f deploy/demo/compose.yaml up -d --build
```

The stack runs with `env=demo`: OIDC is mandatory (roles are mapped from the
configured claim), the local authentication bypass is off and private source
targets stay refused. The environment uses **synthetic or explicitly released
inventory data only**.

Apply the migrations and provision the retention login against the demo
database (the same flow as the local environment; see
`docs/operations/security-hardening.md`):

```sh
docker compose -f deploy/demo/compose.yaml exec -T db \
  psql -U risksignal -d risksignal   # then run `risksignal maintenance migrate`
```

## Off-host backup

`deploy/backup` builds a minimal sidecar (the `postgres:16` client plus the
`risksignal` binary) whose entrypoint runs **one** encrypted logical backup
(`scripts/backup.sh` → `risksignal diagnose backup`, ARCH-007 §4) and exits.
The host scheduler provides the daily cadence — for example a cron entry:

```cron
15 2 * * *  cd /srv/risksignal && docker compose -f deploy/demo/compose.yaml run --rm backup
```

The artifacts land off-host under `backup.dir` (the `backups` volume — mount an
off-host path or NFS in a real deployment, never the database data volume). The
`age` identity is runtime-injected: `backup.encryption_key_ref` names the
environment variable (`RISKSIGNAL_BACKUP_AGE_IDENTITY`), presence-only, and no
secret is committed.

## Export spool

Exports are user-triggered and asynchronous (ARCH-007 §1.2): the create command
schedules the work, the worker's `export.generate` job materialises a file into
the server-local spool and the server streams the download back. The spool
(`export.dir`) is a named `exports` volume both the server and the worker mount
at `/var/exports` — the `export.dir` default, which the distroless non-root
image ships writable (uid `65532`). It is deliberately a separate volume: the
artifacts self-expire after `export.ttl` (default `7d`) and stay out of the
database, the audit trail and the backup retention path. It never needs an
off-host mount; the spool is a time-limited business-content copy, not a record
of record.
