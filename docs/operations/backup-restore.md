# Backup and restore (WP-6.09 / DEV-122)

Encrypted, off-host logical backup and a repeatable restore test
(ARCH-007 §4, NFR-011, AT-015). The backup is the **external tamper-evidence**
for the audit trail (concept ch. 12.4 "externe Backups").

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `backup.dir` (`RISKSIGNAL_BACKUP_DIR`) | `var/backups` | Off-host (or separate volume/mount) root the encrypted artifacts are written to and pruned from. Never the runtime host's data directory. |
| `backup.retain_days` (`RISKSIGNAL_BACKUP_RETAIN_DAYS`) | `14` | Daily states kept before pruning. Startup validation requires **≥ 14** (ARCH-007 §4). |
| `backup.encryption_key_ref` (`RISKSIGNAL_BACKUP_ENCRYPTION_KEY_REF`) | *(empty)* | **Presence-only in the summary.** Names the runtime-injected secret (an environment variable) that holds the `age` **identity** (`AGE-SECRET-KEY-1…`). The encryption recipient is derived from the identity, so one referenced secret covers both directions. Never stored in the repository or an image; the backup/restore commands fail with a key-only validation error when it is unset. |

## Backup

```
risksignal diagnose backup        # (alias: risksignal maintenance backup)
make backup
```

Runs one logical `pg_dump -Fc` of the whole database, encrypts it with `age`
and writes `risksignal-<UTC-timestamp>.dump.age` under `backup.dir`, then prunes
artifacts older than `backup.retain_days`. The `pg_dump` client must be the same
or a newer major version than the server (a newer client can dump an older
server, never the reverse).

The backup is **not** part of the application process. In a deployment it runs
from a containerised sidecar/cron — see `deploy/backup/Containerfile` and
`scripts/backup.sh`, driven by a cron/systemd timer with the runtime
configuration. The demo overlay that wires the sidecar is WP-6.11.

For local runs the `make` targets put `scripts/pg-client` first on `PATH`, so
`pg_dump`/`pg_restore` execute inside the compose `db` service and their major
version matches the `postgres:16` server.

## Restore test (AT-015)

```
risksignal diagnose restore-test    # --backup <file> --target-database <dsn> --keep --reason <t> --as <subject>
make restore-test
```

1. decrypt the newest artifact (or `--backup <file>`) into a private temp file;
2. restore it (`pg_restore --no-owner --no-privileges`) into a **throwaway empty
   database** (created on the configured server, dropped afterwards; `--keep`
   keeps it, `--target-database` restores into an operator-provided empty DB);
3. run the checksum-guarded migration runner (ADR-010) against the restored
   instance and verify its bookkeeping against the embedded files;
4. assert: schema present; per-table object counts match; sample-row hashes
   match; **open signals intact** (`closed_at IS NULL`: count and id set);
   **audit chain intact** (row count, plus structural verification when the
   optional `retention.hash_chain_enabled` chain is populated);
5. record the `backup.restored` audit event on the source database and drop the
   throwaway database.

A non-zero exit means the restored instance does not reproduce the source:
`exit 5` (conflict) names the failed assertions.

`make restore-test` is self-contained: it starts the compose database, migrates
it, takes a fresh backup (injecting a throwaway `age` identity via
`scripts/age-keygen` when `RISKSIGNAL_BACKUP_AGE_IDENTITY` is unset) and then
runs `diagnose restore-test` against that artifact.

## Key management

The `age` identity is runtime-injected and never in the repository or image
layers. Production injects the referenced secret (for example from the OS
credential store or the orchestrator's secret mechanism) into the backup
sidecar's environment under the name given by `backup.encryption_key_ref`.
Losing the identity means losing the ability to restore — store it with the
same care as the data it protects.
