#!/bin/sh
# Off-host backup entrypoint (WP-6.09 / DEV-122, ARCH-007 §4).
#
# Runs one encrypted logical backup of the whole database with the runtime
# configuration (database.url, backup.dir, backup.encryption_key_ref,
# backup.retain_days). In the demo deployment this is invoked by a
# containerised sidecar/cron (deploy/backup) — never from inside the
# application server/worker process. The pg_dump client must be the same or a
# newer major version than the server (the deploy/backup image ships the
# postgres:16 client).
set -eu

exec "${RISKSIGNAL_BIN:-risksignal}" diagnose backup "$@"
