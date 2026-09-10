#!/usr/bin/env bash
#
# RiskSignal E2E walking-skeleton demo (WP-1b.11, DEV-025) — the iteration
# I1b exit criterion of ARCH-001 as one command:
#
#   compose db up + migrations -> `demo reset` (deterministic fresh state) ->
#   `demo seed` (synthetic source, DEV-019, plus the I4 P1-P4 fixture,
#   WP-4.08) -> server up -> GET /api/v1/signals shows the deterministic
#   reference signals with the expected priorities -> teardown.
#
# Teardown scope: the demo server this script starts is always stopped (also
# on failure, via the EXIT trap). The compose db stays up — like `make
# ci-test` the target treats the database as a shared local service, and a
# blanket `docker compose down` would stop a developer's whole `make up`
# environment (mail, oidc, server, worker). `make down` stops it.
#
# Deterministic by construction (ARCH-001 §3): the demo starts by truncating
# the I1b demo tables (`demo reset --yes`, dev-only, concept ch. 11.3), so
# every run seeds from the same clean state and produces the same observable
# outcome — the same reference signals with the same priorities — regardless
# of what earlier runs left behind. Only the synthetic run/signal uuids and
# RFC 3339 timestamps differ between runs; the seed itself is idempotent (a
# second seed without a reset creates nothing new).
#
# Everything binds loopback only: the demo server defaults to 127.0.0.1:18080
# (the server default 127.0.0.1:8080 is left free for a developer's own
# instance) and the compose db publishes the usual loopback-only
# 127.0.0.1:5432. The demo uses synthetic seed data only — no real source
# data ever enters the database (ARCH-001 §6).
#
# Configuration (all optional, all with the defaults below):
#   RISKSIGNAL_DATABASE_URL   compose db URL        (default below)
#   RISKSIGNAL_OIDC_ISSUER    any valid issuer      (default below)
#   RISKSIGNAL_HTTP_ADDR      demo server bind addr (default 127.0.0.1:18080)
#
# Requirements: make + docker compose (`make up-db`), curl and jq on PATH.
# Run via `make demo` (builds the three binaries first) or `scripts/demo.sh`
# after a `make build`.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DB_URL="${RISKSIGNAL_DATABASE_URL:-postgres://risksignal:risksignal@127.0.0.1:5432/risksignal?sslmode=disable}"
OIDC_ISSUER="${RISKSIGNAL_OIDC_ISSUER:-http://127.0.0.1:9000/oidc}"
HTTP_ADDR="${RISKSIGNAL_HTTP_ADDR:-127.0.0.1:18080}"

# The demo commands and the demo server read the configuration through the
# exported RISKSIGNAL_* variables — the same keys the Makefile migrate
# target and the README use.
export RISKSIGNAL_DATABASE_URL="$DB_URL"
export RISKSIGNAL_OIDC_ISSUER="$OIDC_ISSUER"
export RISKSIGNAL_HTTP_ADDR="$HTTP_ADDR"

die() {
	echo "demo: $*" >&2
	exit 1
}

# Preflight: tooling and state checks before anything is started.
for tool in curl jq; do
	command -v "$tool" >/dev/null 2>&1 || die "missing required tool '$tool' on PATH"
done
for b in risksignal risksignal-server; do
	[[ -x "$ROOT/bin/$b" ]] || die "missing $ROOT/bin/$b — run 'make demo' (it builds first) or 'make build'"
done
if curl -fsS --max-time 2 "http://$HTTP_ADDR/health/live" >/dev/null 2>&1; then
	die "address $HTTP_ADDR already answers HTTP — stop the other server or override RISKSIGNAL_HTTP_ADDR"
fi

# Logs of the demo server live in a scratch dir; kept for inspection when the
# demo fails, removed on success.
LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/risksignal-demo.XXXXXX")"
SERVER_LOG="$LOG_DIR/server.log"
SEED_JSON="$LOG_DIR/seed.json"
LIST_JSON="$LOG_DIR/signals.json"
DETAIL_JSON="$LOG_DIR/signal-detail.json"
SERVER_PID=""

cleanup() {
	local rc=$?
	if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
		echo "demo: server (pid $SERVER_PID) stopped"
	fi
	if [[ $rc -eq 0 ]]; then
		rm -rf "$LOG_DIR"
	else
		echo "demo: failed — demo server log kept at: $SERVER_LOG" >&2
	fi
}
trap cleanup EXIT

say() { printf 'demo: %s\n' "$*"; }

say "== RiskSignal E2E walking skeleton (WP-1b.11) =="

# [1/5] compose db up — the same idempotent target `make ci-test` uses.
say "[1/6] compose db up (make up-db)"
make -C "$ROOT" up-db >/dev/null

# [2/5] migrations — checksum-guarded runner against the compose db
# (WP-1a.04 / ADR-010); a fresh volume applies the schema, an existing one
# verifies the checksums and reports nothing to do.
say "[2/6] apply schema migrations"
"$ROOT/bin/risksignal" maintenance migrate >"$LOG_DIR/migrate.log"
tail -n 1 "$LOG_DIR/migrate.log" | sed 's/^/demo:       /' || true

# [3/6] demo reset — truncate the I1b demo tables so every run starts from
# the same deterministic state (dev-only, requires the explicit --yes per
# concept ch. 11.3; the next demo seed rebuilds the demo state).
say "[3/6] demo reset (fresh I1b demo state)"
"$ROOT/bin/risksignal" demo reset --yes >"$LOG_DIR/reset.log"

# [4/6] demo seed — the operator path that produces the reference signals
# (DEV-019) plus the I4 P1-P4 fixture (WP-4.08). --output json prints exactly
# one machine-readable envelope; the assertions pin the deterministic
# first-seed outcome: 2 synthetic assets, 2 components, the run counting the
# malformed E1 case (terminal status 'failed' is the expected reference
# behaviour, ARCH-001 §3) with records 7 / matched 4 / signals 4, and the
# eight-signal I4 fixture.
say "[4/6] demo seed (synthetic source)"
"$ROOT/bin/risksignal" demo seed --output json >"$SEED_JSON"
jq -e '.status == "ok" and .exit_code == 0' "$SEED_JSON" >/dev/null \
	|| die "demo seed envelope is not ok: $(cat "$SEED_JSON")"
jq -e '.result.assets == 2 and .result.components == 2' "$SEED_JSON" >/dev/null \
	|| die "demo seed inventory counts differ from the reference fixture: $(cat "$SEED_JSON")"
jq -e '.result.run.counters == {records: 7, matched: 4, signals: 4}' "$SEED_JSON" >/dev/null \
	|| die "demo seed run counters differ from the reference fixture: $(cat "$SEED_JSON")"
jq -e '.result.run.status == "failed" and (.result.run.errors | length) == 1' "$SEED_JSON" >/dev/null \
	|| die "demo seed run should be 'failed' with the E1 case counted: $(cat "$SEED_JSON")"
RUN_ID="$(jq -r '.result.run.run_id' "$SEED_JSON")"
jq -e '.result.fixture.signals == 8 and .result.fixture.already_present == false' "$SEED_JSON" >/dev/null \
	|| die "demo seed should write the eight-signal I4 fixture: $(cat "$SEED_JSON")"
say "       run $RUN_ID: records 7, matched 4, signals 4 (status 'failed': malformed E1 case counted — expected)"
say "       I4 fixture: 8 signals (P1-P4 across all statuses)"

# [5/6] server up — the composition root of cmd/risksignal-server on the
# loopback demo address; readiness (db ping + verified migrations + config)
# is the go-ahead for the reads.
say "[5/6] start server on http://$HTTP_ADDR"
"$ROOT/bin/risksignal-server" >>"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
ready=""
for _ in $(seq 1 120); do
	if curl -fsS --max-time 2 "http://$HTTP_ADDR/health/ready" >/dev/null 2>&1; then
		ready=1
		break
	fi
	if ! kill -0 "$SERVER_PID" 2>/dev/null; then
		break # server exited on its own — the log says why
	fi
	sleep 0.5
done
[[ -n "$ready" ]] || die "server not ready within 60s (log tail): $(tail -n 5 "$SERVER_LOG" 2>/dev/null || true)"
say "       ready: GET /health/ready answers 200"

# [6/6] the exit-criterion read — GET /api/v1/signals returns the seeded
# signals with the reference priorities: the four synthetic cases (C1 P1,
# C2 P2, C3 P2, C4 P3) and the eight-signal I4 fixture (P1-P4, spanning every
# status) in the priority-ascending sort of ARCH-001 §4, and the detail read
# of the first signal matches.
say "[6/6] assert GET /api/v1/signals (exit-criterion read)"
curl -fsS "http://$HTTP_ADDR/api/v1/signals?limit=100" >"$LIST_JSON" \
	|| die "GET /api/v1/signals failed: $(cat "$LIST_JSON" 2>/dev/null || true)"
jq -e '.data | length == 12' "$LIST_JSON" >/dev/null \
	|| die "expected 12 signals after one demo seed (4 synthetic + 8 I4 fixture), got: $(cat "$LIST_JSON")"
jq -e '.data[0].cve_id == "CVE-2026-9001" and .data[0].priority == "P1" and .data[0].status == "new"' "$LIST_JSON" >/dev/null \
	|| die "first signal is not the P1 fixture signal (CVE-2026-9001): $(cat "$LIST_JSON")"
jq -e --argjson want '[
	{"cve_id": "CVE-2026-9001", "priority": "P1"},
	{"cve_id": "CVE-2026-9002", "priority": "P1"},
	{"cve_id": "CVE-2024-0001", "priority": "P1"},
	{"cve_id": "CVE-2026-9003", "priority": "P2"},
	{"cve_id": "CVE-2026-9004", "priority": "P2"},
	{"cve_id": "CVE-2024-0002", "priority": "P2"},
	{"cve_id": "CVE-2024-0003", "priority": "P2"},
	{"cve_id": "CVE-2026-9005", "priority": "P3"},
	{"cve_id": "CVE-2026-9006", "priority": "P3"},
	{"cve_id": "CVE-2024-0004", "priority": "P3"},
	{"cve_id": "CVE-2026-9007", "priority": "P4"},
	{"cve_id": "CVE-2026-9008", "priority": "P4"}
]' '.data | map({cve_id, priority}) == $want' "$LIST_JSON" >/dev/null \
	|| die "signal list does not match the reference P1/P1/P1/P2/P2/P2/P2/P3/P3/P3/P4/P4 matrix: $(cat "$LIST_JSON")"
SIGNAL_ID="$(jq -r '.data[0].id' "$LIST_JSON")"
curl -fsS "http://$HTTP_ADDR/api/v1/signals/$SIGNAL_ID" >"$DETAIL_JSON" \
	|| die "GET /api/v1/signals/$SIGNAL_ID failed"
jq -e --arg id "$SIGNAL_ID" '.id == $id and .cve_id == "CVE-2026-9001" and .priority == "P1"' "$DETAIL_JSON" >/dev/null \
	|| die "detail read does not match the list read: $(cat "$DETAIL_JSON")"
say "       CVE-2026-9001 P1 readable over the API (list + detail read)"
say "       matrix: P1-P4 across the 8 I4 fixture signals + the 4 synthetic cases (C1-C4)"

say "== E2E demo passed (WP-1b.11 exit criterion demonstrated) =="
say "teardown: demo server stopped; the compose db stays up for the next run ('make down' stops it)"
