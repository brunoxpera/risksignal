#!/usr/bin/env bash
#
# RiskSignal demo smoke — the §8 "no bypass" proof and the §4.4 step-5 smoke
# (DEV-132, ARCH-007 §8 / implementation concept ch. 4.4 step 5).
#
# Two things run here, both deterministic and runnable from a dev checkout:
#
#   A. the §8 negative-startup proof — the real risksignal-server binary is
#      started with env=demo and the local authentication bypass enabled
#      (auth.bypass_enabled=true) and must exit non-zero before binding; the
#      same holds for sources.allow_private=true. This is the process-level
#      face of the unit proof in internal/platform/config
#      (arch007_demo_lockdown_test.go): config.Load is the single startup gate,
#      so a refused configuration is a non-zero exit with no listener taken.
#
#   B. the §4.4 step-5 smoke — login (mock OIDC) → GET /api/v1/signals →
#      source monitor → one signal read — driven by the Go smoke test
#      TestDemoSmokeStep5Flow (cmd/risksignal-server/demo_smoke_test.go).
#
# LOOPBACK APPROXIMATION (documented, by design): the private demo overlay
# (deploy/demo/compose.yaml, DEV-131) is a hardened single host — Caddy
# terminates TLS in front of the application tier. A full container/TLS/ACME
# end to end is neither deterministic nor cheap in a developer or CI checkout,
# so the step-5 smoke runs the same server binaries, the same authentication
# (the real OIDC adapter against the mock provider) and the same application
# use cases over loopback HTTP (httptest) against the compose PostgreSQL. It
# exercises §4.4 step 5's flow exactly — only the TLS termination the overlay
# adds on top is out of scope here. The production overlay keeps the same
# posture the smoke proves: env=demo, OIDC mandatory, no local bypass and no
# private sources (asserted by arch007_demo_lockdown_test.go).
#
# Requirements: go, docker compose (`make up-db`), a reachable PostgreSQL for
# the smoke test (the compose db starts automatically). Run via `make
# demo-smoke`. The smoke test skips itself when no database is reachable.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die() {
	echo "demo-smoke: $*" >&2
	exit 1
}

say() { printf 'demo-smoke: %s\n' "$*"; }

# DB URL the smoke test and the negative-startup proof use. The smoke test
# creates and drops its own scratch database on this server (newServerTestDB).
DB_URL="${RISKSIGNAL_TEST_DATABASE_URL:-postgres://risksignal:risksignal@127.0.0.1:5432/risksignal?sslmode=disable}"
export RISKSIGNAL_TEST_DATABASE_URL="$DB_URL"

for tool in go docker; do
	command -v "$tool" >/dev/null 2>&1 || die "missing required tool '$tool' on PATH"
done

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/risksignal-demo-smoke.XXXXXX")"
cleanup() { rm -rf "$SCRATCH"; }
trap cleanup EXIT

say "== RiskSignal demo smoke (ARCH-007 §8, §4.4 step 5) =="

# ---------------------------------------------------------------------------
# A. §8 negative-startup proof (process level): env=demo refuses the bypass
#    and the private-source relaxation before binding.
# ---------------------------------------------------------------------------
say "[1/3] build risksignal-server for the §8 negative-startup proof"
go build -o "$SCRATCH/risksignal-server" "$ROOT/cmd/risksignal-server"

# A valid mandatory core so the ONLY reason the start is refused is the flag
# under test. http.addr is a loopback address with a free port.
neg_proof() {
	local flag_value="$1" want_key="$2"
	local env_args=(
		"RISKSIGNAL_ENV=demo"
		"RISKSIGNAL_HTTP_ADDR=127.0.0.1:18099"
		"RISKSIGNAL_DATABASE_URL=$DB_URL"
		"RISKSIGNAL_OIDC_ISSUER=http://127.0.0.1:9000/oidc"
	)
	env_args+=("$flag_value")

	local stderr_file="$SCRATCH/stderr.log"
	set +e
	env -i PATH="$PATH" HOME="$HOME" "${env_args[@]}" \
		"$SCRATCH/risksignal-server" >"$SCRATCH/stdout.log" 2>"$stderr_file"
	local rc=$?
	set -e

	[[ $rc -ne 0 ]] || die "$flag_value in env=demo exited 0 — the start was not refused"
	if ! grep -q "$want_key" "$stderr_file"; then
		die "$flag_value in env=demo exited $rc but the error does not name $want_key: $(cat "$stderr_file")"
	fi
	say "      env=demo + $flag_value refused (exit $rc, error names $want_key)"
}

say "[2/3] §8 negative-startup proof: env=demo refuses bypass and allow_private"
neg_proof "RISKSIGNAL_AUTH_BYPASS_ENABLED=true" "auth.bypass_enabled"
neg_proof "RISKSIGNAL_SOURCES_ALLOW_PRIVATE=true" "sources.allow_private"

# ---------------------------------------------------------------------------
# B. §4.4 step-5 smoke: login (mock OIDC) → API → source monitor → signal read.
# ---------------------------------------------------------------------------
say "[3/3] §4.4 step-5 smoke (loopback approximation) via TestDemoSmokeStep5Flow"
make -C "$ROOT" up-db >/dev/null
go test -count=1 -v -run '^TestDemoSmokeStep5Flow$' "$ROOT/cmd/risksignal-server"

say "== demo smoke passed (ARCH-007 §8 no-bypass proof + §4.4 step-5 flow) =="
