#!/usr/bin/env bash
# verify-arch-gate.sh — negative test for the architecture gate (WP-1a.11 / DEV-002).
#
# Proves that `go-arch-lint check` rejects a forbidden import into internal/domain
# without ever modifying the real repository:
#
#   1. builds a throwaway fixture in a temp dir — a minimal go module mirroring
#      the repository layout (internal/domain, the empty inner layers and a stub
#      adapter), using a copy of the repository's real .go-arch-lint.yml so the
#      check runs against the actual gate configuration;
#   2. phase "clean":      the fixture's domain imports nothing -> check must pass;
#   3. phase "violation":  internal/domain gains the forbidden import of the stub
#      adapter package -> check must fail and name that import.
#
# The fixture lives in a temp dir (mktemp) and never enters the repository tree,
# so the clean-repo `go-arch-lint check` (workdir: internal) stays green.
#
# Usage: testdata/arch-gate/verify-arch-gate.sh
# Env:   GO_ARCH_LINT  path to the go-arch-lint binary (default: PATH lookup,
#                      then GOPATH/bin, the default destination of `go install`).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
arch_file="$repo_root/.go-arch-lint.yml"
module_path="github.com/brunoxpera/risksignal" # mirror the real module path

if [ ! -f "$arch_file" ]; then
  echo "verify-arch-gate: FAIL — $arch_file not found; cannot run the gate test." >&2
  exit 1
fi

# --- locate the go-arch-lint binary -----------------------------------------
if [ -n "${GO_ARCH_LINT:-}" ] && [ -x "$GO_ARCH_LINT" ]; then
  linter="$GO_ARCH_LINT"
elif command -v go-arch-lint >/dev/null 2>&1; then
  linter="$(command -v go-arch-lint)"
else
  linter="$(go env GOPATH)/bin/go-arch-lint"
fi
if [ ! -x "$linter" ]; then
  echo "verify-arch-gate: go-arch-lint not found (looked at \$GO_ARCH_LINT, PATH, GOPATH/bin)." >&2
  echo "Install the pinned version: go install github.com/fe3dback/go-arch-lint@v1.19.0" >&2
  exit 2
fi

# --- scaffold the fixture module --------------------------------------------
workdir="$(mktemp -d "${TMPDIR:-/tmp}/risksignal-arch-gate.XXXXXX")"
trap 'rm -rf "$workdir"' EXIT

mkdir -p "$workdir/internal/domain" \
         "$workdir/internal/application" \
         "$workdir/internal/platform" \
         "$workdir/internal/adapters/httpapi"

printf 'module %s\n\ngo 1.27\n' "$module_path" > "$workdir/go.mod"
cp "$arch_file" "$workdir/.go-arch-lint.yml"

printf 'package httpapi\n' > "$workdir/internal/adapters/httpapi/httpapi.go"
printf 'package domain\n' > "$workdir/internal/domain/domain.go"

# --- phase 1: clean fixture must be accepted ---------------------------------
echo "verify-arch-gate: phase 1/2 — clean fixture (no forbidden import) must pass"
if (cd "$workdir" && "$linter" check); then
  echo "verify-arch-gate: phase 1 OK — clean architecture accepted"
else
  echo "verify-arch-gate: FAIL — the clean fixture was rejected; the gate config" >&2
  echo "or the fixture is broken, not the violation this test is meant to prove." >&2
  exit 1
fi

# --- phase 2: the forbidden import must be rejected --------------------------
# internal/domain imports an adapter package — exactly the violation the gate
# exists to catch (concept ch. 2.3/3.2, WP-1a.11, ADR-011).
printf 'package domain\n\nimport _ "%s/internal/adapters/httpapi"\n' "$module_path" \
  > "$workdir/internal/domain/domain.go"

echo "verify-arch-gate: phase 2/2 — forbidden import (domain -> adapters/httpapi) must be rejected"
set +e
(cd "$workdir" && "$linter" check) > "$workdir/lint.out" 2>&1
status=$?
set -e

if [ "$status" -eq 0 ]; then
  echo "verify-arch-gate: FAIL — go-arch-lint accepted a forbidden import into internal/domain:" >&2
  cat "$workdir/lint.out" >&2
  exit 1
fi
if ! grep -q "internal/adapters/httpapi" "$workdir/lint.out"; then
  echo "verify-arch-gate: FAIL — the check failed for the wrong reason (expected a" >&2
  echo "domain -> internal/adapters/httpapi violation):" >&2
  cat "$workdir/lint.out" >&2
  exit 1
fi

echo "verify-arch-gate: phase 2 OK — go-arch-lint rejected the forbidden import (exit $status)"
echo "verify-arch-gate: PASS — the architecture gate catches forbidden imports into internal/domain"
