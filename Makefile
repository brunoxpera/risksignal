# RiskSignal — build and development targets (WP-1a.01 skeleton; WP-1a.03 compose
# environment; WP-1a.11 arch gate).
#
# Go 1.27 is pinned by ADR-008 and declared in go.mod; use a matching toolchain.
# sqlc is pinned to v1.31.1 (ADR-009; the sqlc.yaml comment says the same) and
# resolved from PATH first, then from GOPATH/bin — the default destination of
# `go install`.
# go-arch-lint is pinned to v1.19.0 (docs/plan/orchestrator-decisions.md, D-005).
# The binary is resolved from PATH first, then from GOPATH/bin — the default
# destination of `go install`.
# `make` requires tabs in recipes — do not re-indent with spaces.

GO ?= go
SQLC ?= sqlc
SQLC_VERSION := v1.31.1
SQLC_BIN := $(or $(shell command -v $(SQLC) 2>/dev/null),$(shell $(GO) env GOPATH)/bin/$(SQLC))
GO_ARCH_LINT ?= go-arch-lint
GO_ARCH_LINT_BIN := $(or $(shell command -v $(GO_ARCH_LINT) 2>/dev/null),$(shell $(GO) env GOPATH)/bin/$(GO_ARCH_LINT))
COMPOSE ?= docker compose

# Build metadata (WP-1a.07): injected into every binary at link time and
# served by GET /version. VERSION defaults to dev like the buildinfo package
# itself; override with e.g. `make VERSION=0.1.0`. GIT_COMMIT and BUILD_TIME
# are read from the environment at make time; the fallback "unknown" keeps
# the build reproducible when git or date is unavailable (the buildinfo
# defaults say the same).
VERSION ?= dev
GIT_COMMIT := $(shell git rev-parse --short=8 HEAD 2>/dev/null || echo unknown)
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
GO_LDFLAGS := -X github.com/xpera/risksignal/internal/platform/buildinfo.Version=$(VERSION) \
	-X github.com/xpera/risksignal/internal/platform/buildinfo.Commit=$(GIT_COMMIT) \
	-X github.com/xpera/risksignal/internal/platform/buildinfo.BuildTime=$(BUILD_TIME)

.PHONY: build test test-arch lint lint-arch generate migrate up down verify-connectivity

## build: compile all three binaries into bin/ with build metadata injected
build:
	mkdir -p bin
	$(GO) build -ldflags '$(GO_LDFLAGS)' -o bin/risksignal-server ./cmd/risksignal-server
	$(GO) build -ldflags '$(GO_LDFLAGS)' -o bin/risksignal-worker ./cmd/risksignal-worker
	$(GO) build -ldflags '$(GO_LDFLAGS)' -o bin/risksignal ./cmd/risksignal

## test: run the architecture-gate negative test, then the unit test suite
test: test-arch
	$(GO) test ./...

## test-arch: negative test — prove the arch gate rejects a forbidden import
##            (see testdata/arch-gate/verify-arch-gate.sh)
test-arch:
	@testdata/arch-gate/verify-arch-gate.sh

## lint: architecture gate (lint-arch), then fail on unformatted files and run go vet
lint: lint-arch
	@files="$$(gofmt -l .)"; \
	if [ -n "$$files" ]; then \
		echo "gofmt: unformatted files:"; \
		echo "$$files"; \
		exit 1; \
	fi
	$(GO) vet ./...

## lint-arch: fail if the code violates the dependency rules in .go-arch-lint.yml
##            (TR-001 gate; rules are declared in that file, not in prose)
lint-arch:
	@if [ ! -x "$(GO_ARCH_LINT_BIN)" ]; then \
		echo "go-arch-lint not found (looked at PATH and $$($(GO) env GOPATH)/bin)."; \
		echo "Install the pinned version: go install github.com/fe3dback/go-arch-lint@v1.19.0"; \
		exit 2; \
	fi
	$(GO_ARCH_LINT_BIN) check

## generate: regenerate the sqlc query code (ADR-009, pinned sqlc version),
##            then run go:generate directives. sqlc reads the schema from the
##            migration files (db/migrations) and the queries from db/queries;
##            generated code lands in internal/adapters/postgres/gen and is
##            committed (CI regenerates and fails on a diff, ADR-009).
generate:
	@if [ ! -x "$(SQLC_BIN)" ]; then \
		echo "sqlc not found (looked at PATH and $$($(GO) env GOPATH)/bin)."; \
		echo "Install the pinned version: go install github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION)"; \
		exit 2; \
	fi
	@if [ "$$($(SQLC_BIN) version)" != "$(SQLC_VERSION)" ]; then \
		echo "sqlc $$($(SQLC_BIN) version) in use, pinned version is $(SQLC_VERSION)."; \
		echo "Install the pinned version: go install github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION)"; \
		exit 2; \
	fi
	$(SQLC_BIN) generate
	$(GO) generate ./...

## migrate: run the schema migrations (WP-1a.04) against the compose database.
##         Requires the environment to be up (make up). The command itself is
##         ./bin/risksignal maintenance migrate [--dry-run] with the usual
##         RISKSIGNAL_* configuration (here: the compose defaults).
migrate: build
	RISKSIGNAL_DATABASE_URL='postgres://risksignal:risksignal@127.0.0.1:5432/risksignal?sslmode=disable' \
	RISKSIGNAL_OIDC_ISSUER='http://127.0.0.1:9000/oidc' \
	./bin/risksignal maintenance migrate

## up: build and start the local compose environment in the background.
##     db, mail and oidc stay up; server serves HTTP through the WP-1a.06
##     middleware chain; worker runs its WP-1a.10 scheduler loop (heartbeat
##     and one scheduler run per worker.interval, default 30s). Published
##     ports default to loopback-only bindings (compose.yaml); override a
##     busy host port with e.g. COMPOSE_OIDC_PORT=19000 make up
up:
	$(COMPOSE) up -d --build

## down: stop and remove the local compose environment (keeps the pgdata volume)
down:
	$(COMPOSE) down

## verify-connectivity: prove PostgreSQL answers from the compose network
##     that server/worker use — a one-off psql on the db image resolving the
##     service name db:5432. Requires the environment to be up (make up).
verify-connectivity:
	$(COMPOSE) run --rm --no-deps -e PGPASSWORD=risksignal --entrypoint psql db -h db -p 5432 -U risksignal -d risksignal -tAc 'SELECT 1'
