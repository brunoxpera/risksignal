# RiskSignal — build and development targets (WP-1a.01 skeleton; WP-1a.03 compose
# environment; WP-1a.11 arch gate).
#
# Go 1.27 is pinned by ADR-008 and declared in go.mod; use a matching toolchain.
# go-arch-lint is pinned to v1.19.0 (docs/plan/orchestrator-decisions.md, D-005).
# The binary is resolved from PATH first, then from GOPATH/bin — the default
# destination of `go install`.
# `make` requires tabs in recipes — do not re-indent with spaces.

GO ?= go
GO_ARCH_LINT ?= go-arch-lint
GO_ARCH_LINT_BIN := $(or $(shell command -v $(GO_ARCH_LINT) 2>/dev/null),$(shell $(GO) env GOPATH)/bin/$(GO_ARCH_LINT))
COMPOSE ?= docker compose

.PHONY: build test test-arch lint lint-arch generate migrate up down verify-connectivity

## build: compile all three binaries into bin/
build:
	mkdir -p bin
	$(GO) build -o bin/risksignal-server ./cmd/risksignal-server
	$(GO) build -o bin/risksignal-worker ./cmd/risksignal-worker
	$(GO) build -o bin/risksignal ./cmd/risksignal

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

## generate: run code generators
generate:
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
##     db, mail and oidc stay up; server and worker validate their
##     configuration and exit 0 until their long-running behaviour lands in
##     WP-1a.05/WP-1a.06/WP-1a.10. Published ports default to loopback-only
##     bindings (compose.yaml); override a busy host port with e.g.
##     COMPOSE_OIDC_PORT=19000 make up
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
