# RiskSignal — build and development targets (WP-1a.01 skeleton; WP-1a.11 arch gate).
#
# Go 1.27 is pinned by ADR-008 and declared in go.mod; use a matching toolchain.
# go-arch-lint is pinned to v1.19.0 (docs/plan/orchestrator-decisions.md, D-005).
# The binary is resolved from PATH first, then from GOPATH/bin — the default
# destination of `go install`.
# `make` requires tabs in recipes — do not re-indent with spaces.

GO ?= go
GO_ARCH_LINT ?= go-arch-lint
GO_ARCH_LINT_BIN := $(or $(shell command -v $(GO_ARCH_LINT) 2>/dev/null),$(shell $(GO) env GOPATH)/bin/$(GO_ARCH_LINT))

.PHONY: build test test-arch lint lint-arch generate migrate up down

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

## migrate: database migration runner
## up:    bring up the local environment
## down:  tear down the local environment
# Stubs until WP-1a.04 (migration runner) and WP-1a.03 (compose environment).
migrate up down:
	@echo "not yet implemented — WP-1a.04"
