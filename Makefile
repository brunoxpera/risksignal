# RiskSignal — build and development targets (WP-1a.01 skeleton).
#
# Go 1.27 is pinned by ADR-008 and declared in go.mod; use a matching toolchain.
# `make` requires tabs in recipes — do not re-indent with spaces.

GO ?= go

.PHONY: build test lint generate migrate up down

## build: compile all three binaries into bin/
build:
	mkdir -p bin
	$(GO) build -o bin/risksignal-server ./cmd/risksignal-server
	$(GO) build -o bin/risksignal-worker ./cmd/risksignal-worker
	$(GO) build -o bin/risksignal ./cmd/risksignal

## test: run the unit test suite
test:
	$(GO) test ./...

## lint: fail on unformatted files, then run go vet
lint:
	@files="$$(gofmt -l .)"; \
	if [ -n "$$files" ]; then \
		echo "gofmt: unformatted files:"; \
		echo "$$files"; \
		exit 1; \
	fi
	$(GO) vet ./...

## generate: run code generators
generate:
	$(GO) generate ./...

## migrate: database migration runner
## up:    bring up the local environment
## down:  tear down the local environment
# Stubs until WP-1a.04 (migration runner) and WP-1a.03 (compose environment).
migrate up down:
	@echo "not yet implemented — WP-1a.04"
