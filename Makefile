# RiskSignal — build and development targets (WP-1a.01 skeleton; WP-1a.03 compose
# environment; WP-1a.11 arch gate; WP-1a.12 CI pipeline stages 1-2; WP-1a.13
# images, SBOM, scans and signing groundwork; WP-1b.07 OpenAPI codegen, ADR-011).
#
# Go 1.27 is pinned by ADR-008 and declared in go.mod; use a matching toolchain.
# sqlc is pinned to v1.31.1 (ADR-009; the sqlc.yaml comment says the same) and
# resolved from PATH first, then from GOPATH/bin — the default destination of
# `go install`. oapi-codegen is pinned to v2.8.0 (ADR-011; the oapi-codegen.yml
# comment says the same) and resolved the same way.
# go-arch-lint is pinned to v1.19.0, golangci-lint to v2.13.2, gitleaks to
# 8.30.1 and go-licenses to v1.6.0 (docs/plan/orchestrator-decisions.md, D-005).
# The WP-1a.13 supply-chain tooling is pinned the same way: cyclonedx-gomod
# v1.12.0, govulncheck v1.8.0 and cosign v2.6.5 via `go install`; syft v1.51.1
# and grype v0.118.0 as checksum-verified GitHub release binaries (a `go install`
# build of the anchore tools does not stamp the version). All of them are
# resolved from PATH first, then from GOPATH/bin — the default destination of
# `go install`.
# The CI pipeline (WP-1a.12) runs the same stage sequence as `make ci-lint` /
# `make ci-test` / `make ci-build`, so every stage is verifiable without GitHub;
# the WP-1a.13 image job (`make image` / `make sbom` / `make scan` / `make sign`)
# mirrors the CI image job and reproduces it locally.
# `make` requires tabs in recipes — do not re-indent with spaces.

GO ?= go
SQLC ?= sqlc
SQLC_VERSION := v1.31.1
SQLC_BIN := $(or $(shell command -v $(SQLC) 2>/dev/null),$(shell $(GO) env GOPATH)/bin/$(SQLC))
OAPI_CODEGEN ?= oapi-codegen
OAPI_CODEGEN_VERSION := v2.8.0
OAPI_CODEGEN_BIN := $(or $(shell command -v $(OAPI_CODEGEN) 2>/dev/null),$(shell $(GO) env GOPATH)/bin/$(OAPI_CODEGEN))
GO_ARCH_LINT ?= go-arch-lint
GO_ARCH_LINT_BIN := $(or $(shell command -v $(GO_ARCH_LINT) 2>/dev/null),$(shell $(GO) env GOPATH)/bin/$(GO_ARCH_LINT))
GOLANGCI_LINT ?= golangci-lint
GOLANGCI_LINT_VERSION := 2.13.2
GOLANGCI_LINT_BIN := $(or $(shell command -v $(GOLANGCI_LINT) 2>/dev/null),$(shell $(GO) env GOPATH)/bin/$(GOLANGCI_LINT))
GITLEAKS ?= gitleaks
GITLEAKS_VERSION := 8.30.1
GITLEAKS_BIN := $(or $(shell command -v $(GITLEAKS) 2>/dev/null),$(shell $(GO) env GOPATH)/bin/$(GITLEAKS))
GO_LICENSES ?= go-licenses
GO_LICENSES_BIN := $(or $(shell command -v $(GO_LICENSES) 2>/dev/null),$(shell $(GO) env GOPATH)/bin/$(GO_LICENSES))
CYCLONEDX_GOMOD ?= cyclonedx-gomod
CYCLONEDX_GOMOD_VERSION := v1.12.0
CYCLONEDX_GOMOD_BIN := $(or $(shell command -v $(CYCLONEDX_GOMOD) 2>/dev/null),$(shell $(GO) env GOPATH)/bin/$(CYCLONEDX_GOMOD))
GOVULNCHECK ?= govulncheck
GOVULNCHECK_VERSION := v1.8.0
GOVULNCHECK_BIN := $(or $(shell command -v $(GOVULNCHECK) 2>/dev/null),$(shell $(GO) env GOPATH)/bin/$(GOVULNCHECK))
SYFT ?= syft
SYFT_VERSION := 1.51.1
SYFT_BIN := $(or $(shell command -v $(SYFT) 2>/dev/null),$(shell $(GO) env GOPATH)/bin/$(SYFT))
GRYPE ?= grype
GRYPE_VERSION := 0.118.0
GRYPE_BIN := $(or $(shell command -v $(GRYPE) 2>/dev/null),$(shell $(GO) env GOPATH)/bin/$(GRYPE))
COSIGN ?= cosign
COSIGN_VERSION := v2.6.5
COSIGN_BIN := $(or $(shell command -v $(COSIGN) 2>/dev/null),$(shell $(GO) env GOPATH)/bin/$(COSIGN))
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

# Image names and artifact locations (WP-1a.13): the production images are
# named risksignal/server and risksignal/worker — the names a future registry
# (ghcr.io/xpera/...) would carry — and tagged with VERSION (dev by default),
# like the binaries. SBOMs and scan reports land under dist/, which is
# git-ignored together with bin/ (CI uploads them as workflow artifacts).
IMAGE_SERVER := risksignal/server
IMAGE_WORKER := risksignal/worker
IMAGE_TAG := $(VERSION)
ARTIFACT_DIR := dist
SBOM_DIR := $(ARTIFACT_DIR)/sbom
SCAN_DIR := $(ARTIFACT_DIR)/scan

.PHONY: build test test-arch lint lint-arch generate validate-openapi migrate up down \
	verify-connectivity ci-lint ci-test test-contract ci-build demo check-gofmt vet lint-golangci \
	lint-licenses lint-secrets up-db image sbom scan sign

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

## ci-lint: WP-1a.12 lint stage, in the CI order: formatting check, go vet,
##          static analysis (golangci-lint with gosec), architecture gate,
##          licence check, secret scan. Identical to the CI lint job, so the
##          stage is verifiable without GitHub (deterministic: pinned tools,
##          .golangci.yml and .gitleaks.toml are the sources of truth).
ci-lint: check-gofmt vet lint-golangci lint-arch lint-licenses lint-secrets

## ci-test: WP-1a.12 test stage — race-enabled test suite against a real
##          PostgreSQL. The compose db service is started first (up-db) so
##          the integration tests actually run instead of skipping; the CI
##          test job provides the same database as a service container. The
##          suite includes the ADR-011 gate-3 contract tests (WP-1b.09 /
##          DEV-023, cmd/risksignal-server/contract_test.go): they seed a
##          scratch database through the demo-seed chain and run the
##          generated OpenAPI client against the real handler; without a
##          reachable database they skip cleanly like every other
##          integration test.
ci-test: up-db
	$(GO) test -race ./...

## test-contract: run only the WP-1b.09 contract suite (ADR-011 gate 3,
##          DEV-023) — the OpenAPI 3.1 document validation and the generated
##          client against the demo-seeded server, race-enabled. Requires the
##          compose database (up-db) so the server-side tests run instead of
##          skipping; the same suite is part of ci-test via `go test ./...`.
test-contract: up-db
	$(GO) test -race ./cmd/risksignal-server -run 'Contract'

## ci-build: WP-1a.12 build stage — `make build` is the definition of the
##           stage (three binaries with build metadata).
ci-build: build

## demo: WP-1b.11 E2E walking-skeleton demonstration — one command from a
##       clean checkout to the iteration I1b exit criterion (ARCH-001): the
##       compose db is started (up-db) and migrated, `demo seed` runs the
##       deterministic synthetic source (DEV-019), the server starts on
##       127.0.0.1:18080 and the script (scripts/demo.sh) asserts that
##       GET /api/v1/signals serves the four reference signals with the
##       expected P1/P2/P2/P3 priorities — the exit-criterion read — via
##       the list and the detail endpoint, then tears the demo server down
##       (the compose db stays up, like ci-test; `make down` stops it).
##       Deterministic and runnable locally: synthetic seed data only,
##       loopback bindings only (see scripts/demo.sh for the env overrides
##       RISKSIGNAL_DATABASE_URL / RISKSIGNAL_OIDC_ISSUER /
##       RISKSIGNAL_HTTP_ADDR).
demo: build
	@scripts/demo.sh

## image: build the production container images (WP-1a.13) from the
##        deploy/server and deploy/worker Containerfiles — multi-stage, non-root
##        distroless runtime pinned by digest. The WP-1a.07 build metadata
##        (VERSION / GIT_COMMIT / BUILD_TIME) is injected through build args
##        into the same -ldflags -X variables that `make build` uses, so the
##        image binary answers /version (server) and reports the version in
##        the worker heartbeat like a locally built binary. Override with e.g.
##        `make VERSION=0.1.0 image`.
image:
	@command -v docker >/dev/null 2>&1 || { echo "docker not found on PATH — install Docker Desktop or the docker CLI and start the daemon"; exit 2; }
	docker build --build-arg VERSION=$(VERSION) --build-arg GIT_COMMIT=$(GIT_COMMIT) --build-arg BUILD_TIME=$(BUILD_TIME) -t $(IMAGE_SERVER):$(IMAGE_TAG) -f deploy/server/Containerfile .
	docker build --build-arg VERSION=$(VERSION) --build-arg GIT_COMMIT=$(GIT_COMMIT) --build-arg BUILD_TIME=$(BUILD_TIME) -t $(IMAGE_WORKER):$(IMAGE_TAG) -f deploy/worker/Containerfile .

## sbom: generate the software bills of materials (WP-1a.13, concept ch. 17.3
##       stage 5): the Go module SBOM with cyclonedx-gomod and one
##       container-image SBOM per production image with syft — all CycloneDX
##       JSON. Requires the images (depends on image; docker layer caching
##       keeps rebuilds incremental). Artifacts land in dist/sbom/.
sbom: image
	@if [ ! -x "$(CYCLONEDX_GOMOD_BIN)" ]; then \
		echo "cyclonedx-gomod not found (looked at PATH and $$($(GO) env GOPATH)/bin)."; \
		echo "Install the pinned version: go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@$(CYCLONEDX_GOMOD_VERSION)"; \
		exit 2; \
	fi
	@if [ ! -x "$(SYFT_BIN)" ]; then \
		echo "syft not found (looked at PATH and $$($(GO) env GOPATH)/bin)."; \
		echo "Install the pinned version from the checksum-verified GitHub release (see docs/plan/orchestrator-decisions.md, D-005)."; \
		exit 2; \
	fi
	mkdir -p $(SBOM_DIR)
	$(CYCLONEDX_GOMOD_BIN) mod -json -output $(SBOM_DIR)/module.cdx.json .
	$(SYFT_BIN) scan -q -o cyclonedx-json=$(SBOM_DIR)/server.cdx.json $(IMAGE_SERVER):$(IMAGE_TAG)
	$(SYFT_BIN) scan -q -o cyclonedx-json=$(SBOM_DIR)/worker.cdx.json $(IMAGE_WORKER):$(IMAGE_TAG)
	@echo "SBOMs written to $(SBOM_DIR)/:"
	@ls -1 $(SBOM_DIR)

## scan: vulnerability scans (WP-1a.13, concept ch. 17.3 stage 5): govulncheck
##       over the Go module dependencies and grype over both production
##       images. Both fail the build on findings by default: govulncheck exits
##       non-zero on any vulnerability that affects the build, grype runs with
##       --fail-on high (high and critical fail). Reports are printed and kept
##       in dist/scan/.
scan: image
	@if [ ! -x "$(GOVULNCHECK_BIN)" ]; then \
		echo "govulncheck not found (looked at PATH and $$($(GO) env GOPATH)/bin)."; \
		echo "Install the pinned version: go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)"; \
		exit 2; \
	fi
	@if [ ! -x "$(GRYPE_BIN)" ]; then \
		echo "grype not found (looked at PATH and $$($(GO) env GOPATH)/bin)."; \
		echo "Install the pinned version from the checksum-verified GitHub release (see docs/plan/orchestrator-decisions.md, D-005)."; \
		exit 2; \
	fi
	mkdir -p $(SCAN_DIR)
	@echo "== govulncheck (Go module) =="; \
	$(GOVULNCHECK_BIN) ./... >$(SCAN_DIR)/govulncheck.log 2>&1; \
	rc=$$?; cat $(SCAN_DIR)/govulncheck.log; exit $$rc
	@echo "== grype $(IMAGE_SERVER):$(IMAGE_TAG) =="; \
	GRYPE_CHECK_FOR_APP_UPDATE=false $(GRYPE_BIN) --fail-on high $(IMAGE_SERVER):$(IMAGE_TAG) >$(SCAN_DIR)/grype-server.log 2>&1; \
	rc=$$?; cat $(SCAN_DIR)/grype-server.log; exit $$rc
	@echo "== grype $(IMAGE_WORKER):$(IMAGE_TAG) =="; \
	GRYPE_CHECK_FOR_APP_UPDATE=false $(GRYPE_BIN) --fail-on high $(IMAGE_WORKER):$(IMAGE_TAG) >$(SCAN_DIR)/grype-worker.log 2>&1; \
	rc=$$?; cat $(SCAN_DIR)/grype-worker.log; exit $$rc

## sign: cosign keyless signing groundwork (WP-1a.13, concept ch. 17.3 stage 6
##       and ch. 4.4 step 1). Verifies the pinned cosign binary and prints the
##       intended keyless flow; it deliberately signs nothing — there is no
##       registry and no real release yet. The full flow is documented in
##       docs/plan/release-signing.md.
sign:
	@if [ ! -x "$(COSIGN_BIN)" ]; then \
		echo "cosign not found (looked at PATH and $$($(GO) env GOPATH)/bin)."; \
		echo "Install the pinned version: go install github.com/sigstore/cosign/v2/cmd/cosign@$(COSIGN_VERSION)"; \
		exit 2; \
	fi
	@echo "== cosign (pinned $(COSIGN_VERSION)) =="; \
	$(COSIGN_BIN) version
	@echo
	@echo "Signing skeleton (no signatures produced — release-time step only):"
	@echo "  keyless: cosign sign --yes ghcr.io/xpera/risksignal/server@<digest>"
	@echo "           (release CI job grants id-token: write; GitHub OIDC issuer)"
	@echo "  verify:  cosign verify --certificate-identity '...' --certificate-oidc-issuer \"https://token.actions.githubusercontent.com\" ghcr.io/xpera/risksignal/server@<digest>"
	@echo "See docs/plan/release-signing.md for the details."

## up-db: start only the compose db service and wait until it is healthy.
##        Idempotent; used by ci-test. Compose v2's --wait honours the
##        healthcheck declared in compose.yaml.
up-db:
	$(COMPOSE) up -d --wait db

## check-gofmt: fail on unformatted Go files (gofmt -l must stay empty)
check-gofmt:
	@files="$$(gofmt -l .)"; \
	if [ -n "$$files" ]; then \
		echo "gofmt: unformatted files:"; \
		echo "$$files"; \
		exit 1; \
	fi

## vet: run go vet over the whole module
vet:
	$(GO) vet ./...

## lint-golangci: static analysis with golangci-lint (v2 standard set +
##                gosec; .golangci.yml holds the configuration)
lint-golangci:
	@if [ ! -x "$(GOLANGCI_LINT_BIN)" ]; then \
		echo "golangci-lint not found (looked at PATH and $$($(GO) env GOPATH)/bin)."; \
		echo "Install the pinned version: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v$(GOLANGCI_LINT_VERSION)"; \
		exit 2; \
	fi
	@v="$$($(GOLANGCI_LINT_BIN) version | awk '{print $$4}')"; \
	if [ "$$v" != "$(GOLANGCI_LINT_VERSION)" ]; then \
		echo "golangci-lint $$v in use, pinned version is $(GOLANGCI_LINT_VERSION)."; \
		echo "Install the pinned version: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v$(GOLANGCI_LINT_VERSION)"; \
		exit 2; \
	fi
	"$(GOLANGCI_LINT_BIN)" run

## lint-licenses: licence check of the third-party modules (google/go-licenses,
##                pinned v1.6.0). The main module is ignored: its proprietary
##                notice (LICENSE) is not an open-source licence and is not
##                what this stage checks; every dependency still is.
lint-licenses:
	@if [ ! -x "$(GO_LICENSES_BIN)" ]; then \
		echo "go-licenses not found (looked at PATH and $$($(GO) env GOPATH)/bin)."; \
		echo "Install the pinned version: go install github.com/google/go-licenses@v1.6.0"; \
		exit 2; \
	fi
	"$(GO_LICENSES_BIN)" check --ignore github.com/xpera/risksignal ./...

## lint-secrets: secret scan with gitleaks (pinned 8.30.1; the only allowlist
##               entry is the synthetic redaction fixture, see .gitleaks.toml)
lint-secrets:
	@if [ ! -x "$(GITLEAKS_BIN)" ]; then \
		echo "gitleaks not found (looked at PATH and $$($(GO) env GOPATH)/bin)."; \
		echo "Install the pinned version: go install github.com/gitleaks/gitleaks/v8@v$(GITLEAKS_VERSION)"; \
		exit 2; \
	fi
	@v="$$($(GITLEAKS_BIN) version)"; \
	if [ "$$v" != "$(GITLEAKS_VERSION)" ]; then \
		echo "gitleaks $$v in use, pinned version is $(GITLEAKS_VERSION)."; \
		echo "Install the pinned version: go install github.com/gitleaks/gitleaks/v8@v$(GITLEAKS_VERSION)"; \
		exit 2; \
	fi
	"$(GITLEAKS_BIN)" detect --source .

## lint: the classic lint alias — architecture gate, formatting check, go vet
##       (the complete WP-1a.12 lint stage is `make ci-lint`)
lint: lint-arch check-gofmt vet

## lint-arch: fail if the code violates the dependency rules in .go-arch-lint.yml
##            (TR-001 gate; rules are declared in that file, not in prose)
lint-arch:
	@if [ ! -x "$(GO_ARCH_LINT_BIN)" ]; then \
		echo "go-arch-lint not found (looked at PATH and $$($(GO) env GOPATH)/bin)."; \
		echo "Install the pinned version: go install github.com/fe3dback/go-arch-lint@v1.19.0"; \
		exit 2; \
	fi
	"$(GO_ARCH_LINT_BIN)" check

## generate: regenerate the sqlc query code (ADR-009, pinned sqlc version), the
##            oapi-codegen server code (ADR-011, pinned oapi-codegen version),
##            then run go:generate directives. sqlc reads the schema from the
##            migration files (db/migrations) and the queries from db/queries;
##            generated code lands in internal/adapters/postgres/gen. The
##            OpenAPI document (api/openapi/openapi.yaml, schema-first per
##            ADR-011) is compiled by oapi-codegen from api/openapi/oapi-codegen.yml
##            into internal/adapters/httpapi/gen. Both generated trees are
##            committed (CI regenerates and fails on a diff, ADR-009/ADR-011).
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
	@if [ ! -x "$(OAPI_CODEGEN_BIN)" ]; then \
		echo "oapi-codegen not found (looked at PATH and $$($(GO) env GOPATH)/bin)."; \
		echo "Install the pinned version: go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION)"; \
		exit 2; \
	fi
	@if [ "$$($(OAPI_CODEGEN_BIN) -version | tail -n 1)" != "$(OAPI_CODEGEN_VERSION)" ]; then \
		echo "oapi-codegen $$($(OAPI_CODEGEN_BIN) -version | tail -n 1) in use, pinned version is $(OAPI_CODEGEN_VERSION)."; \
		echo "Install the pinned version: go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION)"; \
		exit 2; \
	fi
	$(SQLC_BIN) generate
	$(OAPI_CODEGEN_BIN) -config api/openapi/oapi-codegen.yml api/openapi/openapi.yaml
	$(GO) generate ./...

## validate-openapi: ADR-011 gate 1 — validate api/openapi/openapi.yaml against
##            the OpenAPI 3.1 specification with @redocly/cli (pinned via npx;
##            the pin lives here until D-005 is amended). The ruleset is
##            api/openapi/redocly.yaml: it extends minimal and turns off the
##            three warning rules that would flag intentional I1b properties
##            (see the config file) — the gate fails on an invalid document,
##            not on lint taste. The CI wiring of gate 1 and the generate
##            diff-gate (gate 2) is WP-1b.11; the contract test is gate 3
##            (WP-1b.09).
validate-openapi:
	@command -v npx >/dev/null 2>&1 || { \
		echo "npx not found on PATH — install Node.js (LTS) to run the schema validator"; \
		exit 2; \
	}
	npx --yes @redocly/cli@2.51.2 lint api/openapi/openapi.yaml --config=api/openapi/redocly.yaml

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
