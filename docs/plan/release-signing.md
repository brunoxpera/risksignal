# Release signing — keyless with cosign (WP-1a.13 groundwork)

> Status: **groundwork only.** Nothing in this repository is signed yet and no
> signature is produced anywhere (non-goal of WP-1a.13). This document records
> the intended flow so that the future release step (implementation concept
> ch. 4.4 step 1, ch. 17.3 stage 6) is a configuration change, not a design
> exercise.

## Goal

Sign the production container images (`risksignal/server`, `risksignal/worker`)
and the CLI binaries with **Sigstore keyless signing**: ephemeral signing keys,
certificate issued against the GitHub Actions OIDC identity of the release run —
no long-lived private key to store, rotate or leak.

## Why keyless

- No secret material in CI or in the repository.
- The signing certificate binds the artefact to the exact repository,
  workflow and ref that produced it (provenance).
- Verification uses the public cosign CLI and the public Sigstore
  transparency log; consumers need no pre-shared key.

## The flow (when a real release exists)

1. A release CI job (tag push or protected branch) builds the artefacts with
   `make VERSION=<tag> build` and `make VERSION=<tag> image`, then pushes the
   images to a registry, e.g. `ghcr.io/xpera/risksignal` (no registry exists
   yet — the current CI image job keeps the images on the runner).
2. The same job signs **by digest, never by moving tag**:
   `cosign sign --yes ghcr.io/xpera/risksignal/server@sha256:<digest>`
   The GitHub Actions OIDC token (job permission `id-token: write`) is the
   identity; no `COSIGN_*` secrets are involved.
3. Consumers verify:
   `cosign verify --certificate-identity-regexp '^https://github.com/brunoxpera/risksignal/.github/workflows/release.yml@refs/tags/' \
   --certificate-oidc-issuer https://token.actions.githubusercontent.com \
   ghcr.io/xpera/risksignal/server@sha256:<digest>`

## What exists today (WP-1a.13)

- `make sign` — verifies the pinned cosign binary (v2.6.5, D-005) and prints
  the keyless flow; it signs nothing.
- The CI image job (`.github/workflows/ci.yml`, stages 4–6) notes where the
  signing step slots in and deliberately does **not** request
  `id-token: write` yet.
- SBOMs (`make sbom`) are the artefact inventory that signing protects —
  concept ch. 4.4 step 1 treats images and SBOM as one release unit.

## Open points before real signing

- Registry choice (ghcr.io assumed here) and its push credentials.
- Whether CLI binaries are signed with `cosign sign-blob` and whether the SBOM
  files are attested (`cosign attest` with the CycloneDX predicate) in addition
  to image signing.
- SHA-pinning of the marketplace actions in the release workflow (the current
  workflow pins actions by tag; see `.github/workflows/ci.yml`).
