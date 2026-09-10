# Reference-matrix fixtures (WP-3.11 / DEV-054)

Versioned, deterministic, network-free fixtures for the I3 reference-matrix
exit-criterion proof (ARCH-003 §8a). They are seeded **directly** through the
postgres repositories/SQL by `reference_matrix_integration_test.go` — never
through the CSV import pipeline (`cmd/risksignal/inventory*`), so the matrix
does not depend on the import use case.

## `inventory.csv`

The canonical ARCH-003 §1.3 inventory shape (snake_case, order-insensitive)
plus one **fixture-only** trailing column `fx_key` that the direct seeder uses
to correlate a row with the `vulnerabilities.json` cells; it is never fed to
the import parser.

One asset per `AssetType` (server_vm, application_framework, container_image,
network_security, cloud_saas) and, under each, one component per identifier
shape:

| `fx_key` | identifier shape | component |
|---|---|---|
| `cpe` | CPE | `cpe:2.3:a:acme:widget:1.2.3:…` |
| `purl` | purl | `pkg:golang/github.com/acme/portal@2.4.0` |
| `digest` | image + digest | `registry.example.com/acme/widget:1.2.3@sha256:…` |
| `alias` | vendor/product | `oracle` / `weblogic server` 12.2.1.4 |
| `range` | vendor/product | `acme` / `widget` 1.5.0 |
| `uncertain` | vendor/product | `acme` / `widget` (no version) |
| `candidate` | vendor/product | `apache` / `apache httpd` 2.4.62 |
| `nomatch` | vendor/product | `acme` / `widget` 3.0.0 |

## `vulnerabilities.json`

The synthetic vulnerability side: one cell per `MatchMethod` (including the
`candidate` similarity band and `no_match`), each keyed to the `inventory.csv`
component (`component_fx`) that realises it, with the expected ADR-015
`method`/`confidence`/`score` and a `reason_contains` token the TR-007 reason
list must carry. `alias_rules` seeds the controlled aliases the two alias cells
require.

Nothing here is real data: identifiers, digests and CVE ids are synthetic
(`CVE-2026-100x`), and the fixtures carry no secrets or keys.
