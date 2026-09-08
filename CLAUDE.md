# RiskSignal — working agreements

## Language

**English is the official project language.** Write everything in English:
documentation, code, identifiers, comments, commit messages, PR descriptions, issues
and prompts.

The one exception: the concept document (`docs/concept/umsetzungskonzept-v0.1.md`) is
maintained in German by the author. Do not translate it and do not create a German counterpart of
any other document. When referring to concept chapters, quote the German chapter title
so it can be located, and write everything around it in English.

## Authority of documents

1. Functional concept v0.2 — authoritative for requirements (FR-001..034, NFR-001..015)
2. Implementation concept — authoritative for technical realisation
3. `docs/adr/` — decisions made after the implementation concept was written

Technical decisions may sharpen the functional concept but never weaken it. Where they
conflict, the functional concept prevails until a documented change is agreed.

## Repository conventions

- Go 1.27, pinned identically in `go.mod`, containerfile and CI (ADR-008)
- Layout follows implementation concept ch. 3.2; `internal/domain` imports no adapters
  and no generated API code — enforced as a CI gate
- SQL lives in `/db/queries` and is generated with sqlc; generated code is committed
  and CI fails on a diff (ADR-009)
- Migrations are numbered, immutable and forward-only under `/db/migrations`
  (ADR-010)
- The OpenAPI document is schema-first; server interfaces are generated and CI fails on
  a diff (ADR-011)

## Naming

- Documentation files: lowercase, hyphenated, English (`i1a-work-packages.md`)
- ADR files: `ADR-<nnn>-<short-english-slug>.md`
- Work packages: `WP-<iteration>.<nn>`, e.g. `WP-1a.04`

## Company name

The company name is always written **xpera** — lowercase, always, including at the
start of a sentence and in document titles.
