# Concept documents

| File | Role |
|---|---|
| `umsetzungskonzept-v0.2.md` | **The** implementation concept, German. Authoritative. |
| `umsetzungskonzept-v0.1.md` | Archive — superseded by v0.2. Kept untouched. |
| `change-log-v0.1-to-v0.2.md` | History — its changes are incorporated in v0.2. |

`umsetzungskonzept-v0.2.md` was consolidated on 8 September 2026 (WP-0.01) from v0.1,
the change log and ADR-008..ADR-015; the ADRs are carried in full as Anhang A so the
document is implementable without a companion file. v0.2 is authoritative for
implementation; v0.1 and the change log remain for provenance only.

## Missing here

The **functional concept v0.2** (`RiskSignal Fachkonzept v0.2`) is not in this
repository. It is authoritative for FR-001..FR-034 and NFR-001..NFR-015 and takes
precedence over the implementation concept. It should be added alongside these files,
in the same Markdown form.

## Language

The concept is maintained in German. This is the documented exception to the project's
English-only rule — see `CLAUDE.md`. Do not translate it and do not create a German
counterpart of any other document.

## Provenance

The Markdown was converted from `RiskSignal_Umsetzungskonzept_v0.1.pdf` (27 pages,
8 September 2026). The conversion was verified against the PDF: all 21 chapters, all
34 tables, and every ADR, TR, TAT, TD, TRI, FR, NFR and AT identifier match. Chapter
2.2 held a rendered architecture image in the PDF; it is reproduced here as a Mermaid
diagram carrying the same boxes and layers. From here on the Markdown is the source of
record — edit it directly and regenerate any PDF from it, not the other way round.

v0.2 was produced from this Markdown by applying the change log chapter by chapter; the
self-formulated passages are listed in the orchestrator's WP-0.01 completion report and
are pending author review before the status moves from `Entwurf` to released.
