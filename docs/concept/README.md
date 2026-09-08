# Concept documents

| File | Role |
|---|---|
| `fachkonzept-v0.2.md` | **Functional concept**, German. Authoritative for FR-001..FR-034, NFR-001..NFR-015, AT-001..AT-021. Takes precedence over the implementation concept. |
| `umsetzungskonzept-v0.1.md` | **Implementation concept**, German. Authoritative for technical realisation. |
| `change-log-v0.1-to-v0.2.md` | Chapter-by-chapter changes agreed in the review of 8 September 2026 |
| `source/RiskSignal_Fachkonzept_v0.2.docx` | The author's Word original of the functional concept — see *Authoring master* below. |

**Read the implementation concept together with the change log.** The change log is not a
summary — it lists what still has to be incorporated into v0.2. Chapters not mentioned
there are unchanged.

That split is temporary. `WP-0.01` — section 7 of
[`../prompts/orchestrator-kickoff.md`](../prompts/orchestrator-kickoff.md) — merges the
two into a single `umsetzungskonzept-v0.2.md` before any implementation starts. After
that, v0.2 is authoritative, v0.1 becomes the archive, and the change log becomes
history rather than a to-do. The functional concept is not affected by that merge.

## Precedence

functional concept → implementation concept → `../adr/` → change log

A technical decision may sharpen a functional requirement but never weaken it.

## Language

Both concepts are maintained in German. This is the documented exception to the
project's English-only rule — see `CLAUDE.md`. Do not translate them and do not create a
German counterpart of any other document.

## Authoring master — open question

The functional concept exists twice: as `fachkonzept-v0.2.md` and as the Word original
under `source/`. Two editable masters drift. One of two rules has to hold, and it is not
yet decided:

- **Word stays the master.** Edits happen in the .docx; the Markdown is regenerated and
  never edited by hand.
- **Markdown becomes the master.** The .docx is kept only as the historical original and
  is no longer edited.

Until this is settled, treat `fachkonzept-v0.2.md` as authoritative for reading and do
not edit either file without saying which rule you are following.

## Provenance

- `fachkonzept-v0.2.md` was converted mechanically from the Word original with
  `pandoc -f docx -t gfm --wrap=none`, then post-processed (heading levels, the
  transparency note into a block quote, escape cleanup, chapter rules). Verified against
  the PDF rendering: 16 chapters, 23 tables, and every FR, NFR, AT, OD, UC, AP and R
  identifier present and matching.
- `umsetzungskonzept-v0.1.md` was converted from a 27-page PDF via text extraction and
  reconstruction. Verified the same way: 21 chapters, 34 tables, all identifiers
  matching. Chapter 2.2 held a rendered architecture image in the PDF and is reproduced
  as a Mermaid diagram carrying the same boxes and layers.

## Regenerating the functional concept from Word

```
pandoc -f docx -t gfm --wrap=none source/RiskSignal_Fachkonzept_v0.2.docx -o fachkonzept-v0.2.md
```

Then redo the post-processing: demote all headings one level, add the title block, turn
the transparency note into a block quote, and insert `---` before each numbered chapter.
