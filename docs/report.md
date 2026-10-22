# internal/report and inject-kit

The IR drafter and the inject kit (design: "Service backups, IR drafter and inject kit"). Pure Go, no
external typesetter: Markdown is the source, `go-pdf/fpdf` renders the PDF with the Go TrueType fonts embedded
(ToUnicode map included), so NISE and `ledongthuc/pdf` can extract the text.

**Design change (recorded here because the design doc said Typst):** rendering is a pure-Go Markdown subset
-> PDF, not a Typst host binary. HTML output is not produced. `phylax_design.md` records the change in the IR
rendering paragraph.

## Entry points the controller and UI call

| Function | Purpose |
| --- | --- |
| `DraftIR(IRInput) (*IRDraft, error)` | Chain/campaign + trace-back + detection + evidence -> draft following the playbook template (header rows, sections 1-8, evidence appendix). |
| `(*IRDraft).Markdown`, `.PDF(allowPlaceholders)`, `.Review()`, `.Checklist`, `.Placeholders` | Output. `PDF(false)` refuses while any `[[FILL: ...]]` remains. `Review()` is the reviewer page (placeholders + rubric), not part of the submission. |
| `RenderInject(InjectData)` | memo, config-memo (per-host summary and evidence tables, platform appendices), policy, extension-request. |
| `BlankTemplate(kind)` | Raw template text from `inject-kit/`. |
| `ValidateSubmission(pdf, SubmitSpec)` | Pre-submit checklist on the final PDF. |
| `Filename(kind, n, team)` / `ParseFilename` | `incidentNN_teamTT.pdf`, `injectNN_teamTT.pdf`. |
| `Central(t)`, `CentralShort(t)` | `2027-03-06 09:00:05 CST (15:00:05 UTC)`; header form ends `(US Central)`. |
| `ExtractText(pdf)` | Per-page text, as a reader sees it. |

## IR draft

- Time zone: US Central with UTC alongside, from `chains.Central()`.
- Per-hop lines in section 3 (attack path) and 6 (remediation), each with link method, confidence, stored event
  pointers (`agent#seq`) and remediation state (OPEN / APPLIED / VERIFIED). Guess hops (time window, unmatched) are
  labelled "inferred, not confirmed".
- Operator facts the controller cannot know are `[[FILL: ...]]` placeholders: detection if not supplied, downtime,
  the data statement, remediation time, retest steps, figure captions, host and taken-time of figures.
- Evidence figures: `Evidence{Kind, Path, Host, Caption, Taken, Tags, HopLabel, Annotated}`. Captions use the house
  format `Figure N: <what it proves> (<host>, taken <Central time>)`. Hashes are computed from the file (or the
  excerpt). PNG/JPEG screenshots are embedded when the file exists; the path and SHA-256 are always printed.
  Tags (`red_activity`, `vuln`, `detection`, `eradication`, `remediation`, `verification`, `firewall`) place the
  figure in the checklist and in the "Evidence:" lines.

### Self-score checklist

Items carry a rubric, weight and status `met | partial | unmet | operator-only`. "No partial points" is honoured:
only `met` earns weight (`Checklist.Earned`).

- WinterKnight: `WK-proof`, `WK-time`, `WK-detect`, `WK-impact`, `WK-mitigate` (10% each), `WK-remediate` (50%; one
  line per hop with verified status; needs a retest step with a result and a verification figure).
- UW-Stout: `ST-attack` 30, `ST-remediate` 20, `ST-eradicate` 15, `ST-impact` 10, `ST-proof` 10, `ST-clarity` 10,
  `ST-general` 5.
- Playbook section 6: `PB-firewall`, `PB-trace`, `PB-placeholders`, `PB-tz`, `PB-one-narrative`, and the operator-only
  `PB-screenshots`, `PB-red-caused`, `PB-header`.

Operator-only items are never auto-passed: screenshot quality (cursor, cropping, annotation), whether the incident is
red-team-caused rather than a preconfigured service or scorer traffic, and the second-person header re-read.

## Inject kit

`inject-kit/*.md.tmpl` are Go `text/template` data files, blank (placeholders only; nothing from past events, per
the MWCCDC public-repo rule). `InjectData.Team` is used only for the file name; the templates cannot see it.
Every document starts with `# Inject N - CODE - title` so the inject number is the first text in the PDF.
`Fields` keys per template are the first argument of `{{f "key" "hint"}}` in the template file.

## Pre-submit validator

`ValidateSubmission` checks: file name rule and agreement with number/team; PDF has extractable text on every page;
inject number first (IR: `Incident Report N` in the header); team number only in the file name for injects (IR: the
From line must carry it); optional forbidden words (school name); every attachment filename appears in the text
(whitespace-insensitive, since wrapping splits names); no `[[FILL`, `<angle>` placeholders or TODO; "US Central" label
(warning); length sanity (words, page warn/fail limits, file size warning).

## Gaps

- Fills for generic placeholders are text substitutions on the generated Markdown. The rubric checklist is the
  drafter's own, so an item that depends on a section's placeholders (for example impact) only turns `met` when the
  structured field (downtime, data statement, detection, retests) is filled, not when its placeholder is replaced by
  a generic fill. `PB-placeholders` is recomputed after the fills.
- Removing a figure renumbers the later ones; retest lines that cite a figure number must be edited.
- Attachments other than screenshots are not uploaded through the UI (`Attachments` stays empty).
- No HTML output; PDF layout is plain (no syntax highlighting, bold/italic inline markup is flattened).
- Fonts are Latin only; other scripts become `?`.
- Rubric text is encoded from the ccdc-private notes; if the graders change, edit `irchecklist.go`.
- Screenshot properties (cursor, cropping) and whether the NISE upload accepts the PDF are untested.

## Controller and UI integration

Code: `internal/controller/report_*.go` (drafts, evidence, render, download) and `internal/ui/reports.go` with the
`draft.html` and `reports.html` templates. Drafts live in the store table `report_drafts` (migration 4): a JSON spec
with the chain or campaign ids, the operator's raw field text, the fills (`what` -> text) and the figure list.
Nothing is cached: every view re-drafts from the stored chains, applies the fills, renders the PDF and runs
`ValidateSubmission`, so the page, the validator and the download always agree.

Config (controller JSON): `team` (1..99, required for drafts), `next_incident` and `next_inject` (first number offered;
later drafts continue after the highest used), `forbidden_words` (school name spellings the validator rejects).

| Route | Does |
| --- | --- |
| `GET /reports` | Drafts list; new inject form (template, number, code, title). |
| `POST /reports/ir` (`chain` or `campaign`) | "Draft IR": `IRInput` from the chains, the earliest alert pointing at them (detection time and method) and its trace-back (collected-file hashes). |
| `GET /reports/{id}` | Review: validation result, field form, placeholder table, rubric checklist (met / partial / unmet / operator-only), figures, text preview. |
| `POST /reports/{id}/save` | Store fields and fills, regenerate. Unparseable times or lines are refused (400). |
| `POST /reports/{id}/upload` | PNG/JPEG screenshot, at most 8 MiB, sniffed and decoded, stored as `<data_dir>/reports/<id>/<sha256[:16]>.png`; the full hash is kept and re-checked on every render. |
| `POST /reports/{id}/hostevidence` | Log-excerpt figure from the newest stored events of one host (and optional kind). |
| `POST /reports/{id}/evidence/{n}/delete`, `/validate` | Detach a figure; record an explicit validation run in the audit log. |
| `GET /reports/{id}/download` | `incidentNN_teamTT.pdf` / `injectNN_teamTT.pdf`, only when `ValidateSubmission` has no failure and no stored figure file changed; otherwise 409 naming the failed checks. Audited. |

All POSTs go through `ui.Handle` (session, CSRF, audit before the handler). The multipart upload reads the CSRF token
from its first form field (or the `X-CSRF-Token` header); only that route has the larger body cap.

Inject drafts: the form lists the template's `{{f "key" "hint"}}` inputs (parsed from the template) plus pipe-separated
lines for deliverables, hosts, statements, finished and remaining items. The config memo's per-host figure column
finds figures by host name, which the host-evidence button sets.
