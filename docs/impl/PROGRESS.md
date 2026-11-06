# Phylax v4 redesign: progress and where to resume

Status as of 2026-10-31. Branch `v4` (local only, not pushed). No product code has been written; David said not to start implementation yet.

## Done

1. **Re-review of the whole design** against the ccdc vault and other teams' platforms: [review.md](review.md). Every v3 capability and every vault or peer finding has a call (KEEP / CHANGE / CUT / ADD), and David answered every area. The "Answers from David" sections at the end override the table rows; "What David prefers" lists his standing preferences (detection depth matters; simplicity means fewer mechanisms; anything touching a scored service must be provably safe; as much automation as possible behind probes and rollback; no AI, no prewritten injects, no inject or scoreboard tracking, no competition-rule reasoning, no mass credential rotation).
2. **Design v4**: [../../phylax_design.md](../../phylax_design.md) (~9,600 lines), restructured around the module contract. 34 modules in a 12-part template, one event-kind table, one core action table, known bugs, "Removed in v4" appendix. Builder-checked by three reviewers ([builder-answers.md](builder-answers.md) holds the resolutions). **David approved it** (commit `5b674c8`, then `7169fe5`).
3. **Invitational data list**: [invitational-data.md](invitational-data.md): 65 questions the 2026-11-07 Invitational can answer, the collectors, and the organizer-only questions.
4. **Implementation plans** (Haiku-ready, superpowers writing-plans format):
   - [README.md](README.md): master plan (workstreams W0-W13, dependencies, gates, branches, execution model).
   - [00-proving.md](00-proving.md) W0, [01-module-contract.md](01-module-contract.md) W1, [02-invitational.md](02-invitational.md) W2, [03-telemetry.md](03-telemetry.md) W3, [05-integrity-hunting.md](05-integrity-hunting.md) W5, [06-network.md](06-network.md) W6: written and committed.
   - [PLAN-BRIEF.md](PLAN-BRIEF.md): the brief every remaining plan writer gets.

## In flight when this was written

All three finished and were committed after this note was first written:
- [04-detection-response.md](04-detection-response.md) W4 (finished; committed)
- [07-scoring-creds.md](07-scoring-creds.md) W7 (finished; committed)
- [11-integrations-depot.md](11-integrations-depot.md) W11 (finished; committed)

If a file is missing or truncated, rerun it with: "Follow docs/impl/PLAN-BRIEF.md exactly. Your workstream: W<n> <name> (see the README row). Write docs/impl/<nn>-<name>.md." Use Sonnet, at most three at a time (David's preference).

## Still to do, in order

1. **Remaining plans** (Sonnet, PLAN-BRIEF.md): W8 analysis (`08-analysis.md`), W9 deception (`09-deception.md`), W10 reports-ops (`10-reports-ops.md`, shell pages only; each module's own page belongs to its workstream), W12 enrollment (`12-enrollment.md`), W13 C2 fingerprint lab (`13-c2-lab.md`; framework list in review.md A6.Q4).
2. **Consistency pass over all plans** using [plan-crossrefs.md](plan-crossrefs.md). Done 2026-11-06 (W1 is final and ready to implement):
   - [x] One name for exporting action registration: `actions.Register` (+ `RegisterUndo`, `Unsupported`, `Env.Now`/`Env.Clock`, `Env.Ext`), W1 Task 2a; W3, W4, W6, W7, W11 fixed.
   - [x] Unowned core features moved into W1: `expires_after` (Task 22a), `gate: auto` (Task 27a), overrides writer (Tasks 11a, 17a), per-device vault keys as prefix grants (Tasks 9a, 17a), seam extras: `WithExtra` (3a), extension fields (4a), `Host.Manifest` (17a), `Env.Now`/`Env.Ext` (2a), `storetest.New` (8a), `LoadModuleTemplateFor` and `plans` in `CoreImports` (22b). W3, W4, W5, W6 trimmed and pointed at W1. W7's `window:`, `gate: manual`, `txn:` stay in W7 (README notes W5 and W10 depend on W7 Tasks 2 to 7).
   - [x] Plan-driven design fixes written into phylax_design.md (registry names, `ad.recycle_restored`, sshsig namespace, `logs`/`inventory` content paths, Host/plan import-cycle fix). W7's design fixes (table names, `pcr.generate`, Kali ordering and the others in plan-crossrefs.md) are still to write.
   - [ ] Add to W5: `sysmon.config`, `eventlog.size`, enabling analytic channels (`sysmon.install` is W4 Task 23).
   - [ ] Add module UI page tasks to W6 (and check the others) since each workstream owns its module's pages.
   - [ ] Ordering note: `deps.edge` stops between W3 Task 17 and W8's `deps` subscriber task; order them or keep a shim.
3. **Self-review of the whole plan set** (spec coverage, type consistency across plans), then hand to David for review and to choose the execution method (subagent-driven recommended: many tasks, tight interfaces).
4. **Outside this repo** (agreed, not done yet):
   - ccdc-private `GOALS.md`: reword "Never downscope Phylax" to "Scope is set by the 2026-11 re-review in phylax_design.md; once a capability is accepted, it isn't cut for time" (review Q20).
   - ccdc-private `strategy/phylax-proposals.md`, `phylax-detection-coverage.md`, `phylax-proposed-rules.md`: mark superseded with a pointer to phylax_design.md v4 (review Q11).
   - Triage the two Discord pastes in `ccdc-private/knowledge-base/inbox/david/` (2026-10-22 Quotient scoring users; 2026-10-26 AD hash dump) into vault records with the knowledge-base skill.

## Open items that wait on facts, not on David

- `pcr.submit`: moot unless organizers allow scripted PCR entry (David is asking).
- Sinkhole: kept until the C2 fingerprinting lab (W13) decides.
- Docker-hosted ecom: unverified for 2027.
- Everything in invitational-data.md, answered at the Invitational and in the pre-quals access week.
