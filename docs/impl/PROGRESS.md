# Phylax v4 redesign: progress and where to resume

Status as of 2026-10-31. Branch `v3-redesign` (local only, not pushed). No product code has been written; David said not to start implementation yet.

## Done

1. **Re-review of the whole design** against the ccdc vault and other teams' platforms: [review.md](review.md). Every v3 capability and every vault or peer finding has a call (KEEP / CHANGE / CUT / ADD), and David answered every area. The "Answers from David" sections at the end override the table rows; "What David prefers" lists his standing preferences (detection depth matters; simplicity means fewer mechanisms; anything touching a scored service must be provably safe; as much automation as possible behind probes and rollback; no AI, no prewritten injects, no inject or scoreboard tracking, no competition-rule reasoning, no mass credential rotation).
2. **Design v4**: [../../phylax_design.md](../../phylax_design.md) (~9,600 lines), restructured around the module contract. 34 modules in a 12-part template, one event-kind table, one core action table, known bugs, "Removed in v4" appendix. Builder-checked by three reviewers ([builder-answers.md](builder-answers.md) holds the resolutions). **David approved it** (commit `5b674c8`, then `7169fe5`).
3. **Invitational data list**: [invitational-data.md](invitational-data.md): 65 questions the 2026-11-07 Invitational can answer, the collectors, and the organizer-only questions.
4. **Implementation plans** (Haiku-ready, superpowers writing-plans format):
   - [README.md](README.md): master plan (workstreams W0-W13, dependencies, gates, branches, execution model).
   - [00-proving.md](00-proving.md) W0, [01-module-contract.md](01-module-contract.md) W1, [02-invitational.md](02-invitational.md) W2, [03-telemetry.md](03-telemetry.md) W3, [05-integrity-hunting.md](05-integrity-hunting.md) W5, [06-network.md](06-network.md) W6: written and committed.
   - [PLAN-BRIEF.md](PLAN-BRIEF.md): the brief every remaining plan writer gets.

## In flight when this was written

Three Sonnet agents were writing these; check whether each file is complete (ends with a self-review and a lab task) before trusting it:
- [04-detection-response.md](04-detection-response.md) W4
- [07-scoring-creds.md](07-scoring-creds.md) W7
- [11-integrations-depot.md](11-integrations-depot.md) W11

If a file is missing or truncated, rerun it with: "Follow docs/impl/PLAN-BRIEF.md exactly. Your workstream: W<n> <name> (see the README row). Write docs/impl/<nn>-<name>.md." Use Sonnet, at most three at a time (David's preference).

## Still to do, in order

1. **Remaining plans** (Sonnet, PLAN-BRIEF.md): W8 analysis (`08-analysis.md`), W9 deception (`09-deception.md`), W10 reports-ops (`10-reports-ops.md`, shell pages only; each module's own page belongs to its workstream), W12 enrollment (`12-enrollment.md`), W13 C2 fingerprint lab (`13-c2-lab.md`; framework list in review.md A6.Q4).
2. **Consistency pass over all plans** using [plan-crossrefs.md](plan-crossrefs.md). The main items:
   - One name for exporting action registration: W3 says `actions.RegisterExtra`, W5 `actions.Register`, W6 `actions.RegisterFamily`. Pick one, put it in W1's seams task, fix the others.
   - Move core features nobody owns into W1: the `expires_after` plan option, the `gate: auto` gate kind, a module-facing overrides writer (`learned_listeners`), per-device vault keys, and the seam extras W3/W5/W6 added (common-struct extension fields, `Event.WithExtra`, `Host.Manifest()`, `Env.Now`/`Env.Ext`, `storetest.New`, `LoadModuleTemplateFor`, the `plans` package in `CoreImports`).
   - Add to W5: `sysmon.install`, `sysmon.config`, `eventlog.size`, enabling analytic channels.
   - Add module UI page tasks to W6 (and check the others) since each workstream owns its module's pages.
   - Ordering note: `deps.edge` stops between W3 Task 17 and W8's `deps` subscriber task; order them or keep a shim.
   - Write the plan-driven design fixes back into phylax_design.md (registry action names `registry.set`/`registry.delete`, `ad.recycle_restored` in `ad` Emits, sshsig namespace `phylax-release`, content dirs for `logs`/`inventory` in Appendix D, W1's Host/plan import-cycle fix).
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
