# Brief for workstream plan writers (W3-W13)

You write one workstream implementation plan for Phylax v4. Do not write product code; do not commit; edit only your plan file(s).

Read, in order:
1. The writing-plans skill: /home/davidracovan/.claude/plugins/cache/superpowers-dev/superpowers/7.0.1/skills/writing-plans/SKILL.md. Follow its format exactly (header with Goal/Architecture/Tech Stack/Spec, Global Constraints, Review Focus, tasks with Files / Interfaces (Consumes/Produces with exact Go signatures) / checkbox TDD steps with test code and exact commands, self-review).
2. docs/impl/README.md (master plan): your workstream's row, dependencies, gates, branch, the execution model (Haiku implementers one task each; a stronger-model "seams" task first; a lab task last by a stronger agent or David), the known-bug and module mapping.
3. docs/impl/01-module-contract.md (W1): every name in its Interfaces "Produces" blocks is the contract your plan consumes. Use those exact package paths, types and signatures; never invent a parallel one. If you need something W1 doesn't produce, add it to your seams task and say so.
4. phylax_design.md (v4 spec): the module sections your workstream owns (12-part template), the module contract, the event-kind table, the core action table, Known bugs, Appendix D layout.
5. The existing code for your modules (internal/..., rules/, plans/, docs/*.md) so every path and name is real, and you know what to move, keep, or delete.

Rules for the plan:
- Haiku-sized tasks: about one package or ~200 lines, exact file paths, exact signatures, test names with assertions using the spec's values, one verification command with expected output.
- Retrofit = move the module onto the contract (package per Appendix D, delete old paths), keep behaviour, keep/port tests; then new features; then the module's known bugs; then its rules/plans/check content.
- Owner rules: small commits, message `area: summary`, NO attribution lines; Go 1.27.2 via mise; CGO_ENABLED=0 for builds, CGO_ENABLED=1 for `-race`; `make build build-windows vet test race` passes every commit; real tests, no mocks of the code under test; bounded everything; atomic writes; ponytail (smallest complete change; `shortcut: <limit>, <when to upgrade>` comments).
- Proportion: signatures, tests and decisions, not transcribed function bodies.
- Simplification pass (2026-11-06, S1-S4 in `docs/impl/design-review-2026-11-06.md`): plan the design as it now reads. No per-module act ladders, rule modes or breakers (the engine's `autonomy` setting and attempt ledger), no per-module operator-edit kinds (`operator.edit`), `act_enabled` only on acting modules, one `deception` module, trace-back inside `chains`, saved queries as report generators. Grep the design for each name before using it.
- Self-review per the skill before replying.

Reply under 200 words: plan file(s), task counts, anything W1 lacked that you added to your seams task, design gaps you hit.
