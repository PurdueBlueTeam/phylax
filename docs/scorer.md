# internal/scorer: the scorer model

Controller-side logic for the competition scorer (Quotient). Pure logic, driven by explicit timestamps; later fed by flow and transaction events. Evidence: ccdc-private `research/topics/quotient.md`; design: `phylax_design.md` ("Active checks and check discovery", "PCR as a transaction", Appendices F and G).

| Part | File | What it does |
| --- | --- | --- |
| Round clock | `clock.go` | `Estimator.Observe(t)` clusters scorer-attributed new connections into bursts (>= 15 within 100 ms, joined while gaps are <= 1 s). Delay and Jitter come from single-round intervals: lattice fit rejects spurious bursts and recognises dropped rounds (interval = m x Delay), MAD rejects residual outliers, Delay = mean, Jitter = max(sqrt(3) x std, half-range) (the scorer draws uniformly). `SafeFor(now, need)` returns the quiet window `[last burst end + 2 s, earliest next start - 3 s]` with confidence; `Hazard(t)` marks burst and enqueue-pass times. |
| Fingerprints | `fingerprint.go`, `fptable.go` | Versioned data table (Appendix G), JSON-loadable per event (`ParseTable`). Score = noisy-or of matched rules and generic hints (burst, one-shot, learned credential), times (1-w) per contradiction. Source address is advisory (3 % and only on top of behaviour). HTTP User-Agent is not a rule. Protocols without a native check (MSSQL, Splunk, RDP-auth) are capped at 0.7. |
| Discovery | `discovery.go` | Services learned after 2 distinct rounds; item sets as a growing union with Good-Turing coverage, Chao1 size estimate and k x H_k expected rounds; proposals (new, update, stale) against the active list, never removing; blocked and silent detection; scored-account learning with `GuardRotation` (sysadmin scored until shown otherwise). |
| SLA | `sla.go` | Streak per service rebuilt by replaying a round log, so `Discard(round)` and operator `Verdict` correct history exactly. Alerts at threshold-2, threshold-1 and penalty (counter resets). Unknown outcomes and discarded rounds neither advance nor reset. |
| PCR | `pcr.go`, `csv.go` | Transaction state machine planned -> host_changed -> pcr_submitted -> verified, with failed -> rolled_back. Timed to the safe window, human-in-the-loop by default (`Prepare` gives the CSV, `ConfirmSubmission` records the portal reply); `PCRConfig.Scripted` enables `Submit`. Password and character rules are delegated to `internal/creds` (`Generate`, `PCRSafe`, `Scored.Check`); secrets are `vault.Secret`; `CredsState`/`SyncRecord` map state onto `creds.Record`. |

## PCR rules implemented

- Never during a burst or its enqueue pad; each step needs `MinWindow` (30 s) of quiet time and clock confidence >= 0.5 (operator override available).
- A scored account needs a credlist path; one CSV block per path; duplicates, display-name paths, unsafe characters are refused; the generated text is re-parsed with a copy of the portal's parser.
- `count` must equal the line count and `skipped` be empty. Skipped users are failed with no PCR rollback needed; any other mismatch is treated as possibly applied.
- Pending (planned, host_changed, pcr_submitted, failed) blocks further rotation of that account (`CanRotate`) until verified or rolled back.
- Rollback reverts the host and resubmits the OLD value; "Reset to Defaults" does not exist in this package.
- A PCR landing in a burst's enqueue pad, or after the deadline, is flagged `Race`; the first failed scorer login in the next burst is forgiven once (mixed snapshot).
- Silence never rolls back: `Tick` only emits notices.

## Resolved ambiguities

- Before 10 bursts the design says publish upstream defaults. With zero intervals we do; once any interval is seen the provisional estimate uses what was observed (lab rounds ran 20 +- 5; a 60 s guess would put the window end past the next burst), at confidence <= 0.35.
- State names follow the task (`host_changed`, `pcr_submitted`, `verified`, `rolled_back`) plus `failed`; they map to the design's names for `creds.Record.PCRState`. The host changes first, then the PCR.
- A service is "learned" after 2 distinct rounds (a recurrence), required to happen within 3.
- A discarded round is unobservable from capture; callers feed it via `Discard` (round gap, portal poll, operator).
