#### `creds`

**1. Purpose and evidence.**

`creds` owns every credential Phylax knows: the inventory per (account, credlist), password generation, the T+0 console sheet, scheduled rotation of unscored accounts, and the one rare, careful operation: changing a scored password on evidence. A scored change is a **host change plus a typed PCR list**. Phylax changes the password on the host inside a scorer quiet window and shows a short list of (credlist, user, new password) that a human has already typed into Quotient on a machine outside the environment and now submits; Phylax then verifies by login. A revert of a host or of AD is detected and re-synced. Credentials are never mass-rotated.

Evidence that it matters for points:

- Default credentials are the first thing red uses: 18 default-credential shells in 2026 [[how-to-win-ccdc-dealing-with-red-team]], a spray at drop flag [[discord-2026q-rt-debrief#e1]]. Team-pack admin passwords leak within seconds (a full domain dump about 10 s after drop flag at Nationals, cleartext about 20 s; MW Discord 2026-10-22 and 2026-10-26, decision 10). Admin and service rotation is therefore a T+0 console action ahead of enrollment (core, Enrollment). `creds` supplies the values and the record.
- Quotient shows teams the users it scores with, no admin accounts are scored, there are a lot of scoring users and mass rotation is a bad play; the red team does not have the user list (decision 10). Selective rotation on evidence is the policy (decision 5, review D424).
- Quotient keeps several credential lists, possibly per service, and a PCR is per list. A user on two lists needs two rows (decision 10; credentials keyed by (account, credlist), cross-cutting idea 4).
- PCRs take effect immediately, Quotient does not know about reverts, and "Reset to Defaults" rewrites every user in a list [Q §5, Q §9.1]. A revert silently fails the scored logins on that host without a re-sync (review N7.3; Jimmy: "Quotient has no idea what a revert is").
- Quotient limits: no shared passwords and none of 40 or more characters (Quotient issue #107) [[issues-dbaseqp-quotient#e9]]; quoting and trimming bugs (issues #13 and #14).
- There is no clipboard between the consoles and the Quotient machine (review A7.Q5), so what a human carries out must be short and typeable. Peer evidence on stateless break-glass derivation: [WT §9.10].
- A breach of the controller exposes every rotated password in the vault (Trust model), and red dumps every AD hash ("one DC's worth of plaintext"). Both argue for rotating few scored passwords (review A7.Q6, A7.Q8).

**2. Status and code.**

Partial. Built: `internal/creds` (`policy.go` generator with uniqueness and `PCRSafe`; `breakglass.go` stateless derivation with a known-answer test; `record.go` records, `PlanRotation`), `internal/vault` (age/scrypt file, versions, rollback, `Secret` type, backup), and the PCR engine in `internal/scorer/pcr.go` and `csv.go` (state machine, window gating, CSV generator with a copy of the portal's parser, rollback). The `credentials` table exists in the core migrations (it moves to this module). Missing or different from this design:

- `Record.Credlist` is one PCR path and `PCRState` one value. Keyed by (account, credlist) means a set of credlists per account and a state per row; a `reverted` state is missing (review N7.3).
- The generator has no typeable class (review A7.Q4): `Scored` is 16-24 random characters, `Unscored` 24-32, `Admin` 32-40.
- The engine has `Scripted` and `Submit`; both are deleted (a human enters PCRs; `pcr.submit` is moot, review D167, D430).
- `PlanRotation` has a scored stage (`MethodPCR`) and holds `sysadmin` until the PCR list is checked. Both go: scored accounts are never planned in bulk, and no admin account is scored (decision 10, review D432, D433).
- No evidence-triggered proposals, no T+0 sheet generator, no typed list screen, no armed-until-window hold, no revert re-sync, no events or table.

The PCR engine moves into this module (`internal/creds/pcr`, with `csv.go`). It reads the window from `scorer.clock` events and imports nothing from `scorer`; the Kali verification goes through a signed `pcr.verify` step rather than a `Verifier` interface from `vantage`.

Files: `internal/creds/*.go`, `internal/creds/pcr/*.go`, `internal/vault/*.go` (core), `plans/creds/` (content), `rules/creds/words.txt` (the passphrase word list).

**3. Capability manifest.**

| Field | Value |
| --- | --- |
| Name | `creds` |
| Sides | controller |
| OS | n/a |
| Privilege | `none` |
| Roles | `controller` |
| Default | core |
| Budget | 20 CPU ms/s, 16 MB held, 1 event/s, 10 KB out/min, 2 MB disk |
| Tables | `credentials`, `cred_credlist`, `pcr_txn`, `pcr_row` |
| Content | `plans/creds` (T+0 sheet, rotation plans for unscored accounts, the scored-change plan), `rules/creds` (word list) |
| Actions | `pcr.generate`, `pcr.verify` (the Kali executes it; see `vantage`) |
| Pages | `/credentials` |
| Evidence | part 1 |

Secrets: `Host.Secrets` grants the names its config declares (`cred/*`). Values are never in events, tables or logs; tables hold vault version ids.

**4. Configuration.**

`accounts.yml` (manifest) declares accounts; `modules/creds.yml` holds the tunables:

```yaml
# accounts.yml (excerpt)
accounts:
  sysadmin@linux:  { scope: local,  hosts: [rocky-ecom, ubuntu-email, debian-splunk], scored: false, rotation: t0_console }
  ad-admin:        { scope: domain, scored: false, rotation: t0_console }
  oc-admin:        { scope: app, hosts: [rocky-ecom], scored: false, rotation: plan, embedded_in: [/var/www/html/config.php] }
  mail-users:      { scope: domain, scored: true,  credlists: [learned], rotation: on_evidence, learn_from: scorer }

# modules/creds.yml
generation:
  typeable: { words: 4, min_len: 20, max_len: 25, digits: 2, wordlist: rules/creds/words.txt }   # scored passwords and any password a human types
  admin:    { words: 5, max_len: 32 }                                                              # console-typed admin accounts at T+0
  machine:  { min_len: 24, max_len: 32 }                                                           # service and app accounts a plan writes
pcr:
  min_window: 30s            # quiet time needed to start a step
  min_confidence: 0.5        # round-clock confidence needed; an operator can override
  verify_notice: 15m         # notice only; silence never rolls back
  max_accounts_per_txn: 3    # starting values, set from the typing exercise (invitational O8)
  max_open_txns: 6
  evict_sessions: true
revert:
  on_reenroll: true          # mark a re-enrolled host's rotated credentials reverted
breakglass:
  epoch: 1                   # raised after a controller restore so an old printed sheet does not match
```

```go
// package creds
type Config struct {
	Gen     GenConfig
	PCR     PCRConfig // MinWindow, MinConfidence, VerifyNotice, MaxAccountsPerTxn, MaxOpenTxns, EvictSessions; no Scripted
	Revert  struct{ OnReenroll bool }
	BreakGlassEpoch int
}

type Record struct { // no secret; the value is in the vault under cred/<host>/<account>
	Account  string // case-exact
	Host     string
	Role     Role
	Domain   bool
	Scored   bool
	Credlists []CredlistRow // one row per Quotient credlist the account sits on
	CurrentVersion, PreviousVersion string
	LastRotated time.Time
}
type CredlistRow struct {
	Credlist string   // the label or the Quotient name entered by the operator
	State    PCRState // stable, planned, host_changed, pcr_submitted, verified, failed, rolled_back, reverted
	Txn      string
}
```

**5. Events.**

Consumes (kinds as named in the producing sections): `scorer.account`, `scorer.round`, `scorer.clock`, `vantage.pcr_verify`, `vantage.probe` (Zerologon result), `detect.alert` (pass-the-hash, DCSync, credential use), `honeytokens.sighting`, `hunt.finding` (credential files), `chains.chain` (remediation items of kind `rotate_credential`), `agent.enrolled` and `agent.reenrolled` (core events; the core Enrollment section describes the transitions, the event names are to be confirmed), `checks.result` (a scored login that stops working).

Emits:

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `creds.state` | 1 | normal | `account`, `host`, `credlist`, `state`, `current_version`, `previous_version`, `txn`; never a value |
| `creds.proposal` | 1 | high | `account`, `credlists[]`, `hosts[]`, `reason`, `evidence[]` (refs to the alert, chain or hunt), `proposed_by` |
| `creds.txn` | 1 | high | `txn`, `account`, `step` (`prepared`, `staged`, `committing`, `host_changed`, `verify_ok`, `pcr_submitted`, `verified`, `failed`, `rolled_back`, `late`, `race`), `window`, `reply` (count, skipped), `by` (operator names) |
| `creds.reverted` | 1 | high | `host`, `accounts[]`, `credlists[]`, `reason` (`reenroll`, `login_mismatch`, `operator`) |
| `creds.notice` | 1 | normal | `txn`, `what` (verification overdue, window missed, open transactions blocking a host) |
| `creds.t0` | 1 | normal | `host`, `account`, `step` ticked; the T+0 console record |

**6. Behaviour.**

*Inventory.* Every account in `accounts.yml`, plus whatever discovery finds: local accounts on every host, domain accounts, service and app accounts (MySQL, OpenCart admin, Splunk, SQL Server, the Palo and VyOS admin accounts). Each has a `scored` flag (declared, or learned from the scorer by `scorer.account`), a set of credlists, a rotation policy (`t0_console`, `plan`, `on_evidence`, `none`) and the files and services that embed it. A scored account takes its credlist rows from the learned groups in `scorer`. Marked accounts are never locked, deleted, renamed, expired or rotated outside a PCR transaction; the scoring-safety lint reads `creds.state` and `scorer.account` for that.

*Generation.* Passwords come from the vault's generator, unique across everything it generated or reserved (SHA-256 digests only, case-insensitive). Three classes:

- **Typeable passphrases** for scored passwords and for any password a human types: four words from a fixed list of short common lowercase words (no ambiguous spellings), joined with `-`, with one word capitalised and two digits (for example `Plum-river-tent-82`), 20 to 25 characters (review A7.Q4). It satisfies AD complexity (upper, lower, digit, non-alphanumeric) and stays inside Quotient's safe set `[A-Za-z0-9._+=-]`: no `@ : /` (which break the MySQL DSN builder), no shell metacharacters (custom checks pass the password through a shell), no leading or trailing quote (the portal strips them) [Q §9.1]. The password never contains the account name (3 or more characters).
- **Admin**, typed at a console at T+0: five words, up to 32 characters.
- **Machine**, written by a plan into a config file and never typed: 24 to 32 characters from the conservative alphabet plus `# % ^`.

A password never contains `, " ' \ space @ : / $ ` ; & | < > ( ) ! * ~ { } [ ]`. All values live in the age vault (`cred/<host>/<account>`, versioned, 20 versions kept) and in memory once unlocked; never in the repo or logs; masked in the UI until revealed, and every reveal is audited. Unscored accounts also have **stateless break-glass** values: `DeriveBreakGlass(secret, host, user, epoch)` is HMAC-SHA256 keyed by a printed 160-bit secret over a length-prefixed encoding of epoch, host and user, expanded into the class's alphabet: a typeable passphrase for console-typed accounts and a 24-character string for machine accounts, each pinned by a known-answer test (the word-list hash is part of the vector). Print the secret and keep it off the controller; a lost controller can regenerate every unscored password. Raise the epoch after a restore. **Scored accounts are never derived**: they stay under PCR [WT §9.10].

*The T+0 console sheet.* Admin and service rotation is by hand at the consoles, ahead of enrollment (core, Enrollment). `phylax creds sheet` renders the sheet from the manifest and the break-glass secret, offline (the manifest is known from the packet in advance, review Invitational D1): every host's `sysadmin`, root and local Administrator, the domain admins and service accounts, the Palo `admin` and VyOS `vyos` accounts. No admin accounts are scored (decision 10), so they rotate freely. Scored users are not on the sheet. The new values are entered in the vault once the controller is up, so first contact can use them. Operators tick each step in the host x step grid (`creds.t0`). After the agents arrive, session eviction runs for every account rotated at T+0 (execution engine); plain eviction, since no admin account is scored.

*Rotation of unscored accounts after enrollment.* Service and app accounts (database rows, application admin accounts) rotate by plan. Each rotation updates the files that embed the credential in the same plan, then runs the scorer-mimic probe. After rotation any successful admin authentication from a source other than the controller is a D9 alert, because no legitimate actor has those credentials. Zerologon first: on the DC the plan reads the build, `FullSecureChannelProtection` and Netlogon events; if the secure channel is not enforced, enforce or patch it (or filter RPC to the DC) before any domain password rotation, because a vulnerable DC lets the attacker reset the machine account and dump the new hashes anyway. This is merged into the T+0 DC console step (the `hardening` module, `dc.zerologon_first`); the `Domain` flag on a record keeps the gate: a domain-account operation is refused until the `vantage` Zerologon check reports not vulnerable. The `krbtgt` double reset (the `ad` module's action) is offered after DCSync evidence; it kills forged tickets and every Kerberos ticket.

*The scored password change (PCR as a transaction).* A scored account is a record with its host password(s), the value Quotient holds per credlist, the last observed scorer login and a state. One transaction covers one account: one host change, one PCR row per credlist.

| State | Meaning | Next |
| --- | --- | --- |
| `stable` | Host and Quotient agree | `planned` |
| `planned` | Proposal accepted; new password generated; the typed list is shown | `host_changed` |
| `host_changed` | In the quiet window the host change ran on every host where the user exists, and the Kali verified the new credential; the PCR is due before the next enqueue | `pcr_submitted` |
| `pcr_submitted` | The human submitted the list in Quotient and reported its reply (`count` equals the rows, `skipped` empty) | `verified` |
| `verified` | A passing scorer login by that user on the credlist's service was observed | `stable` |
| `failed` | The next scorer login by that user failed | `rolled_back` or a fix-forward |
| `rolled_back` | Host reverted and the old value entered by PCR | `stable` |
| `reverted` | The host or AD was reverted behind Quotient's back | `stable` after re-sync |

The state names follow the engine as built; the earlier design names (`applying`, `pending`, `verifying`, `confirmed`) map to `host_changed`, `pcr_submitted`, `pcr_submitted` and `verified`.

The process, step by step (review A7.Q6):

1. **Proposal.** A transaction starts only from evidence of compromise or leak of a specific scored account, as a one-click `creds.proposal`: a pass-the-hash rule hit (NTLM 4624 type 3 or 9, or Kerberos anomalies, by a scored user from a non-scorer source; a `detect` content pack that takes the learned scorer accounts and the burst as context), a scored account in a DCSync or `ntds.dit` chain, a honeytoken or honey AD account that shows a dump, a plaintext credential found by a credential-file hunt, a webshell chain whose remediation item is `rotate_credential`, an interactive login by a scored user from a non-scorer source. Operators can add an account by hand. A proposal names the account, the credlists, the hosts and the evidence. Accepting records the approver's name (a verbal captain approval is entered as "approved by <name>"). Nothing is ever rotated automatically. The engine refuses a transaction when it would exceed `max_accounts_per_txn`, when more than `max_open_txns` are open, when the account already has a pending transaction (`CanRotate`), or when an unresolved `reverted` row exists on the host. These caps are what "never mass-rotate" means in code.
2. **Prepare, outside.** Phylax generates the typeable passphrase and shows the **PCR list** on the controller's screen: one block per credlist, one `username,password` line per row, row numbers, a total row count and the list name as Quotient shows it. The human types it into Quotient's PCR form on the machine outside the environment, without submitting, and ticks "staged" with their name. Reveal is audited. For a timing exercise the UI also generates a dummy list with made-up users and no host change.
3. **Commit, in the quiet window.** When the `scorer.clock` window holds at least `min_window` (30 s) and the clock confidence is at least 0.5, the controller releases the armed plan and counts down on screen. The host change runs first (`user.set_password` for local accounts on every host where the user exists, `ad.*` for domain accounts), then the PCR submit. The window is at least `Delay - Jitter` minus the burst length, about 50 s at the upstream defaults. Never during a burst or its enqueue pad; credentials are copied into tasks at enqueue, so a PCR landing then can give a mixed snapshot.
4. **Eviction.** Right after the host change, inside the same window, `session.terminate_predating` runs for the account. For a scored account it evicts only sessions that began before the rotation, outlived the measured round delay (`scorer.clock.eviction_cutoff`) and are not scorer-labelled; anything it cannot classify is flagged, never killed; while no round delay is measured the step is flag-only.
5. **Verify.** (a) The Kali logs in with the new credential through the public path, per credlist's service (`pcr.verify`, V4 on failure), in the seconds after the host change and before the human submits. A failed verification stops the transaction at `host_changed`: the human does not submit, the host reverts. (b) After the human submits and enters the portal reply (`count` equals the rows, `skipped` empty), the account waits for a passing scorer login by that user on the credlist's service. With `k` users on the list and one random draw per check, one specific user is seen after `k` rounds on average and all `k` after about `k` ln `k`; the UI shows both numbers. After `verify_notice` (15 min) with no pass the UI raises a notice; silence never rolls back.
6. **Failure handling.**
   - The host change fails: the plan rolls back, nothing is submitted, the transaction ends `rolled_back`, the human clears the staged form.
   - The Kali verification fails: as above.
   - The window is missed or the human is late: the host and Quotient disagree until the submit; each round draws that user at most once per check, so at most one failed round per affected user. The transaction is marked `late` or `race` and the first failed scorer login in the next burst is forgiven once (mixed snapshot).
   - The reply does not match (`count` differs from the rows): treated as possibly applied; a rollback then also enters the old value. `skipped` rows are failed with no PCR rollback.
   - A scored login fails after the submit: usually a typing error. The default is **fix forward**: the operator retypes that row (cheap, the host is already verified by the Kali). The alternative is **rollback**: revert the host and enter the old value by PCR in the next quiet window. Rollback never uses "Reset to Defaults", which rewrites every user in the list.
7. **Revert re-apply.** Quotient does not know about reverts. A host or AD revert is detected by: a re-enrollment of that host (`agent.reenrolled`, "Re-enroll all"; a reverted DC reverts every domain credential), a Kali verification or scorer login failing for a `verified` account while the previous password works, or an operator mark. Every rotated credential of that host becomes `reverted` per (account, credlist) and `creds.reverted` is emitted. The host's scored changes are blocked until each row is resolved: **re-apply** (preferred, no typing) sets the host password back to the vault's current value, the value Quotient already holds, through the same host-change plan inside a quiet window, then the Kali verifies; or **PCR back**, which leaves the host at the old value and produces a typed list with the old value for the human. Re-apply is a transaction of type `resync`: it records that Quotient already holds the value, which is what lets the lint allow a scored host change without a PCR.

*Policy against AD dumps.* Red dumps every AD hash; rotating before the dump is lost and rotating after it helps only for accounts known to be compromised. The policy (review A7.Q6, A7.Q7): prevent the dump (T+0 Zerologon, the DCSync rule), pass-the-hash detection (the `detect` content pack above), honey AD accounts (`honeytokens`), selective rotation on evidence, never mass-rotate, never restrict NTLM and never put scored users in Protected Users (the scoring-safety lint). The rotated scored passwords live in the existing age vault with no split-key or delete-after-use mechanism (review A7.Q8); there are few of them, which is why the breach exposure is accepted. Whether this is enough against a full dump is an open question (part 12).

*The PCR list rules* (v3 Appendix F, moved here). One block per credlist. Each line `username,password`, no leading or trailing spaces (the portal does not trim), a comma on every line (a line with no comma stores an empty password), case-exact usernames, no password that starts and ends with the same quote character (the portal strips them), passwords 20 to 25 characters from `[A-Za-z0-9._+=-]`. A duplicated username: the last line wins. The generator re-parses its own text with a copy of the portal's parser and refuses on a mismatch. The reply must show `count` equal to the line count and `skipped` empty. Roll back by a PCR with the old value, never "Reset to Defaults" [Q §5].

**7. Actions and content.**

| Action | Risk | Locks | Touches |
| --- | --- | --- | --- |
| `pcr.generate` | `none` (controller-side) | none | none |
| `pcr.verify` | `none` | none | a login by a scored user from the Kali |

The host change uses the core `user.set_password` and `ad.*` actions inside a transaction plan, risk class `lockout`, with the dead-man switch and the scoring guard's one permitted exception: a scored-account password change is allowed only when the node carries a transaction id. The plan templates `plans/creds/scored-change.yml` (host change, eviction, verify, manual gate for the human reply, scorer-login gate), `plans/creds/resync.yml` and `plans/creds/unscored-rotation.yml` are content.

**8. UI.**

- `/credentials`: the inventory (account, hosts, scored flag, credlists, last rotated, state per row; secrets masked), the open proposals, the PCR list screen (staged tick, countdown, window remaining, reply form), the transaction log, and the `reverted` queue with re-apply and PCR-back buttons.
- Host-grid column "creds handled": verified when the host's T+0 rotation is ticked and no row is `reverted` or open. T+0 ticks need an owner name.
- Overview tile: open transactions and reverted rows.

**9. Health.**

States: `ok`; `degraded` when the round clock is provisional (no transaction can start; gap: "no quiet window"), the vault is locked (gap: "vault locked, no rotation or verification"), or the Kali is down (no verification; transactions cannot start); `unavailable` when the vault cannot be read. Degraded means proposals still appear but cannot be committed.

**10. Scoring safety.**

This module can fail the most scored checks of any, so it is the most constrained:

- The lint rejects a scored-account password change on the host alone, and any plan touching a scored account without a transaction id. No lockout machinery on scored accounts; no `authorized_keys` edits for scored users; no NTLM restriction; no Protected Users; no required encryption the scorer cannot do.
- A change happens only inside a quiet window with confidence 0.5 or more and 30 s of room, after the Kali's pre-check, with the dead-man armed on the host change.
- At most one failed round per affected user; the engine forgives the first failed login after a flagged race.
- Eviction on scored accounts follows the measured-delay rule and flags what it cannot classify.
- Caps on accounts per transaction and open transactions prevent a mass rotation by mistake.
- Alert-only stage: in observe mode proposals appear and the typing exercise works; transactions are disabled. The battle-test tiers allow one deliberate change of one scored user in the second half of the Invitational (Tier C), and T+0 admin rotation plus eviction in Tier B (core, Operations).

**11. Tests.**

- Unit (built): `creds_test.go` (generator classes, uniqueness, alphabet, break-glass known answers, record validation, rotation order), `pcr_test.go` and `csv_test.go` (state machine, windows, CSV parser round trip, rollback, race forgiveness).
- New: the typeable class (length, complexity, safe set, determinism of the derived form); per-credlist rows; `reverted` and both resolutions; the caps; `late` and `race`; the armed plan released at a window; the transaction-id exception in the lint; secrets never in events or logs.
- Conformance: starts locked (health `degraded`, vault gap), stops cleanly, emits only declared kinds, respects its budget, survives link loss and reconfiguration (open transactions are in `pcr_txn`).
- Lab (v3 ids): T35 (PCR transaction: normal, PCR mid-enqueue, wrong order, mismatched CSV, password with edge characters: at most one failed round per affected user; verification via Kali and the scorer's next login; rollback never uses "Reset to Defaults"). New: a host revert and both resolutions against real Quotient with two credlists; a wrong typed row with fix-forward; the Invitational PCR measurements S13 and the typing exercise O8.

**12. Limits and open items.**

- `shortcut: typeable passphrases carry about 50 bits (four words from a 2,048-word list, two digits, one capital); enough against online guessing, weak against offline cracking of a dumped NT hash. Upgrade to five words if the A7.Q6 research shows dumped scored hashes are cracked.`
- `shortcut: the vault is one age file with no split-key; a controller breach exposes the few rotated scored passwords, accepted by review A7.Q8.`
- `shortcut: credlist rows are labelled by the operator from the learned groups; the real Quotient names are typed once into Settings, upgrade if a read path ever exists.`
- Open (review A7.Q6): the scored-password policy against a full AD dump. The process is kept; research on how Quotient-region teams handle it found no public writeup. Until decided, the rule is selective rotation on evidence plus prevention.
- Open: `max_accounts_per_txn` and `max_open_txns` are starting values; the typing exercise (O8) and the first real PCR (S13) set them.
- Open: how many rows the typed list must hold depends on the scored user count (S5, S14).
- Core change: a plan option that holds an approved plan until a `scorer.clock` window opens (`window: scorer_quiet`), and a `gate: manual` that records an operator's reply (the portal count and skipped) as step output.
- Core change: the scoring guard exception keyed by transaction id, and a lint hook that reads `creds.state`.
- Cross-section: the Credentials role carries the list to the Quotient machine outside the environment (Operations, Roles). `vantage` executes `pcr.verify`; `scorer` provides the window, the learned accounts and the eviction cutoff; `detect` ships the pass-the-hash rule pack; `honeytokens` ships the honey AD accounts.
