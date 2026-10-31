#### `vuln`

**1. Purpose and evidence.**

`vuln` is a version-driven vulnerability matcher. The `inventory` module collects installed software versions on every host (dpkg and rpm packages, Splunk, OpenCart, Roundcube, PAN-OS, VyOS, the Windows build, UBR and hotfixes, the SQL Server build). `vuln` matches them offline against the cached CISA Known Exploited Vulnerabilities (KEV) catalogue and against the vendor advisories held in the team vault, and reports each finding as vulnerable, fixed or unknown. The software changes every year; a matcher driven by versions does not go stale the way a hand-written list does. It also feeds the recurring "versions and CVEs" inject (the version and CVE table in `report`, review D492).

Evidence that it matters for points:

- The vault holds a KEV snapshot of 1,758 entries [[known-exploited-vulnerabilities#e1]].
- A "versions and CVEs" inject recurs [[2023-mw-regional-eval15a-response#e1]], [[eval05t]].
- PAN-OS KEV entries (CVE-2024-3400, CVE-2024-0012 and CVE-2024-9474, CVE-2026-0257) are reachable only from a version match [[known-exploited-vulnerabilities#e1]], [[vulns-network]]. This merges the Palo management check (review D524) into the matcher.
- The kernel local-root family (Copy Fail, [[cert-cc-vulnerability-note-vu-260001#e6]]) needs the running kernel version and whether the module is built in; the matcher reports the version, and the hardening mitigation is verified separately (Known bugs 1).
- Fixed builds for vendor apps are known: Splunk 10.0.10 [[security-hardening-in-splunk-enterprise#e3]].
- Peer evidence: none for or against. The module has no direct points evidence beyond the recurring inject and the KEV items red is known to use, so it starts **off** and is a cut candidate at the next review (principle 16).

**2. Status and code.**

Missing. No code. v3 text to carry over: none (new). Build:

- `internal/vuln` (an analyser and a small matcher library), content under `rules/vuln`.
- A product map from inventory names to KEV vendor and product names.
- A generated advisory table (`vuln/advisories.json` in the depot) built by `phylax cache build` from the vault advisories. No hand-maintained advisory file exists (review A5.Q2).

Scope of the first cut (review A5.Q2, N5.1): KEV plus the vendor advisories already in the vault (Splunk, PAN-OS, OpenCart; Roundcube once the 2027 webmail product is known). No distro OVAL feeds. Where a distro backports fixes the verdict is `unknown`.

**3. Capability manifest.**

| Field | Value |
| --- | --- |
| Name | `vuln` |
| Sides | controller (analyser) |
| OS | n/a |
| Privilege | `none` |
| Roles | `controller` |
| Default | opt-in |
| Budget | 30 CPU ms/s during a run, 32 MB held (the KEV index), 1 event/s, 40 KB out/min, 5 MB disk |
| Tables | `vuln_finding` |
| Content | `rules/vuln` (`products.yml`, `kernel.yml`) |
| Actions | none |
| Pages | `/vulns` |
| Evidence | part 1 |

Analyser `vuln.match`. Inputs: `inventory.snapshot` and `inventory.row` with `table: software` (installed software and changes), `devices.version` (PAN-OS `sw-version`, VyOS image), and `depot.sync_state` (the index version changed, so KEV or the advisories were updated). Runs on trigger and once an hour.

**4. Configuration.**

```yaml
# modules/vuln.yml  (the module is off unless hosts.yml or this file enables it)
sources:
  kev: depot            # the cached CISA KEV JSON; the index carries its date
  advisories: depot     # vuln/advisories.json, generated from vault cards
products: rules/vuln/products.yml
severity:
  vulnerable_kev: high        # a KEV-listed product with a version in the affected range
  vulnerable_ransomware: critical   # KEV says known ransomware campaign use
  unknown_kev: normal
scored_only: false      # true: report only hosts that run a scored service
```

```go
// package vuln
type Config struct {
	Kev, Advisories, Products string
	Severity                  map[string]string
	ScoredOnly                bool
}
```

**5. Events.**

Consumes: `inventory.snapshot` and `inventory.row` where `table` is `software` (rows: `name`, `version`, `arch`, `source` such as dpkg, rpm, product file, registry, build), `devices.version`, `depot.sync_state`.

Emits:

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `vuln.finding` | 1 | normal; high or critical by severity | `host`, `product`, `version`, `cves[]`, `kev` (true), `date_added`, `ransomware_use`, `verdict` (`vulnerable`, `fixed`, `unknown`), `fixed_in`, `source` (`kev`, `advisory:<vault card id>`), `reason` (for `unknown`), `scored` (the host runs a scored service) |
| `vuln.summary` | 1 | bulk | counts per verdict and host; the table `report` renders |

**6. Behaviour.**

*Inputs.* The agent side is `inventory`: its `software` table emits a baseline `inventory.snapshot` per epoch and then `inventory.row` events (added, removed, changed) persisted on the host. `vuln` reads those and the device versions that `devices` reports. The depot (`depot`) carries two data files, both built at cache-build time and delivered offline: the CISA KEV JSON, and `vuln/advisories.json`, generated from the vault's vendor advisory cards (Splunk, PAN-OS, OpenCart, later Roundcube) with fields product, affected range, fixed-in version, CVE ids and the source card id. The matcher never fetches anything live (principle 12).

*Matching.*

1. Map each inventory row to a product key with the content table `rules/vuln/products.yml` (for example the dpkg package `openssh-server`, the RPM `httpd`, Splunk Enterprise, PAN-OS, VyOS, OpenCart, Roundcube, Windows build and UBR). A row with no mapping is ignored and counted in health.
2. KEV carries vendor and product names but **no version ranges**. A KEV entry therefore says "this product has known-exploited CVEs", not "this version is affected". Ranges come from the vendor advisories in the vault. The verdict follows:
   - **`vulnerable`**: the product has a matching advisory whose affected range contains the installed version, and a KEV entry (or an advisory CVE marked exploited). Reported with the CVE ids, the advisory source and `fixed_in`.
   - **`fixed`**: an advisory exists and the installed version is at or above `fixed_in`.
   - **`unknown`**: the product has KEV entries but no advisory range for this version, or the package comes from a distro that backports fixes (the version string cannot be judged: dpkg and rpm versions on Ubuntu, Debian and Rocky), or the Windows build has no KB mapping. `reason` says which. These are shown, not hidden, because "KEV lists this product" is itself the lead.
   - Not reported: a product with no KEV or advisory entry.
3. The PAN-OS `sw-version` is matched against the PAN-OS advisory ranges (CVE-2024-3400, CVE-2024-0012 and CVE-2024-9474, CVE-2026-0257). The same applies to the VyOS image and Splunk. The Palo management lockdown (`hardening`, `palo.mgmt_lockdown`) still audits interface management profiles and GlobalProtect; the version match is this module's job.
4. Each finding is stored in `vuln_finding` with the vault citation that supplied the range (the source card id) so the inject answer can cite it.

*Feeds.* `report` renders the software-version and CVE table (D492) from `vuln.summary` and `vuln.finding`. The UI shows findings per host with `scored` hosts first. `hardening` plans may use a finding as the reason for a mitigation (a Splunk fixed build, `pkg.upgrade` from the depot); the first cut does not propose upgrades, because a package change on a scored host is a scoring risk and belongs to the operator's choice.

**7. Actions and content.**

No actions. Content: `rules/vuln/products.yml` (inventory product to KEV vendor and product, with an optional version-comparison scheme: `semver`, `dpkg`, `rpm`, `splunk`, `panos`, `windows_build`), `rules/vuln/kernel.yml` (kernel version bands for the local-root family; reports the version only). Both have inline tests (a fixture row and the expected verdict).

**8. UI.**

`/vulns`: a table of findings per host (verdict, product, installed version, CVEs, fixed in, source card), scored hosts first, filters for `vulnerable` and `unknown`, and an export to the `report` generator. Overview tile: count of `vulnerable` findings on scored hosts. No host-grid column.

**9. Health.**

States: `disabled` (default); `ok`; `degraded` when KEV or the advisory table is missing or older than the depot index says (gap: "no KEV snapshot in the depot"), when `inventory` has not reported software for a host (gap: "no software inventory from <host>"), or when many rows have no product mapping (the count is shown). `unavailable` when `inventory` is not enabled. Degraded means findings are a lower bound.

**10. Scoring safety.**

Read-only analysis over events and cached data. It never touches a host or the scored path and has no alert-only stage to speak of. The risk is wrong advice: an `unknown` is never turned into `fixed`, and a distro package version is never judged from the upstream version alone.

**11. Tests.**

- Unit: version comparison per scheme (semver, dpkg, rpm, Splunk, PAN-OS, Windows build); the verdict table (vulnerable, fixed, unknown for backports, no mapping ignored); KEV parsing against a pinned snapshot excerpt; the product map; kernel bands.
- Fixture: a store with `inventory.snapshot` rows for the 2027 reference hosts and a KEV and advisory fixture produces the expected `vuln.finding` set, identical twice from the same store and `now`.
- Conformance (analyser rules): identical output, switchable alone, within budget with the full KEV index loaded.
- Lab: install a known-vulnerable Splunk and an old OpenCart on the lab hosts; the findings appear with the right CVEs and `fixed_in`; a patched build reports `fixed`; a distro package with a backport reports `unknown`.

**12. Limits and open items.**

- `shortcut: distro backports are not judged (no OVAL or security-tracker feed), so distro packages report unknown; upgrade only if the inject asks for distro-level CVE lists or a lab run shows too many unknowns to be useful.`
- `shortcut: KEV has no version ranges, so only products with a vault advisory can be judged vulnerable or fixed; add advisories to the vault, never a hand-edited file here.`
- `shortcut: Windows findings stop at the build and UBR; no KB-to-CVE mapping in the first cut.`
- Open: the vault advisory card needs a structured block (product, affected range, fixed-in, CVE ids) that `phylax cache build` can extract. Undecided: whether it is frontmatter in the card or a fenced block in the evidence item. The `depot` section decides the build step.
- Open: `devices.version` is taken from the `devices` section's event list; confirm its fields (product, version) cover PAN-OS and VyOS.
- Open: whether upgrade proposals (`pkg.upgrade` from the depot) are worth adding after a lab run; the first cut has none.
- Cross-section: `inventory` collects the versions (review D81, N5.1); `devices` reports the PAN-OS and VyOS versions; `depot` carries the KEV feed and the generated advisory table (review D442-D445); `report` renders the table (D492); `hardening` keeps the Palo management audit and the kernel mitigation (Known bugs 1).
