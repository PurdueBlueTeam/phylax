#### Two repositories

The `phylax` repository holds the product: the binary, its modules, the content they load, the manifest schema and reference manifests, the documentation and the signed-release fallback. The red team can read it (an adversary assumption in the trust model), so it holds nothing that helps them beyond what the source already shows.

The lab, Terraform, Packer and red-team material live in a separate private repo (`ccdc-lab`) and never in `phylax` (review D521). The reason is exposure, not any rule: campaign runbooks, the contaminator's implant sets (defanged but real), exploit and emulation notes, lab scorer configs and the replica topology would tell an attacker what we test against. The replica's VM definitions are built in `btap-infra` (branch `ccdc27-lab`). The team knowledge base (research, strategy, packets, evidence cards) is `ccdc-private`, a vault, not a code repo.

#### The tree

```text
phylax/                          # public product repo
  cmd/phylax/                    # the one binary: serve, agent, init, cache, rules, ledger, set-controller,
                                 #   modules, depot, tools, guard, say, claim
  internal/
    event/  module/              # envelope and typed events; the module contract and registry
    module/conformance/          # the shared conformance suite (run against every registered module in CI)
    agent/  agent/mods/          # agent mode: supervisor, factories, exec; one registration file per agent module
    link/  spool/  store/        # core: TLS pinning and framing; crash-safe spool; SQLite store and query API
    vault/  manifest/  plan/     # core: secrets; manifest types and schema; plan and config types
    actions/  deadman/           # core: the action framework and general families; dead-man journal
    controller/                  # core: host for controller modules; plan engine glue; agent config rendering
    ui/                          # core: UI shell, registrar, templates, vendored htmx
    svcinstall/  atomicfile/     # core helpers: service install; atomic writes
    parsers/                     # shared protocol parsers, one package each (incl. smb2, winrm, tds, ssh)
    # one package per module (agent side, controller side or both):
    audit/  winevt/  net/  logs/  inventory/
    # (internal/checks also holds the shared protocol clients: ntlm, smb, winrm, ssh, mssql, ldap, web)
    detect/  respond/  content_guard/
    integrity/  hunt/  hardening/  ad/
    firewall/  egress/  capture/  devices/  devices/palo/  devices/vyos/
    checks/  scorer/  vantage/  creds/
    traceback/  chains/  deps/  vuln/
    decoys/  honeytokens/
    report/  backup/  teamfeed/  notify/
    depot/  wazuh/  splunk/  suricata/
    e2e/                         # end-to-end tests (the relay test T47 lives here)
  manifest/
    schema/                      # JSON Schema, generated from the Go structs
    2027/                        # the reference manifest (topology, hosts, services, accounts, scorer, devices, ...)
    two-segment/                 # the multi-segment variant (relays)
    modules/                     # one reference <name>.yml per module block
  rules/<module>/                # detection rules per owning module (rules/detect/, rules/respond/, rules/chains/, ...),
                                 #   rules/lists.yml, rules/profiles.yml, rules/ported/ (hand-ported packs), rules/yara/ (the corpus,
                                 #   including the MIT-licensed UCF rules); rules/pending/ for rules waiting on a producer
  plans/<module>/                # plan templates per owning module (plans/hardening/ with the first-hour library, plans/backup/,
                                 #   plans/creds/, plans/hunt/, plans/ad/, ...)
  checks/                        # active check content: checks/checks/, checks/flows/ (Orange flows), checks/doctor/
  reports/                       # the report module's content: generators/, queries/, evidence/, lint.yml
  hunt/                          # hunt content: checks/, killlist.yml, heuristics.yml, baselines/
  ledger/                        # signed ledger indexes shipped in the release
  ad/                            # AD check definitions and default service descriptors
  backups/counts/                # record-count specifications per service kind
  pools/                         # decoy banners, honey filenames, fake-shell content
  depot/                         # recipes and tools.json: the trusted tool depot's index sources
  inject-kit/                    # the memo shell only (inject-kit/memo.md.tmpl); no policies, plans or drafts
  dist/                          # signed binaries, fallback delivery
  docs/                          # implementation notes (docs/*.md), the impl briefs and the review (docs/impl/)
  .github/workflows/             # CI: build, size, vet, race, privileged job, conformance, content tests
  Makefile  mise.toml  AGENTS.md go.mod go.sum
  THIRD_PARTY_RULES.md           # generated: hand-ported rules with upstream id, path, commit, author, licence

ccdc-lab/                        # private, never declared or published
  terraform/  packer/  netem/  proxy/
  reference/                     # baseline and ledger builders
  quotient/                      # lab scorer config, stand-in check scripts
  sim/orange/  sim/contaminator/  sim/faults/   # sim/orange runs the checks module's Orange flows from many sources
  redteam/                       # campaigns 01 to 09, results, the C2 fingerprinting corpus
```

#### What changed from v3

- **Module packages replace topic packages.** Each module is one package under `internal/`, named for the module. Today's `internal/collect/{audit,net,winevt}` become `internal/audit`, `internal/net` and `internal/winevt` in the retrofit; `internal/integrations` splits into `internal/wazuh`, `internal/splunk` and `internal/suricata`; the scorer's round clock, discovery, fingerprints, SLA and PCR code split between `scorer` and `creds`.
- **New core packages:** `internal/module` (the manifest, health and host interfaces) and `internal/module/conformance`.
- **Content directories per module.** Today's flat `rules/*.yml` and `plans/*.yaml` move under their owning module's directory (`rules/detect/`, `plans/hardening/`) as that module is retrofitted. A content file names its module and loads only when the module is enabled on the target.
- **`internal/cache` is gone.** The depot module holds the content-addressed cache and its sync client; `phylax cache` and `phylax depot` are its commands.
- **No Typst.** `inject-kit/` holds one memo shell; the policies, plans, risk register, framework templates and pre-written drafts are cut and live outside Phylax (decision 6). PDFs come from the pure-Go renderer in `internal/report`.
- **No `rules/imported/`.** The Sigma importer is cut; third-party logic is hand-ported into `rules/<module>/` with a `source:` record and listed in `THIRD_PARTY_RULES.md`.
- **No `phylax doctor`.** The `hello` capabilities block and the Platform page replace it; `phylax modules` lists the manifests.
- **`manifest/modules/`** replaces v3's catch-all `policy.yml`.
- **`reports/`** is new: the generators, saved queries, evidence recipes and lint data of the `report` module are content, not Go.
