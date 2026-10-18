# Milestone status

Local-equivalent gate results for the overnight run. Each milestone's gate
references lab tests (Txx); the local equivalent is what ran here, and
unverifiable items are listed in QUESTIONS.md (U-xx).

| Milestone | Status | Gate (local equivalent) | Notes |
| --- | --- | --- | --- |
| M0 Foundations | ✅ complete | manifest loads + validates + lints; firewall policy renders for the 2026 reference shape (golden tests); protocol spec written; CI skeleton committed; scorer simulator v0 writes ground truth | Proxmox/Terraform lab and PAN-OS license: N/A here (U-03/U-04); docker stand-in topology built in M1 |
| M1 Link and enrollment | ✅ complete | T18: TestControllerRestartNoLoss (restart on same port, 15/15 events, no loss/dupes); T21: TestAgentKilledDark (silence marked within threshold); T22: TestRelaySplice (relay splice, segment dark on relay death, local spooling, console restore on same address, no loss); T27 Linux leg: TestBootstrapDownload (pinned-TLS binary + config download, wrong pin aborts before token use) | Binary 16.9 MB raw / 9.7 MB gzip (target ≤40/≤15). TLS pinning + ALPN connection types (agent/relay/splice/patch/bootstrap). Go 1.27 gotcha: tls.NewListener defers the handshake (explicit HandshakeContext in Run). SSH/WinRM first contact: unverified here (U-xx) |
| M2 Execution | ✅ complete | Action catalog (files/accounts/services/kernel/persistence/proc/collect/hunt/agent.*) with check/apply/verify/rollback + risk classes + resource locks; signed plan steps (ed25519, agent-side verify); DAG execution with dry-run diff, live node states and SVG DAG in the UI; T17 local equivalent: dead-man fires on link drop mid-plan, plan blocks for the link, rollback restores the applied node's exact content on reconnect (no lost state, no lockout); T16 rollback half: one-click rollback verified E2E (the health-check-red half lands with M3 service monitoring); T22/T27: carried from M1, re-verified green | Rollback uses base64 wire snapshot (Step.Before []byte); safe mode refuses run steps, allows rollback (verified E2E); per-action resource locks in the agent |
| M3 Telemetry and detection | ⬜ | — | — |
| M4 Capture and checks | ⬜ | — | — |
| M5 Deception, C2 and reporting | ⬜ | — | — |
| M6 Dry runs and freeze | ⬜ | — | — |
