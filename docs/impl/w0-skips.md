# W0 skip inventory

Every `t.Skip`, `t.Skipf` and `t.SkipNow` call in the test sources, so the
lab gate (plan Task 5) knows what is not exercised by an ordinary run. No
test was changed to build this list.

Total: **66** skip calls in 31 files, at `HEAD` `318cdc3`, generated with

```sh
grep -rnE 't\.Skip(f|Now)?\(' --include='*_test.go' . | sed -E 's/^\.\///'
```

`test` is the nearest enclosing `func Test...`; where the skip sits in a helper,
the tests that call the helper are named. `guard` is copied from the skip
message (an empty message is spelled out). `needs` is one of `root`, `docker`,
`nft`, `systemd`, `kernel`, `network`, `tool`, `windows`, `other`: `other` is
a Linux-only test, a repository fixture or an external service, as the guard
says.

## root (privileged) (8)

| file:line | test | guard | needs |
|---|---|---|---|
| internal/actions/systemd_linux_test.go:229 | TestSystemdRealReadOnly | "set PHYLAX_PRIVILEGED_TESTS=1 to query the real system bus (read-only)" | root |
| internal/atomicfile/meta_linux_test.go:54 | TestSELinuxLabelPreserved | "security.selinux not settable here (no SELinux or not root): %v", err | root |
| internal/collect/audit/rawnl_test.go:17 | TestRawNetlinkInterruptAndClose | "cannot open a NETLINK_AUDIT socket here: %v", err | root |
| internal/deadman/backstop_test.go:154 | TestSystemdReal, TestSchtasksReal (via privileged) | "set PHYLAX_PRIVILEGED_TESTS=1 to run tests that create real systemd units / scheduled tasks" | root |
| internal/deadman/backstop_test.go:164 | TestSystemdReal | "needs systemd-run and root" | root |
| internal/decoys/sandbox/sandbox_test.go:157 | TestChildDropsRoot | "needs root to prove the credential drop (the agent runs as root; this machine's tests do not)" | root |
| internal/honeytokens/honeytokens_test.go:370 | TestFanotifyRealRead | "fanotify unavailable (needs Linux and root): %v", err | root |
| internal/honeytokens/honeytokens_test.go:378 | TestFanotifyRealRead | "fanotify mark failed (filesystem or capability): %v", err | root |

## docker (15)

| file:line | test | guard | needs |
|---|---|---|---|
| internal/capture/source_linux_test.go:26 | TestAFPacketTPACKETV3OnContainerLoopback (via requireDocker) | "real AF_PACKET capture test: set PHYLAX_CAPTURE_DOCKER=1 and run inside a container with NET_RAW (see docs/capture.md)" | docker |
| internal/capture/source_linux_test.go:29 | TestAFPacketTPACKETV3OnContainerLoopback (via requireDocker) | "PHYLAX_CAPTURE_DOCKER=1 but /.dockerenv is absent: refusing to open AF_PACKET on a host's real interfaces" | docker |
| internal/collect/audit/docker_test.go:40 | TestDockerKernelExec | "outer driver; the inner test is TestInContainerKernelExec" | docker |
| internal/collect/audit/docker_test.go:43 | TestDockerKernelExec | "real-kernel audit test skipped: set %s=1 to run it inside a Docker container with --cap-add=AUDIT_CONTROL,AUDIT_READ", envDocker | docker |
| internal/collect/audit/docker_test.go:46 | TestDockerKernelExec | "docker not found in PATH" | docker |
| internal/collect/audit/docker_test.go:67 | TestDockerKernelExec | "kernel audit not usable from the container: %s", skipReason(string(out)) | docker |
| internal/collect/audit/docker_test.go:85 | TestInContainerKernelExec | "runs only inside the container started by TestDockerKernelExec" | docker |
| internal/collect/audit/docker_test.go:122 | TestInContainerKernelExec | "audit netlink refused in container (needs the initial network namespace and CAP_AUDIT_*): %v", err | docker |
| internal/collect/audit/docker_test.go:134 | TestInContainerKernelExec | "audit rules could not be installed from the container (kernel refused or audit locked)" | docker |
| internal/collect/net/docker_linux_test.go:30 | TestDockerNFLog | "set PHYLAX_NET_DOCKER=1 to run the Docker NFLOG test" | docker |
| internal/collect/net/docker_linux_test.go:33 | TestDockerNFLog | "docker not found" | docker |
| internal/collect/net/docker_linux_test.go:71 | TestInContainerEgress | "only runs inside the Docker harness (TestDockerNFLog)" | docker |
| internal/firewall/kernel_linux_test.go:32 | TestKernelInDocker | "inside the container" | docker |
| internal/firewall/kernel_linux_test.go:35 | TestKernelInDocker | "real-kernel nftables tests skipped: set PHYLAX_FW_DOCKER=1 to run them in a network-namespace container (docker, --cap-add=NET_ADMIN, no host network)" | docker |
| internal/firewall/kernel_linux_test.go:38 | TestKernelInDocker | "docker not found; cannot run real-kernel nftables tests" | docker |

## nftables (7)

| file:line | test | guard | needs |
|---|---|---|---|
| internal/firewall/kernel_linux_test.go:71 | TestKernel_* (via inContainer) | "real-kernel test: run via TestKernelInDocker (PHYLAX_FW_DOCKER=1)" | nft |
| internal/firewall/kernel_linux_test.go:74 | TestKernel_* (via inContainer) | "refusing to touch nftables outside a container" | nft |
| internal/firewall/kernel_linux_test.go:84 | TestKernel_* (via newMgr/resetKernel) | "nftables not usable in this container: %v", err | nft |
| internal/firewall/kernel_linux_test.go:151 | TestKernel_ApplyVerifyIdempotentAndForeign | "nftables unusable: %v", err | nft |
| internal/manifest/render/domain_test.go:300 | TestDomainNFTValid | "SKIPPED: nft -c cannot run here (%s)", chk.reason | nft |
| internal/manifest/render/nft_test.go:49 | TestNFTablesValidWithNft | "SKIPPED: nft -c cannot run here (%s). Golden tests still ran; CI must provide privileges.", chk.reason | nft |
| internal/manifest/render/render_test.go:342 | TestNFTCheckerRejectsBadRuleset | "SKIPPED: nft -c cannot run here (%s)", chk.reason | nft |

## systemd / D-Bus (5)

| file:line | test | guard | needs |
|---|---|---|---|
| internal/actions/systemd_linux_test.go:137 | TestSystemdBackendOverPrivateBus (via startPrivateBus) | "dbus-daemon not installed; cannot run the D-Bus backend test" | systemd |
| internal/actions/systemd_linux_test.go:151 | TestSystemdBackendOverPrivateBus (via startPrivateBus) | "cannot start private dbus-daemon: %v", err | systemd |
| internal/actions/systemd_linux_test.go:156 | TestSystemdBackendOverPrivateBus (via startPrivateBus) | "no bus address: %v", err | systemd |
| internal/actions/systemd_linux_test.go:165 | TestSystemdBackendOverPrivateBus | "connect private bus: %v", err | systemd |
| internal/actions/systemd_linux_test.go:234 | TestSystemdRealReadOnly | "system bus unavailable: %v", err | systemd |

## kernel feature or filesystem (5)

| file:line | test | guard | needs |
|---|---|---|---|
| internal/actions/linux_sys_test.go:353 | TestFileAttrRealIoctl | "filesystem under %s does not support inode flags: %v", dir, err | kernel |
| internal/actions/linux_sys_test.go:356 | TestFileAttrRealIoctl | "cannot set inode flags here: %v", err | kernel |
| internal/atomicfile/meta_linux_test.go:17 | TestLabelCopyPath (via trySetXattr) | "xattr %s not supported here: %v", name, err | kernel |
| internal/depot/gotools/proc_linux_test.go:75 | TestSSFindsOwnListener | "sock_diag unavailable:", err | kernel |
| internal/integrity/yara_linux_test.go:20 | TestScanProcessMemory | "cannot read own /proc/self/mem: %v", err | kernel |

## network capability (4)

| file:line | test | guard | needs |
|---|---|---|---|
| internal/actions/app_misc_test.go:288 | TestNetTCPProbe | "no loopback: %v", err | network |
| internal/checks/web_dns_test.go:280 | TestPing | "no ICMP socket available here: %s", r.Err | network |
| internal/controller/report_test.go:427 | TestUIChecksFeedScorer | "no loopback listener: ", err | network |
| internal/depot/gotools/proc_linux_test.go:70 | TestSSFindsOwnListener | "cannot listen:", err | network |

## an installed tool (5)

| file:line | test | guard | needs |
|---|---|---|---|
| internal/actions/crypt_test.go:29 | TestSHA512CryptMatchesOpenSSL | "openssl not installed; known-answer vectors still cover the algorithm" | tool |
| internal/actions/crypt_test.go:36 | TestSHA512CryptMatchesOpenSSL | "openssl passwd -6 unsupported: %v", err | tool |
| internal/integrity/checker_test.go:94 | TestExecModifiedBinaryDetected, TestHandleProcessStartUsesRunningImage, TestPinReplacedInPlaceAndDeletedImage, TestPinStaleAfterLegitUpdateIsInformational (via sleepBin) | "no sleep binary" | tool |
| internal/integrity/checker_test.go:201 | TestPinReplacedInPlaceAndDeletedImage | "no true" | tool |
| internal/integrity/checker_test.go:248 | TestPinStaleAfterLegitUpdateIsInformational | (no message: skips when the `true` binary is missing) | tool |

## windows (2)

| file:line | test | guard | needs |
|---|---|---|---|
| internal/deadman/backstop_test.go:201 | TestSchtasksReal | "windows only" | windows |
| internal/svcinstall/windows_test.go:13 | TestWindowsInstallUninstall | "registers a real Windows service; set PHYLAX_PRIVILEGED_TESTS=1 (as Administrator) to run" | windows |

## other (Linux-only, repo fixture, external service) (15)

| file:line | test | guard | needs |
|---|---|---|---|
| cmd/phylax/depot_test.go:42 | TestDepotKeygenPackDeployVerifyRun | "linux only" | other |
| internal/actions/dev_actions_test.go:187 | TestPaloApplyPolicyAndSnapshot, TestVyOSSnapshotAndApply (via loadManifest) | "reference manifest not loadable: %v", err | other |
| internal/actions/dev_actions_test.go:197 | TestPaloApplyPolicyAndSnapshot | "palo intent: %v", err | other |
| internal/actions/dev_actions_test.go:294 | TestVyOSSnapshotAndApply | "vyos intent: %v", err | other |
| internal/actions/mssql_test.go:470 | TestMSSQLRealServer | "PHYLAX_MSSQL_DSN not set (user:password@host:port of a disposable SQL Server)" | other |
| internal/actions/mssql_test.go:480 | TestMSSQLRealServer | "host %q is not loopback; the actions only connect locally", host | other |
| internal/agent/mods/deception_test.go:110 | TestSandboxedDecoysFromSignedConfig | "the sandboxed child is Linux only" | other |
| internal/atomicfile/atomicfile_test.go:83 | TestSymlinkTargetReplaced | "symlinks unsupported:", err | other |
| internal/capture/lab_test.go:29 | TestLabQuotientSvcParsers, TestLabQuotientWeb, TestLabQuotientDB (via labDir) | "lab Quotient pcaps not present in %s (set PHYLAX_QLAB): %v", d, err | other |
| internal/controller/execkeys_test.go:21 | TestPlanKeyPersistedWithRestrictivePermissions | "POSIX permission bits" | other |
| internal/deadman/backstop_test.go:161 | TestSystemdReal | "linux only" | other |
| internal/decoys/sandbox/sandbox_test.go:131 | TestChildHasNoNewPrivsAndStopsWithParent | "no_new_privs is Linux only" | other |
| internal/depot/depot_test.go:69 | TestManifestSignVerifyTamper, TestDeployPermsAndVerify, TestRunVerifiedAndCleanEnv, TestRunRefusesTampered, TestRunExecsVerifiedBytesNotDisk (via newKit) | "fixture deploy tests run on linux" | other |
| internal/honeytokens/akia_rule_test.go:17 | TestDerivedEventMatchesRuleD15g | "rules/deception.yml not present: " + err.Error() | other |
| internal/manifest/render/domain_test.go:225 | TestDomainCrossesVyOS | "no VyOS guarding kali_leg in this layout: %v", err | other |
