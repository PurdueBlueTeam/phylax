# Windows tools

Windows gets only our own Go-native tools (`phylax tools` equivalents compiled
into `phylax.exe`, no extra files) plus Sysinternals.

Sysinternals (`procmon64.exe`, `autoruns64.exe`, `tcpview64.exe`, `handle64.exe`,
`listdlls64.exe`, `sigcheck64.exe`, `sysmon64.exe`, `pslist64.exe`) must not be
redistributed (Microsoft licence). They are `fetch_at_init` entries in
`../tools.json`: the manifest holds the pinned sha256 and the download URL
(`https://live.sysinternals.com/<name>.exe`, or the signed zip from
`https://download.sysinternals.com/files/SysinternalsSuite.zip`). `phylax init`
(or `phylax depot fetch`) downloads them on the controller, verifies the pinned
hash, and stores them in the cache. The same pattern as Sysmon.

Pinning procedure (once, on a machine with internet, before the event):
1. Download each tool, run `sigcheck64 -a` and confirm the Microsoft signature.
2. `sha256sum` it and put the hash and size in `tools.json`.
3. Re-sign with `phylax depot pack`. Microsoft updates these files in place, so a
   fetch that no longer matches the pin fails closed; refresh the pin deliberately.
