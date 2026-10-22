# Credentials and the vault

Packages: `internal/vault` (encrypted store), `internal/creds` (generation, break-glass, records, ordering). Design: phylax_design.md, "Credentials" and "Secrets".

## Vault

- One `age` file, scrypt passphrase recipient (work factor 18 by default), mode 0600, written atomically (`internal/atomicfile`). Plaintext is JSON: `entries[name] = {current, seq, versions[]}`. age authenticates the header and every chunk, so any modification is `ErrCorrupt` (header edits can surface as `ErrWrongPassphrase`, because the recipient stanza no longer unwraps).
- Entries are versioned. `Put` appends `vN` (ids are never reused), `Rollback` re-points `current`, history is capped (20, the current version is never pruned). A failed disk write leaves memory unchanged.
- `Create` / `Open` + `Unlock(passphrase)` / `Lock()`. Locked = no decrypted bytes, passphrase and values zeroed (best effort; Go's GC can copy, and `Secret.Reveal` returns an immutable string).
- `ExportBackup(w)` encrypts the whole vault, history included, to the current passphrase, or to given age recipients (an X25519 key kept off the controller). `RestoreBackup` rebuilds a vault from an X25519 backup under a new passphrase. Restore starts a new epoch (see break-glass).
- `vault.Secret` is the only type that carries values outside the vault. `%v %+v %#v %s %q %x`, JSON, text and slog all print `[REDACTED]`; it refuses `UnmarshalJSON`. `RedactString` masks known secret values in free text such as error messages.

## Generation policy

| Class | Used for | Length | Alphabet |
| --- | --- | --- | --- |
| `Scored` | accounts in a PCR credlist | 16-24 | `A-Za-z0-9._+=-` |
| `Unscored` | service, app, local accounts | 24-32 | above plus `# % ^` |
| `Admin` | device and domain admins | 32-40 | same as Unscored |

Every password has an upper, a lower, a digit and a symbol, and starts and ends alphanumeric (no leading `-`, no trailing `.`). Never present: `, " ' \ space @ : / $ ` ; & | < > ( ) ! * ~ { } [ ]`. A password never contains the account name (3+ chars). `Generator` guarantees uniqueness, case-insensitively, across everything it generated or was `Reserve`d (SHA-256 digests only). `PCRSafe(user, pw)` re-checks the Appendix F CSV rules for any pair.

## Stateless break-glass

`DeriveBreakGlass(secret, host, user, epoch)` is HMAC-SHA256 keyed by a printed 160-bit secret (`NewBreakGlassSecret`, base32 in groups of five) over a length-prefixed encoding of epoch, lower-cased host and lower-cased user, expanded and rejection-sampled into the conservative alphabet, 24 characters. Print the secret, keep it off the controller; a lost controller can regenerate every unscored password. Bump the epoch after a restore so an old sheet does not match. Scored accounts are never derived: they stay under PCR. The derivation is pinned by a known-answer test; changing it breaks printed sheets.

## Records and rotation order

`Record` = account (case-exact), host or device, role, domain flag, scored flag, PCR credlist path, current and previous vault version ids, last rotated, PCR state and reference. It holds no secret; the value is in the vault under `cred/<host>/<account>`.

`PlanRotation` orders: (0) Zerologon mitigation step per DC, (1) device admins, (2) local and domain admins, (3) unscored service accounts, (4) scored accounts, `MethodPCR` only. Domain accounts carry `After: [DCs]`. Unscored `sysadmin` is held until the PCR list has been checked. Order within a stage is by host then account, independent of input order.
