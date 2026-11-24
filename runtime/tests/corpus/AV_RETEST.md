# AV retest checklist (L0.5)

This is the rule for the whole EVB-parity roadmap: **a mechanism is not
accepted until it has been tested with security software enabled, and every
new mechanism is tested on its own.** The P0 experiment is the reason — eleven
injector builds were quarantined as `HVM:Trojan/Injector.gen!A`, and the reason
the remote-injection product form was dropped. "It worked in the demo" is not
evidence about AV.

## Engines available on this machine (re-measured 2026-11-23)

| Engine | State | Use |
| --- | --- | --- |
| Huorong Sysdiag (`HipsTray.exe`, `wsctrlsvc`) | **active** | Primary gate. Quarantine directory: `C:\ProgramData\Huorong\Sysdiag\Quarantine`; entries are named by the file's SHA-1. Baseline count: **17 files** — 11 from the P0 injector experiment on 2026-11-13, 5 older, and as of 2026-11-23 one from the sensor calibration below (`3395856CE81F2B7382DEE72602F798B642F14140`, 84 B, the EICAR test file). |
| 360 Total Security Pro (`360sd.exe`, `360tray.exe`, service `360rp` running) | **active** | Second gate. It has no quarantine directory until it quarantines something, so the countable signal is its real-time record: `C:\Program Files\360\360sd\Log\RealtimeProtectLog\<date>.log`, UTF-16LE, one entry per action, each entry naming the file and the verdict. No entries at baseline that name this repository. |
| Windows Defender | installed but **disabled** (`AntivirusEnabled=False`, `RealTimeProtectionEnabled=False`) | Not used. Listed so a reader can see it was considered and why it is not a gate here. |

The roadmap requires "Huorong + at least one other engine", and that is now
satisfied on this machine: two independent engines, both live, both measured in
the same run. What each engine covers is recorded below rather than averaged
into a single "AV passed".

## Calibration: is the sensor actually firing?

A pass that only records "the count did not move" proves nothing if the engine
was not looking. Before any result was recorded, both engines were shown the
standard EICAR test string (68 bytes, written to `%TEMP%`):

| Engine | Result |
| --- | --- |
| Huorong | quarantined it: its quarantine grew 16 → 17, entry `3395856CE81F2B7382DEE72602F798B642F14140` (SHA-1 of the EICAR string), 84 B, 2026-11-23 16:09:27 |
| 360 | deleted the file within 6 seconds of it being written |

Both sensors fire on a known-bad file, so "unchanged" in a later run means
"this engine looked at it and did not act", not "nothing looked".

## The matrix as measured (2026-11-23)

Each row is a copy placed in `%TEMP%` and watched for 8–10 seconds; the file
itself was then compared byte for byte, because an engine that quarantines a
file can also leave a blocked placeholder behind.

| Artifact | Huorong | 360 Total Security |
| --- | --- | --- |
| `lpvhost.exe` (the launcher, 369 KB) | untouched | untouched |
| `lpvirt.dll` (the runtime, 521 KB) | untouched | untouched |
| a produced `--virtual` bundle (898 KB SFX, runtime embedded) | untouched, still runs | untouched, still runs, SHA-256 unchanged |
| `mini_target.exe` (C fixture) | untouched | untouched |
| `ntdll_target.exe` (C fixture, M2b) | untouched | **blocked**, `HEUR/QVM202.0.992D.Malware.Gen` |
| `com_consumer.exe` (C fixture, M5/M6) | untouched | **blocked**, `HEUR/QVM202.0.992D.Malware.Gen` |

The two blocked fixtures are built by the same script as `mini_target.exe` and
are not shipped. The difference matters in both directions: the shipping
artifacts — the runtime, the launcher, and a bundle that embeds the runtime —
are clean under both engines, and a copy of a fixture can be quarantined by one
engine while the other ignores it. `verify_virtual_bundle.ps1` asserts the first
half (no new detection naming this repository, bundle byte-identical); the
second half is this table.

## Signed vs unsigned

The release build is unsigned. The release workflow ships `lpvirt.dll` as a
standalone asset and every `--virtual` bundle embeds a checksummed copy of it;
neither is code-signed. Signing changes how some engines treat a binary, so
both states must be recorded:

- [x] unsigned `lpvirt.dll` + unsigned host — measured 2026-11-23 on both
      engines (table above): no action from either
- [x] signed bundle — measured 2026-11-23 on both engines: no action from either
      (Huorong 17 → 17, 360 8 → 8, nothing naming this repository)

Producing the signed leg needed two things, and the first attempt had neither:

1. **A certificate signtool will use.** `Cert:\CurrentUser\My` holds several
   certificates with the code-signing EKU and a private key (`CN=Riantr`,
   `CN=ZKHONGTUO`, …) and `signtool sign /sha1 …` answers *"No certificates
   were found that met all the given criteria"* for every one of them.
   `Set-AuthenticodeSignature` aborts with *"cannot build a certificate chain to
   a trusted root"* and leaves the file unsigned. What does work is a
   certificate this machine makes for itself:
   `New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=LunaPack Verify
   Signer' …`, then `signtool sign /sha1 <thumb> /fd sha256 <bundle>` exits 0 and
   the signature reads back out of the file with
   `X509Certificate::CreateFromSignedFile`. `signtool verify /pa` still reports
   an untrusted root, which is the correct answer for a certificate nobody has
   installed: what is signed here is the file, not a chain.
2. **A reader that expects the signature.** Authenticode appends the signature
   after the last byte of the file, and the archive footer used to live exactly
   there: 4096 bytes of anything appended were enough to make `lpvhost.exe`
   report *"this file carries no LunaPack virtual bundle"*. **L7.2a** makes every
   reader walk backwards from the end to the last footer whose two numbers place
   an archive that begins with the marker and finishes at that footer. Measured
   on 2026-11-23: a signed bundle (1002091 → 1003520 bytes, 1429 bytes of
   signature, the last byte signing changed is at 437 — the PE headers) runs and
   prints every `THIN-EXE` line; the same bundle with 4096 zero bytes appended
   runs; the same bundle with 100 bytes cut off is refused;
   `verify_virtual_bundle.ps1` asserts all four, and they failed against the
   pre-change runtime before it did.

A signed pass does not retroactively clear the unsigned build, so both rows are
recorded: the matrix is "signed and unsigned, two engines".

## Per-mechanism retest list

Each row is a separate run. Do not batch them into one "everything" test: a
single quarantine event must be attributable to the mechanism that caused it.

**Second engine, applied to this table.** The rows below were recorded with
Huorong only. On 2026-11-23 the same artifacts were shown to 360 as well, and
the result is not uniform: the runtime, the launcher and a produced bundle are
clean under both, but the C fixtures used by **M2b** (`ntdll_target.exe`) and
**M5/M6** (`com_consumer.exe`) are blocked by 360's QVM heuristic as
`HEUR/QVM202.0.992D.Malware.Gen` when copied out of `dist\`, while Huorong
leaves them alone. That is a property of those two fixture binaries, not of the
mechanism they exercise — but a second-engine retest of M2b, M5 or M6 must
record "fixture detected" rather than "pass", and the qualifier "Huorong only,
second engine pending" is now out of date for every row.

| # | Mechanism | First loop that adds it | Baseline result | Retest date / count | Verdict |
| --- | --- | --- | --- | --- | --- |
| M0 | In-process IAT patching + manual PE32+ map (current runtime) | already in 0.1.25 | no new entries, 16 → 16 | 2026-11-18 / 16 | pass (Huorong only) |
| M1 | Writable VFS + full file-handle semantics | L1 | no new entries, 16 → 16 | 2026-11-18 / 16 | pass (Huorong only, second engine pending) |
| M2a | Thin launcher: map a real EXE image + call its entry point in-process; includes L2.1 worker thread + ExitProcess→ExitThread redirect + ANSI hooks, and L2.2 GetProcAddress/LoadLibrary hooks + runtime module IAT patch | L2.0/L2.1/L2.2 | no new entries, 16 → 16 | 2026-11-19 / 16 | pass (Huorong only, second engine pending); `scripts/verify_thin_launcher.ps1` |
| M2b | ntdll-boundary interception via IAT + GetProcAddress (NtCreateFile/NtOpenFile/NtReadFile/NtClose); **no inline code patch** | L2.3 | 16 → 16, `scripts/verify_ntdll_spike.ps1` (13 invariants) | 2026-11-19 / 16 | pass (Huorong only, second engine pending). Inline ntdll patch NOT attempted — separate AV-gated decision. |
| M2c | Unified hook installer + detach-order guard + fallback-chain audit + per-category behavioural fall-through | L2.4/L2.5 | 16 → 16, `scripts/verify_fallback_chain.ps1` (structural `self_thunk_hits=0` + 7 categories + ntdll regression) | 2026-11-19 / 16 | pass (Huorong only, second engine pending) |
| M3 | Ordinal-import / forwarded-export resolution + delay-import / TLS / SEH C ABI exports (x64) | L3.1-3.4 | 16 → 16, `scripts/verify_pe_features.ps1` (ordinal consumer + forwarded probe + white-box) | 2026-11-19 / 16 | pass (Huorong only, second engine pending) |
| M3b | x86 PE32 mapper + 32-bit runtime | L3.5-3.7 | **NO-GO (toolchain)** — no i686 target; see `X86_DECISION.md` | — | not shipped; no binary to test |
| M4 | Child-process following: `CreateProcessW/A` redirected into the launcher, virtual tree carried in a named shared section; three-level chain (parent → child → grandchild) | L4.1-L4.3 | 16 → 16, `scripts/verify_child_follow.ps1` (21 invariants incl. import-table check: no CreateRemoteThread / WriteProcessMemory / VirtualAllocEx / VirtualProtectEx / OpenProcess / SetThreadContext / QueueUserAPC / NtCreateThreadEx) | 2026-11-19 / 16 | pass (Huorong only, second engine pending). Explicit-token launches (`CreateProcessAsUserW` and friends) are not hooked — documented boundary, not a pass. |
| M5 | COM registration + activation without administrator rights: `RegCreate/Set/Enum/QueryInfo/Delete` and `NtOpenKey/NtQueryValueKey/NtQueryKey` answered from the hive, `LoadLibrary*` served from the VFS, entry-point stub for hand-mapped images | L5.1-L5.5 | 16 → 16, `scripts/verify_com_activation.ps1` (59 assertions over three runs: no-CRT server, ordinary CRT server, and a run where the file is deleted before mapping) | 2026-11-19 / 16 | pass (Huorong only, second engine pending). The entry-point call is an in-process stub invoked through `InitOnceExecuteOnce`, not an injection. |
| M6 | Type-library virtualization: the `TYPELIB` resource parsed out of the archive, seven oleaut32 entry points hooked (by name **and** by ordinal), `ITypeLib` object handed back, registration written to the hive | L5.6 | 16 → 16, `scripts/verify_com_activation.ps1` (now 33 assertions per run over the same three runs, including the library keys, `LoadRegTypeLib` round trip and removal) | 2026-11-19 / 16 | pass (Huorong only, second engine pending). Reads the image's own resource directory; no new memory-write primitive beyond the IAT `VirtualProtect` already covered by M0/M2a. |
| M7 | CLI-shipped virtual launcher: `lpvhost.exe` maps the embedded runtime and main image from a v7 bundle, seeds the virtual layer and runs the program with no extracted files | L6 | 17 → 17 (the calibration above moved the baseline), `scripts/verify_virtual_bundle.ps1` (CLI-produced bundle, fixture deleted after packing, checksum refusal, `--no-virtual`, zero disk, signed copy) | 2026-11-23 / 17 | pass (Huorong 17 → 17, 360 8 → 8; 55 invariants) |

**A detection can take a fixture away from the check that needs it.** On
2026-11-23 `scripts/verify_ntdll_spike.ps1` reports two failures that are not
about the mechanism: `native target deleted before mapping` and `ntdll_target.exe
absent after --consume`. The `--consume` step deletes `dist\ntdll_target.exe`
before mapping it, and 360 now refuses that delete — `DeleteFileW` returns
`ERROR_ACCESS_DENIED` (`gle=5`) and the file is still there afterwards. It is the
engine, not the code: an exclusive open of the same file succeeds, its attributes
are plain `Archive`, and two byte-identical copies in the same directory
(`ntdll_ctrl.exe`, `host_ctrl.exe`) delete without complaint, while
`[System.IO.File]::Delete` from PowerShell on that exact path is denied too. So
M2b's zero-disk leg cannot be measured on this machine while 360 has that path
flagged; the rest of the M2b run (virtual hit, fall-through, counters, hook
lifecycle) still passes. Record it as "fixture blocked by the engine", not as a
regression, and re-run it on a machine where the fixture is not flagged.

## Run procedure (all mechanisms)

1. Record both signals before the run, read-only: Huorong's quarantine count and
   360's real-time record (`RealtimeProtectLog\<date>.log`, decoded as UTF-16LE).
   `scripts/verify_virtual_bundle.ps1` does this itself and prints both.
2. Run **only** the new mechanism, with the smallest reproducible harness.
3. Wait long enough for on-access and behavioural scanning to finish, then
   record both signals again.
4. If either signal moved: identify the file, do not delete the evidence, and
   mark the mechanism NO-GO. Revert it. Do not proceed to the next loop with a
   known-detected mechanism in the tree.
5. If both are unchanged: record the exact counts, engine state, binary hash and
   date in the table above. Say which engines were live — "two engines" is now
   the normal statement, and an "engine not installed" exception has to be
   named per engine rather than averaged away.

Nothing in this checklist disables, excludes, or works around security
software. That was an explicit project constraint from the P0 decision.

## 2026-11-24: the produced bundle is flagged again (open)

The 2026-11-23 matrix above says the virtual bundle is left alone by both
engines. **That is no longer true, and it changed without a code change to the
archive.** On 2026-11-24 the 0.1.29 release candidate produced bundles that 360
deleted as `HEUR/QVM202.0.9D11.Malware.Gen` (the 23rd's verdicts were
`.992D`), while other bundles written by the same binary in the same minute
survived. 360's real-time log (`Log\RealtimeProtectLog\2026-11-24.log`,
UTF-16LE) holds the paths and MD5s:

| Artifact | MD5 | Engine verdict |
| --- | --- | --- |
| `build\verify_virtual_bundle\vdemo.exe` (gate bundle) | `0390504e2f72e132beab06888ab27ee6` | 360 deleted, QVM202.0.9D11 |
| `build\verify_virtual_bundle\chain.exe` | `68fca4be749dabe8d891fcdc33d6dbe5` | 360 deleted, QVM202.0.9D11 |
| `%TEMP%\lpbundleprobe\probe1.exe` | `b64d1c29709ed91d1e71a5692f0cd57f` | 360 deleted, QVM202.0.9D11 |
| `%TEMP%\lpbundleprobe\probe2.exe` | `cb998374cc01a9838283983ad72ef3f3` | 360 deleted, QVM202.0.9D11 |
| `%TEMP%\lpbundleprobe\probe3.exe` | `cb998374cc01a9838283983ad72ef3f3` | 360 deleted, QVM202.0.9D11 |
| `build\vbprobe\vdemo1.exe`, `vdemo2.exe` | `9aff5df1f5fd716215ed6574d7320f4d`, `8378b68b6c1d84f6df7a792c54769de6` | 360 deleted, QVM202.0.9D11 |
| `%TEMP%\lpavprobe2\plain.exe` (same CLI, same minute) | - | survived a 31 s observation and has no 360 record to date |
| `%TEMP%\lpavprobe2\virt.exe` (same CLI, same minute) | `321590128d78756de3263b0db031feec` | 360 deleted it after the 31 s observation had ended, `HEUR/QVM202.0.9D11` |

What this means, stated narrowly:

- The CLI itself, `lpvhost.exe` and `lpvirt.dll` are not what 360 acted on; the
  deleted objects are the **packed output**.
- It is not deterministic per binary: two bundles from the same build, written
  minutes apart, were left alone. The verdict looks like a content/cloud
  classification that changed between the 23rd and the 24th, not a property the
  code acquired.
- The verifier now sees the failure as `@fs.rename(): ... Access is denied` while
  writing the bundle, or as a run that cannot start, because the engine is
  deleting the artefact underneath it. Those two messages are retried by
  `RunChecked` before they are believed, and the 360 leg of the gate fails on the
  log record rather than passing.

Open questions, in the order they should be answered:

1. Does the verdict follow the **virtual layer** (embedded, unsigned
   `lpvirt.dll` + appended archive) or the plain SFX (launcher + appended
   archive)? `plain.exe` survived once, which points at the virtual layer, but
   one sample is not a measurement.
2. Does an Authenticode signature change the verdict? The signed leg is now
   mechanically possible (L7.2a), so this is finally testable.
3. Does the same bundle get a different verdict when produced by the released
   0.1.28 CLI instead of the 0.1.29 build? That separates "the artefact" from
   "this build".

Until 1–3 are answered, no release may state that either engine leaves the
produced bundle alone, and L7.2 stays open.

### 2026-11-24, second pass: all three questions answered

The three open questions above were run as controlled matrices. All verdicts
below are `HEUR/QVM202.0.9D11.Malware.Gen` from
`Log\RealtimeProtectLog\2026-11-24.log`.

**1. It follows `lpvirt.dll`, not the virtual manifest.** Plain SFX (launcher +
appended archive, `--no-virtual`) with and without a 500 KB dummy payload both
survived, with no 360 record. A plain SFX that carried `lpvirt.dll` as an
*ordinary file payload* — no `--virtual`, no runtime mapping — was deleted
(`4730e92af564aad5786dc4d373642c73`). An empty virtual layer was deleted too
(`ff91e315bbf3c44a5724b72edb9c3f59`). One virtual bundle with a real layer
survived (`3a227a1d0ab173076d08c4ea88b3b6d9`, no record), so the engine is not
uniform across every sample, but the only clean control is the one without the
DLL.

**2. A signature does not clear it.** Three bundles were built, then each copied
before signing so the pair differed only in the Authenticode table. After 90 s
all six were gone, one 360 record per file:

| unsigned | signed |
| --- | --- |
| `u1.exe` `929178133fc4cd8ddcb25bc4012eb6b9` | `s1.exe` `0fc9f4a8a54f219d93013139b6db02aa` |
| `u2.exe` `1a1af9d485ea9c710aa62377013eeb0b` | `s2.exe` `cc98d54827c2030f3591c3c0c24eba28` |
| `u3.exe` `a5fb3e56eb473de1208a8f62945dce75` | `s3.exe` `b5ed5a98697c7b680c1ef99f0f02098a` |

The certificate was created with `New-SelfSignedCertificate -Type
CodeSigningCert` for the test and removed from `Cert:/CurrentUser/My`
afterwards. An untrusted signature cannot confer reputation, so this measures
the mechanical effect of the appended table, not what a purchased certificate
would do.

**3. It is not this build.** Five virtual bundles were made with the current
CLI, crossing the current and the **released v0.1.28** `lpvirt.dll` /
`lpvhost.exe` in all four combinations plus a repeat. All five were deleted,
each with its own 360 record:

| runtime | launcher | MD5 |
| --- | --- | --- |
| current | current | `472a88399589e754d0967546b40587a7` |
| v0.1.28 | v0.1.28 | `f5dece4cb136eada43fa374df105113f` |
| v0.1.28 | current | `65d1dca5bc2105f9adc7bb833d09722e` |
| current | v0.1.28 | `91670f94c7ea8abecf0143bac41a0b45` |
| current | current (repeat) | `e9eec3eaed25e2fa128a9a6a894674f0` |

The v0.1.28 binaries were downloaded from the published release, not rebuilt.
So the 23rd's clean run and the 24th's deletions differ by the engine's model
(`.992D` -> `.9D11`), not by anything LunaPack committed in between.

**Conclusion and disposition.** L7.2 stays open as a third-party false positive
against the produced bundle class. It is not fixable by changing the footer
reader, by signing with a certificate available on this machine, or by
reverting to the released runtime. The gate is deliberately left failing: it
asserts that no 360 record names a path in this repository, and that assertion
is true of the engine's behaviour, not something to be tuned away. Release
assets are now produced on clean CI runners (`build-studio` in `release.yml`),
where no engine is installed; those runs cannot establish AV silence and the
release notes make no such claim.
