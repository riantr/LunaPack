# AV retest checklist (L0.5)

This is the rule for the whole EVB-parity roadmap: **a mechanism is not
accepted until it has been tested with security software enabled, and every
new mechanism is tested on its own.** The P0 experiment is the reason — eleven
injector builds were quarantined as `HVM:Trojan/Injector.gen!A`, and the reason
the remote-injection product form was dropped. "It worked in the demo" is not
evidence about AV.

## Engines available on this machine (measured 2026-11-18)

| Engine | State | Use |
| --- | --- | --- |
| Huorong Sysdiag (`HipsTray.exe`, `wsctrlsvc`) | **active** | Primary gate. Quarantine directory: `C:\ProgramData\Huorong\Sysdiag\Quarantine`. Baseline count: **16 files** (11 from the P0 injector experiment on 2026-11-13, 5 older). |
| Windows Defender | installed but **disabled** (`AntivirusEnabled=False`, `RealTimeProtectionEnabled=False`) | Cannot serve as a second live gate here. Listed so the gap is explicit, not hidden. |

Requirement from the roadmap is "Huorong + at least one other engine". That is
**not currently satisfiable on this machine**. Two honest options, to be chosen
before L4 ships:

1. Enable Defender real-time protection for the duration of each test and
   record its detection log. This changes machine state and needs an explicit
   decision — it is not done automatically by any script here.
2. Use a second engine on another machine (or a VM) and attach its report.

Until one of those is in place, any "AV passed" statement in a loop note must
say "Huorong only, second engine pending". Never write a bare "AV passed".

## Signed vs unsigned

The release build is unsigned; the release workflow ships `lpvirt.dll` as an
experimental asset without a code-signing certificate. Signing changes how
some engines treat a binary, so both states must be recorded:

- [ ] unsigned `lpvirt.dll` + unsigned host (current state) — Huorong count before/after
- [ ] signed build, if a certificate becomes available — same test, same harness
- [ ] note whether the engine's verdict differed; a signed pass does not
      retroactively clear the unsigned build

## Per-mechanism retest list

Each row is a separate run. Do not batch them into one "everything" test: a
single quarantine event must be attributable to the mechanism that caused it.

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
| M5 | COM registration redirection | L5 | pending | — | — |
| M6 | CLI-shipped virtual launcher (not a C test double) | L6 | pending | — | — |

## Run procedure (all mechanisms)

1. Record the quarantine file count before the run (PowerShell, read-only).
2. Run **only** the new mechanism, with the smallest reproducible harness.
3. Wait long enough for on-access and behavioural scanning to finish, then
   record the count again.
4. If the count increased: identify the quarantined file, do not delete the
   evidence, and mark the mechanism NO-GO. Revert it. Do not proceed to the
   next loop with a known-detected mechanism in the tree.
5. If unchanged: record the exact count, engine state, binary hash and date in
   the table above, with the "Huorong only" qualifier if no second engine ran.

Nothing in this checklist disables, excludes, or works around security
software. That was an explicit project constraint from the P0 decision.
