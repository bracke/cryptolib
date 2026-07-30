# AGENTS.md

Guidance for AI agents working in the `cryptolib` crate. **This file is the
canonical copy** and applies to every AI coding tool; `CLAUDE.md` imports it so
Claude Code sees the same text. Edit this file, not that one.

## What this is

`cryptolib` is a pure Ada 2022 (Alire/GNAT) cryptographic primitive library —
hashes, MACs/KDFs, ciphers/AEAD, elliptic-curve and finite-field key agreement,
signatures, and post-quantum KEMs. Every package is `CryptoLib.*`. The library
itself has **no Alire dependencies** and no runtime OpenSSL dependency. The test
crate is where the dependencies are: it uses `aunit`, and it links libcrypto so
the suite can ask an independent implementation whether a certificate this crate
issued actually chains.

Three crates in this workspace depend on it directly — `ssh_lib`, `devcert` and
`versionlib` — so an API change breaks them, not just this repo. Run their
suites before calling a change done: `sshlib/tests/bin/main` (56),
`devcert/devcert_tests/bin/devcert_tests` (39).

`README.md` documents usage; `SECURITY.md` documents the security properties,
constant-time guarantees, and known limitations. **Keep both accurate** when you
change behavior. `README.md`'s snippets are fragments chosen to read well; each
has a compilable counterpart under `examples/` that the release preflight
builds, so an example that stops compiling is caught. `SECURITY.md`'s
claims are meant to be checkable against the code.

## Build, test, style

- Toolchain: use Alire GNAT 15 only. The root, tests, and tools crates require
  `gnat_native = "^15"`; validate with `alr exec -- gnatls --version`. Do not
  run plain system `gnat*`, `gnatmake`, `gnatls`, `gnatprove`, `gcc -gnat*`, or
  `gprbuild` for this workspace, because PATH tools can bypass the enforced
  Alire compiler.
- Build: `alr build`.
- Tests (KATs + negative/fail-closed tests): `(cd tests && alr build) && ./tests/bin/tests`
  — an AUnit runner: one line per test, a `Total Tests Run` summary, and a
  non-zero exit status if anything failed. Every check runs even when an
  earlier one fails. The suite links libcrypto for the certificate chain
  cross-check; the library does not.
- **Test layout**: `tests/src/tests.adb` is only the AUnit runner.
  `tests_suite` builds the suite from one `AUnit.Test_Cases.Test_Case` per
  topic, each in `tests/src/tests_<topic>.adb`, with the shared assertion and
  hex/string helpers in `tests_support`. Nothing is declared in the topic
  specs but the test case itself.
- **Adding a check**: write `Check_<Name>` in the topic body, add a
  `Run_Check_<Name>` wrapper, and register it in that package's
  `Register_Tests`. **Registration is what runs it** — an unregistered check
  passes without testing anything, which is what `tools/bin/check_test_suite`
  refuses (it requires a `Run_Check_<Name>'Access` for every `Check_<Name>`).
  A helper that is not itself a test must not be named `Check_<something>`;
  see `Expect_MD5`.
- Assert through `Tests_Support.Check`, not `AUnit.Assertions.Assert`
  directly — `Check` is the one place the whole suite goes through.
- Release/verification tooling lives in the `cryptolib_tools` crate: `(cd tools && alr build)`
  (depends on the shared `project_tools` at `../../project_tools`). Run
  `tools/bin/check_release_ready` from the crate root for the full preflight:
  a forced release build, the constant-time check, a semantic compile of all
  three per-OS backends, a forced library build, the test suite, the Alire
  manifest, the test suite's own shape, the README examples, and GNATdoc tags.
- **CI runs that preflight**, not a subset — `.github/workflows/ci.yml` checks
  out `project_tools` beside this repo, builds the tools crate, and runs it. So
  the checks above are enforced on every push, and a change that only passes
  `alr build` is not a change that passes. Linux only, though: `src-macos` and
  `src-windows` get the semantic check and nothing more.
- **On a fresh checkout, `alr update` once before `alr build` — in the crate
  root as well as `tests/` and `tools/`.** Their `alire/`, `config/`, `obj/`,
  and `bin/` are generated and untracked, and `alr build` alone does not
  resolve the path pins from nothing: it regenerates the directories and then
  fails to find `project_tools` or `cryptolib.gpr`. The root needs it too, or
  `alire/alire.lock` has no toolchain entry and the manifest check fails.
- **No scripts.** The repository is Ada, `.gpr`, `.toml`, Markdown and one CI
  workflow — no `.sh`, no `.py`, no Makefile, nothing with an executable bit.
  Tooling that would be a script elsewhere is an Ada program in `tools/`. Those
  programs do invoke external commands, because building means running `alr`,
  `gprbuild`, `gcc` and `objdump` — but a command line is how a program is
  invoked, not where logic goes: no `&&`, no `cd`, no redirection, no shell
  builtins. Use `Ada.Directories` to make or enter a directory,
  `Project_Tools.Processes.Run_Shell_In_Directory` to run somewhere else, and
  `Locate_Command` to ask whether a tool exists. The test harness reaches
  OpenSSL through `Import, Convention => C`, not by spawning the `openssl` CLI.
- Style is enforced by GNAT flags, not a formatter: Ada 2022, 3-space indent, max
  120 columns, `-gnatwa` (all warnings) + `-gnatVa` (validity). **Keep builds
  warning-clean** — the bar is zero warnings; clear any in code you touch.
  Warnings only surface when a file recompiles, so after editing a widely-`with`ed
  spec run a forced build (`alr build -- -f`) to see them all.
- What the zero-warning bar does *not* cover, because `cryptolib.gpr` and
  `tests/tests.gpr` both end their switch list with `-gnatwU` (the tools and
  examples projects do not): unused entities, including unused subprograms and
  with-clauses. `-gnatwa` would not report unused subprograms anyway (that needs
  `-gnatwu`), but note that adding `-gnatwu` earlier in the list achieves nothing
  — `-gnatwU` comes last and wins. A clean build is not evidence that nothing is
  dead.
- `tests/tests.gpr` additionally passes `-gnatwM` (no "useless assignment"
  warnings); the reason is written down there. The library build does not get it
  and is warning-clean with that warning on.

## Security disciplines (this is a crypto library — not optional)

- **Constant-time on secret paths.** No secret-dependent branches, no memory
  indexed by secret data (no S-box / table lookup indexed by a secret byte), no
  variable-latency arithmetic (`mod`, hardware divide) on secrets. Use branchless
  masks (`Mask := Byte (0) - Bit;`) and `CryptoLib.Constant_Time.Equal` for
  tag/MAC comparison.
- **There is an automated CT gate**: `tools/bin/check_constant_time` disassembles
  the built library and holds a named set of symbols to a recorded budget of
  conditional jumps (`CT_Select` and the `ec_arith` mask helpers are budgeted at
  zero, as are the bit-sliced AES helpers), and
  fails if a symbol it names has gone missing — a check that passes because it
  looked for a name that no longer exists is worse than no check. It also refuses
  an AES S-box or T-table in the binary. It runs in the preflight and therefore
  in CI.
  - Budgets are recorded from a **`--release`** build; `-O3` and the `-Og`
    default disagree (`CT_Select` has zero conditional jumps under one and one
    under the other). Running the tool against whatever `lib/` happens to hold
    reports failures that mean nothing — the preflight builds `--release`
    immediately before it for this reason.
  - What it cannot do is tell you a branch depends on a secret. It counts jumps
    against a number somebody wrote down. A new branch inside a budget is still
    yours to justify, so read the disassembly (`objdump -d`) when you touch a
    secret-dependent path; only loop-counter and invariant range-check jumps are
    acceptable there.
- **Verify a new primitive against a reference vector BEFORE porting.** Check the
  algorithm in Python or against an RFC/NIST vector first, then port to Ada, then
  add the KAT to the matching `tests/src/tests_*.adb`. Hand-transcribed formulas (EC point
  addition, an S-box circuit, a curve order) are easily wrong — never trust one
  un-verified. (A wrong RCB point-addition transcription and a mistyped P-521
  order both cost real time here.)
- **Scrub secrets with `CryptoLib.Secure_Wipe.Wipe (X'Address, X'Size / System.Storage_Unit)`.**
  A plain `X := [others => 0]` on a local before return is a dead store and **is
  eliminated by `-O3`** — it zeroes nothing. Wipe through the object's own
  `'Address` (a by-value/`in out` helper can wipe a copy).
- **Cross-check against real implementations**: AEAD/GCM vs pyca/OpenSSL; DH / PQ
  KEX / ECDSA vs live OpenSSH; hashes/HMAC/PBKDF2 vs RFC/NIST vectors.

## Platform and toolchain gotchas

- **Per-OS code lives in `src-linux/`, `src-macos/` and `src-windows/`**, selected by
  `Source_Dirs = "src-" & Cryptolib_Config.Alire_Host_OS`. NEVER put a glibc-only
  symbol (`getrandom`, `explicit_bzero`) in common `src/` — it breaks the Windows
  link. `CryptoLib.Secure_Wipe` is deliberately portable (volatile stores, no
  libc). The Windows RNG (`BCryptGenRandom`) is written but **unverified off
  Windows** — it only passes an Alire GNAT semantic check off Windows.
- **GNAT `Ada.Numerics.Big_Numbers.Big_Integers` hard-caps at ~6400 bits** (200
  words → `STORAGE_ERROR`). That is why DH group16/18 use `CryptoLib.Modexp`
  (fixed-width Montgomery), not `Big_Integers`.
- **AES uses a bit-sliced S-box** (no lookup table → no cache-timing channel),
  which is slower than AES-NI — the deliberate side-channel/perf tradeoff.

## When you change behavior

Add or adjust the KAT in the matching `tests/src/tests_*.adb`, keep `README.md` / `SECURITY.md`
accurate, run the suite, and — for anything touching a security property —
verify it (objdump for constant-time, live OpenSSH / pyca for correctness).
