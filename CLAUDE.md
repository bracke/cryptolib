# CLAUDE.md

Guidance for AI agents working in the `cryptolib` crate (Claude Code loads this;
other tools read the sibling `AGENTS.md`, which points here).

## What this is

`cryptolib` is a pure Ada 2022 (Alire/GNAT) cryptographic primitive library —
hashes, MACs/KDFs, ciphers/AEAD, elliptic-curve and finite-field key agreement,
signatures, and post-quantum KEMs. Every package is `CryptoLib.*`. It has **no
Alire dependencies** and no runtime OpenSSL dependency; the test harness links
OpenSSL only for cross-checks. It is consumed by `ssh_lib` (and transitively by
`versionlib` / the `version` CLI).

`README.md` documents usage; `SECURITY.md` documents the security properties,
constant-time guarantees, and known limitations. **Keep both accurate** when you
change behavior — every code example in `README.md` is verified to compile, and
`SECURITY.md`'s claims are meant to be checkable against the code.

## Build, test, style

- Toolchain: use Alire GNAT 15 only. The root, tests, and tools crates require
  `gnat_native = "^15"`; validate with `alr exec -- gnatls --version`. Do not
  run plain system `gnat*`, `gnatmake`, `gnatls`, `gnatprove`, `gcc -gnat*`, or
  `gprbuild` for this workspace, because PATH tools can bypass the enforced
  Alire compiler.
- Build: `alr build`.
- Tests (KATs + negative/fail-closed tests): `(cd tests && alr build) && ./tests/bin/tests`
  — prints `cryptolib tests passed`. No OpenSSL: the cross-check vectors are
  embedded, so the suite links nothing beyond the Ada runtime.
- Release/verification tooling lives in the `cryptolib_tools` crate: `(cd tools && alr build)`
  (depends on the shared `project_tools` at `../../project_tools`). Run
  `tools/bin/check_release_ready` from the crate root for the full preflight
  (build + test + manifest + test-suite + GNATdoc-tag checks).
- Style is enforced by GNAT flags, not a formatter: Ada 2022, 3-space indent, max
  120 columns, `-gnatwa` (all warnings) + `-gnatVa` (validity). **Keep builds
  warning-clean** — the bar is zero warnings; clear any in code you touch. Note:
  `-gnatwa` does NOT warn on unused *subprograms* (needs `-gnatwu`), and warnings
  only surface when a file recompiles — after editing a widely-`with`ed spec, run
  a forced build (`alr build -- -f`) to see them all.

## Security disciplines (this is a crypto library — not optional)

- **Constant-time on secret paths.** No secret-dependent branches, no memory
  indexed by secret data (no S-box / table lookup indexed by a secret byte), no
  variable-latency arithmetic (`mod`, hardware divide) on secrets. Use branchless
  masks (`Mask := Byte (0) - Bit;`) and `CryptoLib.Constant_Time.Equal` for
  tag/MAC comparison. There is **no automated CT gate** — verify with `objdump -d`
  (a CT select should compile to zero conditional jumps; only loop-counter and
  invariant range-check jumps are acceptable).
- **Verify a new primitive against a reference vector BEFORE porting.** Check the
  algorithm in Python or against an RFC/NIST vector first, then port to Ada, then
  add the KAT to `tests/src/tests.adb`. Hand-transcribed formulas (EC point
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

- **Per-OS code lives in `src-linux/` and `src-windows/`**, selected by
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

Add or adjust the KAT in `tests/src/tests.adb`, keep `README.md` / `SECURITY.md`
accurate, run the suite, and — for anything touching a security property —
verify it (objdump for constant-time, live OpenSSH / pyca for correctness).
