# CryptoLib Security

`cryptolib` is the cryptographic primitive library used by `versionlib`/`ssh_lib`.
It is pure Ada 2022 (Alire/GNAT) with no OpenSSL dependency. Most cross-check
vectors were generated offline and are embedded; the test harness additionally
links libcrypto to verify that certificates this crate issues chain in an
independent implementation. The library itself links nothing beyond the Ada
runtime. This document records the security
properties the code actually provides, how they are verified, and the known
limitations. It describes the code as implemented — not aspirational goals.

## Algorithms and reference vectors

Every primitive is validated against published test vectors in
`tests/src/tests.adb` (run: `(cd tests && alr build) && ./tests/bin/tests`).
The reference sources are:

| Area | Algorithms | Verified against |
|------|-----------|------------------|
| Hashes | MD5, SHA-1, SHA-256/384/512, SHA3-256/512, SHAKE128/256 | NIST / RFC KATs |
| MAC / KDF | HMAC-SHA1/256/384/512, PBKDF2, PBKDF1, PKCS12KDF, bcrypt_pbkdf, UMAC-64/128 | RFC 2202 / 4231 / 6070; RFC 4418 (UMAC); bcrypt proven by decrypting a real OpenSSH key |
| AEAD / ciphers | AES-128/192/256 (CTR/CBC/GCM), ChaCha20-Poly1305, 3DES, RC2 | FIPS-197; AES-256-GCM and chacha20-poly1305@openssh.com cross-checked vs pyca/OpenSSL |
| GHASH | GF(2¹²⁸) for AES-GCM | via the GCM KAT |
| X25519 | Curve25519 ECDH | RFC 7748 §5.2 |
| Ed25519 | sign / verify | RFC 8032 |
| ECDSA | P-256 (in `ssh_lib`), P-384 / P-521 sign; P-256 / P-384 / P-521 verify | **RFC 6979 A.2.5** (P-384, byte-exact) + P-521 (pyca cross-verified); verification against OpenSSL signatures on all three curves, including curve/digest pairings that differ (P-521 with SHA-256, P-384 with SHA-512) |
| Finite-field DH | groups 1 / 14 / 16 / 18 | live vs OpenSSH; group16/18 pin the exact RFC 3526 primes |
| Post-quantum | ML-KEM-768, sntrup761 (+ hybrid x25519 KEX) | NIST / live vs OpenSSH sntrup761x25519 |
| X.509 (`Certificates`) | local CA, server/client/email issuance, CSR signing, PKCS#12 | PKCS#12 MAC key byte-exact vs OpenSSL; issued Ed25519 and P-384 certificates chain-verified against their CA by OpenSSL in the suite |
| PBES2 (`PBES2`, `PKCS8`, `PKCS12`) | password-based decryption: PBKDF2 over HMAC-SHA1/256/384/512, AES-128/192/256-CBC | keys written by `openssl pkcs8 -topk8` open to the byte-identical scalar OpenSSL holds; a wrong password is refused |
| PKCS#12 (`PKCS12`) | reading a bundle, MAC verified before its contents are parsed | bundles written by this crate and by `openssl pkcs12 -export` both open, including OpenSSL's default layout with the certificates in encrypted content; the extracted certificates hash identically to the originals |
| RSA | PKCS#1 v1.5 and PSS verification, SHA-256/384/512 | signatures produced by OpenSSL at 2048 and 3072 bits; a cube-root forgery against a low exponent is refused; PSS checked at both salt lengths OpenSSL emits, and a signature does not verify under a salt length or hash other than the one its parameters state |
| X.509 parsing (`ASN1`, `PEM`, `X509.*`) | DER reader, PEM armour, certificate decode, extensions, signature verification | field-by-field against `openssl x509 -text` on the same certificates; an OpenSSL-issued RSA chain verifies here and under `openssl verify` |
| Revocation (`X509.CRLs`, `OCSP`) | CRL and OCSP parsing and signature checking | against a CRL and OCSP responses OpenSSL produced through `openssl ca -revoke`; the request builder is byte-identical to `openssl ocsp -reqout`; a delegate without OCSP-signing authority is refused |
| Service identity (`X509.Identity`) | RFC 9525 DNS and IP matching | negative cases pinned: a wildcard matches neither the bare domain nor across two labels, an address is never matched as text, and the common name is consulted only when a caller asks for it |

## Constant-time properties

The following operate on secret data and are implemented without secret-dependent
branches, memory indexing, or variable-latency arithmetic:

- **AES** (`Ciphers`) — the S-box is **bit-sliced** (`affine(x²⁵⁴)` over GF(2⁸)
  with branchless field arithmetic and a public fixed exponent). There is **no
  S-box lookup table** in the binary, so there is no cache-timing side channel.
  `Xtime`/`Gmul` and the GF(2¹²⁸) **GHASH** multiply are branchless (mask, not
  `if`) — relevant because GHASH runs on the GCM authentication subkey.
- **Finite-field DH** (`Modexp`) — fixed-width Montgomery modular exponentiation,
  square-and-multiply-**always** over a fixed iteration count (the public
  exponent byte length), branchless conditional subtract/select.
- **ECDSA** (`EC_Arith` + `ECDSA`) — fixed-width Montgomery field arithmetic
  (branchless add/sub/select), Renes–Costello–Batina **complete** projective
  point addition (no exceptional cases), a fixed-length **double-and-add-always**
  scalar ladder with branchless point select, and `k⁻¹`/`Z⁻¹` via Fermat through
  the constant-time `Modexp`. The RFC 6979 nonce candidate check is branchless.
- **Ed25519** (`Ed25519`) — signing uses always-add scalar multiplication with
  branchless field/`mod L` reduction. (Verification runs on public data.)
- **X25519** (`Curve25519`) — Montgomery ladder with arithmetic conditional swap;
  the all-zero (low-order-point) shared secret is rejected per RFC 7748 / the SSH
  curve25519 KEX.
- **sntrup761** (`SNTRUP761`) — `mod`/hardware-division freezes replaced by
  branchless Barrett multiply-shift; decapsulation selects and rho-substitutes
  branchlessly (constant-time implicit rejection).
- **ML-KEM-768** — the FO re-encryption compare uses `Constant_Time.Equal`.
- **Authentication-tag comparison** — `Constant_Time.Equal` (accumulate-OR,
  no early return) is used for GCM, ChaCha20-Poly1305, and the ML-KEM check.

### Caveats (read these)

- Constant-timeness is enforced at the **Ada source level** (branchless masks),
  not by `pragma Suppress` or a verification tool. It was spot-checked with
  `objdump` (e.g. `CT_Select` compiles to zero conditional jumps; the jumps in
  `Mont_Mul`/`Pack`/`Unpack` are loop counters and input-independent GNAT range
  checks). A compiler upgrade could in principle reintroduce a branch; there is
  **no automated CT regression gate**.
- AES is **bit-sliced, not AES-NI** — it eliminates the cache-timing channel but
  is slower than hardware AES (the deliberate correctness/side-channel tradeoff).
- `Constant_Time_Proof` is a **declarative manifest, not an automated proof**.

## Secret zeroization

`Secure_Wipe.Wipe (Address, Length)` overwrites memory through a
`Volatile_Components` overlay, so the store **cannot be elided** by the optimizer
(unlike a plain `X := [others => 0]`, which `-O3` removes as a dead store — a real
bug this replaced). It needs no libc/OS primitive, so it is portable.

It scrubs sntrup761 key material (recip/keygen work arrays) and the ECDSA signer's
long-term private scalar, per-signature nonce, `k⁻¹`, and HMAC-DRBG state.
Zeroization is **not comprehensive** across every primitive's ephemeral buffers;
it targets the highest-value long-term-key and nonce material.

## Randomness

`Random` in `Production_Mode` delegates to `OS_Random.Fill_OS`, selected per OS
by the project file (`src-linux` / `src-windows`):

- **Linux** — `getrandom(2)` (blocks until the kernel CSPRNG is seeded),
  `/dev/urandom` fallback.
- **Windows** — `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`.

The RNG **fails closed**: if no OS source is available it returns
`Internal_Error` and zeroes the buffer rather than emitting weak randomness.
`Deterministic_Mode` / `Failing_Mode` exist only for reproducible tests.

## Known limitations

- **Windows RNG and `Secure_Wipe`** are written to the documented Windows APIs
  but have **not been built, linked, or run on Windows** from this repo — they
  pass an Alire GNAT semantic check off Windows only and need a Windows CI pass.
- **No AES-NI / hardware acceleration** (see the CT caveat above).
- GNAT `Ada.Numerics.Big_Numbers.Big_Integers` caps at ~6400 bits, which is why
  DH group16/18 use `Modexp` (fixed-width Montgomery) rather than `Big_Integers`.
- CT holds at the source level only; there is no formal or automated guarantee.
- **A configured identity is checked, not trusted.** `CryptoLib.Identities`
  confirms a chain decodes, hangs together by issuer and subject name, and
  that the private key belongs to the leaf. It says nothing about whether the
  chain should be believed, which is `X509.Validation`'s question and needs
  trust anchors. RSA, ECDSA on P-256, P-384 and P-521, and Ed25519 identities
  are all checked. Anything else -- Ed448 today -- reports `Unsupported_Key`
  rather than `Ok`, so an unchecked identity is never mistaken for a checked
  one.
- **RSA is verification only** — there is no RSA signing, key generation, or
  private-key operation, and no RSA-PSS. `X509.Signatures` reports
  `Unsupported_Algorithm` rather than a failure whenever it cannot check a
  signature, so "we did not check" is never mistaken for "the signature was
  bad" -- RSA-PSS whose parameters name a hash this crate does not implement
  lands there. RSA verification touches only public values, so nothing in it needs to
  be constant-time.
- **Path validation checks a supplied path; it does not build one.**
  `X509.Validation` verifies signatures along a chain, issuer/subject linkage,
  validity windows against a caller-supplied time, basic constraints and path
  length, keyCertSign, loops, and unknown critical extensions, and requires the
  path to end at a certificate the caller declares trusted. **Name constraints
  are enforced** for DNS, IP, directory-name, URI and mail subtrees, by every
  CA above a certificate
  rather than only its immediate issuer. A DNS subtree also covers the subject
  common name of an end-entity certificate that carries no DNS alternative
  name -- which is exactly when `X509.Identity` will read that field as a host
  if a caller enables the fallback, so the constraint and the identity check
  cover the same ground rather than leaving a gap between them; a constraint naming a form this crate
  cannot apply (an EDI party name, an x400 address, a registered identifier)
  makes the chain fail
  rather than be checked against only the part that could be applied. A
  directory-name subtree constrains the certificate's own subject as a prefix
  of its relative names; a URI subtree constrains the host the URI names,
  ignoring any credentials, port or path; a mail subtree is read as a mailbox,
  a host or a domain according to its own shape, and covers an address in the
  subject when the certificate carries no rfc822 alternative name. **Certificate policy
  processing is not implemented**: `certificatePolicies` is recognised because
  it restricts nothing without a caller-supplied policy set, while a critical
  `policyConstraints` or `inhibitAnyPolicy` makes a chain fail, since honouring
  those needs processing this does not do. **Revocation (CRL/OCSP) is not
  consulted** by the validator. There is no path building here: finding a chain
  through
  cross-signed roots is `X509.Path_Building`, kept separate: it searches and
  may be wrong, so a path it finds is a proposal that must still go through
  `Validate_Path`. The search verifies signatures as it goes rather than
  trusting name matches, which is what makes cross-signed roots resolve, and
  it is bounded by depth and by a link budget. Trust is never inferred -- a
  self-signed certificate is not an anchor unless the caller says so.
- **Revocation is available but not wired into validation.** `X509.CRLs`
  decodes a CRL, verifies that its issuer signed it, and answers whether a
  serial is on it; `Validate_Path` does not consult one. Nothing here fetches a
  CRL -- retrieval is the application's. `CryptoLib.OCSP` builds requests and
  checks responses, including whether the signer was the issuer or a delegate
  the issuer authorised with the OCSP-signing extended key usage; it makes no
  network requests either, and is likewise not consulted by `Validate_Path`.
  `X509.Revocation` puts the two behind one question and judges freshness: a
  statement outside its own `thisUpdate`/`nextUpdate` window answers `Stale`
  rather than `Not_Revoked`, since reading "not revoked" off a statement made
  long ago is how a revoked certificate keeps working.

## Test coverage

- **Known-answer tests** for every algorithm above, cross-checked against RFC/NIST
  vectors and (for AEAD/PQ) pyca/OpenSSL or live OpenSSH.
- **Negative / fail-closed tests**: Ed25519 rejects a non-canonical `S` (`S ≥ L`)
  and short signatures/keys; X25519 rejects an all-zero (low-order) peer point;
  ChaCha20-Poly1305 `Open` rejects tampered ciphertext and tampered tags.
- **`Secure_Wipe`** has a unit test asserting a filled buffer is zeroed.

Run the suite: `(cd tests && alr build) && ./tests/bin/tests` (expects
`cryptolib tests passed`).
