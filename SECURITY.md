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
| X.509 (`Certificates`) | local CA, server/client/email issuance, CSR signing, PKCS#12 | PKCS#12 MAC key byte-exact vs OpenSSL; issued Ed25519 and P-384 certificates chain-verified against their CA by OpenSSL in the suite; serials are 128-bit random and distinct per certificate; key identifiers match an independent SHA-1 over the public key bits, and OpenSSL refuses the chain if the authority identifier names the wrong key |
| PBES2 (`PBES2`, `PKCS8`, `PKCS12`) | password-based decryption: PBKDF2 over HMAC-SHA1/256/384/512, AES-128/192/256-CBC | keys written by `openssl pkcs8 -topk8` open to the byte-identical scalar OpenSSL holds; a wrong password is refused |
| PKCS#12 (`PKCS12`) | reading a bundle, MAC verified before its contents are parsed | bundles written by this crate and by `openssl pkcs12 -export` both open, including OpenSSL's default layout with the certificates in encrypted content; the extracted certificates hash identically to the originals |
| RSA | PKCS#1 v1.5 and PSS verification, SHA-256/384/512 | signatures produced by OpenSSL at 2048 and 3072 bits; a cube-root forgery against a low exponent is refused; PSS checked at both salt lengths OpenSSL emits, and a signature does not verify under a salt length or hash other than the one its parameters state |
| X.509 parsing (`ASN1`, `PEM`, `X509.*`) | DER reader, PEM armour, certificate decode, extensions, signature verification | field-by-field against `openssl x509 -text` on the same certificates; an OpenSSL-issued RSA chain verifies here and under `openssl verify`; the 122 system roots parse identically before and after the ambiguity checks below |
| Revocation (`X509.CRLs`, `OCSP`) | CRL and OCSP parsing and signature checking | against a CRL and OCSP responses OpenSSL produced through `openssl ca -revoke`; the request builder is byte-identical to `openssl ocsp -reqout`, with and without a nonce; a delegate without OCSP-signing authority is refused; revocation times and reasons match `openssl crl -text`, and the CRL and OCSP paths agree with each other on the same certificate; a CRL scoped by a critical `issuingDistributionPoint` is refused rather than read as a complete list; a validly signed OCSP response carrying an unrecognised critical extension is refused, in its own extensions or in the entry about the certificate |
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
  not by `pragma Suppress` or a verification tool. `tools/bin/check_constant_time`
  now runs in the release preflight and checks two things against the built
  library. That **no AES lookup table is present** -- forward S-box, inverse
  S-box, or T-table -- is decidable and absolute. The **conditional-jump counts**
  of the routines that must not branch on secrets are held to a recorded
  baseline.
- That baseline corrects a claim this document used to make. `CT_Select` does
  **not** compile to zero conditional jumps: it has one, its loop bound against
  a fixed count, and `Constant_Time.Equal` has twelve, on array lengths, loop
  indices and the answer it returns. Those are branches on public values, which
  is what makes them harmless -- but the earlier wording said something that was
  not true, and a jump count cannot by itself tell a branch on a length from a
  branch on a key.
- So the gate catches regressions, not leaks. A branchless mask rewritten as an
  `if` adds jumps inside a loop body and fails it; this was verified by making
  that edit. A data-dependent memory access leaves no branch behind and would
  pass. Constant-timeness here is still a source-level discipline, and the
  primitives' scalar ladders and field arithmetic are **not** covered by the
  budgets -- only the four routines whose entire job is to be branchless.
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
  CRL -- retrieval is the application's, though `X509.Extensions` reads the
  authority information access and CRL distribution point extensions, so the
  application is at least told where to go: which responder to ask, where to
  fetch the issuer, which URLs serve the CRL. A location named in a
  certificate is a claim by its issuer and nothing more -- whatever comes back
  from one still has to be verified like any other input.
  `CryptoLib.OCSP` builds requests and
  checks responses, including whether the signer was the issuer or a delegate
  the issuer authorised with the OCSP-signing extended key usage; a response
  covering several certificates is searched for the one asked about rather than
  answered from its first entry. It makes no network requests either, and is
  likewise not consulted by `Validate_Path`.
  `X509.Revocation` puts the two behind one question and judges freshness: a
  statement outside its own `thisUpdate`/`nextUpdate` window answers `Stale`
  rather than `Not_Revoked`, since reading "not revoked" off a statement made
  long ago is how a revoked certificate keeps working.
- **OCSP replay is the caller's to prevent, and now possible to prevent.**
  `Build_Request` takes a nonce and `Verify` takes the one that was sent;
  a response carrying a different nonce is refused as `Nonce_Mismatch`, and
  one carrying none is refused as `Nonce_Missing` -- reported apart, because a
  responder serving pre-signed answers omits the nonce as a matter of course
  while a wrong nonce is somebody else's answer. Both are optional and
  default to checking nothing: a stapled response has no nonce to check, and
  a library that always demanded one would refuse most of the public
  responders. The nonce must be unpredictable (`CryptoLib.Random`, not a
  counter); without one, a captured "good" response replays until its
  `nextUpdate`.
- **Opening a PKCS#12 bundle costs real work.** The bundle holds a private
  key, so a copy of one is an offline guessing target and the iteration count
  is the only thing between a weak password and the key. It was 2048 -- what
  `openssl pkcs12 -export` still writes, and roughly three hundred times
  cheaper to attack than current guidance for PBKDF2-HMAC-SHA256. It is now
  600,000, floored by a `Compile_Time_Error` so lowering it fails the build
  rather than a review. The count governs the bundle's **MAC as well as its
  encryption**: both derive from the password, an attacker tests guesses
  against whichever is cheaper, and raising one alone would have bought
  nothing. `Generate_PKCS12` takes the count so a caller can go lower where
  something other than the password's protection is being exercised.
  OpenSSL opens the result and reports both counts; a wrong password is
  refused.
- **Building an OCSP request cannot be crashed by the certificate it is
  about.** A CertID carries the certificate's serial number, nothing bounds
  that on the way in, and the request builder's length emitter converted its
  third octet to a `Stream_Element` rather than masking it -- so a
  certificate with a serial past 65,535 octets raised `CONSTRAINT_ERROR`
  instead of writing. Reproduced with a 70,000-octet serial: the certificate
  decoded cleanly and then the builder crashed, on input from whoever
  supplied the certificate. `Maximum_Request_Length` is documented as a
  buffer size sufficient for a conforming certificate rather than an upper
  bound on what the builder can produce, which it never was; a caller sizing
  by it gets `Size_Limit_Exceeded` for such a certificate.
- **DER lengths are emitted for the size they describe.** The long form
  stopped at two octets and `Byte` truncates rather than complains, so
  anything past 65,535 octets was given a length with its high bits dropped.
  Issuance reported `Ok` and produced a certificate OpenSSL refused to read
  at all. A subject alternative name list is unbounded, so a caller with
  enough names reached this with no sign that anything had gone wrong. Note
  that the *default* decode limits cap a single string at 64 KB, so reading a
  certificate this large back needs limits chosen for it -- that bound is a
  caller's policy about what it will decode, not a property of the encoding.
- **DER integers are emitted in the shortest form.** The encoder wrote a
  fixed four octets for any value at or above `16#8000#`, so 600,000 came out
  as `00 09 27 C0` -- a leading zero DER permits only when the next octet
  would otherwise read as negative. Nothing had ever encoded a value in that
  range, so the first bundle written at the new work factor was refused by
  this crate's own reader. Encoder and decoder now agree by construction.
- **An issued certificate names its own key and its signer's.** Neither
  `subjectKeyIdentifier` nor `authorityKeyIdentifier` was emitted, and RFC
  5280 requires both -- SKI in every CA certificate, AKI in everything but a
  self-signed root. A subject name stops identifying a certificate as soon as
  a CA has more than one: after a re-key, or under a cross-signature, several
  certificates share a name and differ only by key, and a verifier with no
  identifier to go on has to try them all. Both are SHA-1 over the public key
  bits (RFC 5280 method 1, which 38 of the 40 system roots carrying an SKI
  were measured to use), and both are non-critical -- they help a verifier
  find the issuer, they do not constrain what it may conclude. SHA-1's
  weakness costs nothing here: the value only has to tell one key from
  another, and a verifier that follows it still checks the signature.
- **An issued certificate's validity window is computed, not compiled in.**
  It used to be two literals -- `260101000000Z` to `360101000000Z` -- so every
  certificate this crate issued claimed the same ten years, and once that
  decade ran out issuing would have gone on producing certificates that were
  expired the moment they were signed. `notBefore` is now the issuing clock
  (backdated an hour, because the issuer's clock and the verifier's are not
  the same clock) and `notAfter` is `Valid_Days` later: 397 days by default
  for a leaf, the CA/Browser Forum's ceiling, and ten years for a CA.
  A long-lived leaf is a long window in which a compromised key stays usable
  with nothing forcing a rotation. Times at or beyond 2050 are written as
  `GeneralizedTime` rather than `UTCTime`, as RFC 5280 requires -- a
  two-digit year `53` would otherwise read back as 1953.
- **An issued serial number is 128 bits of randomness, drawn per
  certificate.** A revocation names a certificate by issuer and serial and by
  nothing else -- both a CRL entry and an OCSP `CertID` key on it -- so two
  certificates from one CA sharing a serial cannot be revoked apart. These
  used to be hardcoded (1 for the CA, 10 for server certificates, 20 for
  signed CSRs), which meant revoking any server certificate revoked every
  server certificate that CA had issued; that was measured, not inferred. The
  serial is drawn from `CryptoLib.Random`, made positive and minimally
  encoded, and issuance fails closed if the RNG cannot supply bytes rather
  than falling back on anything predictable. The width also puts the value
  out of reach of an attacker who would need to predict it to attempt a
  chosen-prefix collision against the signature hash.
- **Malformed input comes back as a status, not an exception.** The decoders
  were run over 14,600 hostile inputs -- truncations at every prefix
  boundary, pathological lengths, nesting thousands deep, and structured
  mutations of real certificates, CRLs, OCSP responses, PKCS#8 keys and PEM
  armour. None raised; 1,992 decoded far enough to produce a usable object,
  and the rest landed across every error status, so the corpus reached real
  code rather than bouncing off the first byte. The suite carries a smaller
  deterministic version of this as a regression guard. It is a smoke test,
  not a proof: it says nothing about inputs the generator never produced.
- **A certificate that can be read two ways is refused, not resolved.** An
  extension appearing twice is rejected at decode: whichever instance a
  reader takes, another implementation takes the other, and the two then
  disagree about what the issuer authorised. Measured before the check went
  in, a leaf re-signed with `basicConstraints CA:TRUE` inserted ahead of its
  own `CA:FALSE` read here as a **CA** -- a certificate OpenSSL refuses to
  load at all. Extensions on a v1 or v2 certificate are refused for the same
  reason: some parsers honour them and some ignore them. Neither is a
  hypothetical encoding -- both fixtures are re-signed with the issuing key,
  so every other check passes them.
- **A critical extension is honoured or the statement is refused.** This
  applies to certificates (`Validate_Path`), to CRLs, and now to OCSP
  responses: an unrecognised critical extension in a response's own
  extensions, or in the entry about the certificate asked after, makes
  `Verify` answer `Unsupported_Extension`. Marking an extension critical is
  the issuer or responder saying that ignoring it changes what the statement
  means, so reading past it is reading a different statement than the one
  that was signed. The per-entry extensions sit behind an optional
  `nextUpdate`, and were previously unreachable rather than merely
  unchecked.
- **A CRL that covers only part of what its issuer signed answers nothing.**
  `issuingDistributionPoint` and `deltaCRLIndicator` must be critical when
  present, and both change what an *absent* serial means: a CRL scoped to CA
  certificates never lists end-entity revocations, and a delta CRL lists only
  what changed since a base CRL. Such a list is well formed, correctly signed
  and inside its own window, so nothing else here would catch it --
  `Check_Against_CRL` would have answered `Not_Revoked` for a certificate that
  was revoked. It now answers `Unsupported_Statement`. `CRLs.Is_Revoked` still
  reports the list's contents, which is a different question from whether the
  list is authoritative; the scope check sits at the decision point, as the
  equivalent check for certificates does in `Validate_Path`.
- **A revocation says when and why, not just that.** Both sources report a
  `Revocation_Details`: when the issuer says the revocation took effect, and
  the `CRLReason` if it gave one. The time is not the moment the statement was
  published -- a signature made before the revocation may still stand, and a
  caller judging one needs the earlier time. The reason is not decoration
  either: `Key_Compromise` discredits every signature that key ever made,
  while `Superseded` or `Cessation_Of_Operation` leave earlier ones standing.
  "No reason given" is kept distinct from "unspecified", because an issuer
  that said nothing did not say that.

## Test coverage

- **Known-answer tests** for every algorithm above, cross-checked against RFC/NIST
  vectors and (for AEAD/PQ) pyca/OpenSSL or live OpenSSH.
- **Negative / fail-closed tests**: Ed25519 rejects a non-canonical `S` (`S ≥ L`)
  and short signatures/keys; X25519 rejects an all-zero (low-order) peer point;
  ChaCha20-Poly1305 `Open` rejects tampered ciphertext and tampered tags.
- **`Secure_Wipe`** has a unit test asserting a filled buffer is zeroed.

Run the suite: `(cd tests && alr build) && ./tests/bin/tests` (expects
`cryptolib tests passed`).
