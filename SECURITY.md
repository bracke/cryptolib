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
| Ed448 | sign / verify | RFC 8032 PureEdDSA over edwards448, SHAKE256; constant-time signing, gated by jump budgets on its field arithmetic. Signatures are deterministic, so agreement with pyca/OpenSSL is byte-for-byte rather than "both verify"; an OpenSSL-issued Ed448 certificate chain verifies here. The curve constants were derived and not transcribed -- the base point was recovered from a real key as `s^-1 * A`, which needs only `p` and `d`, and confirmed by `L * B` reaching the neutral element, so a mistyped digit in any of them would have shown before the port. A public key has one encoding: `y` at or above `p`, spare bits set in the final octet, an `S` at or above the group order, or a non-zero top octet of `S` are each refused |
| Ed25519 | sign / verify | RFC 8032; a public key has one encoding -- the decoder refuses a non-canonical `y`, requires a real square root, and refuses `x = 0` with the sign bit set (RFC 8032 5.1.3) |
| ECDSA | P-256 (in `ssh_lib`), P-384 / P-521 sign; P-256 / P-384 / P-521 verify; the public point is checked to be on the curve and within the field before use | **RFC 6979 A.2.5** (P-384, byte-exact) + P-521 (pyca cross-verified); verification against OpenSSL signatures on all three curves, including curve/digest pairings that differ (P-521 with SHA-256, P-384 with SHA-512) |
| Finite-field DH | groups 1 / 14 / 16 / 18 | live vs OpenSSH; group16/18 pin the exact RFC 3526 primes |
| Post-quantum | ML-KEM-768, sntrup761 (+ hybrid x25519 KEX) | NIST / live vs OpenSSH sntrup761x25519 |
| X.509 (`Certificates`) | local CA, server/client/email issuance, CSR signing, PKCS#12 | a certificate's times must name dates that exist -- the day is checked against its month with the Gregorian leap rule, so the 31st of February is refused as OpenSSL refuses it, rather than decoding and keeping a certificate valid past the end of the month; a certificate issued under a CA is cut short at the CA's own expiry rather than claiming validity the chain will not have once the issuer runs out; a request is signed for the key it asks about, checked by reading the issued certificate back, for Ed25519, P-384 and Ed448 alike, and one whose own signature does not check is refused rather than certified; PKCS#12 MAC key byte-exact vs OpenSSL; issued Ed25519, P-384 and Ed448 certificates chain-verified against their CA by OpenSSL in the suite, each with the key issued alongside it checked to belong to it; serials are 128-bit random and distinct per certificate; key identifiers match an independent SHA-1 over the public key bits, and OpenSSL refuses the chain if the authority identifier names the wrong key |
| PBES2 (`PBES2`, `PKCS8`, `PKCS12`) | password-based decryption: PBKDF2 over HMAC-SHA1/256/384/512, AES-128/192/256-CBC | keys written by `openssl pkcs8 -topk8` open to the byte-identical scalar OpenSSL holds; a wrong password is refused |
| PKCS#12 (`PKCS12`) | reading a bundle, MAC verified before its contents are parsed | bundles written by this crate and by `openssl pkcs12 -export` both open, including OpenSSL's default layout with the certificates in encrypted content; the extracted certificates hash identically to the originals |
| RSA | PKCS#1 v1.5 and PSS verification, SHA-256/384/512 | signatures produced by OpenSSL at 2048 and 3072 bits; a cube-root forgery against a low exponent is refused; PSS checked at both salt lengths OpenSSL emits, and a signature does not verify under a salt length or hash other than the one its parameters state |
| Certificate policies (`X509.Policies`) | RFC 5280 §6.1 policy tree, mapping, and the three counters | every verdict cross-checked against `openssl verify -policy_check -policy ...` on the same chains: explicit-policy demands, a policy no issuer granted, anyPolicy, anyPolicy withdrawn by `inhibitAnyPolicy`, a mapped policy, and mapping inhibited |
| X.509 parsing (`ASN1`, `PEM`, `X509.*`) | DER reader, PEM armour, certificate decode, extensions, signature verification | field-by-field against `openssl x509 -text` on the same certificates; an OpenSSL-issued RSA chain verifies here and under `openssl verify`; the 122 system roots parse identically before and after the ambiguity checks below |
| Revocation (`X509.CRLs`, `OCSP`) | CRL and OCSP parsing and signature checking | against a CRL and OCSP responses OpenSSL produced through `openssl ca -revoke`; the request builder is byte-identical to `openssl ocsp -reqout`, with and without a nonce; a delegate without OCSP-signing authority is refused; revocation times and reasons match `openssl crl -text`, and the CRL and OCSP paths agree with each other on the same certificate, and agree on what a serial number is -- one comparison serves both, reading a serial as a number so that a padded encoding is not taken for a different certificate, which on this path would look like not being revoked; a CRL scoped by a critical `issuingDistributionPoint` is refused rather than read as a complete list; a validly signed OCSP response carrying an unrecognised critical extension is refused, in its own extensions or in the entry about the certificate |
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
- **Ed448** (`Ed448`) — the same shape: complete projective addition (RFC 8032
  §5.2.4, no exceptional cases to test for), a double-and-add-always ladder,
  and branchless selects. The field subtraction is biased by 256 so the
  quotient carries the sign, because written the obvious way -- `if Diff < 0
  then Item := Diff + 256; Borrow := 1` -- it compiles to a `jns` over
  genuinely different work, on a borrow chain derived from the private
  scalar. That is how it was first written here, and `objdump` is what said
  so; `Borrow_Of`, `Select_Field`, `Add_Mod`, `Sub_Mod` and `Mul_Mod` are now
  held to jump budgets by `check_constant_time`, so it cannot come back
  quietly. (Verification runs on public data.)
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
- The baseline is taken from a **release** build, and the preflight makes one
  for the check rather than inspecting whatever was last built. The profile
  changes the answer: `CT_Select` compiles to no conditional jump under `-O3`
  and to one -- its loop bound -- under the `-Og` development default, and the
  test crate rebuilds the library again under its own. `Constant_Time.Equal`
  keeps eleven either way, on array lengths, loop indices and the answer it
  returns. Those are branches on public values, which is what makes them
  harmless; a jump count cannot by itself tell a branch on a length from a
  branch on a key, which is why the budgets are a regression baseline and not
  a proof.
- So the gate catches regressions, not leaks. A branchless mask rewritten as an
  `if` adds a jump and fails it; this was verified by making that edit. A data-dependent memory access leaves no branch behind and would
  pass. Constant-timeness here is still a source-level discipline, and the
  primitives' scalar ladders and field arithmetic are **not** covered by the
  budgets. Sixteen routines are covered: the mask helpers and `CT_Select` in
  `EC_Arith` and `Modexp`, `Constant_Time.Equal`, the five bit-sliced AES
  S-box routines that stand in for the lookup table (`GF_Mul_BS`,
  `GF_Inv_BS`, `Affine_BS`, `Inv_Affine_BS`, `Sub_Word`), the GHASH multiply
  that runs on the GCM subkey, and sntrup761's Barrett freezes and swap flag.
  Eleven of them carry a budget of zero. The scalar ladders themselves, the
  wider field arithmetic, and ML-KEM are **not** covered.
- AES is **bit-sliced, not AES-NI** — it eliminates the cache-timing channel but
  is slower than hardware AES (the deliberate correctness/side-channel tradeoff).
- `Constant_Time_Proof` is a **declarative manifest, not an automated proof**,
  and `Constant_Time_Assurance` lists primitives across the stack rather than
  in this crate: `RSA_Private_Exponentiation` and `ECDSA_P256_Scalar_Arithmetic`
  name operations `ssh_lib` implements on top of this one. Read as an inventory
  of what this crate does, it claims private-key operations that are not here
  -- `CryptoLib.RSA` verifies and never holds a private key -- while omitting
  the P-384 and P-521 signing that is. Nothing connects those levels to the
  `check_constant_time` budgets above, so a level recorded there is not
  evidence that the gate covers the same code.

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
The suite holds it to that -- the failure is checked at the source, the buffer
is checked to be zeroed rather than left as the caller supplied it, and the
failure is checked to reach the callers that matter: neither an ECDSA nor an
Ed25519 key pair is produced without randomness. The regression this guards
against is quiet, since a fallback that makes a failing source "work" leaves
every status reading `Ok` while every key it produces is predictable.
`Deterministic_Mode` / `Failing_Mode` exist only for reproducible tests.

## Known limitations

- **Windows RNG and `Secure_Wipe`** are written to the documented Windows APIs
  but have **not been built, linked, or run on Windows** from this repo — they
  pass an Alire GNAT semantic check off Windows only and need a Windows CI pass.
- **No AES-NI / hardware acceleration** (see the CT caveat above).
- GNAT `Ada.Numerics.Big_Numbers.Big_Integers` caps at ~6400 bits, which is why
  DH group16/18 use `Modexp` (fixed-width Montgomery) rather than `Big_Integers`.
- CT holds at the source level only; there is no formal or automated guarantee.
- **A low-order Ed25519 public key is accepted.** RFC 8032 does not require
  refusing one, and this does not go beyond it. The consequence is worth
  knowing: for the identity key the verification equation reduces to
  `[S]B = R`, so `S = 0` with `R` the identity verifies against *any*
  message. A caller that treats "the signature verified" as authentication
  without having established whose key it is gets nothing from that
  signature. Establishing whose key it is is `X509.Validation`'s job, not
  this one's.
- **A configured identity is checked, not trusted.** `CryptoLib.Identities`
  confirms a chain decodes, hangs together by issuer and subject name, and
  that the private key belongs to the leaf. It says nothing about whether the
  chain should be believed, which is `X509.Validation`'s question and needs
  trust anchors. RSA, ECDSA on P-256, P-384 and P-521, Ed25519 and Ed448
  identities are all checked. Anything else -- an X25519 key in a
  certificate, say, which is not a signing key at all -- reports
  `Unsupported_Key` rather than `Ok`, so an unchecked identity is never
  mistaken for a checked one.
- **RSA is verification only** — there is no RSA signing, key generation, or
  private-key operation, and no RSA-PSS. `X509.Signatures` reports
  `Unsupported_Algorithm` rather than a failure whenever it cannot check a
  signature, so "we did not check" is never mistaken for "the signature was
  bad". It distinguishes four such answers, and each is now held to
  being distinct: `Algorithm_Mismatch` when the algorithm and the key
  cannot go together, `Malformed_Signature` when the bytes are not shaped
  like a signature for that algorithm, `Missing_Input` when a certificate
  that did not decode was handed in, and `Unsupported_Algorithm` for one
  this cannot verify. Collapsing any of them into `Invalid_Signature` fails
  the suite, because that value asserts a certificate was altered -- RSA-PSS whose parameters name a hash this crate does not implement
  lands there. RSA verification touches only public values, so nothing in it needs to
  be constant-time. That distinction is pinned by certificates
  OpenSSL made: one signed with `sha1WithRSAEncryption`, which this does not
  verify, decodes and names its algorithm as one it does not know, and its
  perfectly good self-signature comes back `Unsupported_Algorithm` rather
  than `Invalid_Signature`. `Identities` reports `Unsupported_Key` for a
  certificate carrying an X25519 key rather than `Key_Mismatch` -- nothing
  is wrong with the pair, and saying otherwise would be a claim this cannot
  support. That test used Ed448 for both until Ed448 became something this
  crate decides, which is the right way for such an example to go stale.
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
  makes the chain fail rather than be checked against only the part that
  could be applied -- but only when the certificate carries a name of such a
  form, since a subtree restricts only names of its own type and one naming
  a form the certificate does not use could never have reached it. RFC 5280
  §4.2.1.10 asks for the constraint to be processed or the certificate
  rejected when an instance of that name form appears; when none does, there
  is nothing to process and nothing to reject, and OpenSSL admits such a
  chain too. The same
  answer covers a subtree carrying the `minimum` or `maximum` depth fields:
  they are a restriction on the subtree this does not apply, and on a
  permitted subtree skipping one would admit names the CA did not. RFC 5280
  §4.2.1.10 says the minimum MUST be zero and the maximum MUST be absent, and
  DER omits a DEFAULT that holds, so no conforming certificate carries either
  and refusing them turns nothing legitimate away. A
  directory-name subtree constrains the certificate's own subject as a prefix
  of its relative names; a URI subtree constrains the host the URI names,
  ignoring any credentials, port or path; a mail subtree is read as a mailbox,
  a host or a domain according to its own shape, and covers an address in the
  subject when the certificate carries no rfc822 alternative name. **Certificate policy processing
  is implemented** (RFC 5280 §6.1): the valid_policy_tree, policy mapping, and
  the `explicit_policy` / `policy_mapping` / `inhibit_anyPolicy` counters.
  `certificatePolicies`, `policyConstraints`, `inhibitAnyPolicy` and
  `policyMappings` are all honoured, so a chain carrying them is processed
  rather than refused -- which is what it used to be. All four are on the
  recognised-critical list because all four are acted on; `policyMappings`
  in particular is one RFC 5280 §4.2.1.5 says a conforming CA SHOULD mark
  critical, so refusing it was refusing what the specification asks for. Policy qualifiers -- a pointer to the issuer's
  certification practice statement, and a notice meant to be displayed -- are
  read and reported per policy by `Policies_Of`, clamped at 200 characters
  with `Truncated` set rather than assumed to fit: the RFC bounds
  `DisplayText` but says nothing about how long a CPS URI may be, so the
  bound is this crate's and not a promise about the input. They are deliberately not
  carried through the tree: §6.1 never consults them, a node's qualifiers are
  those of the certificate that created it, and the ones belonging to a
  chain's established policies are the leaf's own, which `Policies_Of` gives
  directly. The `SkipCerts` counts in `policyConstraints` are
  context-tagged INTEGERs carrying an INTEGER's content without its tag, so
  the shared reader cannot be called on them and they are folded by hand;
  that hand-written path now makes the same three checks the shared one does
  -- a negative count is malformed rather than large, a non-minimal encoding
  is refused, and the accumulation saturates instead of overflowing. Four
  octets reach 4294967295 where `Natural` stops at 2147483647, so before
  this a four-octet field raised `CONSTRAINT_ERROR` out of a parser whose
  contract is that it does not. A policy set is a set at both ends. A certificate
  naming the same policy twice in one extension is refused rather than folded
  down to one -- RFC 5280 §4.2.1.4 forbids the repeat, OpenSSL refuses it as
  error 42, and two copies carrying two qualifier sets have no single meaning
  to fold to. In the other direction a policy is reported once however many
  tree nodes carry it, which two mappings converging on one subject policy
  legitimately arrange; the verdict was never wrong there, but a caller
  counting the list would have read a repetition as breadth.
  `Validation_Result.Policies` reports the
  policies the authorities in the path actually agreed on, which is not what
  the leaf asserts: a certificate may name a policy no issuer above it
  granted, and that certificate is refused when an explicit policy is
  required. A self-issued certificate -- one a CA wrote for
  itself, typically to change keys -- does not lengthen the path, so it
  neither spends the explicit-policy countdown nor loses the right to assert
  anyPolicy after `inhibitAnyPolicy` reached zero. Both halves of that rule
  are tested against chains whose verdict turns on them, and OpenSSL agrees
  on all four. The three initial inputs are in `Validation_Policy.Policy_Options`
  and all default off, and the user-initial-policy-set is
  `Validation_Policy.Accepted_Policies`, empty by default, so a caller that has
  not thought about policies sees no change in behaviour. The set is read in the trust anchor's policy
  domain, not the leaf's: under a policy mapping, asking for the policy the
  anchor granted is satisfied by a leaf asserting what it was mapped to, and
  asking for the mapped-to policy is not. Naming policies there
  only decides the outcome when some certificate required an explicit policy:
  otherwise §6.1.5 succeeds on the `explicit_policy` counter alone and the set
  is reported rather than enforced. That is the RFC's behaviour and OpenSSL's,
  and it surprises people -- asking for a policy does not by itself make a
  chain lacking it fail. The tree is bounded -- 64 nodes, 16 policies and 16
  mappings per certificate, a relationship the compiler holds to, since the
  alternative to a truncation guard that cannot fire is not one that can but
  a truncation path no test covers -- and running out of room makes the outcome
  unacceptable rather than truncating it, because a partial tree is missing
  exactly the nodes that pruning would have removed and can only be too
  permissive. That case is reported as `Policies.Exhausted` alongside the
  failure, so a path refused for establishing no acceptable policy can be told
  apart from one refused because this implementation would not hold the tree
  -- the first is the certificates' doing and the second is ours, and they are
  not the same thing to go and investigate. This is a real divergence and not
  only a theoretical one: the suite builds a chain whose tree needs 65 nodes,
  `openssl verify -policy_check` accepts it, and this refuses it. **An RSA key
  below 2048 bits fails the path**, and every certificate in it is measured
  rather than only the leaf, because a chain is no stronger than the weakest
  key that signed a link of it. RSA is the only algorithm this bears on: the
  curves are named and Ed25519 is one size, so their strength arrives with
  the algorithm, while a certificate may carry any modulus at all. The
  signature under a small modulus verifies perfectly well, which is the
  reason to refuse the key rather than wait for the signature to fail --
  a modulus that can be factored is one anyone can sign with. OpenSSL refuses
  the same chain at its default security level (error 66). The floor is
  `Minimum_RSA_Bits` on the validation policy, and zero lifts it.
  **Revocation (CRL/OCSP) is not
  consulted** by the validator. There is no path building here: finding a chain
  through
  cross-signed roots is `X509.Path_Building`, kept separate: it searches and
  may be wrong, so a path it finds is a proposal that must still go through
  `Validate_Path`. The search verifies signatures as it goes rather than
  trusting name matches, which is what makes cross-signed roots resolve, and
  it applies policy processing to a completed path for the same reason -- two
  certificates can share a subject name *and* a key and grant different
  policies, which is what cross-signing produces, so stopping at the first
  anchor reached proposes a path the validator then refuses while a working
  one sits unexamined. It is bounded by depth and by a link budget. Trust is never inferred -- a
  self-signed certificate is not an anchor unless the caller says so.
- **Revocation is available but not wired into validation.** `X509.CRLs`
  decodes a CRL, verifies that its issuer signed it, and answers whether a
  serial is on it; `Validate_Path` does not consult one, which a test holds it
  to: a certificate the suite's own CRL revokes still passes path
  validation, so a caller reading a valid result as "not revoked" is
  reading something that was never checked. Nothing here fetches a
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
- **How much work opening a bundle costs is now the caller's to bound.** A
  PKCS#12 file states its own iteration counts twice -- once for the MAC and
  once for the encryption -- and both are paid before anything in the file
  has been believed. `Open` had no parameter for it and used a ceiling of ten
  million internally, which is about **forty-five seconds** of CPU per file
  here (~2.4s for the SHA-1 MAC KDF, ~42s for PBKDF2-HMAC-SHA256, measured).
  That is acceptable for a person opening a file they chose and not for a
  service opening one that arrived. `Open` now takes `Maximum_Iterations`,
  applied to both counts and checked *before* the derivation rather than
  after. The default is unchanged, so nothing silently starts refusing files;
  a caller handling untrusted bundles should pass something far smaller.
  Legitimate files are nowhere near the ceiling -- `openssl pkcs12 -export`
  writes 2048 and this crate writes 600,000.
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
- **Malformed input comes back as a status, not an exception.** The policy
  parsers were run over a further 13,943 inputs mutated from certificates
  that carry every policy extension and both qualifier kinds; 1,525 of those
  decoded far enough to run all five parsers and read the qualifier text, and
  none raised. The earlier corpus predates that code and its seeds carry no
  policy extensions, so it never reached them. The decoders
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
