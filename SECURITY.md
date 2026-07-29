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
| MAC / KDF | HMAC-SHA1/256/384/512, PBKDF2, PBKDF1, PKCS12KDF, bcrypt_pbkdf, UMAC-64/128, HKDF, TLS 1.3 HKDF-Expand-Label / Derive-Secret | RFC 2202 / 4231 / 6070; the TLS 1.3 schedule against RFC 8448's published handshake -- the early secret and Derive-Secret(early, "derived", "") byte for byte, plus HKDF-Expand-Label at the widths TLS asks for (a 16-octet key, a 12-octet IV, a 32-octet finished key with a context) and the SHA-384 arm; the "tls13 " prefix is pinned by expanding the same secret with a hand-built info that omits it and requiring a different answer, which a round trip written against itself could not catch; HKDF against RFC 5869 A.1, A.2 and A.3 -- basic, long inputs, and the empty salt and info the RFC treats as meaningful -- plus SHA-384 and SHA-512 vectors agreed with pyca, the 255-block ceiling accepted and one octet past it refused, and two contexts over one secret checked to give unrelated keys; RFC 4418 (UMAC); bcrypt_pbkdf against the OpenBSD construction as the `bcrypt` module implements it, at three round counts and output lengths, plus its refusals of a zero round count and an empty passphrase; and end to end, a private key written by `ssh-keygen` is opened using only this crate -- bcrypt_pbkdf for the material, AES-256-CTR for the blob, the 48-byte derivation cut into key and IV the way OpenSSH cuts it -- with the check words matching and the plaintext naming itself `ssh-ed25519`, which a vector for either primitive alone cannot show |
| AEAD / ciphers | AES-128/192/256 (CTR/CBC/GCM), ChaCha20-Poly1305, 3DES, RC2 | every cipher name is checked against `openssl enc` with the same key, IV and plaintext, so a name wired to the wrong mode or key width fails here rather than only against another implementation; a key shorter than the name needs is refused and a longer one is cut to it, which is what RFC 4253 derivation yields when the two directions negotiate ciphers of different widths; FIPS-197; AES-256-GCM and chacha20-poly1305@openssh.com cross-checked vs pyca/OpenSSL; RFC 8439's AEAD_CHACHA20_POLY1305 -- the construction everything outside SSH means by the name -- against the section 2.8.2 vector byte for byte, with a flipped tag, a flipped ciphertext bit and a changed AAD each refused, an empty plaintext and empty AAD each sealed and opened, and the SSH construction's 64-byte key refused; the two constructions are held to being unconfusable, sealing the same bytes to different wire output and neither opening the other's; the packet length is encrypted twice in this crate -- inline by `Seal` and again by `Encrypt_Length`, for a caller that must read a length before it knows how much more to read -- and the two are held to producing the same four bytes, since only the first was covered by that cross-check; UMAC's nonce is checked to be the sequence number in the low four bytes of eight, big-endian, which the RFC 4418 vectors never reach because they supply a nonce ready-made |
| GHASH | GF(2¹²⁸) for AES-GCM | via the GCM KAT |
| NIST ECDH | P-256 / P-384 / P-521 key agreement | NIST CAVP ECC-CDH primitive vectors on P-256 and P-384, and separately against shared secrets OpenSSL derived with `pkeyutl` from keys OpenSSL generated; a fresh exchange on each curve is checked to reach the same secret from both sides. Peer points are validated before the scalar touches them -- an off-curve point, a coordinate equal to p, a compressed tag, the all-zero point and a wrong-width encoding are each refused with the secret left zero, as is a private scalar of zero or one equal to the order. Removing the on-curve check fails the suite. No small-subgroup check is performed or needed: all three curves have cofactor 1, so a point satisfying the equation already generates the full prime-order group |
| X25519 | Curve25519 ECDH | RFC 7748 §5.2, through the raw primitive and again through `Shared_Secret`, the entry point a key exchange calls -- two keypairs agree, and an all-zero peer point is refused there too. The refusal has two layers, a zero Z and a zero result, so removing either alone changes nothing and both had to go before the test noticed |
| Ed448 | sign / verify | RFC 8032 PureEdDSA over edwards448, SHAKE256; constant-time signing, gated by jump budgets on its field arithmetic. Signatures are deterministic, so agreement with pyca/OpenSSL is byte-for-byte rather than "both verify"; an OpenSSL-issued Ed448 certificate chain verifies here. The curve constants were derived and not transcribed -- the base point was recovered from a real key as `s^-1 * A`, which needs only `p` and `d`, and confirmed by `L * B` reaching the neutral element, so a mistyped digit in any of them would have shown before the port. A public key has one encoding: `y` at or above `p`, spare bits set in the final octet, an `S` at or above the group order, or a non-zero top octet of `S` are each refused |
| Ed25519 | sign / verify | RFC 8032; and a signature `ssh-keygen -Y sign` produced verifies here, over the SSHSIG structure OpenSSH frames for itself -- a magic string, the namespace, the hash name and the digest of the file, none of it assembled by this crate, which a vector cannot show; a public key has one encoding -- the decoder refuses a non-canonical `y`, requires a real square root, and refuses `x = 0` with the sign bit set (RFC 8032 5.1.3) |
| ECDSA | P-256 / P-384 / P-521 sign and verify; the public point is checked to be on the curve and within the field before use | **RFC 6979 A.2.5** (P-256 and P-384, byte-exact -- for P-256 both the `sample` and `test` messages, since the DRBG state width is the paired digest's and a vector that only asked whether *a* signature came out would pass on a curve that cannot sign at all) + P-521 (pyca cross-verified); a generated P-256 keypair is checked to be a pair -- the point the scalar implies, not merely a point -- and then signed and verified with; verification against OpenSSL signatures on all three curves, including curve/digest pairings that differ (P-521 with SHA-256, P-384 with SHA-512), and separately through the `Nistp*_Raw` entry points, which choose the digest themselves rather than taking it from the caller -- the pairing SSH means by `ecdsa-sha2-nistp256`, checked against signatures made elsewhere over the matching hash, so a curve wired to the wrong one fails here rather than only against the rest of the world |
| Finite-field DH | groups 1 / 14 / 16 / 18 | in group exchange the server proposes the prime and generator, and `Select_Group_Exchange_Group` is the only thing deciding whether to accept them: each RFC 3526 prime is recognised as itself, a prime one bit away from group14 is refused rather than taken for it, and so are the right prime under generator 5, a small prime, and a proposal with no generator -- a match that should not have been made is a key exchange in a group the server chose; live vs OpenSSH; group16/18 pin the exact RFC 3526 primes; group1 and group14 are pinned by a fixed exponent against a written-down answer, since a round trip between two honest sides is self-consistent and would pass with the wrong prime; groups 1, 14 and 16 all refuse a peer public value outside (1, p-1); and every generator is checked against the function that consumes what it produces -- the public value it emits must be 2 raised to the private value beside it, which is what the shared-secret side computes when the peer sends 2, so a generator using the wrong prime or base disagrees with its own group -- zero and one yield a shared secret of zero or one whatever the private exponent is, which a round-trip test cannot notice |
| Post-quantum | ML-KEM-768, sntrup761 (+ hybrid x25519 KEX) | NIST / live vs OpenSSH sntrup761x25519; the method names are pinned as a table, because `ssh_lib` carries no list of its own -- it offers whatever `Is_Implemented` admits, so these predicates alone decide what is negotiated, which KEM then runs, and which hash combines the two shared secrets. A name in the wrong family runs the wrong KEM and one under the wrong combiner derives a different key; the peer is the only party that would notice either |
| X.509 (`Certificates`) | local CA, server/client/email issuance, CSR signing, PKCS#12 | a certificate's times must name dates that exist -- the day is checked against its month with the Gregorian leap rule, so the 31st of February is refused as OpenSSL refuses it, rather than decoding and keeping a certificate valid past the end of the month; a certificate issued under a CA is cut short at the CA's own expiry rather than claiming validity the chain will not have once the issuer runs out; a request is signed only for a name of the kind the profile admits -- the common name it asks for becomes the certificate's dNSName, and one carrying spaces or punctuation is refused rather than certified, as the profile paths have always done and this path did not; a request is signed for the key it asks about, checked by reading the issued certificate back, for Ed25519, P-384, Ed448 and RSA alike -- the subject's key goes in as the request encoded it, so signing a request needs no ability to generate that kind of key, only to check the signature proving the requester holds it, and one whose own signature does not check is refused rather than certified; PKCS#12 MAC key byte-exact vs OpenSSL; issued Ed25519, P-256, P-384 and Ed448 certificates chain-verified against their CA by OpenSSL in the suite, each with the key issued alongside it checked to belong to it -- and that cross-check earns its place: P-256 issuance arrived with a leaf key generated on the wrong curve, because the branch choosing the key algorithm was an `if` chain whose `else` fell through to Ed25519, so the certificate said P-256 and carried an Ed25519 key. Nothing in the type system objected and nothing inside this crate noticed; OpenSSL refusing the chain is what found it. Both such chains in that file are `case` statements now, which the compiler holds exhaustive; serials are 128-bit random and distinct per certificate; key identifiers match an independent SHA-1 over the public key bits, and OpenSSL refuses the chain if the authority identifier names the wrong key |
| PBES2 (`PBES2`, `PKCS8`, `PKCS12`) | password-based decryption: PBKDF2 over HMAC-SHA1/256/384/512, AES-128/192/256-CBC | keys written by `openssl pkcs8 -topk8` open to the byte-identical scalar OpenSSL holds; a wrong password is refused |
| PKCS#12 (`PKCS12`) | reading a bundle, MAC verified before its contents are parsed | bundles written by this crate and by `openssl pkcs12 -export` both open, including OpenSSL's default layout with the certificates in encrypted content; the extracted certificates hash identically to the originals |
| RSA | PKCS#1 v1.5 and PSS signing and verification, SHA-256/384/512; 2048/3072/4096-bit key generation | signatures produced by OpenSSL at 2048 and 3072 bits; a cube-root forgery against a low exponent is refused; PSS checked at both salt lengths OpenSSL emits, and a signature does not verify under a salt length or hash other than the one its parameters state; signing is pinned byte for byte against an independent Python implementation confirmed by pyca -- PKCS#1 v1.5, which is deterministic, and PSS at salt length zero, which is the only way to hold a randomised scheme to an exact answer -- with OpenSSL verifying signatures this crate made at a real salt length, two signatures over one message required to differ, and a salt-32 signature required not to verify as salt-0 |
| Certificate policies (`X509.Policies`) | RFC 5280 §6.1 policy tree, mapping, and the three counters | every verdict cross-checked against `openssl verify -policy_check -policy ...` on the same chains: explicit-policy demands, a policy no issuer granted, anyPolicy, anyPolicy withdrawn by `inhibitAnyPolicy`, a mapped policy, and mapping inhibited |
| X.509 parsing (`ASN1`, `PEM`, `X509.*`) | DER reader, PEM armour, certificate decode, extensions, signature verification | field-by-field against `openssl x509 -text` on the same certificates; an OpenSSL-issued RSA chain verifies here and under `openssl verify`; the 122 system roots parse identically before and after the ambiguity checks below. Re-measured against the store on this machine: all 122 decode, every `notAfter` agrees with `openssl x509 -enddate`, and 117 of the self-signatures verify here. The other five are `sha1WithRSAEncryption`, which this does not verify and reports as unchecked -- none of the 122 comes back as an invalid signature, which is the answer that would mean this crate believes a real root was tampered with |
| Revocation (`X509.CRLs`, `OCSP`) | CRL and OCSP parsing and signature checking | against a CRL and OCSP responses OpenSSL produced through `openssl ca -revoke`; the request builder is byte-identical to `openssl ocsp -reqout`, with and without a nonce; a delegate without OCSP-signing authority is refused; revocation times and reasons match `openssl crl -text`, and the CRL and OCSP paths agree with each other on the same certificate, and agree on what a serial number is -- one comparison serves both, reading a serial as a number so that a padded encoding is not taken for a different certificate, which on this path would look like not being revoked; a CRL scoped by a critical `issuingDistributionPoint` is refused rather than read as a complete list; a statement that names no `nextUpdate` -- which is optional in both a CRL and an OCSP response, and left it with no window to be outside of -- is believed only for `Maximum_Age_Days` from when it was issued, seven by default, because replaying a genuine old "nothing revoked" needs no forgery; a validly signed OCSP response carrying an unrecognised critical extension is refused, in its own extensions or in the entry about the certificate |
| Key fingerprints (`Fingerprints`) | OpenSSH MD5 and SHA-256 renderings | byte-identical to what `ssh-keygen -l` prints for the same key blobs, Ed25519 and RSA, including that the SHA-256 form carries no base64 padding |
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
  Its shape is held to a jump budget, which says nothing about whether it
  answers correctly, so a difference at each of the eight byte positions is
  checked separately along with mismatched lengths -- a comparison that runs
  one byte short is right about all the others.

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

## Output buffers on failure

Separate from wiping secrets: every entry point in `Ciphers`,
`ChaCha20_Poly1305`, `ECDSA`, `BCrypt_PBKDF`, `HKDF`, `Ed25519`, `Ed448`,
`Curve25519` and `Random` that takes an `out` buffer zeroes it before doing
anything else, so a status other than `Ok` leaves that buffer zero rather than
holding a partial result, an unauthenticated plaintext, or the caller's own
stale bytes. The two AEAD `Open` paths and ChaCha's go further and verify the
tag *before* computing any plaintext, so a forged packet never produces
plaintext that then has to be discarded.

This is a plain `[others => 0]`, not `Secure_Wipe`, and deliberately so: the
target is a caller-visible `out` parameter that is read after the call
returns, so it is not a dead store and the optimizer cannot remove it. The
same assignment on a local before return would be removed, which is what
`Secure_Wipe` exists for.

Pinned by `Check_Zero_On_Failure`, which pre-fills each buffer with a non-zero
pattern, forces the refusal, and inspects what is left -- a bad GCM tag, a bad
ChaCha tag, an unknown cipher name, an uninitialized streaming context, a
wrong-width ECDSA signature or public point, a zero bcrypt round count, and
HKDF one octet past its 255-block ceiling. Deleting the zeroing at either of
two representative sites was confirmed to fail the suite.

Callers must still check the status. An all-zero buffer is a plausible
plaintext, not a sentinel.

## Entry points the consumers reach for

Coverage here was audited against what the downstream crates actually call,
not only against what looked important from inside. Six public entry points
turned out to be exercised in shipping code and by nothing in this suite:
`Ciphers.AES_GCM_Key_Length`, `Ciphers.Encrypt_GCM_Length`,
`Hybrid_PQ_Kex.Is_OpenSSH_Hybrid_PQ_Kex_Name` and `X509.Policies.Encoded_Value`
(`ssh_lib`), and `Ciphers.Is_Active` and `Errors.Is_Success` (`versionlib`).

Every public subprogram in the library is now named by the suite: the audit
that found those six was run to exhaustion, and the count of subprograms
neither tested here nor called anywhere else in the library is zero. The last
of them were ML-KEM's algebraic core, the two self-describing manifests, and a
handful of small helpers.

The ML-KEM core is checked by identity rather than by stored vectors, with one
deliberately independent anchor: `Ring_Multiply_Reference` is held against a
negacyclic convolution written out longhand in the test. That anchor has to
exist because `Pointwise_Multiply` is implemented as `NTT (reference multiply
(inverse NTT of each operand))` -- it is not a separate fast path -- so
comparing the two would compare the reference multiply with itself and pass
however wrong it was. Everything else chains off the verified base: the NTT
round-trips, twelve-bit encoding is exact, a message survives its polynomial,
the compressed encodings stay inside the FIPS 203 error bound and are checked
to actually be lossy, matrix sampling depends on both row and column, and
centred binomial noise stays within eta2. Making the reference multiply cyclic
instead of negacyclic fails the suite.

`Check_Consumer_Entry_Points` holds each to the code that consumes its answer
rather than to a restatement of its body: the GCM key length is checked to be
the length `Seal_GCM` accepts and one octet short is checked to be refused, so
it cannot be a self-consistent wrong number; the hybrid-PQ predicate must agree
with `Kind_Of` in both directions and carry wire lengths exactly when it says
hybrid; `Is_Success` is swept across the whole `Status` enumeration so a value
added later cannot quietly join the success side. Teeth-checked: reporting 16
octets for `aes256-gcm@openssh.com` and admitting `End_Of_Stream` as success
each fail the suite.

## Randomness

`Random` in `Production_Mode` delegates to `OS_Random.Fill_OS`, selected per OS
by the project file (`src-linux` / `src-windows`):

- **Linux** — `getrandom(2)` (blocks until the kernel CSPRNG is seeded),
  `/dev/urandom` fallback.
- **Windows** — `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`.
  **Never run.** There is no Windows toolchain or emulator on the machines
  this has been developed on, so the binding has been read against the
  documented API rather than exercised: a null algorithm handle, which is
  what that flag requires; only `STATUS_SUCCESS` accepted, so a warning
  status is a failure rather than randomness; the buffer zeroed before the
  call and again if it fails; `ULONG` and `NTSTATUS` written as
  `Interfaces.Unsigned_32` and `Integer_32` rather than the C long types,
  because Windows fixes both at 32 bits whatever the word size and the C
  types would follow the target compiler instead. The release preflight
  compiles it for semantics on every run, which catches it rotting against
  a changed spec but says nothing about whether the call is right. Treat it
  as unproven until somebody runs it on Windows.

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
- **RSA signs blinded, generates keys, and has no CRT.** PKCS#1 v1.5 and PSS
  both sign and verify, and keys are generated at 2048, 3072 and 4096 bits.
  The private exponentiation goes through `CryptoLib.Modexp`, which is
  word-serial constant-time Montgomery, and every signature is verified
  against the public exponent before it is returned -- a faulty RSA signature
  released beside a correct one can give up the factorisation, so nothing
  leaves unchecked.

  The private operation is **blinded**: a fresh random r is drawn per
  signature, the input is multiplied by r^e before exponentiating and the
  result by r^-1 after, so what the exponentiation sees is uniformly random
  and unrelated to the message while the signature is unchanged. Signing
  **fails closed** if no blinding factor can be drawn rather than falling back
  to unblinded. Blinding cannot be observed in the output -- the signature is
  identical with or without it, and the byte-exact vectors pass either way --
  so that fail-closed behaviour is the only black-box evidence it is being
  done, and it is what the suite checks. Removing the blinding fails there and
  nowhere else.

  Omitting CRT costs roughly a factor of four in signing speed and removes the
  fault mode CRT is notorious for; it is also why the CRT parameters in a
  PKCS#8 key are parsed past rather than surfaced.

  Key generation draws two primes with their top two bits set, trial-divides
  by the primes below 1000, and runs 24 Miller-Rabin rounds. The private
  exponent is required to exceed the square root of the modulus, which puts it
  out of reach of Wiener's continued-fraction attack, and the primes are
  required to be far enough apart that Fermat's method does not apply. Before
  a key is returned it is used: a signature is made and verified, so a modulus
  or exponent that is subtly wrong never leaves. Generated keys were checked
  from outside -- pyca recovered p and q from (n, e, d), confirmed both prime
  and their product equal to n, and built a working private key from them.
  That self-check has a cost worth knowing: it turns a wrong private exponent
  into a retry rather than a failure, so the modular inverse is tested
  directly in `CryptoLib.Bignum` rather than through key generation, which
  hides it.

  The arithmetic key generation needs is `CryptoLib.Bignum`, written on plain
  arrays rather than GNAT's Big_Integers, because a Big_Integer holds its
  digits in controlled storage this crate cannot reach: a prime or a private
  exponent living there could not be scrubbed. It has no general big division
  and needs none. With a public exponent of 65537 the only division is by a
  machine integer, and one such division makes the extended Euclid small
  enough to finish in Integer arithmetic; the inverse blinding needs, where
  the value is as large as the modulus, uses the binary extended Euclid
  instead -- halvings, additions and comparisons, and no division either.
  Every operation was checked against Python over random inputs before
  anything was built on it.

  `X509.Signatures` reports
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
- **A certificate must not disagree with itself about how it was signed.**
  The signature algorithm appears twice: inside the TBS, covered by the
  signature, and outside it, where it is not. Only the inner copy is
  protected, so the outer one can be changed by anyone holding the file, and
  a verifier reading the algorithm from there is being told how to check a
  signature by whoever touched it last. RFC 5280 requires the two to agree
  and this refuses the certificate at decode when they do not -- pinned
  against a pair carrying the same substitution, applied to the outer copy
  alone and to both, where only the disagreeing one is refused.
- **The oldest chain questions are pinned, not assumed.** How deep a CA may
  delegate (`pathLenConstraint`), whether an issuer is a CA at all, and
  whether it is permitted to sign certificates are each asserted against a
  chain built to break them -- a genuine intermediate issuing below a
  `pathlen:0` root, an issuer whose own basic constraints say `CA:FALSE`, and
  a CA whose key usage omits `keyCertSign`. In each the signature over the
  leaf is perfectly good, which is what makes the check the only thing
  standing there. Name constraints are asserted against the intermediate's
  own name as well as the leaf's, since a constrained CA may not issue a CA
  named outside its subtree either. OpenSSL refuses all four.
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
  Widened since against the machine's own trust store: 488,000 mutations
  seeded from each of the 122 system roots in turn, so the seeds carry a
  decade of real encodings from a hundred issuers rather than certificates
  this crate wrote. None raised. The same store also agrees with
  `openssl x509 -text` on every root about whether it is a CA, whether it
  may sign certificates and CRLs, and whether it carries a subject key
  identifier -- 122 of 122, the fields a chain is actually judged on.
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
