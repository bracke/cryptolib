# Changelog

## 0.1.0-dev

Initial development release. Nothing has been published to the Alire index yet,
so everything below is the state of this version rather than a change against a
predecessor.

* Pure Ada 2022 crate with no Alire dependencies and no runtime OpenSSL
  dependency. Every package is `CryptoLib.*`. The test crate links libcrypto,
  and only the test crate: it is how the suite asks an independent
  implementation whether a certificate this crate issued actually chains.
* Hashes and MACs: SHA-1, SHA-256, SHA-384, SHA-512, SHA-3, UMAC, and the
  shared `Hashes`, `Macs`, `Checksums` and `Fingerprints` interfaces.
* Password hashing: bcrypt (`$2b$`), hashing and verification, on a Blowfish
  key schedule extracted from `BCrypt_PBKDF` so the two share one copy. The
  shared package is a private child, so the cipher is reachable from inside
  `CryptoLib` and not from a caller.
* Password hashing: Argon2d, Argon2i and Argon2id (RFC 9106) over a new
  BLAKE2b (RFC 7693). Argon2id is the one to reach for. scrypt (RFC 7914) and
  `bcrypt_pbkdf` were already here.
* Key derivation: HKDF (RFC 5869), the TLS 1.3 schedule (`TLS13_KDF`, RFC 8446
  §7.1), PBES2, and `bcrypt_pbkdf`.
* Ciphers and AEAD: `Ciphers`, and ChaCha20-Poly1305 in both constructions --
  the OpenSSH one (`Seal`/`Open`) and RFC 8439's (`Seal_AEAD`/`Open_AEAD`).
  AES uses a bit-sliced S-box rather than a lookup table, trading speed for the
  absence of a cache-timing channel.
* Finite-field Diffie-Hellman over the RFC 7919 named groups (`FFDHE`):
  ffdhe2048 through ffdhe8192, the groups TLS negotiates, distinct from the SSH
  MODP groups. Primes derived from the RFC's construction and confirmed by
  OpenSSL naming them back from p and g alone.
* X448 key agreement (RFC 7748), which the crate lacked while carrying Ed448
  signatures. Both are over p = 2**448 - 2**224 - 1 and now share one field
  arithmetic, `CryptoLib.Field448`, a private child.
* Key agreement: X25519, finite-field Diffie-Hellman over the fixed-width
  Montgomery `Modexp` rather than `Big_Integers`, ECDH on P-256/384/521 with
  full peer-point validation, and a hybrid post-quantum exchange.
* Signatures: Ed25519, Ed448, ECDSA on P-256/384/521 with RFC 6979 deterministic
  nonces, and RSA -- PKCS#1 v1.5 and PSS, verification and signing, with key
  generation, base blinding, and CRT.
* Post-quantum KEMs: ML-KEM-768 and sntrup761.
* X.509: parsing, validation, path building, name constraints, policies,
  purposes, revocation (CRL and OCSP), and issuance of CA, server, client and
  email certificates for Ed25519, Ed448, P-256, P-384 and RSA keys.
* Encodings: ASN.1/DER with canonical-form enforcement, PEM, PKCS#8, PKCS#10,
  PKCS#12, and OID handling.
* Constant-time discipline: `Constant_Time` for comparisons, `Secure_Wipe` for
  scrubbing through an object's own address, and `Constant_Time_Assurance` and
  `Constant_Time_Proof` for the properties the crate asserts about itself.
  `tools/bin/check_constant_time` inspects the generated code against recorded
  budgets; there is no automated gate beyond it.
* Per-OS entropy backends in `src-linux`, `src-macos` and `src-windows`,
  selected by `Source_Dirs`. The release preflight semantically checks all
  three, so the two a given host does not build cannot rot unnoticed. The
  Windows backend (`BCryptGenRandom`) has never been run on Windows -- see
  `SECURITY.md`.
* The test suite is AUnit: `tests/src/tests.adb` is the runner, `tests_suite`
  assembles one `AUnit.Test_Cases.Test_Case` per topic, and each topic package
  registers its checks as individual routines. 136 tests over 14 packages,
  asserting through `Tests_Support.Check`. It was a single 17,439-line
  procedure that raised on the first failed assertion and hid every check
  after it; now each check is a test of its own, a failure names itself, and
  the rest of the suite still runs.
* The style and warning bar is enforced rather than printed: the preflight
  builds the library and then the suite with `--validation`, where `-gnatwe`
  makes every warning and style breach an error. Alire's `release` profile
  carries no warning or style switches at all, so a release build had never had
  an opinion about either; switching the gate on found three breaches in the
  library and 129 in the suite.
* Release preflight (`tools/bin/check_release_ready`): a forced build, the
  constant-time check, every per-OS backend, the test suite, the Alire manifest,
  the test suite's own shape, the README examples, and GNATdoc tags. CI runs it.
