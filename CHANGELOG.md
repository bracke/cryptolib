# Changelog

Notable changes to cryptolib. Format follows [Keep a Changelog](https://keepachangelog.com/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`0.1.0-dev`, no tag: consumers — ssllib among them, which reaches the network
through this crate's AEADs, hashes and constant-time primitives — pin it **by
path**, so the commit is the version.

This file starts where it was written rather than reconstructing two hundred
commits; each of those says what it changed.

## [Unreleased]

### Added

- Argon2: `Verify`, so the recommended password hash can be checked without a
  caller writing its own comparison, and the PHC string encoding beside it.
- The ECDSA DER signature encoder and decoder.
- Tests for the ML-KEM and Argon2 entry points that nothing executed.

### Changed

- AES and GHASH run on the processor's AES-NI and PCLMULQDQ instructions where
  CPUID reports both (x86-64), in data-independent time as the bitsliced code
  does, and several hundred times faster: a TLS download through ssllib went
  from 1.2 MB/s at a full core to the link's speed at a tenth of one. The
  bitsliced AES and bitwise GHASH remain the portable path, and the one used
  elsewhere. The expanded key is kept also as round-key blocks
  (`Round_Blocks`), the form the instructions take.
- SHA-256 runs on the processor's SHA extensions where CPUID reports them
  (x86-64), and `Update` hashes whole blocks where they lie instead of copying
  and counting each byte: 66 to 312 MB/s, the digest unchanged. Every hub
  download is hashed as it arrives.
- ChaCha20 computes eight blocks at once, each state word a row of eight lanes
  the compiler turns into vector instructions (built at -O3, validity checks
  off for that unit), and Poly1305 takes whole blocks in one copy: 62 to 325
  MB/s, output matching pyca/cryptography at lengths on both sides of the
  eight-block boundary.

## Releasing

No procedure yet.
