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

## Releasing

No procedure yet.
