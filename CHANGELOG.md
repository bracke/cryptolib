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

## Releasing

No procedure yet.
