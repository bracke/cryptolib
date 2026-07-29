# CryptoLib

A pure Ada 2022 (Alire/GNAT) cryptographic primitive library — hashes, MACs/KDFs,
symmetric ciphers and AEAD, elliptic-curve and finite-field key agreement,
signatures, and post-quantum KEMs. It has no dependency on OpenSSL at all — the
cross-check reference vectors were generated offline (pyca/OpenSSL, RFC/NIST) and
are embedded in the test suite, which links nothing beyond the Ada runtime.

For the security properties, constant-time guarantees, and known limitations, see
[`SECURITY.md`](SECURITY.md).

## Toolchain

CryptoLib must be built and validated with Alire GNAT 15 only. The root, tests,
and tools crates require `gnat_native = "^15"`. Confirm with:

```sh
alr exec -- gnatls --version
```

Do not run plain system `gnat*`, `gnatmake`, `gnatls`, `gnatprove`,
`gcc -gnat*`, or `gprbuild` in this workspace.

## Package map

| Package | What it provides |
|---------|------------------|
| `CryptoLib.Hashes` | MD5, SHA-1, SHA-256/384/512, XXH3 |
| `CryptoLib.Checksums` | Adler-32 and CRC-32 |
| `CryptoLib.SHA3` | SHA3-256/512, SHAKE128/256 |
| `CryptoLib.Macs` | HMAC-SHA1/256/384/512, PBKDF2, PBKDF1, PKCS12KDF |
| `CryptoLib.UMAC` | UMAC-64/128 (RFC 4418) |
| `CryptoLib.Bcrypt_PBKDF` | bcrypt-PBKDF (OpenSSH key derivation) |
| `CryptoLib.Ciphers` | AES-128/192/256 (CTR/CBC/GCM), 3DES, RC2 |
| `CryptoLib.ChaCha20_Poly1305` | ChaCha20-Poly1305 AEAD (OpenSSH transport framing) |
| `CryptoLib.Curve25519` | X25519 key agreement |
| `CryptoLib.Ed25519` | Ed25519 signatures |
| `CryptoLib.ECDSA` | ECDSA P-384/P-521 signing (RFC 6979 deterministic); P-256/P-384/P-521 verification with any of SHA-256/384/512 and public-key derivation |
| `CryptoLib.Diffie_Hellman` | finite-field DH groups 1/14/16/18 |
| `CryptoLib.MLKEM768`, `CryptoLib.SNTRUP761`, `CryptoLib.Hybrid_PQ_KEX` | post-quantum KEMs + hybrid x25519 |
| `CryptoLib.Random` | CSPRNG (getrandom/urandom/BCryptGenRandom), fail-closed |
| `CryptoLib.Secure_Wipe` | non-elidable secret zeroization |
| `CryptoLib.Constant_Time` | constant-time byte comparison |
| `CryptoLib.RSA` | RSA PKCS#1 v1.5 and PSS signature verification (SHA-256/384/512) |
| `CryptoLib.ASN1`, `CryptoLib.ASN1.DER`, `CryptoLib.ASN1.OIDs` | defensive bounded DER reader, object identifiers |
| `CryptoLib.PEM` | strict PEM armour decoding, multi-block |
| `CryptoLib.PKCS10` | certification requests: decode, read the subject and key, check proof of possession |
| `CryptoLib.PKCS8` | private keys, plain or PBES2-encrypted; wipes its own storage when it goes out of scope |
| `CryptoLib.PBES2` | password-based decryption shared by PKCS#8 and PKCS#12 |
| `CryptoLib.PKCS12` | read a bundle: MAC first, then its certificates and key |
| `CryptoLib.Identities` | a chain and its key, checked to belong together before use |
| `CryptoLib.X509.Certificates` | parsed X.509 certificates: inspection, extensions, signature verification |
| `CryptoLib.X509.Extensions` | basic constraints, key usage, alternative names, and where a certificate says to fetch its CRL or ask its responder |
| `CryptoLib.X509.Validation` | path validation against explicit trust anchors, policy processing included (no path building, no revocation) |
| `CryptoLib.X509.Policies` | certificate policies and RFC 5280 §6.1 processing: the policy tree, policy mapping, and the explicit-policy, mapping and anyPolicy counters |
| `CryptoLib.X509.Name_Constraints` | DNS, IP, directory-name, URI and mail subtrees a constrained CA may certify, enforced by the validator |
| `CryptoLib.X509.Identity` | RFC 9525 service identity matching: DNS names, wildcards, IP addresses |
| `CryptoLib.X509.Purposes` | may this certificate serve TLS, sign code, act as a CA |
| `CryptoLib.X509.Names` | distinguished names by attribute; RFC 4514 formatting kept separate |
| `CryptoLib.X509.CRLs` | revocation lists: decode, verify the issuer's signature, look a serial up, and read when it was revoked and why |
| `CryptoLib.OCSP` | OCSP requests and responses, including responder authorisation |
| `CryptoLib.X509.Revocation` | ask a CRL or an OCSP response about a certificate, freshness included |
| `CryptoLib.X509.Path_Building` | search for a path to a trust anchor; proposes, never concludes |
| `CryptoLib.Certificates` | X.509: local CA, server/client/email issuance, CSR signing, PKCS#12, fingerprints; issued certificates carry a random serial, a validity window from the clock, and key identifiers |
| `CryptoLib.Errors`, `CryptoLib.Buffers`, `CryptoLib.Fingerprints` | status codes, packet buffers, key fingerprints |

The snippets below are fragments, chosen to show the call rather than a whole
program. `examples/` holds compilable counterparts that the release preflight
builds.

## Conventions

- **Data is `Ada.Streams.Stream_Element_Array`.** Fixed-size outputs (digests,
  keys) are small array types like `Hashes.SHA256_Digest`.
- **Operations that can fail return `CryptoLib.Errors.Status`** and write results
  to `out` parameters. Check for `CryptoLib.Errors.Ok`. The library **fails
  closed** — on any error the `out` result is zeroed rather than left partial.
- **No exceptions escape** the public API for ordinary failures; they map to a
  `Status`.
- **Defaults that cost time or expire are stated, not buried.** An issued
  certificate is valid for 397 days from the moment it is issued, not for a
  decade; a PKCS#12 bundle takes 600,000 PBKDF2 iterations to open. Both are
  parameters — `Valid_Days` on the issuing calls, `Iterations` on
  `Generate_PKCS12` — and `PKCS12.Open` takes `Maximum_Iterations` so a
  caller opening bundles it did not write can say what it is willing to
  spend. `SECURITY.md` explains why each is what it is.

## Quickstart

### Hash

```ada
with CryptoLib.Hashes;
--  Message : Ada.Streams.Stream_Element_Array
declare
   Digest : constant CryptoLib.Hashes.SHA256_Digest :=
     CryptoLib.Hashes.SHA256 (Message);   --  32-byte Stream_Element array
begin
   null;
end;
```

### HMAC and PBKDF2

```ada
with CryptoLib.Macs;
Tag : constant CryptoLib.Macs.HMAC_SHA256_Digest :=
  CryptoLib.Macs.HMAC_SHA256 (Key_Bytes, Message_Bytes);

Derived_Key : constant Ada.Streams.Stream_Element_Array :=
  CryptoLib.Macs.PBKDF2_HMAC_SHA256
    (Password_Data => Password_Bytes,
     Salt_Data     => Salt_Bytes,
     Iterations    => 100_000,
     Output_Length => 32);
```

### AEAD (ChaCha20-Poly1305)

`Seal`/`Open` use the `chacha20-poly1305@openssh.com` transport framing: the
`Sequence` value is the packet sequence number (the nonce), and the sealed
`Wire_Packet` is `Plain_Packet'Length + Tag_Length` bytes.

```ada
with CryptoLib.ChaCha20_Poly1305;   use CryptoLib;
--  Key : 64-byte key; Seq : Interfaces.Unsigned_32; Plain : Stream_Element_Array
Wire : Ada.Streams.Stream_Element_Array
  (Plain'First .. Plain'Last
                  + Ada.Streams.Stream_Element_Offset (ChaCha20_Poly1305.Tag_Length));
Back : Ada.Streams.Stream_Element_Array (Plain'Range);
St   : Errors.Status;
begin
   St := ChaCha20_Poly1305.Seal (Key, Seq, Plain, Wire);   --  encrypt + tag
   --  ...
   St := ChaCha20_Poly1305.Open (Key, Seq, Wire, Back);    --  Authentication_Failed on tamper
```

(`CryptoLib.Ciphers` offers AES-GCM/CTR/CBC with the same `Status` idiom.)

### X25519 key agreement

```ada
with CryptoLib.Curve25519;   use CryptoLib;
with CryptoLib.Random;
Rng    : Random.Random_Source;
Priv   : Curve25519.Private_Key;
Pub    : Curve25519.Public_Key;   --  send Pub to the peer
Secret : Curve25519.Public_Key;   --  the 32-byte shared secret
St     : Errors.Status;
begin
   Random.Initialize_Production (Rng);
   St := Curve25519.Generate_Keypair (Rng, Priv, Pub);
   --  receive Peer_Public : Curve25519.Public_Key
   St := Curve25519.Shared_Secret (Priv, Peer_Public, Secret);
   --  St = Handshake_Failed if the peer sent a low-order point (all-zero secret)
   Curve25519.Clear (Priv);   --  scrub the private scalar when done
```

### Ed25519 signatures

```ada
with CryptoLib.Ed25519;   use CryptoLib;
--  Seed : 32-byte private seed; Pub : 32-byte public key; Message : bytes
Sig : Ada.Streams.Stream_Element_Array
  (1 .. Ada.Streams.Stream_Element_Offset (Ed25519.Signature_Length));  --  64
St  : Errors.Status;
begin
   St := Ed25519.Sign (Seed, Pub, Message, Sig);
   --  verify (returns Ok only for a valid, canonical signature):
   St := Ed25519.Verify (Pub, Sig, Message);
```

### Random bytes

```ada
with CryptoLib.Random;   use CryptoLib;
Rng : Random.Random_Source;
Buf : Ada.Streams.Stream_Element_Array (1 .. 32);
St  : Errors.Status;
begin
   Random.Initialize_Production (Rng);
   St := Random.Fill (Rng, Buf);   --  St /= Ok => no OS entropy; Buf is zeroed
```

### Scrub secrets

```ada
with CryptoLib.Secure_Wipe;
--  Secret : any local holding key/nonce material
CryptoLib.Secure_Wipe.Wipe (Secret'Address, Secret'Length);
```

## Build and test

```sh
alr build                                   # build the library
(cd tests && alr build) && ./tests/bin/tests  # run the KAT + negative-test suite
```

The suite prints `cryptolib tests passed` on success. See [`SECURITY.md`](SECURITY.md)
for what each test validates.
