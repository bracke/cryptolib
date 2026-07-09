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
| `CryptoLib.ECDSA` | ECDSA P-384/P-521 signing (RFC 6979 deterministic) |
| `CryptoLib.Diffie_Hellman` | finite-field DH groups 1/14/16/18 |
| `CryptoLib.MLKEM768`, `CryptoLib.SNTRUP761`, `CryptoLib.Hybrid_PQ_KEX` | post-quantum KEMs + hybrid x25519 |
| `CryptoLib.Random` | CSPRNG (getrandom/urandom/BCryptGenRandom), fail-closed |
| `CryptoLib.Secure_Wipe` | non-elidable secret zeroization |
| `CryptoLib.Constant_Time` | constant-time byte comparison |
| `CryptoLib.Errors`, `CryptoLib.Buffers`, `CryptoLib.Fingerprints` | status codes, packet buffers, key fingerprints |

## Conventions

- **Data is `Ada.Streams.Stream_Element_Array`.** Fixed-size outputs (digests,
  keys) are small array types like `Hashes.SHA256_Digest`.
- **Operations that can fail return `CryptoLib.Errors.Status`** and write results
  to `out` parameters. Check for `CryptoLib.Errors.Ok`. The library **fails
  closed** — on any error the `out` result is zeroed rather than left partial.
- **No exceptions escape** the public API for ordinary failures; they map to a
  `Status`.

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
