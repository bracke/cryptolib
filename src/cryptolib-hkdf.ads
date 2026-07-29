with Ada.Streams;
with CryptoLib.Errors;

--  @summary HKDF (RFC 5869) extract-and-expand key derivation over
--  HMAC-SHA-256/384/512.
--
--  For turning material that is already unguessable -- a Diffie-Hellman
--  shared secret, a KEM output, a key read from a file -- into as many
--  independent keys as a protocol needs. It is deliberately fast, and that
--  is the whole difference from the other derivations here: PBKDF2, PBKDF1,
--  PKCS12KDF and bcrypt_pbkdf exist to be slow, because their input is a
--  password somebody chose. Handing HKDF a password would derive from it at
--  the speed of one HMAC, which is the speed an attacker guesses at.
--
--  The two halves are separate because RFC 5869 says they may be used
--  apart. Extract concentrates whatever entropy the input has into one
--  pseudorandom key; Expand stretches that key into output, bound to a
--  context string. A caller whose input is already a uniformly random key
--  of the right length may skip Extract and Expand from it directly, which
--  is what TLS 1.3 does between handshake stages.
--
--  SHA-1 is not offered. It exists in this crate for reading formats that
--  predate the alternatives, and nothing needs an HKDF that speaks it.
package CryptoLib.HKDF is

   --  Which HMAC the derivation runs on. The choice fixes the length of a
   --  pseudorandom key and the ceiling on how much output can be asked for.
   type Hash_Algorithm is (SHA256, SHA384, SHA512);

   --  The length of the pseudorandom key Extract produces, which is the
   --  underlying hash's own output length.
   --  @param Hash the hash the derivation runs on
   --  @return 32, 48 or 64 octets
   function PRK_Length (Hash : Hash_Algorithm) return Positive;

   --  The most output Expand can produce for a hash: RFC 5869 counts the
   --  blocks with one octet, so it stops at 255 of them.
   --  @param Hash the hash the derivation runs on
   --  @return the largest Output_Length that will not be refused
   function Maximum_Output (Hash : Hash_Algorithm) return Positive;

   --  RFC 5869 section 2.2: concentrate the input keying material into a
   --  pseudorandom key.
   --
   --  The salt need not be secret and need not be random; it may be empty,
   --  which the RFC defines as a string of zeros as long as the hash output
   --  rather than as an error. A salt still helps: it separates derivations
   --  that would otherwise share an input.
   --  @param Hash               the hash the derivation runs on
   --  @param Salt               the salt, possibly empty
   --  @param Input_Key_Material the secret to derive from
   --  @param PRK                out: the pseudorandom key, PRK_Length octets,
   --    zeroed on failure
   --  @return Ok, or Handshake_Failed when PRK is not PRK_Length octets
   function Extract
     (Hash               : Hash_Algorithm;
      Salt               : Ada.Streams.Stream_Element_Array;
      Input_Key_Material : Ada.Streams.Stream_Element_Array;
      PRK                : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  RFC 5869 section 2.3: stretch a pseudorandom key into output keying
   --  material.
   --
   --  Info is what separates one key from another drawn from the same PRK:
   --  two Expands differing only in Info give unrelated output, which is how
   --  a protocol derives an encryption key and a MAC key from one exchange.
   --  It is not secret.
   --  @param Hash   the hash the derivation runs on
   --  @param PRK    the pseudorandom key, at least PRK_Length octets
   --  @param Info   the context string, possibly empty
   --  @param Output out: the derived key material, zeroed on failure
   --  @return Ok, Handshake_Failed when the PRK is too short, or
   --    Unsupported_Feature when more output is asked for than
   --    Maximum_Output
   function Expand
     (Hash   : Hash_Algorithm;
      PRK    : Ada.Streams.Stream_Element_Array;
      Info   : Ada.Streams.Stream_Element_Array;
      Output : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Extract then Expand, for the ordinary case where a caller has a
   --  secret and wants keys from it.
   --  @param Hash               the hash the derivation runs on
   --  @param Salt               the salt, possibly empty
   --  @param Input_Key_Material the secret to derive from
   --  @param Info               the context string, possibly empty
   --  @param Output             out: the derived key material, zeroed on
   --    failure
   --  @return Ok, or the status Extract or Expand refused with
   function Derive
     (Hash               : Hash_Algorithm;
      Salt               : Ada.Streams.Stream_Element_Array;
      Input_Key_Material : Ada.Streams.Stream_Element_Array;
      Info               : Ada.Streams.Stream_Element_Array;
      Output             : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

end CryptoLib.HKDF;
