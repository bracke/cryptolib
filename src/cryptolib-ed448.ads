with Ada.Streams;
with CryptoLib.Errors;
with CryptoLib.Random;

--  @summary Ed448 (RFC 8032 PureEdDSA over edwards448) sign and verify.
--
--  Constant-time signing over the untwisted Edwards curve edwards448 with
--  SHAKE256 hashing; seeds and public keys are 57 bytes and signatures are
--  114 bytes (R || S).  Point arithmetic uses the complete projective
--  addition of RFC 8032 5.2.4 and a double-and-add-always ladder with
--  branchless selects, so no operand or bit of the scalar decides a branch.
--
--  This is the pure variant with an empty context, which is what "Ed448"
--  means in a certificate or an SSH key.  Ed448ph, and a context other than
--  the empty one, would hash a different prefix and are not offered rather
--  than being silently treated as the same thing.
package CryptoLib.Ed448 is

   Seed_Length       : constant Natural := 57;
   Public_Key_Length : constant Natural := 57;
   Signature_Length  : constant Natural := 114;

   --  Generate an Ed448 seed and matching public key.
   --  @param Rng the configured random source used to fill the private seed
   --  @param Seed_Bytes out: 57-byte private seed, zeroed on failure
   --  @param Public_Key_Bytes out: 57-byte public key, zeroed on failure
   --  @return Ok on success, Handshake_Failed on wrong-length arguments,
   --          Internal_Error when random generation or derivation fails
   function Generate_Keypair
     (Rng              : in out CryptoLib.Random.Random_Source;
      Seed_Bytes       : out Ada.Streams.Stream_Element_Array;
      Public_Key_Bytes : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Derive an Ed448 public key from a 57-byte private seed.
   --  @param Seed_Bytes the 57-byte private seed
   --  @param Public_Key_Bytes out: 57-byte public key, zeroed on failure
   --  @return Ok on success, Handshake_Failed on wrong-length arguments
   function Public_Key_From_Seed
     (Seed_Bytes       : Ada.Streams.Stream_Element_Array;
      Public_Key_Bytes : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Produce an Ed448 signature over Message_Bytes.
   --  @param Seed_Bytes       the 57-byte private seed
   --  @param Public_Key_Bytes the signer's 57-byte public key
   --  @param Message_Bytes    the message to sign (any length)
   --  @param Signature_Bytes  out: the 114-byte signature R || S
   --  @return Ok on success, Handshake_Failed on a wrong-length argument
   function Sign
     (Seed_Bytes       : Ada.Streams.Stream_Element_Array;
      Public_Key_Bytes : Ada.Streams.Stream_Element_Array;
      Message_Bytes    : Ada.Streams.Stream_Element_Array;
      Signature_Bytes  : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Verify an Ed448 signature over Message_Bytes.
   --
   --  A public key or an R that is not a point on the curve is a refusal
   --  rather than a fault: it is something an attacker can send.
   --  @param Public_Key_Bytes the signer's 57-byte public key
   --  @param Signature_Bytes  the 114-byte signature R || S to check
   --  @param Message_Bytes    the message the signature covers
   --  @return Ok if the signature is valid, Handshake_Failed if it is
   --          invalid or an argument has the wrong length
   function Verify
     (Public_Key_Bytes : Ada.Streams.Stream_Element_Array;
      Signature_Bytes  : Ada.Streams.Stream_Element_Array;
      Message_Bytes    : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

end CryptoLib.Ed448;
