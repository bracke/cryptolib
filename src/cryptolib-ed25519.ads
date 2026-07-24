with Ada.Streams;
with CryptoLib.Errors;
with CryptoLib.Random;

--  @summary Ed25519 (RFC 8032 PureEdDSA over edwards25519) sign and verify.
--
--  Constant-time signing over the twisted Edwards curve with SHA-512 hashing;
--  public keys are 32 bytes and signatures are 64 bytes (R || S).  Point
--  arithmetic uses a double-and-add-always ladder with branchless selects.
package CryptoLib.Ed25519 is

   Public_Key_Length : constant Natural := 32;
   Signature_Length  : constant Natural := 64;

   --  Generate an Ed25519 seed and matching public key.
   --  @param Rng the configured random source used to fill the private seed
   --  @param Seed_Bytes out: 32-byte private seed, zeroed on failure
   --  @param Public_Key_Bytes out: 32-byte public key, zeroed on failure
   --  @return Ok on success, Handshake_Failed on wrong-length arguments,
   --          Internal_Error when random generation or derivation fails
   function Generate_Keypair
     (Rng              : in out CryptoLib.Random.Random_Source;
      Seed_Bytes       : out Ada.Streams.Stream_Element_Array;
      Public_Key_Bytes : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Derive an Ed25519 public key from a 32-byte private seed.
   --  @param Seed_Bytes the 32-byte private seed
   --  @param Public_Key_Bytes out: 32-byte public key, zeroed on failure
   --  @return Ok on success, Handshake_Failed on wrong-length arguments,
   --          Internal_Error on an internal fault
   function Public_Key_From_Seed
     (Seed_Bytes       : Ada.Streams.Stream_Element_Array;
      Public_Key_Bytes : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Produce an Ed25519 signature over Message_Bytes.
   --  @param Seed_Bytes       the 32-byte private seed
   --  @param Public_Key_Bytes the signer's 32-byte public key
   --  @param Message_Bytes    the message to sign (any length)
   --  @param Signature_Bytes  the resulting 64-byte signature R || S
   --  @return Ok on success, Handshake_Failed on a wrong-length argument,
   --          Internal_Error on an internal fault
   function Sign
     (Seed_Bytes       : Ada.Streams.Stream_Element_Array;
      Public_Key_Bytes : Ada.Streams.Stream_Element_Array;
      Message_Bytes    : Ada.Streams.Stream_Element_Array;
      Signature_Bytes  : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Verify an Ed25519 signature over Message_Bytes.
   --  @param Public_Key_Bytes the signer's 32-byte public key
   --  @param Signature_Bytes  the 64-byte signature R || S to check
   --  @param Message_Bytes    the message the signature covers
   --  @return Ok if the signature is valid, Handshake_Failed if it is invalid
   --          or an argument has the wrong length, Internal_Error on a fault
   function Verify
     (Public_Key_Bytes : Ada.Streams.Stream_Element_Array;
      Signature_Bytes  : Ada.Streams.Stream_Element_Array;
      Message_Bytes    : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;
end CryptoLib.Ed25519;
