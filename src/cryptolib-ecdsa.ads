with Ada.Streams;
with CryptoLib.Errors;
with CryptoLib.Random;

--  @summary Constant-time RFC 6979 deterministic ECDSA for NIST P-384 and
--  P-521: signing, and for P-384 also keys.
--
--  Nonces are derived deterministically (RFC 6979 HMAC-DRBG, SHA-384/SHA-512);
--  all curve arithmetic is fixed-width, branchless Montgomery (see
--  CryptoLib.EC_Arith).  Signatures are returned as fixed-width big-endian
--  r and s octet strings.
package CryptoLib.ECDSA is

   --  Deterministically sign a pre-formed message over NIST P-384 (SHA-384).
   --  @param Private_Scalar_Mpint the private scalar d as an SSH mpint
   --         (big-endian magnitude, optional leading 0x00 sign byte), in [1, n-1]
   --  @param Message_Bytes the message to sign (hashed internally with SHA-384)
   --  @param R_Bytes the signature component r as 48 big-endian bytes
   --  @param S_Bytes the signature component s as 48 big-endian bytes
   --  @return Ok on success, Authentication_Failed if the private scalar is
   --          invalid or no valid nonce is found, Handshake_Failed on a
   --          wrong-length output buffer, Internal_Error on a fault
   function Sign_Nistp384_Raw
     (Private_Scalar_Mpint : Ada.Streams.Stream_Element_Array;
      Message_Bytes        : Ada.Streams.Stream_Element_Array;
      R_Bytes              : out Ada.Streams.Stream_Element_Array;
      S_Bytes              : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Deterministically sign a pre-formed message over NIST P-521 (SHA-512).
   --  @param Private_Scalar_Mpint the private scalar d as an SSH mpint
   --         (big-endian magnitude, optional leading 0x00 sign byte), in [1, n-1]
   --  @param Message_Bytes the message to sign (hashed internally with SHA-512)
   --  @param R_Bytes the signature component r as 66 big-endian bytes
   --  @param S_Bytes the signature component s as 66 big-endian bytes
   --  @return Ok on success, Authentication_Failed if the private scalar is
   --          invalid or no valid nonce is found, Handshake_Failed on a
   --          wrong-length output buffer, Internal_Error on a fault
   function Sign_Nistp521_Raw
     (Private_Scalar_Mpint : Ada.Streams.Stream_Element_Array;
      Message_Bytes        : Ada.Streams.Stream_Element_Array;
      R_Bytes              : out Ada.Streams.Stream_Element_Array;
      S_Bytes              : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Derive the public point of a P-384 private scalar, as the uncompressed
   --  SEC1 encoding 16#04# || X || Y.
   --
   --  Signing alone was enough for SSH, which carries the public key beside
   --  the signature. A certificate has to state the key it is about, so the
   --  point has to be derivable from the scalar.
   --  @param Private_Scalar_Mpint the private scalar d as an SSH mpint
   --  @param Public_Point 97 bytes: 16#04#, then X and Y as 48 bytes each
   --  @return Ok, Authentication_Failed for a scalar outside [1, n-1],
   --          Handshake_Failed on a wrong-length output buffer
   function Public_Nistp384_Raw
     (Private_Scalar_Mpint : Ada.Streams.Stream_Element_Array;
      Public_Point         : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Generate a P-384 keypair.
   --  @param Rng the random source
   --  @param Private_Scalar the scalar d as 48 big-endian bytes
   --  @param Public_Point 97 bytes: 16#04#, then X and Y as 48 bytes each
   --  @return Ok, Handshake_Failed on a wrong-length output buffer,
   --          Internal_Error if the source will not yield a usable scalar
   function Generate_Nistp384_Keypair
     (Rng            : in out CryptoLib.Random.Random_Source;
      Private_Scalar : out Ada.Streams.Stream_Element_Array;
      Public_Point   : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Verify a P-384 signature against a public point.
   --  @param Public_Point 97 bytes: 16#04#, then X and Y as 48 bytes each
   --  @param Message_Bytes the signed message (hashed internally with SHA-384)
   --  @param R_Bytes the signature component r as 48 big-endian bytes
   --  @param S_Bytes the signature component s as 48 big-endian bytes
   --  @return Ok when the signature is that key's over that message,
   --          Authentication_Failed when it is not, Handshake_Failed on a
   --          wrong-length input
   function Verify_Nistp384_Raw
     (Public_Point  : Ada.Streams.Stream_Element_Array;
      Message_Bytes : Ada.Streams.Stream_Element_Array;
      R_Bytes       : Ada.Streams.Stream_Element_Array;
      S_Bytes       : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

end CryptoLib.ECDSA;
