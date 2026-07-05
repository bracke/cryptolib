with Ada.Streams;
with CryptoLib.Errors;

--  @summary Constant-time RFC 6979 deterministic ECDSA signer for NIST P-384
--  and P-521.
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

end CryptoLib.ECDSA;
