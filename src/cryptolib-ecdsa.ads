with Ada.Streams;
with CryptoLib.Errors;
with CryptoLib.Random;

--  @summary Constant-time RFC 6979 deterministic ECDSA for NIST P-256,
--  P-384 and P-521: signing, verification, and for P-256 and P-384 also keys.
--
--  Nonces are derived deterministically (RFC 6979 HMAC-DRBG, under the digest
--  each curve pairs with -- SHA-256/384/512);
--  all curve arithmetic is fixed-width, branchless Montgomery (see
--  CryptoLib.EC_Arith).  Signatures are returned as fixed-width big-endian
--  r and s octet strings.
--
--  Every subprogram here that takes an out buffer zeroes it before doing
--  anything else, so a status other than Ok never leaves half a signature or
--  half a public key for a caller that ignores it.
package CryptoLib.ECDSA is

   --  Deterministically sign a pre-formed message over NIST P-384 (SHA-384).
   --  @param Private_Scalar_Mpint the private scalar d, as an SSH mpint or
   --  as the curve's width in big-endian bytes; both are read, and the name
   --  is kept for the callers that pass an mpint
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

   --  Deterministically sign a pre-formed message over NIST P-256 (SHA-256).
   --
   --  The curve arithmetic, the RFC 6979 nonce derivation and the scrubbing
   --  are the same code the other two curves run; only the curve constants
   --  and the paired digest differ.
   --  @param Private_Scalar_Mpint the private scalar d, as an SSH mpint or
   --  as the curve's width in big-endian bytes; both are read, and the name
   --  is kept for the callers that pass an mpint
   --  @param Message_Bytes the message to sign (hashed internally with SHA-256)
   --  @param R_Bytes the signature component r as 32 big-endian bytes
   --  @param S_Bytes the signature component s as 32 big-endian bytes
   --  @return Ok on success, Authentication_Failed if the private scalar is
   --          invalid or no valid nonce is found, Handshake_Failed on a
   --          wrong-length output buffer, Internal_Error on a fault
   function Sign_Nistp256_Raw
     (Private_Scalar_Mpint : Ada.Streams.Stream_Element_Array;
      Message_Bytes        : Ada.Streams.Stream_Element_Array;
      R_Bytes              : out Ada.Streams.Stream_Element_Array;
      S_Bytes              : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Deterministically sign a pre-formed message over NIST P-521 (SHA-512).
   --  @param Private_Scalar_Mpint the private scalar d, as an SSH mpint or
   --  as the curve's width in big-endian bytes; both are read, and the name
   --  is kept for the callers that pass an mpint
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
   --  @param Private_Scalar_Mpint the private scalar d, as an SSH mpint or
   --  as the curve's width in big-endian bytes; both are read, and the name
   --  is kept for the callers that pass an mpint
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

   --  Generate a P-256 keypair.
   --
   --  Offered because a signing curve a caller cannot make a key for is only
   --  half a curve. Public_Key_Raw already derives the point from a scalar
   --  that came from somewhere else.
   --  @param Rng the random source
   --  @param Private_Scalar the scalar d as 32 big-endian bytes
   --  @param Public_Point 65 bytes: 16#04#, then X and Y as 32 bytes each
   --  @return Ok, Handshake_Failed on a wrong-length output buffer,
   --          Internal_Error if the source will not yield a usable scalar
   function Generate_Nistp256_Keypair
     (Rng            : in out CryptoLib.Random.Random_Source;
      Private_Scalar : out Ada.Streams.Stream_Element_Array;
      Public_Point   : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Which curve a key is on.
   type Curve_Id is (Nistp256, Nistp384, Nistp521);

   --  Which digest a signature was made with.
   --
   --  Separate from the curve on purpose. An ECDSA signature algorithm names
   --  only the hash -- ecdsa-with-SHA256 says nothing about the curve -- and
   --  a P-521 key signing with SHA-256 is an ordinary, legal combination that
   --  a verifier pairing the two would refuse.
   type Digest_Id is (SHA256, SHA384, SHA512);

   --  Verify an ECDSA signature on any supported curve with any supported
   --  digest.
   --
   --  A digest wider than the curve's order is truncated to its leftmost
   --  octets, as ECDSA requires.
   --  @param Curve which curve the public point is on
   --  @param Digest which hash the signature was made with
   --  @param Public_Point 16#04#, then X and Y, each the curve's width
   --  @param Message_Bytes the signed message, hashed here
   --  @param R_Bytes the signature component r, the curve's width
   --  @param S_Bytes the signature component s, the curve's width
   --  @return Ok when the signature is that key's over that message,
   --          Authentication_Failed when it is not, Handshake_Failed on a
   --          wrong-length input
   function Verify_Signature
     (Curve         : Curve_Id;
      Digest        : Digest_Id;
      Public_Point  : Ada.Streams.Stream_Element_Array;
      Message_Bytes : Ada.Streams.Stream_Element_Array;
      R_Bytes       : Ada.Streams.Stream_Element_Array;
      S_Bytes       : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  The public point a private scalar implies, on any supported curve.
   --
   --  Offered for every curve because deciding whether a private key belongs
   --  to a certificate means deriving its public key and comparing, and a
   --  caller that can do that on one curve and not another has to report the
   --  difference rather than the answer.
   --  @param Curve which curve the scalar belongs to
   --  @param Private_Scalar_Mpint the scalar d, as an SSH mpint or as the
   --  curve's width in big-endian bytes
   --  @param Public_Point receives 16#04#, then X and Y, each the curve's
   --  width; 65, 97 or 133 octets
   --  @return Ok on success, Handshake_Failed on a wrong-length output,
   --          Authentication_Failed when the scalar is not one
   function Public_Key_Raw
     (Curve                : Curve_Id;
      Private_Scalar_Mpint : Ada.Streams.Stream_Element_Array;
      Public_Point         : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Verify a P-256 signature against a public point.
   --  @param Public_Point 65 bytes: 16#04#, then X and Y as 32 bytes each
   --  @param Message_Bytes the signed message (hashed internally with SHA-256)
   --  @param R_Bytes the signature component r as 32 big-endian bytes
   --  @param S_Bytes the signature component s as 32 big-endian bytes
   --  @return Ok when the signature is that key's over that message,
   --          Authentication_Failed when it is not, Handshake_Failed on a
   --          wrong-length input
   function Verify_Nistp256_Raw
     (Public_Point  : Ada.Streams.Stream_Element_Array;
      Message_Bytes : Ada.Streams.Stream_Element_Array;
      R_Bytes       : Ada.Streams.Stream_Element_Array;
      S_Bytes       : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Verify a P-521 signature against a public point.
   --  @param Public_Point 133 bytes: 16#04#, then X and Y as 66 bytes each
   --  @param Message_Bytes the signed message (hashed internally with SHA-512)
   --  @param R_Bytes the signature component r as 66 big-endian bytes
   --  @param S_Bytes the signature component s as 66 big-endian bytes
   --  @return Ok when the signature is that key's over that message,
   --          Authentication_Failed when it is not, Handshake_Failed on a
   --          wrong-length input
   function Verify_Nistp521_Raw
     (Public_Point  : Ada.Streams.Stream_Element_Array;
      Message_Bytes : Ada.Streams.Stream_Element_Array;
      R_Bytes       : Ada.Streams.Stream_Element_Array;
      S_Bytes       : Ada.Streams.Stream_Element_Array)
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
