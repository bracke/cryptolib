with Ada.Streams;
with CryptoLib.EC_Arith;
with CryptoLib.EC_Curves;
with CryptoLib.Errors;
with CryptoLib.Random;

--  @summary ECDH key agreement on the NIST prime curves P-256, P-384 and
--  P-521.
--
--  The shared secret is the x-coordinate of d*Q, as SEC 1, RFC 5903 and
--  NIST SP 800-56A all define it: the curve's width in big-endian octets,
--  with no hashing and no leading tag. Every protocol that uses this hashes
--  it into keys its own way, so hashing it here would be wrong for all of
--  them.
--
--  Prefer X25519 (CryptoLib.Curve25519) where the choice is yours. These
--  curves are here for protocols and peers that require them -- TLS's
--  secp256r1 and secp384r1 groups, SSH's ecdh-sha2-nistp* methods -- not as
--  a better option.
--
--  Peer points are validated before the scalar touches them. Shared_Secret
--  refuses an encoding that is not an uncompressed point of the right width,
--  a coordinate at or above p, the point at infinity, and any point that
--  does not satisfy the curve equation. That last check is the one that
--  matters most: multiplying a secret scalar by a point on some *other*
--  curve, chosen by the peer to have a smooth order, leaks the scalar a few
--  bits at a time and recovers the private key. Refusing off-curve points is
--  what stops it.
--
--  No separate small-subgroup check is performed, and none is needed: all
--  three curves have cofactor 1, so every point that satisfies the equation
--  already generates the full prime-order group. This is stated rather than
--  silently omitted, because on a curve with a cofactor above 1 -- which
--  these are not -- omitting it would be a hole.
package CryptoLib.ECDH is

   --  Which curve the agreement runs on. The literals come from
   --  CryptoLib.EC_Curves: Nistp256, Nistp384, Nistp521.
   subtype Curve_Id is CryptoLib.EC_Curves.Curve_Kind;

   --  The width of a private scalar and of the shared secret, in octets:
   --  32, 48 or 66.
   --  @param Curve which curve
   --  @return the curve's field width in octets
   function Secret_Length (Curve : Curve_Id) return Positive;

   --  The width of an encoded public point, in octets: 65, 97 or 133.
   --  @param Curve which curve
   --  @return 1 + twice the field width
   function Public_Key_Length (Curve : Curve_Id) return Positive;

   --  Generate an ECDH keypair.
   --  @param Curve          which curve
   --  @param Rng            the random source
   --  @param Private_Scalar out: the scalar d, Secret_Length octets, zeroed
   --    on failure
   --  @param Public_Point   out: 16#04# then X and Y, Public_Key_Length
   --    octets, zeroed on failure
   --  @return Ok, Handshake_Failed on a wrong-length output buffer,
   --    Internal_Error if the source will not yield a usable scalar
   function Generate_Keypair
     (Curve          : Curve_Id;
      Rng            : in out CryptoLib.Random.Random_Source;
      Private_Scalar : out Ada.Streams.Stream_Element_Array;
      Public_Point   : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  The public point a private scalar implies.
   --  @param Curve          which curve
   --  @param Private_Scalar the scalar d, as an SSH mpint or as the curve's
   --    width in big-endian octets
   --  @param Public_Point   out: 16#04# then X and Y, zeroed on failure
   --  @return Ok, Handshake_Failed on a wrong-length output,
   --    Authentication_Failed when the scalar is not in [1, n-1]
   function Public_Key
     (Curve          : Curve_Id;
      Private_Scalar : Ada.Streams.Stream_Element_Array;
      Public_Point   : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Agree a shared secret with a peer.
   --
   --  Both sides reach the same octets: d_a * Q_b and d_b * Q_a are the same
   --  point. The result is that point's x-coordinate, unhashed.
   --
   --  The peer point is fully validated first; see the package comment for
   --  what is checked and why. A refusal is not a protocol nicety here -- an
   --  unvalidated point recovers the private key.
   --  @param Curve          which curve
   --  @param Private_Scalar the scalar d, as an SSH mpint or as the curve's
   --    width in big-endian octets, in [1, n-1]
   --  @param Peer_Point     the peer's public point, uncompressed
   --  @param Secret         out: the shared x-coordinate, Secret_Length
   --    octets, zeroed on failure
   --  @return Ok, Handshake_Failed on a wrong-length argument,
   --    Authentication_Failed when the scalar or the peer point is rejected
   function Shared_Secret
     (Curve          : Curve_Id;
      Private_Scalar : Ada.Streams.Stream_Element_Array;
      Peer_Point     : Ada.Streams.Stream_Element_Array;
      Secret         : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Is this a point this crate will agree with?
   --
   --  The validation Shared_Secret performs, exposed on its own for a caller
   --  that wants to reject a peer key at the point it arrives rather than at
   --  the point it is used.
   --  @param Curve      which curve
   --  @param Peer_Point the encoded point to check
   --  @return True when the point is uncompressed, correctly sized, reduced,
   --    not infinity, and on the curve
   function Valid_Peer_Point
     (Curve      : Curve_Id;
      Peer_Point : Ada.Streams.Stream_Element_Array) return Boolean;

private

   use CryptoLib.EC_Arith;

end CryptoLib.ECDH;
