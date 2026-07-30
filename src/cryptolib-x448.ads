with Ada.Streams;
with CryptoLib.Errors;
with CryptoLib.Random;

--  @summary X448 key agreement (RFC 7748) on curve448.
--
--  The 448-bit counterpart to CryptoLib.Curve25519, and the key agreement
--  that belongs beside CryptoLib.Ed448's signatures: the crate had the
--  448-bit signature and not the 448-bit exchange, which is an odd place to
--  stop. Both are defined over p = 2**448 - 2**224 - 1 and share the field
--  arithmetic.
--
--  Prefer X25519 where the choice is yours. X448 buys a larger security
--  margin -- roughly 224 bits against X25519's 128 -- for about three times
--  the work, and 128 bits is not the weak part of any system that has one.
--  Use it when a peer or a policy asks for it, or when the margin is the
--  point.
--
--  Values are 56 octets, little-endian, as RFC 7748 encodes them. The scalar
--  is clamped on the way in, so any 56 octets are a usable private key: the
--  low two bits are cleared and the top bit set, which is what keeps the
--  result in the right subgroup and the ladder's timing independent of the
--  scalar.
--
--  All-zero shared secrets are refused. A peer u-coordinate of small order
--  drives the result to zero whatever the private scalar is, so returning it
--  would hand both sides a "shared" secret an attacker already knows. RFC
--  7748 section 6.1 requires the check for exactly that reason.
package CryptoLib.X448 is

   --  A private scalar: 56 octets, clamped on use.
   subtype Private_Key is Ada.Streams.Stream_Element_Array (1 .. 56);

   --  A public u-coordinate: 56 octets, little-endian.
   subtype Public_Key is Ada.Streams.Stream_Element_Array (1 .. 56);

   --  A shared secret: 56 octets.
   subtype Shared_Key is Ada.Streams.Stream_Element_Array (1 .. 56);

   --  Generate a keypair.
   --  @param Rng          the random source
   --  @param Private_Item out: the scalar, zeroed on failure
   --  @param Public_Item  out: the public u-coordinate, zeroed on failure
   --  @return Ok, or Internal_Error when the source will not yield bytes
   function Generate_Keypair
     (Rng          : in out CryptoLib.Random.Random_Source;
      Private_Item : out Private_Key;
      Public_Item  : out Public_Key) return CryptoLib.Errors.Status;

   --  The public value a scalar implies: the scalar times the base point,
   --  whose u-coordinate is 5.
   --  @param Private_Item the scalar
   --  @param Public_Item  out: the public u-coordinate
   --  @return Ok, or Authentication_Failed if the result is degenerate
   function Public_Value
     (Private_Item : Private_Key;
      Public_Item  : out Public_Key) return CryptoLib.Errors.Status;

   --  Agree a shared secret with a peer.
   --  @param Private_Item the scalar
   --  @param Peer_Item    the peer's public u-coordinate
   --  @param Secret       out: the shared secret, zeroed on failure
   --  @return Ok, or Authentication_Failed when the result is all zero, which
   --    is what a small-order peer value produces
   function Shared_Secret
     (Private_Item : Private_Key;
      Peer_Item    : Public_Key;
      Secret       : out Shared_Key) return CryptoLib.Errors.Status;

   --  The raw primitive of RFC 7748: X448(k, u), with no refusal of a
   --  degenerate result.
   --
   --  Offered because the RFC's own test vectors are stated in these terms
   --  and a caller checking against them needs the unfiltered answer. A key
   --  exchange should use Shared_Secret, which refuses what this returns.
   --  @param Scalar the scalar k, clamped on use
   --  @param U      the u-coordinate
   --  @param Result out: X448 (k, u)
   --  @return Ok
   function Compute_Raw
     (Scalar : Private_Key;
      U      : Public_Key;
      Result : out Shared_Key) return CryptoLib.Errors.Status;

   --  Scrub a scalar.
   --  @param Private_Item out: the scalar, zeroed
   procedure Clear (Private_Item : out Private_Key);

end CryptoLib.X448;
