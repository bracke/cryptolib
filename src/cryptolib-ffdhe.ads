with Ada.Streams;
with CryptoLib.Errors;
with CryptoLib.Random;

--  @summary Finite-field Diffie-Hellman over the RFC 7919 named groups
--  ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144 and ffdhe8192.
--
--  These are the groups TLS negotiates for finite-field key exchange, and they
--  are not the groups CryptoLib.Diffie_Hellman implements: those are the SSH
--  MODP primes of RFC 2409 and RFC 3526. The names collide in conversation --
--  both are "2048-bit DH" -- and the primes are different, so a value from one
--  is meaningless in the other.
--
--  Prefer X25519 (CryptoLib.Curve25519) or the NIST curves (CryptoLib.ECDH)
--  where the choice is yours; an 8192-bit exponentiation is thousands of times
--  the work of a curve multiplication for comparable strength. These exist for
--  peers and policies that require finite-field key exchange.
--
--  Every prime here is a **safe** prime: (p-1)/2 is also prime, which the
--  construction in RFC 7919 section 2 guarantees and which was checked rather
--  than assumed before these constants were written down. That is what makes
--  the cheap peer check below sufficient.
--
--  Values are fixed-width, big-endian, and exactly as wide as the prime, which
--  is how TLS encodes them (RFC 8446 section 4.2.8.1: left-padded with zeros
--  to the length of p). A short value is not accepted and not left-padded for
--  the caller: a wrong-width value is a wrong value.
--
--  The exponentiation goes through CryptoLib.Modexp, which is word-serial
--  constant-time Montgomery, so its timing depends on the operand widths --
--  which are public -- and not on the private exponent.
package CryptoLib.FFDHE is

   --  Which RFC 7919 group. The numbers are the prime's bit length.
   type Group_Id is (FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192);

   --  The width of the prime, and so of every public value and shared secret,
   --  in octets: 256, 384, 512, 768 or 1024.
   --  @param Group which group
   --  @return the prime's width in octets
   function Value_Length (Group : Group_Id) return Positive;

   --  The width of a private exponent for this group, in octets.
   --
   --  Short exponents, as RFC 7919 appendix A allows and recommends: 256 bits
   --  for ffdhe2048 rising to 448 for ffdhe8192, each comfortably above the
   --  appendix's floor and far below the prime's width. With a safe prime this
   --  costs no security and is the difference between an 8192-bit exchange
   --  that is merely slow and one nobody would use.
   --  @param Group which group
   --  @return the private exponent's width in octets
   function Exponent_Length (Group : Group_Id) return Positive;

   --  Generate a keypair.
   --  @param Group         which group
   --  @param Rng           the random source
   --  @param Private_Value out: the exponent x, Exponent_Length octets, zeroed
   --    on failure
   --  @param Public_Value  out: g**x mod p, Value_Length octets, zeroed on
   --    failure
   --  @return Ok, Handshake_Failed on a wrong-length output buffer,
   --    Internal_Error if the source will not yield a usable exponent
   function Generate_Keypair
     (Group         : Group_Id;
      Rng           : in out CryptoLib.Random.Random_Source;
      Private_Value : out Ada.Streams.Stream_Element_Array;
      Public_Value  : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  The public value a private exponent implies.
   --  @param Group         which group
   --  @param Private_Value the exponent x, Exponent_Length octets
   --  @param Public_Value  out: g**x mod p, zeroed on failure
   --  @return Ok, Handshake_Failed on a wrong-length argument,
   --    Authentication_Failed when the exponent is zero or one
   function Public_Value
     (Group         : Group_Id;
      Private_Value : Ada.Streams.Stream_Element_Array;
      Public_Value  : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Agree a shared secret with a peer.
   --
   --  The result is Y**x mod p, the prime's width, unhashed -- every protocol
   --  that uses this derives keys from it its own way, so hashing it here would
   --  be wrong for all of them. TLS 1.3 feeds exactly these octets into the key
   --  schedule.
   --
   --  The peer value is validated first; see Valid_Peer_Value. A shared secret
   --  of 1 or p-1 is refused as well, which is what catches a peer value whose
   --  order is 1 or 2 having somehow passed the range check.
   --  @param Group         which group
   --  @param Private_Value the exponent x, Exponent_Length octets
   --  @param Peer_Value    the peer's public value, Value_Length octets
   --  @param Secret        out: the shared secret, Value_Length octets, zeroed
   --    on failure
   --  @return Ok, Handshake_Failed on a wrong-length argument,
   --    Authentication_Failed when the exponent or the peer value is rejected
   function Shared_Secret
     (Group         : Group_Id;
      Private_Value : Ada.Streams.Stream_Element_Array;
      Peer_Value    : Ada.Streams.Stream_Element_Array;
      Secret        : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Is this a peer value this crate will agree with?
   --
   --  Checks the width and that 1 < Y < p-1, which is what RFC 8446 section
   --  4.2.8.1 requires and what RFC 7919 section 5.2 calls the minimum. Y = 0,
   --  1 or p-1 are the elements of order 1 and 2, and they are what an attacker
   --  sends to force a known shared secret.
   --
   --  No subgroup check is performed, and the reason is worth stating rather
   --  than leaving to inference. Because p is a safe prime, a Y that passes
   --  this check generates either the prime-order subgroup or the whole group,
   --  so the most a hostile Y can learn is one bit -- the parity of x, through
   --  the Legendre symbol. RFC 7919 section 5.2 offers Y**q mod p = 1 to close
   --  that bit and notes it costs a second full exponentiation. This crate does
   --  not spend it, and says so here rather than being silently weaker than a
   --  reader assumes.
   --  @param Group      which group
   --  @param Peer_Value the value to check
   --  @return True when the width is right and 1 < Y < p-1
   function Valid_Peer_Value
     (Group      : Group_Id;
      Peer_Value : Ada.Streams.Stream_Element_Array) return Boolean;

end CryptoLib.FFDHE;
