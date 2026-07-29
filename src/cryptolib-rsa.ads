with Ada.Streams;

with CryptoLib.Errors;
with CryptoLib.Random;

--  @summary RSA signatures: RSASSA-PKCS1-v1_5 and RSASSA-PSS, both
--  directions.
--
--  Verification touches only public values -- modulus, public exponent,
--  signature, message -- so nothing in it needs to be constant-time, and
--  saying so plainly beats leaving a reader to wonder whether it was
--  overlooked. (CryptoLib.Constant_Time.Equal is still used for the final
--  comparison, because it costs nothing and keeps the habit intact.)
--
--  Signing does hold a private exponent, and what protects it is stated here
--  rather than assumed:
--
--  * The exponentiation goes through CryptoLib.Modexp, which is word-serial
--    constant-time Montgomery: its timing depends on the operand widths,
--    which are public, and not on the exponent.
--
--  * Every signature is verified against the public exponent before it is
--    returned. A fault during the private operation -- a flipped bit, a
--    glitched multiply -- produces a signature that does not verify, and a
--    faulty RSA signature is not merely wrong: released next to a correct one
--    it can reveal the factorisation. Nothing leaves here unchecked.
--
--  * There is **no blinding**. A blinded implementation randomises the input
--    to the private operation so that even a leak correlated with that input
--    reveals nothing; this one relies on the exponentiation being
--    constant-time by construction instead. That is the weaker of the two
--    positions, and it is the known next step rather than a decision that
--    the defence is unnecessary. Callers doing high-volume signing where an
--    attacker can supply messages and measure timing precisely should weigh
--    that.
--
--  There is no key generation and no CRT. Without p and q there is no CRT
--  path to get wrong, which removes the fault mode CRT is notorious for, at
--  the cost of signing roughly four times slower than a CRT implementation.
--
--  The verification is done by constructing the block the signature should
--  have decrypted to and comparing it, rather than by taking the decrypted
--  block apart and checking the pieces. That is deliberate and it is the
--  whole security argument of this package. A parser that scans forward for
--  the 16#00# separator and then reads whatever follows will accept
--  signatures with too little padding or with data after the digest -- the
--  Bleichenbacher forgery against low public exponents is exactly that
--  mistake. A comparison against a fully determined expected block cannot
--  make it: there is no scan, no optional part, and nothing after the digest
--  to ignore.
package CryptoLib.RSA is

   type Hash_Algorithm is (SHA256, SHA384, SHA512);

   --  Is this signature the given RSA public key's over this message?
   --
   --  Message is hashed here; pass what was signed, not its digest. Modulus
   --  and Exponent are unsigned big-endian and may carry leading zero octets,
   --  as they do when taken straight from a DER INTEGER.
   --  @param Modulus the public modulus n, unsigned big-endian
   --  @param Exponent the public exponent e, unsigned big-endian
   --  @param Hash which digest the signature was made with
   --  @param Message the signed message
   --  @param Signature the signature, which must be exactly as long as the
   --  modulus
   --  @return Ok when the signature verifies, Authentication_Failed when it
   --          does not, Handshake_Failed when an argument cannot be used --
   --          an even or zero modulus, an empty exponent, a signature of the
   --          wrong length or one not less than the modulus, or a modulus too
   --          small to hold the padded digest
   function Verify_PKCS1_V1_5
     (Modulus   : Ada.Streams.Stream_Element_Array;
      Exponent  : Ada.Streams.Stream_Element_Array;
      Hash      : Hash_Algorithm;
      Message   : Ada.Streams.Stream_Element_Array;
      Signature : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Is this signature the given RSA public key's, under RSASSA-PSS?
   --
   --  PSS carries its own parameters -- which hash, which mask generation
   --  function, how long the salt -- in the algorithm identifier rather than
   --  in the algorithm's name, so a caller has to supply them. Getting them
   --  from anywhere but the signature's own parameters is guessing, and a
   --  guess that happens to be right proves nothing about the next one.
   --
   --  Salt_Length is the length the parameters state. The recovered salt is
   --  required to be exactly that: accepting whatever length turns up would
   --  let a signature be reinterpreted with a shorter salt than its issuer
   --  chose.
   --  @param Modulus the public modulus n, unsigned big-endian
   --  @param Exponent the public exponent e, unsigned big-endian
   --  @param Hash which digest the signature was made with, used for the
   --  message digest and for the mask generation function alike
   --  @param Salt_Length the salt length the parameters state, in octets
   --  @param Message the signed message
   --  @param Signature the signature, exactly as long as the modulus
   --  @return Ok when the signature verifies, Authentication_Failed when it
   --          does not, Handshake_Failed when an argument cannot be used
   function Verify_PSS
     (Modulus     : Ada.Streams.Stream_Element_Array;
      Exponent    : Ada.Streams.Stream_Element_Array;
      Hash        : Hash_Algorithm;
      Salt_Length : Natural;
      Message     : Ada.Streams.Stream_Element_Array;
      Signature   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  How many bits wide is this modulus?
   --
   --  For a caller enforcing a minimum key size. No minimum is imposed here:
   --  what counts as too small is policy, it changes over time, and a
   --  primitive that decided it would have to be edited to change it.
   --  @param Modulus the public modulus, unsigned big-endian
   --  @return the modulus's bit length, zero when it is zero
   function Modulus_Bits
     (Modulus : Ada.Streams.Stream_Element_Array) return Natural;

   --  Sign under RSASSA-PKCS1-v1_5.
   --
   --  Deterministic: the same key and message always give the same signature.
   --  Public_Exponent is required because the signature is verified against
   --  it before being returned; a caller who does not have it does not get an
   --  unchecked signature instead.
   --  @param Modulus          the public modulus n, unsigned big-endian
   --  @param Public_Exponent  the public exponent e, unsigned big-endian
   --  @param Private_Exponent the private exponent d, unsigned big-endian
   --  @param Hash             which digest to sign under
   --  @param Message          the message to sign; hashed here
   --  @param Signature        out: the signature, exactly as long as the
   --    modulus, zeroed on failure
   --  @return Ok, Handshake_Failed when an argument cannot be used or the
   --    modulus is too small to hold the block, Authentication_Failed when
   --    the signature produced does not verify under the public exponent,
   --    Internal_Error on a fault
   function Sign_PKCS1_V1_5
     (Modulus          : Ada.Streams.Stream_Element_Array;
      Public_Exponent  : Ada.Streams.Stream_Element_Array;
      Private_Exponent : Ada.Streams.Stream_Element_Array;
      Hash             : Hash_Algorithm;
      Message          : Ada.Streams.Stream_Element_Array;
      Signature        : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Sign under RSASSA-PSS.
   --
   --  Randomised unless Salt_Length is zero: PSS draws a fresh salt for each
   --  signature, so signing the same message twice gives different bytes and
   --  both verify. A salt length of zero is legal and makes the scheme
   --  deterministic; it is what a caller wanting reproducible output asks
   --  for, and it is how this is held to a byte-exact vector.
   --
   --  The salt length must be the one the verifier will expect, since PSS
   --  carries it in the algorithm parameters rather than deriving it. The
   --  common choices are the digest's own length and zero.
   --  @param Modulus          the public modulus n, unsigned big-endian
   --  @param Public_Exponent  the public exponent e, unsigned big-endian
   --  @param Private_Exponent the private exponent d, unsigned big-endian
   --  @param Hash             which digest to sign under, used for the
   --    message digest and the mask generation function alike
   --  @param Salt_Length      how many salt octets to draw; may be zero
   --  @param Message          the message to sign; hashed here
   --  @param Rng              the source the salt is drawn from; unused when
   --    Salt_Length is zero
   --  @param Signature        out: the signature, exactly as long as the
   --    modulus, zeroed on failure
   --  @return Ok, Handshake_Failed when an argument cannot be used or the
   --    modulus cannot hold a block with this digest and salt,
   --    Authentication_Failed when the signature produced does not verify,
   --    Internal_Error on a fault or when the salt cannot be drawn
   function Sign_PSS
     (Modulus          : Ada.Streams.Stream_Element_Array;
      Public_Exponent  : Ada.Streams.Stream_Element_Array;
      Private_Exponent : Ada.Streams.Stream_Element_Array;
      Hash             : Hash_Algorithm;
      Salt_Length      : Natural;
      Message          : Ada.Streams.Stream_Element_Array;
      Rng              : in out CryptoLib.Random.Random_Source;
      Signature        : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

end CryptoLib.RSA;
