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
--  * The private operation is **blinded**. A fresh random r is drawn per
--    signature and the input is multiplied by r**e before exponentiating,
--    then the result by r**-1 after; both cancel, so the signature is
--    unchanged while what the exponentiation actually sees is uniformly
--    random and unrelated to the message. A leak correlated with the input
--    therefore reveals nothing about the message or the key. Signing fails
--    rather than falling back to unblinded if the random source will not
--    yield bytes.
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
   --  Deterministic in its output: the same key and message always give the
   --  same signature. It still needs a random source, because the private
   --  operation is blinded -- the randomness changes what the exponentiation
   --  sees, not what it produces. Signing fails rather than proceeding
   --  unblinded if the source will not yield bytes.
   --
   --  Public_Exponent is required because the signature is verified against
   --  it before being returned; a caller who does not have it does not get an
   --  unchecked signature instead.
   --  @param Modulus          the public modulus n, unsigned big-endian
   --  @param Public_Exponent  the public exponent e, unsigned big-endian
   --  @param Private_Exponent the private exponent d, unsigned big-endian
   --  @param Hash             which digest to sign under
   --  @param Message          the message to sign; hashed here
   --  @param Rng              the source the blinding factor is drawn from
   --  @param Signature        out: the signature, exactly as long as the
   --    modulus, zeroed on failure
   --  @return Ok, Handshake_Failed when an argument cannot be used or the
   --    modulus is too small to hold the block, Authentication_Failed when
   --    the signature produced does not verify under the public exponent,
   --    Internal_Error on a fault or when the blinding factor cannot be
   --    drawn
   function Sign_PKCS1_V1_5
     (Modulus          : Ada.Streams.Stream_Element_Array;
      Public_Exponent  : Ada.Streams.Stream_Element_Array;
      Private_Exponent : Ada.Streams.Stream_Element_Array;
      Hash             : Hash_Algorithm;
      Message          : Ada.Streams.Stream_Element_Array;
      Rng              : in out CryptoLib.Random.Random_Source;
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

   --  The modulus sizes this will generate.
   --
   --  Nothing below 2048 bits: a smaller RSA key is not a key with a smaller
   --  margin, it is one that is factored. Offering it would be offering a
   --  footgun with a size argument.
   type Modulus_Size is (RSA_2048, RSA_3072, RSA_4096);

   --  The public exponent every generated key uses, 65537.
   --
   --  Not a parameter. A caller who could choose would eventually choose 3,
   --  and a small public exponent turns several implementation slips --
   --  unpadded messages, related messages, a verifier that parses rather than
   --  compares -- into practical attacks. 65537 has one bit more than the
   --  minimum useful Hamming weight, verifies fast, and has no such history.
   Generated_Public_Exponent : constant := 65537;

   --  Generate an RSA keypair.
   --
   --  Two primes are drawn with their top two bits set, so the modulus has
   --  exactly the requested width and the primes cannot be close enough for
   --  Fermat factorisation. Each candidate is trial-divided by the small
   --  primes and then put through Miller-Rabin. The private exponent is
   --  checked to be large enough that Wiener's attack does not apply, and the
   --  key is checked to work -- a signature is made and verified -- before it
   --  is returned.
   --
   --  This is not fast. Nothing here is optimised for key generation, and a
   --  4096-bit key can take a while; it is a thing done once per key, not per
   --  operation.
   --  @param Size             which modulus width to generate
   --  @param Rng              the random source the primes are drawn from
   --  @param Modulus          out: the modulus n, Size octets, zeroed on
   --    failure
   --  @param Public_Exponent  out: 65537 as three octets, zeroed on failure
   --  @param Private_Exponent out: the private exponent d, the same width as
   --    the modulus, zeroed on failure
   --  @return Ok, Handshake_Failed on a wrong-length output buffer,
   --    Internal_Error when the random source fails or no key is found
   function Generate_Keypair
     (Size             : Modulus_Size;
      Rng              : in out CryptoLib.Random.Random_Source;
      Modulus          : out Ada.Streams.Stream_Element_Array;
      Public_Exponent  : out Ada.Streams.Stream_Element_Array;
      Private_Exponent : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Generate a keypair and hand back the primes and CRT parameters too.
   --
   --  Everything an RSAPrivateKey carries, which is what a caller needs to
   --  write a private key any other implementation will read: PKCS#8 around
   --  RFC 3447's structure has prime1, prime2, exponent1, exponent2 and
   --  coefficient as required fields, so a key missing them is not a key file.
   --
   --  This crate signs without them -- see the package summary on CRT -- so
   --  Generate_Keypair, which returns only what signing needs, is the one to
   --  call unless the key has to be written out.
   --
   --  The CRT parameters come from the same inverses key generation already
   --  computes and need no division: exponent1 is d mod (p-1), which is also
   --  the inverse of e modulo p-1, and coefficient is q inverse modulo p.
   --  @param Size             which modulus width to generate
   --  @param Rng              the random source the primes are drawn from
   --  @param Modulus          out: n, Size octets
   --  @param Public_Exponent  out: 65537 as three octets
   --  @param Private_Exponent out: d, as wide as the modulus
   --  @param Prime_P          out: p, half the modulus width
   --  @param Prime_Q          out: q, half the modulus width
   --  @param Exponent_P       out: d mod (p-1), half the modulus width
   --  @param Exponent_Q       out: d mod (q-1), half the modulus width
   --  @param Coefficient      out: q inverse mod p, half the modulus width
   --  @return Ok, Handshake_Failed on a wrong-length output buffer,
   --    Internal_Error when the random source fails or no key is found
   function Generate_Keypair_With_Primes
     (Size             : Modulus_Size;
      Rng              : in out CryptoLib.Random.Random_Source;
      Modulus          : out Ada.Streams.Stream_Element_Array;
      Public_Exponent  : out Ada.Streams.Stream_Element_Array;
      Private_Exponent : out Ada.Streams.Stream_Element_Array;
      Prime_P          : out Ada.Streams.Stream_Element_Array;
      Prime_Q          : out Ada.Streams.Stream_Element_Array;
      Exponent_P       : out Ada.Streams.Stream_Element_Array;
      Exponent_Q       : out Ada.Streams.Stream_Element_Array;
      Coefficient      : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  The modulus width in octets for a size.
   --  @param Size which modulus width
   --  @return 256, 384 or 512
   function Modulus_Octets (Size : Modulus_Size) return Positive;

end CryptoLib.RSA;
