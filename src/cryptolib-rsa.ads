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
--  CRT is used when the caller supplies the primes and their exponents, and
--  the plain exponentiation when it does not; both are the same call.
--
--  Two exponentiations at half the width cost about a quarter of one at full
--  width, but that is not what a signature costs. Measured, CRT makes a
--  2048-bit signature a little over twice as fast -- not four times, because
--  the blinding factor's inverse, the unblinding multiply and the check
--  against the public exponent are all full width and untouched by it.
--
--  Ratios rather than milliseconds on purpose: the absolute figures moved by a
--  factor of two between runs on the same machine under different load, so a
--  number written here would be a number that is wrong somewhere else.
--
--  A fault in either CRT half produces a signature that does not verify, and
--  releasing a faulty CRT signature next to a correct one gives up the
--  factorisation -- the Bellcore attack, which is what CRT is notorious for.
--  What makes CRT safe here is the check that was already in place before it
--  arrived: every signature is raised to the public exponent and compared
--  with the block that went in, so nothing faulty is ever returned. Without
--  that check CRT would be a bad trade at any speed.
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

   --  A blinding pair, reused across signatures made with one key.
   --
   --  The blinding factor's modular inverse is the most expensive part of a
   --  signature -- measured, about half of one, and more than the
   --  exponentiation itself. It need not be paid every time: a pair can be carried forward and refreshed by squaring both
   --  halves, which costs two modular multiplications instead of an inverse and
   --  keeps the pair consistent, since squaring r and r inverse leaves them
   --  inverses of each other.
   --
   --  Worth using when signing repeatedly with the same key. Signing once --
   --  which is what issuing a certificate does -- gains nothing, and the
   --  entry points without a pair are simpler.
   --
   --  This holds secret material and is wiped by Wipe. A pair belongs to the
   --  modulus it was started for and is refused by any other, because a pair
   --  from another key would blind with a factor whose inverse does not undo
   --  it -- which would produce signatures that do not verify rather than
   --  anything worse, but a clear refusal is better than a puzzle.
   type Blinding_Pair is limited private;

   --  Start a blinding pair for a key. This is where the one inverse is paid.
   --  @param Modulus         the modulus the pair will be used with
   --  @param Public_Exponent the matching public exponent
   --  @param Rng             the source the first factor is drawn from
   --  @param Pair            out: the pair, unusable on failure
   --  @return Ok, Handshake_Failed on an unusable modulus, Internal_Error when
   --    no factor with an inverse can be drawn
   function Start_Blinding
     (Modulus         : Ada.Streams.Stream_Element_Array;
      Public_Exponent : Ada.Streams.Stream_Element_Array;
      Rng             : in out CryptoLib.Random.Random_Source;
      Pair            : out Blinding_Pair)
      return CryptoLib.Errors.Status;

   --  Scrub a blinding pair.
   --  @param Pair the pair to wipe
   procedure Wipe (Pair : in out Blinding_Pair);

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
   --  @param Prime_P     p, for CRT; omit all five to sign the plain way
   --  @param Prime_Q     q, for CRT
   --  @param Exponent_P  d mod (p-1), for CRT
   --  @param Exponent_Q  d mod (q-1), for CRT
   --  @param Coefficient q inverse mod p, for CRT
   function Sign_PKCS1_V1_5
     (Modulus          : Ada.Streams.Stream_Element_Array;
      Public_Exponent  : Ada.Streams.Stream_Element_Array;
      Private_Exponent : Ada.Streams.Stream_Element_Array;
      Hash             : Hash_Algorithm;
      Message          : Ada.Streams.Stream_Element_Array;
      Rng              : in out CryptoLib.Random.Random_Source;
      Signature        : out Ada.Streams.Stream_Element_Array;
      Prime_P          : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Prime_Q          : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Exponent_P       : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Exponent_Q       : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Coefficient      : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0])
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
   --  @param Prime_P     p, for CRT; omit all five to sign the plain way
   --  @param Prime_Q     q, for CRT
   --  @param Exponent_P  d mod (p-1), for CRT
   --  @param Exponent_Q  d mod (q-1), for CRT
   --  @param Coefficient q inverse mod p, for CRT
   function Sign_PSS
     (Modulus          : Ada.Streams.Stream_Element_Array;
      Public_Exponent  : Ada.Streams.Stream_Element_Array;
      Private_Exponent : Ada.Streams.Stream_Element_Array;
      Hash             : Hash_Algorithm;
      Salt_Length      : Natural;
      Message          : Ada.Streams.Stream_Element_Array;
      Rng              : in out CryptoLib.Random.Random_Source;
      Signature        : out Ada.Streams.Stream_Element_Array;
      Prime_P          : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Prime_Q          : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Exponent_P       : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Exponent_Q       : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Coefficient      : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0])
      return CryptoLib.Errors.Status;

   --  As Sign_PKCS1_V1_5, reusing a blinding pair instead of drawing one.
   --
   --  The pair is refreshed on each use, so one serves any number of
   --  signatures and the inverse is paid once. An unstarted pair is drawn here,
   --  so this is safe to call without Start_Blinding -- it just pays the
   --  inverse on the first signature instead of before the first.
   --  @param Modulus          the public modulus n
   --  @param Public_Exponent  the public exponent e
   --  @param Private_Exponent the private exponent d
   --  @param Hash             which digest to sign under
   --  @param Message          the message to sign
   --  @param Rng              the source a pair is drawn from if needed
   --  @param Pair             in out: the blinding pair, refreshed here
   --  @param Signature        out: the signature, zeroed on failure
   --  @param Prime_P     p, for CRT; omit all five to sign the plain way
   --  @param Prime_Q     q, for CRT
   --  @param Exponent_P  d mod (p-1), for CRT
   --  @param Exponent_Q  d mod (q-1), for CRT
   --  @param Coefficient q inverse mod p, for CRT
   --  @return Ok, Handshake_Failed when the pair belongs to another modulus,
   --    otherwise as the plain form
   function Sign_PKCS1_V1_5
     (Modulus          : Ada.Streams.Stream_Element_Array;
      Public_Exponent  : Ada.Streams.Stream_Element_Array;
      Private_Exponent : Ada.Streams.Stream_Element_Array;
      Hash             : Hash_Algorithm;
      Message          : Ada.Streams.Stream_Element_Array;
      Rng              : in out CryptoLib.Random.Random_Source;
      Pair             : in out Blinding_Pair;
      Signature        : out Ada.Streams.Stream_Element_Array;
      Prime_P          : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Prime_Q          : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Exponent_P       : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Exponent_Q       : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Coefficient      : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0])
      return CryptoLib.Errors.Status;

   --  As Sign_PSS, reusing a blinding pair. The random source is still drawn
   --  on for the salt, which is a different randomness from the blinding.
   --  @param Modulus          the public modulus n
   --  @param Public_Exponent  the public exponent e
   --  @param Private_Exponent the private exponent d
   --  @param Hash             which digest to sign under
   --  @param Salt_Length      how many salt octets to draw
   --  @param Message          the message to sign
   --  @param Rng              the source for the salt, and for a pair if
   --    one has not been started
   --  @param Pair             in out: the blinding pair, refreshed here
   --  @param Signature        out: the signature, zeroed on failure
   --  @param Prime_P     p, for CRT; omit all five to sign the plain way
   --  @param Prime_Q     q, for CRT
   --  @param Exponent_P  d mod (p-1), for CRT
   --  @param Exponent_Q  d mod (q-1), for CRT
   --  @param Coefficient q inverse mod p, for CRT
   --  @return Ok, Handshake_Failed when the pair belongs to another modulus,
   --    otherwise as the plain form
   function Sign_PSS
     (Modulus          : Ada.Streams.Stream_Element_Array;
      Public_Exponent  : Ada.Streams.Stream_Element_Array;
      Private_Exponent : Ada.Streams.Stream_Element_Array;
      Hash             : Hash_Algorithm;
      Salt_Length      : Natural;
      Message          : Ada.Streams.Stream_Element_Array;
      Rng              : in out CryptoLib.Random.Random_Source;
      Pair             : in out Blinding_Pair;
      Signature        : out Ada.Streams.Stream_Element_Array;
      Prime_P          : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Prime_Q          : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Exponent_P       : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Exponent_Q       : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Coefficient      : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0])
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

private

   --  Wide enough for a 4096-bit modulus, which is the largest key generated
   --  here and the largest a pair is useful for.
   Maximum_Pair_Width : constant := 512;

   type Blinding_Pair is limited record
      Factor  : Ada.Streams.Stream_Element_Array (1 .. Maximum_Pair_Width) :=
        [others => 0];                 --  r**e mod n, what the input is
                                       --  multiplied by
      Inverse : Ada.Streams.Stream_Element_Array (1 .. Maximum_Pair_Width) :=
        [others => 0];                 --  r inverse mod n, what undoes it
      Width   : Ada.Streams.Stream_Element_Offset := 0;
      Ready   : Boolean := False;
   end record;

end CryptoLib.RSA;
