with Ada.Streams;
with CryptoLib.Errors;
with CryptoLib.Random;

--  @summary ML-KEM (FIPS 203), the module-lattice key-encapsulation
--  mechanism, in all three parameter sets.
--
--  CryptoLib.MLKEM768 came first and covers the one parameter set that SSH
--  and the TLS hybrids actually negotiate. This covers the standard: FIPS 203
--  defines ML-KEM-512, ML-KEM-768 and ML-KEM-1024, and a library that has one
--  of them cannot be configured to a policy that names another. CNSA 2.0 is
--  the concrete case -- it requires ML-KEM-1024 with ML-DSA-87, and the
--  ML-DSA side of that pair was already here.
--
--  Which one:
--
--  * **ML-KEM-768** unless a policy says otherwise. It is the set the hybrid
--    key exchanges use, and FIPS 203's own recommendation as the default.
--  * **ML-KEM-1024** when the policy asks for NIST category 5 -- CNSA 2.0
--    does. Larger keys and ciphertexts, and slower, for a margin above what
--    768 already provides.
--  * **ML-KEM-512** only to interoperate with something that chose it.
--
--  Decapsulation never reports failure. FIPS 203 uses implicit rejection: a
--  ciphertext that does not re-encrypt to itself yields a pseudorandom shared
--  secret derived from the key's rejection seed, rather than an error that
--  would tell an attacker their probe was detected. A caller that wants to
--  know whether the peer agreed must find out by using the secret, which is
--  what a key exchange does anyway.
--
--  CryptoLib.MLKEM768 is now a thin wrapper over this package, so the KEM
--  exists once rather than twice. Its fixed-length subtypes are still the
--  better interface for a caller that only wants that parameter set, and
--  ssh_lib's key exchange is typed on them; only the implementation moved.

package CryptoLib.MLKEM is

   --  Which parameter set. The numbers are FIPS 203's module ranks scaled to
   --  the usual names: k = 2, 3 and 4 respectively.
   type Parameter_Set is (ML_KEM_512, ML_KEM_768, ML_KEM_1024);

   --  The shared secret is 32 octets for every parameter set.
   Shared_Key_Length : constant := 32;

   --  The encapsulation (public) key length in octets: 800, 1184 or 1568.
   --  @param Set which parameter set
   --  @return the public key length
   function Public_Key_Length (Set : Parameter_Set) return Positive;

   --  The decapsulation (secret) key length in octets: 1632, 2400 or 3168.
   --  @param Set which parameter set
   --  @return the secret key length
   function Secret_Key_Length (Set : Parameter_Set) return Positive;

   --  The ciphertext length in octets: 768, 1088 or 1568.
   --  @param Set which parameter set
   --  @return the ciphertext length
   function Ciphertext_Length (Set : Parameter_Set) return Positive;

   --  Derive a keypair from the two 32-octet seeds (FIPS 203
   --  ML-KEM.KeyGen_internal).
   --
   --  Exposed with the seeds explicit because that is what makes a key
   --  reproducible, and what the standard's own test vectors are stated in
   --  terms of. Use Generate_Keypair for a real key.
   --  @param Set         which parameter set
   --  @param D           the 32-octet key seed
   --  @param Z           the 32-octet implicit-rejection seed
   --  @param Public_Key  out: the encapsulation key, zeroed on failure
   --  @param Secret_Key  out: the decapsulation key, zeroed on failure
   --  @return Ok, or Handshake_Failed on a wrong-length argument
   function Key_From_Seeds
     (Set        : Parameter_Set;
      D          : Ada.Streams.Stream_Element_Array;
      Z          : Ada.Streams.Stream_Element_Array;
      Public_Key : out Ada.Streams.Stream_Element_Array;
      Secret_Key : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Generate a keypair from the random source.
   --  @param Set        which parameter set
   --  @param Rng        the random source
   --  @param Public_Key out: the encapsulation key, zeroed on failure
   --  @param Secret_Key out: the decapsulation key, zeroed on failure
   --  @return Ok, Handshake_Failed on a wrong-length buffer, or
   --    Internal_Error when the source will not yield seeds
   function Generate_Keypair
     (Set        : Parameter_Set;
      Rng        : in out CryptoLib.Random.Random_Source;
      Public_Key : out Ada.Streams.Stream_Element_Array;
      Secret_Key : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Encapsulate with a caller-supplied message (FIPS 203
   --  ML-KEM.Encaps_internal).
   --
   --  Deterministic, and therefore what the standard's vectors are stated in
   --  terms of. A real encapsulation must use Encapsulate, which draws the
   --  message from the random source: reusing a message across two
   --  encapsulations to the same key reproduces the shared secret.
   --  @param Set        which parameter set
   --  @param Public_Key the recipient's encapsulation key
   --  @param Message    the 32-octet message
   --  @param Ciphertext out: the ciphertext, zeroed on failure
   --  @param Shared_Key out: the 32-octet shared secret, zeroed on failure
   --  @return Ok, or Handshake_Failed on a wrong-length argument
   function Encapsulate_With_Message
     (Set        : Parameter_Set;
      Public_Key : Ada.Streams.Stream_Element_Array;
      Message    : Ada.Streams.Stream_Element_Array;
      Ciphertext : out Ada.Streams.Stream_Element_Array;
      Shared_Key : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Encapsulate to a public key, drawing the message from the source.
   --  @param Set        which parameter set
   --  @param Rng        the random source
   --  @param Public_Key the recipient's encapsulation key
   --  @param Ciphertext out: the ciphertext, zeroed on failure
   --  @param Shared_Key out: the 32-octet shared secret, zeroed on failure
   --  @return Ok, Handshake_Failed on a wrong-length argument, or
   --    Internal_Error when the source will not yield a message
   function Encapsulate
     (Set        : Parameter_Set;
      Rng        : in out CryptoLib.Random.Random_Source;
      Public_Key : Ada.Streams.Stream_Element_Array;
      Ciphertext : out Ada.Streams.Stream_Element_Array;
      Shared_Key : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Decapsulate a ciphertext.
   --
   --  Returns Ok for a tampered ciphertext as well as a genuine one, with the
   --  implicit-rejection secret in the second case -- see the note above.
   --  @param Set        which parameter set
   --  @param Secret_Key the decapsulation key
   --  @param Ciphertext the received ciphertext
   --  @param Shared_Key out: the 32-octet shared secret, or the rejection
   --    secret, zeroed only on a wrong-length argument
   --  @return Ok, or Handshake_Failed on a wrong-length argument
   function Decapsulate
     (Set        : Parameter_Set;
      Secret_Key : Ada.Streams.Stream_Element_Array;
      Ciphertext : Ada.Streams.Stream_Element_Array;
      Shared_Key : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

end CryptoLib.MLKEM;
