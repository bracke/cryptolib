with Ada.Streams;
with CryptoLib.Errors;
with CryptoLib.Random;

--  @summary ML-DSA (FIPS 204), the module-lattice digital signature: the
--  post-quantum signature to sit beside the post-quantum KEMs this crate
--  already has.
--
--  CryptoLib.MLKEM768 and CryptoLib.SNTRUP761 cover key establishment against
--  a quantum adversary; nothing here covered signatures until this. A protocol
--  that hybridises its key exchange and then authenticates it with Ed25519 has
--  moved the problem rather than solved it, if the threat is an adversary who
--  records now and factors later -- though for authentication, unlike
--  confidentiality, the recording attack does not apply, so the urgency is
--  lower and the migration is about certificate chains rather than sessions.
--
--  Three parameter sets, as FIPS 204 defines them. ML_DSA_65 is the usual
--  choice; ML_DSA_44 is the smallest and ML_DSA_87 the most conservative.
--
--  Signatures are large. ML-DSA-44 produces 2420 octets against Ed25519's 64,
--  and public keys 1312 against 32. That is the cost of the assumption
--  changing, and it is worth knowing before a protocol commits to it.
--
--  Not constant-time in the sense the ciphers here are. ML-DSA signing
--  rejects and retries, so its running time depends on values derived from
--  the private key -- that is inherent to the design and FIPS 204 accepts it.
--  What must not leak is the key itself through a data-dependent memory
--  access, and the implementation avoids those.
package CryptoLib.MLDSA is

   --  Which parameter set. The numbers are FIPS 204's.
   type Parameter_Set is (ML_DSA_44, ML_DSA_65, ML_DSA_87);

   --  The encoded public key length, in octets: 1312, 1952 or 2592.
   --  @param Set which parameter set
   --  @return the public key length
   function Public_Key_Length (Set : Parameter_Set) return Positive;

   --  The encoded private key length, in octets: 2560, 4032 or 4896.
   --  @param Set which parameter set
   --  @return the private key length
   function Private_Key_Length (Set : Parameter_Set) return Positive;

   --  The signature length, in octets: 2420, 3309 or 4627.
   --  @param Set which parameter set
   --  @return the signature length
   function Signature_Length (Set : Parameter_Set) return Positive;

   --  Derive a keypair from a 32-octet seed.
   --
   --  FIPS 204's KeyGen_internal. Exposed with the seed explicit because that
   --  is what makes a key reproducible, which is what the standard's own test
   --  vectors are stated in terms of.
   --  @param Set        which parameter set
   --  @param Seed       the 32-octet seed
   --  @param Public_Key out: the encoded public key, zeroed on failure
   --  @param Private_Key out: the encoded private key, zeroed on failure
   --  @return Ok, or Handshake_Failed on a wrong-length buffer
   function Key_From_Seed
     (Set         : Parameter_Set;
      Seed        : Ada.Streams.Stream_Element_Array;
      Public_Key  : out Ada.Streams.Stream_Element_Array;
      Private_Key : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Generate a keypair from the random source.
   --  @param Set         which parameter set
   --  @param Rng         the random source
   --  @param Public_Key  out: the encoded public key, zeroed on failure
   --  @param Private_Key out: the encoded private key, zeroed on failure
   --  @return Ok, Handshake_Failed on a wrong-length buffer, Internal_Error
   --    when the source will not yield a seed
   function Generate_Keypair
     (Set         : Parameter_Set;
      Rng         : in out CryptoLib.Random.Random_Source;
      Public_Key  : out Ada.Streams.Stream_Element_Array;
      Private_Key : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

end CryptoLib.MLDSA;
