--  @summary Declarative manifest of the side-channel assurance level assigned
--  to each cryptographic primitive.
--
--  Maps every Crypto_Primitive to an Assurance_Level recorded by code review;
--  it performs no timing measurement and always flags that independent external
--  review is still required.
package CryptoLib.Constant_Time_Assurance
  with SPARK_Mode => On
is
   pragma Preelaborate;

   type Crypto_Primitive is
     (RSA_Private_Exponentiation,
      RSA_PKCS1_Verification,
      ECDSA_P256_Scalar_Arithmetic,
      Ed25519_Scalar_Arithmetic,
      X25519_Scalar_Multiplication,
      DH_Group14_Exponentiation,
      DH_Group16_Exponentiation,
      DH_Group18_Exponentiation,
      MLKEM768_Decapsulation,
      SNTRUP761_Decapsulation,
      UMAC_Tag_Generation,
      Packet_MAC_Verification);

   type Assurance_Level is
     (Not_Assessed,
      Branch_Hardened,
      Fixed_Iteration_Audited,
      Source_Gated_Formal_Assurance,
      External_Proof_Required);

   --  Return the stable lowercase identifier for a primitive.
   --  @param Item the primitive to name
   --  @return the manifest label, e.g. "rsa-private-exponentiation"
   function Primitive_Label (Item : Crypto_Primitive) return String
     with SPARK_Mode => On;

   --  Return the assurance level recorded for a primitive.
   --  @param Item the primitive to query
   --  @return its Assurance_Level classification
   function Level (Item : Crypto_Primitive) return Assurance_Level
     with SPARK_Mode => On;

   --  Report whether a primitive carries an audited or source-gated level.
   --  @param Item the primitive to query
   --  @return True when the level is Fixed_Iteration_Audited or Source_Gated_Formal_Assurance
   function Is_Assurance_Gated (Item : Crypto_Primitive) return Boolean
     with SPARK_Mode => On;

   --  Report whether independent external review is still required.
   --  @param Item the primitive to query
   --  @return True for every primitive; the in-tree gate never substitutes for external review
   function Requires_External_Review (Item : Crypto_Primitive) return Boolean
     with SPARK_Mode => On;

   --  Return the version tag of this assurance manifest.
   --  @return the manifest version string
   function Manifest_Version return String
     with SPARK_Mode => On;

   --  Report whether every primitive has a labelled, gated assurance level.
   --  @return True when all primitives are assessed and gated
   function All_Primitives_Assessed return Boolean
     with SPARK_Mode => On;
end CryptoLib.Constant_Time_Assurance;
