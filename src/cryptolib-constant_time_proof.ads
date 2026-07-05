with CryptoLib.Constant_Time_Assurance;

--  @summary Declarative manifest recording which source-level constant-time
--  obligations each primitive is asserted (by review) to discharge, and which
--  still require external evidence.
--
--  DECLARATIVE MANIFEST, NOT AN AUTOMATED PROOF.  This package records which
--  source-level constant-time obligations the crypto primitives are asserted
--  (by code review) to satisfy.  It performs no timing measurement, no leakage
--  analysis, and no codegen inspection of its own; the source obligations are
--  always reported as discharged for any assessed primitive.  The obligations
--  that genuinely require external work -- External_Leakage_Tool_Required,
--  Compiler_Codegen_Audit_Required and Independent_Crypto_Review_Required --
--  always report External_Evidence_Required and are never discharged here.
--  "Formal_Proof" in the names below is historical; read it as "manifest".
package CryptoLib.Constant_Time_Proof
  with SPARK_Mode => On
is
   pragma Preelaborate;

   type Proof_Obligation is
     (No_Secret_Dependent_Branches,
      No_Secret_Dependent_Loop_Bounds,
      Constant_Time_Selection_For_Secret_Choice,
      Constant_Time_Equality_For_Secret_Compare,
      Fixed_Public_Width_Arithmetic,
      Invalid_Ciphertext_Fallback_Selection,
      Source_Audit_Tokens_Present,
      External_Leakage_Tool_Required,
      Compiler_Codegen_Audit_Required,
      Independent_Crypto_Review_Required);

   type Proof_Status is
     (Missing,
      Source_Obligation_Discharged,
      External_Evidence_Required);

   --  Return the stable lowercase identifier for an obligation.
   --  @param Item the obligation to name
   --  @return the manifest label, e.g. "no-secret-dependent-branches"
   function Obligation_Label (Item : Proof_Obligation) return String
     with SPARK_Mode => On;

   --  Return the manifest status of one obligation for one primitive.
   --  @param Primitive  the primitive being assessed
   --  @param Obligation the obligation of interest
   --  @return Missing if the primitive is unassessed, External_Evidence_Required
   --    for the three external obligations, otherwise Source_Obligation_Discharged
   function Status
     (Primitive  : CryptoLib.Constant_Time_Assurance.Crypto_Primitive;
      Obligation : Proof_Obligation)
      return Proof_Status
     with SPARK_Mode => On;

   --  Report whether every source-level obligation is discharged for a primitive.
   --  @param Primitive the primitive to check
   --  @return True when no obligation reports Missing (external ones may remain open)
   function Source_Obligations_Discharged
     (Primitive : CryptoLib.Constant_Time_Assurance.Crypto_Primitive)
      return Boolean
     with SPARK_Mode => On;

   --  Report whether the external obligations still await outside evidence.
   --  @param Primitive the primitive to check
   --  @return True when all three external obligations report External_Evidence_Required
   function External_Proof_Remains_Required
     (Primitive : CryptoLib.Constant_Time_Assurance.Crypto_Primitive)
      return Boolean
     with SPARK_Mode => On;

   --  Report whether the source obligations hold across every primitive.
   --  @return True when Source_Obligations_Discharged holds for all primitives
   function All_Source_Obligations_Discharged return Boolean
     with SPARK_Mode => On;

   --  Return the version tag of this proof manifest.
   --  @return the manifest version string
   function Formal_Proof_Manifest_Version return String
     with SPARK_Mode => On;
end CryptoLib.Constant_Time_Proof;
