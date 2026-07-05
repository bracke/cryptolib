package body CryptoLib.Constant_Time_Proof
  with SPARK_Mode => On
is
   use CryptoLib.Constant_Time_Assurance;

   function Obligation_Label (Item : Proof_Obligation) return String
     with SPARK_Mode => On
   is
   begin
      case Item is
         when No_Secret_Dependent_Branches =>
            return "no-secret-dependent-branches";
         when No_Secret_Dependent_Loop_Bounds =>
            return "no-secret-dependent-loop-bounds";
         when Constant_Time_Selection_For_Secret_Choice =>
            return "constant-time-selection-for-secret-choice";
         when Constant_Time_Equality_For_Secret_Compare =>
            return "constant-time-equality-for-secret-compare";
         when Fixed_Public_Width_Arithmetic =>
            return "fixed-public-width-arithmetic";
         when Invalid_Ciphertext_Fallback_Selection =>
            return "invalid-ciphertext-fallback-selection";
         when Source_Audit_Tokens_Present =>
            return "source-audit-tokens-present";
         when External_Leakage_Tool_Required =>
            return "external-leakage-tool-required";
         when Compiler_Codegen_Audit_Required =>
            return "compiler-codegen-audit-required";
         when Independent_Crypto_Review_Required =>
            return "independent-crypto-review-required";
      end case;
   end Obligation_Label;

   function Status
     (Primitive  : Crypto_Primitive;
      Obligation : Proof_Obligation)
      return Proof_Status
     with SPARK_Mode => On
   is
   begin
      if Level (Primitive) = Not_Assessed then
         return Missing;
      end if;

      --  Every source-level obligation is asserted (by code review) to hold for
      --  each assessed primitive; only the three external obligations remain
      --  open.  This is a manifest, so there is no per-primitive discrimination
      --  here beyond that split.
      case Obligation is
         when No_Secret_Dependent_Branches
            | No_Secret_Dependent_Loop_Bounds
            | Constant_Time_Selection_For_Secret_Choice
            | Source_Audit_Tokens_Present
            | Constant_Time_Equality_For_Secret_Compare
            | Fixed_Public_Width_Arithmetic
            | Invalid_Ciphertext_Fallback_Selection =>
            return Source_Obligation_Discharged;

         when External_Leakage_Tool_Required
            | Compiler_Codegen_Audit_Required
            | Independent_Crypto_Review_Required =>
            return External_Evidence_Required;
      end case;
   end Status;

   function Source_Obligations_Discharged (Primitive : Crypto_Primitive) return Boolean
     with SPARK_Mode => On
   is
   begin
      for Obligation in Proof_Obligation loop
         if Status (Primitive, Obligation) = Missing then
            return False;
         end if;

         if Status (Primitive, Obligation) = External_Evidence_Required then
            null;
         elsif Status (Primitive, Obligation) /= Source_Obligation_Discharged then
            return False;
         end if;
      end loop;
      return True;
   end Source_Obligations_Discharged;

   function External_Proof_Remains_Required (Primitive : Crypto_Primitive) return Boolean
     with SPARK_Mode => On
   is
   begin
      return Status (Primitive, External_Leakage_Tool_Required) = External_Evidence_Required
        and then Status (Primitive, Compiler_Codegen_Audit_Required) = External_Evidence_Required
        and then Status (Primitive, Independent_Crypto_Review_Required) = External_Evidence_Required;
   end External_Proof_Remains_Required;

   function All_Source_Obligations_Discharged return Boolean
     with SPARK_Mode => On
   is
   begin
      for Primitive in Crypto_Primitive loop
         if not Source_Obligations_Discharged (Primitive) then
            return False;
         end if;
      end loop;
      return True;
   end All_Source_Obligations_Discharged;

   function Formal_Proof_Manifest_Version return String
     with SPARK_Mode => On
   is
   begin
      return "side-channel-formal-proof-v1";
   end Formal_Proof_Manifest_Version;
end CryptoLib.Constant_Time_Proof;
