package body CryptoLib.Constant_Time_Assurance
  with SPARK_Mode => On
is
   function Primitive_Label (Item : Crypto_Primitive) return String
     with SPARK_Mode => On
   is
   begin
      case Item is
         when RSA_Private_Exponentiation =>
            return "rsa-private-exponentiation";
         when RSA_PKCS1_Verification =>
            return "rsa-pkcs1-verification";
         when ECDSA_P256_Scalar_Arithmetic =>
            return "ecdsa-p256-scalar-arithmetic";
         when Ed25519_Scalar_Arithmetic =>
            return "ed25519-scalar-arithmetic";
         when X25519_Scalar_Multiplication =>
            return "x25519-scalar-multiplication";
         when DH_Group14_Exponentiation =>
            return "dh-group14-exponentiation";
         when DH_Group16_Exponentiation =>
            return "dh-group16-exponentiation";
         when DH_Group18_Exponentiation =>
            return "dh-group18-exponentiation";
         when MLKEM768_Decapsulation =>
            return "mlkem768-decapsulation";
         when SNTRUP761_Decapsulation =>
            return "sntrup761-decapsulation";
         when UMAC_Tag_Generation =>
            return "umac-tag-generation";
         when Packet_MAC_Verification =>
            return "packet-mac-verification";
      end case;
   end Primitive_Label;

   function Level (Item : Crypto_Primitive) return Assurance_Level
     with SPARK_Mode => On
   is
   begin
      case Item is
         when RSA_Private_Exponentiation
            | RSA_PKCS1_Verification
            | ECDSA_P256_Scalar_Arithmetic
            | Ed25519_Scalar_Arithmetic
            | X25519_Scalar_Multiplication
            | DH_Group14_Exponentiation
            | DH_Group16_Exponentiation
            | DH_Group18_Exponentiation
            | Packet_MAC_Verification =>
            return Source_Gated_Formal_Assurance;
         when MLKEM768_Decapsulation
            | SNTRUP761_Decapsulation
            | UMAC_Tag_Generation =>
            return Fixed_Iteration_Audited;
      end case;
   end Level;

   function Is_Assurance_Gated (Item : Crypto_Primitive) return Boolean
     with SPARK_Mode => On
   is
   begin
      return Level (Item) in Fixed_Iteration_Audited .. Source_Gated_Formal_Assurance;
   end Is_Assurance_Gated;

   function Requires_External_Review (Item : Crypto_Primitive) return Boolean
     with SPARK_Mode => On
   is
      pragma Unreferenced (Item);
   begin
      --  The in-tree gate is a formal source/evidence gate.  It is not a
      --  replacement for independent leakage tooling, compiler inspection, or
      --  third-party cryptographic review.
      return True;
   end Requires_External_Review;

   function Manifest_Version return String
     with SPARK_Mode => On
   is
   begin
      return "side-channel-assurance-v1";
   end Manifest_Version;

   function All_Primitives_Assessed return Boolean
     with SPARK_Mode => On
   is
   begin
      for Item in Crypto_Primitive loop
         if Level (Item) = Not_Assessed
           or else Primitive_Label (Item)'Length = 0
           or else not Is_Assurance_Gated (Item)
         then
            return False;
         end if;
      end loop;
      return True;
   end All_Primitives_Assessed;
end CryptoLib.Constant_Time_Assurance;
