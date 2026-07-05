with CryptoLib.MLKEM768;
with CryptoLib.SNTRUP761;

package body CryptoLib.Hybrid_PQ_Kex
  with SPARK_Mode => On
is

   function Kind_Of (Name_Text : String) return Hybrid_PQ_Kind is
   begin
      if Name_Text = "mlkem768x25519-sha256" then
         return MLKEM768_X25519_SHA256;
      elsif Name_Text = "mlkem768x25519-sha512" then
         return MLKEM768_X25519_SHA512;
      elsif Name_Text = "sntrup761x25519-sha512@openssh.com" then
         return SNTRUP761_X25519_SHA512_OpenSSH;
      elsif Name_Text = "sntrup761x25519-sha512" then
         return SNTRUP761_X25519_SHA512;
      else
         return Not_Hybrid_PQ;
      end if;
   end Kind_Of;

   function Is_OpenSSH_Hybrid_PQ_Kex_Name (Name_Text : String) return Boolean
   is
   begin
      return Kind_Of (Name_Text) /= Not_Hybrid_PQ;
   end Is_OpenSSH_Hybrid_PQ_Kex_Name;

   function Is_MLKEM768_Hybrid_PQ_Kex_Name (Name_Text : String) return Boolean
   is
   begin
      return
        Kind_Of (Name_Text) in MLKEM768_X25519_SHA256 | MLKEM768_X25519_SHA512;
   end Is_MLKEM768_Hybrid_PQ_Kex_Name;

   function Is_SNTRUP761_Hybrid_PQ_Kex_Name (Name_Text : String) return Boolean
   is
   begin
      return
        Kind_Of (Name_Text)
        in SNTRUP761_X25519_SHA512_OpenSSH | SNTRUP761_X25519_SHA512;
   end Is_SNTRUP761_Hybrid_PQ_Kex_Name;

   function Uses_SHA512_Combiner (Name_Text : String) return Boolean is
   begin
      return
        Kind_Of (Name_Text)
        in MLKEM768_X25519_SHA512
         | SNTRUP761_X25519_SHA512_OpenSSH
         | SNTRUP761_X25519_SHA512;
   end Uses_SHA512_Combiner;

   function Client_Init_PQ_Length (Name_Text : String) return Natural is
   begin
      if Is_MLKEM768_Hybrid_PQ_Kex_Name (Name_Text) then
         return CryptoLib.MLKEM768.Public_Key_Length;
      elsif Is_SNTRUP761_Hybrid_PQ_Kex_Name (Name_Text) then
         return CryptoLib.SNTRUP761.Public_Key_Length;
      else
         return 0;
      end if;
   end Client_Init_PQ_Length;

   function Server_Reply_PQ_Length (Name_Text : String) return Natural is
   begin
      if Is_MLKEM768_Hybrid_PQ_Kex_Name (Name_Text) then
         return CryptoLib.MLKEM768.Ciphertext_Length;
      elsif Is_SNTRUP761_Hybrid_PQ_Kex_Name (Name_Text) then
         return CryptoLib.SNTRUP761.Ciphertext_Length;
      else
         return 0;
      end if;
   end Server_Reply_PQ_Length;

   function Client_Init_Total_Length (Name_Text : String) return Natural is
   begin
      if Is_MLKEM768_Hybrid_PQ_Kex_Name (Name_Text) then
         return CryptoLib.MLKEM768.Public_Key_Length + 32;
      elsif Is_SNTRUP761_Hybrid_PQ_Kex_Name (Name_Text) then
         return CryptoLib.SNTRUP761.Public_Key_Length + 32;
      else
         return 0;
      end if;
   end Client_Init_Total_Length;

   function Server_Reply_Total_Length (Name_Text : String) return Natural is
   begin
      if Is_MLKEM768_Hybrid_PQ_Kex_Name (Name_Text) then
         return CryptoLib.MLKEM768.Ciphertext_Length + 32;
      elsif Is_SNTRUP761_Hybrid_PQ_Kex_Name (Name_Text) then
         return CryptoLib.SNTRUP761.Ciphertext_Length + 32;
      else
         return 0;
      end if;
   end Server_Reply_Total_Length;

   function Readiness_Of (Name_Text : String) return Hybrid_PQ_Readiness is
   begin
      case Kind_Of (Name_Text) is
         when Not_Hybrid_PQ                                             =>
            return Unknown_Algorithm;

         when MLKEM768_X25519_SHA256 | MLKEM768_X25519_SHA512           =>
            --  The ML-KEM-768 public KEM boundary, imported ACVP JSON
            --  expected-results corpus, transport wrapper, and recorded
            --  OpenSSH transcript validation gate are present.
            return Advertised_And_Selectable;

         when SNTRUP761_X25519_SHA512_OpenSSH | SNTRUP761_X25519_SHA512 =>
            --  The SNTRUP761 public KEM boundary, bundled OpenSSH-shaped
            --  corpus, transport wrapper, and recorded OpenSSH transcript
            --  validation gate are present.
            return Advertised_And_Selectable;
      end case;
   end Readiness_Of;

   function Readiness_Image (Value : Hybrid_PQ_Readiness) return String is
   begin
      case Value is
         when Unknown_Algorithm                 =>
            return "unknown-algorithm";

         when KEM_Boundary_Present              =>
            return "kem-boundary-present";

         when External_KAT_Gate_Pending         =>
            return "external-kat-gate-pending";

         when Live_OpenSSH_Interop_Gate_Pending =>
            return "live-openssh-interop-gate-pending";

         when Advertised_And_Selectable         =>
            return "advertised-and-selectable";
      end case;
   end Readiness_Image;

   function Is_Implemented (Name_Text : String) return Boolean is
   begin
      --  Hybrid/PQ KEX is selectable only for the four OpenSSH-compatible
      --  names whose KEM boundaries, length policy, hash combiner policy,
      --  KAT corpora, and OpenSSH transcript-validation fixtures are present.
      return Is_OpenSSH_Hybrid_PQ_Kex_Name (Name_Text);
   end Is_Implemented;

   function Fail_Closed_Status
     (Name_Text : String) return CryptoLib.Errors.Status is
   begin
      if Is_OpenSSH_Hybrid_PQ_Kex_Name (Name_Text) then
         if Is_Implemented (Name_Text) then
            return CryptoLib.Errors.Ok;
         else
            return CryptoLib.Errors.Unsupported_Feature;
         end if;
      end if;

      return CryptoLib.Errors.Handshake_Failed;
   end Fail_Closed_Status;

end CryptoLib.Hybrid_PQ_Kex;
