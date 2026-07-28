with Ada.Streams;
with Ada.Strings.Fixed;

with CryptoLib.Ciphers;
with CryptoLib.ECDSA;
with CryptoLib.Ed25519;
with CryptoLib.Errors;
with CryptoLib.Hashes;
with CryptoLib.Macs;
with CryptoLib.Random;

package body CryptoLib.Certificates is
   use Ada.Strings.Unbounded;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.Errors.Status;

   Hex : constant String := "0123456789abcdef";
   B64 : constant String :=
     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

   type Certificate_Profile is (CA_Profile, Server_Profile, Client_Profile,
                                Email_Profile);

   function Status_Image (Status : Certificate_Status) return String is
   begin
      case Status is
         when Ok =>
            return "ok";
         when Invalid_Input =>
            return "invalid input";
         when Unsupported_Profile =>
            return "unsupported profile";
         when Internal_Error =>
            return "internal error";
      end case;
   end Status_Image;

   function Byte (Value : Natural) return Character is
   begin
      return Character'Val (Value mod 256);
   end Byte;

   function To_Bytes (Text : String) return Ada.Streams.Stream_Element_Array is
      Result : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Text'Length));
      Pos : Ada.Streams.Stream_Element_Offset := Result'First;
   begin
      for C of Text loop
         Result (Pos) := Ada.Streams.Stream_Element (Character'Pos (C));
         Pos := Pos + 1;
      end loop;
      return Result;
   end To_Bytes;

   function To_String
     (Data : Ada.Streams.Stream_Element_Array) return String
   is
      Result : String (1 .. Natural (Data'Length));
      Pos    : Positive := Result'First;
   begin
      for B of Data loop
         Result (Pos) := Byte (Natural (B));
         Pos := Pos + 1;
      end loop;
      return Result;
   end To_String;

   procedure Append_Line (Target : in out Unbounded_String; Line : String) is
   begin
      Append (Target, Line);
      Append (Target, ASCII.LF);
   end Append_Line;

   function Hex_Image
     (Data : Ada.Streams.Stream_Element_Array) return String
   is
      Result : String (1 .. Data'Length * 2);
      Pos    : Positive := Result'First;
   begin
      for B of Data loop
         Result (Pos) := Hex (Natural (B) / 16 + 1);
         Result (Pos + 1) := Hex (Natural (B) mod 16 + 1);
         Pos := Pos + 2;
      end loop;
      return Result;
   end Hex_Image;

   function Digest_Hex (Text : String) return String is
   begin
      return Hex_Image
        (Ada.Streams.Stream_Element_Array
           (CryptoLib.Hashes.SHA256 (To_Bytes (Text))));
   end Digest_Hex;

   function DER_Length (Length : Natural) return String is
   begin
      if Length < 128 then
         return "" & Byte (Length);
      elsif Length < 256 then
         return Byte (16#81#) & Byte (Length);
      else
         return Byte (16#82#) & Byte (Length / 256) & Byte (Length mod 256);
      end if;
   end DER_Length;

   function TLV (Tag : Natural; Content : String) return String is
   begin
      return Byte (Tag) & DER_Length (Content'Length) & Content;
   end TLV;

   function Seq (Content : String) return String is (TLV (16#30#, Content));
   function Set_Of (Content : String) return String is (TLV (16#31#, Content));
   function Octets (Content : String) return String is (TLV (16#04#, Content));
   function Bits (Content : String) return String is (TLV (16#03#, Byte (0) & Content));
   function Explicit (Tag : Natural; Content : String) return String is
     (TLV (16#A0# + Tag, Content));
   function Bool (Value : Boolean) return String is
     (TLV (16#01#, "" & (if Value then Byte (16#FF#) else Byte (0))));
   function UTF8 (Value : String) return String is (TLV (16#0C#, Value));
   function UTC (Value : String) return String is (TLV (16#17#, Value));

   function Integer_DER (Value : Natural) return String is
   begin
      if Value < 128 then
         return TLV (16#02#, "" & Byte (Value));
      elsif Value < 16#8000# then
         return TLV (16#02#, Byte (Value / 256) & Byte (Value mod 256));
      else
         return TLV
           (16#02#,
            Byte (Value / 16#1000000#)
            & Byte ((Value / 16#10000#) mod 256)
            & Byte ((Value / 256) mod 256)
            & Byte (Value mod 256));
      end if;
   end Integer_DER;

   function OID (Content : String) return String is
   begin
      return TLV (16#06#, Content);
   end OID;

   function OID_Data return String is
   begin
      return OID
        (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#86#)
         & Byte (16#F7#) & Byte (16#0D#) & Byte (16#01#) & Byte (16#07#)
         & Byte (16#01#));
   end OID_Data;

   function OID_Shrouded_Key_Bag return String is
   begin
      return OID
        (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#86#)
         & Byte (16#F7#) & Byte (16#0D#) & Byte (16#01#) & Byte (16#0C#)
         & Byte (16#0A#) & Byte (16#01#) & Byte (16#02#));
   end OID_Shrouded_Key_Bag;

   function OID_Cert_Bag return String is
   begin
      return OID
        (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#86#)
         & Byte (16#F7#) & Byte (16#0D#) & Byte (16#01#) & Byte (16#0C#)
         & Byte (16#0A#) & Byte (16#01#) & Byte (16#03#));
   end OID_Cert_Bag;

   function OID_X509_Certificate return String is
   begin
      return OID
        (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#86#)
         & Byte (16#F7#) & Byte (16#0D#) & Byte (16#01#) & Byte (16#09#)
         & Byte (16#16#) & Byte (16#01#));
   end OID_X509_Certificate;

   function OID_SHA1 return String is
   begin
      return OID
        (Byte (16#2B#) & Byte (16#0E#) & Byte (16#03#) & Byte (16#02#)
         & Byte (16#1A#));
   end OID_SHA1;

   function OID_PBES2 return String is
   begin
      return OID
        (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#86#)
         & Byte (16#F7#) & Byte (16#0D#) & Byte (16#01#) & Byte (16#05#)
         & Byte (16#0D#));
   end OID_PBES2;

   function OID_PBKDF2 return String is
   begin
      return OID
        (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#86#)
         & Byte (16#F7#) & Byte (16#0D#) & Byte (16#01#) & Byte (16#05#)
         & Byte (16#0C#));
   end OID_PBKDF2;

   function OID_HMAC_SHA256 return String is
   begin
      return OID
        (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#86#)
         & Byte (16#F7#) & Byte (16#0D#) & Byte (16#02#) & Byte (16#09#));
   end OID_HMAC_SHA256;

   function OID_AES_256_CBC return String is
   begin
      return OID
        (Byte (16#60#) & Byte (16#86#) & Byte (16#48#) & Byte (16#01#)
         & Byte (16#65#) & Byte (16#03#) & Byte (16#04#) & Byte (16#01#)
         & Byte (16#2A#));
   end OID_AES_256_CBC;

   --  1.3.101.112 id-Ed25519
   function Ed25519_Algorithm return String is
   begin
      return Seq (OID (Byte (16#2B#) & Byte (16#65#) & Byte (16#70#)));
   end Ed25519_Algorithm;

   --  1.2.840.10045.2.1 id-ecPublicKey with 1.3.132.0.34 secp384r1: an EC key
   --  states its curve, where an Ed25519 key is only ever one thing.
   function P384_Algorithm return String is
   begin
      return Seq
        (OID (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#CE#)
              & Byte (16#3D#) & Byte (16#02#) & Byte (16#01#))
         & OID (Byte (16#2B#) & Byte (16#81#) & Byte (16#04#) & Byte (16#00#)
                & Byte (16#22#)));
   end P384_Algorithm;

   --  1.2.840.10045.4.3.3 ecdsa-with-SHA384. The signature algorithm is its
   --  own identifier here: Ed25519 names the hash inside the scheme, ECDSA
   --  pairs a curve with a digest and has to say which.
   function P384_Signature_Algorithm return String is
   begin
      return Seq
        (OID (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#CE#)
              & Byte (16#3D#) & Byte (16#04#) & Byte (16#03#) & Byte (16#03#)));
   end P384_Signature_Algorithm;

   function Algorithm_Identifier
     (Algorithm : Key_Algorithm := Ed25519_Key) return String is
   begin
      return (case Algorithm is
                 when Ed25519_Key => Ed25519_Algorithm,
                 when P384_Key    => P384_Algorithm);
   end Algorithm_Identifier;

   function Signature_Algorithm (Algorithm : Key_Algorithm) return String is
   begin
      return (case Algorithm is
                 when Ed25519_Key => Ed25519_Algorithm,
                 when P384_Key    => P384_Signature_Algorithm);
   end Signature_Algorithm;

   --  DER INTEGER from a big-endian magnitude: leading zeros are not part of
   --  the value, and a top bit that is set needs a zero byte in front or the
   --  integer reads as negative.
   function Integer_From_Bytes (Value : String) return String is
      First : Natural := Value'First;
   begin
      while First < Value'Last and then Value (First) = Character'Val (0) loop
         First := First + 1;
      end loop;

      if Character'Pos (Value (First)) >= 16#80# then
         return TLV (16#02#, Byte (0) & Value (First .. Value'Last));
      end if;
      return TLV (16#02#, Value (First .. Value'Last));
   end Integer_From_Bytes;

   function Name_DER (Common_Name : String) return String is
   begin
      return Seq
        (Set_Of
           (Seq
              (OID (Byte (16#55#) & Byte (16#04#) & Byte (16#03#))
               & UTF8 (Common_Name))));
   end Name_DER;

   function Validity_DER return String is
   begin
      return Seq (UTC ("260101000000Z") & UTC ("360101000000Z"));
   end Validity_DER;

   function SPKI_DER
     (Public_Key : Ada.Streams.Stream_Element_Array;
      Algorithm  : Key_Algorithm := Ed25519_Key) return String is
   begin
      return Seq
        (Algorithm_Identifier (Algorithm) & Bits (To_String (Public_Key)));
   end SPKI_DER;

   function Private_Key_DER
     (Seed : Ada.Streams.Stream_Element_Array) return String
   is
   begin
      return Seq
        (Integer_DER (0)
         & Algorithm_Identifier
         & Octets (Octets (To_String (Seed))));
   end Private_Key_DER;

   --  PKCS#8 around an RFC 5915 ECPrivateKey. The inner structure carries the
   --  public point as well: a reader that has only the scalar would otherwise
   --  have to multiply to learn the key it belongs to.
   function P384_Private_Key_DER
     (Scalar : Ada.Streams.Stream_Element_Array;
      Public : Ada.Streams.Stream_Element_Array) return String
   is
      Inner : constant String :=
        Seq
          (Integer_DER (1)
           & Octets (To_String (Scalar))
           & Explicit (1, Bits (To_String (Public))));
   begin
      return Seq
        (Integer_DER (0) & P384_Algorithm & Octets (Inner));
   end P384_Private_Key_DER;

   function Mac_Data
     (Authenticated_Safe : String;
      Password           : String;
      Salt               : Ada.Streams.Stream_Element_Array) return String
   is
      Iterations : constant Positive := 2048;
      Key        : constant Ada.Streams.Stream_Element_Array :=
        CryptoLib.Macs.PKCS12_KDF_SHA1
          --  The plain password: PKCS12_KDF_SHA1 widens it to a BMPString
          --  itself, and handing it one already widened produced a key for a
          --  password nobody typed -- so every bundle failed its own MAC check.
          (Password_Data => To_Bytes (Password),
           Salt_Data     => Salt,
           Iterations    => Iterations,
           Id_Byte       => 3,
           Output_Length => 20);
      Tag        : constant CryptoLib.Macs.HMAC_SHA1_Digest :=
        CryptoLib.Macs.HMAC_SHA1 (Key, To_Bytes (Authenticated_Safe));
      Digest_Info : constant String :=
        Seq
          (Seq (OID_SHA1 & TLV (16#05#, ""))
           & Octets (To_String (Ada.Streams.Stream_Element_Array (Tag))));
   begin
      return Seq
        (Digest_Info & Octets (To_String (Salt)) & Integer_DER (Iterations));
   end Mac_Data;

   function PKCS7_Pad
     (Data       : String;
      Block_Size : Positive) return Ada.Streams.Stream_Element_Array
   is
      Pad_Length : constant Positive :=
        (if Data'Length mod Block_Size = 0
         then Block_Size
         else Block_Size - (Data'Length mod Block_Size));
      Result : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Data'Length + Pad_Length));
      Pos : Ada.Streams.Stream_Element_Offset := Result'First;
   begin
      for C of Data loop
         Result (Pos) := Ada.Streams.Stream_Element (Character'Pos (C));
         Pos := Pos + 1;
      end loop;
      for Index_Value in 1 .. Pad_Length loop
         pragma Unreferenced (Index_Value);
         Result (Pos) := Ada.Streams.Stream_Element (Pad_Length);
         Pos := Pos + 1;
      end loop;
      return Result;
   end PKCS7_Pad;

   function PBES2_AES_256_CBC_Algorithm
     (Salt       : Ada.Streams.Stream_Element_Array;
      Iterations : Positive;
      IV_Data    : Ada.Streams.Stream_Element_Array) return String
   is
      PBKDF2_Params : constant String :=
        Seq
          (Octets (To_String (Salt))
           & Integer_DER (Iterations)
           & Integer_DER (32)
           & Seq (OID_HMAC_SHA256 & TLV (16#05#, "")));
      KDF_Algorithm : constant String := Seq (OID_PBKDF2 & PBKDF2_Params);
      Enc_Algorithm : constant String :=
        Seq (OID_AES_256_CBC & Octets (To_String (IV_Data)));
   begin
      return Seq (OID_PBES2 & Seq (KDF_Algorithm & Enc_Algorithm));
   end PBES2_AES_256_CBC_Algorithm;

   function Base64_Encode (Data : String) return String is
      Result : Unbounded_String;
      I      : Natural := Data'First;
      B1     : Natural;
      B2     : Natural;
      B3     : Natural;
      Count  : Natural;
   begin
      while I <= Data'Last loop
         B1 := Character'Pos (Data (I));
         B2 := 0;
         B3 := 0;
         Count := 1;
         if I + 1 <= Data'Last then
            B2 := Character'Pos (Data (I + 1));
            Count := 2;
         end if;
         if I + 2 <= Data'Last then
            B3 := Character'Pos (Data (I + 2));
            Count := 3;
         end if;
         Append (Result, B64 (B1 / 4 + 1));
         Append (Result, B64 (((B1 mod 4) * 16) + (B2 / 16) + 1));
         Append
           (Result,
            (if Count >= 2 then B64 (((B2 mod 16) * 4) + (B3 / 64) + 1)
             else '='));
         Append (Result, (if Count = 3 then B64 (B3 mod 64 + 1) else '='));
         I := I + 3;
      end loop;
      return To_String (Result);
   end Base64_Encode;

   function PEM (Label : String; DER : String) return Unbounded_String is
      Encoded : constant String := Base64_Encode (DER);
      Result  : Unbounded_String;
      I       : Natural := Encoded'First;
      Last    : Natural;
   begin
      Append_Line (Result, "-----BEGIN " & Label & "-----");
      while I <= Encoded'Last loop
         Last := Natural'Min (Encoded'Last, I + 63);
         Append_Line (Result, Encoded (I .. Last));
         I := Last + 1;
      end loop;
      Append_Line (Result, "-----END " & Label & "-----");
      return Result;
   end PEM;

   function Base64_Value (C : Character) return Integer is
   begin
      if C in 'A' .. 'Z' then
         return Character'Pos (C) - Character'Pos ('A');
      elsif C in 'a' .. 'z' then
         return Character'Pos (C) - Character'Pos ('a') + 26;
      elsif C in '0' .. '9' then
         return Character'Pos (C) - Character'Pos ('0') + 52;
      elsif C = '+' then
         return 62;
      elsif C = '/' then
         return 63;
      else
         return -1;
      end if;
   end Base64_Value;

   function Base64_Decode (Text : String) return String is
      Clean  : Unbounded_String;
      Result : Unbounded_String;
      I      : Natural;
      A      : Integer;
      B      : Integer;
      C      : Integer;
      D      : Integer;
      First  : Natural := Ada.Strings.Fixed.Index (Text, "" & ASCII.LF);
      Last   : Natural;
      Footer : Natural;
   begin
      if First = 0 then
         First := Text'First;
      else
         First := First + 1;
      end if;

      Footer := Ada.Strings.Fixed.Index (Text (First .. Text'Last), "-----END");
      if Footer = 0 then
         Last := Text'Last;
      else
         Last := Footer - 1;
      end if;

      for Ch of Text (First .. Last) loop
         if Base64_Value (Ch) >= 0 or else Ch = '=' then
            Append (Clean, Ch);
         end if;
      end loop;
      declare
         S : constant String := To_String (Clean);
      begin
         I := S'First;
         while I + 3 <= S'Last loop
            A := Base64_Value (S (I));
            B := Base64_Value (S (I + 1));
            C := (if S (I + 2) = '=' then -1 else Base64_Value (S (I + 2)));
            D := (if S (I + 3) = '=' then -1 else Base64_Value (S (I + 3)));
            if A < 0 or else B < 0 then
               return "";
            end if;
            Append (Result, Byte (A * 4 + B / 16));
            if C >= 0 then
               Append (Result, Byte ((B mod 16) * 16 + C / 4));
            end if;
            if C >= 0 and then D >= 0 then
               Append (Result, Byte ((C mod 4) * 64 + D));
            end if;
            I := I + 4;
         end loop;
      end;
      return To_String (Result);
   end Base64_Decode;

   function Contains (Data : String; Needle : String) return Boolean;

   --  Which algorithm a private key PEM carries. An Ed25519 key is only ever
   --  one thing; an EC key names its curve, so the curve OID in the DER is the
   --  discriminator.
   function Algorithm_Of_Private_Key (Private_Key_PEM : String) return Key_Algorithm is
      DER       : constant String := Base64_Decode (Private_Key_PEM);
      Secp384r1 : constant String :=
        Byte (16#2B#) & Byte (16#81#) & Byte (16#04#) & Byte (16#00#) & Byte (16#22#);
   begin
      if Contains (DER, Secp384r1) then
         return P384_Key;
      end if;
      return Ed25519_Key;
   end Algorithm_Of_Private_Key;

   --  The P-384 scalar out of a PKCS#8 ECPrivateKey: the 48-byte OCTET STRING
   --  inside it. Ed25519's seed is found the same way, by its own length, and
   --  neither shape can be mistaken for the other.
   function Scalar_From_Private_Key_PEM
     (Private_Key_PEM : String;
      Scalar          : out Ada.Streams.Stream_Element_Array) return Boolean
   is
      DER    : constant String := Base64_Decode (Private_Key_PEM);
      Wanted : constant Natural := Natural (Scalar'Length);
   begin
      Scalar := [others => 0];
      if DER'Length < Wanted + 2 then
         return False;
      end if;

      for I in DER'First .. DER'Last - Wanted - 1 loop
         if Character'Pos (DER (I)) = 16#04#
           and then Character'Pos (DER (I + 1)) = Wanted
         then
            for J in Scalar'Range loop
               Scalar (J) :=
                 Ada.Streams.Stream_Element
                   (Character'Pos (DER (I + 2 + Natural (J - Scalar'First))));
            end loop;
            return True;
         end if;
      end loop;
      return False;
   end Scalar_From_Private_Key_PEM;

   function Seed_From_Private_Key_PEM
     (Private_Key_PEM : String;
      Seed            : out Ada.Streams.Stream_Element_Array) return Boolean
   is
      DER : constant String := Base64_Decode (Private_Key_PEM);
   begin
      if Seed'Length /= 32 or else DER'Length < 34 then
         Seed := [others => 0];
         return False;
      end if;

      for I in DER'First .. DER'Last - 33 loop
         if Character'Pos (DER (I)) = 16#04#
           and then Character'Pos (DER (I + 1)) = 16#20#
         then
            for J in Seed'Range loop
               Seed (J) :=
                 Ada.Streams.Stream_Element
                   (Character'Pos
                      (DER (I + 2 + Natural (J - Seed'First))));
            end loop;
            return True;
         end if;
      end loop;

      Seed := [others => 0];
      return False;
   end Seed_From_Private_Key_PEM;

   function Valid_Name (Text : String) return Boolean is
   begin
      if Text = "" then
         return False;
      end if;

      for C of Text loop
         if not (C in 'a' .. 'z'
                 or else C in 'A' .. 'Z'
                 or else C in '0' .. '9'
                 or else C = '.'
                 or else C = '-'
                 or else C = '_'
                 or else C = '*')
         then
            return False;
         end if;
      end loop;
      return True;
   end Valid_Name;

   function Valid_Email (Text : String) return Boolean is
      At_Pos : Natural := 0;
      Dot_Pos : Natural := 0;
   begin
      if Text'Length < 3 then
         return False;
      end if;

      for I in Text'Range loop
         if Text (I) = '@' then
            if At_Pos /= 0 or else I = Text'First or else I = Text'Last then
               return False;
            end if;
            At_Pos := I;
         elsif Text (I) = '.' and then At_Pos /= 0 and then I > At_Pos + 1 then
            Dot_Pos := I;
         elsif not (Text (I) in 'a' .. 'z'
                    or else Text (I) in 'A' .. 'Z'
                    or else Text (I) in '0' .. '9'
                    or else Text (I) = '.'
                    or else Text (I) = '-'
                    or else Text (I) = '_'
                    or else Text (I) = '+')
         then
            return False;
         end if;
      end loop;

      return At_Pos /= 0 and then Dot_Pos /= 0 and then Dot_Pos < Text'Last;
   end Valid_Email;

   function IPv4_Bytes (Text : String) return String is
      Result      : String (1 .. 4);
      Part        : Natural := 0;
      Value       : Natural := 0;
      Digit_Count : Natural := 0;

      procedure Finish (Ok : in out Boolean) is
      begin
         if Digit_Count = 0 or else Value > 255 or else Part = 4 then
            Ok := False;
         else
            Part := Part + 1;
            Result (Part) := Byte (Value);
            Value := 0;
            Digit_Count := 0;
         end if;
      end Finish;

      Ok : Boolean := True;
   begin
      if Text = "" then
         return "";
      end if;

      for C of Text loop
         if C in '0' .. '9' then
            Value := Value * 10 + Character'Pos (C) - Character'Pos ('0');
            Digit_Count := Digit_Count + 1;
         elsif C = '.' then
            Finish (Ok);
            if not Ok then
               return "";
            end if;
         else
            return "";
         end if;
      end loop;

      Finish (Ok);
      if Ok and then Part = 4 then
         return Result;
      else
         return "";
      end if;
   end IPv4_Bytes;

   function Hex_Value (C : Character) return Integer is
   begin
      if C in '0' .. '9' then
         return Character'Pos (C) - Character'Pos ('0');
      elsif C in 'a' .. 'f' then
         return Character'Pos (C) - Character'Pos ('a') + 10;
      elsif C in 'A' .. 'F' then
         return Character'Pos (C) - Character'Pos ('A') + 10;
      else
         return -1;
      end if;
   end Hex_Value;

   function IPv6_Bytes (Text : String) return String is
      Groups          : array (1 .. 8) of Natural := [others => 0];
      Group_Count     : Natural := 0;
      Compress_Index  : Natural := 0;
      I               : Natural := Text'First;

      function Read_Group
        (Pos   : in out Natural;
         Value : out Natural) return Boolean
      is
         Digit_Total : Natural := 0;
         V      : Natural := 0;
         H      : Integer;
      begin
         Value := 0;
         while Pos <= Text'Last loop
            exit when Text (Pos) = ':';
            H := Hex_Value (Text (Pos));
            if H < 0 or else Digit_Total = 4 then
               return False;
            end if;
            V := V * 16 + Natural (H);
            Digit_Total := Digit_Total + 1;
            Pos := Pos + 1;
         end loop;
         if Digit_Total = 0 then
            return False;
         end if;
         Value := V;
         return True;
      end Read_Group;
   begin
      if Text'Length < 2 then
         return "";
      end if;

      while I <= Text'Last loop
         if Text (I) = ':' then
            if I = Text'Last or else Text (I + 1) /= ':' or else Compress_Index /= 0
            then
               return "";
            end if;
            Compress_Index := Group_Count + 1;
            I := I + 2;
            if I > Text'Last then
               exit;
            end if;
         else
            if Group_Count = 8 then
               return "";
            end if;
            Group_Count := Group_Count + 1;
            if not Read_Group (I, Groups (Group_Count)) then
               return "";
            end if;
            if I <= Text'Last then
               if Text (I) /= ':' then
                  return "";
               end if;
               I := I + 1;
            end if;
         end if;
      end loop;

      if Compress_Index = 0 and then Group_Count /= 8 then
         return "";
      elsif Compress_Index /= 0 then
         declare
            Missing : constant Natural := 8 - Group_Count;
         begin
            if Missing = 0 then
               return "";
            end if;
            for J in reverse Compress_Index .. Group_Count loop
               Groups (J + Missing) := Groups (J);
            end loop;
            for J in Compress_Index .. Compress_Index + Missing - 1 loop
               Groups (J) := 0;
            end loop;
         end;
      end if;

      declare
         Result : String (1 .. 16);
         Pos    : Positive := Result'First;
      begin
         for G of Groups loop
            Result (Pos) := Byte (G / 256);
            Result (Pos + 1) := Byte (G mod 256);
            Pos := Pos + 2;
         end loop;
         return Result;
      end;
   end IPv6_Bytes;

   function IP_Bytes (Text : String) return String is
      V4 : constant String := IPv4_Bytes (Text);
   begin
      if V4 /= "" then
         return V4;
      else
         return IPv6_Bytes (Text);
      end if;
   end IP_Bytes;

   function Valid_Profile_Name
     (Profile : Certificate_Profile;
      Text    : String) return Boolean
   is
   begin
      if Profile = Email_Profile then
         return Valid_Email (Text);
      else
         return Valid_Name (Text) or else IP_Bytes (Text) /= "";
      end if;
   end Valid_Profile_Name;

   function Extensions_DER
     (Profile : Certificate_Profile;
      Names   : Subject_Alternative_Name_List) return String
   is
      Items : Unbounded_String;
      SANs  : Unbounded_String;
   begin
      if Profile = CA_Profile then
         Append
           (Items,
            Seq
              (OID (Byte (16#55#) & Byte (16#1D#) & Byte (16#13#))
               & Bool (True)
               & Octets (Seq (Bool (True)))));
         Append
           (Items,
            Seq
              (OID (Byte (16#55#) & Byte (16#1D#) & Byte (16#0F#))
               & Bool (True)
               & Octets (TLV (16#03#, Byte (1) & Byte (16#06#)))));
      else
         for Name of Names loop
            declare
               Name_Text : constant String := To_String (Name);
               IP_Data   : constant String := IP_Bytes (Name_Text);
            begin
               if IP_Data /= "" then
                  Append (SANs, TLV (16#87#, IP_Data));
               else
                  Append
                    (SANs,
                     TLV
                       ((if Profile = Email_Profile then 16#81# else 16#82#),
                        Name_Text));
               end if;
            end;
         end loop;
         Append
           (Items,
            Seq
              (OID (Byte (16#55#) & Byte (16#1D#) & Byte (16#13#))
               & Bool (True)
               & Octets (Seq (""))));
         Append
           (Items,
            Seq
              (OID (Byte (16#55#) & Byte (16#1D#) & Byte (16#0F#))
               & Bool (True)
               & Octets (TLV (16#03#, Byte (7) & Byte (16#80#)))));
         Append
           (Items,
            Seq
              (OID (Byte (16#55#) & Byte (16#1D#) & Byte (16#11#))
               & Octets (Seq (To_String (SANs)))));
         Append
           (Items,
            Seq
              (OID (Byte (16#55#) & Byte (16#1D#) & Byte (16#25#))
               & Octets
                   (Seq
                      (OID
                         (Byte (16#2B#) & Byte (16#06#) & Byte (16#01#)
                          & Byte (16#05#) & Byte (16#05#) & Byte (16#07#)
                          & Byte (16#03#)
                          & (case Profile is
                               when Server_Profile => Byte (16#01#),
                               when Client_Profile => Byte (16#02#),
                               when Email_Profile => Byte (16#04#),
                               when CA_Profile => Byte (16#01#)))))));
      end if;
      return Explicit (3, Seq (To_String (Items)));
   end Extensions_DER;

   function Sign_Certificate
     (Serial      : Natural;
      Issuer_CN   : String;
      Subject_CN  : String;
      Subject_Key : Ada.Streams.Stream_Element_Array;
      Sign_Seed   : Ada.Streams.Stream_Element_Array;
      Sign_Public : Ada.Streams.Stream_Element_Array;
      Profile     : Certificate_Profile;
      Names       : Subject_Alternative_Name_List;
      Algorithm   : Key_Algorithm := Ed25519_Key;
      Subject_Algorithm : Key_Algorithm := Ed25519_Key) return String
   is
      --  The signer's algorithm and the subject's need not agree: a CSR brings
      --  its own key, and the CA signs whatever it was handed.
      TBS : constant String :=
        Seq
          (Explicit (0, Integer_DER (2))
           & Integer_DER (Serial)
           & Signature_Algorithm (Algorithm)
           & Name_DER (Issuer_CN)
           & Validity_DER
           & Name_DER (Subject_CN)
           & SPKI_DER (Subject_Key, Subject_Algorithm)
           & Extensions_DER (Profile, Names));
   begin
      case Algorithm is
         when Ed25519_Key =>
            declare
               Sig : Ada.Streams.Stream_Element_Array (1 .. 64);
               St  : constant CryptoLib.Errors.Status :=
                 CryptoLib.Ed25519.Sign
                   (Sign_Seed, Sign_Public, To_Bytes (TBS), Sig);
            begin
               if St /= CryptoLib.Errors.Ok then
                  return "";
               end if;
               return Seq
                 (TBS & Signature_Algorithm (Algorithm)
                  & Bits (To_String (Sig)));
            end;

         when P384_Key =>
            --  ECDSA signs as two integers, not one fixed block, and DER wants
            --  each of them minimally encoded.
            declare
               R  : Ada.Streams.Stream_Element_Array (1 .. 48);
               S2 : Ada.Streams.Stream_Element_Array (1 .. 48);
               St : constant CryptoLib.Errors.Status :=
                 CryptoLib.ECDSA.Sign_Nistp384_Raw
                   (Sign_Seed, To_Bytes (TBS), R, S2);
            begin
               if St /= CryptoLib.Errors.Ok then
                  return "";
               end if;
               return Seq
                 (TBS & Signature_Algorithm (Algorithm)
                  & Bits
                      (Seq
                         (Integer_From_Bytes (To_String (R))
                          & Integer_From_Bytes (To_String (S2)))));
            end;
      end case;
   end Sign_Certificate;

   function Read_Length
     (DER : String;
      Pos : in out Natural;
      Len : out Natural) return Boolean
   is
      Octet : Natural;
      Count : Natural;
   begin
      if Pos > DER'Last then
         return False;
      end if;

      Octet := Character'Pos (DER (Pos));
      Pos := Pos + 1;
      if Octet < 128 then
         Len := Octet;
         return True;
      end if;

      Count := Octet mod 128;
      if Count = 0 or else Count > 2 or else Pos + Count - 1 > DER'Last then
         return False;
      end if;

      Len := 0;
      for I in 1 .. Count loop
         Len := Len * 256 + Character'Pos (DER (Pos));
         Pos := Pos + 1;
      end loop;
      return True;
   end Read_Length;

   function Read_TLV
     (DER     : String;
      Pos     : in out Natural;
      Tag     : Natural;
      Content : out Unbounded_String) return Boolean
   is
      Len   : Natural;
      First : Natural;
   begin
      Content := Null_Unbounded_String;
      if Pos > DER'Last or else Character'Pos (DER (Pos)) /= Tag then
         return False;
      end if;
      Pos := Pos + 1;
      if not Read_Length (DER, Pos, Len) then
         return False;
      end if;
      First := Pos;
      if Len = 0 then
         Content := Null_Unbounded_String;
         return True;
      elsif First + Len - 1 > DER'Last then
         return False;
      end if;
      Content := To_Unbounded_String (DER (First .. First + Len - 1));
      Pos := First + Len;
      return True;
   end Read_TLV;

   function Contains (Data : String; Needle : String) return Boolean is
   begin
      return Ada.Strings.Fixed.Index (Data, Needle) /= 0;
   end Contains;

   function Extract_Common_Name
     (Name_DER : String;
      Common_Name : out Unbounded_String) return Boolean
   is
      CN_OID : constant String :=
        Byte (16#06#) & Byte (16#03#) & Byte (16#55#) & Byte (16#04#)
        & Byte (16#03#);
      Start : constant Natural := Ada.Strings.Fixed.Index (Name_DER, CN_OID);
      Pos   : Natural;
      Value : Unbounded_String;
   begin
      Common_Name := Null_Unbounded_String;
      if Start = 0 then
         return False;
      end if;

      Pos := Start + CN_OID'Length;
      if Pos > Name_DER'Last then
         return False;
      end if;

      if Character'Pos (Name_DER (Pos)) = 16#0C#
        or else Character'Pos (Name_DER (Pos)) = 16#13#
        or else Character'Pos (Name_DER (Pos)) = 16#16#
      then
         declare
            Tag : constant Natural := Character'Pos (Name_DER (Pos));
         begin
            if not Read_TLV (Name_DER, Pos, Tag, Value) then
               return False;
            elsif not Valid_Name (To_String (Value)) then
               return False;
            else
               Common_Name := Value;
               return True;
            end if;
         end;
      end if;
      return False;
   end Extract_Common_Name;

   --  A DER INTEGER carries no leading zeros and may have gained a sign byte;
   --  the verifier wants a fixed-width big-endian value.
   function Fixed_Width
     (Value : String;
      Out_Bytes : out Ada.Streams.Stream_Element_Array) return Boolean
   is
      First : Natural := Value'First;
   begin
      Out_Bytes := [others => 0];
      while First <= Value'Last and then Value (First) = Character'Val (0) loop
         First := First + 1;
      end loop;
      if First > Value'Last
        or else Natural (Value'Last - First + 1) > Natural (Out_Bytes'Length)
      then
         return False;
      end if;

      declare
         Width : constant Natural := Value'Last - First + 1;
         Start : constant Ada.Streams.Stream_Element_Offset :=
           Out_Bytes'Last - Ada.Streams.Stream_Element_Offset (Width) + 1;
      begin
         for I in 0 .. Width - 1 loop
            Out_Bytes (Start + Ada.Streams.Stream_Element_Offset (I)) :=
              Ada.Streams.Stream_Element (Character'Pos (Value (First + I)));
         end loop;
      end;
      return True;
   end Fixed_Width;

   function Extract_CSR
     (CSR_PEM    : String;
      Subject_CN : out Unbounded_String;
      Public_Key : out Ada.Streams.Stream_Element_Array) return Boolean
   is
      DER      : constant String := Base64_Decode (CSR_PEM);
      Pos      : Natural := DER'First;
      Outer    : Unbounded_String;
      CRI      : Unbounded_String;
      Version  : Unbounded_String;
      Name     : Unbounded_String;
      SPKI     : Unbounded_String;
      Alg      : Unbounded_String;
      Bits_U   : Unbounded_String;
      CSR_Alg  : Unbounded_String;
      CSR_Sig  : Unbounded_String;
      OID_Ed    : constant String :=
        Byte (16#06#) & Byte (16#03#) & Byte (16#2B#) & Byte (16#65#)
        & Byte (16#70#);
      OID_P384  : constant String :=
        Byte (16#06#) & Byte (16#05#) & Byte (16#2B#) & Byte (16#81#)
        & Byte (16#04#) & Byte (16#00#) & Byte (16#22#);
      OID_ECDSA_SHA384 : constant String :=
        Byte (16#06#) & Byte (16#08#) & Byte (16#2A#) & Byte (16#86#)
        & Byte (16#48#) & Byte (16#CE#) & Byte (16#3D#) & Byte (16#04#)
        & Byte (16#03#) & Byte (16#03#);
      Is_EC     : Boolean := False;
   begin
      Subject_CN := Null_Unbounded_String;
      Public_Key := [others => 0];

      --  The caller decides which shape it can take: a 32-byte buffer asks for
      --  an Ed25519 request, a 97-byte one for P-384.
      if DER = ""
        or else (Public_Key'Length /= 32 and then Public_Key'Length /= 97)
      then
         return False;
      end if;
      Is_EC := Public_Key'Length = 97;

      if not Read_TLV (DER, Pos, 16#30#, Outer) then
         return False;
      end if;

      declare
         Outer_Text : constant String := To_String (Outer);
         Outer_Pos  : Natural := Outer_Text'First;
      begin
         if not Read_TLV (Outer_Text, Outer_Pos, 16#30#, CRI) then
            return False;
         end if;
         if not Read_TLV (Outer_Text, Outer_Pos, 16#30#, CSR_Alg) then
            return False;
         end if;
         --  The request's own signature algorithm, which is not the algorithm
         --  of the key it carries -- though for these two shapes they agree.
         if Is_EC then
            if not Contains (To_String (CSR_Alg), OID_ECDSA_SHA384) then
               return False;
            end if;
         elsif not Contains (To_String (CSR_Alg), OID_Ed) then
            return False;
         end if;
         if not Read_TLV (Outer_Text, Outer_Pos, 16#03#, CSR_Sig) then
            return False;
         end if;
      end;

      declare
         CRI_Text : constant String := To_String (CRI);
         CRI_Pos  : Natural := CRI_Text'First;
      begin
         if not Read_TLV (CRI_Text, CRI_Pos, 16#02#, Version) then
            return False;
         end if;
         if not Read_TLV (CRI_Text, CRI_Pos, 16#30#, Name) then
            return False;
         end if;
         if not Extract_Common_Name (To_String (Name), Subject_CN) then
            return False;
         end if;
         if not Read_TLV (CRI_Text, CRI_Pos, 16#30#, SPKI) then
            return False;
         end if;
      end;

      declare
         SPKI_Text : constant String := To_String (SPKI);
         SPKI_Pos  : Natural := SPKI_Text'First;
      begin
         if not Read_TLV (SPKI_Text, SPKI_Pos, 16#30#, Alg) then
            return False;
         end if;
         if Is_EC then
            if not Contains (To_String (Alg), OID_P384) then
               return False;
            end if;
         elsif not Contains (To_String (Alg), OID_Ed) then
            return False;
         end if;
         if not Read_TLV (SPKI_Text, SPKI_Pos, 16#03#, Bits_U) then
            return False;
         end if;
      end;

      declare
         Bits_Text : constant String := To_String (Bits_U);
      begin
         if Bits_Text'Length /= Natural (Public_Key'Length) + 1
           or else Character'Pos (Bits_Text (Bits_Text'First)) /= 0
         then
            return False;
         end if;

         for I in Public_Key'Range loop
            Public_Key (I) :=
              Ada.Streams.Stream_Element
                (Character'Pos
                   (Bits_Text
                      (Bits_Text'First + Natural (I - Public_Key'First) + 1)));
         end loop;
      end;

      declare
         Signature_Text : constant String := To_String (CSR_Sig);
      begin
         if Signature_Text'Length < 2
           or else Character'Pos (Signature_Text (Signature_Text'First)) /= 0
         then
            return False;
         end if;

         if Is_EC then
            --  ECDSA signs as two integers of their own lengths, so they are
            --  read back and re-padded to the fixed width the verifier wants.
            declare
               Body_Text : constant String :=
                 Signature_Text (Signature_Text'First + 1 .. Signature_Text'Last);
               Pos    : Natural := Body_Text'First;
               Pair   : Unbounded_String;
               R_Int  : Unbounded_String;
               S_Int  : Unbounded_String;
               R      : Ada.Streams.Stream_Element_Array (1 .. 48);
               S2     : Ada.Streams.Stream_Element_Array (1 .. 48);
            begin
               if not Read_TLV (Body_Text, Pos, 16#30#, Pair) then
                  return False;
               end if;
               declare
                  Pair_Text : constant String := To_String (Pair);
                  Pair_Pos  : Natural := Pair_Text'First;
               begin
                  if not Read_TLV (Pair_Text, Pair_Pos, 16#02#, R_Int)
                    or else not Read_TLV (Pair_Text, Pair_Pos, 16#02#, S_Int)
                  then
                     return False;
                  end if;
               end;
               if not Fixed_Width (To_String (R_Int), R)
                 or else not Fixed_Width (To_String (S_Int), S2)
               then
                  return False;
               end if;
               if CryptoLib.ECDSA.Verify_Nistp384_Raw
                 (Public_Key, To_Bytes (Seq (To_String (CRI))), R, S2)
                 /= CryptoLib.Errors.Ok
               then
                  return False;
               end if;
            end;
         else
            declare
               Signature : Ada.Streams.Stream_Element_Array (1 .. 64);
            begin
               if Signature_Text'Length /= 65 then
                  return False;
               end if;
               for I in Signature'Range loop
                  Signature (I) :=
                    Ada.Streams.Stream_Element
                      (Character'Pos
                         (Signature_Text
                            (Signature_Text'First
                             + Natural (I - Signature'First) + 1)));
               end loop;
               if CryptoLib.Ed25519.Verify
                 (Public_Key, Signature, To_Bytes (Seq (To_String (CRI))))
                 /= CryptoLib.Errors.Ok
               then
                  return False;
               end if;
            end;
         end if;
      end;
      return True;
   exception
      when others =>
         Subject_CN := Null_Unbounded_String;
         Public_Key := [others => 0];
         return False;
   end Extract_CSR;

   function Create_Local_CA
     (Common_Name     : String;
      Certificate_PEM : out Unbounded_String;
      Private_Key_PEM : out Unbounded_String;
      Algorithm       : Key_Algorithm := Ed25519_Key) return Certificate_Status
   is
      Rng  : CryptoLib.Random.Random_Source;
      Cert : Unbounded_String;

      Seed_Length   : constant := 32;
      Scalar_Length : constant := 48;
      Point_Length  : constant := 97;

      Seed   : Ada.Streams.Stream_Element_Array
        (1 .. (if Algorithm = Ed25519_Key then Seed_Length else Scalar_Length));
      Public : Ada.Streams.Stream_Element_Array
        (1 .. (if Algorithm = Ed25519_Key then Seed_Length else Point_Length));
   begin
      Certificate_PEM := Null_Unbounded_String;
      Private_Key_PEM := Null_Unbounded_String;

      if not Valid_Name (Common_Name) then
         return Invalid_Input;
      end if;

      CryptoLib.Random.Initialize_Production (Rng);
      case Algorithm is
         when Ed25519_Key =>
            if CryptoLib.Ed25519.Generate_Keypair (Rng, Seed, Public)
              /= CryptoLib.Errors.Ok
            then
               return Internal_Error;
            end if;
         when P384_Key =>
            if CryptoLib.ECDSA.Generate_Nistp384_Keypair (Rng, Seed, Public)
              /= CryptoLib.Errors.Ok
            then
               return Internal_Error;
            end if;
      end case;

      Cert :=
        To_Unbounded_String
          (Sign_Certificate
             (Serial      => 1,
              Issuer_CN   => Common_Name,
              Subject_CN  => Common_Name,
              Subject_Key => Public,
              Sign_Seed   => Seed,
              Sign_Public => Public,
              Profile     => CA_Profile,
              Names       => [1 => To_Unbounded_String (Common_Name)],
              Algorithm   => Algorithm,
              Subject_Algorithm => Algorithm));
      if Length (Cert) = 0 then
         return Internal_Error;
      end if;

      Certificate_PEM := PEM ("CERTIFICATE", To_String (Cert));
      Private_Key_PEM :=
        PEM ("PRIVATE KEY",
             (case Algorithm is
                 when Ed25519_Key => Private_Key_DER (Seed),
                 when P384_Key    => P384_Private_Key_DER (Seed, Public)));
      return Ok;
   end Create_Local_CA;

   function Issue_Profile_Certificate
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Names              : Subject_Alternative_Name_List;
      Profile            : Certificate_Profile;
      Certificate_PEM    : out Unbounded_String;
      Private_Key_PEM    : out Unbounded_String) return Certificate_Status
   is
      pragma Unreferenced (CA_Certificate_PEM);
      Rng : CryptoLib.Random.Random_Source;

      --  A leaf is signed by the CA and has to be verifiable by whatever
      --  accepts the CA, so it carries the same kind of key. Nothing asks the
      --  caller: the CA's own key already says which.
      Algorithm : constant Key_Algorithm :=
        Algorithm_Of_Private_Key (CA_Private_Key_PEM);
      Is_EC     : constant Boolean := Algorithm = P384_Key;

      CA_Seed   : Ada.Streams.Stream_Element_Array
        (1 .. (if Is_EC then 48 else 32));
      CA_Public : Ada.Streams.Stream_Element_Array
        (1 .. (if Is_EC then 97 else 32));
      Seed      : Ada.Streams.Stream_Element_Array
        (1 .. (if Is_EC then 48 else 32));
      Public    : Ada.Streams.Stream_Element_Array
        (1 .. (if Is_EC then 97 else 32));
      Cert      : Unbounded_String;
   begin
      Certificate_PEM := Null_Unbounded_String;
      Private_Key_PEM := Null_Unbounded_String;

      if CA_Private_Key_PEM = ""
        or else not Valid_Profile_Name (Profile, Common_Name)
        or else Names'Length = 0
        or else Profile = CA_Profile
      then
         return Invalid_Input;
      end if;

      for Name of Names loop
         if not Valid_Profile_Name (Profile, To_String (Name)) then
            return Invalid_Input;
         end if;
      end loop;

      if Is_EC then
         if not Scalar_From_Private_Key_PEM (CA_Private_Key_PEM, CA_Seed) then
            return Invalid_Input;
         end if;
         if CryptoLib.ECDSA.Public_Nistp384_Raw (CA_Seed, CA_Public)
           /= CryptoLib.Errors.Ok
         then
            return Internal_Error;
         end if;
      else
         if not Seed_From_Private_Key_PEM (CA_Private_Key_PEM, CA_Seed) then
            return Invalid_Input;
         end if;
         if CryptoLib.Ed25519.Public_Key_From_Seed (CA_Seed, CA_Public)
           /= CryptoLib.Errors.Ok
         then
            return Internal_Error;
         end if;
      end if;

      CryptoLib.Random.Initialize_Production (Rng);
      if Is_EC then
         if CryptoLib.ECDSA.Generate_Nistp384_Keypair (Rng, Seed, Public)
           /= CryptoLib.Errors.Ok
         then
            return Internal_Error;
         end if;
      elsif CryptoLib.Ed25519.Generate_Keypair (Rng, Seed, Public)
        /= CryptoLib.Errors.Ok
      then
         return Internal_Error;
      end if;

      Cert :=
        To_Unbounded_String
          (Sign_Certificate
             (Serial      => 10,
              Issuer_CN   => "devcert-local-development-ca",
              Subject_CN  => Common_Name,
              Subject_Key => Public,
              Sign_Seed   => CA_Seed,
              Sign_Public => CA_Public,
              Profile     => Profile,
              Names       => Names,
              Algorithm   => Algorithm,
              Subject_Algorithm => Algorithm));
      if Length (Cert) = 0 then
         return Internal_Error;
      end if;

      Certificate_PEM := PEM ("CERTIFICATE", To_String (Cert));
      Private_Key_PEM :=
        PEM ("PRIVATE KEY",
             (if Is_EC then P384_Private_Key_DER (Seed, Public)
              else Private_Key_DER (Seed)));
      return Ok;
   exception
      when others =>
         Certificate_PEM := Null_Unbounded_String;
         Private_Key_PEM := Null_Unbounded_String;
         return Internal_Error;
   end Issue_Profile_Certificate;

   function Issue_Server_Certificate
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Names              : Subject_Alternative_Name_List;
      Certificate_PEM    : out Unbounded_String;
      Private_Key_PEM    : out Unbounded_String) return Certificate_Status is
   begin
      return Issue_Profile_Certificate
        (CA_Certificate_PEM, CA_Private_Key_PEM, Common_Name, Names,
         Server_Profile, Certificate_PEM, Private_Key_PEM);
   end Issue_Server_Certificate;

   function Issue_Client_Certificate
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Names              : Subject_Alternative_Name_List;
      Certificate_PEM    : out Unbounded_String;
      Private_Key_PEM    : out Unbounded_String) return Certificate_Status is
   begin
      return Issue_Profile_Certificate
        (CA_Certificate_PEM, CA_Private_Key_PEM, Common_Name, Names,
         Client_Profile, Certificate_PEM, Private_Key_PEM);
   end Issue_Client_Certificate;

   function Issue_Email_Certificate
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Emails             : Subject_Alternative_Name_List;
      Certificate_PEM    : out Unbounded_String;
      Private_Key_PEM    : out Unbounded_String) return Certificate_Status is
   begin
      return Issue_Profile_Certificate
        (CA_Certificate_PEM, CA_Private_Key_PEM, Common_Name, Emails,
         Email_Profile, Certificate_PEM, Private_Key_PEM);
   end Issue_Email_Certificate;

   function Sign_CSR
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      CSR_PEM            : String;
      Certificate_PEM    : out Unbounded_String) return Certificate_Status
   is
      pragma Unreferenced (CA_Certificate_PEM);
      Algorithm : constant Key_Algorithm :=
        Algorithm_Of_Private_Key (CA_Private_Key_PEM);
      Is_EC     : constant Boolean := Algorithm = P384_Key;
      CA_Seed   : Ada.Streams.Stream_Element_Array
        (1 .. (if Is_EC then 48 else 32));
      CA_Public : Ada.Streams.Stream_Element_Array
        (1 .. (if Is_EC then 97 else 32));
      Subject   : Unbounded_String;
      --  The CSR carries an Ed25519 key: this reads and verifies that shape
      --  only, whatever the CA itself is signed with.
      CSR_Public : Ada.Streams.Stream_Element_Array (1 .. 32);
      Cert      : Unbounded_String;
   begin
      Certificate_PEM := Null_Unbounded_String;
      if CA_Private_Key_PEM = "" or else CSR_PEM = "" then
         return Invalid_Input;
      end if;
      if Is_EC then
         if not Scalar_From_Private_Key_PEM (CA_Private_Key_PEM, CA_Seed) then
            return Invalid_Input;
         end if;
         if CryptoLib.ECDSA.Public_Nistp384_Raw (CA_Seed, CA_Public)
           /= CryptoLib.Errors.Ok
         then
            return Internal_Error;
         end if;
      else
         if not Seed_From_Private_Key_PEM (CA_Private_Key_PEM, CA_Seed) then
            return Invalid_Input;
         end if;
         if CryptoLib.Ed25519.Public_Key_From_Seed (CA_Seed, CA_Public)
           /= CryptoLib.Errors.Ok
         then
            return Internal_Error;
         end if;
      end if;

      --  Which kind of request this is shows in the request itself, so try the
      --  EC shape first and fall back rather than making the caller declare it.
      declare
         EC_Public : Ada.Streams.Stream_Element_Array (1 .. 97);
      begin
         if Extract_CSR (CSR_PEM, Subject, EC_Public) then
            Cert :=
              To_Unbounded_String
                (Sign_Certificate
                   (Serial      => 20,
                    Issuer_CN   => "devcert-local-development-ca",
                    Subject_CN  => To_String (Subject),
                    Subject_Key => EC_Public,
                    Sign_Seed   => CA_Seed,
                    Sign_Public => CA_Public,
                    Profile     => Server_Profile,
                    Names       => [1 => Subject],
                    Algorithm   => Algorithm,
                    Subject_Algorithm => P384_Key));
            if Length (Cert) = 0 then
               return Internal_Error;
            end if;
            Certificate_PEM := PEM ("CERTIFICATE", To_String (Cert));
            return Ok;
         end if;
      end;

      if not Extract_CSR (CSR_PEM, Subject, CSR_Public) then
         return Invalid_Input;
      end if;

      Cert :=
        To_Unbounded_String
          (Sign_Certificate
             (Serial      => 20,
              Issuer_CN   => "devcert-local-development-ca",
              Subject_CN  => To_String (Subject),
              Subject_Key => CSR_Public,
              Sign_Seed   => CA_Seed,
              Sign_Public => CA_Public,
              Profile     => Server_Profile,
              Names       => [1 => Subject],
              Algorithm   => Algorithm,
              Subject_Algorithm => Ed25519_Key));
      if Length (Cert) = 0 then
         return Internal_Error;
      end if;
      Certificate_PEM := PEM ("CERTIFICATE", To_String (Cert));
      return Ok;
   end Sign_CSR;

   --  Label rules, not a character set: a DNS label is 1 to 63 characters, may
   --  hold hyphens inside but not at either end, and the name may not be one
   --  long label of dots. A charset check accepts "-.-" and a trailing dot,
   --  which no resolver will.
   function Valid_DNS_Name (Text : String) return Boolean is
      Label_Start : Positive;
      Label_Len   : Natural := 0;

      function Alpha_Num (C : Character) return Boolean is
        (C in 'a' .. 'z' or else C in 'A' .. 'Z' or else C in '0' .. '9');

      function Valid_Label (First : Positive; Last : Natural) return Boolean is
      begin
         if Last < First or else Last - First + 1 > 63 then
            return False;
         elsif not Alpha_Num (Text (First)) or else not Alpha_Num (Text (Last))
         then
            return False;
         end if;

         for I in First .. Last loop
            if not Alpha_Num (Text (I)) and then Text (I) /= '-' then
               return False;
            end if;
         end loop;
         return True;
      end Valid_Label;
   begin
      if Text'Length = 0 or else Text'Length > 253 then
         return False;
      end if;

      --  A wildcard stands for one label and only the leftmost, and only where
      --  something remains for it to qualify: "*.example.test" names hosts in a
      --  domain, "*" and "*.test" name far too much, and "a*b" is not a
      --  wildcard at all.
      if Text = "*" then
         return False;
      elsif Text'Length > 2
        and then Text (Text'First) = '*'
        and then Text (Text'First + 1) = '.'
      then
         return Ada.Strings.Fixed.Index
                  (Text (Text'First + 2 .. Text'Last), ".") /= 0
           and then Valid_DNS_Name (Text (Text'First + 2 .. Text'Last));
      elsif Ada.Strings.Fixed.Index (Text, "*") /= 0 then
         return False;
      end if;

      Label_Start := Text'First;
      for I in Text'Range loop
         if Text (I) = '.' then
            if not Valid_Label (Label_Start, I - 1) then
               return False;
            end if;
            Label_Start := I + 1;
            Label_Len := 0;
         else
            Label_Len := Label_Len + 1;
         end if;
      end loop;

      return Label_Len > 0 and then Valid_Label (Label_Start, Text'Last);
   end Valid_DNS_Name;

   --  The encoder is the authority: an address is valid exactly when it can be
   --  turned into the bytes a certificate carries.
   function Valid_IP_Address (Text : String) return Boolean is
   begin
      return IP_Bytes (Text) /= "";
   end Valid_IP_Address;

   function Valid_Email_Address (Text : String) return Boolean is
   begin
      return Valid_Email (Text);
   end Valid_Email_Address;

   function Fingerprint (Certificate_PEM : String) return String is
      DER : constant String := Base64_Decode (Certificate_PEM);
   begin
      if DER = "" then
         return "";
      end if;

      declare
         Digest : constant String := Digest_Hex (DER);
         Result : Unbounded_String;
      begin
         for I in 1 .. Digest'Length / 2 loop
            if I > 1 then
               Append (Result, ":");
            end if;
            Append
              (Result,
               Digest (Digest'First + (I - 1) * 2 .. Digest'First + (I - 1) * 2 + 1));
         end loop;
         return To_String (Result);
      end;
   end Fingerprint;

   function Same_Certificate (Left : String; Right : String) return Boolean is
      Left_DER  : constant String := Base64_Decode (Left);
      Right_DER : constant String := Base64_Decode (Right);
   begin
      return Left_DER /= "" and then Left_DER = Right_DER;
   end Same_Certificate;

   function Contains_Certificate (Text : String) return Boolean is
   begin
      return Contains (Text, "BEGIN CERTIFICATE")
        and then Contains (Text, "END CERTIFICATE");
   end Contains_Certificate;

   function Contains_Private_Key (Text : String) return Boolean is
   begin
      return Contains (Text, "BEGIN PRIVATE KEY")
        and then Contains (Text, "END PRIVATE KEY");
   end Contains_Private_Key;

   function Private_Key_Matches_Certificate
     (Certificate_PEM : String;
      Private_Key_PEM : String) return Certificate_Status
   is
      DER       : constant String := Base64_Decode (Certificate_PEM);
      Algorithm : constant Key_Algorithm :=
        Algorithm_Of_Private_Key (Private_Key_PEM);
      Is_EC     : constant Boolean := Algorithm = P384_Key;
      Seed      : Ada.Streams.Stream_Element_Array
        (1 .. (if Is_EC then 48 else 32));
      Public    : Ada.Streams.Stream_Element_Array
        (1 .. (if Is_EC then 97 else 32));
   begin
      if DER = "" or else Private_Key_PEM = "" then
         return Invalid_Input;
      end if;

      --  Derive the public key the private one implies and look for it in the
      --  certificate: a key that belongs to another certificate cannot produce
      --  a subject public key that matches this one.
      if Is_EC then
         if not Scalar_From_Private_Key_PEM (Private_Key_PEM, Seed) then
            return Invalid_Input;
         elsif CryptoLib.ECDSA.Public_Nistp384_Raw (Seed, Public)
           /= CryptoLib.Errors.Ok
         then
            return Internal_Error;
         end if;
      else
         if not Seed_From_Private_Key_PEM (Private_Key_PEM, Seed) then
            return Invalid_Input;
         elsif CryptoLib.Ed25519.Public_Key_From_Seed (Seed, Public)
           /= CryptoLib.Errors.Ok
         then
            return Internal_Error;
         end if;
      end if;

      if Contains (DER, SPKI_DER (Public, Algorithm)) then
         return Ok;
      else
         return Invalid_Input;
      end if;
   end Private_Key_Matches_Certificate;

   function Generate_PKCS12
     (Certificate_PEM : String;
      Private_Key_PEM : String;
      Friendly_Name   : String;
      Password        : String;
      Bundle_Data     : out Unbounded_String) return Certificate_Status
   is
      Cert_DER        : constant String := Base64_Decode (Certificate_PEM);
      Key_DER         : constant String := Base64_Decode (Private_Key_PEM);
      Iterations      : constant Positive := 2048;
      Padded_Key      : constant Ada.Streams.Stream_Element_Array :=
        PKCS7_Pad (Key_DER, 16);
      Rng             : CryptoLib.Random.Random_Source;
      Mac_Salt        : Ada.Streams.Stream_Element_Array (1 .. 8);
      Encryption_Salt : Ada.Streams.Stream_Element_Array (1 .. 16);
      IV_Data         : Ada.Streams.Stream_Element_Array (1 .. 16);
   begin
      Bundle_Data := Null_Unbounded_String;
      if Certificate_PEM = "" or else Private_Key_PEM = "" or else Friendly_Name = "" then
         return Invalid_Input;
      end if;
      if Cert_DER = "" or else Key_DER = "" then
         return Invalid_Input;
      end if;

      CryptoLib.Random.Initialize_Production (Rng);
      if CryptoLib.Random.Fill (Rng, Mac_Salt) /= CryptoLib.Errors.Ok
        or else CryptoLib.Random.Fill (Rng, Encryption_Salt) /= CryptoLib.Errors.Ok
        or else CryptoLib.Random.Fill (Rng, IV_Data) /= CryptoLib.Errors.Ok
      then
         return Internal_Error;
      end if;

      declare
         Key_Data : constant Ada.Streams.Stream_Element_Array :=
           CryptoLib.Macs.PBKDF2_HMAC_SHA256
             (Password_Data => To_Bytes (Password),
              Salt_Data     => Encryption_Salt,
              Iterations    => Iterations,
              Output_Length => 32);
         Encrypted_Key : Ada.Streams.Stream_Element_Array (Padded_Key'Range);
         Status        : CryptoLib.Errors.Status;
      begin
         Status :=
           CryptoLib.Ciphers.Encrypt_CBC_Raw
             ("aes256-cbc", Key_Data, IV_Data, Padded_Key, Encrypted_Key);
         if Status /= CryptoLib.Errors.Ok then
            return Internal_Error;
         end if;

         declare
            Encrypted_Private_Key_Info : constant String :=
              Seq
                (PBES2_AES_256_CBC_Algorithm
                   (Encryption_Salt, Iterations, IV_Data)
                 & Octets (To_String (Encrypted_Key)));
            Key_Bag : constant String :=
              Seq
                (OID_Shrouded_Key_Bag
                 & Explicit (0, Encrypted_Private_Key_Info));
            Cert_Bag : constant String :=
              Seq
                (OID_Cert_Bag
                 & Explicit
                     (0,
                      Seq
                        (OID_X509_Certificate
                         & Explicit (0, Octets (Cert_DER)))));
            Safe_Contents : constant String := Seq (Key_Bag & Cert_Bag);
            Inner_Content : constant String :=
              Seq (OID_Data & Explicit (0, Octets (Safe_Contents)));
            Authenticated_Safe : constant String := Seq (Inner_Content);
            Auth_Safe : constant String :=
              Seq (OID_Data & Explicit (0, Octets (Authenticated_Safe)));
         begin
            Bundle_Data :=
              To_Unbounded_String
                (Seq
                   (Integer_DER (3)
                    & Auth_Safe
                    & Mac_Data (Authenticated_Safe, Password, Mac_Salt)));
            return Ok;
         end;
      end;
   end Generate_PKCS12;
end CryptoLib.Certificates;
