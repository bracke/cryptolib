with AUnit.Assertions;

with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Interfaces;
with System;
with CryptoLib.ASN1;
with CryptoLib.PEM;
with CryptoLib.X509;
with CryptoLib.X509.Certificates;
with CryptoLib.X509.Extensions;
with CryptoLib.X509.Identity;
with CryptoLib.X509.Purposes;
with CryptoLib.X509.Names;
with Ada.Directories;
with Ada.Streams.Stream_IO;
with CryptoLib.X509.CRLs;
with CryptoLib.X509.Revocation;
with CryptoLib.OCSP;
with CryptoLib.PKCS10;
with CryptoLib.PKCS8;
with CryptoLib.PKCS12;
with CryptoLib.Identities;
with CryptoLib.X509.Policies;
with CryptoLib.HKDF;
with CryptoLib.TLS13_KDF;
with CryptoLib.ECDH;
with CryptoLib.Constant_Time_Proof;
with CryptoLib.Constant_Time_Assurance;
with CryptoLib.EC_Curves;
with CryptoLib.Hybrid_PQ_Kex;
with CryptoLib.Fingerprints;
with CryptoLib.Constant_Time;
with CryptoLib.BCrypt_PBKDF;
with CryptoLib.X509.Times;
with CryptoLib.X509.Validation;
with CryptoLib.X509.Path_Building;
with CryptoLib.X509.Name_Constraints;
with CryptoLib.X509.Signatures;
with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.Errors;
with CryptoLib.ASN1.OIDs;
with CryptoLib.ChaCha20_Poly1305;
with CryptoLib.Certificates;
with OpenSSL_Interop;
with CryptoLib.Checksums;
with CryptoLib.Secure_Wipe;
with CryptoLib.Hashes;
with CryptoLib.Ciphers;
with CryptoLib.ECDSA;
with CryptoLib.Errors;
with CryptoLib.Macs;
with CryptoLib.UMAC;
with CryptoLib.MLKEM768;
with CryptoLib.SNTRUP761;
with CryptoLib.Curve25519;
with CryptoLib.Ed25519;
with CryptoLib.Ed448;
with CryptoLib.SHA3;
with CryptoLib.Buffers;
with CryptoLib.Diffie_Hellman;
with CryptoLib.Modexp;
with CryptoLib.Bignum;
with CryptoLib.Random;
with CryptoLib.RSA;

package body Tests_Support is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Certificates.Certificate_Status;
   use type Interfaces.Unsigned_32;

   --  The whole suite asserts through here, so this one delegation is what
   --  makes every check an AUnit assertion: a failure is reported against the
   --  routine that raised it and the rest of the suite still runs.
   procedure Check (Condition : Boolean; Message : String) is
   begin
      AUnit.Assertions.Assert (Condition, Message);
   end Check;

   function Bytes_From_String
     (Value : String) return Ada.Streams.Stream_Element_Array
   is
      Result : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Value'Length));
      Index  : Ada.Streams.Stream_Element_Offset := Result'First;
   begin
      for Character_Value of Value loop
         Result (Index) := Character'Pos (Character_Value);
         Index := Index + 1;
      end loop;
      return Result;
   end Bytes_From_String;

   function Nibble_From_Hex (C : Character) return Ada.Streams.Stream_Element is
     (case C is
         when '0' .. '9' =>
           Ada.Streams.Stream_Element (Character'Pos (C) - Character'Pos ('0')),
         when 'a' .. 'f' =>
           Ada.Streams.Stream_Element
             (Character'Pos (C) - Character'Pos ('a') + 10),
         when 'A' .. 'F' =>
           Ada.Streams.Stream_Element
             (Character'Pos (C) - Character'Pos ('A') + 10),
         when others => 0);

   function Bytes_From_Hex
     (Value : String)
      return Ada.Streams.Stream_Element_Array
   is
      Result : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Value'Length / 2));
   begin
      for Index in Result'Range loop
         declare
            Position : constant Natural := Value'First + Natural (Index - 1) * 2;
         begin
            Result (Index) :=
              Nibble_From_Hex (Value (Position)) * 16
              + Nibble_From_Hex (Value (Position + 1));
         end;
      end loop;
      return Result;
   end Bytes_From_Hex;

   function Sequence_Data
     (Length : Natural)
      return Ada.Streams.Stream_Element_Array
   is
      Result : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Length));
   begin
      for Index in Result'Range loop
         Result (Index) :=
           Ada.Streams.Stream_Element
             ((Natural (Index - Result'First) * 37 + 11) mod 256);
      end loop;
      return Result;
   end Sequence_Data;

   --  The certificate NSS refused was refused for its key: certutil would not
   --  import an Ed25519 certificate at all, so a CA built that way is trusted
   --  by no browser. This checks the P-384 path emits what a reader expects --
   --  the curve OID in the key, and the ecdsa-with-SHA384 OID as the signature
   --  algorithm -- rather than only that some bytes came back.
   --  Enough base64 to look inside a PEM: the assertions below are about DER
   --  bytes, and armoured text does not show them.
   function Decode_PEM_Body (Text : String) return String is
      Alphabet : constant String :=
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      Result   : Ada.Strings.Unbounded.Unbounded_String;
      Bits     : Natural := 0;
      Held     : Natural := 0;
      In_Body  : Boolean := False;
      Line_End : Natural;
      First    : Natural := Text'First;
   begin
      while First <= Text'Last loop
         Line_End := First;
         while Line_End <= Text'Last and then Text (Line_End) /= ASCII.LF loop
            Line_End := Line_End + 1;
         end loop;

         declare
            Line : constant String := Text (First .. Natural'Min (Line_End - 1, Text'Last));
         begin
            if Line'Length > 5 and then Line (Line'First .. Line'First + 4) = "-----" then
               In_Body := not In_Body;
            elsif In_Body then
               for C of Line loop
                  declare
                     Position : Natural := 0;
                  begin
                     for I in Alphabet'Range loop
                        if Alphabet (I) = C then
                           Position := I - Alphabet'First;
                           exit;
                        end if;
                     end loop;
                     if C /= '=' and then (Position > 0 or else C = 'A') then
                        Held := Held * 64 + Position;
                        Bits := Bits + 6;
                        if Bits >= 8 then
                           Bits := Bits - 8;
                           Ada.Strings.Unbounded.Append
                             (Result, Character'Val ((Held / (2 ** Bits)) mod 256));
                           Held := Held mod (2 ** Bits);
                        end if;
                     end if;
                  end;
               end loop;
            end if;
         end;
         First := Line_End + 1;
      end loop;
      return Ada.Strings.Unbounded.To_String (Result);
   end Decode_PEM_Body;

   function Index_Of (Haystack : String; Needle : String) return Natural is
   begin
      if Needle'Length = 0 or else Haystack'Length < Needle'Length then
         return 0;
      end if;
      for I in Haystack'First .. Haystack'Last - Needle'Length + 1 loop
         if Haystack (I .. I + Needle'Length - 1) = Needle then
            return I;
         end if;
      end loop;
      return 0;
   end Index_Of;

end Tests_Support;
