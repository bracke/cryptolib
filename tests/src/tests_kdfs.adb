with Ada.Streams;
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
with CryptoLib.MLKEM768_Core;
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
with Tests_Support; use Tests_Support;

package body Tests_KDFs is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Certificates.Certificate_Status;
   use type Interfaces.Unsigned_32;

   procedure Check_PBKDF2_SHA1 is
      Actual : constant Ada.Streams.Stream_Element_Array :=
        CryptoLib.Macs.PBKDF2_HMAC_SHA1
          (Bytes_From_String ("password"), Bytes_From_String ("salt"), 1, 20);
      Expected : constant Ada.Streams.Stream_Element_Array (1 .. 20) :=
        [16#0C#, 16#60#, 16#C8#, 16#0F#, 16#96#, 16#1F#, 16#0E#, 16#71#,
         16#F3#, 16#A9#, 16#B5#, 16#24#, 16#AF#, 16#60#, 16#12#, 16#06#,
         16#2F#, 16#E0#, 16#37#, 16#A6#];
   begin
      Check (Actual = Expected, "PBKDF2-HMAC-SHA1 RFC vector");
   end Check_PBKDF2_SHA1;

   procedure Check_PBKDF2_SHA2 is
      Actual_256 : constant Ada.Streams.Stream_Element_Array :=
        CryptoLib.Macs.PBKDF2_HMAC_SHA256
          (Bytes_From_String ("password"), Bytes_From_String ("salt"), 1, 32);
      Expected_256 : constant Ada.Streams.Stream_Element_Array (1 .. 32) :=
        [16#12#, 16#0F#, 16#B6#, 16#CF#, 16#FC#, 16#F8#, 16#B3#, 16#2C#,
         16#43#, 16#E7#, 16#22#, 16#52#, 16#56#, 16#C4#, 16#F8#, 16#37#,
         16#A8#, 16#65#, 16#48#, 16#C9#, 16#2C#, 16#CC#, 16#35#, 16#48#,
         16#08#, 16#05#, 16#98#, 16#7C#, 16#B7#, 16#0B#, 16#E1#, 16#7B#];
      Actual_512 : constant Ada.Streams.Stream_Element_Array :=
        CryptoLib.Macs.PBKDF2_HMAC_SHA512
          (Bytes_From_String ("password"), Bytes_From_String ("salt"), 1, 64);
      Expected_512 : constant Ada.Streams.Stream_Element_Array (1 .. 64) :=
        [16#86#, 16#7F#, 16#70#, 16#CF#, 16#1A#, 16#DE#, 16#02#, 16#CF#,
         16#F3#, 16#75#, 16#25#, 16#99#, 16#A3#, 16#A5#, 16#3D#, 16#C4#,
         16#AF#, 16#34#, 16#C7#, 16#A6#, 16#69#, 16#81#, 16#5A#, 16#E5#,
         16#D5#, 16#13#, 16#55#, 16#4E#, 16#1C#, 16#8C#, 16#F2#, 16#52#,
         16#C0#, 16#2D#, 16#47#, 16#0A#, 16#28#, 16#5A#, 16#05#, 16#01#,
         16#BA#, 16#D9#, 16#99#, 16#BF#, 16#E9#, 16#43#, 16#C0#, 16#8F#,
         16#05#, 16#02#, 16#35#, 16#D7#, 16#D6#, 16#8B#, 16#1D#, 16#A5#,
         16#5E#, 16#63#, 16#F7#, 16#3B#, 16#60#, 16#A5#, 16#7F#, 16#CE#];
      Actual_384 : constant Ada.Streams.Stream_Element_Array :=
        CryptoLib.Macs.PBKDF2_HMAC_SHA384
          (Bytes_From_String ("password"), Bytes_From_String ("salt"), 1, 48);
   begin
      Check (Actual_256 = Expected_256, "PBKDF2-HMAC-SHA256 RFC vector");
      Check (Actual_512 = Expected_512, "PBKDF2-HMAC-SHA512 RFC vector");
      Check
        (Actual_384'Length = 48
         and then Actual_384 /= [Actual_384'Range => 0],
         "PBKDF2-HMAC-SHA384 derives output");
   end Check_PBKDF2_SHA2;

   procedure Check_PBKDF1 is
      Salt : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("12345678");
      Actual_MD5 : constant Ada.Streams.Stream_Element_Array :=
        CryptoLib.Macs.PBKDF1_MD5
          (Bytes_From_String ("password"), Salt, 1, 16);
      Expected_MD5 : constant Ada.Streams.Stream_Element_Array (1 .. 16) :=
        [16#BB#, 16#B0#, 16#DD#, 16#FF#, 16#1B#, 16#94#, 16#4B#, 16#3C#,
         16#C6#, 16#8E#, 16#AA#, 16#EB#, 16#7A#, 16#C2#, 16#00#, 16#99#];
      Actual_SHA1 : constant Ada.Streams.Stream_Element_Array :=
        CryptoLib.Macs.PBKDF1_SHA1
          (Bytes_From_String ("password"), Salt, 1, 20);
      Expected_SHA1 : constant Ada.Streams.Stream_Element_Array (1 .. 20) :=
        [16#23#, 16#17#, 16#AA#, 16#72#, 16#DA#, 16#FA#, 16#0A#, 16#07#,
         16#F0#, 16#5A#, 16#F4#, 16#7B#, 16#AA#, 16#2E#, 16#38#, 16#8F#,
         16#95#, 16#DC#, 16#F6#, 16#F3#];
      Prefix_MD5 : constant Ada.Streams.Stream_Element_Array :=
        CryptoLib.Macs.PBKDF1_MD5
          (Bytes_From_String ("password"), Salt, 1, 8);
   begin
      Check (Actual_MD5 = Expected_MD5, "PBKDF1-MD5 vector");
      Check (Actual_SHA1 = Expected_SHA1, "PBKDF1-SHA1 vector");
      Check
        (Prefix_MD5 = Expected_MD5 (1 .. 8),
         "PBKDF1-MD5 bounded prefix output");
   end Check_PBKDF1;

   procedure Check_PKCS12_KDF_SHA1 is
      Salt : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("12345678");
      Key_Data : constant Ada.Streams.Stream_Element_Array :=
        CryptoLib.Macs.PKCS12_KDF_SHA1
          (Bytes_From_String ("password"), Salt, 1, 1, 24);
      Expected_Key : constant Ada.Streams.Stream_Element_Array (1 .. 24) :=
        [16#6F#, 16#E1#, 16#C2#, 16#49#, 16#FA#, 16#28#, 16#B6#, 16#20#,
         16#F7#, 16#50#, 16#FA#, 16#EF#, 16#06#, 16#42#, 16#88#, 16#DF#,
         16#64#, 16#FB#, 16#CE#, 16#7B#, 16#D3#, 16#B8#, 16#C1#, 16#DE#];
      IV_Data : constant Ada.Streams.Stream_Element_Array :=
        CryptoLib.Macs.PKCS12_KDF_SHA1
          (Bytes_From_String ("password"), Salt, 1, 2, 8);
      Expected_IV : constant Ada.Streams.Stream_Element_Array (1 .. 8) :=
        [16#70#, 16#B8#, 16#9D#, 16#4B#, 16#0D#, 16#97#, 16#07#, 16#71#];
      Iterated_Key : constant Ada.Streams.Stream_Element_Array :=
        CryptoLib.Macs.PKCS12_KDF_SHA1
          (Bytes_From_String ("password"), Salt, 5, 1, 24);
      Expected_Iterated_Key :
        constant Ada.Streams.Stream_Element_Array (1 .. 24) :=
          [16#79#, 16#C9#, 16#E5#, 16#E4#, 16#04#, 16#A2#, 16#E1#, 16#5A#,
           16#5F#, 16#DC#, 16#8E#, 16#AD#, 16#95#, 16#6D#, 16#43#, 16#9B#,
           16#54#, 16#C0#, 16#93#, 16#F9#, 16#53#, 16#E4#, 16#68#, 16#30#];
   begin
      Check (Key_Data = Expected_Key, "PKCS12KDF-SHA1 key vector");
      Check (IV_Data = Expected_IV, "PKCS12KDF-SHA1 IV vector");
      Check
        (Iterated_Key = Expected_Iterated_Key,
         "PKCS12KDF-SHA1 iteration vector");
   end Check_PKCS12_KDF_SHA1;

   procedure Check_Scrypt_SHA256 is
      Actual : constant Ada.Streams.Stream_Element_Array :=
        CryptoLib.Macs.Scrypt_SHA256
          (Bytes_From_String ("password"),
           Bytes_From_String ("12345678"),
           16,
           1,
           1,
           64);
      Expected : constant Ada.Streams.Stream_Element_Array (1 .. 64) :=
        [16#61#, 16#D0#, 16#75#, 16#CB#, 16#C3#, 16#C1#, 16#4B#, 16#BC#,
         16#CD#, 16#22#, 16#68#, 16#27#, 16#72#, 16#6A#, 16#40#, 16#4C#,
         16#95#, 16#C5#, 16#DE#, 16#B5#, 16#41#, 16#0B#, 16#3B#, 16#7E#,
         16#B5#, 16#5D#, 16#70#, 16#51#, 16#1D#, 16#56#, 16#8C#, 16#6A#,
         16#59#, 16#09#, 16#7D#, 16#32#, 16#1F#, 16#7B#, 16#28#, 16#DA#,
         16#D0#, 16#D7#, 16#AB#, 16#84#, 16#15#, 16#D4#, 16#81#, 16#3C#,
         16#8E#, 16#08#, 16#EA#, 16#82#, 16#27#, 16#92#, 16#66#, 16#84#,
         16#B4#, 16#6A#, 16#AF#, 16#32#, 16#16#, 16#63#, 16#6E#, 16#01#];
   begin
      Check (Actual = Expected, "scrypt-SHA256 vector");
   end Check_Scrypt_SHA256;

   procedure Check_Seven_Zip_AES_SHA256_KDF is
      Password : constant Ada.Streams.Stream_Element_Array (1 .. 2) :=
        [16#70#, 16#00#];
      Salt     : constant Ada.Streams.Stream_Element_Array (1 .. 3) :=
        [16#01#, 16#02#, 16#03#];
      Actual   : constant Ada.Streams.Stream_Element_Array :=
        CryptoLib.Macs.Seven_Zip_AES_SHA256_KDF (Password, Salt, 3);
      Expected : constant Ada.Streams.Stream_Element_Array (1 .. 32) :=
        [16#3F#, 16#9F#, 16#B2#, 16#B7#, 16#95#, 16#0B#, 16#BA#, 16#38#,
         16#E1#, 16#CC#, 16#1F#, 16#B6#, 16#20#, 16#29#, 16#2F#, 16#B1#,
         16#70#, 16#91#, 16#8A#, 16#20#, 16#54#, 16#B4#, 16#84#, 16#F6#,
         16#E8#, 16#39#, 16#89#, 16#96#, 16#4E#, 16#86#, 16#63#, 16#04#];
   begin
      Check (Actual = Expected, "7zAES SHA-256 KDF vector");
   end Check_Seven_Zip_AES_SHA256_KDF;

   procedure Check_EVP_Bytes_To_Key_MD5 is
      Actual : constant Ada.Streams.Stream_Element_Array :=
        CryptoLib.Macs.EVP_Bytes_To_Key_MD5
          (Bytes_From_String ("password"),
           Ada.Streams.Stream_Element_Array'
             (1 => 16#12#, 2 => 16#34#, 3 => 16#56#, 4 => 16#78#,
              5 => 16#90#, 6 => 16#AB#, 7 => 16#CD#, 8 => 16#EF#),
           32);
   begin
      Check
        (Actual'Length = 32 and then Actual /= [Actual'Range => 0],
         "EVP_BytesToKey-MD5 derives output");
   end Check_EVP_Bytes_To_Key_MD5;

   --  These decide what a certificate may contain, and they moved here from a
   --  caller that had its own copy of the rules. Both copies could not have
   --  been checked against each other; one can be checked against the encoder.
   --  A bundle nothing can open is not a bundle. The MAC key comes from the
   --  password as typed -- PKCS12_KDF_SHA1 widens it to a BMPString itself --
   --  and handing it one already widened derived a key for a password nobody
   --  typed, so every bundle failed its own integrity check. The vector here
   --  was taken from OpenSSL, which agrees with it byte for byte.
   procedure Check_PKCS12_Mac_Key is
      Password : constant Ada.Streams.Stream_Element_Array :=
        [16#73#, 16#65#, 16#63#, 16#72#, 16#65#, 16#74#];        --  "secret"
      Salt     : constant Ada.Streams.Stream_Element_Array :=
        [16#C7#, 16#40#, 16#DF#, 16#A4#, 16#CA#, 16#54#, 16#E2#, 16#4B#];
      Expected : constant Ada.Streams.Stream_Element_Array :=
        [16#4A#, 16#0F#, 16#8B#, 16#F9#, 16#AF#, 16#DB#, 16#AA#, 16#5A#,
         16#E5#, 16#14#, 16#BB#, 16#67#, 16#40#, 16#CD#, 16#53#, 16#9D#,
         16#66#, 16#57#, 16#53#, 16#81#];
   begin
      Check
        (CryptoLib.Macs.PKCS12_KDF_SHA1
           (Password_Data => Password,
            Salt_Data     => Salt,
            Iterations    => 2048,
            Id_Byte       => 3,
            Output_Length => 20) = Expected,
         "PKCS#12 MAC key matches OpenSSL for a password as typed");
   end Check_PKCS12_Mac_Key;

   --  How much work a password has to be put through to open a bundle.
   --
   --  A PKCS#12 file holds a private key, so a copy of it is an offline
   --  guessing target and the iteration count is the only thing standing
   --  between a weak password and the key.
   procedure Check_PKCS12_Work_Factor is
      use type CryptoLib.PKCS12.Open_Status;

      package P12 renames CryptoLib.PKCS12;

      --  Above 16#8000#, where the DER integer encoder used to emit a
      --  leading zero octet that DER does not permit -- so a bundle written
      --  with a count in this range was refused by this crate's own reader.
      --  Small enough to keep the suite quick.
      Count : constant := 32_768;

      --  02 03 00 80 00: an INTEGER, three content octets, 32_768 with the
      --  pad that keeps it positive.
      Encoded : constant String :=
        Character'Val (16#02#) & Character'Val (16#03#)
        & Character'Val (16#00#) & Character'Val (16#80#)
        & Character'Val (16#00#);

      CA_PEM, CA_Key, Bundle : Unbounded_String;
      Outcome : CryptoLib.Certificates.Certificate_Status;
      Seen    : Natural := 0;
   begin
      --  The default itself is floored by a Compile_Time_Error in the spec,
      --  which is where a check the compiler can settle belongs. What is
      --  worth checking here is that the count reaches the bundle at all.
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("p12-work-ca", CA_PEM, CA_Key, CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      Outcome :=
        CryptoLib.Certificates.Generate_PKCS12
          (To_String (CA_PEM), To_String (CA_Key), "work", "secret",
           Bundle, Iterations => Count);
      Check (Outcome = CryptoLib.Certificates.Ok,
             "a bundle is written at this count");

      --  Both the MAC and the encryption derive from the password, so an
      --  attacker tests guesses against whichever is cheaper. Raising one
      --  and leaving the other buys nothing, which is why the count has to
      --  appear twice.
      declare
         Text : constant String := To_String (Bundle);
      begin
         for I in Text'First .. Text'Last - Encoded'Length + 1 loop
            if Text (I .. I + Encoded'Length - 1) = Encoded then
               Seen := Seen + 1;
            end if;
         end loop;
      end;
      Check (Seen = 2,
             "the count governs both the MAC and the encryption, found"
             & Natural'Image (Seen) & " of 2");

      --  And the bundle still opens, which is what the old encoder broke:
      --  a count in this range came out non-canonical and this crate's own
      --  reader refused the file it had just written.
      declare
         Text : constant String := To_String (Bundle);
         Raw  : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Text'Length));
         Item : P12.Bundle;
         St   : P12.Open_Status;
      begin
         for I in Text'Range loop
            Raw (Ada.Streams.Stream_Element_Offset (I - Text'First + 1)) :=
              Character'Pos (Text (I));
         end loop;

         P12.Open (Raw, "secret", CryptoLib.ASN1.Default_Limits, Item, St);
         Check (St = P12.Ok,
                "and it opens, got " & P12.Status_Image (St));
      end;
   end Check_PKCS12_Work_Factor;

   --  What a bundle costs to open is a number the bundle chooses.
   --
   --  A PKCS#12 file states its own iteration counts, twice -- once for the
   --  MAC and once for the encryption -- and both are paid before anything
   --  in the file has been believed. Open had no way to be told a ceiling,
   --  and the one it used internally allows about forty-five seconds of CPU
   --  per file here. That is a person opening a file they chose; it is not a
   --  service opening one that arrived.
   procedure Check_PKCS12_Work_Ceiling is
      use type CryptoLib.PKCS12.Open_Status;

      package P12 renames CryptoLib.PKCS12;

      Written : constant := 32_768;

      CA_PEM, CA_Key, Bundle : Unbounded_String;
      Outcome : CryptoLib.Certificates.Certificate_Status;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("ceiling-ca", CA_PEM, CA_Key, CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      Outcome :=
        CryptoLib.Certificates.Generate_PKCS12
          (To_String (CA_PEM), To_String (CA_Key), "ceiling", "secret",
           Bundle, Iterations => Written);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: bundle written");

      declare
         Text : constant String := To_String (Bundle);
         Raw  : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Text'Length));
      begin
         for I in Text'Range loop
            Raw (Ada.Streams.Stream_Element_Offset (I - Text'First + 1)) :=
              Character'Pos (Text (I));
         end loop;

         --  Allowed the work, it opens.
         declare
            Item : P12.Bundle;
            St   : P12.Open_Status;
         begin
            P12.Open (Raw, "secret", CryptoLib.ASN1.Default_Limits, Item, St,
                      Maximum_Iterations => Written);
            Check (St = P12.Ok,
                   "a bundle within the ceiling opens, got "
                   & P12.Status_Image (St));
         end;

         --  Told to spend less than the bundle asks, it refuses. The
         --  password is right; what is wrong is the price.
         declare
            Item : P12.Bundle;
            St   : P12.Open_Status;
         begin
            P12.Open (Raw, "secret", CryptoLib.ASN1.Default_Limits, Item, St,
                      Maximum_Iterations => Written - 1);
            Check (St /= P12.Ok,
                   "and a bundle asking for more than the caller allows does "
                   & "not, got " & P12.Status_Image (St));
            Check (not P12.Is_Present (Item),
                   "with nothing decoded from it");
         end;
      end;
   end Check_PKCS12_Work_Ceiling;

   --  bcrypt_pbkdf, which nothing here was checking.
   --
   --  This crate exports it for OpenSSH private keys and does not use it
   --  itself, so no other test reached it even indirectly, and the suite
   --  named it nowhere -- while SECURITY.md listed it among the primitives
   --  validated against published vectors. The implementation turns out to
   --  be right; what was missing was anything that would have said so.
   --
   --  The vectors come from the bcrypt module's kdf, which is the same
   --  OpenBSD construction, and were compared against this before being
   --  written down.
   procedure Check_Bcrypt_PBKDF is
      function From_Hex
        (Text : String) return Ada.Streams.Stream_Element_Array
      is
         Result : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Text'Length / 2));
         function Nibble (C : Character) return Natural
         is (case C is
                when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
                when others     => Character'Pos (C) - Character'Pos ('a') + 10);
      begin
         for I in Result'Range loop
            Result (I) :=
              Ada.Streams.Stream_Element
                (Nibble (Text (Text'First + 2 * Natural (I - 1))) * 16
                 + Nibble (Text (Text'First + 2 * Natural (I - 1) + 1)));
         end loop;
         return Result;
      end From_Hex;

      procedure One_Vector
        (Passphrase : String;
         Salt       : String;
         Rounds     : Natural;
         Length     : Natural;
         Expected   : String)
      is
         Derived : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Length));
         Status  : constant CryptoLib.Errors.Status :=
           CryptoLib.BCrypt_PBKDF.Derive
             (Passphrase, From_Hex (Salt),
              Interfaces.Unsigned_32 (Rounds), Derived);
      begin
         Check (Status = CryptoLib.Errors.Ok
                and then Derived = From_Hex (Expected),
                "bcrypt_pbkdf over" & Natural'Image (Rounds)
                & " rounds into" & Natural'Image (Length) & " bytes");
      end One_Vector;
   begin
      One_Vector
        ("password", "0102030405060708", 8, 32,
         "dabe5bcaf0e213b7ab90f96262fc3a9eacf94dcd1b887381ad437350ef38b5de");
      One_Vector
        ("correct horse battery staple", "73616c7479736f6d657468696e6721", 16, 64,
         "c59a3adaea5e47dc1937e1e4c51e33e149d0c7b0ab44573b3796d7125c1037a87eb1dd86f139"
         & "e6f43ce8c9334e721fc0b8de115f3d9305c53a2a45d3126b001f");
      One_Vector
        ("x", "aabbccddeeff0011", 1, 48,
         "f73b50dc8b834e74ec8f8ae35589883266eb246d10b88eeb76ce08e927861c18351b2faccf53"
         & "57492128d74c1bffa71e");

      --  The limits are refusals, not silent truncations.
      declare
         Small : Ada.Streams.Stream_Element_Array (1 .. 16);
      begin
         Check (CryptoLib.BCrypt_PBKDF.Derive
                  ("pw", From_Hex ("0102030405060708"), 0, Small)
                /= CryptoLib.Errors.Ok,
                "no rounds is refused rather than derived from");
         Check (Small = [1 .. 16 => 0],
                "and the output is zeroed rather than left half filled");

         Check (CryptoLib.BCrypt_PBKDF.Derive
                  ("", From_Hex ("0102030405060708"), 8, Small)
                /= CryptoLib.Errors.Ok,
                "an empty passphrase is refused");
                  Check (Small = [Small'Range => 0], "and the output is zeroed");
      end;
   end Check_Bcrypt_PBKDF;

   --  RFC 8446 7.1 key-schedule derivations, against RFC 8448's published
   --  handshake values.
   procedure Check_TLS13_KDF is
      package K renames CryptoLib.TLS13_KDF;
      package H renames CryptoLib.HKDF;

      Empty : constant Ada.Streams.Stream_Element_Array (1 .. 0) :=
        [others => 0];
      Zeros32 : constant Ada.Streams.Stream_Element_Array (1 .. 32) :=
        [others => 0];
      Early, Derived : Ada.Streams.Stream_Element_Array (1 .. 32);
      St : CryptoLib.Errors.Status;
   begin
      --  The first two steps of every TLS 1.3 handshake, byte for byte as
      --  RFC 8448 prints them.
      St := H.Extract (H.SHA256, Empty, Zeros32, Early);
      Check (St = CryptoLib.Errors.Ok
             and then Early = Bytes_From_Hex
               ("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170"
                & "f92a"),
             "RFC 8448 early secret");

      St := K.Derive_Secret (H.SHA256, Early, "derived", Empty, Derived);
      Check (St = CryptoLib.Errors.Ok
             and then Derived = Bytes_From_Hex
               ("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c36"
                & "11ba"),
             "RFC 8448 Derive-Secret(early, 'derived', '')");

      --  Expand-Label at the widths TLS asks for: a 16-byte key, a 12-byte
      --  IV, and a 32-byte finished key with a non-empty context.
      declare
         Secret : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
           ("3fce516009c21727d0f2e4e86ee403bc3fce516009c21727d0f2e4e86ee403bc");
         Ctx    : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_Hex ("0102030405");
         Key16  : Ada.Streams.Stream_Element_Array (1 .. 16);
         Iv12   : Ada.Streams.Stream_Element_Array (1 .. 12);
         Fin32  : Ada.Streams.Stream_Element_Array (1 .. 32);
      begin
         Check (K.Expand_Label (H.SHA256, Secret, "key", Empty, Key16)
                  = CryptoLib.Errors.Ok
                and then Key16 = Bytes_From_Hex
                  ("2090cfce94b714260a55851367768505"),
                "HKDF-Expand-Label 'key' at 16 octets");
         Check (K.Expand_Label (H.SHA256, Secret, "iv", Empty, Iv12)
                  = CryptoLib.Errors.Ok
                and then Iv12 = Bytes_From_Hex ("13bb276fe56315b474c6e454"),
                "HKDF-Expand-Label 'iv' at 12 octets");
         Check (K.Expand_Label (H.SHA256, Secret, "finished", Ctx, Fin32)
                  = CryptoLib.Errors.Ok
                and then Fin32 = Bytes_From_Hex
                  ("68fcae0978b33ec74bacce1a51c1f124f641e227d762b574744871de4d"
                   & "3bfc8e"),
                "HKDF-Expand-Label 'finished' with a context");

         --  The "tls13 " prefix has to actually be applied. Expanding with a
         --  hand-built info that omits it must give something else -- without
         --  this, a package that forgot the prefix would still pass every
         --  round-trip test written against itself.
         declare
            No_Prefix : constant Ada.Streams.Stream_Element_Array :=
              [16#00#, 16#10#, 16#03#, Character'Pos ('k'),
               Character'Pos ('e'), Character'Pos ('y'), 16#00#];
            Other : Ada.Streams.Stream_Element_Array (1 .. 16);
         begin
            Check (H.Expand (H.SHA256, Secret, No_Prefix, Other)
                     = CryptoLib.Errors.Ok,
                   "expanding with a hand-built info succeeds");
            Check (Other /= Key16,
                   "the label is prefixed with 'tls13 ', not used bare");
         end;

         --  Two labels over one secret must not collide.
         declare
            A, B : Ada.Streams.Stream_Element_Array (1 .. 16);
         begin
            Check (K.Expand_Label (H.SHA256, Secret, "key", Empty, A)
                     = CryptoLib.Errors.Ok
                   and then K.Expand_Label (H.SHA256, Secret, "iv", Empty, B)
                     = CryptoLib.Errors.Ok,
                   "both labels expand");
            Check (A /= B, "different labels give unrelated keys");
         end;
      end;

      --  The SHA-384 arm, which TLS_AES_256_GCM_SHA384 uses.
      declare
         Z48 : constant Ada.Streams.Stream_Element_Array (1 .. 48) :=
           [others => 0];
         E48, D48 : Ada.Streams.Stream_Element_Array (1 .. 48);
      begin
         St := H.Extract (H.SHA384, Empty, Z48, E48);
         Check (St = CryptoLib.Errors.Ok, "SHA-384 early secret extracts");
         St := K.Derive_Secret (H.SHA384, E48, "derived", Empty, D48);
         Check (St = CryptoLib.Errors.Ok
                and then D48 = Bytes_From_Hex
                  ("1591dac5cbbf0330a4a84de9c753330e92d01f0a88214b4464972fd668"
                   & "049e93e52f2b16fad922fdc0584478428f282b"),
                "SHA-384 Derive-Secret(early, 'derived', '')");
      end;

      --  Derive_Secret and Derive_Secret_From_Transcript must agree: one
      --  hashes the messages, the other is handed the digest.
      declare
         Msgs : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String ("a handshake transcript");
         Digest : constant Ada.Streams.Stream_Element_Array :=
           Ada.Streams.Stream_Element_Array
             (CryptoLib.Hashes.SHA256 (Msgs));
         A, B : Ada.Streams.Stream_Element_Array (1 .. 32);
      begin
         St := K.Derive_Secret (H.SHA256, Early, "c hs traffic", Msgs, A);
         Check (St = CryptoLib.Errors.Ok, "Derive_Secret over messages");
         St := K.Derive_Secret_From_Transcript
           (H.SHA256, Early, "c hs traffic", Digest, B);
         Check (St = CryptoLib.Errors.Ok and then A = B,
                "hashing the transcript here or outside gives one answer");
      end;

      --  Refusals, each with the buffer left zero.
      declare
         Secret : constant Ada.Streams.Stream_Element_Array (1 .. 32) :=
           [others => 1];
         Short  : constant Ada.Streams.Stream_Element_Array (1 .. 31) :=
           [others => 1];
         Big    : constant Ada.Streams.Stream_Element_Array (1 .. 256) :=
           [others => 2];
         Long_Label : constant String (1 .. 250) := [others => 'x'];
         Out16  : Ada.Streams.Stream_Element_Array (1 .. 16) :=
           [others => 16#A5#];
         Out31  : Ada.Streams.Stream_Element_Array (1 .. 31) :=
           [others => 16#A5#];
      begin
         Check (K.Expand_Label (H.SHA256, Secret, "", Empty, Out16)
                  /= CryptoLib.Errors.Ok,
                "an empty label is refused");
         Check (Out16 = [Out16'Range => 0], "and the output is zeroed");

         Check (K.Expand_Label (H.SHA256, Secret, Long_Label, Empty, Out16)
                  /= CryptoLib.Errors.Ok,
                "a label past 249 characters is refused, not truncated");
         Check (Out16 = [Out16'Range => 0], "and the output is zeroed");

         Check (K.Expand_Label (H.SHA256, Short, "key", Empty, Out16)
                  /= CryptoLib.Errors.Ok,
                "a secret narrower than the hash is refused");
         Check (Out16 = [Out16'Range => 0], "and the output is zeroed");

         Check (K.Expand_Label (H.SHA256, Secret, "key", Big, Out16)
                  /= CryptoLib.Errors.Ok,
                "a context past 255 octets is refused");
         Check (Out16 = [Out16'Range => 0], "and the output is zeroed");

         Check (K.Derive_Secret (H.SHA256, Secret, "derived", Empty, Out31)
                  /= CryptoLib.Errors.Ok,
                "Derive-Secret refuses an output that is not the hash's width");
         Check (Out31 = [Out31'Range => 0], "and the output is zeroed");
      end;
   end Check_TLS13_KDF;

   procedure Check_HKDF is
      package HK renames CryptoLib.HKDF;

      V1_IKM : constant String :=
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
      V1_Salt : constant String :=
        "000102030405060708090a0b0c";
      V1_Info : constant String :=
        "f0f1f2f3f4f5f6f7f8f9";
      V1_PRK : constant String :=
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
      V1_OKM : constant String :=
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
      V2_IKM : constant String :=
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829" &
        "2a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f";
      V2_Salt : constant String :=
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283848586878889" &
        "8a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
      V2_Info : constant String :=
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9" &
        "dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
      V2_PRK : constant String :=
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244";
      V2_OKM : constant String :=
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb" &
        "41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87";
      V3_IKM : constant String :=
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
      V3_Salt : constant String := "";
      V3_Info : constant String := "";
      V3_PRK : constant String :=
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04";
      V3_OKM : constant String :=
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8";
      V4_IKM : constant String :=
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
      V4_Salt : constant String :=
        "000102030405060708090a0b0c";
      V4_Info : constant String :=
        "f0f1f2f3f4f5f6f7f8f9";
      V4_PRK : constant String :=
        "704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8dec70ee9a7e1f3e293ef68" &
        "eceb072a5ade";
      V4_OKM : constant String :=
        "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5" &
        "d95d1da3e625";
      V5_IKM : constant String :=
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
      V5_Salt : constant String :=
        "000102030405060708090a0b0c";
      V5_Info : constant String :=
        "f0f1f2f3f4f5f6f7f8f9";
      V5_PRK : constant String :=
        "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf8" &
        "0ef802d57e2f7cebcf1e00e083848be19929c61b4237";
      V5_OKM : constant String :=
        "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb" &
        "cce0dff7098769cf15959867d571c1715450cb530137";

      function From_Hex
        (Text : String) return Ada.Streams.Stream_Element_Array
      is
         Result : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Text'Length / 2));
         function Nibble (C : Character) return Natural
         is (case C is
                when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
                when others     => Character'Pos (C) - Character'Pos ('a') + 10);
      begin
         for I in Result'Range loop
            Result (I) :=
              Ada.Streams.Stream_Element
                (Nibble (Text (Text'First + 2 * Natural (I - 1))) * 16
                 + Nibble (Text (Text'First + 2 * Natural (I - 1) + 1)));
         end loop;
         return Result;
      end From_Hex;

      procedure One_Vector
        (Label  : String;
         Hash   : HK.Hash_Algorithm;
         IKM, Salt, Info : String;
         Length : Natural;
         PRK, OKM : String)
      is
         Got_PRK : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (HK.PRK_Length (Hash)));
         Got_OKM : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Length));
         Status  : CryptoLib.Errors.Status;
      begin
         Status := HK.Extract (Hash, From_Hex (Salt), From_Hex (IKM), Got_PRK);
         Check (Status = CryptoLib.Errors.Ok
                and then Got_PRK = From_Hex (PRK),
                Label & ": the pseudorandom key");

         --  Expand from that key on its own, which RFC 5869 allows and
         --  TLS 1.3 does between handshake stages.
         Status := HK.Expand (Hash, Got_PRK, From_Hex (Info), Got_OKM);
         Check (Status = CryptoLib.Errors.Ok
                and then Got_OKM = From_Hex (OKM),
                Label & ": expanding that key gives the output");

         --  And the two together.
         Got_OKM := [others => 0];
         Status := HK.Derive (Hash, From_Hex (Salt), From_Hex (IKM),
                              From_Hex (Info), Got_OKM);
         Check (Status = CryptoLib.Errors.Ok
                and then Got_OKM = From_Hex (OKM),
                Label & ": and deriving in one step gives the same");
      end One_Vector;
   begin
      One_Vector ("A.1 SHA-256 basic", HK.SHA256,
                  V1_IKM, V1_Salt, V1_Info, 42,
                  V1_PRK, V1_OKM);
      One_Vector ("A.2 SHA-256 long inputs", HK.SHA256,
                  V2_IKM, V2_Salt, V2_Info, 82,
                  V2_PRK, V2_OKM);
      One_Vector ("A.3 SHA-256 empty salt and info", HK.SHA256,
                  V3_IKM, V3_Salt, V3_Info, 42,
                  V3_PRK, V3_OKM);
      One_Vector ("SHA-384", HK.SHA384,
                  V4_IKM, V4_Salt, V4_Info, 48,
                  V4_PRK, V4_OKM);
      One_Vector ("SHA-512", HK.SHA512,
                  V5_IKM, V5_Salt, V5_Info, 64,
                  V5_PRK, V5_OKM);

      --  The counter is one octet, so 255 blocks is the ceiling. A 256th
      --  would repeat the first block's counter and so its output.
      declare
         PRK : constant Ada.Streams.Stream_Element_Array (1 .. 32) :=
           [others => 16#42#];
         At_Ceiling : Ada.Streams.Stream_Element_Array (1 .. 255 * 32);
         Past_It    : Ada.Streams.Stream_Element_Array (1 .. 255 * 32 + 1);
         Nothing    : Ada.Streams.Stream_Element_Array (1 .. 0);
         Status     : CryptoLib.Errors.Status;
      begin
         Check (HK.Maximum_Output (HK.SHA256) = 255 * 32,
                "the SHA-256 ceiling is 255 blocks");

         Status := HK.Expand (HK.SHA256, PRK, [1 .. 0 => 0], At_Ceiling);
         Check (Status = CryptoLib.Errors.Ok,
                "output right up to the ceiling is produced");

         Status := HK.Expand (HK.SHA256, PRK, [1 .. 0 => 0], Past_It);
         Check (Status /= CryptoLib.Errors.Ok,
                "and one octet past it is refused rather than wrapped");
         Check (Past_It = [Past_It'Range => 0],
                "with nothing left in the buffer to be mistaken for a key");

         Status := HK.Expand (HK.SHA256, PRK, [1 .. 0 => 0], Nothing);
         Check (Status = CryptoLib.Errors.Ok,
                "asking for no output at all is not an error");
         Check (Nothing = [1 .. 0 => 0], "and returns nothing");

         --  A pseudorandom key shorter than the hash is not one.
         declare
            Short  : constant Ada.Streams.Stream_Element_Array (1 .. 31) :=
              [others => 16#42#];
            Some_Out : Ada.Streams.Stream_Element_Array (1 .. 16);
         begin
            Check (HK.Expand (HK.SHA256, Short, [1 .. 0 => 0], Some_Out)
                   /= CryptoLib.Errors.Ok,
                   "a key shorter than the hash is refused");
            Check (Some_Out = [Some_Out'Range => 0], "and the output is zeroed");
         end;
      end;

      --  Info is what separates two keys drawn from one exchange. If it did
      --  not reach the computation, every key a protocol derived would be
      --  the same key.
      declare
         Secret : constant Ada.Streams.Stream_Element_Array (1 .. 32) :=
           [others => 16#5A#];
         Salt   : constant Ada.Streams.Stream_Element_Array (1 .. 8) :=
           [others => 16#11#];
         Enc, Mac : Ada.Streams.Stream_Element_Array (1 .. 32);
         Status : CryptoLib.Errors.Status;
      begin
         Status := HK.Derive (HK.SHA256, Salt, Secret,
                              [1 => Character'Pos ('e')], Enc);
         Check (Status = CryptoLib.Errors.Ok, "one context derives");
         Status := HK.Derive (HK.SHA256, Salt, Secret,
                              [1 => Character'Pos ('m')], Mac);
         Check (Status = CryptoLib.Errors.Ok, "another context derives");
         Check (Enc /= Mac,
                "two contexts over one secret give unrelated keys");
      end;
   end Check_HKDF;

   --  PBKDF2-HMAC-SHA1 with a high iteration count (RFC 6070, c = 4096) to
   --  exercise the iteration/XOR-accumulation loop (previously only c = 1).
   procedure Check_PBKDF2_High_Iteration is
   begin
      Check
        (CryptoLib.Macs.PBKDF2_HMAC_SHA1
           (Bytes_From_String ("password"), Bytes_From_String ("salt"), 4096, 20)
         = Bytes_From_Hex ("4b007901b765489abead49d926f721d065a429c1"),
         "PBKDF2-HMAC-SHA1 RFC 6070 c=4096 KAT");
   end Check_PBKDF2_High_Iteration;

   --  AUnit routine wrappers. Each check is a test of its own, so a
   --  failure reports the check that failed and the rest still run.
   procedure Run_Check_PBKDF2_SHA1 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_PBKDF2_SHA2 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_PBKDF1 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_PKCS12_KDF_SHA1 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Scrypt_SHA256 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Seven_Zip_AES_SHA256_KDF (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_EVP_Bytes_To_Key_MD5 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Bcrypt_PBKDF (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_HKDF (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_TLS13_KDF (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_PKCS12_Work_Factor (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_PKCS12_Work_Ceiling (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_PKCS12_Mac_Key (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_PBKDF2_High_Iteration (Item : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Check_PBKDF2_SHA1 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_PBKDF2_SHA1;
   end Run_Check_PBKDF2_SHA1;

   procedure Run_Check_PBKDF2_SHA2 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_PBKDF2_SHA2;
   end Run_Check_PBKDF2_SHA2;

   procedure Run_Check_PBKDF1 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_PBKDF1;
   end Run_Check_PBKDF1;

   procedure Run_Check_PKCS12_KDF_SHA1 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_PKCS12_KDF_SHA1;
   end Run_Check_PKCS12_KDF_SHA1;

   procedure Run_Check_Scrypt_SHA256 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Scrypt_SHA256;
   end Run_Check_Scrypt_SHA256;

   procedure Run_Check_Seven_Zip_AES_SHA256_KDF (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Seven_Zip_AES_SHA256_KDF;
   end Run_Check_Seven_Zip_AES_SHA256_KDF;

   procedure Run_Check_EVP_Bytes_To_Key_MD5 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_EVP_Bytes_To_Key_MD5;
   end Run_Check_EVP_Bytes_To_Key_MD5;

   procedure Run_Check_Bcrypt_PBKDF (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Bcrypt_PBKDF;
   end Run_Check_Bcrypt_PBKDF;

   procedure Run_Check_HKDF (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_HKDF;
   end Run_Check_HKDF;

   procedure Run_Check_TLS13_KDF (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_TLS13_KDF;
   end Run_Check_TLS13_KDF;

   procedure Run_Check_PKCS12_Work_Factor (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_PKCS12_Work_Factor;
   end Run_Check_PKCS12_Work_Factor;

   procedure Run_Check_PKCS12_Work_Ceiling (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_PKCS12_Work_Ceiling;
   end Run_Check_PKCS12_Work_Ceiling;

   procedure Run_Check_PKCS12_Mac_Key (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_PKCS12_Mac_Key;
   end Run_Check_PKCS12_Mac_Key;

   procedure Run_Check_PBKDF2_High_Iteration (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_PBKDF2_High_Iteration;
   end Run_Check_PBKDF2_High_Iteration;

   overriding procedure Register_Tests (Item : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (Item, Run_Check_PBKDF2_SHA1'Access, "pbkdf2 sha1");
      Register_Routine (Item, Run_Check_PBKDF2_SHA2'Access, "pbkdf2 sha2");
      Register_Routine (Item, Run_Check_PBKDF1'Access, "pbkdf1");
      Register_Routine (Item, Run_Check_PKCS12_KDF_SHA1'Access, "pkcs12 kdf sha1");
      Register_Routine (Item, Run_Check_Scrypt_SHA256'Access, "scrypt sha256");
      Register_Routine (Item, Run_Check_Seven_Zip_AES_SHA256_KDF'Access, "seven zip aes sha256 kdf");
      Register_Routine (Item, Run_Check_EVP_Bytes_To_Key_MD5'Access, "evp bytes to key md5");
      Register_Routine (Item, Run_Check_Bcrypt_PBKDF'Access, "bcrypt pbkdf");
      Register_Routine (Item, Run_Check_HKDF'Access, "hkdf");
      Register_Routine (Item, Run_Check_TLS13_KDF'Access, "tls13 kdf");
      Register_Routine (Item, Run_Check_PKCS12_Work_Factor'Access, "pkcs12 work factor");
      Register_Routine (Item, Run_Check_PKCS12_Work_Ceiling'Access, "pkcs12 work ceiling");
      Register_Routine (Item, Run_Check_PKCS12_Mac_Key'Access, "pkcs12 mac key");
      Register_Routine (Item, Run_Check_PBKDF2_High_Iteration'Access, "pbkdf2 high iteration");
   end Register_Tests;

   overriding function Name (Item : Test_Case) return AUnit.Message_String is
      pragma Unreferenced (Item);
   begin
      return AUnit.Format ("cryptolib key derivation");
   end Name;

end Tests_KDFs;
