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
with CryptoLib.X509.CRLs;
with CryptoLib.X509.Revocation;
with CryptoLib.OCSP;
with CryptoLib.PKCS10;
with CryptoLib.PKCS8;
with CryptoLib.PKCS12;
with CryptoLib.Identities;
with CryptoLib.X509.Validation;
with CryptoLib.X509.Path_Building;
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
with CryptoLib.SHA3;
with CryptoLib.Buffers;
with CryptoLib.Diffie_Hellman;
with CryptoLib.Modexp;
with CryptoLib.Random;
with CryptoLib.RSA;

procedure Tests is
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Certificates.Certificate_Status;
   use type Interfaces.Unsigned_32;

   procedure Check (Condition : Boolean; Message : String) is
   begin
      if not Condition then
         raise Program_Error with Message;
      end if;
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

   procedure Check_MD5
     (Data     : Ada.Streams.Stream_Element_Array;
      Expected : CryptoLib.Hashes.MD5_Digest;
      Label    : String)
   is
      Actual : constant CryptoLib.Hashes.MD5_Digest := CryptoLib.Hashes.MD5 (Data);
   begin
      for Index in Actual'Range loop
         Check (Actual (Index) = Expected (Index), Label);
      end loop;
   end Check_MD5;

   procedure Check_XXH3 is
      procedure Check_64
        (Length       : Natural;
         Expected_Hex : String)
      is
         Actual   : constant CryptoLib.Hashes.XXH3_64_Digest :=
           CryptoLib.Hashes.XXH3_64 (Sequence_Data (Length));
         Expected : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_Hex (Expected_Hex);
      begin
         Check
           (Ada.Streams.Stream_Element_Array (Actual) = Expected,
            "XXH3-64 vector len" & Length'Image);
      end Check_64;

      procedure Check_128
        (Length       : Natural;
         Expected_Hex : String)
      is
         Actual   : constant CryptoLib.Hashes.XXH3_128_Digest :=
           CryptoLib.Hashes.XXH3_128 (Sequence_Data (Length));
         Expected : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_Hex (Expected_Hex);
      begin
         Check
           (Ada.Streams.Stream_Element_Array (Actual) = Expected,
            "XXH3-128 vector len" & Length'Image);
      end Check_128;
   begin
      Check_64 (0, "2d06800538d394c2");
      Check_64 (1, "4a4139caf4136257");
      Check_64 (3, "505118c313121c0e");
      Check_64 (4, "3f6889ef166b4ad1");
      Check_64 (8, "93f1200f9be82671");
      Check_64 (9, "05b2fd4d97edcdae");
      Check_64 (16, "2e4359e2a04a5e32");
      Check_64 (17, "f60c53684bbc489d");
      Check_64 (31, "a2ee08c196bd0790");
      Check_64 (32, "664864df0876efc6");
      Check_64 (64, "8e7464ffdf82c775");
      Check_64 (128, "5c6ab7b5b2360539");
      Check_64 (129, "45fabbd183de7649");
      Check_64 (240, "c0796428068cd12e");
      Check_64 (241, "859dc8ab6dd85c7c");
      Check_64 (1024, "7df7f049c0c1ad73");

      Check_128 (0, "99aa06d3014798d86001c324468d497f");
      Check_128 (1, "885f487031a569684a4139caf4136257");
      Check_128 (3, "d2f76a3b5388f28b505118c313121c0e");
      Check_128 (4, "b89f1314ee265fbdad17cf6483bb4f31");
      Check_128 (8, "acabfc73a36cbcfb2f685e863b34edb1");
      Check_128 (9, "428f8225bc32ed204d47bbb9821d4d08");
      Check_128 (16, "465d964535f22d7aaf8b52bc8abd84af");
      Check_128 (17, "e0b749d9e42a6e14261ec05370486e62");
      Check_128 (31, "a48ddde1988ba3afefcf769250ead5eb");
      Check_128 (32, "9c925523a19f36393744a5456b09b5e9");
      Check_128 (64, "ed537e7017e31effda39cd24c80e650a");
      Check_128 (128, "b0adb160b0d7e62efc7e5a4d38ed3773");
      Check_128 (129, "ca19d202aba3e00afd5fb995ce889f09");
      Check_128 (240, "60776a21568c1469e3382cc948003965");
      Check_128 (241, "8fe4da37d29ec7b9859dc8ab6dd85c7c");
      Check_128 (1024, "02e7aa13471474567df7f049c0c1ad73");
   end Check_XXH3;

   procedure Check_Adler32 is
      Empty : constant Ada.Streams.Stream_Element_Array (1 .. 0) := [others => 0];
      Hello : constant Ada.Streams.Stream_Element_Array := Bytes_From_String ("hello");
      Decimal_Data : constant Ada.Streams.Stream_Element_Array := Bytes_From_String ("123456789");
      Binary : constant Ada.Streams.Stream_Element_Array :=
        [1 => 16#00#,
         2 => 16#FF#,
         3 => 16#80#,
         4 => 16#0D#,
         5 => 16#0A#,
         6 => 16#41#,
         7 => 16#00#,
         8 => 16#7F#];
      State : CryptoLib.Checksums.Adler32_State;
   begin
      Check (CryptoLib.Checksums.Adler32 (Empty) = 16#0000_0001#, "Adler-32 empty vector");
      Check (CryptoLib.Checksums.Adler32 (Hello) = 16#062C_0215#, "Adler-32 hello vector");
      Check (CryptoLib.Checksums.Adler32 (Decimal_Data) = 16#091E_01DE#, "Adler-32 digits vector");
      Check (CryptoLib.Checksums.Adler32 (Binary) = 16#0BAC_0257#, "Adler-32 binary vector");

      CryptoLib.Checksums.Adler32_Reset (State);
      CryptoLib.Checksums.Adler32_Update (State, Binary (1 .. 2));
      CryptoLib.Checksums.Adler32_Update (State, Binary (3));
      CryptoLib.Checksums.Adler32_Update (State, Binary (4 .. 8));
      Check
        (CryptoLib.Checksums.Adler32_Value (State) = CryptoLib.Checksums.Adler32 (Binary),
         "chunked Adler-32 matches one-shot Adler-32");
   end Check_Adler32;

   procedure Check_CRC32 is
      Empty : constant Ada.Streams.Stream_Element_Array (1 .. 0) := [others => 0];
      Hello : constant Ada.Streams.Stream_Element_Array := Bytes_From_String ("hello");
      Decimal_Data : constant Ada.Streams.Stream_Element_Array := Bytes_From_String ("123456789");
      Binary : constant Ada.Streams.Stream_Element_Array :=
        [1 => 16#00#,
         2 => 16#FF#,
         3 => 16#80#,
         4 => 16#0D#,
         5 => 16#0A#,
         6 => 16#41#,
         7 => 16#00#,
         8 => 16#7F#];
      State : CryptoLib.Checksums.CRC32_State;
   begin
      Check (CryptoLib.Checksums.CRC32 (Empty) = 16#0000_0000#, "CRC-32 empty vector");
      Check (CryptoLib.Checksums.CRC32 (Hello) = 16#3610_A686#, "CRC-32 hello vector");
      Check (CryptoLib.Checksums.CRC32 (Decimal_Data) = 16#CBF4_3926#, "CRC-32 digits vector");
      Check (CryptoLib.Checksums.CRC32 (Binary) = 16#CF6B_2E0E#, "CRC-32 binary vector");

      CryptoLib.Checksums.CRC32_Reset (State);
      CryptoLib.Checksums.CRC32_Update (State, Binary (1 .. 2));
      CryptoLib.Checksums.CRC32_Update (State, Binary (3));
      CryptoLib.Checksums.CRC32_Update (State, Binary (4 .. 8));
      Check
        (CryptoLib.Checksums.CRC32_Value (State) = CryptoLib.Checksums.CRC32 (Binary),
         "chunked CRC-32 matches one-shot CRC-32");
   end Check_CRC32;

   procedure Check_Certificates is
      CA_Cert   : Ada.Strings.Unbounded.Unbounded_String;
      CA_Key    : Ada.Strings.Unbounded.Unbounded_String;
      Leaf_Cert : Ada.Strings.Unbounded.Unbounded_String;
      Leaf_Key  : Ada.Strings.Unbounded.Unbounded_String;
      CSR_Cert  : Ada.Strings.Unbounded.Unbounded_String;
      Bundle    : Ada.Strings.Unbounded.Unbounded_String;
      Client_Cert : Ada.Strings.Unbounded.Unbounded_String;
      Client_Key  : Ada.Strings.Unbounded.Unbounded_String;
      Email_Cert  : Ada.Strings.Unbounded.Unbounded_String;
      Email_Key   : Ada.Strings.Unbounded.Unbounded_String;
      Other_CA_Cert : Ada.Strings.Unbounded.Unbounded_String;
      Other_CA_Key  : Ada.Strings.Unbounded.Unbounded_String;
   begin
      Check
        (CryptoLib.Certificates.Create_Local_CA
           ("devcert-test-ca", CA_Cert, CA_Key) = CryptoLib.Certificates.Ok,
         "local CA creation succeeds");

      --  The issuer name has to come from the CA certificate, or the leaf
      --  cannot be chained to it: it was once a fixed string, so any CA not
      --  named that produced certificates no verifier would accept. Issuing
      --  without a readable CA certificate must fail rather than sign with a
      --  name of its own choosing.
      declare
         Orphan_Cert : Ada.Strings.Unbounded.Unbounded_String;
         Orphan_Key  : Ada.Strings.Unbounded.Unbounded_String;
      begin
         Check
           (CryptoLib.Certificates.Issue_Server_Certificate
              ("",
               Ada.Strings.Unbounded.To_String (CA_Key),
               "orphan.example",
               [1 => Ada.Strings.Unbounded.To_Unbounded_String
                       ("orphan.example")],
               Orphan_Cert, Orphan_Key)
            = CryptoLib.Certificates.Invalid_Input,
            "issuing without a CA certificate is refused");
         Check
           (CryptoLib.Certificates.Sign_CSR
              ("",
               Ada.Strings.Unbounded.To_String (CA_Key),
               "not a csr", Orphan_Cert)
            = CryptoLib.Certificates.Invalid_Input,
            "signing a CSR without a CA certificate is refused");
      end;

      --  Ask OpenSSL whether anybody else would accept what we issued. The CA
      --  names here are deliberately not the string the issuer field once
      --  carried: a leaf naming the wrong issuer parses perfectly and fails
      --  only when a verifier tries to build the chain.
      declare
         use type CryptoLib.Certificates.Key_Algorithm;

         procedure Check_Chain (Algorithm : CryptoLib.Certificates.Key_Algorithm)
         is
            Label   : constant String :=
              (if Algorithm = CryptoLib.Certificates.P384_Key
               then "p384" else "ed25519");
            Root    : Ada.Strings.Unbounded.Unbounded_String;
            Root_Key : Ada.Strings.Unbounded.Unbounded_String;
            Leaf    : Ada.Strings.Unbounded.Unbounded_String;
            Leaf_K  : Ada.Strings.Unbounded.Unbounded_String;
         begin
            Check
              (CryptoLib.Certificates.Create_Local_CA
                 ("cryptolib-chain-check-" & Label, Root, Root_Key, Algorithm)
               = CryptoLib.Certificates.Ok,
               Label & " chain-check CA creation succeeds");
            Check
              (CryptoLib.Certificates.Issue_Server_Certificate
                 (Ada.Strings.Unbounded.To_String (Root),
                  Ada.Strings.Unbounded.To_String (Root_Key),
                  "chain.example",
                  [1 => Ada.Strings.Unbounded.To_Unbounded_String
                          ("chain.example")],
                  Leaf, Leaf_K)
               = CryptoLib.Certificates.Ok,
               Label & " chain-check leaf issuance succeeds");
            Check
              (OpenSSL_Interop.Chain_Verifies
                 (Ada.Strings.Unbounded.To_String (Root),
                  Ada.Strings.Unbounded.To_String (Leaf)),
               Label & " issued certificate verifies against its CA in OpenSSL");
         end Check_Chain;
      begin
         Check_Chain (CryptoLib.Certificates.Ed25519_Key);
         Check_Chain (CryptoLib.Certificates.P384_Key);
      end;
      Check
        (Ada.Strings.Unbounded.Index
           (CA_Cert, "BEGIN CERTIFICATE") /= 0,
         "local CA certificate is PEM encoded");
      Check
        (Ada.Strings.Unbounded.Index
           (CA_Key, "BEGIN PRIVATE KEY") /= 0,
         "local CA private key is PKCS#8 PEM");
      Check
        (CryptoLib.Certificates.Create_Local_CA
           ("devcert-other-ca", Other_CA_Cert, Other_CA_Key)
         = CryptoLib.Certificates.Ok,
         "second local CA creation succeeds");
      Check
        (CryptoLib.Certificates.Private_Key_Matches_Certificate
           (To_String (CA_Cert), To_String (CA_Key))
         = CryptoLib.Certificates.Ok,
         "certificate/private-key match is detected");
      Check
        (CryptoLib.Certificates.Private_Key_Matches_Certificate
           (To_String (CA_Cert), To_String (Other_CA_Key))
         = CryptoLib.Certificates.Invalid_Input,
         "certificate/private-key mismatch is rejected");

      Check
        (CryptoLib.Certificates.Issue_Server_Certificate
           (To_String (CA_Cert),
            To_String (CA_Key),
            "localhost",
            [1 => To_Unbounded_String ("localhost")],
            Leaf_Cert,
            Leaf_Key) = CryptoLib.Certificates.Ok,
         "server certificate creation succeeds");
      Check
        (Ada.Strings.Unbounded.Index
           (Leaf_Cert, "BEGIN CERTIFICATE") /= 0,
         "server certificate is PEM encoded");
      Check
        (Ada.Strings.Unbounded.Index
           (Leaf_Key, "BEGIN PRIVATE KEY") /= 0,
         "server private key is PKCS#8 PEM");

      Check
        (CryptoLib.Certificates.Issue_Server_Certificate
           (To_String (CA_Cert),
            To_String (CA_Key),
            "127.0.0.1",
            [1 => To_Unbounded_String ("127.0.0.1"),
             2 => To_Unbounded_String ("::1")],
            Leaf_Cert,
            Leaf_Key) = CryptoLib.Certificates.Ok,
         "IP SAN certificate creation succeeds");

      Check
        (CryptoLib.Certificates.Issue_Client_Certificate
           (To_String (CA_Cert),
            To_String (CA_Key),
            "client",
            [1 => To_Unbounded_String ("client")],
            Client_Cert,
            Client_Key) = CryptoLib.Certificates.Ok,
         "client certificate creation succeeds");
      Check
        (Ada.Strings.Unbounded.Index
           (Client_Cert, "BEGIN CERTIFICATE") /= 0,
         "client certificate is PEM encoded");
      Check
        (Ada.Strings.Unbounded.Index
           (Client_Key, "BEGIN PRIVATE KEY") /= 0,
         "client private key is PKCS#8 PEM");

      Check
        (CryptoLib.Certificates.Issue_Email_Certificate
           (To_String (CA_Cert),
            To_String (CA_Key),
            "user@example.test",
            [1 => To_Unbounded_String ("user@example.test")],
            Email_Cert,
            Email_Key) = CryptoLib.Certificates.Ok,
         "email certificate creation succeeds");
      Check
        (Ada.Strings.Unbounded.Index
           (Email_Cert, "BEGIN CERTIFICATE") /= 0,
         "email certificate is PEM encoded");
      Check
        (Ada.Strings.Unbounded.Index
           (Email_Key, "BEGIN PRIVATE KEY") /= 0,
         "email private key is PKCS#8 PEM");

      Check
        (CryptoLib.Certificates.Sign_CSR
           (To_String (CA_Cert),
            To_String (CA_Key),
            "-----BEGIN CERTIFICATE REQUEST-----",
            CSR_Cert) = CryptoLib.Certificates.Invalid_Input,
         "malformed CSR is rejected");
      Check
        (Ada.Strings.Unbounded.Length (CSR_Cert) = 0,
         "malformed CSR does not produce a certificate");

      Check
        (CryptoLib.Certificates.Generate_PKCS12
           (To_String (Leaf_Cert),
            To_String (Leaf_Key),
            "localhost",
            "secret",
            Bundle) = CryptoLib.Certificates.Ok,
         "PKCS#12 generation succeeds");
      Check
        (Ada.Strings.Unbounded.Element (Bundle, 1) = Character'Val (16#30#),
         "PKCS#12 bundle is DER sequence");
   end Check_Certificates;

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

   procedure Check_ZIP_AES_CTR_Roundtrip is
      Key    : constant Ada.Streams.Stream_Element_Array (1 .. 16) := [others => 0];
      Plain  : constant Ada.Streams.Stream_Element_Array := Bytes_From_String ("zip aes ctr");
      Cipher : Ada.Streams.Stream_Element_Array (Plain'Range);
      Round  : Ada.Streams.Stream_Element_Array (Plain'Range);
      Status : CryptoLib.Errors.Status;
   begin
      Status := CryptoLib.Ciphers.Apply_ZIP_AES_CTR ("aes128", Key, Plain, Cipher);
      Check (Status = CryptoLib.Errors.Ok, "ZIP AES CTR encrypt status");
      Status := CryptoLib.Ciphers.Apply_ZIP_AES_CTR ("aes128", Key, Cipher, Round);
      Check (Status = CryptoLib.Errors.Ok, "ZIP AES CTR decrypt status");
      Check (Round = Plain, "ZIP AES CTR roundtrip");
   end Check_ZIP_AES_CTR_Roundtrip;

   procedure Check_RC2_40_CBC_Decrypt is
      Key    : constant Ada.Streams.Stream_Element_Array (1 .. 5) :=
        [16#01#, 16#02#, 16#03#, 16#04#, 16#05#];
      IV     : constant Ada.Streams.Stream_Element_Array (1 .. 8) :=
        [16#06#, 16#07#, 16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#];
      Cipher : constant Ada.Streams.Stream_Element_Array (1 .. 16) :=
        [16#97#, 16#A5#, 16#9C#, 16#AA#, 16#C7#, 16#08#, 16#A5#, 16#31#,
         16#5C#, 16#B9#, 16#CE#, 16#C4#, 16#99#, 16#9A#, 16#C9#, 16#BD#];
      Plain  : Ada.Streams.Stream_Element_Array (1 .. 16) := [others => 0];
      Expect : constant Ada.Streams.Stream_Element_Array (1 .. 16) :=
        [16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
         16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#];
      Status : CryptoLib.Errors.Status;
   begin
      Status := CryptoLib.Ciphers.Decrypt_CBC_Raw
        ("rc2-40-cbc", Key, IV, Cipher, Plain);
      Check (Status = CryptoLib.Errors.Ok, "RC2-40-CBC decrypt status");
      Check (Plain = Expect, "RC2-40-CBC decrypt vector");
   end Check_RC2_40_CBC_Decrypt;

   procedure Check_AES_256_CBC_Raw_Roundtrip is
      Key    : constant Ada.Streams.Stream_Element_Array (1 .. 32) :=
        [16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
         16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#,
         16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#,
         16#18#, 16#19#, 16#1A#, 16#1B#, 16#1C#, 16#1D#, 16#1E#, 16#1F#];
      IV     : constant Ada.Streams.Stream_Element_Array (1 .. 16) :=
        [16#20#, 16#21#, 16#22#, 16#23#, 16#24#, 16#25#, 16#26#, 16#27#,
         16#28#, 16#29#, 16#2A#, 16#2B#, 16#2C#, 16#2D#, 16#2E#, 16#2F#];
      Plain  : constant Ada.Streams.Stream_Element_Array (1 .. 32) :=
        [16#30#, 16#31#, 16#32#, 16#33#, 16#34#, 16#35#, 16#36#, 16#37#,
         16#38#, 16#39#, 16#3A#, 16#3B#, 16#3C#, 16#3D#, 16#3E#, 16#3F#,
         16#40#, 16#41#, 16#42#, 16#43#, 16#44#, 16#45#, 16#46#, 16#47#,
         16#48#, 16#49#, 16#4A#, 16#4B#, 16#4C#, 16#4D#, 16#4E#, 16#4F#];
      Cipher : Ada.Streams.Stream_Element_Array (Plain'Range);
      Round  : Ada.Streams.Stream_Element_Array (Plain'Range);
      Status : CryptoLib.Errors.Status;
   begin
      Status :=
        CryptoLib.Ciphers.Encrypt_CBC_Raw
          ("aes256-cbc", Key, IV, Plain, Cipher);
      Check (Status = CryptoLib.Errors.Ok, "AES-256-CBC raw encrypt status");
      Check (Cipher /= Plain, "AES-256-CBC raw changes plaintext");

      Status :=
        CryptoLib.Ciphers.Decrypt_CBC_Raw
          ("aes256-cbc", Key, IV, Cipher, Round);
      Check (Status = CryptoLib.Errors.Ok, "AES-256-CBC raw decrypt status");
      Check (Round = Plain, "AES-256-CBC raw roundtrip");
   end Check_AES_256_CBC_Raw_Roundtrip;

   procedure Check_AES_CBC_Raw_Rejects_Bad_Sizes is
      Key    : constant Ada.Streams.Stream_Element_Array (1 .. 32) :=
        [16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
         16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#,
         16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#,
         16#18#, 16#19#, 16#1A#, 16#1B#, 16#1C#, 16#1D#, 16#1E#, 16#1F#];
      IV     : constant Ada.Streams.Stream_Element_Array (1 .. 16) :=
        [16#20#, 16#21#, 16#22#, 16#23#, 16#24#, 16#25#, 16#26#, 16#27#,
         16#28#, 16#29#, 16#2A#, 16#2B#, 16#2C#, 16#2D#, 16#2E#, 16#2F#];
      Short_IV : constant Ada.Streams.Stream_Element_Array (1 .. 15) :=
        [16#20#, 16#21#, 16#22#, 16#23#, 16#24#, 16#25#, 16#26#, 16#27#,
         16#28#, 16#29#, 16#2A#, 16#2B#, 16#2C#, 16#2D#, 16#2E#];
      Cipher : constant Ada.Streams.Stream_Element_Array (1 .. 16) :=
        [16#30#, 16#31#, 16#32#, 16#33#, 16#34#, 16#35#, 16#36#, 16#37#,
         16#38#, 16#39#, 16#3A#, 16#3B#, 16#3C#, 16#3D#, 16#3E#, 16#3F#];
      Bad_Cipher : constant Ada.Streams.Stream_Element_Array (1 .. 17) :=
        [16#30#, 16#31#, 16#32#, 16#33#, 16#34#, 16#35#, 16#36#, 16#37#,
         16#38#, 16#39#, 16#3A#, 16#3B#, 16#3C#, 16#3D#, 16#3E#, 16#3F#,
         16#40#];
      Plain      : Ada.Streams.Stream_Element_Array (Cipher'Range);
      Bad_Plain  : Ada.Streams.Stream_Element_Array (Bad_Cipher'Range);
      Status     : CryptoLib.Errors.Status;
   begin
      Status :=
        CryptoLib.Ciphers.Decrypt_CBC_Raw
          ("aes256-cbc", Key, Short_IV, Cipher, Plain);
      Check
        (Status = CryptoLib.Errors.Authentication_Failed,
         "AES-CBC raw rejects short IV");
      Check (Plain = [Plain'Range => 0], "AES-CBC raw clears short-IV output");

      Status :=
        CryptoLib.Ciphers.Decrypt_CBC_Raw
          ("aes256-cbc", Key, IV, Bad_Cipher, Bad_Plain);
      Check
        (Status = CryptoLib.Errors.Authentication_Failed,
         "AES-CBC raw rejects partial block");
      Check
        (Bad_Plain = [Bad_Plain'Range => 0],
         "AES-CBC raw clears partial-block output");
   end Check_AES_CBC_Raw_Rejects_Bad_Sizes;

   --  d = 1 multiplies the base point by one, so the public point is the
   --  generator itself -- a value published in FIPS 186-4, not one this code
   --  produced. Signing was interoperable long before the public point could
   --  be derived at all, which is exactly the half that was missing.
   procedure Check_ECDSA_P384_Public_Key is
      Generator : constant Ada.Streams.Stream_Element_Array (1 .. 97) :=
        [16#04#,
         16#aa#, 16#87#, 16#ca#, 16#22#, 16#be#, 16#8b#, 16#05#, 16#37#,
         16#8e#, 16#b1#, 16#c7#, 16#1e#, 16#f3#, 16#20#, 16#ad#, 16#74#,
         16#6e#, 16#1d#, 16#3b#, 16#62#, 16#8b#, 16#a7#, 16#9b#, 16#98#,
         16#59#, 16#f7#, 16#41#, 16#e0#, 16#82#, 16#54#, 16#2a#, 16#38#,
         16#55#, 16#02#, 16#f2#, 16#5d#, 16#bf#, 16#55#, 16#29#, 16#6c#,
         16#3a#, 16#54#, 16#5e#, 16#38#, 16#72#, 16#76#, 16#0a#, 16#b7#,
         16#36#, 16#17#, 16#de#, 16#4a#, 16#96#, 16#26#, 16#2c#, 16#6f#,
         16#5d#, 16#9e#, 16#98#, 16#bf#, 16#92#, 16#92#, 16#dc#, 16#29#,
         16#f8#, 16#f4#, 16#1d#, 16#bd#, 16#28#, 16#9a#, 16#14#, 16#7c#,
         16#e9#, 16#da#, 16#31#, 16#13#, 16#b5#, 16#f0#, 16#b8#, 16#c0#,
         16#0a#, 16#60#, 16#b1#, 16#ce#, 16#1d#, 16#7e#, 16#81#, 16#9d#,
         16#7a#, 16#43#, 16#1d#, 16#7c#, 16#90#, 16#ea#, 16#0e#, 16#5f#];

      Point    : Ada.Streams.Stream_Element_Array (1 .. 97);
      Derived  : Ada.Streams.Stream_Element_Array (1 .. 97);
      Scalar   : Ada.Streams.Stream_Element_Array (1 .. 48);
      Source   : CryptoLib.Random.Random_Source;
      Status   : CryptoLib.Errors.Status;
   begin
      Status := CryptoLib.ECDSA.Public_Nistp384_Raw ([1 => 1], Point);
      Check (Status = CryptoLib.Errors.Ok, "ECDSA P-384 public key status");
      Check (Point = Generator, "ECDSA P-384 d=1 yields the generator");

      --  A scalar of zero is not in [1, n-1] and must be rejected rather than
      --  quietly yielding the point at infinity.
      Status := CryptoLib.ECDSA.Public_Nistp384_Raw ([1 => 0], Point);
      Check
        (Status /= CryptoLib.Errors.Ok,
         "ECDSA P-384 rejects a zero scalar");

      CryptoLib.Random.Initialize_Deterministic (Source, [16#5A#, 16#C3#]);
      Status :=
        CryptoLib.ECDSA.Generate_Nistp384_Keypair (Source, Scalar, Point);
      Check (Status = CryptoLib.Errors.Ok, "ECDSA P-384 keypair status");
      Check (Scalar /= [Scalar'Range => 0], "ECDSA P-384 keypair emits a scalar");

      Status := CryptoLib.ECDSA.Public_Nistp384_Raw (Scalar, Derived);
      Check (Status = CryptoLib.Errors.Ok, "ECDSA P-384 keypair scalar derives");
      Check
        (Derived = Point,
         "ECDSA P-384 keypair public point matches its own scalar");
   end Check_ECDSA_P384_Public_Key;

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

   procedure Check_Identity_Predicates is
      Cert, Key, Other_Cert, Other_Key : Ada.Strings.Unbounded.Unbounded_String;
      Status : CryptoLib.Certificates.Certificate_Status;
   begin
      Check (CryptoLib.Certificates.Valid_DNS_Name ("localhost"), "plain host");
      Check (CryptoLib.Certificates.Valid_DNS_Name ("a.b.example"), "dotted name");
      Check
        (CryptoLib.Certificates.Valid_DNS_Name ("x-1.example"),
         "a hyphen inside a label");
      Check
        (not CryptoLib.Certificates.Valid_DNS_Name ("-bad.example"),
         "a label may not begin with a hyphen");
      Check
        (not CryptoLib.Certificates.Valid_DNS_Name ("bad-.example"),
         "a label may not end with a hyphen");
      Check
        (not CryptoLib.Certificates.Valid_DNS_Name ("trailing.dot."),
         "a trailing dot is not a label");
      Check (not CryptoLib.Certificates.Valid_DNS_Name (""), "an empty name");
      Check
        (not CryptoLib.Certificates.Valid_DNS_Name ("under_score.example"),
         "an underscore is not a DNS character");

      Check
        (CryptoLib.Certificates.Valid_DNS_Name ("*.example.test"),
         "a wildcard qualifying a domain");
      Check
        (not CryptoLib.Certificates.Valid_DNS_Name ("*"),
         "a wildcard alone names everything");
      Check
        (not CryptoLib.Certificates.Valid_DNS_Name ("*.test"),
         "a wildcard needs more than a single label under it");
      Check
        (not CryptoLib.Certificates.Valid_DNS_Name ("a*b.example.test"),
         "a star inside a label is not a wildcard");

      Check (CryptoLib.Certificates.Valid_IP_Address ("127.0.0.1"), "IPv4");
      Check (CryptoLib.Certificates.Valid_IP_Address ("::1"), "IPv6");
      Check
        (not CryptoLib.Certificates.Valid_IP_Address ("256.0.0.1"),
         "an octet above 255 is not an address");
      Check
        (CryptoLib.Certificates.Valid_Email_Address ("someone@example.test"),
         "an email address");
      Check
        (not CryptoLib.Certificates.Valid_Email_Address ("no-at-sign"),
         "an address needs an at sign");

      --  Same certificate, different armour width: the text differs, the
      --  certificate does not.
      Status :=
        CryptoLib.Certificates.Create_Local_CA ("compare-ca", Cert, Key);
      Check (Status = CryptoLib.Certificates.Ok, "comparison CA");
      Status :=
        CryptoLib.Certificates.Create_Local_CA
          ("compare-other", Other_Cert, Other_Key);
      Check (Status = CryptoLib.Certificates.Ok, "second comparison CA");

      declare
         Text : constant String := Ada.Strings.Unbounded.To_String (Cert);
         --  The same bytes, armoured with different line endings.
         Rewrapped : constant String := Text & ASCII.LF & ASCII.LF;
      begin
         Check
           (CryptoLib.Certificates.Same_Certificate (Text, Rewrapped),
            "the same certificate compares equal through its armour");
         Check
           (not CryptoLib.Certificates.Same_Certificate
              (Text, Ada.Strings.Unbounded.To_String (Other_Cert)),
            "a different certificate does not");
         Check
           (not CryptoLib.Certificates.Same_Certificate
              (Text, Ada.Strings.Unbounded.To_String (Key)),
            "a private key is not that certificate");

         --  Readers put things in front of the armour: keytool -rfc names the
         --  alias and the entry type first, openssl -text prints the whole
         --  certificate. Every letter of that used to be swept into the base64,
         --  so a certificate a keystore really held compared as a different one
         --  -- and devcert refused to remove its own anchor on the strength of
         --  it.
         declare
            Preamble : constant String :=
              "Alias name: devcert-ca" & ASCII.LF
              & "Creation date: Jul 28, 2026" & ASCII.LF
              & "Entry type: trustedCertEntry" & ASCII.LF & ASCII.LF & Text;
         begin
            Check
              (CryptoLib.Certificates.Same_Certificate (Text, Preamble),
               "a certificate is itself with a reader's preamble in front");
            Check
              (CryptoLib.Certificates.Fingerprint (Preamble)
               = CryptoLib.Certificates.Fingerprint (Text),
               "and fingerprints the same either way");
            Check
              (not CryptoLib.Certificates.Same_Certificate
                 (Preamble, Ada.Strings.Unbounded.To_String (Other_Cert)),
               "while a different certificate still differs");
         end;
         Check
           (CryptoLib.Certificates.Contains_Certificate (Text),
            "a certificate is recognised by its armour");
         Check
           (not CryptoLib.Certificates.Contains_Private_Key (Text),
            "and is not mistaken for a key");
         Check
           (CryptoLib.Certificates.Contains_Private_Key
              (Ada.Strings.Unbounded.To_String (Key)),
            "a private key is recognised by its armour");
      end;
   end Check_Identity_Predicates;

   procedure Check_P384_Local_CA is
      Cert, Key : Ada.Strings.Unbounded.Unbounded_String;
      Status    : CryptoLib.Certificates.Certificate_Status;

      Secp384r1 : constant String :=
        Character'Val (16#2B#) & Character'Val (16#81#) & Character'Val (16#04#)
        & Character'Val (16#00#) & Character'Val (16#22#);
      Ecdsa_SHA384 : constant String :=
        Character'Val (16#2A#) & Character'Val (16#86#) & Character'Val (16#48#)
        & Character'Val (16#CE#) & Character'Val (16#3D#) & Character'Val (16#04#)
        & Character'Val (16#03#) & Character'Val (16#03#);

   begin
      Status :=
        CryptoLib.Certificates.Create_Local_CA
          ("cryptolib-p384-ca", Cert, Key, CryptoLib.Certificates.P384_Key);
      Check (Status = CryptoLib.Certificates.Ok, "P-384 local CA status");
      Check
        (Ada.Strings.Unbounded.Length (Cert) > 0
         and then Ada.Strings.Unbounded.Length (Key) > 0,
         "P-384 local CA emits both PEMs");

      declare
         DER : constant String :=
           Decode_PEM_Body (Ada.Strings.Unbounded.To_String (Cert));
      begin
         Check
           (Index_Of (DER, Secp384r1) > 0,
            "P-384 certificate names secp384r1");
         Check
           (Index_Of (DER, Ecdsa_SHA384) > 0,
            "P-384 certificate is signed with ecdsa-with-SHA384");
      end;

      declare
         DER : constant String :=
           Decode_PEM_Body (Ada.Strings.Unbounded.To_String (Key));
      begin
         Check
           (Index_Of (DER, Secp384r1) > 0,
            "P-384 private key names secp384r1");
      end;
   end Check_P384_Local_CA;

   --  Verification closes the loop the signer left open: signing was
   --  interoperable, but nothing here could check a signature, so an ECDSA CSR
   --  had to be refused rather than examined.
   procedure Check_ECDSA_P384_Verify is
      Message : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("cryptolib ecdsa verification");
      Other   : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("cryptolib ecdsa verificatiom");
      Scalar  : Ada.Streams.Stream_Element_Array (1 .. 48);
      Point   : Ada.Streams.Stream_Element_Array (1 .. 97);
      R       : Ada.Streams.Stream_Element_Array (1 .. 48);
      S       : Ada.Streams.Stream_Element_Array (1 .. 48);
      Source  : CryptoLib.Random.Random_Source;
      Status  : CryptoLib.Errors.Status;
   begin
      CryptoLib.Random.Initialize_Deterministic (Source, [16#11#, 16#22#]);
      Status :=
        CryptoLib.ECDSA.Generate_Nistp384_Keypair (Source, Scalar, Point);
      Check (Status = CryptoLib.Errors.Ok, "ECDSA P-384 verify keypair");

      Status := CryptoLib.ECDSA.Sign_Nistp384_Raw (Scalar, Message, R, S);
      Check (Status = CryptoLib.Errors.Ok, "ECDSA P-384 verify signing");

      Status := CryptoLib.ECDSA.Verify_Nistp384_Raw (Point, Message, R, S);
      Check (Status = CryptoLib.Errors.Ok, "ECDSA P-384 accepts its own signature");

      Status := CryptoLib.ECDSA.Verify_Nistp384_Raw (Point, Other, R, S);
      Check
        (Status /= CryptoLib.Errors.Ok,
         "ECDSA P-384 rejects a signature over another message");

      declare
         Tampered : Ada.Streams.Stream_Element_Array := R;
      begin
         Tampered (Tampered'Last) := Tampered (Tampered'Last) xor 1;
         Status :=
           CryptoLib.ECDSA.Verify_Nistp384_Raw (Point, Message, Tampered, S);
         Check
           (Status /= CryptoLib.Errors.Ok,
            "ECDSA P-384 rejects a tampered r");
      end;

      declare
         Zero_R : constant Ada.Streams.Stream_Element_Array (1 .. 48) :=
           [others => 0];
      begin
         Status :=
           CryptoLib.ECDSA.Verify_Nistp384_Raw (Point, Message, Zero_R, S);
         Check
           (Status /= CryptoLib.Errors.Ok,
            "ECDSA P-384 rejects r outside [1, n-1]");
      end;
   end Check_ECDSA_P384_Verify;

   procedure Check_ECDSA_P384_P521_Signing is
      Message : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("cryptolib ecdsa signing");
      R384    : Ada.Streams.Stream_Element_Array (1 .. 48);
      S384    : Ada.Streams.Stream_Element_Array (1 .. 48);
      R521    : Ada.Streams.Stream_Element_Array (1 .. 66);
      S521    : Ada.Streams.Stream_Element_Array (1 .. 66);
      Status  : CryptoLib.Errors.Status;
   begin
      Status :=
        CryptoLib.ECDSA.Sign_Nistp384_Raw
          ([1 => 1], Message, R384, S384);
      Check (Status = CryptoLib.Errors.Ok, "ECDSA P-384 raw signing status");
      Check (R384 /= [R384'Range => 0], "ECDSA P-384 raw signing emits r");
      Check (S384 /= [S384'Range => 0], "ECDSA P-384 raw signing emits s");

      Status :=
        CryptoLib.ECDSA.Sign_Nistp521_Raw
          ([1 => 1], Message, R521, S521);
      Check (Status = CryptoLib.Errors.Ok, "ECDSA P-521 raw signing status");
      Check (R521 /= [R521'Range => 0], "ECDSA P-521 raw signing emits r");
      Check (S521 /= [S521'Range => 0], "ECDSA P-521 raw signing emits s");
   end Check_ECDSA_P384_P521_Signing;

   --  The DER reader is the floor everything X.509 stands on, so these check
   --  the refusals as closely as the acceptances. Each malformed case is a
   --  shape that is legal BER, or nearly legal DER, and would be accepted by a
   --  reader that only looked at tags and lengths.
   procedure Check_ASN1_DER is
      use CryptoLib.ASN1;
      use type CryptoLib.ASN1.Errors.Decode_Status;

      subtype ASN1_Element is CryptoLib.ASN1.Element;

      package DER renames CryptoLib.ASN1.DER;
      package Err renames CryptoLib.ASN1.Errors;

      Limits : constant Decode_Limits := Default_Limits;

      procedure Expect
        (Data    : Ada.Streams.Stream_Element_Array;
         Wanted  : Err.Decode_Status;
         Message : String)
      is
         Pos    : Ada.Streams.Stream_Element_Offset := Data'First;
         Item   : ASN1_Element;
         Status : Err.Decode_Status;
      begin
         DER.Read (Data, Pos, Data'Last, 0, Limits, Item, Status);
         Check (Status = Wanted,
                Message & ": expected " & Err.Status_Image (Wanted)
                & ", got " & Err.Status_Image (Status));
      end Expect;
   begin
      --  A SEQUENCE holding INTEGER 5, read through and then into.
      declare
         Data : constant Ada.Streams.Stream_Element_Array :=
           [16#30#, 16#03#, 16#02#, 16#01#, 16#05#];
         Pos    : Ada.Streams.Stream_Element_Offset := Data'First;
         Seq    : ASN1_Element;
         Status : Err.Decode_Status;
         Value  : Natural;
      begin
         DER.Read_Sequence (Data, Pos, Data'Last, 0, Limits, Seq, Status);
         Check (Status = Err.Ok, "DER reads a SEQUENCE header");
         Check (Seq.Constructed, "a SEQUENCE is constructed");
         Check (Content_Length (Seq) = 3, "SEQUENCE content is three octets");
         Check (Encoded_First (Seq) = Data'First
                and then Encoded_Last (Seq) = Data'Last,
                "the encoded range covers the whole TLV, header included");
         Check (DER.At_End (Pos, Data'Last),
                "reading an element advances past it");

         Pos := Seq.First;
         DER.Read_Small_Integer
           (Data, Pos, Seq.Last, 1, Limits, Value, Status);
         Check (Status = Err.Ok and then Value = 5,
                "DER reads a nested INTEGER");
         Check (DER.At_End (Pos, Seq.Last), "the SEQUENCE is consumed");
      end;

      --  Indefinite length is BER. Refusing it is the point.
      Expect ([16#30#, 16#80#, 16#00#, 16#00#], Err.Unsupported_Encoding,
              "indefinite length is refused");

      --  Long form where the short form would do.
      Expect ([16#04#, 16#81#, 16#01#, 16#41#], Err.Non_Canonical_DER,
              "a length in long form that fits the short form is refused");
      Expect ([16#04#, 16#82#, 16#00#, 16#81#], Err.Non_Canonical_DER,
              "a length with a leading zero octet is refused");
      Expect ([16#04#, 16#FF#, 16#01#], Err.Invalid_Length,
              "the reserved length octet is refused");

      --  A length the buffer cannot satisfy.
      Expect ([16#04#, 16#05#, 16#01#, 16#02#], Err.Truncated_Input,
              "a length past the end of the buffer is refused");
      Expect ([16#04#], Err.Truncated_Input, "a header with no length is refused");

      --  High-tag-number form used for a tag that fits the identifier octet.
      Expect ([16#1F#, 16#01#, 16#00#], Err.Non_Canonical_DER,
              "a high-tag form for a low tag number is refused");
      Expect ([16#1F#, 16#80#, 16#01#, 16#00#], Err.Non_Canonical_DER,
              "a high tag padded with a leading zero group is refused");

      --  Nesting, against a deliberately shallow limit.
      declare
         Shallow : constant Decode_Limits :=
           (Maximum_Input_Size     => 1024,
            Maximum_Nesting_Depth  => 2,
            Maximum_Sequence_Items => 16,
            Maximum_String_Length  => 256);
         Data : constant Ada.Streams.Stream_Element_Array :=
           [16#30#, 16#02#, 16#05#, 16#00#];
         Pos    : Ada.Streams.Stream_Element_Offset := Data'First;
         Item   : ASN1_Element;
         Status : Err.Decode_Status;
      begin
         DER.Read (Data, Pos, Data'Last, 3, Shallow, Item, Status);
         Check (Status = Err.Excessive_Nesting,
                "a read below the depth limit is refused");
      end;

      --  A length larger than the caller will decode.
      declare
         Tight : constant Decode_Limits :=
           (Maximum_Input_Size     => 100,
            Maximum_Nesting_Depth  => 8,
            Maximum_Sequence_Items => 16,
            Maximum_String_Length  => 100);
         Data : constant Ada.Streams.Stream_Element_Array :=
           [16#04#, 16#82#, 16#01#, 16#00#];
         Pos    : Ada.Streams.Stream_Element_Offset := Data'First;
         Item   : ASN1_Element;
         Status : Err.Decode_Status;
      begin
         DER.Read (Data, Pos, Data'Last, 0, Tight, Item, Status);
         Check (Status = Err.Size_Limit_Exceeded,
                "a length beyond the caller's limit is refused");
      end;

      --  INTEGER: shortest form, and the sign rules that go with it.
      declare
         Pos      : Ada.Streams.Stream_Element_Offset;
         Item     : ASN1_Element;
         Negative : Boolean;
         Status   : Err.Decode_Status;

         Padded   : constant Ada.Streams.Stream_Element_Array :=
           [16#02#, 16#02#, 16#00#, 16#01#];
         Legal    : constant Ada.Streams.Stream_Element_Array :=
           [16#02#, 16#02#, 16#00#, 16#80#];
         Signed   : constant Ada.Streams.Stream_Element_Array :=
           [16#02#, 16#01#, 16#FF#];
         Empty    : constant Ada.Streams.Stream_Element_Array :=
           [16#02#, 16#00#];
      begin
         Pos := Padded'First;
         DER.Read_Integer
           (Padded, Pos, Padded'Last, 0, Limits, Item, Negative, Status);
         Check (Status = Err.Non_Canonical_DER,
                "an INTEGER with a redundant leading zero is refused");

         --  The same leading zero is required here: without it the value
         --  would read as negative.
         Pos := Legal'First;
         DER.Read_Integer
           (Legal, Pos, Legal'Last, 0, Limits, Item, Negative, Status);
         Check (Status = Err.Ok and then not Negative,
                "an INTEGER whose leading zero carries the sign is accepted");

         Pos := Signed'First;
         DER.Read_Integer
           (Signed, Pos, Signed'Last, 0, Limits, Item, Negative, Status);
         Check (Status = Err.Ok and then Negative,
                "a negative INTEGER is reported as negative");

         Pos := Signed'First;
         declare
            Value : Natural;
         begin
            DER.Read_Small_Integer
              (Signed, Pos, Signed'Last, 0, Limits, Value, Status);
            Check (Status = Err.Invalid_Value,
                   "a negative INTEGER is not a small non-negative one");
         end;

         Pos := Empty'First;
         DER.Read_Integer
           (Empty, Pos, Empty'Last, 0, Limits, Item, Negative, Status);
         Check (Status = Err.Invalid_Value,
                "an INTEGER with no content octets is refused");
      end;

      --  BOOLEAN: DER fixes true at all bits set.
      declare
         Pos    : Ada.Streams.Stream_Element_Offset;
         Value  : Boolean;
         Status : Err.Decode_Status;

         Yes  : constant Ada.Streams.Stream_Element_Array :=
           [16#01#, 16#01#, 16#FF#];
         No   : constant Ada.Streams.Stream_Element_Array :=
           [16#01#, 16#01#, 16#00#];
         Odd  : constant Ada.Streams.Stream_Element_Array :=
           [16#01#, 16#01#, 16#01#];
      begin
         Pos := Yes'First;
         DER.Read_Boolean (Yes, Pos, Yes'Last, 0, Limits, Value, Status);
         Check (Status = Err.Ok and then Value, "BOOLEAN 16#FF# is true");

         Pos := No'First;
         DER.Read_Boolean (No, Pos, No'Last, 0, Limits, Value, Status);
         Check (Status = Err.Ok and then not Value, "BOOLEAN 16#00# is false");

         Pos := Odd'First;
         DER.Read_Boolean (Odd, Pos, Odd'Last, 0, Limits, Value, Status);
         Check (Status = Err.Invalid_Value,
                "any other BOOLEAN octet is refused, however BER reads it");
      end;

      --  BIT STRING: the unused-bit count is consumed, not handed back as
      --  part of the value.
      declare
         Pos     : Ada.Streams.Stream_Element_Offset;
         Item    : ASN1_Element;
         Unused  : Natural;
         Status  : Err.Decode_Status;

         Key   : constant Ada.Streams.Stream_Element_Array :=
           [16#03#, 16#03#, 16#00#, 16#AB#, 16#CD#];
         Wide  : constant Ada.Streams.Stream_Element_Array :=
           [16#03#, 16#02#, 16#08#, 16#00#];
         Bare  : constant Ada.Streams.Stream_Element_Array :=
           [16#03#, 16#01#, 16#03#];
         None  : constant Ada.Streams.Stream_Element_Array :=
           [16#03#, 16#00#];
      begin
         Pos := Key'First;
         DER.Read_Bit_String
           (Key, Pos, Key'Last, 0, Limits, Item, Unused, Status);
         Check (Status = Err.Ok and then Unused = 0
                and then Content_Length (Item) = 2
                and then Key (Item.First) = 16#AB#,
                "a BIT STRING yields its value without the unused-bit octet");

         Pos := Wide'First;
         DER.Read_Bit_String
           (Wide, Pos, Wide'Last, 0, Limits, Item, Unused, Status);
         Check (Status = Err.Invalid_Value,
                "more than seven unused bits is refused");

         Pos := Bare'First;
         DER.Read_Bit_String
           (Bare, Pos, Bare'Last, 0, Limits, Item, Unused, Status);
         Check (Status = Err.Invalid_Value,
                "unused bits with no value octets is refused");

         Pos := None'First;
         DER.Read_Bit_String
           (None, Pos, None'Last, 0, Limits, Item, Unused, Status);
         Check (Status = Err.Invalid_Value,
                "a BIT STRING without its unused-bit octet is refused");
      end;

      --  NULL carries nothing.
      declare
         Pos    : Ada.Streams.Stream_Element_Offset;
         Status : Err.Decode_Status;

         Good : constant Ada.Streams.Stream_Element_Array := [16#05#, 16#00#];
         Bad  : constant Ada.Streams.Stream_Element_Array :=
           [16#05#, 16#01#, 16#00#];
      begin
         Pos := Good'First;
         DER.Read_Null (Good, Pos, Good'Last, 0, Limits, Status);
         Check (Status = Err.Ok, "an empty NULL is accepted");

         Pos := Bad'First;
         DER.Read_Null (Bad, Pos, Bad'Last, 0, Limits, Status);
         Check (Status = Err.Invalid_Value, "a NULL with content is refused");
      end;

      --  OBJECT IDENTIFIER: encoding rules, then a match against the table.
      declare
         Pos    : Ada.Streams.Stream_Element_Offset;
         Item   : ASN1_Element;
         Status : Err.Decode_Status;

         --  ecdsa-with-SHA384, as it appears in a certificate this crate
         --  issues under a P-384 CA.
         Sig : constant Ada.Streams.Stream_Element_Array :=
           [16#06#, 16#08#, 16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#04#,
            16#03#, 16#03#];
         CN  : constant Ada.Streams.Stream_Element_Array :=
           [16#06#, 16#03#, 16#55#, 16#04#, 16#03#];
         Pad : constant Ada.Streams.Stream_Element_Array :=
           [16#06#, 16#02#, 16#80#, 16#01#];
         Cut : constant Ada.Streams.Stream_Element_Array :=
           [16#06#, 16#02#, 16#55#, 16#81#];
      begin
         Pos := Sig'First;
         DER.Read_Object_Identifier
           (Sig, Pos, Sig'Last, 0, Limits, Item, Status);
         Check (Status = Err.Ok, "a well-formed OID is accepted");
         Check (CryptoLib.ASN1.OIDs.Matches
                  (Sig, Item, CryptoLib.ASN1.OIDs.ECDSA_With_SHA384),
                "the OID table recognises ecdsa-with-SHA384");
         Check (not CryptoLib.ASN1.OIDs.Matches
                  (Sig, Item, CryptoLib.ASN1.OIDs.ECDSA_With_SHA256),
                "a different signature OID does not match");

         Pos := CN'First;
         DER.Read_Object_Identifier
           (CN, Pos, CN'Last, 0, Limits, Item, Status);
         Check (Status = Err.Ok
                and then CryptoLib.ASN1.OIDs.Matches
                           (CN, Item, CryptoLib.ASN1.OIDs.Common_Name),
                "the OID table recognises id-at-commonName");
         Check (not CryptoLib.ASN1.OIDs.Matches
                  (CN, Item, CryptoLib.ASN1.OIDs.Organization),
                "a shorter arc list does not match a longer identifier");

         Pos := Pad'First;
         DER.Read_Object_Identifier
           (Pad, Pos, Pad'Last, 0, Limits, Item, Status);
         Check (Status = Err.Non_Canonical_DER,
                "an OID arc padded with a leading zero group is refused");

         Pos := Cut'First;
         DER.Read_Object_Identifier
           (Cut, Pos, Cut'Last, 0, Limits, Item, Status);
         Check (Status = Err.Invalid_Value,
                "an OID ending mid-arc is refused");
      end;

      --  A tag that is not the one required.
      declare
         Data : constant Ada.Streams.Stream_Element_Array :=
           [16#02#, 16#01#, 16#05#];
         Pos    : Ada.Streams.Stream_Element_Offset := Data'First;
         Item   : ASN1_Element;
         Status : Err.Decode_Status;
      begin
         DER.Read_Sequence (Data, Pos, Data'Last, 0, Limits, Item, Status);
         Check (Status = Err.Invalid_Tag,
                "an INTEGER read as a SEQUENCE is refused");
         Check (Pos = Data'First,
                "a refused read leaves the position where it was");
      end;
   end Check_ASN1_DER;


   --  Decoding a certificate this crate has just issued, end to end: PEM
   --  armour off, DER in, fields out. The CA is P-384 because that exercises
   --  the EC parameter path -- the curve is named beside the algorithm rather
   --  than implied by it, and getting that wrong yields a key of unknown type
   --  rather than a parse failure, which is the quieter mistake.
   procedure Check_X509_Decode is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.PEM.Decode_Status;
      use type CryptoLib.X509.Public_Key_Algorithm;
      use type CryptoLib.X509.Signature_Algorithm;

      package X509C renames CryptoLib.X509.Certificates;

      CA_PEM  : Unbounded_String;
      CA_Key  : Unbounded_String;
      Leaf    : Unbounded_String;
      Leaf_Key : Unbounded_String;
      Outcome : CryptoLib.Certificates.Certificate_Status;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          (Common_Name     => "asn1-decode-test-ca",
           Certificate_PEM => CA_PEM,
           Private_Key_PEM => CA_Key,
           Algorithm       => CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok,
             "fixture: the P-384 CA must be created");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (CA_Certificate_PEM => To_String (CA_PEM),
           CA_Private_Key_PEM => To_String (CA_Key),
           Common_Name        => "leaf.example",
           Names              =>
             [1 => To_Unbounded_String ("leaf.example")],
           Certificate_PEM    => Leaf,
           Private_Key_PEM    => Leaf_Key);
      Check (Outcome = CryptoLib.Certificates.Ok,
             "fixture: the leaf certificate must be issued");

      declare
         Text   : constant String := To_String (CA_PEM);
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Text)));
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Text'First;
         PEM_St : CryptoLib.PEM.Decode_Status;
         Parsed : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         Check (CryptoLib.PEM.Block_Count (Text, CryptoLib.PEM.Certificate_Label) = 1,
                "the CA text holds exactly one certificate block");

         CryptoLib.PEM.Decode_Block
           (Text, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, PEM_St);
         Check (PEM_St = CryptoLib.PEM.Ok,
                "the CA armour decodes: "
                & CryptoLib.PEM.Status_Image (PEM_St));

         declare
            CA : constant X509C.Certificate :=
              X509C.Decode_DER
                (Buffer (Buffer'First .. Last),
                 CryptoLib.ASN1.Default_Limits, Parsed);
         begin
            Check (Parsed = CryptoLib.ASN1.Errors.Ok,
                   "the CA certificate decodes: "
                   & CryptoLib.ASN1.Errors.Status_Image (Parsed));
            Check (X509C.Is_Present (CA), "the decoded CA is present");
            Check (X509C.Version (CA) = 3, "a CA issued here is v3");
            Check (X509C.Subject_Common_Name (CA) = "asn1-decode-test-ca",
                   "the subject common name is the one asked for, got "
                   & X509C.Subject_Common_Name (CA));
            Check (X509C.Is_Self_Issued (CA),
                   "a local CA names itself as issuer");
            Check (X509C.Public_Key_Algorithm_Of (CA)
                     = CryptoLib.X509.ECDSA_P384,
                   "the CA key is recognised as P-384");
            Check (X509C.Signature_Algorithm_Of (CA)
                     = CryptoLib.X509.ECDSA_With_SHA384,
                   "the CA signature algorithm is ecdsa-with-SHA384");
            Check (X509C.Serial_Number (CA)'Length > 0,
                   "the CA carries a serial number");
            Check (CryptoLib.X509.Is_Not_After
                     (X509C.Not_Before (CA), X509C.Not_After (CA)),
                   "the CA's validity window is not inverted");
            Check (X509C.Not_Before (CA).Year >= 2000,
                   "the notBefore year decodes into this century");

            --  basicConstraints is what makes a CA a CA, and it must be
            --  critical for anything to honour it.
            declare
               Index : constant Natural :=
                 X509C.Find_Extension
                   (CA, CryptoLib.ASN1.OIDs.Basic_Constraints);
            begin
               Check (Index > 0, "the CA carries basicConstraints");
               Check (X509C.Extension_Is_Critical (CA, Index),
                      "basicConstraints is critical on a CA");
            end;

            --  The signed bytes must be the ones that were signed: the TBS
            --  span has to sit inside the certificate and start with a
            --  SEQUENCE header.
            declare
               TBS : constant Ada.Streams.Stream_Element_Array :=
                 X509C.TBS_Bytes (CA);
               Whole : constant Ada.Streams.Stream_Element_Array :=
                 X509C.DER_Bytes (CA);
            begin
               Check (TBS'Length > 0 and then TBS'Length < Whole'Length,
                      "the signed bytes are a proper part of the certificate");
               Check (TBS (TBS'First) = 16#30#,
                      "the signed bytes begin at the TBSCertificate header");
               Check (Whole'Length = Last - Buffer'First + 1,
                      "the certificate kept the whole encoding it was given");
            end;
         end;
      end;

      --  The leaf, which must name the CA as issuer rather than itself.
      declare
         Text   : constant String := To_String (Leaf);
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Text)));
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Text'First;
         PEM_St : CryptoLib.PEM.Decode_Status;
         Parsed : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Text, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, PEM_St);
         Check (PEM_St = CryptoLib.PEM.Ok, "the leaf armour decodes");

         declare
            Cert : constant X509C.Certificate :=
              X509C.Decode_DER
                (Buffer (Buffer'First .. Last),
                 CryptoLib.ASN1.Default_Limits, Parsed);
         begin
            Check (Parsed = CryptoLib.ASN1.Errors.Ok,
                   "the leaf certificate decodes: "
                   & CryptoLib.ASN1.Errors.Status_Image (Parsed));
            Check (X509C.Subject_Common_Name (Cert) = "leaf.example",
                   "the leaf subject is the one asked for");
            Check (X509C.Issuer_Common_Name (Cert) = "asn1-decode-test-ca",
                   "the leaf names the CA as its issuer, got "
                   & X509C.Issuer_Common_Name (Cert));
            Check (not X509C.Is_Self_Issued (Cert),
                   "an issued leaf is not self-issued");
            Check (X509C.Find_Extension
                     (Cert, CryptoLib.ASN1.OIDs.Subject_Alternative_Name) > 0,
                   "the leaf carries a subject alternative name");
            Check (X509C.Extension_Count (Cert) > 0,
                   "the leaf carries extensions");
         end;
      end;

      --  PEM armour, refused where it should be.
      declare
         Buffer : Ada.Streams.Stream_Element_Array (1 .. 64);
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive;
         St     : CryptoLib.PEM.Decode_Status;

         Crossed : constant String :=
           "-----BEGIN CERTIFICATE-----" & ASCII.LF & "QUJD" & ASCII.LF
           & "-----END PRIVATE KEY-----" & ASCII.LF;
         Junk : constant String :=
           "-----BEGIN CERTIFICATE-----" & ASCII.LF & "QU!C" & ASCII.LF
           & "-----END CERTIFICATE-----" & ASCII.LF;
         Good : constant String :=
           "-----BEGIN CERTIFICATE-----" & ASCII.LF & "QUJD" & ASCII.LF
           & "-----END CERTIFICATE-----" & ASCII.LF;
         Preamble : constant String :=
           "Alias name: mykey" & ASCII.LF & "Entry type: PrivateKeyEntry"
           & ASCII.LF & Good;
      begin
         From := Crossed'First;
         CryptoLib.PEM.Decode_Block
           (Crossed, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, St);
         Check (St = CryptoLib.PEM.Malformed_Armour,
                "a block closed by a different label is refused");

         From := Junk'First;
         CryptoLib.PEM.Decode_Block
           (Junk, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, St);
         Check (St = CryptoLib.PEM.Invalid_Base64,
                "a character that is not base64 is refused, not skipped");

         From := Good'First;
         CryptoLib.PEM.Decode_Block
           (Good, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, St);
         Check (St = CryptoLib.PEM.Ok
                and then Last = Buffer'First + 2
                and then Buffer (Buffer'First) = Character'Pos ('A'),
                "a well-formed block decodes to its bytes");

         --  The preamble case that broke this once: text before the armour
         --  must not become part of the payload.
         From := Preamble'First;
         CryptoLib.PEM.Decode_Block
           (Preamble, CryptoLib.PEM.Certificate_Label, From, Buffer, Last,
            St);
         Check (St = CryptoLib.PEM.Ok
                and then Last = Buffer'First + 2
                and then Buffer (Buffer'First) = Character'Pos ('A'),
                "text before the armour is not swept into the payload");

         --  Walking a two-block chain.
         declare
            Chain : constant String := Good & Good;
         begin
            Check (CryptoLib.PEM.Block_Count
                     (Chain, CryptoLib.PEM.Certificate_Label) = 2,
                   "two blocks are counted");
            From := Chain'First;
            CryptoLib.PEM.Decode_Block
              (Chain, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, St);
            Check (St = CryptoLib.PEM.Ok, "the first block of a chain decodes");
            CryptoLib.PEM.Decode_Block
              (Chain, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, St);
            Check (St = CryptoLib.PEM.Ok,
                   "the walk reaches the second block");
            CryptoLib.PEM.Decode_Block
              (Chain, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, St);
            Check (St = CryptoLib.PEM.No_Block_Found,
                   "the walk ends after the last block");
         end;
      end;

      --  Trailing bytes after the certificate are not part of what was
      --  signed, so they must not be waved through.
      declare
         Text   : constant String := To_String (CA_PEM);
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Text)) + 1);
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Text'First;
         PEM_St : CryptoLib.PEM.Decode_Status;
         Parsed : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Text, CryptoLib.PEM.Certificate_Label, From,
            Buffer (Buffer'First .. Buffer'Last - 1), Last, PEM_St);
         Check (PEM_St = CryptoLib.PEM.Ok, "fixture: the CA decodes");
         Buffer (Last + 1) := 0;

         declare
            Cert : constant X509C.Certificate :=
              X509C.Decode_DER
                (Buffer (Buffer'First .. Last + 1),
                 CryptoLib.ASN1.Default_Limits, Parsed);
            pragma Unreferenced (Cert);
         begin
            Check (Parsed = CryptoLib.ASN1.Errors.Trailing_Data,
                   "a byte after the certificate is refused, got "
                   & CryptoLib.ASN1.Errors.Status_Image (Parsed));
         end;
      end;
   end Check_X509_Decode;


   --  Certificate signature verification, against the one implementation in
   --  the room that is not ours: the suite already links libcrypto so it can
   --  ask OpenSSL whether a chain we issued actually chains. Here the two are
   --  asked about the same certificates and must agree.
   procedure Check_X509_Verify is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.PEM.Decode_Status;
      use type CryptoLib.X509.Signatures.Verification_Result;

      package X509C renames CryptoLib.X509.Certificates;
      package X509S renames CryptoLib.X509.Signatures;

      --  Decode the first certificate in a PEM text.
      function Decoded (Text : String) return X509C.Certificate is
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Text)));
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Text'First;
         P      : CryptoLib.PEM.Decode_Status;
         D      : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Text, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, P);
         Check (P = CryptoLib.PEM.Ok, "fixture: the armour must decode");
         return X509C.Decode_DER
           (Buffer (Buffer'First .. Last), CryptoLib.ASN1.Default_Limits, D);
      end Decoded;

      procedure Check_Pair
        (Algorithm : CryptoLib.Certificates.Key_Algorithm;
         Label     : String)
      is
         CA_PEM   : Unbounded_String;
         CA_Key   : Unbounded_String;
         Leaf_PEM : Unbounded_String;
         Leaf_Key : Unbounded_String;
         Outcome  : CryptoLib.Certificates.Certificate_Status;
      begin
         Outcome :=
           CryptoLib.Certificates.Create_Local_CA
             (Common_Name     => Label & "-verify-ca",
              Certificate_PEM => CA_PEM,
              Private_Key_PEM => CA_Key,
              Algorithm       => Algorithm);
         Check (Outcome = CryptoLib.Certificates.Ok,
                "fixture: " & Label & " CA must be created");

         Outcome :=
           CryptoLib.Certificates.Issue_Server_Certificate
             (CA_Certificate_PEM => To_String (CA_PEM),
              CA_Private_Key_PEM => To_String (CA_Key),
              Common_Name        => "leaf.invalid",
              Names              => [1 => To_Unbounded_String ("leaf.invalid")],
              Certificate_PEM    => Leaf_PEM,
              Private_Key_PEM    => Leaf_Key);
         Check (Outcome = CryptoLib.Certificates.Ok,
                "fixture: " & Label & " leaf must be issued");

         declare
            CA   : constant X509C.Certificate := Decoded (To_String (CA_PEM));
            Leaf : constant X509C.Certificate :=
              Decoded (To_String (Leaf_PEM));
            Ours : constant X509S.Verification_Result :=
              X509S.Verify_Certificate_Signature (Leaf, CA);
            Theirs : constant Boolean :=
              OpenSSL_Interop.Chain_Verifies
                (CA_PEM => To_String (CA_PEM),
                 Leaf_PEM => To_String (Leaf_PEM));
         begin
            Check (X509C.Is_Present (CA) and then X509C.Is_Present (Leaf),
                   "fixture: " & Label & " certificates must decode");

            Check (Ours = X509S.Valid,
                   Label & " leaf verifies under its CA, got "
                   & X509S.Result_Image (Ours));
            Check (Theirs,
                   "fixture: OpenSSL must chain the " & Label & " pair");
            Check ((Ours = X509S.Valid) = Theirs,
                   Label & ": our verdict and OpenSSL's must agree");

            --  A CA signs itself, and that is a signature like any other.
            Check (X509S.Verify_Certificate_Signature (CA, CA) = X509S.Valid,
                   Label & " CA is signed by its own key");

            --  The leaf did not sign itself. This is the case a verifier
            --  that ignored the issuer key would get wrong.
            Check (X509S.Verify_Certificate_Signature (Leaf, Leaf)
                     = X509S.Invalid_Signature,
                   Label & " leaf is not signed by its own key, got "
                   & X509S.Result_Image
                       (X509S.Verify_Certificate_Signature (Leaf, Leaf)));
         end;
      end Check_Pair;
   begin
      Check_Pair (CryptoLib.Certificates.P384_Key, "p384");
      Check_Pair (CryptoLib.Certificates.Ed25519_Key, "ed25519");

      --  A certificate altered after signing must not verify. The bytes are
      --  changed inside the TBS, which is what the signature covers.
      declare
         CA_PEM   : Unbounded_String;
         CA_Key   : Unbounded_String;
         Leaf_PEM : Unbounded_String;
         Leaf_Key : Unbounded_String;
         Outcome  : CryptoLib.Certificates.Certificate_Status;
      begin
         Outcome :=
           CryptoLib.Certificates.Create_Local_CA
             ("tamper-ca", CA_PEM, CA_Key,
              CryptoLib.Certificates.P384_Key);
         Check (Outcome = CryptoLib.Certificates.Ok, "fixture: tamper CA");
         Outcome :=
           CryptoLib.Certificates.Issue_Server_Certificate
             (To_String (CA_PEM), To_String (CA_Key), "tamper.invalid",
              [1 => To_Unbounded_String ("tamper.invalid")],
              Leaf_PEM, Leaf_Key);
         Check (Outcome = CryptoLib.Certificates.Ok, "fixture: tamper leaf");

         declare
            Text   : constant String := To_String (Leaf_PEM);
            Buffer : Ada.Streams.Stream_Element_Array
              (1 .. Ada.Streams.Stream_Element_Offset
                      (CryptoLib.PEM.Maximum_Decoded_Length (Text)));
            Last   : Ada.Streams.Stream_Element_Offset;
            From   : Positive := Text'First;
            P      : CryptoLib.PEM.Decode_Status;
            D      : CryptoLib.ASN1.Errors.Decode_Status;
            CA     : constant X509C.Certificate := Decoded (To_String (CA_PEM));
         begin
            CryptoLib.PEM.Decode_Block
              (Text, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, P);
            Check (P = CryptoLib.PEM.Ok, "fixture: leaf armour decodes");

            declare
               Intact : constant X509C.Certificate :=
                 X509C.Decode_DER (Buffer (Buffer'First .. Last),
                                   CryptoLib.ASN1.Default_Limits, D);
               TBS    : constant Ada.Streams.Stream_Element_Array :=
                 X509C.TBS_Bytes (Intact);
               --  Where the signed bytes sit within the certificate. The TBS
               --  begins right after the outer SEQUENCE header, which is four
               --  octets for a certificate of this size.
               Target : constant Ada.Streams.Stream_Element_Offset :=
                 Buffer'First + 4 + Ada.Streams.Stream_Element_Offset
                                      (TBS'Length) - 8;
            begin
               Check (X509S.Verify_Certificate_Signature (Intact, CA)
                        = X509S.Valid,
                      "fixture: the intact leaf verifies");

               Buffer (Target) := Buffer (Target) xor 1;

               declare
                  Altered : constant X509C.Certificate :=
                    X509C.Decode_DER (Buffer (Buffer'First .. Last),
                                      CryptoLib.ASN1.Default_Limits, D);
               begin
                  --  Flipping a bit inside the TBS may or may not still parse.
                  --  If it does, the signature must fail; if it does not, the
                  --  decode must have said so.
                  --  Asserted rather than guarded: if the flip stops
                  --  landing inside the TBS this must fail loudly, not skip
                  --  the check it exists for.
                  Check (D = CryptoLib.ASN1.Errors.Ok,
                         "the altered certificate still parses, so the "
                         & "signature is what has to reject it");
                  Check (X509S.Verify_Certificate_Signature (Altered, CA)
                           /= X509S.Valid,
                         "an altered certificate must not verify");
               end;
            end;
         end;
      end;

      --  Asking about an algorithm this crate cannot verify must say so
      --  rather than report a bad signature. Today that is every RSA
      --  certificate and ECDSA on P-256 and P-521.
      Check (X509S.Is_Supported (CryptoLib.X509.SHA256_With_RSA)
             and then X509S.Is_Supported (CryptoLib.X509.SHA384_With_RSA)
             and then X509S.Is_Supported (CryptoLib.X509.SHA512_With_RSA),
             "the RSA signature algorithms are verifiable");
      Check (X509S.Is_Supported (CryptoLib.X509.ECDSA_With_SHA256)
             and then X509S.Is_Supported (CryptoLib.X509.ECDSA_With_SHA384)
             and then X509S.Is_Supported (CryptoLib.X509.ECDSA_With_SHA512),
             "every ECDSA digest is verifiable");
      Check (X509S.Is_Supported (CryptoLib.X509.RSASSA_PSS),
             "RSA-PSS is claimed now that its parameters can be read");
      Check (X509S.Is_Supported (CryptoLib.X509.ECDSA_With_SHA384),
             "ECDSA P-384 is supported");
      Check (X509S.Is_Supported (CryptoLib.X509.Ed25519_Signature),
             "Ed25519 is supported");
   end Check_X509_Verify;


   --  The extensions that decide what a certificate is for. Every expected
   --  value here was read off "openssl x509 -text" for the same certificate
   --  before being written down.
   procedure Check_X509_Extensions is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.PEM.Decode_Status;
      use type CryptoLib.X509.Extensions.General_Name_Kind;

      package X509C renames CryptoLib.X509.Certificates;
      package XE renames CryptoLib.X509.Extensions;

      function Decoded (Text : String) return X509C.Certificate is
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Text)));
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Text'First;
         P      : CryptoLib.PEM.Decode_Status;
         D      : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Text, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, P);
         Check (P = CryptoLib.PEM.Ok, "fixture: armour decodes");
         return X509C.Decode_DER
           (Buffer (Buffer'First .. Last), CryptoLib.ASN1.Default_Limits, D);
      end Decoded;

      CA_PEM   : Unbounded_String;
      CA_Key   : Unbounded_String;
      Leaf_PEM : Unbounded_String;
      Leaf_Key : Unbounded_String;
      Outcome  : CryptoLib.Certificates.Certificate_Status;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("extensions-ca", CA_PEM, CA_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "host.example",
           [1 => To_Unbounded_String ("host.example"),
            2 => To_Unbounded_String ("alt.example"),
            3 => To_Unbounded_String ("127.0.0.1")],
           Leaf_PEM, Leaf_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: leaf issued");

      declare
         CA : constant X509C.Certificate := Decoded (To_String (CA_PEM));
         BC : constant XE.Basic_Constraints := XE.Get_Basic_Constraints (CA);
         KU : constant XE.Key_Usage := XE.Get_Key_Usage (CA);
         EK : constant XE.Extended_Key_Usage := XE.Get_Extended_Key_Usage (CA);
      begin
         Check (BC.Present and then BC.Well_Formed and then BC.Is_CA,
                "the CA's basic constraints say CA:TRUE");
         Check (not BC.Has_Path_Length,
                "the CA states no path length constraint");
         Check (KU.Present and then KU.Well_Formed,
                "the CA carries a well-formed key usage");
         Check (KU.Certificate_Sign and then KU.CRL_Sign,
                "the CA may sign certificates and CRLs");
         Check (not KU.Digital_Signature,
                "the CA's key usage is only what it needs");

         --  Absent is not the same as empty, and the type says which.
         Check (not EK.Present,
                "the CA has no extended key usage, which is not an empty one");
         Check (not XE.Has_Unsupported_Critical_Extension (CA),
                "every critical extension on the CA is one we understand");
      end;

      declare
         Leaf : constant X509C.Certificate := Decoded (To_String (Leaf_PEM));
         BC   : constant XE.Basic_Constraints :=
           XE.Get_Basic_Constraints (Leaf);
         KU   : constant XE.Key_Usage := XE.Get_Key_Usage (Leaf);
         EK   : constant XE.Extended_Key_Usage :=
           XE.Get_Extended_Key_Usage (Leaf);
      begin
         Check (BC.Present and then not BC.Is_CA,
                "the leaf's basic constraints say CA:FALSE");
         Check (KU.Present and then KU.Digital_Signature
                and then not KU.Certificate_Sign,
                "the leaf may sign but may not issue certificates");
         Check (EK.Present and then EK.Well_Formed and then EK.Server_Auth,
                "the leaf is issued for TLS server authentication");
         Check (not EK.Client_Auth,
                "a server certificate is not also a client one");
         Check (not EK.Any_Purpose and then not EK.Has_Unrecognised,
                "the leaf's purposes are exactly the ones recognised");

         --  Subject alternative names, in the order they were asked for.
         Check (XE.Subject_Alternative_Name_Count (Leaf) = 3,
                "the leaf carries three alternative names");
         Check (XE.Subject_Alternative_Name_Kind (Leaf, 1) = XE.DNS_Name
                and then XE.Subject_Alternative_Name_Text (Leaf, 1)
                           = "host.example",
                "the first alternative name is the DNS name asked for");
         Check (XE.Subject_Alternative_Name_Kind (Leaf, 2) = XE.DNS_Name
                and then XE.Subject_Alternative_Name_Text (Leaf, 2)
                           = "alt.example",
                "the second alternative name is the other DNS name");

         --  An address is bytes. Rendering it would invite comparing
         --  addresses as text, where 10.0.0.1 and 10.000.000.001 differ and
         --  the addresses do not.
         Check (XE.Subject_Alternative_Name_Kind (Leaf, 3) = XE.IP_Address,
                "the third alternative name is an address");
         Check (XE.Subject_Alternative_Name_Text (Leaf, 3) = "",
                "an address is not offered as text");
         declare
            Address : constant Ada.Streams.Stream_Element_Array :=
              XE.Subject_Alternative_Name_Bytes (Leaf, 3);
         begin
            Check (Address'Length = 4,
                   "an IPv4 address is four octets");
            Check (Address (Address'First) = 127
                   and then Address (Address'First + 1) = 0
                   and then Address (Address'First + 2) = 0
                   and then Address (Address'First + 3) = 1,
                   "the address octets are 127.0.0.1");
         end;

         Check (not XE.Has_Unsupported_Critical_Extension (Leaf),
                "every critical extension on the leaf is one we understand");

         --  Asking past the end must not invent a name.
         Check (XE.Subject_Alternative_Name_Text (Leaf, 9) = "",
                "a name past the end is empty");
         Check (XE.Subject_Alternative_Name_Bytes (Leaf, 9)'Length = 0,
                "a name past the end has no octets");
      end;
   end Check_X509_Extensions;


   --  RSA PKCS#1 v1.5 verification, against signatures OpenSSL produced and
   --  against a forgery it would take a careless verifier to accept.
   procedure Check_RSA_Verify is

   RSA_KAT_Modulus : constant String :=
     "eda66e8e74fd6e04e99282f52f13153b856a59cf6be7b5bddd5473b54eacac4c43e60b2d5bd98e0aa8559439fe" &
     "a7d24389e4cb59a782909127d5661b4ceca2b51ee802688ad9bbaf77871706c55ec8b09343768f6eb6240db647" &
     "4e6dcf4f639559455b94010ed58244a5eccc9066ef4daaac62cbcf3af938a20e8da458a18e8d78edf75ff4d65f" &
     "3eb3bade68f4a0e80848ac60edec51199ecb3490b662e04e692dac129919af92e83bd88f658bd7e48c610845ae" &
     "d7c86b68827de33e31be15cc13ccdda683c64d015919d47da0e552860295101086c547e2a6aaeaba65d844ddaf" &
     "5658dc61b0a97187fb0fa2b1a7176d1028f70739d67a5ae9ae410c4b60befb";

   RSA_KAT_Signature : constant String :=
     "530c2f01750f7144cebf71adc28e85fd4a260df4ae04010cd02a6564ed6fe91ba0b079ecb8d71338d74de969a3" &
     "2a8e24a8d5136f091aef96928e1c1e1305b0bee914287828841735c370700a634dbab47a879b3c83e8006e699d" &
     "66d392739dd74d2bad567215dfae6b3ba4b9abd1590b3be5f55de3296e52a1895beffa7f98a8a06f2164ca2d0c" &
     "35a85635c5c01636431a8207815f1389bf99980f55c3941c26af9bd3a8bf50c7cd0612bdd897f7fefd4ad97db9" &
     "a1209301672004aad1533160cb4ce7c16af6bf721b6d3defe03d874a872a3da330eec797786b3f156565391bd6" &
     "f3ed70db44b77a171527c94ef57ce79a3ec518e9c78e4bcfe69293dfe30225";

   RSA_E3_Modulus : constant String :=
     "c7622357e8a021f789d17baaf52775a78c959252e3692adce05c4461c90892b7f59b95d2a074ce2d3d89c6dbe4" &
     "9abe665cb0349b2f6d44b51366cf770902e5638c254b9425ebd5d6b4d8683274f7f883a77f271084ae75fe9c5c" &
     "bbe4564df5eca7fc6b4bd3920eeaef9c42d4fe8169856df20532a98a0040638c4a9915e7f23cf75f69c6b061df" &
     "679b707b7610db8000ebf84dd94efe2e1ebc5b199cf7a6d900bb5c858bb68c93be728b76477c1108de6d252a65" &
     "ed71e99294bbe6f5b8feb423b2b8a80abad46a71ae8eddfa51ade3335fac5dedecb551928750dd77c2e10be73e" &
     "1fea9e8683eab0a5c67fb02826dc4cd10f6ff507fc4320ecbedf835b0f6937";

   RSA_E3_Forged_Signature : constant String :=
     "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" &
     "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" &
     "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" &
     "00000000000000000000000000000000000000000000000000000000000000000000000032cbfd4a7adc790558" &
     "3d767520f51640759176d37826f2ef63ae3dc7ac54f8f7785a2f2b27eb80ed15f3e4067a188e0274f45efeecbd" &
     "de6b69cddc76507c062d672d288ee2769c329c82aa34096594dd9184bdf260";

      Message : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("cryptolib rsa pkcs1 v1.5 known answer");

      Exponent_65537 : constant Ada.Streams.Stream_Element_Array :=
        [16#01#, 16#00#, 16#01#];
      Exponent_3 : constant Ada.Streams.Stream_Element_Array := [16#03#];

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

      Modulus   : constant Ada.Streams.Stream_Element_Array :=
        From_Hex (RSA_KAT_Modulus);
      Signature : constant Ada.Streams.Stream_Element_Array :=
        From_Hex (RSA_KAT_Signature);
   begin
      Check (CryptoLib.RSA.Modulus_Bits (Modulus) = 2048,
             "the known-answer modulus is 2048 bits");

      Check (CryptoLib.RSA.Verify_PKCS1_V1_5
               (Modulus, Exponent_65537, CryptoLib.RSA.SHA256,
                Message, Signature) = CryptoLib.Errors.Ok,
             "an OpenSSL SHA-256 signature verifies");

      --  Wrong message, right signature.
      Check (CryptoLib.RSA.Verify_PKCS1_V1_5
               (Modulus, Exponent_65537, CryptoLib.RSA.SHA256,
                Bytes_From_String ("cryptolib rsa pkcs1 v1.5 known answe"),
                Signature) = CryptoLib.Errors.Authentication_Failed,
             "the signature does not verify over a different message");

      --  Right message, right key, wrong digest algorithm. The DigestInfo
      --  names the hash, so this must fail rather than quietly succeed.
      Check (CryptoLib.RSA.Verify_PKCS1_V1_5
               (Modulus, Exponent_65537, CryptoLib.RSA.SHA384,
                Message, Signature) = CryptoLib.Errors.Authentication_Failed,
             "a SHA-256 signature does not verify as SHA-384");

      declare
         Tampered : Ada.Streams.Stream_Element_Array := Signature;
      begin
         Tampered (Tampered'Last) := Tampered (Tampered'Last) xor 1;
         Check (CryptoLib.RSA.Verify_PKCS1_V1_5
                  (Modulus, Exponent_65537, CryptoLib.RSA.SHA256,
                   Message, Tampered) = CryptoLib.Errors.Authentication_Failed,
                "a signature with a bit flipped does not verify");
      end;

      --  Arguments that cannot be used are told apart from signatures that
      --  do not verify. A caller retrying with a different key needs to know
      --  which it got.
      Check (CryptoLib.RSA.Verify_PKCS1_V1_5
               (Modulus, Exponent_65537, CryptoLib.RSA.SHA256,
                Message, Signature (Signature'First .. Signature'Last - 1))
               = CryptoLib.Errors.Handshake_Failed,
             "a signature shorter than the modulus is refused, not failed");

      declare
         Even : Ada.Streams.Stream_Element_Array := Modulus;
      begin
         Even (Even'Last) := Even (Even'Last) and 16#FE#;
         Check (CryptoLib.RSA.Verify_PKCS1_V1_5
                  (Even, Exponent_65537, CryptoLib.RSA.SHA256,
                   Message, Signature) = CryptoLib.Errors.Handshake_Failed,
                "an even modulus is refused rather than exponentiated");
      end;

      --  The forgery this package's shape exists to refuse.
      --
      --  Against a low public exponent, a cube root can be found whose cube
      --  begins 16#00# 16#01# 16#FF#..16#FF# 16#00# followed by a correct
      --  DigestInfo for the message, with arbitrary bytes after it. A
      --  verifier that scans for the separator and parses what follows
      --  accepts it as a valid signature without the private key. Comparing
      --  against a fully determined expected block cannot: the garbage tail
      --  has nowhere to hide.
      declare
         E3_Modulus : constant Ada.Streams.Stream_Element_Array :=
           From_Hex (RSA_E3_Modulus);
         Forged     : constant Ada.Streams.Stream_Element_Array :=
           From_Hex (RSA_E3_Forged_Signature);
      begin
         Check (CryptoLib.RSA.Verify_PKCS1_V1_5
                  (E3_Modulus, Exponent_3, CryptoLib.RSA.SHA256,
                   Message, Forged) = CryptoLib.Errors.Authentication_Failed,
                "a cube-root forgery with a well-formed prefix is refused");
      end;
   end Check_RSA_Verify;


   --  ECDSA verification across curves and digests.
   --
   --  Two of these three vectors deliberately pair a curve with a digest that
   --  is not "its own": P-521 with SHA-256 and P-384 with SHA-512. Both are
   --  ordinary and legal -- an ECDSA algorithm identifier names only the hash
   --  -- and a verifier that inferred the curve from the algorithm would
   --  refuse them. It is the mistake this code made before these were added.
   procedure Check_ECDSA_Curves is

      EC_P256_Point : constant String :=
        "04ab77f04240ffa7388eef4c158f929ab1748039e79a7720358a3e4780da54162f97382f07d105790ec7fc1128" &
        "605139bbb33bc7f58df3c20313b08aadee338626";
      EC_P256_R : constant String :=
        "ad11b676041c86ccac693504ae97a463e3db02b78624cce40b22ff94859c039a";
      EC_P256_S : constant String :=
        "c27b52a3125e0f682180e8fd134366db7c4560b698dcfc5132dbeee2a9fbaa92";

      EC_P521_Point : constant String :=
        "0401f9b325a0943c5f0b687878f1bd99d81690bfb084695decad2eefd788717cb0bba1d0e8acea11fbaa6ce9f1" &
        "0ce41c06afda95cd3eec755606ae55928071a49bce99004cfdbeee17dc63a974e917146e6b9a60d0eb97bbe1dc" &
        "e43bd42c9ea6beb3f3e9b619e28ff17bdee3d6f101e312bab1424ba49fc7f793177724bad175afe65a4572";
      EC_P521_R : constant String :=
        "014656dd265508026a55e10a7996d5b60da758210a10a8673f2c832a682e4c3b4b7fb3c78d338e84f600654809" &
        "fd365b5ced3a57227d974b4bc439943a142185a2f7";
      EC_P521_S : constant String :=
        "00743ee773b2d115f9ddb577c034068a367377b9619f4cb71465118632faa1798176303db6df30abda83fb13d7" &
        "b31b43dd6f1303585d6ca9cb6910ef590eb78626f4";

      EC_P384_Point : constant String :=
        "04da8a61701c3aeeb1633e25606310587c169425652ebfea93ea3aa44706100a4047baf288d16b076485cb1c96" &
        "a28d75dd0e6ec2a77a03030402f7d66ee7b126654055ed7389ecbbd050994f41aaa80f9cfdfa873db916c78c38" &
        "df92e02a89404a";
      EC_P384_R : constant String :=
        "2fbdf38aeb6858b4c274830048b5dfd9bfaf39f9e6d4ef4aca8dacf8f54aa0d57309663df01bd4f2fd81610d6f" &
        "6901f2";
      EC_P384_S : constant String :=
        "99f0af5ad1ad517278c89ec6be67b850d1a349e88e47d794394ec49f898c92f1a9398040f1c220d8256cfe5df0" &
        "de83e3";


      Message : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("cryptolib ecdsa known answer");

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

      procedure Check_Vector
        (Curve   : CryptoLib.ECDSA.Curve_Id;
         Digest  : CryptoLib.ECDSA.Digest_Id;
         Point   : String;
         R_Hex   : String;
         S_Hex   : String;
         Label   : String)
      is
         P : constant Ada.Streams.Stream_Element_Array := From_Hex (Point);
         R : constant Ada.Streams.Stream_Element_Array := From_Hex (R_Hex);
         S : constant Ada.Streams.Stream_Element_Array := From_Hex (S_Hex);
      begin
         Check (CryptoLib.ECDSA.Verify_Signature
                  (Curve, Digest, P, Message, R, S) = CryptoLib.Errors.Ok,
                Label & ": an OpenSSL signature verifies");

         declare
            Bad : Ada.Streams.Stream_Element_Array := S;
         begin
            Bad (Bad'Last) := Bad (Bad'Last) xor 1;
            Check (CryptoLib.ECDSA.Verify_Signature
                     (Curve, Digest, P, Message, R, Bad)
                     = CryptoLib.Errors.Authentication_Failed,
                   Label & ": a tampered s does not verify");
         end;

         Check (CryptoLib.ECDSA.Verify_Signature
                  (Curve, Digest, P,
                   Bytes_From_String ("cryptolib ecdsa known answe"), R, S)
                  = CryptoLib.Errors.Authentication_Failed,
                Label & ": the signature does not cover a different message");
      end Check_Vector;
   begin
      Check_Vector (CryptoLib.ECDSA.Nistp256, CryptoLib.ECDSA.SHA256,
                    EC_P256_Point, EC_P256_R, EC_P256_S, "P-256 with SHA-256");

      --  The pairings that matter: curve and digest chosen independently.
      Check_Vector (CryptoLib.ECDSA.Nistp521, CryptoLib.ECDSA.SHA256,
                    EC_P521_Point, EC_P521_R, EC_P521_S, "P-521 with SHA-256");
      Check_Vector (CryptoLib.ECDSA.Nistp384, CryptoLib.ECDSA.SHA512,
                    EC_P384_Point, EC_P384_R, EC_P384_S, "P-384 with SHA-512");

      --  Verifying under the wrong curve must fail rather than be refused for
      --  its length: the point is the right shape for P-256 and wrong for the
      --  curve it is checked on.
      declare
         P : constant Ada.Streams.Stream_Element_Array :=
           From_Hex (EC_P256_Point);
         R : constant Ada.Streams.Stream_Element_Array := From_Hex (EC_P256_R);
         S : constant Ada.Streams.Stream_Element_Array := From_Hex (EC_P256_S);
      begin
         Check (CryptoLib.ECDSA.Verify_Signature
                  (CryptoLib.ECDSA.Nistp384, CryptoLib.ECDSA.SHA256,
                   P, Message, R, S) /= CryptoLib.Errors.Ok,
                "a P-256 point does not verify as a P-384 one");
      end;
   end Check_ECDSA_Curves;


   --  Path validation over chains this crate issues.
   --
   --  The negative cases are the point. A validator that accepts a good chain
   --  proves very little; one that says precisely why a bad chain is bad, and
   --  refuses to be talked out of it, proves rather more.
   procedure Check_X509_Validation is
      use type CryptoLib.PEM.Decode_Status;
      use type CryptoLib.X509.Validation.Validation_Failure;

      package X509C renames CryptoLib.X509.Certificates;
      package XV renames CryptoLib.X509.Validation;

      CA_PEM    : Unbounded_String;
      CA_Key    : Unbounded_String;
      Leaf_PEM  : Unbounded_String;
      Leaf_Key  : Unbounded_String;
      Other_PEM : Unbounded_String;
      Other_Key : Unbounded_String;
      Twin_PEM  : Unbounded_String;
      Twin_Key  : Unbounded_String;
      Outcome   : CryptoLib.Certificates.Certificate_Status;

      function Decoded (Text : String) return X509C.Certificate is
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Text)));
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Text'First;
         P      : CryptoLib.PEM.Decode_Status;
         D      : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Text, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, P);
         Check (P = CryptoLib.PEM.Ok, "fixture: armour decodes");
         return X509C.Decode_DER
           (Buffer (Buffer'First .. Last), CryptoLib.ASN1.Default_Limits, D);
      end Decoded;

      --  What the caller has to write: two certificates by position, and a
      --  rule for what it trusts. Declared inside a procedure, which is where
      --  a caller would really write it.
      type Chain_Kind is (Issued, Wrong_CA, Twin_CA, Looping, Leaf_Alone);

      type Test_Path (Kind : Chain_Kind; Trust_CN_Length : Natural) is
        new XV.Path_Source with record
         Trust_CN : String (1 .. Trust_CN_Length);
      end record;

      overriding function Length (Source : Test_Path) return Positive
      is (if Source.Kind = Leaf_Alone then 1 else 2);

      overriding function Certificate_At
        (Source : Test_Path; Index : Positive) return X509C.Certificate
      is (case Source.Kind is
             when Leaf_Alone => Decoded (To_String (Leaf_PEM)),
             when Looping    => Decoded (To_String (Leaf_PEM)),
             when Wrong_CA   =>
               (if Index = 1 then Decoded (To_String (Leaf_PEM))
                else Decoded (To_String (Other_PEM))),
             when Twin_CA    =>
               (if Index = 1 then Decoded (To_String (Leaf_PEM))
                else Decoded (To_String (Twin_PEM))),
             when Issued     =>
               (if Index = 1 then Decoded (To_String (Leaf_PEM))
                else Decoded (To_String (CA_PEM))));

      overriding function Is_Trust_Anchor
        (Source : Test_Path; Item : X509C.Certificate) return Boolean
      is (Source.Trust_CN'Length > 0
          and then X509C.Subject_Common_Name (Item) = Source.Trust_CN);

      Now_Time : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2027, Month => 6, Day => 1,
         Hour => 12, Minute => 0, Second => 0);

      Result : XV.Validation_Result;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("validation-ca", CA_PEM, CA_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "host.example",
           [1 => To_Unbounded_String ("host.example")],
           Leaf_PEM, Leaf_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: leaf issued");

      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("unrelated-ca", Other_PEM, Other_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: other CA created");

      --  A second CA with the same name as the first. Its subject encodes
      --  identically, so the leaf's issuer name matches it exactly -- and its
      --  key does not. This is the only case that reaches the signature check
      --  with everything else in order, which is what makes it the one that
      --  proves the signature is checked at all.
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("validation-ca", Twin_PEM, Twin_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: twin CA created");

      --  The chain as issued, judged at a time inside its window.
      declare
         Path : constant Test_Path :=
           (Kind => Issued, Trust_CN_Length => 13,
            Trust_CN => "validation-ca");
      begin
         Result := XV.Validate_Path (Path, Now_Time);
         Check (Result.Valid and then Result.Failure = XV.None,
                "a chain issued here validates against its own CA, got "
                & XV.Failure_Image (Result.Failure));

         --  Before it was issued, and long after it expires.
         Result :=
           XV.Validate_Path
             (Path, (Year => 2000, Month => 1, Day => 1,
                     Hour => 0, Minute => 0, Second => 0));
         Check (not Result.Valid
                and then Result.Failure = XV.Certificate_Not_Yet_Valid,
                "a chain judged before its validity begins is refused, got "
                & XV.Failure_Image (Result.Failure));

         Result :=
           XV.Validate_Path
             (Path, (Year => 2099, Month => 1, Day => 1,
                     Hour => 0, Minute => 0, Second => 0));
         Check (not Result.Valid
                and then Result.Failure = XV.Certificate_Expired,
                "an expired chain is refused, got "
                & XV.Failure_Image (Result.Failure));

         --  Policy is the caller's: a path longer than it allows is refused
         --  before anything is verified.
         Result :=
           XV.Validate_Path
             (Path, Now_Time,
              (Maximum_Path_Length       => 1,
               Require_Basic_Constraints => True,
               Require_Key_Cert_Sign     => True,
               Reject_Unknown_Critical   => True));
         Check (not Result.Valid and then Result.Failure = XV.Path_Too_Long,
                "a path longer than policy allows is refused, got "
                & XV.Failure_Image (Result.Failure));
      end;

      --  The same chain with nothing trusted. Well formed is not trusted, and
      --  the two failures must not look alike.
      declare
         Path : constant Test_Path :=
           (Kind => Issued, Trust_CN_Length => 0, Trust_CN => "");
      begin
         Result := XV.Validate_Path (Path, Now_Time);
         Check (not Result.Valid and then Result.Failure = XV.No_Trust_Anchor,
                "a correct chain ending outside the trust set is untrusted, "
                & "not invalid, got " & XV.Failure_Image (Result.Failure));
      end;

      --  A CA that did not issue this leaf: the names do not line up, which
      --  is caught before any signature is checked.
      declare
         Path : constant Test_Path :=
           (Kind => Wrong_CA, Trust_CN_Length => 12,
            Trust_CN => "unrelated-ca");
      begin
         Result := XV.Validate_Path (Path, Now_Time);
         Check (not Result.Valid and then Result.Failure = XV.Issuer_Mismatch,
                "a chain to the wrong CA fails on the names, got "
                & XV.Failure_Image (Result.Failure));
      end;

      --  A CA whose name matches but whose key did not sign this leaf.
      declare
         Path : constant Test_Path :=
           (Kind => Twin_CA, Trust_CN_Length => 13,
            Trust_CN => "validation-ca");
         Leaf : constant X509C.Certificate := Decoded (To_String (Leaf_PEM));
         Twin : constant X509C.Certificate := Decoded (To_String (Twin_PEM));
      begin
         --  The premise: the names really do line up, so nothing earlier in
         --  the walk can reject this path.
         Check (X509C.Issuer_Bytes (Leaf) = X509C.Subject_Bytes (Twin),
                "fixture: the twin CA's subject matches the leaf's issuer");

         Result := XV.Validate_Path (Path, Now_Time);
         Check (not Result.Valid
                and then Result.Failure = XV.Invalid_Signature,
                "a CA with the right name and the wrong key is refused on "
                & "the signature, got " & XV.Failure_Image (Result.Failure));
         Check (Result.Index = 1,
                "the failure is reported against the certificate that does "
                & "not verify");
      end;

      --  The leaf twice: a loop, which is a property of the path rather than
      --  of any link within it.
      declare
         Path : constant Test_Path :=
           (Kind => Looping, Trust_CN_Length => 12,
            Trust_CN => "host.example");
      begin
         Result := XV.Validate_Path (Path, Now_Time);
         Check (not Result.Valid
                and then Result.Failure = XV.Duplicate_Certificate,
                "a path containing the same certificate twice is refused, got "
                & XV.Failure_Image (Result.Failure));
      end;

      --  One certificate the caller trusts is a path: there is no link to
      --  check and the caller has said it trusts it. Untrusted, the same
      --  certificate is not a path at all.
      declare
         Trusted : constant Test_Path :=
           (Kind => Leaf_Alone, Trust_CN_Length => 12,
            Trust_CN => "host.example");
         Untrusted : constant Test_Path :=
           (Kind => Leaf_Alone, Trust_CN_Length => 0, Trust_CN => "");
      begin
         Result := XV.Validate_Path (Trusted, Now_Time);
         Check (Result.Valid,
                "a path of one trusted certificate is valid, got "
                & XV.Failure_Image (Result.Failure));

         Result := XV.Validate_Path (Untrusted, Now_Time);
         Check (not Result.Valid
                and then Result.Failure = XV.No_Trust_Anchor,
                "the same certificate untrusted is not a path");
      end;
   end Check_X509_Validation;


   --  Service identity matching. The interesting cases are all the ones that
   --  must NOT match: a wildcard reaching too far is how a certificate for
   --  one name gets used for another.
   procedure Check_X509_Identity is
      use type CryptoLib.PEM.Decode_Status;
      use type CryptoLib.X509.Identity.Match_Result;

      package X509C renames CryptoLib.X509.Certificates;
      package XI renames CryptoLib.X509.Identity;

      CA_PEM   : Unbounded_String;
      CA_Key   : Unbounded_String;
      Outcome  : CryptoLib.Certificates.Certificate_Status;

      function Decoded (Text : String) return X509C.Certificate is
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Text)));
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Text'First;
         P      : CryptoLib.PEM.Decode_Status;
         D      : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Text, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, P);
         Check (P = CryptoLib.PEM.Ok, "fixture: armour decodes");
         return X509C.Decode_DER
           (Buffer (Buffer'First .. Last), CryptoLib.ASN1.Default_Limits, D);
      end Decoded;

      --  Issue a leaf carrying the given names and hand it back decoded.
      function Leaf_With
        (Names : CryptoLib.Certificates.Subject_Alternative_Name_List)
         return X509C.Certificate
      is
         Leaf_PEM : Unbounded_String;
         Leaf_Key : Unbounded_String;
         St       : CryptoLib.Certificates.Certificate_Status;
      begin
         St :=
           CryptoLib.Certificates.Issue_Server_Certificate
             (To_String (CA_PEM), To_String (CA_Key),
              To_String (Names (Names'First)), Names, Leaf_PEM, Leaf_Key);
         Check (St = CryptoLib.Certificates.Ok, "fixture: leaf issued");
         return Decoded (To_String (Leaf_PEM));
      end Leaf_With;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("identity-ca", CA_PEM, CA_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      declare
         Exact : constant X509C.Certificate :=
           Leaf_With ([1 => To_Unbounded_String ("host.example.com")]);
      begin
         Check (XI.Match_DNS_Name (Exact, "host.example.com") = XI.Matched,
                "an exact name matches");
         Check (XI.Match_DNS_Name (Exact, "HOST.Example.COM") = XI.Matched,
                "the comparison is case-insensitive");
         Check (XI.Match_DNS_Name (Exact, "host.example.com.") = XI.Matched,
                "a trailing root dot is the same name");
         Check (XI.Match_DNS_Name (Exact, "other.example.com") = XI.No_Match,
                "a different name does not match");
         Check (XI.Match_DNS_Name (Exact, "host.example.com.evil.test")
                  = XI.No_Match,
                "a name with the wanted one as a prefix does not match");

         --  A certificate with no address must say so rather than say no.
         Check (XI.Match_IP_Address (Exact, [127, 0, 0, 1])
                  = XI.No_Names_Present,
                "a certificate carrying no address says so");

         Check (XI.Match_DNS_Name (Exact, "") = XI.Malformed_Reference,
                "an empty reference is not a name");
         Check (XI.Match_DNS_Name (Exact, "a..example.com")
                  = XI.Malformed_Reference,
                "a name with an empty label is refused");
         Check (XI.Match_DNS_Name (Exact, "host.example.com" & ASCII.NUL)
                  = XI.Malformed_Reference,
                "a reference with a NUL in it is refused");
      end;

      --  Wildcards: one label, leftmost, whole label.
      declare
         Wild : constant X509C.Certificate :=
           Leaf_With ([1 => To_Unbounded_String ("*.example.com")]);
      begin
         Check (XI.Match_DNS_Name (Wild, "a.example.com") = XI.Matched,
                "a wildcard matches one label");
         Check (XI.Match_DNS_Name (Wild, "A.Example.Com") = XI.Matched,
                "a wildcard match is case-insensitive too");

         --  The two that matter.
         Check (XI.Match_DNS_Name (Wild, "example.com") = XI.No_Match,
                "a wildcard does not match the bare domain");
         Check (XI.Match_DNS_Name (Wild, "a.b.example.com") = XI.No_Match,
                "a wildcard does not stretch across two labels");

         Check (XI.Match_DNS_Name (Wild, "a.other.com") = XI.No_Match,
                "a wildcard does not match a different domain");

         --  A caller that refuses wildcards gets no wildcard matching.
         Check (XI.Match_DNS_Name
                  (Wild, "a.example.com",
                   (Allow_Wildcards            => False,
                    Allow_Common_Name_Fallback => False)) = XI.No_Match,
                "wildcards can be switched off");
      end;

      --  Addresses are octets, and a certificate naming one does not thereby
      --  name the text of it.
      declare
         Addressed : constant X509C.Certificate :=
           Leaf_With ([1 => To_Unbounded_String ("host.example.com"),
                       2 => To_Unbounded_String ("192.0.2.10")]);
      begin
         Check (XI.Match_IP_Address (Addressed, [192, 0, 2, 10]) = XI.Matched,
                "an address matches its octets");
         Check (XI.Match_IP_Address (Addressed, [192, 0, 2, 11]) = XI.No_Match,
                "a different address does not match");
         Check (XI.Match_DNS_Name (Addressed, "192.0.2.10") = XI.No_Match,
                "an address is not matched as a DNS name");
         Check (XI.Match_IP_Address (Addressed, [1 => 192])
                  = XI.Malformed_Reference,
                "an address of the wrong width is refused");
         Check (XI.Match_DNS_Name (Addressed, "host.example.com")
                  = XI.Matched,
                "the DNS name alongside an address still matches");
      end;

      --  The common name is not a service identity. A certificate whose name
      --  lives only there does not match unless the caller asks for the old
      --  behaviour by name.
      declare
         CN_Only : constant X509C.Certificate :=
           Decoded (To_String (CA_PEM));
      begin
         Check (XI.Match_DNS_Name (CN_Only, "identity-ca")
                  = XI.No_Names_Present,
                "a certificate with no subject alternative name says so "
                & "rather than falling back to the common name");
         Check (XI.Match_DNS_Name
                  (CN_Only, "identity-ca",
                   (Allow_Wildcards            => True,
                    Allow_Common_Name_Fallback => True)) = XI.Matched,
                "the common name is consulted only when asked for");
      end;
   end Check_X509_Identity;


   --  Purpose checks over the three profiles this crate issues, plus a CA
   --  and a certificate carrying no extensions at all.
   --
   --  The certificates are real ones with real extensions rather than
   --  hand-built cases, so what is being pinned is that the rules agree with
   --  what an issuer actually emits.
   procedure Check_X509_Purposes is
      use type CryptoLib.PEM.Decode_Status;
      use type CryptoLib.X509.Purposes.Purpose_Result;

      package X509C renames CryptoLib.X509.Certificates;
      package XP renames CryptoLib.X509.Purposes;

      CA_PEM   : Unbounded_String;
      CA_Key   : Unbounded_String;
      Outcome  : CryptoLib.Certificates.Certificate_Status;

      --  A v1 certificate made by OpenSSL, with no extensions whatever. This
      --  crate cannot issue one, and it is the only shape that makes the
      --  absent-extension rules decisive: everything issued here carries a
      --  key usage that answers first.
      Bare_Certificate : constant String :=
        "308202b43082019c02140a69642915b0555887f43cad736f58c003e69dec300d06092a864886f70d01010b0500" &
        "30163114301206035504030c0b7273612d746573742d6361301e170d3236303732383139323833315a170d3237" &
        "303732383139323833315a30173115301306035504030c0c626172652e6578616d706c6530820122300d06092a" &
        "864886f70d01010105000382010f003082010a0282010100be3f29726771c05e0be942271271bf263e9f2e5f65" &
        "798adad43a490461a131d74dbec6a12fac4280da922a541026d82b8a55af928ca44779be1c54cd1268af9a906a" &
        "3652e9b8d89e2d600d8719019cf0d968b22ce2ef22ab3735a1af0be2916ce67c7e777bab2fa52ec49d463696d1" &
        "ce20a1bc0e59f28363d6d2ba4e9d14cee81d1004cec40ef346206b8c445b896310b00db2a70ca7c03e4b8e131c" &
        "ee947830c82ba5f818574def5edd2864666869ce260a825d07f27713e61aa8a871817e4b5813f53d2bfc2a4800" &
        "f7cd2a694e6f1f1f05ca62ba94f9e25fbe55e9956c66dca63892fd2415a629e24d737f62a82ee70633e59cf3f0" &
        "130edf653f5365dcd3110203010001300d06092a864886f70d01010b050003820101004d1ae2d9f624efddb283" &
        "9322d7f9c5f3dbaa60299ffcb6f2ea4d736f8cc50553a6dc282b96681dc60f630e738301843066571b651cb29c" &
        "b050b901f3f3221ce0db5f7a095a48b2bba5b2c28b46dd3228175622992c2b111e25c7e67a885f6fa106ce96da" &
        "0f3b27667d6420a7264618649297bf642dfb2ca3ee0ac4f01fcdecb775c2a0b83460bef042b1399d485786dd71" &
        "431dd9085b3000bbafbf3d091f7c137a4f0a916bde37536d3f35f57fabdc5f48f6edd8839c66344a6b4262b0b5" &
        "2ffa2a40439906edd68d89303c1e01ae540175c4ec5de833d5f5dbf36122273b68808b94152aea8b5d8f3a60c2" &
        "ba24e622729f9908b84d9280f6d07dcc86ba39dafe";

      function Decoded (Text : String) return X509C.Certificate is
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Text)));
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Text'First;
         P      : CryptoLib.PEM.Decode_Status;
         D      : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Text, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, P);
         Check (P = CryptoLib.PEM.Ok, "fixture: armour decodes");
         return X509C.Decode_DER
           (Buffer (Buffer'First .. Last), CryptoLib.ASN1.Default_Limits, D);
      end Decoded;

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
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("purpose-ca", CA_PEM, CA_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      --  The CA. It may issue certificates; it is not a TLS server.
      declare
         CA : constant X509C.Certificate := Decoded (To_String (CA_PEM));
      begin
         Check (XP.Check_Purpose (CA, XP.Certificate_Authority)
                  = XP.Permitted,
                "a CA may act as a CA");

         --  Its key usage is keyCertSign and cRLSign, which does not include
         --  anything a TLS handshake could use.
         Check (XP.Check_Purpose (CA, XP.TLS_Server) = XP.Key_Usage_Forbids,
                "a CA is not a TLS server, got "
                & XP.Result_Image (XP.Check_Purpose (CA, XP.TLS_Server)));
      end;

      --  A server certificate.
      declare
         Leaf_PEM : Unbounded_String;
         Leaf_Key : Unbounded_String;
      begin
         Outcome :=
           CryptoLib.Certificates.Issue_Server_Certificate
             (To_String (CA_PEM), To_String (CA_Key), "host.example",
              [1 => To_Unbounded_String ("host.example")],
              Leaf_PEM, Leaf_Key);
         Check (Outcome = CryptoLib.Certificates.Ok, "fixture: server issued");

         declare
            Leaf : constant X509C.Certificate := Decoded (To_String (Leaf_PEM));
         begin
            Check (XP.Check_Purpose (Leaf, XP.TLS_Server) = XP.Permitted,
                   "a server certificate may serve TLS");
            Check (XP.Check_Purpose (Leaf, XP.TLS_Client)
                     = XP.Extended_Key_Usage_Forbids,
                   "a server certificate is not a client one, got "
                   & XP.Result_Image
                       (XP.Check_Purpose (Leaf, XP.TLS_Client)));
            Check (XP.Check_Purpose (Leaf, XP.Code_Signing)
                     = XP.Extended_Key_Usage_Forbids,
                   "a server certificate does not sign code");

            --  The one that matters most: a leaf must not be able to issue.
            Check (XP.Check_Purpose (Leaf, XP.Certificate_Authority)
                     = XP.Not_A_CA,
                   "a leaf may not act as a CA, got "
                   & XP.Result_Image
                       (XP.Check_Purpose (Leaf, XP.Certificate_Authority)));
         end;
      end;

      --  No extensions at all. Absent does not constrain, so every
      --  end-entity purpose is permitted -- and reading absent as "permits
      --  nothing" would reject most of the private PKI in existence. But
      --  absent basic constraints do not make a CA, which is the one place
      --  where absence means no.
      declare
         Raw  : constant Ada.Streams.Stream_Element_Array :=
           From_Hex (Bare_Certificate);
         D    : CryptoLib.ASN1.Errors.Decode_Status;
         Bare : constant X509C.Certificate :=
           X509C.Decode_DER (Raw, CryptoLib.ASN1.Default_Limits, D);
      begin
         Check (X509C.Is_Present (Bare) and then X509C.Version (Bare) = 1,
                "fixture: the bare certificate is a v1 with no extensions");
         Check (X509C.Extension_Count (Bare) = 0,
                "fixture: it really carries no extensions");

         Check (XP.Check_Purpose (Bare, XP.TLS_Server) = XP.Permitted,
                "a certificate with no extended key usage may serve TLS, got "
                & XP.Result_Image (XP.Check_Purpose (Bare, XP.TLS_Server)));
         Check (XP.Check_Purpose (Bare, XP.Code_Signing) = XP.Permitted,
                "an absent extended key usage does not constrain any purpose");
         Check (XP.Check_Purpose (Bare, XP.Certificate_Authority)
                  = XP.Not_A_CA,
                "absent basic constraints do not make a CA, got "
                & XP.Result_Image
                    (XP.Check_Purpose (Bare, XP.Certificate_Authority)));
      end;

      --  A client certificate is the mirror image.
      declare
         Leaf_PEM : Unbounded_String;
         Leaf_Key : Unbounded_String;
      begin
         Outcome :=
           CryptoLib.Certificates.Issue_Client_Certificate
             (To_String (CA_PEM), To_String (CA_Key), "client.example",
              [1 => To_Unbounded_String ("client.example")],
              Leaf_PEM, Leaf_Key);
         Check (Outcome = CryptoLib.Certificates.Ok, "fixture: client issued");

         declare
            Leaf : constant X509C.Certificate := Decoded (To_String (Leaf_PEM));
         begin
            Check (XP.Check_Purpose (Leaf, XP.TLS_Client) = XP.Permitted,
                   "a client certificate may authenticate a client");
            Check (XP.Check_Purpose (Leaf, XP.TLS_Server)
                     = XP.Extended_Key_Usage_Forbids,
                   "a client certificate is not a server one");
         end;
      end;

      --  And an email certificate.
      declare
         Leaf_PEM : Unbounded_String;
         Leaf_Key : Unbounded_String;
      begin
         Outcome :=
           CryptoLib.Certificates.Issue_Email_Certificate
             (To_String (CA_PEM), To_String (CA_Key), "person@example.com",
              [1 => To_Unbounded_String ("person@example.com")],
              Leaf_PEM, Leaf_Key);
         Check (Outcome = CryptoLib.Certificates.Ok, "fixture: email issued");

         declare
            Leaf : constant X509C.Certificate := Decoded (To_String (Leaf_PEM));
         begin
            Check (XP.Check_Purpose (Leaf, XP.Email_Protection)
                     = XP.Permitted,
                   "an email certificate may protect email");
            Check (XP.Check_Purpose (Leaf, XP.TLS_Server)
                     = XP.Extended_Key_Usage_Forbids,
                   "an email certificate is not a TLS server");
         end;
      end;
   end Check_X509_Purposes;


   --  Distinguished names taken apart rather than flattened.
   --
   --  The certificate is one OpenSSL issued with every common attribute, so
   --  the ordering and the labels can be checked against what "openssl x509
   --  -nameopt rfc2253" prints for the same bytes.
   procedure Check_X509_Names is
      use type CryptoLib.X509.Attribute_Kind;
      use type CryptoLib.X509.Names.Directory_String_Kind;

      package X509C renames CryptoLib.X509.Certificates;
      package XN renames CryptoLib.X509.Names;

      Multi_Certificate : constant String :=
        "308203403082022802140a69642915b0555887f43cad736f58c003e69ded300d06092a864886f70d01010b0500" &
        "30163114301206035504030c0b7273612d746573742d6361301e170d3236303732383139333135365a170d3237" &
        "303732383139333135365a3081a2310b300906035504061302444b3114301206035504080c0b486f7665647374" &
        "6164656e3113301106035504070c0a436f70656e686167656e31143012060355040a0c0b4578616d706c65204c" &
        "746431143012060355040b0c0b456e67696e656572696e67311a301806035504030c116d756c74692e6578616d" &
        "706c652e636f6d3120301e06092a864886f70d010901161161646d696e406578616d706c652e636f6d30820122" &
        "300d06092a864886f70d01010105000382010f003082010a0282010100c62626cc40706f4eec4a2098b1dc8694" &
        "a5a20d0896371462df1bc05898b1ca553793bdc8a7f22e5318d4bd6057d203e61f6565a1c02cebff0652fd1522" &
        "54992da0b4148071de75e897baeede1201d65086c860bb0f096719360fc373b333de8eff20179775ca8bee5c89" &
        "9930dee779e02ba0cde4f7a58b12abca10e6a2f0624ae9f8cc3d7da1fbafd8139d265b2c48ab6e36660921f5b1" &
        "ae05c3fbe7630d7fc7a138b1f2eba7b9ed5d303a4276161595bf6234746974c68b2da2c2a45a6550955cd179cb" &
        "003f432b99ae9260fd32adddf394796660f19809d79b3778419d23365d91b105212a94fb814583eb2e90ceb48f" &
        "552b888442c732288e4b4137fff0d10203010001300d06092a864886f70d01010b050003820101002632f88d68" &
        "f7c8bd35178730a33cbc9b20c8b5e8b5c756be3c4872636470ccf2e2f6f19bd26ef01d9b365c38307e384591e6" &
        "e90745014af092fc62c4a41bcac2cf37f92038c5dfca9355e6ea9590eb23031cc7af80f46effde8ec1fab977b7" &
        "1089990e5f7355c3819762fc131572e8e358c389dd79993c4022cf8d3796516ad46af2209720aaa332bfee7bb2" &
        "424c5881863874f9db30742009310858f5a63a5a8454a183aa41c0a02feb2d7fdeb0e81ba59af4fa7e124e6d62" &
        "1a8a2e0fecd6ecfeeae65066de8140c5f71bbff3e8d67c305b5c8aa34f1080ef83fb658782d6fd7255c93f664b" &
        "fb0de858da0800ac25c9edba5d7866b1db86116fc5d307652791";

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

      Raw    : constant Ada.Streams.Stream_Element_Array :=
        From_Hex (Multi_Certificate);
      Status : CryptoLib.ASN1.Errors.Decode_Status;
      Item   : constant X509C.Certificate :=
        X509C.Decode_DER (Raw, CryptoLib.ASN1.Default_Limits, Status);
   begin
      Check (X509C.Is_Present (Item), "fixture: the certificate decodes");

      --  Seven attributes, in the order DER holds them.
      Check (XN.Attribute_Count (Item, XN.Subject_Name) = 7,
             "the subject carries seven attributes, got"
             & Natural'Image (XN.Attribute_Count (Item, XN.Subject_Name)));

      Check (XN.Attribute_Kind_At (Item, XN.Subject_Name, 1)
               = CryptoLib.X509.Country
             and then XN.Attribute_Text (Item, XN.Subject_Name, 1) = "DK",
             "the first attribute is the country");
      Check (XN.Attribute_Kind_At (Item, XN.Subject_Name, 4)
               = CryptoLib.X509.Organization
             and then XN.Attribute_Text (Item, XN.Subject_Name, 4)
                        = "Example Ltd",
             "the fourth is the organization");
      Check (XN.Attribute_Kind_At (Item, XN.Subject_Name, 6)
               = CryptoLib.X509.Common_Name
             and then XN.Attribute_Text (Item, XN.Subject_Name, 6)
                        = "multi.example.com",
             "the sixth is the common name");
      Check (XN.Attribute_Kind_At (Item, XN.Subject_Name, 7)
               = CryptoLib.X509.Email_Address,
             "the seventh is the email address");

      --  Found by kind rather than by counting.
      Check (XN.Find_Attribute
               (Item, XN.Subject_Name, CryptoLib.X509.Organizational_Unit) = 5,
             "the organizational unit is found by kind");
      Check (XN.Find_Attribute
               (Item, XN.Subject_Name, CryptoLib.X509.Domain_Component) = 0,
             "an attribute the name does not carry is not found");
      Check (XN.Find_Attribute
               (Item, XN.Subject_Name, CryptoLib.X509.Unknown_Attribute) = 0,
             "searching for the unknown kind finds nothing, since every "
             & "unrecognised attribute would answer to it");

      --  The encodings are reported, not guessed at.
      Check (XN.Attribute_String_Kind (Item, XN.Subject_Name, 1)
               = XN.Printable_String,
             "a country is a PrintableString");
      Check (XN.Attribute_String_Kind (Item, XN.Subject_Name, 7)
               = XN.IA5_String,
             "an email address is an IA5String");

      --  Formatting is RFC 4514 order: most specific first, which is the
      --  reverse of how DER holds it. This is the same string openssl prints
      --  with -nameopt rfc2253, except for the label it gives the email
      --  attribute.
      Check (XN.Format (Item, XN.Subject_Name)
               = "EMAIL=admin@example.com,CN=multi.example.com,"
               & "OU=Engineering,O=Example Ltd,L=Copenhagen,"
               & "ST=Hovedstaden,C=DK",
             "the formatted subject is in RFC 4514 order, got "
             & XN.Format (Item, XN.Subject_Name));

      --  The issuer of this certificate is the RSA test CA, one attribute.
      Check (XN.Attribute_Count (Item, XN.Issuer_Name) = 1
             and then XN.Attribute_Text (Item, XN.Issuer_Name, 1)
                        = "rsa-test-ca",
             "the issuer name is read the same way");

      --  Formatting is for reading, not for comparing: the encoded name is
      --  what an issuer signed and what tells two subjects apart.
      Check (X509C.Subject_Bytes (Item)'Length > 0
             and then X509C.Subject_Bytes (Item) /= X509C.Issuer_Bytes (Item),
             "the encoded subject and issuer differ, which is the comparison "
             & "that counts");
   end Check_X509_Names;


   --  The armour handling behind the issuance API, now that it goes through
   --  the strict decoder.
   --
   --  What this pins is not that good input works -- the certificate tests
   --  already cover that -- but that damaged input is refused rather than
   --  decoded into something else. A decoder that skips what it does not
   --  recognise turns one stray character into a different certificate, and
   --  the fingerprint of that certificate is a number nobody can match.
   procedure Check_Certificate_Armour is
      CA_PEM  : Unbounded_String;
      CA_Key  : Unbounded_String;
      Outcome : CryptoLib.Certificates.Certificate_Status;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("armour-ca", CA_PEM, CA_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      declare
         Good        : constant String := To_String (CA_PEM);
         Fingerprint : constant String :=
           CryptoLib.Certificates.Fingerprint (Good);
      begin
         Check (Fingerprint'Length > 0,
                "a well-formed certificate has a fingerprint");

         --  A stray character inside the base64. Skipping it would shift
         --  every following bit and yield a different certificate with a
         --  perfectly plausible fingerprint.
         declare
            Body_Start : constant Natural :=
              Ada.Strings.Fixed.Index (Good, "-----" & ASCII.LF) + 6;
            Damaged    : String := Good;
         begin
            Check (Body_Start in Good'Range,
                   "fixture: the armour body was found");
            Damaged (Body_Start + 4) := '!';
            Check (CryptoLib.Certificates.Fingerprint (Damaged) = "",
                   "a certificate with a stray character in its armour has "
                   & "no fingerprint, rather than a different one");
            Check (not CryptoLib.Certificates.Same_Certificate
                         (Good, Damaged),
                   "damaged armour does not compare equal to the original");
         end;

         --  Armour that opens as one thing and closes as another.
         declare
            Crossed : constant String :=
              "-----BEGIN CERTIFICATE-----" & ASCII.LF & "QUJD" & ASCII.LF
              & "-----END PRIVATE KEY-----" & ASCII.LF;
         begin
            Check (CryptoLib.Certificates.Fingerprint (Crossed) = "",
                   "a block closed by a different label is refused");
         end;

         --  Text before the armour must not become part of the payload. This
         --  is the shape that failed here once: keytool names the alias
         --  first, and openssl -text prints the whole certificate.
         declare
            With_Preamble : constant String :=
              "Alias name: mykey" & ASCII.LF
              & "Entry type: PrivateKeyEntry" & ASCII.LF & Good;
         begin
            Check (CryptoLib.Certificates.Fingerprint (With_Preamble)
                     = Fingerprint,
                   "a preamble before the armour does not change the "
                   & "certificate");
         end;
      end;
   end Check_Certificate_Armour;


   --  A revocation list made by OpenSSL, with a certificate genuinely
   --  revoked through "openssl ca -revoke".
   procedure Check_X509_CRL is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.X509.Signatures.Verification_Result;

      package X509C renames CryptoLib.X509.Certificates;
      package XC renames CryptoLib.X509.CRLs;

      CRL_DER : constant String :=
        "308201863070020101300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d74657374" &
        "2d6361170d3236303732383230313534375a170d3236303832373230313534375a3015301302021000170d3236" &
        "303732383230313534375aa00f300d300b0603551d14040402021000300d06092a864886f70d01010b05000382" &
        "0101006658640fbac6a1af6d6ae781e8565bde72e4d010700077d31961e4927583013585ed7dbe4fc3a86e1a5f" &
        "ad9bfd07334f077af62093de31acb5c1d137d1a25e67ba5d7faa7330cb422947461d2a395068594ddde4f739be" &
        "3bd345e04807299af988b58413704b2227863de0cfdfc8eb4090620bb5f299a7952a194ba4d273d6453c7cb9d0" &
        "d5ddab9a0365ebe032d1abfb3a10bed8a02d52aff966391e0bef4601150fccf121628bdbf5302e155cbc492ced" &
        "d9b07a9d8faf65476f1e3494ca0835eaaa97ea86bd0e0c4aa0f63584a3829891fc7a8b9d79522ed10c8d627a69" &
        "a018f0630976bf890136c61568406f615df99b62cd3db8eb62fbe778914516b4d902";

      CRL_CA_DER : constant String :=
        "3082030d308201f5a0030201020214695a2eb222fd6509af65d97b7099306d68b399eb300d06092a864886f70d" &
        "01010b050030163114301206035504030c0b63726c2d746573742d6361301e170d323630373238323031353437" &
        "5a170d3336303732353230313534375a30163114301206035504030c0b63726c2d746573742d63613082012230" &
        "0d06092a864886f70d01010105000382010f003082010a0282010100b5e60ee7058f7f9e991a038feeac5eb95d" &
        "99b6b52f543a4cf379d9b84ab68125a82424b27f07a1f6a39f6f6e5ac4df194a06d3683fafc31123427f768f60" &
        "24aa6b2d5f759d0629a578497370038d70020ea20e261a913c332504d70327b2cd747a2ae0f415764976ae21d8" &
        "c34874405cfabefd83ffc5b03de5c6521a611c333189ead8755a0bf56113ad088deb953cf1febb465a377d256b" &
        "ad055bf627727ccfffa616cfe8edc009a49f318a6c1e935dc42b69ab1d2aa9ee2173defdf45fbb595b99aced52" &
        "9fca129587fac967025980f7617070edde4748fa62cd395a608475ba22bd65c29f1fabdefe5e8aeed28baa1703" &
        "88bca8bb6490db6bacea3473ed8f0203010001a3533051301d0603551d0e04160414a1f6d41f7e7b24380aa8a0" &
        "cd33926e4452de852f301f0603551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300f06" &
        "03551d130101ff040530030101ff300d06092a864886f70d01010b050003820101005f484fd12f7d522aa3787c" &
        "0ee05c3e06067d91b3f51a3747e1ffcd7d57e839f17a9bfcf878faa9c4af435426aa06ed4907dfb9c29ca36c6b" &
        "53af27ce22516b5bd4cb19e9d912893e3800a1f7acc3abefbc18a6c899793b6ff9d378f2a77e0feb03659f8a24" &
        "09bee7a4804773be1f8428608fb9041ac74581b1943d0d90dd2939be1b74015bcd676cf483167988523fba452b" &
        "255b49146d3c5be21408d8c9848f6794a4fa588ab2d6d326bc7d92920c3547d3f4d9270c01ec4d368c98e11a61" &
        "1f40cd6672de148b3bf435f812eda7e9e5d383ff2eefcf1384d136c45b1c062f731fc3414a237cf1b971994cce" &
        "d2b6852b3f4314e9335fc96ba21fd8949c58f5c5";

      CRL_Leaf_DER : constant String :=
        "308202a53082018d02021000300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d74" &
        "6573742d6361301e170d3236303732383230313534375a170d3237303732383230313534375a301a3118301606" &
        "035504030c0f7265766f6b65642e6578616d706c6530820122300d06092a864886f70d01010105000382010f00" &
        "3082010a0282010100c0ed219d3150260bb4a5a976fd93941636a1dcdc8976321a5c82e468c74ff7e755f29a69" &
        "40524606cf7e70308e8c3ed01c6954e7e7a45fdedd1d914b6cf2459cbba0b0a2f3a248771f69301ac2735a408a" &
        "f830e03b7c3941648de0810c102c79f17da1d486a3b676993fd30102ed86ee4d4cde770d3abf8dd4b178885132" &
        "f79e8799c63595af16af350d94207d96a5d830c19e2eff9edb43607e7c8e5ba3e737b82f71937a7ca59ffcac9d" &
        "fc633aa69ce1e08aabf84a068c4e1dfa9f7ca28f959062408140c1c8cf63d66761609bc2dff8b3d4bd3250ee0a" &
        "86b507023e9f9aee80b2184c01758ffaf3c280eeeff0fb0926de9c83cfc2f327c4dcd6254a0447150203010001" &
        "300d06092a864886f70d01010b0500038201010080e42f4484be128c22efd3e63c0ea74f0efc8937b0a9529a0d" &
        "90efd502c75e3647fa117adca923af965a184fa141d74ce910ad9fbed2fb1f1eb295f9cd28ebff73c6b8ea6ace" &
        "a4d54009be31e34a52fa63c4277ebe37865d16ce20d7776ff9dbfee953305678b1dc967f59f836b6fc5ce4f166" &
        "c3e4d20a992bbdb0b2ac53f8c8a23b9176097ae12e84bcebe9e81b77da3571a2f2bcf77d7e516102c37352c1e0" &
        "fba2439d98a01280abcefe8a91b5857a2f515e6ae71c14f10fa56fb4710798b987f0a0b89a2510995a6f6cfa27" &
        "2f10d60bcd56e3add0eb664aaa565ee2471a1f5b00eae79e62e58b987db98503855bb0bd82b803d2b7ee27f40c" &
        "f62c878f5876";

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

      Status : CryptoLib.ASN1.Errors.Decode_Status;

      CA : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (CRL_CA_DER), CryptoLib.ASN1.Default_Limits, Status);
      Leaf : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (CRL_Leaf_DER), CryptoLib.ASN1.Default_Limits, Status);
      List : constant XC.Revocation_List :=
        XC.Decode_DER
          (From_Hex (CRL_DER), CryptoLib.ASN1.Default_Limits, Status);
   begin
      Check (Status = CryptoLib.ASN1.Errors.Ok and then XC.Is_Present (List),
             "the CRL decodes: "
             & CryptoLib.ASN1.Errors.Status_Image (Status));
      Check (X509C.Is_Present (CA) and then X509C.Is_Present (Leaf),
             "fixture: the CA and the revoked certificate decode");

      --  Issued by the CA it claims, which is what makes it about these
      --  certificates at all.
      Check (XC.Issuer_Bytes (List) = X509C.Subject_Bytes (CA),
             "the CRL's issuer is the CA's subject");

      Check (XC.This_Update (List).Year = 2026,
             "thisUpdate decodes to the year OpenSSL wrote");
      Check (XC.Has_Next_Update (List),
             "this CRL states when the next one is due");
      Check (CryptoLib.X509.Is_Not_After
               (XC.This_Update (List), XC.Next_Update (List)),
             "the update window is not inverted");

      Check (XC.Entry_Count (List) = 1,
             "the list carries one revoked certificate, got"
             & Natural'Image (XC.Entry_Count (List)));

      --  The certificate that was revoked, looked up by the serial its own
      --  encoding carries.
      Check (XC.Is_Revoked (List, X509C.Serial_Number (Leaf)),
             "the revoked certificate is on the list");

      --  One that was not.
      Check (not XC.Is_Revoked (List, [16#7F#, 16#FF#]),
             "a serial that was never issued is not on the list");

      --  A serial written with a sign-preserving leading zero is the same
      --  number. Missing that would treat a revoked certificate as good.
      declare
         Serial : constant Ada.Streams.Stream_Element_Array :=
           X509C.Serial_Number (Leaf);
         Padded : constant Ada.Streams.Stream_Element_Array :=
           [0] & Serial;
      begin
         Check (XC.Is_Revoked (List, Padded),
                "a serial with a leading zero is the same serial");
      end;

      --  The CA really signed it.
      Check (XC.Verify_Signature (List, CA)
               = CryptoLib.X509.Signatures.Valid,
             "the CRL verifies under its issuer's key");

      --  And the leaf did not.
      Check (XC.Verify_Signature (List, Leaf)
               /= CryptoLib.X509.Signatures.Valid,
             "the CRL does not verify under an unrelated key");

      --  A CRL with a byte changed inside the signed body must not verify.
      declare
         Damaged : Ada.Streams.Stream_Element_Array := From_Hex (CRL_DER);
         Broken  : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         --  Inside the TBSCertList rather than in the signature: this is the
         --  alteration a signature exists to detect.
         Damaged (Damaged'First + 30) := Damaged (Damaged'First + 30) xor 1;
         declare
            Altered : constant XC.Revocation_List :=
              XC.Decode_DER
                (Damaged, CryptoLib.ASN1.Default_Limits, Broken);
         begin
            if Broken = CryptoLib.ASN1.Errors.Ok then
               Check (XC.Verify_Signature (Altered, CA)
                        /= CryptoLib.X509.Signatures.Valid,
                      "an altered CRL does not verify");
            end if;
         end;
      end;
   end Check_X509_CRL;


   --  OCSP, against requests and responses OpenSSL produced.
   --
   --  The two delegated cases are the reason this package is careful: a
   --  responder answering for somebody else's certificates is the whole
   --  attack, and the only thing standing between the two responses below is
   --  one extended key usage.
   procedure Check_OCSP is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.OCSP.Verification_Result;
      use type CryptoLib.OCSP.Response_Status;
      use type CryptoLib.OCSP.Certificate_Status;
      use type CryptoLib.OCSP.Responder_Kind;

      package X509C renames CryptoLib.X509.Certificates;
      package CO renames CryptoLib.OCSP;

      OCSP_Request : constant String :=
        "30433041303f303d303b300906052b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414" &
        "a1f6d41f7e7b24380aa8a0cd33926e4452de852f02021000";

      OCSP_Direct : constant String :=
        "308204de0a0100a08204d7308204d306092b0601050507300101048204c4308204c0308190a118301631143012" &
        "06035504030c0b63726c2d746573742d6361180f32303236303732383230323335385a30633061303b30090605" &
        "2b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b24380aa8a0cd3392" &
        "6e4452de852f02021000a111180f32303236303732383230313534375a180f3230323630373238323032333538" &
        "5a300d06092a864886f70d01010b05000382010100862fd17f69d414772feb68610edde88340d444547f7e017a" &
        "efab65e16849a6bd80267d5e624d5bdc87f5d6434ab54062c31f42ecaa312ad9a748c695c0d9d2e347dc540697" &
        "5ec19765aa29f2c3ba9376a21127c69294df5eb7adf737ebe67b2d68f7902a3e52a9853dcc3ef610046bf4a501" &
        "0d68c20b943c3dd04347b08a14be4b4e41c768e86784909e0d6bc36f09472ef4fb68025e5f92eecb0e9f816386" &
        "55c57d49f1b8b4931eccf246a8e342a83dd8b52ea209524956c4f3ab3ed05ca51d25fb648fb3218ee3516653d1" &
        "cf10b640ac0c3b561087977344d0a7ad93f276f89a19a8b667fd389b3650b83fe4183cf51ae996640d687a40b4" &
        "2faf4d10f5619ea0820315308203113082030d308201f5a0030201020214695a2eb222fd6509af65d97b709930" &
        "6d68b399eb300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d746573742d636130" &
        "1e170d3236303732383230313534375a170d3336303732353230313534375a30163114301206035504030c0b63" &
        "726c2d746573742d636130820122300d06092a864886f70d01010105000382010f003082010a0282010100b5e6" &
        "0ee7058f7f9e991a038feeac5eb95d99b6b52f543a4cf379d9b84ab68125a82424b27f07a1f6a39f6f6e5ac4df" &
        "194a06d3683fafc31123427f768f6024aa6b2d5f759d0629a578497370038d70020ea20e261a913c332504d703" &
        "27b2cd747a2ae0f415764976ae21d8c34874405cfabefd83ffc5b03de5c6521a611c333189ead8755a0bf56113" &
        "ad088deb953cf1febb465a377d256bad055bf627727ccfffa616cfe8edc009a49f318a6c1e935dc42b69ab1d2a" &
        "a9ee2173defdf45fbb595b99aced529fca129587fac967025980f7617070edde4748fa62cd395a608475ba22bd" &
        "65c29f1fabdefe5e8aeed28baa170388bca8bb6490db6bacea3473ed8f0203010001a3533051301d0603551d0e" &
        "04160414a1f6d41f7e7b24380aa8a0cd33926e4452de852f301f0603551d23041830168014a1f6d41f7e7b2438" &
        "0aa8a0cd33926e4452de852f300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003" &
        "820101005f484fd12f7d522aa3787c0ee05c3e06067d91b3f51a3747e1ffcd7d57e839f17a9bfcf878faa9c4af" &
        "435426aa06ed4907dfb9c29ca36c6b53af27ce22516b5bd4cb19e9d912893e3800a1f7acc3abefbc18a6c89979" &
        "3b6ff9d378f2a77e0feb03659f8a2409bee7a4804773be1f8428608fb9041ac74581b1943d0d90dd2939be1b74" &
        "015bcd676cf483167988523fba452b255b49146d3c5be21408d8c9848f6794a4fa588ab2d6d326bc7d92920c35" &
        "47d3f4d9270c01ec4d368c98e11a611f40cd6672de148b3bf435f812eda7e9e5d383ff2eefcf1384d136c45b1c" &
        "062f731fc3414a237cf1b971994cced2b6852b3f4314e9335fc96ba21fd8949c58f5c5";

      OCSP_Delegated : constant String :=
        "308205060a0100a08204ff308204fb06092b0601050507300101048204ec308204e8308193a11b301931173015" &
        "06035504030c0e6f6373702d726573706f6e646572180f32303236303732383230323431345a30633061303b30" &
        "0906052b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b24380aa8a0" &
        "cd33926e4452de852f02021000a111180f32303236303732383230313534375a180f3230323630373238323032" &
        "3431345a300d06092a864886f70d01010b05000382010100743a3e5445a00169dbfac8f1d889ae13523335e534" &
        "cfe136842b5316d626794304f602bee55c287bf8d5ebb02eadeb2ccf21392ab83aafb07de20fb8365ba7a7f180" &
        "91973241ef823100826a8a5da50ce96bd5d2c09095ded007e05038c8974e4d6d24df3ae3fe9088cc5c8719ba21" &
        "86933f61cd4657ba32b0885504597dcc45c8295fc478250f12ffe9398432f3d547017920b59880e05a2d7a320a" &
        "7e207b5b30354b3540a69256b623a3abf06200155e43dc9b347d0a184bdb0dddf431cec3ad1d76b8fcac3174ff" &
        "55a1e9590225d17eade87430acc731a02f0b936e675ad4ea2831530ec05ce57c917f47e57f8ffcdaba3fab5e31" &
        "6604116d938c1f4cd958a082033a30820336308203323082021aa003020102021444aab1aa260bfa011e9556a8" &
        "1fcac713d43514b6300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d746573742d" &
        "6361301e170d3236303732383230323431345a170d3237303732383230323431345a3019311730150603550403" &
        "0c0e6f6373702d726573706f6e64657230820122300d06092a864886f70d01010105000382010f003082010a02" &
        "82010100f51a4c10fd2b7b59f399fd3f6f2cd2f3b2f0ca1e94b48c7aa86fd4389e857ab7dc515e1de5debeeca2" &
        "10baa228975c38d7580b62b1e8e0e7b94030a79d3c572c2b5ed916a48c354bfec591c7685e8802e8be5789eb86" &
        "b2b209ece387c0ab75246ec81af3e7194b0e79c6238841da91497cffd00dc470027b242664f870511af713de07" &
        "50032a3e3cc73f83ca64d0e2f50e0137e74f0bae16eadb203e23907f9a7ee72a2069e095e9a3fb17be25d07557" &
        "32feaafe7e76e2b560086d6575a3b681f69347ce78aa56f8f9d13ad9b08813cb0f3d9397c403a5d943a85854c0" &
        "9657ab024e9dece7a5f6c0d81eb2a078fb8842cba426ee93e6c279c2cd0ebf86e0197f0203010001a375307330" &
        "090603551d1304023000300e0603551d0f0101ff04040302078030160603551d250101ff040c300a06082b0601" &
        "0505070309301d0603551d0e04160414d2f9e7ddf12388f9a8660ebd49decec3c844e664301f0603551d230418" &
        "30168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300d06092a864886f70d01010b050003820101007a" &
        "21aa45f4758c6a4ed14ffd336edfa0fa154e11b040e19d400bc6b95c4887cd2a6903eaf7b6e74e907df6bfb1fd" &
        "d1012b697abee6ab86946130e5bd37e65510e5728443c717bec4bb0986e97956903e25cdabbea19b60aab68588" &
        "d80be5e44eaf53c4f36f076124ad56a48c46abfb7eb806303d87b96b6bd7416192f5072d8536f53bbaf5087390" &
        "ce561548386d645695b8293bf35486124bfbca35ce0ff1892b7b697570033dae46b40b870c0fe0069fd153f6ba" &
        "6222b02f13b0a8a6cee43751a074c55dc7e0445117a02ae476d349bc164c136518fe15bbb3c9578baaeccee905" &
        "1cf77a0bb0b44ed31349a77fc4353a468cb1f1fc3555515f67c4c530a75e";

      OCSP_Unauthorized : constant String :=
        "3082050c0a0100a08205053082050106092b0601050507300101048204f2308204ee308196a11e301c311a3018" &
        "06035504030c116e6f746f6373702d726573706f6e646572180f32303236303732383230323431345a30633061" &
        "303b300906052b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b2438" &
        "0aa8a0cd33926e4452de852f02021000a111180f32303236303732383230313534375a180f3230323630373238" &
        "3230323431345a300d06092a864886f70d01010b050003820101003efd3a59e9a03c2805dfbdcf26a8cd69030b" &
        "f0b8ce62077c1a1bb41fa48a7a057fce3a66620e77c8d4b94c900d60e1d571fdbe63885930bdc90c57cd70c27a" &
        "8ebf532a48e349f9815238bed4ae6c74e91c12b5d1a46b2597e88ac38b844bebbfb80e10542e0f054a74f39720" &
        "05b9161b2ce6d81e5013f0c4526695d228983d426b74771432b1407cb26e7f517ff6742a562c884c5aad5d5162" &
        "21adc1f9a277ae81b718ad0a10a55b2cbce9d76bde99f6dc9d386701574cb9273a1b1a708ca7d09eb20eea15ec" &
        "2d71b2f0abe87b2bd8ea5642cbf88fdd89d91b757bced088d1e4bca01dd9aad9fa99c8ab3d5c4c5fe2fc505360" &
        "458c7e4237a2c11f15ed7f6075a082033d30820339308203353082021da003020102021444aab1aa260bfa011e" &
        "9556a81fcac713d43514b7300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d7465" &
        "73742d6361301e170d3236303732383230323431345a170d3237303732383230323431345a301c311a30180603" &
        "5504030c116e6f746f6373702d726573706f6e64657230820122300d06092a864886f70d01010105000382010f" &
        "003082010a0282010100c491c573ae839cb45ecb75d47f2ee41bc065ae9ac39fd7afd4f5cd4d7e89b400a7a79e" &
        "a43a2c43a05cb58e21d352370dc4d2956c4a709881048aafcd9e3d9c6a72aa007f6a259f43df29f8266532ae82" &
        "7cda39eeeafd679d1ceb61decd7bf001ba1678361cd24a53ce9173af7998f0498c73cf279ed10996c9bee9350b" &
        "c4137886fd8147c3402fc31447f03bffde66f34846635843750384edeeaa53aeb8b838fa8ab77f60a1f5a3e0e0" &
        "57991dd329172f19bc27db6a197ca7dd0b6ecb9b3c3455bd4c961ddb9d96ec27ee13367135de9567f041ea418f" &
        "bdb7df415504cabedbffa399a9f3a044bb9f1c0e473df09b22386d1cf2258a9b78ee21800ece10801502030100" &
        "01a375307330090603551d1304023000300e0603551d0f0101ff04040302078030160603551d250101ff040c30" &
        "0a06082b06010505070301301d0603551d0e041604146ad1ce7fdde3bfe17e9475437ce287f6a1b1f787301f06" &
        "03551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300d06092a864886f70d01010b0500" &
        "038201010064cf0f298af11571ae94fed30d1d5d06dacd42eea12c67ff6314a8ce09022033055285288afdbe17" &
        "4c219b8353b4cf08474ad7b98d0cfe39b89786822a712cf5bcfac43ea9469c0764d8d855fd8c0e433a478f9fbf" &
        "bc44a4ae55765959d634b2049200d96b4583d4815987808a8fed6a00fd9c4bca8bbaa94b35866393bc56238e5b" &
        "e6cc4b57faf9318df531ed1ac623f546f05fc72b168174b6211f65564bebccdeb3a87332bc76c84fffe8722525" &
        "e90a24602ea7bb0c5ccc21d5190bf9ddbeee2603064d2d4f18be78400151956112375b19f87a5a09eb4a63cd12" &
        "8dc20797b0fcf9cd0ab02d7b3aa89591c00bfd50b2006b51bd6aab88bd9eebc1f91109b0";

      CRL_CA_DER : constant String :=
        "3082030d308201f5a0030201020214695a2eb222fd6509af65d97b7099306d68b399eb300d06092a864886f70d" &
        "01010b050030163114301206035504030c0b63726c2d746573742d6361301e170d323630373238323031353437" &
        "5a170d3336303732353230313534375a30163114301206035504030c0b63726c2d746573742d63613082012230" &
        "0d06092a864886f70d01010105000382010f003082010a0282010100b5e60ee7058f7f9e991a038feeac5eb95d" &
        "99b6b52f543a4cf379d9b84ab68125a82424b27f07a1f6a39f6f6e5ac4df194a06d3683fafc31123427f768f60" &
        "24aa6b2d5f759d0629a578497370038d70020ea20e261a913c332504d70327b2cd747a2ae0f415764976ae21d8" &
        "c34874405cfabefd83ffc5b03de5c6521a611c333189ead8755a0bf56113ad088deb953cf1febb465a377d256b" &
        "ad055bf627727ccfffa616cfe8edc009a49f318a6c1e935dc42b69ab1d2aa9ee2173defdf45fbb595b99aced52" &
        "9fca129587fac967025980f7617070edde4748fa62cd395a608475ba22bd65c29f1fabdefe5e8aeed28baa1703" &
        "88bca8bb6490db6bacea3473ed8f0203010001a3533051301d0603551d0e04160414a1f6d41f7e7b24380aa8a0" &
        "cd33926e4452de852f301f0603551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300f06" &
        "03551d130101ff040530030101ff300d06092a864886f70d01010b050003820101005f484fd12f7d522aa3787c" &
        "0ee05c3e06067d91b3f51a3747e1ffcd7d57e839f17a9bfcf878faa9c4af435426aa06ed4907dfb9c29ca36c6b" &
        "53af27ce22516b5bd4cb19e9d912893e3800a1f7acc3abefbc18a6c899793b6ff9d378f2a77e0feb03659f8a24" &
        "09bee7a4804773be1f8428608fb9041ac74581b1943d0d90dd2939be1b74015bcd676cf483167988523fba452b" &
        "255b49146d3c5be21408d8c9848f6794a4fa588ab2d6d326bc7d92920c3547d3f4d9270c01ec4d368c98e11a61" &
        "1f40cd6672de148b3bf435f812eda7e9e5d383ff2eefcf1384d136c45b1c062f731fc3414a237cf1b971994cce" &
        "d2b6852b3f4314e9335fc96ba21fd8949c58f5c5";

      CRL_Leaf_DER : constant String :=
        "308202a53082018d02021000300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d74" &
        "6573742d6361301e170d3236303732383230313534375a170d3237303732383230313534375a301a3118301606" &
        "035504030c0f7265766f6b65642e6578616d706c6530820122300d06092a864886f70d01010105000382010f00" &
        "3082010a0282010100c0ed219d3150260bb4a5a976fd93941636a1dcdc8976321a5c82e468c74ff7e755f29a69" &
        "40524606cf7e70308e8c3ed01c6954e7e7a45fdedd1d914b6cf2459cbba0b0a2f3a248771f69301ac2735a408a" &
        "f830e03b7c3941648de0810c102c79f17da1d486a3b676993fd30102ed86ee4d4cde770d3abf8dd4b178885132" &
        "f79e8799c63595af16af350d94207d96a5d830c19e2eff9edb43607e7c8e5ba3e737b82f71937a7ca59ffcac9d" &
        "fc633aa69ce1e08aabf84a068c4e1dfa9f7ca28f959062408140c1c8cf63d66761609bc2dff8b3d4bd3250ee0a" &
        "86b507023e9f9aee80b2184c01758ffaf3c280eeeff0fb0926de9c83cfc2f327c4dcd6254a0447150203010001" &
        "300d06092a864886f70d01010b0500038201010080e42f4484be128c22efd3e63c0ea74f0efc8937b0a9529a0d" &
        "90efd502c75e3647fa117adca923af965a184fa141d74ce910ad9fbed2fb1f1eb295f9cd28ebff73c6b8ea6ace" &
        "a4d54009be31e34a52fa63c4277ebe37865d16ce20d7776ff9dbfee953305678b1dc967f59f836b6fc5ce4f166" &
        "c3e4d20a992bbdb0b2ac53f8c8a23b9176097ae12e84bcebe9e81b77da3571a2f2bcf77d7e516102c37352c1e0" &
        "fba2439d98a01280abcefe8a91b5857a2f515e6ae71c14f10fa56fb4710798b987f0a0b89a2510995a6f6cfa27" &
        "2f10d60bcd56e3add0eb664aaa565ee2471a1f5b00eae79e62e58b987db98503855bb0bd82b803d2b7ee27f40c" &
        "f62c878f5876";

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

      Status : CryptoLib.ASN1.Errors.Decode_Status;

      --  The same CA and revoked certificate the CRL fixtures come from.
      CA : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (CRL_CA_DER), CryptoLib.ASN1.Default_Limits, Status);
      Leaf : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (CRL_Leaf_DER), CryptoLib.ASN1.Default_Limits, Status);
   begin
      --  A request built here is the request OpenSSL builds, byte for byte.
      --  Anything less and the responder is being asked a question about a
      --  certificate it cannot recognise.
      declare
         Built : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CO.Maximum_Request_Length));
         Last  : Ada.Streams.Stream_Element_Offset;
         St    : CryptoLib.ASN1.Errors.Decode_Status;
         Want  : constant Ada.Streams.Stream_Element_Array :=
           From_Hex (OCSP_Request);
      begin
         CO.Build_Request (Leaf, CA, Built, Last, St);
         Check (St = CryptoLib.ASN1.Errors.Ok, "the request is built");
         Check (Built (Built'First .. Last) = Want,
                "the request is byte-identical to OpenSSL's");
      end;

      --  Signed by the issuer itself.
      declare
         Item : CO.Response :=
           CO.Decode_Response
             (From_Hex (OCSP_Direct), CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok and then CO.Is_Present (Item),
                "the direct response decodes: "
                & CryptoLib.ASN1.Errors.Status_Image (Status));
         Check (CO.Status_Of (Item) = CO.Successful,
                "the responder answered");
         Check (CO.Verify (Item, Leaf, CA) = CO.Accepted,
                "a response signed by the issuer is accepted");
         Check (CO.Responder (Item) = CO.Issuer_Signed,
                "and is recorded as issuer-signed");
         Check (CO.Certificate_Status_Of (Item) = CO.Revoked,
                "the certificate is reported revoked, which is what "
                & "openssl ca -revoke made it");
      end;

      --  Signed by a responder the issuer delegated to.
      declare
         Item : CO.Response :=
           CO.Decode_Response
             (From_Hex (OCSP_Delegated), CryptoLib.ASN1.Default_Limits,
              Status);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok, "the delegated response "
                & "decodes");
         Check (CO.Verify (Item, Leaf, CA) = CO.Accepted,
                "a response from an authorized delegate is accepted");
         Check (CO.Responder (Item) = CO.Delegate_Signed,
                "and is recorded as delegate-signed, not confused with the "
                & "issuer answering directly");
      end;

      --  Signed by a certificate the issuer really did issue, which is not
      --  authorized to answer. Without the extended key usage check any
      --  server certificate could speak for its CA's revocation state.
      declare
         Item : CO.Response :=
           CO.Decode_Response
             (From_Hex (OCSP_Unauthorized), CryptoLib.ASN1.Default_Limits,
              Status);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok,
                "the unauthorized response decodes -- it is well formed");
         Check (CO.Verify (Item, Leaf, CA) = CO.Delegate_Not_Authorized,
                "a delegate without OCSP signing authority is refused, got "
                & CO.Result_Image (CO.Verify (Item, Leaf, CA)));
         Check (CO.Responder (Item) = CO.Not_Established,
                "and no responder is established for it");
      end;

      --  A response about somebody else's certificate. Verified against the
      --  CA as if it were the subject, so the CertID cannot match.
      declare
         Item : CO.Response :=
           CO.Decode_Response
             (From_Hex (OCSP_Direct), CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (CO.Verify (Item, CA, CA) = CO.Wrong_Certificate,
                "a response about a different certificate is refused, got "
                & CO.Result_Image (CO.Verify (Item, CA, CA)));
      end;
   end Check_OCSP;


   --  Path building, and specifically the case that separates a builder that
   --  works from one that appears to.
   --
   --  Two CAs share a subject name and have different keys. Only one of them
   --  issued the leaf, and the other is offered first. A builder that took
   --  the first name match and stopped would report no path where one plainly
   --  exists -- and the arrangement is not exotic: it is what cross-signing
   --  looks like from the inside.
   procedure Check_X509_Path_Building is
      use type CryptoLib.PEM.Decode_Status;
      use type CryptoLib.X509.Validation.Validation_Failure;

      package X509C renames CryptoLib.X509.Certificates;
      package PB renames CryptoLib.X509.Path_Building;
      package XV renames CryptoLib.X509.Validation;

      Real_PEM  : Unbounded_String;   --  the CA that issued the leaf
      Real_Key  : Unbounded_String;
      Twin_PEM  : Unbounded_String;   --  same name, different key
      Twin_Key  : Unbounded_String;
      Other_PEM : Unbounded_String;   --  unrelated, to pad the pool
      Other_Key : Unbounded_String;
      Leaf_PEM  : Unbounded_String;
      Leaf_Key  : Unbounded_String;
      Outcome   : CryptoLib.Certificates.Certificate_Status;

      function Decoded (Text : String) return X509C.Certificate is
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Text)));
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Text'First;
         P      : CryptoLib.PEM.Decode_Status;
         D      : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Text, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, P);
         Check (P = CryptoLib.PEM.Ok, "fixture: armour decodes");
         return X509C.Decode_DER
           (Buffer (Buffer'First .. Last), CryptoLib.ASN1.Default_Limits, D);
      end Decoded;

      --  The pool, in a deliberately unhelpful order: the impostor first.
      type Pool is limited new PB.Candidate_Source with null record;

      overriding function Count (Source : Pool) return Natural is (3);

      overriding function Candidate
        (Source : Pool; Index : Positive) return X509C.Certificate
      is (case Index is
             when 1      => Decoded (To_String (Twin_PEM)),
             when 2      => Decoded (To_String (Other_PEM)),
             when others => Decoded (To_String (Real_PEM)));

      overriding function Is_Trust_Anchor
        (Source : Pool; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Common_Name (Item) = "shared-ca");

      --  A pool holding only the impostor, so no path exists at all.
      type Impostor_Only is limited new PB.Candidate_Source with null record;

      overriding function Count (Source : Impostor_Only) return Natural is (1);

      overriding function Candidate
        (Source : Impostor_Only; Index : Positive) return X509C.Certificate
      is (Decoded (To_String (Twin_PEM)));

      overriding function Is_Trust_Anchor
        (Source : Impostor_Only; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Common_Name (Item) = "shared-ca");

      --  A path fetched by position, so the built path can be validated.
      type Built_Path (Length : Natural) is limited new XV.Path_Source
      with record
         Chain : PB.Path_Indices;
      end record;

      overriding function Length (Source : Built_Path) return Positive
      is (Source.Length + 1);

      overriding function Certificate_At
        (Source : Built_Path; Index : Positive) return X509C.Certificate
      is (if Index = 1
          then Decoded (To_String (Leaf_PEM))
          else Candidate (Pool'(null record), Source.Chain (Index - 1)));

      overriding function Is_Trust_Anchor
        (Source : Built_Path; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Common_Name (Item) = "shared-ca");

      Search : PB.Build_Result;
   begin
      --  Two CAs with one name. Create_Local_CA names the subject from what
      --  it is given, so these encode identically and differ only in key.
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("shared-ca", Twin_PEM, Twin_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: twin CA");

      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("shared-ca", Real_PEM, Real_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: real CA");

      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("unrelated-ca", Other_PEM, Other_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: unrelated CA");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (Real_PEM), To_String (Real_Key), "host.example",
           [1 => To_Unbounded_String ("host.example")],
           Leaf_PEM, Leaf_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: leaf issued");

      --  The premise: the impostor really does look like the issuer by name.
      Check (X509C.Subject_Bytes (Decoded (To_String (Twin_PEM)))
               = X509C.Subject_Bytes (Decoded (To_String (Real_PEM))),
             "fixture: the two CAs encode the same subject name");
      Check (X509C.Issuer_Bytes (Decoded (To_String (Leaf_PEM)))
               = X509C.Subject_Bytes (Decoded (To_String (Twin_PEM))),
             "fixture: the leaf's issuer name matches the impostor too");

      --  The search must look past the name match that fails on signature.
      Search :=
        PB.Build_Path (Decoded (To_String (Leaf_PEM)), Pool'(null record));
      Check (Search.Found,
             "a path is found although the first name match is the wrong key");
      Check (Search.Length = 1,
             "the path is the leaf and one issuer, got"
             & Natural'Image (Search.Length));
      Check (Search.Indices (1) = 3,
             "the issuer chosen is the CA that actually signed the leaf, "
             & "not the one that merely shares its name, got"
             & Natural'Image (Search.Indices (1)));
      Check (Search.Examined >= 2,
             "the search examined the impostor before finding the issuer");

      --  What it found must survive validation, which is the only thing
      --  entitled to conclude anything.
      declare
         Path : constant Built_Path :=
           (Length => Search.Length, Chain => Search.Indices);
         Verdict : constant XV.Validation_Result :=
           XV.Validate_Path
             (Path,
              (Year => 2027, Month => 6, Day => 1,
               Hour => 12, Minute => 0, Second => 0));
      begin
         Check (Verdict.Valid,
                "the path found also validates, got "
                & XV.Failure_Image (Verdict.Failure));
      end;

      --  With only the impostor available there is no path, and saying so is
      --  different from having run out of budget.
      Search :=
        PB.Build_Path
          (Decoded (To_String (Leaf_PEM)), Impostor_Only'(null record));
      Check (not Search.Found,
             "no path is found when only the wrong key is available");
      Check (not Search.Exhausted,
             "and the search finished rather than being cut short");

      --  A budget too small to reach the issuer is reported as such, not as
      --  an absence of paths.
      Search :=
        PB.Build_Path
          (Decoded (To_String (Leaf_PEM)), Pool'(null record),
           (Maximum_Depth => 1, Maximum_Links => 1));
      Check (not Search.Found and then Search.Exhausted,
             "a search stopped by its budget says so");
   end Check_X509_Path_Building;


   --  Certification requests, against ones OpenSSL made and calls
   --  "self-signature verify OK".
   --
   --  The RSA request is the interesting one: the hand-written reader this
   --  replaced knew two algorithms, so an RSA request was simply unreadable.
   procedure Check_PKCS10 is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.X509.Public_Key_Algorithm;
      use type CryptoLib.X509.Signature_Algorithm;
      use type CryptoLib.X509.Signatures.Verification_Result;

      package P10 renames CryptoLib.PKCS10;

      CSR_RSA : constant String :=
        "308202633082014b020100301e311c301a06035504030c137273612e726571756573742e6578616d706c653082" &
        "0122300d06092a864886f70d01010105000382010f003082010a0282010100c1c24293d3566de90f477d154854" &
        "281159fab3eabb92eeb1b4e0f9e00753a8f89b7caa8de4dd45f2ddc013cb0ecb1370507b9b6eabdeff51889bc4" &
        "6e98270250359fc2faef13fc95f25e08ea82b060f8015744f96594b546a43aee73bb11b16c8cb5ff163a43ae0a" &
        "1526ee976813de79a73c1b71102a62e38415bebe127c086674d7bc53acef027b80f03f28a05b0863f953eed88a" &
        "1e7bad9299ca7ccfb60ae1d1def70ac7f28c504758e6c7a0738e02af6f818ef532144198be1ead781a1c70e30c" &
        "b6be02fb0be6a6ccb44eccd90ec9782f5efad9759cbdf50aa846049b7be9720ad60ce347fa4284e13ff088914b" &
        "ecfb5a7d15a91af2f9fcce5d093695c0510203010001a000300d06092a864886f70d01010b050003820101004f" &
        "c18037940cb48d2e21a943e7473e3190c84fc1eaf42d46927c4bcea5b8eaba59997c30544247c8165bdefc9a91" &
        "20d0855021fc80c47cfdc15c2f478e84a22e6b1f39b42ef99609cf67ee5b6ff24ddfdbbe25f4d1e68b8ac1dfb0" &
        "f58167b252ebe9ad17f4e56edc876cd5bcd9d79c3e137d27fe8cbd6091c1de738f3b666e7594b1862f7e63b8c7" &
        "4871ca326027cdf4a10be9bdd3d72e2426368754fd003e1df004e08701ae757cf666b07e69c23f1b0d45764c65" &
        "c7417958bbdb43591fa35caa562427d8b0a1b01e4f9abd265564519e8b9555337c931fb12f0122229b27f02719" &
        "dcc8a98acdd5a49ebcd124326d15595c7b93b3c487eda992d820943dcf1f";

      CSR_EC : constant String :=
        "3081d6307f020100301d311b301906035504030c1265632e726571756573742e6578616d706c65305930130607" &
        "2a8648ce3d020106082a8648ce3d030107034200048065edef6450ae2dd122ee3be6dd3e788e005e20718fd4ca" &
        "9ddcb1932f0abb8de8342e09ed93f3843807090c731e5aa1956f658349545f742a53e0008d0e970aa000300a06" &
        "082a8648ce3d0403020347003044022032a17de60ae9eeaca6e34dc95d4a28a7d6d4546a3fa85051460d510f84" &
        "fc122902204cfa118746d6f0419d522722f0a1a5d6ab34fe24109e33714197275afce901c7";

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

      Status : CryptoLib.ASN1.Errors.Decode_Status;
   begin
      declare
         Item : constant P10.Request :=
           P10.Decode_DER
             (From_Hex (CSR_RSA), CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok and then P10.Is_Present (Item),
                "an RSA request decodes: "
                & CryptoLib.ASN1.Errors.Status_Image (Status));
         Check (P10.Subject_Common_Name (Item) = "rsa.request.example",
                "its subject is read, got " & P10.Subject_Common_Name (Item));
         Check (P10.Public_Key_Algorithm_Of (Item) = CryptoLib.X509.RSA,
                "its key is recognised as RSA");
         Check (P10.Signature_Algorithm_Of (Item)
                  = CryptoLib.X509.SHA256_With_RSA,
                "its signature algorithm is read");
         Check (P10.Verify_Signature (Item)
                  = CryptoLib.X509.Signatures.Valid,
                "the requester proves possession of the key, got "
                & CryptoLib.X509.Signatures.Result_Image
                    (P10.Verify_Signature (Item)));
      end;

      declare
         Item : constant P10.Request :=
           P10.Decode_DER
             (From_Hex (CSR_EC), CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok, "an EC request decodes");
         Check (P10.Public_Key_Algorithm_Of (Item)
                  = CryptoLib.X509.ECDSA_P256,
                "its key is recognised as P-256");
         Check (P10.Verify_Signature (Item)
                  = CryptoLib.X509.Signatures.Valid,
                "and it too proves possession");
      end;

      --  A request altered after signing. The signature covers the name and
      --  the key, so changing either has to break it -- otherwise a request
      --  could be edited in flight to ask for a different name, which is the
      --  attack a CA reads this signature to prevent.
      declare
         Damaged : Ada.Streams.Stream_Element_Array := From_Hex (CSR_EC);
         Broken  : CryptoLib.ASN1.Errors.Decode_Status;
         Where   : Ada.Streams.Stream_Element_Offset := 0;
      begin
         --  Inside the subject's text rather than at an arbitrary offset: a
         --  character changes and every tag and length stays as it was, so
         --  the encoding still parses and only the signature can object.
         for I in Damaged'Range loop
            if I + 2 <= Damaged'Last
              and then Damaged (I) = Character'Pos ('r')
              and then Damaged (I + 1) = Character'Pos ('e')
              and then Damaged (I + 2) = Character'Pos ('q')
            then
               Where := I;
               exit;
            end if;
         end loop;
         Check (Where /= 0, "fixture: the subject text was found");
         Damaged (Where) := Character'Pos ('R');
         declare
            Item : constant P10.Request :=
              P10.Decode_DER
                (Damaged, CryptoLib.ASN1.Default_Limits, Broken);
         begin
            --  Asserted rather than guarded: a tamper that stopped being a
            --  tamper would otherwise skip the check it exists for.
            Check (Broken = CryptoLib.ASN1.Errors.Ok,
                   "the altered request still parses, so the signature is "
                   & "what has to reject it");
            Check (P10.Verify_Signature (Item)
                     /= CryptoLib.X509.Signatures.Valid,
                   "an altered request does not verify");
         end;
      end;

      --  Trailing bytes are refused, as on a certificate.
      declare
         Padded : constant Ada.Streams.Stream_Element_Array :=
           From_Hex (CSR_EC) & [0];
         Item   : constant P10.Request :=
           P10.Decode_DER (Padded, CryptoLib.ASN1.Default_Limits, Status);
         pragma Unreferenced (Item);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Trailing_Data,
                "a byte after the request is refused, got "
                & CryptoLib.ASN1.Errors.Status_Image (Status));
      end;
   end Check_PKCS10;


   --  PKCS#8 private keys, decoded from the structure rather than found by
   --  looking for bytes that resemble a key.
   procedure Check_PKCS8 is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.X509.Public_Key_Algorithm;

      package P8 renames CryptoLib.PKCS8;

      P8_EC : constant String :=
        "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b02010104300dbe7e740d398458dc39" &
        "a3f0d7e71e7132b65e26af9a13766441d3b1c79a30f141700119bb0be582c54a8f09fad2815ba16403620004d8" &
        "e1d6e84534ed29f11bc644c46499728c15b025b8bfbaa8238d053946fed7f22fced5751f61c20208bf534ec12e" &
        "1a8abf3ed710988a642539fd5e33f5da33755b63aad074d171ba133c82b99bfca240d3fd6e5408e0f2ca6b82d5" &
        "c721f9e7d8";

      P8_ED : constant String :=
        "302e020100300506032b65700422042080ab3b0dfee005444ee6adfa364f304e2ae937d00c1d30ce92cfeb3697" &
        "165818";

      P8_ENCRYPTED : constant String :=
        "3082011c305706092a864886f70d01050d304a302906092a864886f70d01050c301c0408284f2424c1ce1bd702" &
        "020800300c06082a864886f70d02090500301d060960864801650304012a04106fb723fb9ef3b3abd27e95015b" &
        "9e9bd40481c05a630d1d00b1af14808281d59b93505214f7d933ee5bf2a6d1d993b50beadc93404590b57d9f2e" &
        "543acae2938d951742ad0f56338ea5f27ae865c8f51cf900aae0c2ccd3bde779e0fe9dde9d8e9fe779c1e34602" &
        "976f3cd7b4320e251fdab8f79b02ac2d1e3093feba822275034d86bff7eaaa46aa7694705b98120138ff47dc89" &
        "68febec15edf5ccbf1749d626c53bca650c92de959bc6425624c83d6ab1e8922191a7e69713e9c4106140c8b98" &
        "91606bda2f21cc102304985001e9ca7e8f07";

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

      Status : CryptoLib.ASN1.Errors.Decode_Status;
   begin
      --  A P-384 key made by OpenSSL. The scalar is the octet string inside
      --  the ECPrivateKey, reached by walking there.
      declare
         Item : P8.Private_Key;
      begin
         P8.Decode_DER
           (From_Hex (P8_EC), CryptoLib.ASN1.Default_Limits, Item, Status);
         Check (Status = CryptoLib.ASN1.Errors.Ok and then P8.Is_Present (Item),
                "an EC private key decodes: "
                & CryptoLib.ASN1.Errors.Status_Image (Status));
         Check (P8.Algorithm_Of (Item) = CryptoLib.X509.ECDSA_P384,
                "its curve is read from the algorithm parameters");
         Check (P8.Private_Value (Item)'Length = 48,
                "a P-384 scalar is 48 octets, got"
                & Natural'Image (Natural (P8.Private_Value (Item)'Length)));

         --  Wiping is not only a matter of scope: it can be asked for.
         P8.Wipe (Item);
         Check (not P8.Is_Present (Item),
                "a wiped key is no longer present");
         Check (P8.Private_Value (Item)'Length = 0,
                "and holds nothing");
      end;

      declare
         Item : P8.Private_Key;
      begin
         P8.Decode_DER
           (From_Hex (P8_ED), CryptoLib.ASN1.Default_Limits, Item, Status);
         Check (Status = CryptoLib.ASN1.Errors.Ok,
                "an Ed25519 private key decodes");
         Check (P8.Algorithm_Of (Item) = CryptoLib.X509.Ed25519,
                "its algorithm is read");
         Check (P8.Private_Value (Item)'Length = 32,
                "the seed is 32 octets, unwrapped from the octet string that "
                & "this one encoding doubles up");
      end;

      --  An encrypted key needs a password, and there is nowhere here to put
      --  one. Refused as unsupported rather than read as if it were plain,
      --  which would yield ciphertext presented as a key.
      declare
         Item : P8.Private_Key;
      begin
         P8.Decode_DER
           (From_Hex (P8_ENCRYPTED), CryptoLib.ASN1.Default_Limits, Item,
            Status);
         Check (Status = CryptoLib.ASN1.Errors.Unsupported_Encoding,
                "an encrypted key is refused as unsupported, got "
                & CryptoLib.ASN1.Errors.Status_Image (Status));
         Check (not P8.Is_Present (Item),
                "and nothing is left behind from the attempt");
      end;

      --  Trailing data, as everywhere else.
      declare
         Item   : P8.Private_Key;
         Padded : constant Ada.Streams.Stream_Element_Array :=
           From_Hex (P8_ED) & [0];
      begin
         P8.Decode_DER
           (Padded, CryptoLib.ASN1.Default_Limits, Item, Status);
         Check (Status = CryptoLib.ASN1.Errors.Trailing_Data,
                "a byte after the key is refused");
      end;
   end Check_PKCS8;


   --  A private scalar is read by its width, not by its first byte.
   --
   --  An SSH mpint pads a value whose top bit is set with a leading zero, so
   --  it is one octet wider than the curve; a raw scalar is exactly the
   --  curve's width whatever its top byte. Reading the first byte instead
   --  refused every raw scalar of 16#80# or above -- about half of the P-384
   --  keys generated anywhere but here, which is why it went unnoticed: this
   --  crate only ever produced scalars the old reading accepted.
   procedure Check_ECDSA_Scalar_Encodings is
      --  Two scalars that differ only in whether the top bit is set, and the
      --  same values written as mpints.
      Low_Raw : constant Ada.Streams.Stream_Element_Array (1 .. 48) :=
        [1 => 16#7F#, others => 16#11#];
      High_Raw : constant Ada.Streams.Stream_Element_Array (1 .. 48) :=
        [1 => 16#C0#, others => 16#11#];
      High_Mpint : constant Ada.Streams.Stream_Element_Array (1 .. 49) :=
        [1 => 16#00#, 2 => 16#C0#, others => 16#11#];

      Low_Point   : Ada.Streams.Stream_Element_Array (1 .. 97);
      High_Point  : Ada.Streams.Stream_Element_Array (1 .. 97);
      Mpint_Point : Ada.Streams.Stream_Element_Array (1 .. 97);
   begin
      Check (CryptoLib.ECDSA.Public_Nistp384_Raw (Low_Raw, Low_Point)
               = CryptoLib.Errors.Ok,
             "a raw scalar whose top bit is clear is read");

      --  The case that used to be refused.
      Check (CryptoLib.ECDSA.Public_Nistp384_Raw (High_Raw, High_Point)
               = CryptoLib.Errors.Ok,
             "a raw scalar whose top bit is set is read too");

      --  And the mpint spelling of that same value still is, which is what
      --  sshlib hands in from an identity file.
      Check (CryptoLib.ECDSA.Public_Nistp384_Raw (High_Mpint, Mpint_Point)
               = CryptoLib.Errors.Ok,
             "the mpint spelling of the same scalar is read");
      Check (High_Point = Mpint_Point,
             "and yields the same public key, because it is the same scalar");

      --  Zero is not a scalar, however it is written.
      declare
         Zero_Raw : constant Ada.Streams.Stream_Element_Array (1 .. 48) :=
           [others => 0];
         Point    : Ada.Streams.Stream_Element_Array (1 .. 97);
      begin
         Check (CryptoLib.ECDSA.Public_Nistp384_Raw (Zero_Raw, Point)
                  /= CryptoLib.Errors.Ok,
                "a zero scalar is refused");
      end;

      --  Wider than the curve, with nothing but padding to remove.
      declare
         Too_Wide : constant Ada.Streams.Stream_Element_Array (1 .. 50) :=
           [1 => 16#01#, others => 16#11#];
         Point    : Ada.Streams.Stream_Element_Array (1 .. 97);
      begin
         Check (CryptoLib.ECDSA.Public_Nistp384_Raw (Too_Wide, Point)
                  /= CryptoLib.Errors.Ok,
                "a value too wide for the curve is refused");
      end;
   end Check_ECDSA_Scalar_Encodings;


   --  A configured identity: a chain and the key that goes with it, checked
   --  before anything tries to use them.
   --
   --  The two failures worth catching are a key that does not belong to the
   --  certificate and a chain assembled the wrong way round. Both are
   --  ordinary configuration mistakes that otherwise surface as a handshake
   --  failing somewhere far from the cause.
   procedure Check_Identities is
      use type CryptoLib.Identities.Identity_Status;
      use type CryptoLib.X509.Public_Key_Algorithm;

      package ID renames CryptoLib.Identities;

      CA_PEM    : Unbounded_String;
      CA_Key    : Unbounded_String;
      Leaf_PEM  : Unbounded_String;
      Leaf_Key  : Unbounded_String;
      Other_PEM : Unbounded_String;
      Other_Key : Unbounded_String;
      Outcome   : CryptoLib.Certificates.Certificate_Status;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("identity-chain-ca", CA_PEM, CA_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "host.example",
           [1 => To_Unbounded_String ("host.example")],
           Leaf_PEM, Leaf_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: leaf issued");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "other.example",
           [1 => To_Unbounded_String ("other.example")],
           Other_PEM, Other_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: other leaf");

      --  Leaf then issuer, which is the order a PEM file and a TLS handshake
      --  both use.
      declare
         Item : ID.Local_Identity;
         St   : ID.Identity_Status;
      begin
         ID.Decode
           (To_String (Leaf_PEM) & To_String (CA_PEM),
            To_String (Leaf_Key), Item, St);
         Check (St = ID.Ok,
                "a chain and its own key check out, got "
                & ID.Status_Image (St));
         Check (ID.Is_Present (Item), "and the identity is present");
         Check (ID.Chain_Length (Item) = 2,
                "both certificates are held, got"
                & Natural'Image (ID.Chain_Length (Item)));
         Check (ID.Key_Algorithm_Of (Item) = CryptoLib.X509.ECDSA_P384,
                "the key algorithm is reported");
         Check (ID.Certificate_Bytes (Item, 1)'Length > 0
                and then ID.Certificate_Bytes (Item, 3)'Length = 0,
                "certificates are addressable and asking past the end is "
                & "empty");

         --  Wiping is not only end of scope.
         ID.Wipe (Item);
         Check (not ID.Is_Present (Item), "a wiped identity is not present");
         Check (ID.Chain_Length (Item) = 0, "and holds no chain");
      end;

      --  A leaf alone is a chain of one, which is ordinary.
      declare
         Item : ID.Local_Identity;
         St   : ID.Identity_Status;
      begin
         ID.Decode (To_String (Leaf_PEM), To_String (Leaf_Key), Item, St);
         Check (St = ID.Ok and then ID.Chain_Length (Item) = 1,
                "a single certificate and its key check out");
      end;

      --  The mistake this exists for: the wrong key.
      declare
         Item : ID.Local_Identity;
         St   : ID.Identity_Status;
      begin
         ID.Decode (To_String (Leaf_PEM), To_String (Other_Key), Item, St);
         Check (St = ID.Key_Mismatch,
                "a key from another certificate is refused, got "
                & ID.Status_Image (St));
         Check (not ID.Is_Present (Item),
                "and nothing is left usable behind it");
      end;

      --  And the other one: the chain upside down.
      declare
         Item : ID.Local_Identity;
         St   : ID.Identity_Status;
      begin
         ID.Decode
           (To_String (CA_PEM) & To_String (Leaf_PEM),
            To_String (Leaf_Key), Item, St);
         Check (St = ID.Chain_Out_Of_Order,
                "a chain in the wrong order is refused, got "
                & ID.Status_Image (St));
      end;

      --  Material that is not there, or not a key.
      declare
         Item : ID.Local_Identity;
         St   : ID.Identity_Status;
      begin
         ID.Decode ("", To_String (Leaf_Key), Item, St);
         Check (St = ID.Empty_Chain, "no certificate is an empty chain");

         ID.Decode (To_String (Leaf_PEM), "", Item, St);
         Check (St = ID.Malformed_Private_Key,
                "no key is a malformed key, got " & ID.Status_Image (St));

         ID.Decode (To_String (Leaf_PEM), To_String (Leaf_PEM), Item, St);
         Check (St = ID.Malformed_Private_Key,
                "a certificate offered as a key is refused");
      end;
   end Check_Identities;


   --  RSASSA-PSS, which states its hash and salt length in its parameters
   --  rather than in its name -- so a verifier that cannot read the
   --  parameters cannot check it at all.
   procedure Check_RSA_PSS is
      use type CryptoLib.X509.Signature_Algorithm;
      use type CryptoLib.X509.Signatures.Verification_Result;
      use type CryptoLib.ASN1.Errors.Decode_Status;

      package X509C renames CryptoLib.X509.Certificates;
      package XS renames CryptoLib.X509.Signatures;

      PSS_Modulus : constant String :=
        "eda66e8e74fd6e04e99282f52f13153b856a59cf6be7b5bddd5473b54eacac4c43e60b2d5bd98e0aa8559439fe" &
        "a7d24389e4cb59a782909127d5661b4ceca2b51ee802688ad9bbaf77871706c55ec8b09343768f6eb6240db647" &
        "4e6dcf4f639559455b94010ed58244a5eccc9066ef4daaac62cbcf3af938a20e8da458a18e8d78edf75ff4d65f" &
        "3eb3bade68f4a0e80848ac60edec51199ecb3490b662e04e692dac129919af92e83bd88f658bd7e48c610845ae" &
        "d7c86b68827de33e31be15cc13ccdda683c64d015919d47da0e552860295101086c547e2a6aaeaba65d844ddaf" &
        "5658dc61b0a97187fb0fa2b1a7176d1028f70739d67a5ae9ae410c4b60befb";

      PSS_Signature : constant String :=
        "604e628b09500e7271e6c38a37959ff5f868a4854d199ee9f7479b2933673a744b08cfd01364701899b36cad8c" &
        "414d568c31a2b8ec2259c8a5b83c29d69153ee52435becb74352ee6e6fb36ac352ca6eef9ebe07888901f02293" &
        "cf536a12f8ba2398417c9d3ea1d418c51444b602758559e9f064db94a9ebb21fb49eee88a8071a77ce3625b32c" &
        "1c6c516ae590b51f71c6a81d40836362c5c9249462d6ec6b907e51c27f3a3edf52b42b42fb3b6c01f99976d739" &
        "bd5ba56a09fc7ad3835961ac9439d8cd678c2b0b5245c493fef468b5c926163000f6df15cd35c17fc2e290e2d3" &
        "377f7ff6f7cf875423e5ea74d7dc9e448ee5fea36d0507ac93e4ea4dc6c8f9";

      PSS_CA_DER : constant String :=
        "3082037530820229a00302010202145d794958f07d3b709cb0cc15cdbbb2c61a346f84304106092a864886f70d" &
        "01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d060960864801" &
        "65030402010500a20302012030163114301206035504030c0b7073732d746573742d6361301e170d3236303732" &
        "383231303733375a170d3336303732353231303733375a30163114301206035504030c0b7073732d746573742d" &
        "636130820122300d06092a864886f70d01010105000382010f003082010a0282010100b2add9660ccbe5aefc7e" &
        "414bb23729467cb2420ab007af7c854c68814ec9a74b1f8f79ca3cf5e4e2463b718f0d3f214c8c4e2fd7f56273" &
        "823c098b50c91cc946e5f7c697181913f203b7d365858b68621ad65c60c18173aed321248f082aa88dbc1811d0" &
        "5349a3cf2d3586ef110eba19945851eb9bc854a1ef40443d3e02d0c7a3d42b80767a333c0c8988c5259ac69a18" &
        "ea13dad1da10be872dbbd1b05c3cfe1a6f4db2472efa8c32aa5738007ef8850f5563f52dcea492a026985ccbe0" &
        "fc2c26fe4c9a4a6b68175da28ca90138ff71e12df36a2190e7990a97b659ac2b9554cd86db2aa9518f25b0b9bc" &
        "7f923f7ea91c8d76e39578dfdc91a2a4ab7294c3b30203010001a3533051301d0603551d0e04160414a5225ecd" &
        "549c29086a28891c4a7f05174fbf3efd301f0603551d23041830168014a5225ecd549c29086a28891c4a7f0517" &
        "4fbf3efd300f0603551d130101ff040530030101ff304106092a864886f70d01010a3034a00f300d0609608648" &
        "0165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a2030201200382" &
        "0101004b675897eb67b837796ae813228fa313623e1760bdf18e03228a3ab9d9e51e350dbda13814380350edd2" &
        "9c872a17e0e5da1e638729afb0297e46b5722f2d48b22a511e997835f6f06f40cd074613801dbcf17b8b550700" &
        "c0fb6165458484e0d75b172bb3e6412da6482b63d7f6bd52f615019406ebb2c27d8707dd8b76c91ba93d15882f" &
        "1f0d86ad4b1f78c694859e7572b192aac722ca6549bf896a4925f914320ca166cdf2db06bd613a3c59428c739c" &
        "ec06bff0731e13868719dadaa4d4c47b702b3a0e16be1aa2caa3006d57624727caf698f81713d4143db3de18e8" &
        "d77dca9126a42366ef8c32b17ec3c1d583db529c87c9aa2f0e2446778859a162e66d";

      PSS_Leaf_DER : constant String :=
        "30820320308201d402147b1e0382ff4548786567e183e4cb80a05746a51b304106092a864886f70d01010a3034" &
        "a00f300d06096086480165030402020500a11c301a06092a864886f70d010108300d0609608648016503040202" &
        "0500a20302013030163114301206035504030c0b7073732d746573742d6361301e170d32363037323832313037" &
        "33375a170d3237303732383231303733375a301b3119301706035504030c106c6561662e7073732e6578616d70" &
        "6c6530820122300d06092a864886f70d01010105000382010f003082010a0282010100c2595197dd4fa8f39583" &
        "0f476d4fdd4b7e6c5b1197fe40c2de95ec19b67db230d371b70cc22da4a3c064000466838cb12b5b4a213aed52" &
        "9e2e7e6c9429d8c988a04f80ecda5f88f662858599f0ae70bf3ecd39c85cbac0bb19cf89f24dcd3f2826f89bbc" &
        "01c6e4002a7510e17cb005c4ae7544dfb032522294c986159a42feb100e4577ab99f09364e86e51e7505114b30" &
        "da291e13a21b8b59827f6830e8bf1758dac0d6fbbcb0de2ec94ebe3ab69f2fc6ef6fd94fa7a3ef6f2b4f4ce1f9" &
        "0656d9e7a738d10c9fff35b3023e484be147f857a2fbac6c27e22c114a05836938be804212e915b8462a7e37be" &
        "df4e21590cadadf274210609db48f603490484c26f0203010001304106092a864886f70d01010a3034a00f300d" &
        "06096086480165030402020500a11c301a06092a864886f70d010108300d06096086480165030402020500a203" &
        "020130038201010095480a4c24178b4da8dc41eee3a2e96eeeb038cf3c55d5eef9058be3f3aa898edef7b213be" &
        "01a14349e5be88c9413055cb5dee0b09a64d8f680af9f24d4b1c705952cbc4aeb5f5c8d6278cd6603fa85419a5" &
        "b16e47f60ea9b9df5d862fa8cde41b816abe749f4a832bfa403b5b7c2ef501a2379b7d253bbfb2ca881ec6bd12" &
        "7bb81d458703e34cc1b8fafe8599adb248772b1fe94a3d26fcdac3594ed136571de7628856388df990409356ef" &
        "4527f083f8f1d210db78a648e5d7abb84ea55a5622ae3a212fcf83e3be46e0b2387814613e4fdb93d7b67307c6" &
        "2009ede9e1ed3a6ef11558f8c9c7e7347171ec8679f98d37795738e109db934750188668e98e8e";

      Message : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("cryptolib pss known answer");
      Exponent : constant Ada.Streams.Stream_Element_Array :=
        [16#01#, 16#00#, 16#01#];

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

      Modulus   : constant Ada.Streams.Stream_Element_Array :=
        From_Hex (PSS_Modulus);
      Signature : constant Ada.Streams.Stream_Element_Array :=
        From_Hex (PSS_Signature);
      Status    : CryptoLib.ASN1.Errors.Decode_Status;
   begin
      Check (CryptoLib.RSA.Verify_PSS
               (Modulus, Exponent, CryptoLib.RSA.SHA256, 32,
                Message, Signature) = CryptoLib.Errors.Ok,
             "an OpenSSL PSS signature verifies");

      --  The salt length is part of what was signed, not a hint. Accepting
      --  whatever length turns up would let a signature be reinterpreted
      --  under a salt its issuer did not choose.
      Check (CryptoLib.RSA.Verify_PSS
               (Modulus, Exponent, CryptoLib.RSA.SHA256, 20,
                Message, Signature)
               = CryptoLib.Errors.Authentication_Failed,
             "the same signature does not verify under a different salt "
             & "length");

      Check (CryptoLib.RSA.Verify_PSS
               (Modulus, Exponent, CryptoLib.RSA.SHA384, 32,
                Message, Signature)
               = CryptoLib.Errors.Authentication_Failed,
             "nor under a different hash");

      declare
         Tampered : Ada.Streams.Stream_Element_Array := Signature;
      begin
         Tampered (Tampered'Last) := Tampered (Tampered'Last) xor 1;
         Check (CryptoLib.RSA.Verify_PSS
                  (Modulus, Exponent, CryptoLib.RSA.SHA256, 32,
                   Message, Tampered)
                  = CryptoLib.Errors.Authentication_Failed,
                "a tampered PSS signature does not verify");
      end;

      --  End to end: a chain OpenSSL signed with PSS, whose two certificates
      --  use different hashes and salt lengths, so the parameters have to be
      --  read per certificate rather than assumed once.
      declare
         CA : constant X509C.Certificate :=
           X509C.Decode_DER
             (From_Hex (PSS_CA_DER), CryptoLib.ASN1.Default_Limits, Status);
         Leaf : constant X509C.Certificate :=
           X509C.Decode_DER
             (From_Hex (PSS_Leaf_DER), CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (X509C.Is_Present (CA) and then X509C.Is_Present (Leaf),
                "the PSS certificates decode");
         Check (X509C.Signature_Algorithm_Of (Leaf)
                  = CryptoLib.X509.RSASSA_PSS,
                "the leaf is signed with PSS");
         Check (X509C.Signature_Parameters (Leaf)'Length > 0,
                "and its parameters are kept, since the name does not say "
                & "which hash it used");

         Check (XS.Is_Supported (CryptoLib.X509.RSASSA_PSS),
                "PSS is now a signature this crate can check");
         Check (XS.Verify_Certificate_Signature (Leaf, CA) = XS.Valid,
                "a PSS leaf verifies under its PSS CA, got "
                & XS.Result_Image (XS.Verify_Certificate_Signature (Leaf, CA)));
         Check (XS.Verify_Certificate_Signature (CA, CA) = XS.Valid,
                "and the CA under its own key");
         Check (XS.Verify_Certificate_Signature (Leaf, Leaf)
                  = XS.Invalid_Signature,
                "while the leaf is not signed by itself");
      end;
   end Check_RSA_PSS;


   --  Revocation answered from material the caller already has, and judged
   --  for freshness -- which nothing was doing before. A statement made years
   --  ago saying a certificate was fine says nothing about now, and reading
   --  it as though it did is how a revoked certificate keeps working.
   procedure Check_Revocation is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.X509.Revocation.Revocation_Answer;

      package X509C renames CryptoLib.X509.Certificates;
      package XR renames CryptoLib.X509.Revocation;

      --  The same CA, revoked leaf, CRL and OCSP responses the earlier tests
      --  use, all made by OpenSSL through "openssl ca -revoke".
      CRL_DER : constant String :=
        "308201863070020101300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d74657374" &
        "2d6361170d3236303732383230313534375a170d3236303832373230313534375a3015301302021000170d3236" &
        "303732383230313534375aa00f300d300b0603551d14040402021000300d06092a864886f70d01010b05000382" &
        "0101006658640fbac6a1af6d6ae781e8565bde72e4d010700077d31961e4927583013585ed7dbe4fc3a86e1a5f" &
        "ad9bfd07334f077af62093de31acb5c1d137d1a25e67ba5d7faa7330cb422947461d2a395068594ddde4f739be" &
        "3bd345e04807299af988b58413704b2227863de0cfdfc8eb4090620bb5f299a7952a194ba4d273d6453c7cb9d0" &
        "d5ddab9a0365ebe032d1abfb3a10bed8a02d52aff966391e0bef4601150fccf121628bdbf5302e155cbc492ced" &
        "d9b07a9d8faf65476f1e3494ca0835eaaa97ea86bd0e0c4aa0f63584a3829891fc7a8b9d79522ed10c8d627a69" &
        "a018f0630976bf890136c61568406f615df99b62cd3db8eb62fbe778914516b4d902";

      CRL_CA_DER : constant String :=
        "3082030d308201f5a0030201020214695a2eb222fd6509af65d97b7099306d68b399eb300d06092a864886f70d" &
        "01010b050030163114301206035504030c0b63726c2d746573742d6361301e170d323630373238323031353437" &
        "5a170d3336303732353230313534375a30163114301206035504030c0b63726c2d746573742d63613082012230" &
        "0d06092a864886f70d01010105000382010f003082010a0282010100b5e60ee7058f7f9e991a038feeac5eb95d" &
        "99b6b52f543a4cf379d9b84ab68125a82424b27f07a1f6a39f6f6e5ac4df194a06d3683fafc31123427f768f60" &
        "24aa6b2d5f759d0629a578497370038d70020ea20e261a913c332504d70327b2cd747a2ae0f415764976ae21d8" &
        "c34874405cfabefd83ffc5b03de5c6521a611c333189ead8755a0bf56113ad088deb953cf1febb465a377d256b" &
        "ad055bf627727ccfffa616cfe8edc009a49f318a6c1e935dc42b69ab1d2aa9ee2173defdf45fbb595b99aced52" &
        "9fca129587fac967025980f7617070edde4748fa62cd395a608475ba22bd65c29f1fabdefe5e8aeed28baa1703" &
        "88bca8bb6490db6bacea3473ed8f0203010001a3533051301d0603551d0e04160414a1f6d41f7e7b24380aa8a0" &
        "cd33926e4452de852f301f0603551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300f06" &
        "03551d130101ff040530030101ff300d06092a864886f70d01010b050003820101005f484fd12f7d522aa3787c" &
        "0ee05c3e06067d91b3f51a3747e1ffcd7d57e839f17a9bfcf878faa9c4af435426aa06ed4907dfb9c29ca36c6b" &
        "53af27ce22516b5bd4cb19e9d912893e3800a1f7acc3abefbc18a6c899793b6ff9d378f2a77e0feb03659f8a24" &
        "09bee7a4804773be1f8428608fb9041ac74581b1943d0d90dd2939be1b74015bcd676cf483167988523fba452b" &
        "255b49146d3c5be21408d8c9848f6794a4fa588ab2d6d326bc7d92920c3547d3f4d9270c01ec4d368c98e11a61" &
        "1f40cd6672de148b3bf435f812eda7e9e5d383ff2eefcf1384d136c45b1c062f731fc3414a237cf1b971994cce" &
        "d2b6852b3f4314e9335fc96ba21fd8949c58f5c5";

      CRL_Leaf_DER : constant String :=
        "308202a53082018d02021000300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d74" &
        "6573742d6361301e170d3236303732383230313534375a170d3237303732383230313534375a301a3118301606" &
        "035504030c0f7265766f6b65642e6578616d706c6530820122300d06092a864886f70d01010105000382010f00" &
        "3082010a0282010100c0ed219d3150260bb4a5a976fd93941636a1dcdc8976321a5c82e468c74ff7e755f29a69" &
        "40524606cf7e70308e8c3ed01c6954e7e7a45fdedd1d914b6cf2459cbba0b0a2f3a248771f69301ac2735a408a" &
        "f830e03b7c3941648de0810c102c79f17da1d486a3b676993fd30102ed86ee4d4cde770d3abf8dd4b178885132" &
        "f79e8799c63595af16af350d94207d96a5d830c19e2eff9edb43607e7c8e5ba3e737b82f71937a7ca59ffcac9d" &
        "fc633aa69ce1e08aabf84a068c4e1dfa9f7ca28f959062408140c1c8cf63d66761609bc2dff8b3d4bd3250ee0a" &
        "86b507023e9f9aee80b2184c01758ffaf3c280eeeff0fb0926de9c83cfc2f327c4dcd6254a0447150203010001" &
        "300d06092a864886f70d01010b0500038201010080e42f4484be128c22efd3e63c0ea74f0efc8937b0a9529a0d" &
        "90efd502c75e3647fa117adca923af965a184fa141d74ce910ad9fbed2fb1f1eb295f9cd28ebff73c6b8ea6ace" &
        "a4d54009be31e34a52fa63c4277ebe37865d16ce20d7776ff9dbfee953305678b1dc967f59f836b6fc5ce4f166" &
        "c3e4d20a992bbdb0b2ac53f8c8a23b9176097ae12e84bcebe9e81b77da3571a2f2bcf77d7e516102c37352c1e0" &
        "fba2439d98a01280abcefe8a91b5857a2f515e6ae71c14f10fa56fb4710798b987f0a0b89a2510995a6f6cfa27" &
        "2f10d60bcd56e3add0eb664aaa565ee2471a1f5b00eae79e62e58b987db98503855bb0bd82b803d2b7ee27f40c" &
        "f62c878f5876";

      OCSP_Direct : constant String :=
        "308204de0a0100a08204d7308204d306092b0601050507300101048204c4308204c0308190a118301631143012" &
        "06035504030c0b63726c2d746573742d6361180f32303236303732383230323335385a30633061303b30090605" &
        "2b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b24380aa8a0cd3392" &
        "6e4452de852f02021000a111180f32303236303732383230313534375a180f3230323630373238323032333538" &
        "5a300d06092a864886f70d01010b05000382010100862fd17f69d414772feb68610edde88340d444547f7e017a" &
        "efab65e16849a6bd80267d5e624d5bdc87f5d6434ab54062c31f42ecaa312ad9a748c695c0d9d2e347dc540697" &
        "5ec19765aa29f2c3ba9376a21127c69294df5eb7adf737ebe67b2d68f7902a3e52a9853dcc3ef610046bf4a501" &
        "0d68c20b943c3dd04347b08a14be4b4e41c768e86784909e0d6bc36f09472ef4fb68025e5f92eecb0e9f816386" &
        "55c57d49f1b8b4931eccf246a8e342a83dd8b52ea209524956c4f3ab3ed05ca51d25fb648fb3218ee3516653d1" &
        "cf10b640ac0c3b561087977344d0a7ad93f276f89a19a8b667fd389b3650b83fe4183cf51ae996640d687a40b4" &
        "2faf4d10f5619ea0820315308203113082030d308201f5a0030201020214695a2eb222fd6509af65d97b709930" &
        "6d68b399eb300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d746573742d636130" &
        "1e170d3236303732383230313534375a170d3336303732353230313534375a30163114301206035504030c0b63" &
        "726c2d746573742d636130820122300d06092a864886f70d01010105000382010f003082010a0282010100b5e6" &
        "0ee7058f7f9e991a038feeac5eb95d99b6b52f543a4cf379d9b84ab68125a82424b27f07a1f6a39f6f6e5ac4df" &
        "194a06d3683fafc31123427f768f6024aa6b2d5f759d0629a578497370038d70020ea20e261a913c332504d703" &
        "27b2cd747a2ae0f415764976ae21d8c34874405cfabefd83ffc5b03de5c6521a611c333189ead8755a0bf56113" &
        "ad088deb953cf1febb465a377d256bad055bf627727ccfffa616cfe8edc009a49f318a6c1e935dc42b69ab1d2a" &
        "a9ee2173defdf45fbb595b99aced529fca129587fac967025980f7617070edde4748fa62cd395a608475ba22bd" &
        "65c29f1fabdefe5e8aeed28baa170388bca8bb6490db6bacea3473ed8f0203010001a3533051301d0603551d0e" &
        "04160414a1f6d41f7e7b24380aa8a0cd33926e4452de852f301f0603551d23041830168014a1f6d41f7e7b2438" &
        "0aa8a0cd33926e4452de852f300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003" &
        "820101005f484fd12f7d522aa3787c0ee05c3e06067d91b3f51a3747e1ffcd7d57e839f17a9bfcf878faa9c4af" &
        "435426aa06ed4907dfb9c29ca36c6b53af27ce22516b5bd4cb19e9d912893e3800a1f7acc3abefbc18a6c89979" &
        "3b6ff9d378f2a77e0feb03659f8a2409bee7a4804773be1f8428608fb9041ac74581b1943d0d90dd2939be1b74" &
        "015bcd676cf483167988523fba452b255b49146d3c5be21408d8c9848f6794a4fa588ab2d6d326bc7d92920c35" &
        "47d3f4d9270c01ec4d368c98e11a611f40cd6672de148b3bf435f812eda7e9e5d383ff2eefcf1384d136c45b1c" &
        "062f731fc3414a237cf1b971994cced2b6852b3f4314e9335fc96ba21fd8949c58f5c5";

      OCSP_Unauthorized : constant String :=
        "3082050c0a0100a08205053082050106092b0601050507300101048204f2308204ee308196a11e301c311a3018" &
        "06035504030c116e6f746f6373702d726573706f6e646572180f32303236303732383230323431345a30633061" &
        "303b300906052b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b2438" &
        "0aa8a0cd33926e4452de852f02021000a111180f32303236303732383230313534375a180f3230323630373238" &
        "3230323431345a300d06092a864886f70d01010b050003820101003efd3a59e9a03c2805dfbdcf26a8cd69030b" &
        "f0b8ce62077c1a1bb41fa48a7a057fce3a66620e77c8d4b94c900d60e1d571fdbe63885930bdc90c57cd70c27a" &
        "8ebf532a48e349f9815238bed4ae6c74e91c12b5d1a46b2597e88ac38b844bebbfb80e10542e0f054a74f39720" &
        "05b9161b2ce6d81e5013f0c4526695d228983d426b74771432b1407cb26e7f517ff6742a562c884c5aad5d5162" &
        "21adc1f9a277ae81b718ad0a10a55b2cbce9d76bde99f6dc9d386701574cb9273a1b1a708ca7d09eb20eea15ec" &
        "2d71b2f0abe87b2bd8ea5642cbf88fdd89d91b757bced088d1e4bca01dd9aad9fa99c8ab3d5c4c5fe2fc505360" &
        "458c7e4237a2c11f15ed7f6075a082033d30820339308203353082021da003020102021444aab1aa260bfa011e" &
        "9556a81fcac713d43514b7300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d7465" &
        "73742d6361301e170d3236303732383230323431345a170d3237303732383230323431345a301c311a30180603" &
        "5504030c116e6f746f6373702d726573706f6e64657230820122300d06092a864886f70d01010105000382010f" &
        "003082010a0282010100c491c573ae839cb45ecb75d47f2ee41bc065ae9ac39fd7afd4f5cd4d7e89b400a7a79e" &
        "a43a2c43a05cb58e21d352370dc4d2956c4a709881048aafcd9e3d9c6a72aa007f6a259f43df29f8266532ae82" &
        "7cda39eeeafd679d1ceb61decd7bf001ba1678361cd24a53ce9173af7998f0498c73cf279ed10996c9bee9350b" &
        "c4137886fd8147c3402fc31447f03bffde66f34846635843750384edeeaa53aeb8b838fa8ab77f60a1f5a3e0e0" &
        "57991dd329172f19bc27db6a197ca7dd0b6ecb9b3c3455bd4c961ddb9d96ec27ee13367135de9567f041ea418f" &
        "bdb7df415504cabedbffa399a9f3a044bb9f1c0e473df09b22386d1cf2258a9b78ee21800ece10801502030100" &
        "01a375307330090603551d1304023000300e0603551d0f0101ff04040302078030160603551d250101ff040c30" &
        "0a06082b06010505070301301d0603551d0e041604146ad1ce7fdde3bfe17e9475437ce287f6a1b1f787301f06" &
        "03551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300d06092a864886f70d01010b0500" &
        "038201010064cf0f298af11571ae94fed30d1d5d06dacd42eea12c67ff6314a8ce09022033055285288afdbe17" &
        "4c219b8353b4cf08474ad7b98d0cfe39b89786822a712cf5bcfac43ea9469c0764d8d855fd8c0e433a478f9fbf" &
        "bc44a4ae55765959d634b2049200d96b4583d4815987808a8fed6a00fd9c4bca8bbaa94b35866393bc56238e5b" &
        "e6cc4b57faf9318df531ed1ac623f546f05fc72b168174b6211f65564bebccdeb3a87332bc76c84fffe8722525" &
        "e90a24602ea7bb0c5ccc21d5190bf9ddbeee2603064d2d4f18be78400151956112375b19f87a5a09eb4a63cd12" &
        "8dc20797b0fcf9cd0ab02d7b3aa89591c00bfd50b2006b51bd6aab88bd9eebc1f91109b0";

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

      Status : CryptoLib.ASN1.Errors.Decode_Status;

      CA : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (CRL_CA_DER), CryptoLib.ASN1.Default_Limits, Status);
      Leaf : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (CRL_Leaf_DER), CryptoLib.ASN1.Default_Limits, Status);
      List : constant CryptoLib.X509.CRLs.Revocation_List :=
        CryptoLib.X509.CRLs.Decode_DER
          (From_Hex (CRL_DER), CryptoLib.ASN1.Default_Limits, Status);

      --  The CRL was issued in July 2026 and is due to be replaced a month
      --  later, so these three times sit before, inside and after its window.
      Before : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 1, Day => 1,
         Hour => 0, Minute => 0, Second => 0);
      Inside : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 8, Day => 1,
         Hour => 0, Minute => 0, Second => 0);
      After  : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2027, Month => 1, Day => 1,
         Hour => 0, Minute => 0, Second => 0);
   begin
      Check (X509C.Is_Present (CA) and then X509C.Is_Present (Leaf),
             "fixture: the certificates decode");

      --  Inside the window, the list revokes the certificate it revoked.
      Check (XR.Check_Against_CRL (Leaf, CA, List, Inside) = XR.Revoked,
             "a current list reports the revoked certificate, got "
             & XR.Answer_Image (XR.Check_Against_CRL (Leaf, CA, List, Inside)));

      --  Outside it, the list says nothing about now -- in either direction.
      Check (XR.Check_Against_CRL (Leaf, CA, List, Before) = XR.Stale,
             "a list issued after the time asked about is stale, got "
             & XR.Answer_Image (XR.Check_Against_CRL (Leaf, CA, List, Before)));
      Check (XR.Check_Against_CRL (Leaf, CA, List, After) = XR.Stale,
             "a list past its nextUpdate is stale, got "
             & XR.Answer_Image (XR.Check_Against_CRL (Leaf, CA, List, After)));

      --  A list about another issuer's certificates says nothing about this
      --  one, however well it is signed.
      Check (XR.Check_Against_CRL (CA, Leaf, List, Inside) = XR.Wrong_Issuer,
             "a list is refused for a certificate whose issuer it is not "
             & "about, got "
             & XR.Answer_Image (XR.Check_Against_CRL (CA, Leaf, List, Inside)));

      --  And the OCSP responses, which carry their own window.
      declare
         Direct : CryptoLib.OCSP.Response :=
           CryptoLib.OCSP.Decode_Response
             (From_Hex (OCSP_Direct), CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (XR.Check_Against_OCSP (Leaf, CA, Direct, Inside) = XR.Revoked,
                "a current response reports the revoked certificate, got "
                & XR.Answer_Image
                    (XR.Check_Against_OCSP (Leaf, CA, Direct, Inside)));
      end;

      declare
         Direct : CryptoLib.OCSP.Response :=
           CryptoLib.OCSP.Decode_Response
             (From_Hex (OCSP_Direct), CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (XR.Check_Against_OCSP (Leaf, CA, Direct, Before) = XR.Stale,
                "a response from after the time asked about is stale");
      end;

      --  A responder the issuer never authorised is not an answer at all.
      declare
         Rogue : CryptoLib.OCSP.Response :=
           CryptoLib.OCSP.Decode_Response
             (From_Hex (OCSP_Unauthorized), CryptoLib.ASN1.Default_Limits,
              Status);
      begin
         Check (XR.Check_Against_OCSP (Leaf, CA, Rogue, Inside)
                  = XR.Untrusted_Signature,
                "an unauthorized responder's answer is not trusted, got "
                & XR.Answer_Image
                    (XR.Check_Against_OCSP (Leaf, CA, Rogue, Inside)));
      end;
   end Check_Revocation;


   --  Encrypted PKCS#8, which is how a private key is usually stored when it
   --  is stored at all.
   procedure Check_PKCS8_Encrypted is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.PKCS8.Unlock_Status;
      use type CryptoLib.X509.Public_Key_Algorithm;

      package P8 renames CryptoLib.PKCS8;

      Enc_AES256_SHA256 : constant String :=
        "3082011c305706092a864886f70d01050d304a302906092a864886f70d01050c301c0408df34818c3c3c80a202" &
        "020800300c06082a864886f70d02090500301d060960864801650304012a041006fdcf33c7464bdca2fa561a76" &
        "a00ef70481c00128f1659941272ed217c3593b453df712ac47e26e769eba6219b81be2c99312221bac341c46bb" &
        "d4ce9679b6709504ab612214d770f8851d4acab66a78860b54ec047a5f2918be4cac36033411285de399123f34" &
        "9a35ed38497670f0cc9b18311cf771e3df5a5c9af377d7b62dbbd83c16bc4444d14102424b8c9d6e9895987cb6" &
        "5c1a27a6add7f081ff703de76aacc7dfa40852ee6dd6110ddb32e5dc91346c1ff29d8b0285647c14357de6972e" &
        "59437e826e896351c0430a25151763d60a41";

      Enc_AES128_SHA256 : constant String :=
        "3082011c305706092a864886f70d01050d304a302906092a864886f70d01050c301c040857868de5f9d6e0c102" &
        "020800300c06082a864886f70d02090500301d06096086480165030401020410247e74d67631454ced2016b9b4" &
        "65b8380481c0992e4ccba11bb6d3c02440b5b71aef8528f7cd55fb1294aee05f338b05eea055112bdb5b312053" &
        "5ac985bcdd51a0a7fafafac751766e6c5e636818a5ab3ef1fa0b557f90fcf90d2565d50263bedd270bd0af4dbb" &
        "76150606db97ad3486e0509a20f75a8015e6cde6aad9ea451e13be85f66159a0f66899c1b345f15199e50d98e9" &
        "3230073ee61c4826680cb09dd94f088d0e411487ad611d1179afe4d928befa8f2000e20b39e2acaedf1a86a4e2" &
        "8385bdde0e38a759d3bbf49f291453aa319a";

      Enc_AES256_SHA1 : constant String :=
        "3082011c305706092a864886f70d01050d304a302906092a864886f70d01050c301c04088effc7d368f0ae4202" &
        "020800300c06082a864886f70d02090500301d060960864801650304012a0410adbe6acbca7a9cd8c22c289b3c" &
        "5a14750481c0e2c9a9c43c182a05c1613d30c9127642b2a65aebdb9b53a45cb3aa9aeb9d85747664d70aa8125a" &
        "b29562acf5e96cdbfd904c445c23725b9fe42ab9e092dcdca993a70c73150a6c220fae6858905bc804df74f605" &
        "43236a390b5707858caf30d8489ac4cd0643841ce658f997fd483b359a59b9047c775f242752b05d59be6318ec" &
        "62b44723e089039e77340800cc7f1b7d44c2bc9e535bbff3aa0f327e5c7024b6c997472faf6839daa7a92ca09d" &
        "7e6823d3f34e04b2dc0bac4c946dfce8c062";

      Enc_Ed25519 : constant String :=
        "30819b305706092a864886f70d01050d304a302906092a864886f70d01050c301c040806b7d23f573e40950202" &
        "0800300c06082a864886f70d020b0500301d060960864801650304012a041033efd4612f61a77cf17e2a339875" &
        "bc800440ef28f1ea1c4b1dbfc9d4e6eb9eaa0e629d4ca045484862db42fcfa101bf3ced85fd0ae9862399c8716" &
        "4bda482f82cb02b73538967572ac02ec051ada2d0a9aee";

      Expected_Scalar : constant String :=
        "0dbe7e740d398458dc39a3f0d7e71e7132b65e26af9a13766441d3b1c79a30f141700119bb0be582c54a8f09fad2815b";

      P8_EC : constant String :=
        "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b02010104300dbe7e740d398458dc39" &
        "a3f0d7e71e7132b65e26af9a13766441d3b1c79a30f141700119bb0be582c54a8f09fad2815ba16403620004d8" &
        "e1d6e84534ed29f11bc644c46499728c15b025b8bfbaa8238d053946fed7f22fced5751f61c20208bf534ec12e" &
        "1a8abf3ed710988a642539fd5e33f5da33755b63aad074d171ba133c82b99bfca240d3fd6e5408e0f2ca6b82d5" &
        "c721f9e7d8";

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

      procedure Check_Scheme (Encoded : String; Label : String) is
         Item : P8.Private_Key;
         St   : P8.Unlock_Status;
      begin
         P8.Decode_Encrypted_DER
           (From_Hex (Encoded), "secret", CryptoLib.ASN1.Default_Limits,
            Item, St);
         Check (St = P8.Ok,
                Label & " opens with the right password, got "
                & P8.Unlock_Image (St));

         --  The right key, not merely something that parses. A wrong key that
         --  happened to decode would pass every test but this one.
         Check (P8.Private_Value (Item) = From_Hex (Expected_Scalar),
                Label & " recovers the scalar OpenSSL holds");

         P8.Decode_Encrypted_DER
           (From_Hex (Encoded), "wrong", CryptoLib.ASN1.Default_Limits,
            Item, St);
         Check (St = P8.Wrong_Password_Or_Corrupt,
                Label & " refuses a wrong password, got "
                & P8.Unlock_Image (St));
         Check (not P8.Is_Present (Item),
                Label & " leaves nothing behind after refusing");
      end Check_Scheme;
   begin
      --  The combinations OpenSSL writes: two key sizes, and the PRF both
      --  named and defaulted.
      Check_Scheme (Enc_AES256_SHA256, "AES-256 with HMAC-SHA256");
      Check_Scheme (Enc_AES128_SHA256, "AES-128 with HMAC-SHA256");
      Check_Scheme (Enc_AES256_SHA1, "AES-256 with the default PRF");

      declare
         Item : P8.Private_Key;
         St   : P8.Unlock_Status;
      begin
         P8.Decode_Encrypted_DER
           (From_Hex (Enc_Ed25519), "secret", CryptoLib.ASN1.Default_Limits,
            Item, St);
         Check (St = P8.Ok
                and then P8.Algorithm_Of (Item) = CryptoLib.X509.Ed25519
                and then P8.Private_Value (Item)'Length = 32,
                "an encrypted Ed25519 key opens to its seed, got "
                & P8.Unlock_Image (St));
      end;

      --  An iteration count is a number in a file somebody else wrote.
      --  Honouring an enormous one is doing what that file says.
      declare
         Item : P8.Private_Key;
         St   : P8.Unlock_Status;
      begin
         P8.Decode_Encrypted_DER
           (From_Hex (Enc_AES256_SHA256), "secret",
            CryptoLib.ASN1.Default_Limits, Item, St,
            Maximum_Iterations => 1);
         Check (St = P8.Excessive_Iterations,
                "work beyond the caller's limit is refused before it is "
                & "done, got " & P8.Unlock_Image (St));
      end;

      --  A plain key handed to the encrypted reader, and an encrypted one
      --  handed to the plain reader. Neither should be mistaken for the
      --  other.
      declare
         Item   : P8.Private_Key;
         St     : P8.Unlock_Status;
         Parse  : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         P8.Decode_Encrypted_DER
           (From_Hex (P8_EC), "secret", CryptoLib.ASN1.Default_Limits,
            Item, St);
         Check (St /= P8.Ok,
                "a plain key is not opened as an encrypted one");

         P8.Decode_DER
           (From_Hex (Enc_AES256_SHA256), CryptoLib.ASN1.Default_Limits,
            Item, Parse);
         Check (Parse = CryptoLib.ASN1.Errors.Unsupported_Encoding,
                "an encrypted key is refused by the plain reader rather "
                & "than read as though it were plain");
      end;
   end Check_PKCS8_Encrypted;


   --  Reading a PKCS#12 bundle, which this crate could write and not read --
   --  the kind of asymmetry that leaves a caller unable to check what it just
   --  produced.
   procedure Check_PKCS12 is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.PKCS12.Open_Status;
      use type CryptoLib.X509.Public_Key_Algorithm;

      package X509C renames CryptoLib.X509.Certificates;
      package P12 renames CryptoLib.PKCS12;

      OpenSSL_Bundle : constant String :=
        "30820cbf02010330820c8506092a864886f70d010701a0820c7604820c7230820c6e308206e206092a864886f7" &
        "0d010706a08206d3308206cf020100308206c806092a864886f70d010701305706092a864886f70d01050d304a" &
        "302906092a864886f70d01050c301c040839469ec75087e37902020800300c06082a864886f70d02090500301d" &
        "060960864801650304012a0410132fc7eb0141c3dfbdb906a4d869655b8082066057c51abbe81587124880906d" &
        "d798e12b0fef0e98140c64ad59d75e522cd9888486d43f2dcb0ae36d084726f495dd8f817dd9b21d04cd22c250" &
        "d64f0a97519736da96e088683cfe740698356b6a548a11a3fc24002fd121883e8c9bc26833b487bcb7ef64a749" &
        "22c344ae61dff8359bb0ca2285503697cf333e58553819ededb581dbb285514d88f3e246f67b261aabd19af46f" &
        "b65920c433cf9a76d7d3436cd54a1f0ddda79e90bd296f7269b9e400db185a67bdfcaed8776ee08a94daf1df6e" &
        "bf654d051a0ff956559d04b6649b2941214e1c00a0bedbf279e9cd1867f013688f8842e13523b0e11560af8648" &
        "34d99c5fce339d91c9873fc3dd0d4b48c7bc149f58a13e36afb3985cf088edb91c5499c05b3c6a22089071d7e0" &
        "35fd7943015a9c7e27fea13830549359a285e888eeb1517dfa8e22059606adc4bb4ded95a6b44939cc2aa104cc" &
        "ac77daebbee2627137511cc110864b1c8ce105006f2174ce303fa0816cf49bfee33d6b9c908b81ef553339f865" &
        "dff5f007828c7b89bb1425aa6e3a79b2f003b8c43221e7b2d6d8495da987d8a76f1913e18b758507121234d06a" &
        "f7ad89ac7ff85d75480c590fcb633116e4201325fa29124217c8a54615f47e6b21a7c7b779d8810c90f3a20f56" &
        "28e0bb6b0af29e96a7e513a0ec354cd8cea9e54855d8c7539aa5dac38af055573043544f94739d062785320597" &
        "6978009a879ba6895eb566ac974ec84ca7754e5c70e025022017fb2773b5b2ad9ccafd567ef80d95c9d6f8e633" &
        "81a1281550f09d5b9568411dc8f048db50c857c262ee94b4b97ba31d4dbe32435e4bc288d0df425487d970835c" &
        "95a425275479d88c33ea7eea47c7ee6b8d2a424152a4982f5e84c18120803c2ee66eff1586cf6092278e94c4a9" &
        "64740a98b3783ab6be86d7df8d94e3fe76f628a2879a9b5c851c248712605bba34c2c45dc63d1a00df8cde827c" &
        "2d04c6f263280628c05bbef6d351f852cadc19e25c81afaef51545c884b177769ae46eee02ffc9108a8b9f5233" &
        "6ffc104a7514f47ae60621ce1f1f8eec4e38c8a698e293aa8a4c70ee988b3a4d29608852d0ebd53f773045fc36" &
        "cb4c5f54f4b7409acd479714894ad4b774718489c4c60953b621d3516daa7b05eb0d6c7638c06768bab563e78c" &
        "142d99031be6ac8e8c6a34ede011e7f2fd2fcdfe59f1b6bbd39933c6554dc2c06031ef6404ef526ea7e0370791" &
        "cf96d25a9f91ac0d0cd7e819d094a3ade7c71222e13954187493f3e25468d5747278b7e4bc1a31e464b58627fd" &
        "b13dbf86fc770a6dd91f48ba974a54285d8b4a08ca5ae43d83c13bdbba7c0f974565e87b139bd1c16438384169" &
        "f89e51c93949c36d757c15264dc2a7f0380c7c3001ff42398cb6131bf99d6a05cd4e222ae05b843d43dc6ca444" &
        "41613f0ea55e96c8506ffd9ddc3de069a560e84667d621082237c569130eb12a6099aaf4820405751a466824a7" &
        "50fae6301bb274951c09c035301a68e4a81cf5ff86c69a550b39782e7dbf5490dc7c147cd5b71901e12efa740b" &
        "92ada61c27495cc05ed6a598e00458384b3069d56b8a7f84edb7a2785bf9f1907657172396d78311761334f22e" &
        "45735f8724693be80017c76bf3612fd24afc1e55283ba84051fc9b20fdcd9542621af55ceb837bf2da5c581b62" &
        "610f454f7a4f28870ddc26bb4e7a7a7ddbd7ab17437c49191c9c05e1aab948788865369e883d30c747686519ce" &
        "27f301d060a5192d1a204a6ffcd9f9f157c2f85dd90d00446f94014c9d19b2c6cf11bad958e966ba799cf4cf46" &
        "91ead8cccb4eab9f28808f5a1230e6efe91357a7333e7d05c3ed5ca3eadf396ba9c08f9b123e8adb1e29193ada" &
        "be2b18cc46a5eec5dd25f07882eebcd6eb4382110d08ea6d1b862f241a0f8b91e986a79187a6a50a00d45fb200" &
        "20c17b117c4ccc11a9fac2736157cf13b417a8561aad359fef693ed574c453c3c1f127332b20fab318ea06d74c" &
        "c4e22674bf3796ed619dd2d0a52aaff9a14ba01e923566fdc338951799b31aaf63182bfde8b9111e6ea2a8a1d0" &
        "8d6604e328b010bd18dff25164691c8f6ad29066540d648595445a84322f1329918fcdc913b230fde3ab6b5de0" &
        "2460a8b560d7063fab107ab0b1e281f30a99cbd966f256ef101e81f65ef8b3dbd3c9e5f018f6080a03d9288c42" &
        "a731553ee47083e35fd1a43aa8ef90b39447766dacdf5792b59c76a16c7a95e9361017f2b72ecc25bef66b9ca6" &
        "c8d450eaf8520b827742b3912bbf1b552f84101b26ffaf34fe6170e79f803eefefc036867eb285c8c86d746f7d" &
        "3082058406092a864886f70d010701a0820575048205713082056d30820569060b2a864886f70d010c0a0102a0" &
        "8205313082052d305706092a864886f70d01050d304a302906092a864886f70d01050c301c04085f6ef3c0caaf" &
        "fb8e02020800300c06082a864886f70d02090500301d060960864801650304012a04107c38d110d01fb5c9d68c" &
        "561dee0f4252048204d02570beeac202309e79155bb893405dc3c9877e80684cb5be23815713c58b40e2ac286c" &
        "b06a7e646a2fe125a73335700dd4d1eed1e5d3cc4839267a9504984d953bcf13f3f9ff373adc11cff7659dd22d" &
        "5b5e063d676353a121365192b358859c50b299b5f6a0fe893e60dbfe3af81b600e3d69acae1585e56e8008352e" &
        "ed116a8a7c5ae739860e5f45fce0b22d39809ceb62d9cb88f0d4303cd9005c142ee01690a81dbd0fd10a989d22" &
        "dd9ba695c66069821eab3c987a5904a6f51fd6493cdc5e3c98f690bbfbcaf83f53b1eef64bebc9f2bda4165066" &
        "7e5a2d892e1d9ddbab7fe58c39ac40670e97dce8d64c541ad8813cd89aebc37e665a0310b772b4b4e4043c0069" &
        "c94644c00a05456816e8fcdb10cdd647413dc5c266817b8ed651c477acf36030b45372a50ad125a4e24dc2d326" &
        "4373c263075ea01bd438921f2798bd504d043c4d52a577caaf5ecb386e83b61616051329b4741a4a82d0e44e54" &
        "1d7d05a0cb4aab5c29a5405cf7afd668867aedec13c991b238496bc1439a1ff8b559fa7cd26d9387e921ad6b8c" &
        "77b44e9dad9d3b4e573ffd4f1fce1bd4aca1ae8b4b95f95da8082bc2db0e8f4c53446ca7f59473680cfe43e0e6" &
        "e21a405e1dbb4f85205c6226535f8c0518013d98e3f623f6da68dbceffed1c19c1a69173baff3c352d3b527654" &
        "9b02e300bd786ad068453fa0072baafbfa42acd40ba3cdf746740f229e320dd5612eb0af2fcee57944e0be44bb" &
        "67d0c2356a7a4a57bb9a014cd469f6f1d8a5122478fe835421c111e93b9476028cc55039220aee8f2bdabf4549" &
        "ead539582145723ba108916f359ba330907d12d725828b1767636f9f71c9a55ddb55263995cbcb09b5d9ade403" &
        "f2831edced726db547162693cdfba523807c19dc86d2ee12edf55278b14dd5528b6bff297e31913da9e4822977" &
        "60ceb2e1ceee7f0098e74168ee649f9d978698637c1bdb0f42075ae468682eead73c7661b35c83787dcbb773ed" &
        "13205d51feda27a55e2834db39c3a181c4a2cb6a8a32176105f3d7792d797f692e75b1492f02fb8bc6102c4add" &
        "0ddad1f73e09c6019a13ede66ddc70052bad93d0a1ce02a729096abcee9ab477df4d95add82fdda21512b9d296" &
        "80d24863f5add6c937d5d77abf05c89fa6d45ee43c45d3ae94daacfe14d78edb6d90e12e80f2b395c8de5f5f8a" &
        "cc620c0a252a92208efb9e52c24985e9e6087587ea486e518c7d84281a9e8bd4b0261b52ecc2ef76000be6ba2b" &
        "21f843804aab5cd3198668b09e45e99e1bc31392052d2d010b000de1653a1c435604656c66000b3b0ee7e4a82b" &
        "adc924f2a47aadce070265bde6422ef50ddc111857a7db39f9bc49f30fa0e6ead6028b4e83fb6eb397569d45f2" &
        "0b1759033a4f75d222b4650d9ce0355ff9e8743a1e6b508c815dbfc3e692680f075f2b6f341bf6d2289fbd7e6c" &
        "a54fb93f1f6f3870f55c632af30cb7b17ca2ec7ba81c170d46bb173b838ea7be35ac077d577b641e13c7e0dbe5" &
        "227f4d90e65d04952ba62cbfa6d88cb911e14cf9da2e569fbdc30510ff1277be8c4829b88b86c14cabd327b443" &
        "7d405cf75efbd44032c1944a42010ad046abedea8f82b67563cd26f0420ea5ac9129a661dc29e115121698dbf7" &
        "f3105760168aeb4a199438dd58436ce3e008febb3c67b8a1a6278c84ca862ed4ed372a26d2f4dde637cab2b069" &
        "a70fa82a3277362f7177aa73f73808d1400ad7aac95c00f85aced73125302306092a864886f70d010915311604" &
        "140f8b7a610f5ad04c532f9f02fc593c808a3a2bdd30313021300906052b0e03021a0500041417b42fdeeddc75" &
        "cad52c98532b3e92b52a334c4e04088b98cc91beff977802020800";

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

      CA_PEM  : Unbounded_String;
      CA_Key  : Unbounded_String;
      Bundle  : Unbounded_String;
      Outcome : CryptoLib.Certificates.Certificate_Status;
   begin
      --  A bundle this crate wrote, read back. The round trip is the point:
      --  generating one nobody can open is a failure that only shows up in
      --  somebody else's tool.
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("p12-roundtrip-ca", CA_PEM, CA_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      Outcome :=
        CryptoLib.Certificates.Generate_PKCS12
          (To_String (CA_PEM), To_String (CA_Key), "friendly", "secret",
           Bundle);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: bundle written");

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
                "a bundle this crate wrote opens here, got "
                & P12.Status_Image (St));
         Check (P12.Certificate_Count (Item) = 1,
                "it carries its one certificate");
         Check (P12.Has_Private_Key (Item)
                and then P12.Key_Algorithm_Of (Item)
                           = CryptoLib.X509.ECDSA_P384
                and then P12.Private_Value (Item)'Length = 48,
                "and the P-384 key that goes with it");

         --  The certificate really is the CA's, not merely certificate-shaped.
         declare
            Parsed : CryptoLib.ASN1.Errors.Decode_Status;
            Cert   : constant X509C.Certificate :=
              X509C.Decode_DER
                (P12.Certificate_Bytes (Item, 1),
                 CryptoLib.ASN1.Default_Limits, Parsed);
         begin
            Check (Parsed = CryptoLib.ASN1.Errors.Ok
                   and then X509C.Subject_Common_Name (Cert)
                              = "p12-roundtrip-ca",
                   "the certificate inside is the one that went in");
         end;

         --  Nothing is believed before the MAC is checked, so a wrong
         --  password yields nothing rather than a hopeful parse.
         P12.Open (Raw, "wrong", CryptoLib.ASN1.Default_Limits, Item, St);
         Check (St = P12.Wrong_Password_Or_Corrupt,
                "a wrong password is refused, got " & P12.Status_Image (St));
         Check (not P12.Is_Present (Item)
                and then P12.Certificate_Count (Item) = 0,
                "and nothing is left readable behind it");
      end;

      --  A bundle OpenSSL wrote with its own defaults, where the certificates
      --  sit in PKCS#7 encrypted content rather than in the clear. This is
      --  the common shape; a reader that skipped it would report a bundle
      --  full of certificates as having none.
      declare
         Item : P12.Bundle;
         St   : P12.Open_Status;
      begin
         P12.Open (From_Hex (OpenSSL_Bundle), "secret",
                   CryptoLib.ASN1.Default_Limits, Item, St);
         Check (St = P12.Ok,
                "an OpenSSL bundle opens, got " & P12.Status_Image (St));
         Check (P12.Certificate_Count (Item) = 2,
                "both its certificates are found, got"
                & Natural'Image (P12.Certificate_Count (Item)));
         Check (P12.Has_Private_Key (Item)
                and then P12.Key_Algorithm_Of (Item) = CryptoLib.X509.RSA,
                "and its RSA key");

         declare
            Leaf_Parsed   : CryptoLib.ASN1.Errors.Decode_Status;
            Issuer_Parsed : CryptoLib.ASN1.Errors.Decode_Status;
            Leaf   : constant X509C.Certificate :=
              X509C.Decode_DER
                (P12.Certificate_Bytes (Item, 1),
                 CryptoLib.ASN1.Default_Limits, Leaf_Parsed);
            Issuer : constant X509C.Certificate :=
              X509C.Decode_DER
                (P12.Certificate_Bytes (Item, 2),
                 CryptoLib.ASN1.Default_Limits, Issuer_Parsed);
         begin
            Check (Leaf_Parsed = CryptoLib.ASN1.Errors.Ok
                   and then Issuer_Parsed = CryptoLib.ASN1.Errors.Ok,
                   "both extracted certificates decode");
            Check (X509C.Subject_Common_Name (Leaf) = "leaf.rsa.example",
                   "the leaf comes out of the encrypted bag intact, got "
                   & X509C.Subject_Common_Name (Leaf));
            Check (X509C.Subject_Common_Name (Issuer) = "rsa-test-ca",
                   "and so does its issuer");
         end;
      end;
   end Check_PKCS12;


begin
   Check_PBKDF2_SHA1;
   Check_PBKDF2_SHA2;
   Check_PBKDF1;
   Check_PKCS12_KDF_SHA1;
   Check_Scrypt_SHA256;
   Check_Seven_Zip_AES_SHA256_KDF;
   Check_EVP_Bytes_To_Key_MD5;
   Check_ZIP_AES_CTR_Roundtrip;
   Check_RC2_40_CBC_Decrypt;
   Check_AES_256_CBC_Raw_Roundtrip;
   Check_AES_CBC_Raw_Rejects_Bad_Sizes;
   Check_ECDSA_P384_P521_Signing;
   Check_ECDSA_P384_Public_Key;
   Check_P384_Local_CA;
   Check_ASN1_DER;
   Check_X509_Decode;
   Check_X509_Verify;
   Check_X509_Extensions;
   Check_RSA_Verify;
   Check_ECDSA_Curves;
   Check_X509_Validation;
   Check_X509_Identity;
   Check_X509_Purposes;
   Check_X509_Names;
   Check_Certificate_Armour;
   Check_X509_CRL;
   Check_OCSP;
   Check_X509_Path_Building;
   Check_PKCS10;
   Check_PKCS8;
   Check_ECDSA_Scalar_Encodings;
   Check_Identities;
   Check_RSA_PSS;
   Check_Revocation;
   Check_PKCS8_Encrypted;
   Check_PKCS12;
   Check_Identity_Predicates;
   Check_PKCS12_Mac_Key;
   Check_ECDSA_P384_Verify;
   Check_Certificates;
   Check_XXH3;
   Check_Adler32;
   Check_CRC32;

   Check_MD5
     (Ada.Streams.Stream_Element_Array'(1 .. 0 => 0),
      [16#D4#, 16#1D#, 16#8C#, 16#D9#, 16#8F#, 16#00#, 16#B2#, 16#04#,
       16#E9#, 16#80#, 16#09#, 16#98#, 16#EC#, 16#F8#, 16#42#, 16#7E#],
      "MD5 empty vector");
   Check_MD5
     (Bytes_From_String ("abc"),
      [16#90#, 16#01#, 16#50#, 16#98#, 16#3C#, 16#D2#, 16#4F#, 16#B0#,
       16#D6#, 16#96#, 16#3F#, 16#7D#, 16#28#, 16#E1#, 16#7F#, 16#72#],
      "MD5 abc vector");
   --  RFC 1321 vectors that exercise the padding paths the "abc" case cannot:
   --  62 bytes forces the extra-block pad (used > 56), 80 bytes spans two
   --  compression blocks.
   Check_MD5
     (Bytes_From_String
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
      [16#D1#, 16#74#, 16#AB#, 16#98#, 16#D2#, 16#77#, 16#D9#, 16#F5#,
       16#A5#, 16#61#, 16#1C#, 16#2C#, 16#9F#, 16#41#, 16#9D#, 16#9F#],
      "MD5 alphanumeric vector");
   Check_MD5
     (Bytes_From_String
        ("1234567890123456789012345678901234567890"
         & "1234567890123456789012345678901234567890"),
      [16#57#, 16#ED#, 16#F4#, 16#A2#, 16#2B#, 16#E3#, 16#C9#, 16#55#,
       16#AC#, 16#49#, 16#DA#, 16#2E#, 16#21#, 16#07#, 16#B6#, 16#7A#],
      "MD5 eighty-digit vector");

   --  Streaming MD5: chunked updates reproduce the KAT, and byte-at-a-time
   --  updates match the one-shot digest across every padding boundary.
   declare
      Ctx : CryptoLib.Hashes.MD5_Context;
   begin
      CryptoLib.Hashes.Initialize_MD5 (Ctx);
      CryptoLib.Hashes.Update (Ctx, Bytes_From_String ("ab"));
      CryptoLib.Hashes.Update (Ctx, Bytes_From_String ("c"));
      Check
        (Ada.Streams.Stream_Element_Array (CryptoLib.Hashes.Finalize (Ctx))
         = Bytes_From_Hex ("900150983cd24fb0d6963f7d28e17f72"),
         "MD5 streaming KAT (abc, chunked)");

      for Length in 0 .. 200 loop
         declare
            Data : constant Ada.Streams.Stream_Element_Array :=
              Sequence_Data (Length);
            Byte_Ctx  : CryptoLib.Hashes.MD5_Context;
            Split_Ctx : CryptoLib.Hashes.MD5_Context;
            Split     : constant Ada.Streams.Stream_Element_Offset :=
              Data'First + Ada.Streams.Stream_Element_Offset (Length / 3) - 1;
         begin
            CryptoLib.Hashes.Initialize_MD5 (Byte_Ctx);
            for Index in Data'Range loop
               CryptoLib.Hashes.Update (Byte_Ctx, Data (Index .. Index));
            end loop;
            Check
              (Ada.Streams.Stream_Element_Array
                 (CryptoLib.Hashes.Finalize (Byte_Ctx))
               = Ada.Streams.Stream_Element_Array (CryptoLib.Hashes.MD5 (Data)),
               "MD5 streaming byte-at-a-time matches one-shot");

            CryptoLib.Hashes.Initialize_MD5 (Split_Ctx);
            CryptoLib.Hashes.Update (Split_Ctx, Data (Data'First .. Split));
            CryptoLib.Hashes.Update (Split_Ctx, Data (Split + 1 .. Data'Last));
            Check
              (Ada.Streams.Stream_Element_Array
                 (CryptoLib.Hashes.Finalize (Split_Ctx))
               = Ada.Streams.Stream_Element_Array (CryptoLib.Hashes.MD5 (Data)),
               "MD5 streaming split update matches one-shot");
         end;
      end loop;
   end;

   --  chacha20-poly1305@openssh.com known-answer vectors (generated by an
   --  independent reference cross-checked against OpenSSL's ChaCha20) and
   --  Seal/Open round-trip.
   declare
      function Nib (C : Character) return Ada.Streams.Stream_Element is
        (case C is
            when '0' .. '9' =>
              Ada.Streams.Stream_Element (Character'Pos (C) - Character'Pos ('0')),
            when 'a' .. 'f' =>
              Ada.Streams.Stream_Element
                (Character'Pos (C) - Character'Pos ('a') + 10),
            when others => 0);

      function From_Hex (H : String) return Ada.Streams.Stream_Element_Array is
         Result : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (H'Length / 2));
      begin
         for I in Result'Range loop
            declare
               P : constant Natural := H'First + Natural (I - 1) * 2;
            begin
               Result (I) := Nib (H (P)) * 16 + Nib (H (P + 1));
            end;
         end loop;
         return Result;
      end From_Hex;

      Key   : Ada.Streams.Stream_Element_Array (1 .. 64);
      Plain : constant Ada.Streams.Stream_Element_Array :=
        From_Hex ("0000001806050000000c7373682d7573657261757468000000000000");

      procedure Check_Seq (Seq : Interfaces.Unsigned_32; Expected_Hex : String) is
         Expected : constant Ada.Streams.Stream_Element_Array :=
           From_Hex (Expected_Hex);
         Wire : Ada.Streams.Stream_Element_Array
           (1 .. Plain'Length
                 + Ada.Streams.Stream_Element_Offset
                     (CryptoLib.ChaCha20_Poly1305.Tag_Length));
         Back : Ada.Streams.Stream_Element_Array (Plain'Range);
         St   : CryptoLib.Errors.Status;
      begin
         St := CryptoLib.ChaCha20_Poly1305.Seal (Key, Seq, Plain, Wire);
         Check (St = CryptoLib.Errors.Ok, "chacha20 seal status");
         Check (Wire = Expected, "chacha20 openssh KAT seq" & Seq'Image);
         St := CryptoLib.ChaCha20_Poly1305.Open (Key, Seq, Wire, Back);
         Check (St = CryptoLib.Errors.Ok, "chacha20 open status");
         Check (Back = Plain, "chacha20 roundtrip seq" & Seq'Image);
      end Check_Seq;
   begin
      for I in Key'Range loop
         Key (I) :=
           Ada.Streams.Stream_Element ((Integer (I - 1) * 7 + 3) mod 256);
      end loop;
      Check_Seq
        (0,
         "cded60dcda72fd6a5b0c0a73e29d8d6a493aa077574d5c95cff5ee8db110b5f4"
         & "9f1abd26781b75d16a180cf5");
      Check_Seq
        (3,
         "b909eaccf8d7a0a968380b7204a76ab2a8769f4988c5347dc99b6b3a668c4217"
         & "7f8bfa2063a9970534ffc773");
      Check_Seq
        (300,
         "b5904fc8ff8e38bbc29550e9a0de6ac4424188d25965840fa5e14921fdaae58e"
         & "28b27b87556027ca3a451bc6");
   end;

   --  aes256-gcm@openssh.com known-answer (RFC 5647: 4-octet length is
   --  cleartext GCM AAD, only the body is encrypted) cross-checked against
   --  pyca/cryptography AESGCM, plus a Seal/Open round-trip. Sequence is unused
   --  (per-packet IV uniqueness is the caller's job), so a nonzero value here
   --  must not change the result.
   declare
      function Nib (C : Character) return Ada.Streams.Stream_Element is
        (case C is
            when '0' .. '9' =>
              Ada.Streams.Stream_Element (Character'Pos (C) - Character'Pos ('0')),
            when 'a' .. 'f' =>
              Ada.Streams.Stream_Element
                (Character'Pos (C) - Character'Pos ('a') + 10),
            when others => 0);
      function From_Hex (H : String) return Ada.Streams.Stream_Element_Array is
         Result : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (H'Length / 2));
      begin
         for I in Result'Range loop
            declare
               P : constant Natural := H'First + Natural (I - 1) * 2;
            begin
               Result (I) := Nib (H (P)) * 16 + Nib (H (P + 1));
            end;
         end loop;
         return Result;
      end From_Hex;

      Key : constant Ada.Streams.Stream_Element_Array :=
        From_Hex ("030a11181f262d343b424950575e656c"
                  & "737a81888f969da4abb2b9c0c7ced5dc");
      IV : constant Ada.Streams.Stream_Element_Array :=
        From_Hex ("01060b10151a1f24292e3338");
      Plain : constant Ada.Streams.Stream_Element_Array :=
        From_Hex ("00000020"
                  & "000306090c0f1215181b1e2124272a2d"
                  & "303336393c3f4245484b4e5154575a5d");
      Expected : constant Ada.Streams.Stream_Element_Array :=
        From_Hex ("000000204e153e6346275b0a5c9bbcba5f3d1b9a"
                  & "907a9df8f3f8d1480bea7e4f5ce580aa4"
                  & "103ac2e23ebf79fade3345a94131e2b");
      Wire : Ada.Streams.Stream_Element_Array
        (1 .. Plain'Length
              + Ada.Streams.Stream_Element_Offset
                  (CryptoLib.Ciphers.AES_GCM_Tag_Length));
      Back : Ada.Streams.Stream_Element_Array (Plain'Range);
      St   : CryptoLib.Errors.Status;
   begin
      St :=
        CryptoLib.Ciphers.Seal_GCM
          ("aes256-gcm@openssh.com", Key, IV, 7, Plain, Wire);
      Check (St = CryptoLib.Errors.Ok, "aes256-gcm seal status");
      Check (Wire = Expected, "aes256-gcm openssh KAT");
      St :=
        CryptoLib.Ciphers.Open_GCM
          ("aes256-gcm@openssh.com", Key, IV, 7, Wire, Back);
      Check (St = CryptoLib.Errors.Ok, "aes256-gcm open status");
      Check (Back = Plain, "aes256-gcm roundtrip");
   end;

   --  RFC 4418 UMAC known-answer tests. Key "abcdefghijklmnop", nonce
   --  "bcdefghi". The RFC publishes tags up to 96 bits, so umac-64 is checked
   --  in full and umac-128 against its 96-bit (12-byte) prefix (streams 0-2);
   --  the full 128-bit result additionally interoperates with live OpenSSH.
   declare
      function Reps (N : Natural) return Ada.Streams.Stream_Element_Array is
         M : constant Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (N)) :=
             [others => Character'Pos ('a')];
      begin
         return M;
      end Reps;

      Key   : constant CryptoLib.UMAC.UMAC_Key :=
        Bytes_From_String ("abcdefghijklmnop");
      Nonce : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("bcdefghi");

      procedure Check_64 (Msg : Ada.Streams.Stream_Element_Array;
                          Want : String) is
      begin
         Check
           (CryptoLib.UMAC.Generate_With_Nonce
              ("umac-64@openssh.com", Key, Nonce, Msg) = Bytes_From_Hex (Want),
            "umac-64 KAT len" & Natural'Image (Msg'Length));
      end Check_64;

      procedure Check_96 (Msg : Ada.Streams.Stream_Element_Array;
                          Want : String) is
         Tag : constant Ada.Streams.Stream_Element_Array :=
           CryptoLib.UMAC.Generate_With_Nonce
             ("umac-128@openssh.com", Key, Nonce, Msg);
      begin
         Check
           (Tag (Tag'First .. Tag'First + 11) = Bytes_From_Hex (Want),
            "umac-128/96-prefix KAT len" & Natural'Image (Msg'Length));
      end Check_96;
   begin
      Check_64 (Reps (0),     "6e155fad26900be1");
      Check_64 (Reps (3),     "44b5cb542f220104");
      Check_64 (Reps (1024),  "26bf2f5d60118bd9");
      Check_64 (Reps (32768), "27f8ef643b0d118d");

      Check_96 (Reps (0),     "32fedb100c79ad58f07ff764");
      Check_96 (Reps (3),     "185e4fe905cba7bd85e4c2dc");
      Check_96 (Reps (1024),  "7a54abe04af82d60fb298c3c");
      Check_96 (Reps (32768), "7b136bd911e4b734286ef2be");
   end;

   --  FIPS 203 ML-KEM-768 known-answer test.  Deterministic keygen from d || z
   --  and encaps from m, checked against the pq-crystals final ML-KEM reference
   --  (byte-identical to OpenSSH).  The 1184/2400/1088-byte ek/dk/ct are
   --  compared via SHA-256; the 32-byte shared secret K is compared directly.
   declare
      D : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("f688563f7c66a5da2d8bdb5a5f3e07bd"
           & "8dce6f7efcec7f41298d79863459f7cd");
      Z : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("d1d49a515250dbceb9f6e3fcc1c7d530"
           & "6918964b21ddb22207e03e57f0600da8");
      M : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("3dc27ca0a6594b0e56320457c45a0f76"
           & "bb8a213ea4a76d442186a0aefadbcdb9");
      H_Ek : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("8d7887ad6b47c80dcf2210ca209cc35d"
           & "584977aeae1a30dfae68d28a98dd196e");
      H_Dk : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("3cdc2333bc4ca7090835fd34ad4407e9"
           & "6a9621da932be9f0998979afcadb722e");
      H_Ct : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("b96b0f142e4955ed41d76b8837355bcb"
           & "67f2e994c0a98f195ca69c0cd07aa879");
      K_Ref : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("ae726da2df66601c6648a7565c02b203"
           & "a089276ac30f6cc226d048f93fafd78c");

      function Digest (Data : Ada.Streams.Stream_Element_Array)
        return Ada.Streams.Stream_Element_Array
      is
         Dg : constant CryptoLib.Hashes.SHA256_Digest :=
           CryptoLib.Hashes.SHA256 (Data);
         R  : Ada.Streams.Stream_Element_Array (1 .. 32);
      begin
         for I in 1 .. 32 loop
            R (Ada.Streams.Stream_Element_Offset (I)) := Dg (I);
         end loop;
         return R;
      end Digest;

      Src : CryptoLib.Random.Random_Source;
      St  : CryptoLib.Errors.Status;
      Pk  : CryptoLib.MLKEM768.Public_Key;
      Sk  : CryptoLib.MLKEM768.Secret_Key;
      Ct  : CryptoLib.MLKEM768.Ciphertext;
      Ss  : CryptoLib.MLKEM768.Shared_Key;
   begin
      CryptoLib.Random.Initialize_Deterministic (Src, D & Z);
      St := CryptoLib.MLKEM768.Generate_Keypair (Src, Pk, Sk);
      Check (St = CryptoLib.Errors.Ok, "mlkem-768 keygen status");
      Check (Digest (Ada.Streams.Stream_Element_Array (Pk)) = H_Ek,
             "mlkem-768 keygen ek FIPS 203 KAT");
      Check (Digest (Ada.Streams.Stream_Element_Array (Sk)) = H_Dk,
             "mlkem-768 keygen dk FIPS 203 KAT");

      CryptoLib.Random.Initialize_Deterministic (Src, M);
      St := CryptoLib.MLKEM768.Encapsulate (Src, Pk, Ct, Ss);
      Check (St = CryptoLib.Errors.Ok, "mlkem-768 encaps status");
      Check (Digest (Ada.Streams.Stream_Element_Array (Ct)) = H_Ct,
             "mlkem-768 encaps ct FIPS 203 KAT");
      Check (Ada.Streams.Stream_Element_Array (Ss) = K_Ref,
             "mlkem-768 encaps shared secret FIPS 203 KAT");

      St := CryptoLib.MLKEM768.Decapsulate (Sk, Ct, Ss);
      Check (St = CryptoLib.Errors.Ok, "mlkem-768 decaps status");
      Check (Ada.Streams.Stream_Element_Array (Ss) = K_Ref,
             "mlkem-768 decaps shared secret FIPS 203 KAT");
   end;

   declare
      S761_Sk_Hex : constant String :=
        "465545156582195951566154950866811165054a948519655555259125558145555a4555a0155569811555551504625a5555" &
        "21155959521455a66565988995a16996955559656519552562595594545155415956650505194150649a69456465689555a6" &
        "5656615699512956445051951941506525555661544961191556509555985255514524465125405516495951550565655449" &
        "14a584429955255961550661a0165455659154a55514146555564455459965515119955a555058640111a8a2aa04aa048260" &
        "41190598564099686688512a6a9a6151625066426650188928290a18552240218a218982a1415a2050950a256aaa14aaa086" &
        "522516592599101565958488a864515a90660146a918191868555a89209451962299a1041a645a50895822260804a51a6420" &
        "0a10021a0a5a290460414094aa95566a944112154a99122406490142220148688a66426469a11921066a5a15412452586a5a" &
        "8a0612294252a9a5581955851919944501852499a961412a54145a6a4a9095006c66708068a3e17e978558514b05d7fd000b" &
        "12da9a3e6cbed0f12a6c447067813d3efbd4059a40ec87e0e2cb49dada472b2d582762dd87e44b16a5dab5a70bc4e1ef3860" &
        "e866b5cb5c1b53b2bddc40d9337a36225d3b3287e616dffd8a02a85ace86e8476c5a4cd04d593d98b196bf748653475fcdb8" &
        "9f6e0d152dbfc3d57f11eb514ffe8e16e9be5f19f1a6daea48e542e37bbcca318644b45a7d0eefe13b63bd5942814f5195f2" &
        "c56364534317a40a256389751f06d50ba57088dc4117eb41b02f347b560e03eab371ee7945760f2fc1e64ea945937f5a0f87" &
        "6183dc046fccc90150acd1e8b7102e347492e9965d12b0659a628fca9532c8e51f71b9cae7bf70b1e74d52b70bc797adebe5" &
        "563fe244f324da17d5fa1fdc479eb600eabc82f87cb9fbc4731e87851cd07989b03b6cf1e642c296ac43ede095d86770d1fc" &
        "38f1ff6834ec79d59441791a746428366296090f9f796bee37fc56310494016767553f809e2e6d75d81a0e097b510873e38b" &
        "9bc0867164ba5f659c09a418486db9d57a8ce58fc8f20fc6497c15077cf02f689d52775c341e986901e40a629182d63a3223" &
        "3f7a7752ea150b6dd20a1adca46a2d088cfe1b7fcdbb2111bbdf2b65b97709a1445872092bf40f04bc6a8ff6994598de65f5" &
        "d2a2bfe7366d4cfa09a04b0bdf7c85d2565ddffcf0a82d6a767dff89104b5b374e05efe206cc20c865faada1cb7f491ff7de" &
        "070e5b142ab850a56bc5115c373b89eaf4f6545839c4094dd70001efdd877597543deb9848f42a17cf0413261cf2913c73f1" &
        "062b358626aedf68d6c3056401d6ec7a791de064cb2cfd92fee4029e7d943ee26801f04203f7b0eac7c7427de9e4c1921e6a" &
        "b9a1a7da5e4453e1f7bfbd80002abfc1d981a6f634efd07022118ce66dc4f9484dea7f9c893cc455b67216321ad8aaa6e73a" &
        "64ef7e2fe6c5ba6d18e3cccfc0b2773bdcfcbc901105e59a102df10a448f0e82fe9c96d8f100ec6f56dd4e9e082d2798f47f" &
        "eec376f143c53d63ae5a6245e0602a8757d968ff7c2f13719d80c3fa3f30b7991fac1f72774c45de077a929cb70168657951" &
        "6c558f2fa29a09a4f3689869cacfb405d2d3fa12cf63e86998df57c08e3abd6a2f8f78efdb05c8514fa320d3dccdef9b18fe" &
        "df52f81fe22fabd294daaaccf7096f2be39d3702a6736b6024775f84d341a895bc5d37d2cee72e0b86fbcc8745e2ee71edb1" &
        "28bf11f88b25db73cfba27d45830a8142ce19322ac9c4e58040e229eed709c10d21f4832a126f3469b9853b3b0bf7bb6a395" &
        "8c67bae93b6ab56be0821d7ce9df173574038b79e569d9df3e17b432d5acf680feb3a207e92ee816a0a30360dc219fea1276" &
        "671088eb6b139c1a1ee812ff58f77b405db4815aa66ea3c524c05035a8b20b05f868b735ff2260edfe3be98b069f3f73533b" &
        "d2f26b30a9644235a75ec3750601814491fcfe1dbff71501ef3708aebf7e6f802bf0735fc4e3272d4ecec0facc4594cc7854" &
        "b88cf24b801aff19fff30b09386a9549d99da091282f7e77b38ffc7ec996079b31cd3ed1caac26e4dc01004c32f311c7b69d" &
        "e69129cda655071f380eae70faef05fd2789c785333bcf85d95d6a0527ebb3051ac3ec406e4954017135d5ca66ef7dea72ff" &
        "ab8a84d85ea9a9e7252a5fef6bd722217357ad30cfbd0b29251c213d722ea3118b17b89f696f6ffa3676cfcbb248088c2cd3" &
        "ed616cbc743dd5974d4d08fe9235eec88f88f4363de71c707c8fe82c76dad7bc99b7bd6ed0c9fd45041d35d724bfde416716" &
        "3655b3f35b2fa46cbb2b76a3cf23f5189df183c152df20fcf0d3e59af6a417cc5232fef9977d62e8c52a00b3314b0b41f0fe" &
        "1cf635f0983170ed664dacb36ab196cd619a467872b52b75a51987a5df1d4501a63d61c06bdb3a6900f82c640696f973bea7" &
        "c20f1bf0172bcbab421eb73210";
      S761_C_Hex : constant String :=
        "097d05333185288e68c81e4908d553672d571ebe1da7dc1f70c9f5afac49e87c849cddfb75837a87066cd4ee05bcda7b0398" &
        "289d45c5966f071bb18f6c1ee225d9340138fe56550bc0259934fbd59dfcb8b723e767d50adc2683eb8e2480a51f07ce439f" &
        "3a8aa787e92de4d682ee40dc708a109b4f1f74719af6f523cf272313d98a5cb71f25a52337bc74c01b4e648cf7affd7a60bf" &
        "90b00c5415c469784d3120948031191115c53d2de8bdb1eef53feb802f8334a2f645b8af6841e66599d7f23079f0107fb788" &
        "751caa2143eb427ba11d8e9a5b05f84975b36d247b52d7a7625df62df9b9644e65fd878e05dc7f2b7ee45be6e1eafeb1678d" &
        "7e95d46748d866ca0cdcfd87d627b02380b177eb9fa806f3676d99c0793945d99c08a988dc5f3196653ba75b9e075c2d96fe" &
        "324f10fd88980665451a5f9ec039b70b719e7d14948598ae7d2d83b35cd8cec27cb40554a243450eed60feaa6f6b4a46103d" &
        "af43678323c527b124eeb2b8879f0c9fe7f8a098db26de90e80b445658cb0d38c10ff9e29728a5a8350da852da97f5f27e2e" &
        "8e03c6a37ce62fd6a612fc3f84b393328ba6dc81b765d738e27a7ebd7ad065ba7c75a1dd649e5286ee7d711cd4c5d30021ee" &
        "15144b7e47f86dc630880527c2d2b3ed0e8f660441efd0503bf9fd8297fc6acb51c3f58a314d9dbf49990a121118b03b797a" &
        "42069c7e87a6514f7697ebe21c9394f810388d9d1a588a459497f99ef49e0e852090d3087cd69be0c427aaf24a1c015bdbce" &
        "e61803a51b44a57ecb1ac4276052af6db909d7d358f021a051c7712f6b7e4933631535bbf91df866e007b8db04e176a032cf" &
        "db8d39c3bc8512ac212ebfe48c0a09e8508ea2a7e7718d5825f4761596f4f20945a9c60a4e489e65e4012a4f881bdfcbefd1" &
        "70a5721f27cd7ba6e8e86e54d724a24c749a0a8879c9eacff56e8f206a8aebc35678a198bf5f63f33421dab916a8579908fe" &
        "51414fa0d9e6b1306c233c45663e780f599038379b393328de213cccc6b38e892b3acb16739f02610f20a71e5781f2060820" &
        "6246bf36d022cbdd5ea8cceebe97e8781ba0b857a2bb7513b7094a49975f43381d73e307583b713590eda7d7879009d0d4ea" &
        "2d1e3bb6140b25837eb5c93b788f6dd0774fe4d3865bad6fb113b8d5631f3b93dd3e779b9ca980766957b73d2a127fdb886b" &
        "24c61a60130abde9956169a1cbdfa1123d47071fb6dd8833132f4b016b6b8bca52aa2347441cc201640d1b51a4f72c41b9f8" &
        "f04c28ecc509efafa177603ee725dbfb31d9c33b6003cfb6f6679bfcf5b5017082fc94cd985c2e86dd06c5ba133580efd0f3" &
        "5603c83a77b4f77374ebdbdf8e90b016575c4ebfadc2bca8e89cec7ed5db1ab6563b8b8caa9a6524da1f3ffd3721b5669a5c" &
        "3c707b5190960aa3707ef18e1737a50295de622ac086930a1a614e299decf39a227ffb82c97fa8";
      S761_K_Hex : constant String :=
        "ec374e979535f5c7ce4ccdf1af1ef9cf745b56ff1b13f14afe6af5f7c92a185e";
      Sk761 : constant CryptoLib.SNTRUP761.Secret_Key :=
        CryptoLib.SNTRUP761.Secret_Key (Bytes_From_Hex (S761_Sk_Hex));
      Ct761 : constant CryptoLib.SNTRUP761.Ciphertext :=
        CryptoLib.SNTRUP761.Ciphertext (Bytes_From_Hex (S761_C_Hex));
      Ss761 : CryptoLib.SNTRUP761.Shared_Key;
      St761 : CryptoLib.Errors.Status;
      Src761 : CryptoLib.Random.Random_Source;
      Pk_R  : CryptoLib.SNTRUP761.Public_Key;
      Sk_R  : CryptoLib.SNTRUP761.Secret_Key;
      Ct_R  : CryptoLib.SNTRUP761.Ciphertext;
      Ss_A, Ss_B : CryptoLib.SNTRUP761.Shared_Key;
   begin
      --  Decapsulation KAT against an OpenSSH sntrup761 reference (sk, c, k).
      St761 := CryptoLib.SNTRUP761.Decapsulate (Sk761, Ct761, Ss761);
      Check (St761 = CryptoLib.Errors.Ok, "sntrup761 decaps status");
      Check (Ada.Streams.Stream_Element_Array (Ss761) = Bytes_From_Hex (S761_K_Hex),
             "sntrup761 decaps KAT vs OpenSSH reference");

      --  Full keygen -> encaps -> decaps roundtrip (internal consistency).
      CryptoLib.Random.Initialize_Production (Src761);
      St761 := CryptoLib.SNTRUP761.Generate_Keypair (Src761, Pk_R, Sk_R);
      Check (St761 = CryptoLib.Errors.Ok, "sntrup761 keygen status");
      St761 := CryptoLib.SNTRUP761.Encapsulate (Src761, Pk_R, Ct_R, Ss_A);
      Check (St761 = CryptoLib.Errors.Ok, "sntrup761 encaps status");
      St761 := CryptoLib.SNTRUP761.Decapsulate (Sk_R, Ct_R, Ss_B);
      Check (St761 = CryptoLib.Errors.Ok, "sntrup761 decaps (roundtrip) status");
      Check (Ada.Streams.Stream_Element_Array (Ss_A)
             = Ada.Streams.Stream_Element_Array (Ss_B),
             "sntrup761 keygen/encaps/decaps roundtrip");
   end;

   declare
      ME_B : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex ("03");
      ME_E : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex ("deadbeefcafebabe0123456789abcdef");
      ME_M : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("c0000000000000000000000000000000"
           & "000000000000000000000000000000fd");
      ME_R : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("a581a80a22ada40def1c4aac041e84b7"
           & "f3e9d9aa2c09d84e7f158460b8218e8b");
      G18_Priv : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("0b30557a9fc4e90e33587da2c7ec1136"
           & "5b80a5caef14395e83a8cdf2173c6186"
           & "abd0f51a3f6489aed3f81d42678cb1d6");
      G18_Server_Pub : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex ("0000000107");
      G18_Shared_SHA256 : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("13ac601793ca9f3e28d612ef044ea321"
           & "5a83ff808a1f79d8a38d758b42e96cc6");
      Shared_Buf : CryptoLib.Buffers.Packet_Buffer;
      St_DH      : CryptoLib.Errors.Status;
      Src_DH     : CryptoLib.Random.Random_Source;
      A_Priv, A_Pub, B_Priv, B_Pub, Sh_A, Sh_B :
        CryptoLib.Buffers.Packet_Buffer;
   begin
      --  Montgomery modular exponentiation known-answer vector.
      Check
        (CryptoLib.Modexp.Mod_Exp (ME_B, ME_E, ME_M) = ME_R,
         "Mod_Exp Montgomery KAT");

      --  group18 shared-secret KAT: pins the RFC 3526 8192-bit prime AND the
      --  modexp (a wrong prime yields a different shared secret).
      St_DH :=
        CryptoLib.Diffie_Hellman.Compute_Group18_Shared_Secret
          (G18_Priv, G18_Server_Pub, Shared_Buf);
      Check (St_DH = CryptoLib.Errors.Ok, "group18 shared-secret status");
      declare
         Dg : constant CryptoLib.Hashes.SHA256_Digest :=
           CryptoLib.Hashes.SHA256
             (CryptoLib.Buffers.To_Array (Shared_Buf));
         Got : Ada.Streams.Stream_Element_Array (1 .. 32);
      begin
         for I in 1 .. 32 loop
            Got (Ada.Streams.Stream_Element_Offset (I)) := Dg (I);
         end loop;
         Check
           (Got = G18_Shared_SHA256,
            "group18 shared-secret KAT (RFC 3526 prime + Montgomery modexp)");
      end;

      --  group16 (4096-bit) end-to-end roundtrip: exceeds GNAT Big_Integers'
      --  cap, so this also guards against the STORAGE_ERROR regression.
      CryptoLib.Random.Initialize_Production (Src_DH);
      St_DH :=
        CryptoLib.Diffie_Hellman.Generate_Group16_Keypair
          (Src_DH, A_Priv, A_Pub);
      Check (St_DH = CryptoLib.Errors.Ok, "group16 keypair A status");
      St_DH :=
        CryptoLib.Diffie_Hellman.Generate_Group16_Keypair
          (Src_DH, B_Priv, B_Pub);
      Check (St_DH = CryptoLib.Errors.Ok, "group16 keypair B status");
      St_DH :=
        CryptoLib.Diffie_Hellman.Compute_Group16_Shared_Secret
          (CryptoLib.Buffers.To_Array (A_Priv),
           CryptoLib.Buffers.To_Array (B_Pub), Sh_A);
      Check (St_DH = CryptoLib.Errors.Ok, "group16 shared A status");
      St_DH :=
        CryptoLib.Diffie_Hellman.Compute_Group16_Shared_Secret
          (CryptoLib.Buffers.To_Array (B_Priv),
           CryptoLib.Buffers.To_Array (A_Pub), Sh_B);
      Check (St_DH = CryptoLib.Errors.Ok, "group16 shared B status");
      Check
        (CryptoLib.Buffers.To_Array (Sh_A) = CryptoLib.Buffers.To_Array (Sh_B),
         "group16 DH roundtrip (Montgomery modexp)");
   end;

   --  SHA-3 / SHAKE NIST known-answer vectors (previously only validated
   --  transitively via ML-KEM / sntrup761).
   Check
     (Ada.Streams.Stream_Element_Array (CryptoLib.SHA3.SHA3_256 (Bytes_From_String ("")))
      = Bytes_From_Hex
          ("a7ffc6f8bf1ed76651c14756a061d662"
           & "f580ff4de43b49fa82d80a4b80f8434a"),
      "SHA3-256 NIST KAT (empty)");
   Check
     (Ada.Streams.Stream_Element_Array
        (CryptoLib.SHA3.SHA3_256 (Bytes_From_String ("abc")))
      = Bytes_From_Hex
          ("3a985da74fe225b2045c172d6bd390bd"
           & "855f086e3e9d525b46bfe24511431532"),
      "SHA3-256 NIST KAT (abc)");
   Check
     (Ada.Streams.Stream_Element_Array
        (CryptoLib.SHA3.SHA3_512 (Bytes_From_String ("abc")))
      = Bytes_From_Hex
          ("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
           & "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"),
      "SHA3-512 NIST KAT (abc)");
   Check
     (CryptoLib.SHA3.SHAKE128 (Bytes_From_String (""), 32)
      = Bytes_From_Hex
          ("7f9c2ba4e88f827d616045507605853e"
           & "d73b8093f6efbc88eb1a6eacfa66ef26"),
      "SHAKE128 NIST KAT (empty, 32)");
   Check
     (CryptoLib.SHA3.SHAKE256 (Bytes_From_String ("abc"), 64)
      = Bytes_From_Hex
          ("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
           & "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"),
      "SHAKE256 NIST KAT (abc, 64)");

   --  Ed25519 sign/verify (RFC 8032-style deterministic vector).
   declare
      Seed : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("9d61b19defffbaa5c0ceb40f3c9e2a5b"
           & "2e9e6bad6f2b0f4c6a1e8d3e2c1b0a09");
      Pub  : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("158ce5d4d6bd44bcb829399ecbc29497"
           & "3406965edcec77b64d2e49a2523259f5");
      Msg  : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("abc");
      Want : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("77bbf796bff069ddc46177610af724d0ff666ab76b4987f087b560a0b59603b2"
           & "35941c5db7aa566e4fa300c19764674ea123453d4785828982e6464210435b0f");
      Sig  : Ada.Streams.Stream_Element_Array (1 .. 64);
      St_E : CryptoLib.Errors.Status;
      Bad  : Ada.Streams.Stream_Element_Array (1 .. 64);
   begin
      St_E := CryptoLib.Ed25519.Sign (Seed, Pub, Msg, Sig);
      Check (St_E = CryptoLib.Errors.Ok, "Ed25519 sign status");
      Check (Sig = Want, "Ed25519 RFC 8032 sign KAT");
      Check
        (CryptoLib.Ed25519.Verify (Pub, Sig, Msg) = CryptoLib.Errors.Ok,
         "Ed25519 verify accepts valid signature");
      Bad := Sig;
      Bad (Bad'Last) := Bad (Bad'Last) xor 16#01#;
      Check
        (CryptoLib.Ed25519.Verify (Pub, Bad, Msg) /= CryptoLib.Errors.Ok,
         "Ed25519 verify rejects tampered signature");
      Check
        (CryptoLib.Ed25519.Verify (Pub, Sig, Bytes_From_String ("abd"))
           /= CryptoLib.Errors.Ok,
         "Ed25519 verify rejects wrong message");

      --  Malleability guard: reject a non-canonical S (S >= L).  The upper 32
      --  signature bytes are S; all-ones is far above the group order L.
      Bad := Sig;
      for I in Ada.Streams.Stream_Element_Offset range 33 .. 64 loop
         Bad (I) := 16#FF#;
      end loop;
      Check
        (CryptoLib.Ed25519.Verify (Pub, Bad, Msg) /= CryptoLib.Errors.Ok,
         "Ed25519 verify rejects non-canonical S (S >= L)");

      --  Reject wrong-length signature and public key (bounds/fail-closed).
      Check
        (CryptoLib.Ed25519.Verify (Pub, Sig (1 .. 63), Msg)
           /= CryptoLib.Errors.Ok,
         "Ed25519 verify rejects short signature");
      Check
        (CryptoLib.Ed25519.Verify (Pub (Pub'First .. Pub'Last - 1), Sig, Msg)
           /= CryptoLib.Errors.Ok,
         "Ed25519 verify rejects short public key");
   end;

   --  X25519 RFC 7748 section 5.2 known-answer vectors.
   declare
      procedure Check_X25519 (Scalar_Hex, U_Hex, Out_Hex, Label : String) is
         Scalar : constant CryptoLib.Curve25519.Public_Key :=
           CryptoLib.Curve25519.Public_Key (Bytes_From_Hex (Scalar_Hex));
         U_Coord : constant CryptoLib.Curve25519.Public_Key :=
           CryptoLib.Curve25519.Public_Key (Bytes_From_Hex (U_Hex));
         Result : CryptoLib.Curve25519.Public_Key;
         St_X   : CryptoLib.Errors.Status;
      begin
         St_X := CryptoLib.Curve25519.Compute_Raw (Scalar, U_Coord, Result);
         Check (St_X = CryptoLib.Errors.Ok, Label & " status");
         Check
           (Ada.Streams.Stream_Element_Array (Result) = Bytes_From_Hex (Out_Hex),
            Label);
      end Check_X25519;
   begin
      Check_X25519
        ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
         "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
         "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
         "X25519 RFC 7748 KAT vector 1");
      Check_X25519
        ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
         "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
         "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
         "X25519 RFC 7748 KAT vector 2");
   end;

   --  ECDSA deterministic (RFC 6979) signing.  P-384 is the authoritative
   --  RFC 6979 A.2.5 vector; P-521 is cross-verified with an external library.
   declare
      Msg   : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("sample");
      P384_D : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d8"
           & "96d5724e4c70a825f872c9ea60d2edf5");
      P384_R : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c"
           & "81a648152e44acf96e36dd1e80fabe46");
      P384_S : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94f"
           & "a329c145786e679e7b82c71a38628ac8");
      P521_D : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("00fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75"
           & "caa896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b"
           & "83538");
      P521_R : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("00c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f"
           & "174e25a1ee9017b5d450606add152b534931d7d4e8455cc91f9b15bf05ec36e"
           & "377fa");
      P521_S : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
          ("00617cce7cf5064806c467f678d3b4080d6f1cc50af26ca209417308281b68af"
           & "282623eaa63e5b5c0723d8b8c37ff0777b1a20f8ccb1dccc43997f1ee0e44da"
           & "4a67a");
      R384 : Ada.Streams.Stream_Element_Array (1 .. 48);
      S384 : Ada.Streams.Stream_Element_Array (1 .. 48);
      R521 : Ada.Streams.Stream_Element_Array (1 .. 66);
      S521 : Ada.Streams.Stream_Element_Array (1 .. 66);
      St_D : CryptoLib.Errors.Status;
   begin
      St_D := CryptoLib.ECDSA.Sign_Nistp384_Raw (P384_D, Msg, R384, S384);
      Check (St_D = CryptoLib.Errors.Ok, "ECDSA P-384 sign status");
      Check (R384 = P384_R and then S384 = P384_S,
             "ECDSA P-384 RFC 6979 A.2.5 KAT");
      St_D := CryptoLib.ECDSA.Sign_Nistp521_Raw (P521_D, Msg, R521, S521);
      Check (St_D = CryptoLib.Errors.Ok, "ECDSA P-521 sign status");
      Check (R521 = P521_R and then S521 = P521_S,
             "ECDSA P-521 RFC 6979 deterministic KAT");
   end;

   --  Direct SHA-1/2 known-answer vectors ("abc"), previously only exercised
   --  transitively through PBKDF2 / ML-KEM.
   Check
     (Ada.Streams.Stream_Element_Array
        (CryptoLib.Hashes.SHA1 (Bytes_From_String ("abc")))
      = Bytes_From_Hex ("a9993e364706816aba3e25717850c26c9cd0d89d"),
      "SHA-1 KAT (abc)");
   --  Streaming SHA-1: chunked updates reproduce the KAT, and a byte-at-a-time
   --  multi-block (>64 byte) input matches the one-shot digest.
   declare
      Ctx  : CryptoLib.Hashes.SHA1_Context;
      Ctx2 : CryptoLib.Hashes.SHA1_Context;
      Long : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String
          ("The quick brown fox jumps over the lazy dog. "
           & "Pack my box with five dozen liquor jugs. 0123456789");
   begin
      CryptoLib.Hashes.Initialize_SHA1 (Ctx);
      CryptoLib.Hashes.Update (Ctx, Bytes_From_String ("ab"));
      CryptoLib.Hashes.Update (Ctx, Bytes_From_String ("c"));
      Check
        (Ada.Streams.Stream_Element_Array (CryptoLib.Hashes.Finalize (Ctx))
         = Bytes_From_Hex ("a9993e364706816aba3e25717850c26c9cd0d89d"),
         "SHA-1 streaming KAT (abc, chunked)");

      CryptoLib.Hashes.Initialize_SHA1 (Ctx2);
      for Index in Long'Range loop
         CryptoLib.Hashes.Update (Ctx2, Long (Index .. Index));
      end loop;
      Check
        (Ada.Streams.Stream_Element_Array (CryptoLib.Hashes.Finalize (Ctx2))
         = Ada.Streams.Stream_Element_Array (CryptoLib.Hashes.SHA1 (Long)),
         "SHA-1 streaming matches one-shot (multi-block)");
   end;
   Check
     (Ada.Streams.Stream_Element_Array
        (CryptoLib.Hashes.SHA256 (Bytes_From_String ("abc")))
      = Bytes_From_Hex
          ("ba7816bf8f01cfea414140de5dae2223"
           & "b00361a396177a9cb410ff61f20015ad"),
      "SHA-256 KAT (abc)");
   Check
     (Ada.Streams.Stream_Element_Array
        (CryptoLib.Hashes.SHA384 (Bytes_From_String ("abc")))
      = Bytes_From_Hex
          ("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
           & "8086072ba1e7cc2358baeca134c825a7"),
      "SHA-384 KAT (abc)");
   --  Streaming SHA-384: chunked updates reproduce the KAT, the 112-byte NIST
   --  vector exercises the extra-block pad (used > 112) across two blocks, and
   --  byte-at-a-time updates match the one-shot at every padding boundary.
   declare
      Ctx      : CryptoLib.Hashes.SHA384_Context;
      Long_Ctx : CryptoLib.Hashes.SHA384_Context;
      Long     : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String
          ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
           & "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
   begin
      CryptoLib.Hashes.Initialize_SHA384 (Ctx);
      CryptoLib.Hashes.Update (Ctx, Bytes_From_String ("ab"));
      CryptoLib.Hashes.Update (Ctx, Bytes_From_String ("c"));
      Check
        (Ada.Streams.Stream_Element_Array (CryptoLib.Hashes.Finalize (Ctx))
         = Bytes_From_Hex
             ("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
              & "8086072ba1e7cc2358baeca134c825a7"),
         "SHA-384 streaming KAT (abc, chunked)");

      CryptoLib.Hashes.Initialize_SHA384 (Long_Ctx);
      for Index in Long'Range loop
         CryptoLib.Hashes.Update (Long_Ctx, Long (Index .. Index));
      end loop;
      Check
        (Ada.Streams.Stream_Element_Array
           (CryptoLib.Hashes.Finalize (Long_Ctx))
         = Bytes_From_Hex
             ("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
              & "fcc7c71a557e2db966c3e9fa91746039"),
         "SHA-384 streaming KAT (112-byte NIST vector, byte-at-a-time)");

      for Length in 0 .. 300 loop
         declare
            Data : constant Ada.Streams.Stream_Element_Array :=
              Sequence_Data (Length);
            Split_Ctx : CryptoLib.Hashes.SHA384_Context;
            Split     : constant Ada.Streams.Stream_Element_Offset :=
              Data'First + Ada.Streams.Stream_Element_Offset (Length / 3) - 1;
         begin
            CryptoLib.Hashes.Initialize_SHA384 (Split_Ctx);
            CryptoLib.Hashes.Update (Split_Ctx, Data (Data'First .. Split));
            CryptoLib.Hashes.Update (Split_Ctx, Data (Split + 1 .. Data'Last));
            Check
              (Ada.Streams.Stream_Element_Array
                 (CryptoLib.Hashes.Finalize (Split_Ctx))
               = Ada.Streams.Stream_Element_Array
                   (CryptoLib.Hashes.SHA384 (Data)),
               "SHA-384 streaming split update matches one-shot");
         end;
      end loop;
   end;
   Check
     (Ada.Streams.Stream_Element_Array
        (CryptoLib.Hashes.SHA512 (Bytes_From_String ("abc")))
      = Bytes_From_Hex
          ("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
           & "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
      "SHA-512 KAT (abc)");

   --  HMAC known-answer vectors (RFC 2202 / RFC 4231 test case 1:
   --  key = 0x0b x20, message = "Hi There").
   declare
      HK  : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex ("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
      HM  : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("Hi There");
   begin
      Check
        (Ada.Streams.Stream_Element_Array (CryptoLib.Macs.HMAC_SHA1 (HK, HM))
         = Bytes_From_Hex ("b617318655057264e28bc0b6fb378c8ef146be00"),
         "HMAC-SHA1 RFC 2202 KAT");
      Check
        (Ada.Streams.Stream_Element_Array (CryptoLib.Macs.HMAC_SHA256 (HK, HM))
         = Bytes_From_Hex
             ("b0344c61d8db38535ca8afceaf0bf12b"
              & "881dc200c9833da726e9376c2e32cff7"),
         "HMAC-SHA256 RFC 4231 KAT");
      Check
        (Ada.Streams.Stream_Element_Array (CryptoLib.Macs.HMAC_SHA512 (HK, HM))
         = Bytes_From_Hex
             ("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
              & "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"),
         "HMAC-SHA512 RFC 4231 KAT");
   end;

   --  HMAC-SHA384 (RFC 4231 test case 1) plus the long-key path of all four
   --  variants (RFC 2202 / RFC 4231 test case 6): a key longer than the hash
   --  block is replaced by its own digest before the pads are derived.
   declare
      HK  : constant Ada.Streams.Stream_Element_Array (1 .. 20) :=
        [others => 16#0B#];
      HM  : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("Hi There");
      LK1 : constant Ada.Streams.Stream_Element_Array (1 .. 80) :=
        [others => 16#AA#];
      LK  : constant Ada.Streams.Stream_Element_Array (1 .. 131) :=
        [others => 16#AA#];
      LM  : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String
          ("Test Using Larger Than Block-Size Key - Hash Key First");
   begin
      Check
        (Ada.Streams.Stream_Element_Array (CryptoLib.Macs.HMAC_SHA384 (HK, HM))
         = Bytes_From_Hex
             ("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec6"
              & "82aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"),
         "HMAC-SHA384 RFC 4231 KAT");
      Check
        (Ada.Streams.Stream_Element_Array
           (CryptoLib.Macs.HMAC_SHA1 (LK1, LM))
         = Bytes_From_Hex ("aa4ae5e15272d00e95705637ce8a3b55ed402112"),
         "HMAC-SHA1 RFC 2202 long-key KAT");
      Check
        (Ada.Streams.Stream_Element_Array
           (CryptoLib.Macs.HMAC_SHA256 (LK, LM))
         = Bytes_From_Hex
             ("60e431591ee0b67f0d8a26aacbf5b77f"
              & "8e0bc6213728c5140546040f0ee37f54"),
         "HMAC-SHA256 RFC 4231 long-key KAT");
      Check
        (Ada.Streams.Stream_Element_Array
           (CryptoLib.Macs.HMAC_SHA384 (LK, LM))
         = Bytes_From_Hex
             ("4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f"
              & "3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"),
         "HMAC-SHA384 RFC 4231 long-key KAT");
      Check
        (Ada.Streams.Stream_Element_Array
           (CryptoLib.Macs.HMAC_SHA512 (LK, LM))
         = Bytes_From_Hex
             ("80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
              & "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"),
         "HMAC-SHA512 RFC 4231 long-key KAT");
   end;

   --  Streaming HMAC: split and byte-at-a-time updates reproduce the one-shot
   --  tag, with a short key and with a key longer than the hash block, and an
   --  Initialize/Finalize with no Update matches the empty message.
   declare
      SK    : constant Ada.Streams.Stream_Element_Array (1 .. 20) :=
        [others => 16#0B#];
      LK    : constant Ada.Streams.Stream_Element_Array (1 .. 131) :=
        [others => 16#AA#];
      Msg   : constant Ada.Streams.Stream_Element_Array := Sequence_Data (200);
      Empty : constant Ada.Streams.Stream_Element_Array (1 .. 0) :=
        [others => 0];
      Split : constant Ada.Streams.Stream_Element_Offset := Msg'First + 77;

      Split_1   : CryptoLib.Macs.HMAC_SHA1_Context;
      Split_256 : CryptoLib.Macs.HMAC_SHA256_Context;
      Split_384 : CryptoLib.Macs.HMAC_SHA384_Context;
      Split_512 : CryptoLib.Macs.HMAC_SHA512_Context;
      Byte_1    : CryptoLib.Macs.HMAC_SHA1_Context;
      Byte_256  : CryptoLib.Macs.HMAC_SHA256_Context;
      Byte_384  : CryptoLib.Macs.HMAC_SHA384_Context;
      Byte_512  : CryptoLib.Macs.HMAC_SHA512_Context;
      Empty_256 : CryptoLib.Macs.HMAC_SHA256_Context;
   begin
      CryptoLib.Macs.Initialize_HMAC_SHA1 (Split_1, SK);
      CryptoLib.Macs.Update (Split_1, Msg (Msg'First .. Split));
      CryptoLib.Macs.Update (Split_1, Msg (Split + 1 .. Msg'Last));
      Check
        (Ada.Streams.Stream_Element_Array
           (CryptoLib.Macs.Finalize (Split_1))
         = Ada.Streams.Stream_Element_Array
             (CryptoLib.Macs.HMAC_SHA1 (SK, Msg)),
         "HMAC-SHA1 streaming split update matches one-shot");

      CryptoLib.Macs.Initialize_HMAC_SHA256 (Split_256, SK);
      CryptoLib.Macs.Update (Split_256, Msg (Msg'First .. Split));
      CryptoLib.Macs.Update (Split_256, Msg (Split + 1 .. Msg'Last));
      Check
        (Ada.Streams.Stream_Element_Array
           (CryptoLib.Macs.Finalize (Split_256))
         = Ada.Streams.Stream_Element_Array
             (CryptoLib.Macs.HMAC_SHA256 (SK, Msg)),
         "HMAC-SHA256 streaming split update matches one-shot");

      CryptoLib.Macs.Initialize_HMAC_SHA384 (Split_384, SK);
      CryptoLib.Macs.Update (Split_384, Msg (Msg'First .. Split));
      CryptoLib.Macs.Update (Split_384, Msg (Split + 1 .. Msg'Last));
      Check
        (Ada.Streams.Stream_Element_Array
           (CryptoLib.Macs.Finalize (Split_384))
         = Ada.Streams.Stream_Element_Array
             (CryptoLib.Macs.HMAC_SHA384 (SK, Msg)),
         "HMAC-SHA384 streaming split update matches one-shot");

      CryptoLib.Macs.Initialize_HMAC_SHA512 (Split_512, SK);
      CryptoLib.Macs.Update (Split_512, Msg (Msg'First .. Split));
      CryptoLib.Macs.Update (Split_512, Msg (Split + 1 .. Msg'Last));
      Check
        (Ada.Streams.Stream_Element_Array
           (CryptoLib.Macs.Finalize (Split_512))
         = Ada.Streams.Stream_Element_Array
             (CryptoLib.Macs.HMAC_SHA512 (SK, Msg)),
         "HMAC-SHA512 streaming split update matches one-shot");

      --  Long keys go through the hash-the-key branch of Initialize.
      CryptoLib.Macs.Initialize_HMAC_SHA1 (Byte_1, LK);
      CryptoLib.Macs.Initialize_HMAC_SHA256 (Byte_256, LK);
      CryptoLib.Macs.Initialize_HMAC_SHA384 (Byte_384, LK);
      CryptoLib.Macs.Initialize_HMAC_SHA512 (Byte_512, LK);
      for Index in Msg'Range loop
         CryptoLib.Macs.Update (Byte_1, Msg (Index .. Index));
         CryptoLib.Macs.Update (Byte_256, Msg (Index .. Index));
         CryptoLib.Macs.Update (Byte_384, Msg (Index .. Index));
         CryptoLib.Macs.Update (Byte_512, Msg (Index .. Index));
      end loop;
      Check
        (Ada.Streams.Stream_Element_Array (CryptoLib.Macs.Finalize (Byte_1))
         = Ada.Streams.Stream_Element_Array
             (CryptoLib.Macs.HMAC_SHA1 (LK, Msg)),
         "HMAC-SHA1 streaming byte-at-a-time (long key) matches one-shot");
      Check
        (Ada.Streams.Stream_Element_Array (CryptoLib.Macs.Finalize (Byte_256))
         = Ada.Streams.Stream_Element_Array
             (CryptoLib.Macs.HMAC_SHA256 (LK, Msg)),
         "HMAC-SHA256 streaming byte-at-a-time (long key) matches one-shot");
      Check
        (Ada.Streams.Stream_Element_Array (CryptoLib.Macs.Finalize (Byte_384))
         = Ada.Streams.Stream_Element_Array
             (CryptoLib.Macs.HMAC_SHA384 (LK, Msg)),
         "HMAC-SHA384 streaming byte-at-a-time (long key) matches one-shot");
      Check
        (Ada.Streams.Stream_Element_Array (CryptoLib.Macs.Finalize (Byte_512))
         = Ada.Streams.Stream_Element_Array
             (CryptoLib.Macs.HMAC_SHA512 (LK, Msg)),
         "HMAC-SHA512 streaming byte-at-a-time (long key) matches one-shot");

      CryptoLib.Macs.Initialize_HMAC_SHA256 (Empty_256, SK);
      Check
        (Ada.Streams.Stream_Element_Array
           (CryptoLib.Macs.Finalize (Empty_256))
         = Ada.Streams.Stream_Element_Array
             (CryptoLib.Macs.HMAC_SHA256 (SK, Empty)),
         "HMAC-SHA256 streaming with no Update matches empty message");
   end;

   --  PBKDF2-HMAC-SHA1 with a high iteration count (RFC 6070, c = 4096) to
   --  exercise the iteration/XOR-accumulation loop (previously only c = 1).
   Check
     (CryptoLib.Macs.PBKDF2_HMAC_SHA1
        (Bytes_From_String ("password"), Bytes_From_String ("salt"), 4096, 20)
      = Bytes_From_Hex ("4b007901b765489abead49d926f721d065a429c1"),
      "PBKDF2-HMAC-SHA1 RFC 6070 c=4096 KAT");

   --  Negative / fail-closed tests: low-order X25519 point and AEAD tamper.
   declare
      Scalar : constant CryptoLib.Curve25519.Public_Key :=
        CryptoLib.Curve25519.Public_Key
          (Bytes_From_Hex
             ("a546e36bf0527c9d3b16154b82465edd"
              & "62144c0ac1fc5a18506a2244ba449ac4"));
      Zero_U : constant CryptoLib.Curve25519.Public_Key := [others => 0];
      Result : CryptoLib.Curve25519.Public_Key;
      St     : CryptoLib.Errors.Status;
   begin
      St := CryptoLib.Curve25519.Compute_Raw (Scalar, Zero_U, Result);
      Check
        (St /= CryptoLib.Errors.Ok,
         "X25519 rejects all-zero (low-order) peer point");
   end;

   declare
      Key   : constant Ada.Streams.Stream_Element_Array (1 .. 64) :=
        [others => 7];
      Plain : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("attack at dawn!!");
      Wire  : Ada.Streams.Stream_Element_Array
        (1 .. Plain'Length
              + Ada.Streams.Stream_Element_Offset
                  (CryptoLib.ChaCha20_Poly1305.Tag_Length));
      Bad   : Ada.Streams.Stream_Element_Array (Wire'Range);
      Back  : Ada.Streams.Stream_Element_Array (Plain'Range);
      St    : CryptoLib.Errors.Status;
   begin
      St := CryptoLib.ChaCha20_Poly1305.Seal (Key, 0, Plain, Wire);
      Check (St = CryptoLib.Errors.Ok, "chacha20-poly seal (tamper setup)");

      Bad := Wire;                                       --  flip a ciphertext byte
      Bad (Bad'First) := Bad (Bad'First) xor 16#01#;
      St := CryptoLib.ChaCha20_Poly1305.Open (Key, 0, Bad, Back);
      Check
        (St /= CryptoLib.Errors.Ok,
         "chacha20-poly open rejects tampered ciphertext");

      Bad := Wire;                                       --  flip a tag byte
      Bad (Bad'Last) := Bad (Bad'Last) xor 16#80#;
      St := CryptoLib.ChaCha20_Poly1305.Open (Key, 0, Bad, Back);
      Check
        (St /= CryptoLib.Errors.Ok,
         "chacha20-poly open rejects tampered tag");
   end;

   --  CryptoLib.Secure_Wipe zeroizes a buffer through volatile stores that the
   --  optimizer cannot elide (used to scrub key material before it leaves scope).
   declare
      use type Interfaces.Unsigned_8;
      Secret  : array (1 .. 48) of Interfaces.Unsigned_8;
      Nonzero : Natural := 0;
   begin
      for Index in Secret'Range loop
         Secret (Index) := Interfaces.Unsigned_8 ((Index * 3) mod 251 + 1);
      end loop;
      CryptoLib.Secure_Wipe.Wipe (Secret'Address, Secret'Length);
      for Index in Secret'Range loop
         if Secret (Index) /= 0 then
            Nonzero := Nonzero + 1;
         end if;
      end loop;
      Check (Nonzero = 0, "Secure_Wipe zeroizes buffer");
   end;

   --  Seal_AEAD / Open_AEAD: plain AES-256-GCM with no SSH framing, checked
   --  against the NIST GCM specification's AES-256 test vectors.
   declare
      use Ada.Streams;
      Algorithm : constant String := "aes256-gcm@openssh.com";
      Key       : constant Stream_Element_Array (1 .. 32) := [others => 0];
      Nonce     : constant Stream_Element_Array (1 .. 12) := [others => 0];
      Empty     : constant Stream_Element_Array (1 .. 0) := [others => 0];

      --  Test case 13: empty plaintext, empty AAD -> tag only.
      Tag_13 : constant Stream_Element_Array :=
        [16#53#, 16#0F#, 16#8A#, 16#FB#, 16#C7#, 16#45#, 16#36#, 16#B9#,
         16#A9#, 16#63#, 16#B4#, 16#F1#, 16#C4#, 16#CB#, 16#73#, 16#8B#];
      Wire_13 : Stream_Element_Array (1 .. 16);

      --  Test case 14: 16 zero bytes of plaintext, empty AAD.
      Plain_14 : constant Stream_Element_Array (1 .. 16) := [others => 0];
      Wire_14  : constant Stream_Element_Array :=
        [16#CE#, 16#A7#, 16#40#, 16#3D#, 16#4D#, 16#60#, 16#6B#, 16#6E#,
         16#07#, 16#4E#, 16#C5#, 16#D3#, 16#BA#, 16#F3#, 16#9D#, 16#18#,
         16#D0#, 16#D1#, 16#C8#, 16#A7#, 16#99#, 16#99#, 16#6B#, 16#F0#,
         16#26#, 16#5B#, 16#98#, 16#B5#, 16#D4#, 16#8A#, 16#B9#, 16#19#];
      Sealed_14 : Stream_Element_Array (1 .. 32);

      Message   : constant Stream_Element_Array :=
        [16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#];
      Aad       : constant Stream_Element_Array := [16#AA#, 16#BB#];
      Sealed    : Stream_Element_Array (1 .. Message'Length + 16);
      Recovered : Stream_Element_Array (1 .. Message'Length);
      Restored  : Stream_Element_Array (1 .. 0);
      Result    : CryptoLib.Errors.Status;
   begin
      Result :=
        CryptoLib.Ciphers.Seal_AEAD (Algorithm, Key, Nonce, Empty, Empty,
                                     Wire_13);
      Check (Result = CryptoLib.Errors.Ok and then Wire_13 = Tag_13,
             "Seal_AEAD matches NIST GCM case 13 (empty plaintext)");

      Result :=
        CryptoLib.Ciphers.Open_AEAD (Algorithm, Key, Nonce, Empty, Wire_13,
                                     Restored);
      Check (Result = CryptoLib.Errors.Ok,
             "Open_AEAD accepts an empty sealed plaintext");

      Result :=
        CryptoLib.Ciphers.Seal_AEAD (Algorithm, Key, Nonce, Empty, Plain_14,
                                     Sealed_14);
      Check (Result = CryptoLib.Errors.Ok and then Sealed_14 = Wire_14,
             "Seal_AEAD matches NIST GCM case 14");

      Result :=
        CryptoLib.Ciphers.Seal_AEAD (Algorithm, Key, Nonce, Aad, Message,
                                     Sealed);
      Check (Result = CryptoLib.Errors.Ok, "Seal_AEAD seals with AAD");

      --  The plaintext must not appear in the clear anywhere in the wire.
      Check (Sealed (Sealed'First .. Sealed'First + Message'Length - 1)
               /= Message,
             "Seal_AEAD leaves no cleartext prefix");

      Result :=
        CryptoLib.Ciphers.Open_AEAD (Algorithm, Key, Nonce, Aad, Sealed,
                                     Recovered);
      Check (Result = CryptoLib.Errors.Ok and then Recovered = Message,
             "Open_AEAD round-trips the plaintext");

      --  A different AAD must fail the tag check.
      Result :=
        CryptoLib.Ciphers.Open_AEAD (Algorithm, Key, Nonce, Empty, Sealed,
                                     Recovered);
      Check (Result /= CryptoLib.Errors.Ok,
             "Open_AEAD rejects a changed AAD");

      --  A flipped ciphertext bit must fail the tag check.
      declare
         Tampered : Stream_Element_Array := Sealed;
      begin
         Tampered (Tampered'First) := Tampered (Tampered'First) xor 1;
         Result :=
           CryptoLib.Ciphers.Open_AEAD (Algorithm, Key, Nonce, Aad, Tampered,
                                        Recovered);
         Check (Result /= CryptoLib.Errors.Ok,
                "Open_AEAD rejects tampered ciphertext");
      end;
   end;

   Ada.Text_IO.Put_Line ("cryptolib tests passed");
end Tests;
