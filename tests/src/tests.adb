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
with CryptoLib.X509.Policies;
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
              (case Algorithm is
                  when CryptoLib.Certificates.P384_Key    => "p384",
                  when CryptoLib.Certificates.Ed448_Key   => "ed448",
                  when CryptoLib.Certificates.Ed25519_Key => "ed25519");
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

            --  The key that comes back with it is the leaf's own. Issuing a
            --  certificate and a key that do not go together would be caught
            --  by nothing else here: both halves look well formed alone.
            Check
              (CryptoLib.Certificates.Private_Key_Matches_Certificate
                 (Ada.Strings.Unbounded.To_String (Leaf),
                  Ada.Strings.Unbounded.To_String (Leaf_K))
               = CryptoLib.Certificates.Ok,
               Label & " issued key belongs to the certificate issued with it");
         end Check_Chain;
      begin
         Check_Chain (CryptoLib.Certificates.Ed25519_Key);
         Check_Chain (CryptoLib.Certificates.P384_Key);
         Check_Chain (CryptoLib.Certificates.Ed448_Key);
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
            Bundle,
            --  Cheap on purpose: this checks that a bundle comes out, not
            --  how hard it is to open. Check_PKCS12_Work_Factor covers that.
            Iterations => 4_096) = CryptoLib.Certificates.Ok,
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
   --  Where a certificate says to ask about it, and where to fetch its
   --  issuer. Reading these is what makes the revocation machinery reachable:
   --  a caller told that fetching is its own job still needs to be told the
   --  address.
   procedure Check_X509_Access_Locations is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.X509.Extensions.Access_Method;
      use type CryptoLib.X509.Extensions.General_Name_Kind;

      package X509C renames CryptoLib.X509.Certificates;
      package XE renames CryptoLib.X509.Extensions;

      Rich_Locations_DER : constant String :=
        "308202653082020ba003020102021442a799cc9ee44693e58977316c17422710dee46a300a06082a8648ce3d04" &
        "030230123110300e06035504030c077375626a656374301e170d3236303732383232323732345a170d32363038" &
        "32373232323732345a30123110300e06035504030c077375626a6563743059301306072a8648ce3d020106082a" &
        "8648ce3d0301070342000485a12a9ae8f287719fb228ab6c3e7382797ae9f619dd81191c057c95fe5657fed0e7" &
        "077ec57d20367034ca121396308c33f8f2caf86aa74d628dcfe8d675d097a382013d3082013930819906082b06" &
        "01050507010104818c308189302106082b060105050730018615687474703a2f2f6f6373702e6578616d706c65" &
        "2f61302306082b060105050730028617687474703a2f2f63612e6578616d706c652f692e637274301c06082b06" &
        "01050507300181106f637370406578616d706c652e636f6d302106082b060105050730018615687474703a2f2f" &
        "6f6373702e6578616d706c652f62307c0603551d1f047530733038a036a0348618687474703a2f2f63726c2e65" &
        "78616d706c652f312e63726c8618687474703a2f2f63726c2e6578616d706c652f322e63726c3037a035a033a4" &
        "1730153113301106035504030c0a63726c206973737565728618687474703a2f2f63726c2e6578616d706c652f" &
        "332e63726c301d0603551d0e04160414fd1d94e663fdd9c8c5cc77056ed51f11a34760fb300a06082a8648ce3d" &
        "0403020348003045022100a74db3351d4d7b5243fb3ee98f32c304e2103f79909ac3ae30db26bd9390c7480220" &
        "3094ade938c48216df9851f5ebe6c419a4004b02f85c5b1bec00c40bf61dc9aa";

      Relative_CRL_DER : constant String :=
        "3082016c30820113a00302010202141d7d7ae17d3708b8e11237cd63c957816560baa6300a06082a8648ce3d04" &
        "030230123110300e06035504030c077375626a656374301e170d3236303732383232323631335a170d32363038" &
        "32373232323631335a30123110300e06035504030c077375626a6563743059301306072a8648ce3d020106082a" &
        "8648ce3d0301070342000485a12a9ae8f287719fb228ab6c3e7382797ae9f619dd81191c057c95fe5657fed0e7" &
        "077ec57d20367034ca121396308c33f8f2caf86aa74d628dcfe8d675d097a347304530240603551d1f041d301b" &
        "3019a017a115301306035504030c0c72656c61746976652063726c301d0603551d0e04160414fd1d94e663fdd9" &
        "c8c5cc77056ed51f11a34760fb300a06082a8648ce3d0403020347003044022066e115503346fdced94320de48" &
        "193b36846f5be7bc4a42366ff1ada0c2324afe02205bf99505389f545214dca1452037398df88d4ce833fa7cbb" &
        "1ddd7fcea157428c";

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
      Rich   : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (Rich_Locations_DER), CryptoLib.ASN1.Default_Limits,
           Status);
   begin
      Check (Status = CryptoLib.ASN1.Errors.Ok,
             "a certificate naming responders and CRLs decodes");

      --  Four access descriptions, reported in the order the certificate
      --  gives them. Order is not decoration: it is the issuer's preference,
      --  and a caller working down the list is following it.
      Check (XE.Authority_Info_Count (Rich) = 4,
             "every access description is counted");
      Check (XE.Authority_Info_Method (Rich, 1) = XE.OCSP_Responder
             and then XE.Authority_Info_URI (Rich, 1)
                      = "http://ocsp.example/a",
             "the first entry is a responder");
      Check (XE.Authority_Info_Method (Rich, 2) = XE.CA_Issuers
             and then XE.Authority_Info_URI (Rich, 2)
                      = "http://ca.example/i.crt",
             "the second is where to fetch the issuer");
      Check (XE.Authority_Info_Method (Rich, 4) = XE.OCSP_Responder
             and then XE.Authority_Info_URI (Rich, 4)
                      = "http://ocsp.example/b",
             "the fourth is a second responder");

      --  The third entry names a responder by mail address rather than URI.
      --  It is still counted and its kind still reported: dropping it would
      --  renumber everything after it, and a caller indexing the list would
      --  quietly read the wrong entry.
      Check (XE.Authority_Info_Method (Rich, 3) = XE.OCSP_Responder,
             "a non-URI location keeps its place in the list");
      Check (XE.Authority_Info_Kind (Rich, 3) = XE.Email_Address,
             "and its kind is reported rather than guessed");
      Check (XE.Authority_Info_URI (Rich, 3) = "",
             "and it yields no URI, since it is not one");

      Check (XE.OCSP_Responder_URI (Rich) = "http://ocsp.example/a",
             "the first responder URI is the one to ask");
      Check (XE.CA_Issuers_URI (Rich) = "http://ca.example/i.crt",
             "and the issuer is fetched from the first caIssuers URI");

      --  Four names across two distribution points -- three URIs and a
      --  directory name -- flattened: a caller wants the places a CRL can be
      --  fetched from, and which distribution point each came from does not
      --  change where to go.
      Check (XE.CRL_Distribution_Point_Count (Rich) = 4,
             "names from every distribution point are counted");
      Check (XE.CRL_Distribution_Point_URI (Rich, 1)
             = "http://crl.example/1.crl"
             and then XE.CRL_Distribution_Point_URI (Rich, 2)
                      = "http://crl.example/2.crl",
             "both names of the first distribution point are reached");
      Check (XE.CRL_Distribution_Point_Kind (Rich, 3) = XE.Directory_Name,
             "a directory name is reported as one");
      Check (XE.CRL_Distribution_Point_URI (Rich, 4)
             = "http://crl.example/3.crl",
             "and the URI beside it is still reached");

      --  A distribution point named relative to the CRL issuer is a fragment
      --  of a name, not a place. Reporting it as a location would hand a
      --  caller something it cannot fetch from.
      declare
         Relative : constant X509C.Certificate :=
           X509C.Decode_DER
             (From_Hex (Relative_CRL_DER), CryptoLib.ASN1.Default_Limits,
              Status);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok,
                "a relative distribution point decodes");
         Check (XE.CRL_Distribution_Point_Count (Relative) = 0,
                "a distribution point relative to the CRL issuer names no "
                & "place to fetch from");

         --  Absent is not empty-and-present: a certificate naming nothing
         --  must not read as one naming something unreachable.
         Check (XE.Authority_Info_Count (Relative) = 0,
                "a certificate with no access descriptions reports none");
         Check (XE.OCSP_Responder_URI (Relative) = "",
                "and names no responder");
      end;
   end Check_X509_Access_Locations;

   --  An extension that appears twice, and extensions on a certificate whose
   --  version does not admit them. Both are ways of writing a certificate
   --  that means one thing to one reader and something else to another,
   --  which is worth refusing outright: whichever instance this happened to
   --  take, some other implementation takes the other, and the two disagree
   --  about what the issuer authorised.
   procedure Check_Certificate_Ambiguity is
      use type CryptoLib.ASN1.Errors.Decode_Status;

      package X509C renames CryptoLib.X509.Certificates;
      package XE renames CryptoLib.X509.Extensions;

      Honest_V3_DER : constant String :=
        "308203253082020da00302010202023000300d06092a864886f70d01010b050030163114301206035504030c0b" &
        "63726c2d746573742d6361301e170d3236303732393031313432365a170d3237303732393031313432365a301a" &
        "3118301606035504030c0f7265766f6b65642e6578616d706c6530820122300d06092a864886f70d0101010500" &
        "0382010f003082010a0282010100c0ed219d3150260bb4a5a976fd93941636a1dcdc8976321a5c82e468c74ff7" &
        "e755f29a6940524606cf7e70308e8c3ed01c6954e7e7a45fdedd1d914b6cf2459cbba0b0a2f3a248771f69301a" &
        "c2735a408af830e03b7c3941648de0810c102c79f17da1d486a3b676993fd30102ed86ee4d4cde770d3abf8dd4" &
        "b178885132f79e8799c63595af16af350d94207d96a5d830c19e2eff9edb43607e7c8e5ba3e737b82f71937a7c" &
        "a59ffcac9dfc633aa69ce1e08aabf84a068c4e1dfa9f7ca28f959062408140c1c8cf63d66761609bc2dff8b3d4" &
        "bd3250ee0a86b507023e9f9aee80b2184c01758ffaf3c280eeeff0fb0926de9c83cfc2f327c4dcd6254a044715" &
        "0203010001a3793077300c0603551d130101ff04023000300e0603551d0f0101ff0404030205a030170603551d" &
        "110410300e820c686f73742e6578616d706c65301d0603551d0e04160414b2300eeca1b7034732dc8f88bc8292" &
        "ab5ecbe8fe301f0603551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300d06092a8648" &
        "86f70d01010b0500038201010032fbc37897b1aded84fd07e03393dbd35ab45ba2149704757853447c7c82dc2f" &
        "1e5a5cf0fca4a9b513e7014f240a1acf63ec11514a61fa82d801339d754fcf60049cda3f618b215aa8c0bbd547" &
        "4fae1fcb1d7a60853962fc7a99af186be8f9eab7c4dfedac2824545d94eca8f716bb2e7a99145172c8f626b0d8" &
        "8e50bfa8083c833abe24a060379ae0bae5478e728d9bf302ff18540b24443ad055ce624d7c3de8526df13a6bc4" &
        "b727e57e0f2cb2ee3cafa62b177b7272e0b8bcc327441e5fc27acd6bf5a57df5ac9cb24025efb811d7520b94d2" &
        "0ecf1d6d96a26f7d1312e1c4e9389c35ff6bdce8ee602ed60cce5f9a7ddbb20fa4a1d073d217a282782a40de";

      Duplicate_Extension_DER : constant String :=
        "308203433082022ba00302010202023000300d06092a864886f70d01010b050030163114301206035504030c0b" &
        "63726c2d746573742d6361301e170d3236303732393031313432365a170d3237303732393031313432365a301a" &
        "3118301606035504030c0f7265766f6b65642e6578616d706c6530820122300d06092a864886f70d0101010500" &
        "0382010f003082010a0282010100c0ed219d3150260bb4a5a976fd93941636a1dcdc8976321a5c82e468c74ff7" &
        "e755f29a6940524606cf7e70308e8c3ed01c6954e7e7a45fdedd1d914b6cf2459cbba0b0a2f3a248771f69301a" &
        "c2735a408af830e03b7c3941648de0810c102c79f17da1d486a3b676993fd30102ed86ee4d4cde770d3abf8dd4" &
        "b178885132f79e8799c63595af16af350d94207d96a5d830c19e2eff9edb43607e7c8e5ba3e737b82f71937a7c" &
        "a59ffcac9dfc633aa69ce1e08aabf84a068c4e1dfa9f7ca28f959062408140c1c8cf63d66761609bc2dff8b3d4" &
        "bd3250ee0a86b507023e9f9aee80b2184c01758ffaf3c280eeeff0fb0926de9c83cfc2f327c4dcd6254a044715" &
        "0203010001a38196308193300f0603551d130101ff040530030101ff30090603551d1304023000300c0603551d" &
        "130101ff04023000300e0603551d0f0101ff0404030205a030170603551d110410300e820c686f73742e657861" &
        "6d706c65301d0603551d0e04160414b2300eeca1b7034732dc8f88bc8292ab5ecbe8fe301f0603551d23041830" &
        "168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300d06092a864886f70d01010b0500038201010007da" &
        "c8456835599f6b84eb8f88ad5eacc9bea0568a5f832288edab6454b5f06a5083f7bd83789d554dc33e44e9b8eb" &
        "f07d199b9e1a9980e900f490a1726e0cb6891e8413012e64193f90f1de7383e0442be007a0d38a8322701a5281" &
        "6abe62869d7d117b961b005a2752d592eeb4e0486ae4065038d05792501c3d1e24bf081522e0af4bf0986aac51" &
        "dc915ba204f188d4d5f124a32c5823bff6d671c07b2f2df9cd4728b136c11aed8a110d8ed37297d50fb4c13f8c" &
        "04625622168659e00a7b39ad192f4eccfe9c031dd1da51968543c6bce1d0d2850a40072f66040452bae65aa06b" &
        "d363111be7d43e77c292e762910985d6fc3bd65dba43bb5d54cfc38c81";

      V1_With_Extensions_DER : constant String :=
        "308203203082020802023000300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d74" &
        "6573742d6361301e170d3236303732393031313432365a170d3237303732393031313432365a301a3118301606" &
        "035504030c0f7265766f6b65642e6578616d706c6530820122300d06092a864886f70d01010105000382010f00" &
        "3082010a0282010100c0ed219d3150260bb4a5a976fd93941636a1dcdc8976321a5c82e468c74ff7e755f29a69" &
        "40524606cf7e70308e8c3ed01c6954e7e7a45fdedd1d914b6cf2459cbba0b0a2f3a248771f69301ac2735a408a" &
        "f830e03b7c3941648de0810c102c79f17da1d486a3b676993fd30102ed86ee4d4cde770d3abf8dd4b178885132" &
        "f79e8799c63595af16af350d94207d96a5d830c19e2eff9edb43607e7c8e5ba3e737b82f71937a7ca59ffcac9d" &
        "fc633aa69ce1e08aabf84a068c4e1dfa9f7ca28f959062408140c1c8cf63d66761609bc2dff8b3d4bd3250ee0a" &
        "86b507023e9f9aee80b2184c01758ffaf3c280eeeff0fb0926de9c83cfc2f327c4dcd6254a0447150203010001" &
        "a3793077300c0603551d130101ff04023000300e0603551d0f0101ff0404030205a030170603551d110410300e" &
        "820c686f73742e6578616d706c65301d0603551d0e04160414b2300eeca1b7034732dc8f88bc8292ab5ecbe8fe" &
        "301f0603551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300d06092a864886f70d0101" &
        "0b050003820101004a659bb771d37116b98b3991540d1a1bc392137fcfb077420fb43b414b0db9f3404a29d98c" &
        "94bc9b74c34f37b68486dcb533d263fe52b2129fc5874f2269f86b73b3deb0580aec94172626aad4a6906bca5d" &
        "5b28d350a62597ac9958dc34d0228800b4016423cabd05a264c5e2dd7601183daf8f4135cbfd01314579a3b6bc" &
        "5c1db235debec26f05edc536ca0aca626374ccd53b443ee9ab1e7e8ef627f59867c5d85533bd0a0e6958b61d02" &
        "3405f393c510ec66bb744f8b3a2f8db42b779b1f0c47fc9cbcf91b1f2392057848f152967817d96afc45d11a1d" &
        "1655f418563d3b91466b825335c56ac1b1d755240fe6b50a0eee3c28f0dc7f62aa548200ded705";

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
      --  The certificate the other two are built from: an ordinary v3 leaf
      --  that is not a CA. This must keep working, or the check below is
      --  refusing certificates rather than ambiguity.
      declare
         Honest : constant X509C.Certificate :=
           X509C.Decode_DER
             (From_Hex (Honest_V3_DER), CryptoLib.ASN1.Default_Limits,
              Status);
         Limits : constant XE.Basic_Constraints :=
           XE.Get_Basic_Constraints (Honest);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok
                and then X509C.Is_Present (Honest),
                "an ordinary v3 certificate decodes");
         Check (Limits.Present and then not Limits.Is_CA,
                "and is not a CA");
      end;

      --  The same certificate with basicConstraints CA:TRUE inserted before
      --  the CA:FALSE it already carried, and re-signed so the signature
      --  holds. Taking the first instance makes it a CA; taking the last
      --  makes it a leaf. OpenSSL refuses to load it at all.
      declare
         Doubled : constant X509C.Certificate :=
           X509C.Decode_DER
             (From_Hex (Duplicate_Extension_DER),
              CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (Status /= CryptoLib.ASN1.Errors.Ok,
                "a certificate carrying an extension twice is refused, got "
                & CryptoLib.ASN1.Errors.Status_Image (Status));
         Check (not X509C.Is_Present (Doubled),
                "and nothing is decoded from it");
      end;

      --  Extensions on a v1 certificate: some parsers read them, some
      --  ignore them, which is the same disagreement reached another way.
      declare
         Old : constant X509C.Certificate :=
           X509C.Decode_DER
             (From_Hex (V1_With_Extensions_DER),
              CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (Status /= CryptoLib.ASN1.Errors.Ok,
                "extensions on a v1 certificate are refused, got "
                & CryptoLib.ASN1.Errors.Status_Image (Status));
         Check (not X509C.Is_Present (Old),
                "and nothing is decoded from it either");
      end;
   end Check_Certificate_Ambiguity;

   --  Malformed input must come back as a status, never as an exception.
   --
   --  A library that parses what an attacker sends and lets an exception out
   --  has turned a malformed message into a denial of service, which is a
   --  vulnerability in a component whose whole contract is to fail closed.
   --  The seed is a real certificate; the mutations are deterministic, so a
   --  failure here reproduces exactly rather than once in a while.
   procedure Check_Decoder_Robustness is
      use type CryptoLib.ASN1.Errors.Decode_Status;

      package X509C renames CryptoLib.X509.Certificates;
      package XC renames CryptoLib.X509.CRLs;
      package CO renames CryptoLib.OCSP;

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

      function Decoded_Bytes (Text : String)
        return Ada.Streams.Stream_Element_Array
      is
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Text)));
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Text'First;
         P      : CryptoLib.PEM.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Text, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, P);
         return Buffer (Buffer'First .. Last);
      end Decoded_Bytes;

      CA_PEM   : Unbounded_String;
      CA_Key   : Unbounded_String;
      Leaf_PEM : Unbounded_String;
      Leaf_Key : Unbounded_String;
      Outcome  : CryptoLib.Certificates.Certificate_Status;

      --  A deterministic generator: the suite must fail the same way twice.
      State : Interfaces.Unsigned_64 := 16#2545F4914F6CDD1D#;
      function Next return Natural is
         use type Interfaces.Unsigned_64;
      begin
         State := State xor Interfaces.Shift_Left (State, 13);
         State := State xor Interfaces.Shift_Right (State, 7);
         State := State xor Interfaces.Shift_Left (State, 17);
         return Natural (State mod 65_536);
      end Next;

      Raised  : Natural := 0;
      Decoded : Natural := 0;
      Rounds  : constant := 3_000;

      --  A second seed, carrying every policy extension and both qualifier
      --  kinds. The issued certificate above carries none, so without this
      --  the policy parsers never see a mutated byte -- and they are five
      --  readers of attacker-supplied extension values.
      Policy_Seed_DER : constant String :=
        "30820249308201cea003020102021457dc68c06a8727f75fca6853854da359d207b6fc300a06082a8648ce3d04" &
        "030230163114301206035504030c0b706f6c6963792d726f6f74301e170d3236303732393037343631385a170d" &
        "3237303532353037343631385a30163114301206035504030c0b706f6c6963792d726f6f743076301006072a86" &
        "48ce3d020106052b8104002203620004fab57ef5a1788133397062176d5925a43cd8595df917f6743c6323355d" &
        "2658e3173fce28a87905f80b9ba83ee1aab697a7bb599368c751864a56fbaa711e5b2726530bc20c83714e3ce3" &
        "718536a74005d731b1489eb8e166434548c44d69b0cfa381dc3081d9300f0603551d130101ff040530030101ff" &
        "300e0603551d0f0101ff0404030201063081960603551d2004818e30818b30818806092b06010401868d1f0130" &
        "7b302906082b06010505070201161d68747470733a2f2f6578616d706c652e746573742f6370732e68746d6c30" &
        "4e06082b060105050702023042301a1a104578616d706c652054657374204f726730060201010201021a244973" &
        "7375656420756e64657220746865206578616d706c65207465737420706f6c696379301d0603551d0e04160414" &
        "208a7da7f801c4b3c24c5dea13986578cbec0ed6300a06082a8648ce3d0403020369003066023100d3a5eb9ed0" &
        "6bc532ebf2da5d489183d0d4f082690d1e888f8ea954e0594b77d2a9d2494c620bc7665fec33b9f48809510231" &
        "00e86ff2b3713b9ba9a632c6a0fa424829c0548fee20becea5932b0f3e759885375e1feb99b0a882cd62789cfe" &
        "ea02f666";
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("robustness-ca", CA_PEM, CA_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "host.example",
           [1 => To_Unbounded_String ("host.example")],
           Leaf_PEM, Leaf_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: leaf issued");

      declare
         Issued : constant Ada.Streams.Stream_Element_Array :=
           Decoded_Bytes (To_String (Leaf_PEM));
         With_Policies : constant Ada.Streams.Stream_Element_Array :=
           From_Hex (Policy_Seed_DER);
      begin
         Check (Issued'Length > 64, "fixture: the seed certificate decoded");
         Check (With_Policies'Length > 64,
                "fixture: the policy-carrying seed decoded");

         for Round in 1 .. Rounds loop
            declare
               --  Alternating, so both shapes are mutated equally.
               Seed : constant Ada.Streams.Stream_Element_Array :=
                 (if Round mod 2 = 0 then Issued else With_Policies);
               Work : Ada.Streams.Stream_Element_Array := Seed;
               Cuts : constant Natural := 1 + Next mod 6;
               Last : Ada.Streams.Stream_Element_Offset := Work'Last;
            begin
               for Edit in 1 .. Cuts loop
                  declare
                     Where : constant Ada.Streams.Stream_Element_Offset :=
                       Work'First
                       + Ada.Streams.Stream_Element_Offset
                           (Next mod Natural (Work'Length));
                  begin
                     case Next mod 3 is
                        when 0 =>
                           --  A byte anywhere.
                           Work (Where) :=
                             Ada.Streams.Stream_Element (Next mod 256);
                        when 1 =>
                           --  Something that looks like a length, which is
                           --  where a reader is most likely to be led astray.
                           Work (Where) :=
                             (case Next mod 6 is
                                 when 0 => 16#80#,
                                 when 1 => 16#81#,
                                 when 2 => 16#82#,
                                 when 3 => 16#84#,
                                 when 4 => 16#FF#,
                                 when others => 16#00#);
                        when others =>
                           --  Truncation.
                           if Where > Work'First then
                              Last :=
                                Ada.Streams.Stream_Element_Offset'Min
                                  (Last, Where);
                           end if;
                     end case;
                  end;
               end loop;

               --  Every decoder sees every input. A mutated certificate is
               --  not a CRL, but the CRL reader still walks into it, and
               --  walking into the wrong thing is exactly the case that has
               --  to stay safe.
               declare
                  Input  : Ada.Streams.Stream_Element_Array
                    renames Work (Work'First .. Last);
                  Status : CryptoLib.ASN1.Errors.Decode_Status;
               begin
                  declare
                     C : constant X509C.Certificate :=
                       X509C.Decode_DER
                         (Input, CryptoLib.ASN1.Default_Limits, Status);
                  begin
                     if X509C.Is_Present (C) then
                        Decoded := Decoded + 1;

                        --  Read every policy extension and the qualifier
                        --  text: a parser that returns a status and then
                        --  hands back a span that blows up on use has not
                        --  failed safely.
                        declare
                           package PP renames CryptoLib.X509.Policies;
                           Named : constant PP.Policy_Set :=
                             PP.Policies_Of (C);
                           Maps  : constant PP.Mapping_Set :=
                             PP.Mappings_Of (C);
                           Cons  : constant PP.Policy_Constraints :=
                             PP.Constraints_Of (C);
                           Inh   : constant PP.Inhibit_Any_Policy :=
                             PP.Inhibit_Of (C);
                        begin
                           for P in 1 .. Named.Count loop
                              for Q in 1 ..
                                Named.Entries (P).Qualifier_Count
                              loop
                                 declare
                                    Text : constant String :=
                                      Named.Entries (P).Qualifiers (Q).Text
                                        (1 .. Named.Entries (P).Qualifiers (Q)
                                                .Length);
                                 begin
                                    pragma Unreferenced (Text);
                                 end;
                              end loop;
                           end loop;
                           pragma Unreferenced (Maps, Cons, Inh);
                        end;

                        for I in 1 .. X509C.Extension_Count (C) loop
                           declare
                              Ignore : constant CryptoLib.ASN1.Octets :=
                                X509C.Extension_Value (C, I);
                           begin
                              pragma Unreferenced (Ignore);
                           end;
                        end loop;
                     end if;
                  end;

                  declare
                     L : constant XC.Revocation_List :=
                       XC.Decode_DER
                         (Input, CryptoLib.ASN1.Default_Limits, Status);
                     N : constant Natural := XC.Entry_Count (L);
                     B : constant Boolean :=
                       XC.Has_Unsupported_Critical_Extension (L);
                  begin
                     pragma Unreferenced (N, B);
                  end;

                  declare
                     R : constant CO.Response :=
                       CO.Decode_Response
                         (Input, CryptoLib.ASN1.Default_Limits, Status);
                     B : constant Boolean :=
                       CO.Has_Unsupported_Critical_Extension (R);
                  begin
                     pragma Unreferenced (B);
                  end;
               end;
            exception
               when others =>
                  Raised := Raised + 1;
            end;
         end loop;

         Check (Raised = 0,
                "no malformed input escaped as an exception, got"
                & Natural'Image (Raised) & " of" & Natural'Image (Rounds));

         --  Without this the check above passes trivially on input that
         --  never reaches the decoder at all.
         Check (Decoded > Rounds / 100,
                "and enough mutations still decoded to reach real code, got"
                & Natural'Image (Decoded));
      end;
   end Check_Decoder_Robustness;

   --  A serial number names a certificate. A revocation names a certificate
   --  by issuer and serial and by nothing else, so two certificates from one
   --  CA sharing a serial cannot be revoked apart: revoking either revokes
   --  both, and there is no way to revoke just one. These used to be
   --  hardcoded, so every server certificate this crate issued carried the
   --  same one.
   procedure Check_Serial_Numbers is
      use type CryptoLib.ASN1.Errors.Decode_Status;

      package X509C renames CryptoLib.X509.Certificates;

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
         return X509C.Decode_DER
           (Buffer (Buffer'First .. Last), CryptoLib.ASN1.Default_Limits, D);
      end Decoded;

      CA_PEM, CA_Key   : Unbounded_String;
      A_PEM, A_Key     : Unbounded_String;
      B_PEM, B_Key     : Unbounded_String;
      Outcome          : CryptoLib.Certificates.Certificate_Status;

      --  Enough that a collision is not a thing that happens, and enough to
      --  put the value out of reach of anyone wanting to predict it.
      Minimum_Octets : constant := 8;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("serial-ca", CA_PEM, CA_Key, CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "alpha.example",
           [1 => To_Unbounded_String ("alpha.example")], A_PEM, A_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: alpha issued");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "beta.example",
           [1 => To_Unbounded_String ("beta.example")], B_PEM, B_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: beta issued");

      declare
         CA    : constant X509C.Certificate := Decoded (To_String (CA_PEM));
         Alpha : constant X509C.Certificate := Decoded (To_String (A_PEM));
         Beta  : constant X509C.Certificate := Decoded (To_String (B_PEM));

         SA : constant Ada.Streams.Stream_Element_Array :=
           X509C.Serial_Number (Alpha);
         SB : constant Ada.Streams.Stream_Element_Array :=
           X509C.Serial_Number (Beta);
         SC : constant Ada.Streams.Stream_Element_Array :=
           X509C.Serial_Number (CA);
      begin
         Check (X509C.Is_Present (Alpha) and then X509C.Is_Present (Beta),
                "fixture: both certificates decode");

         --  The property that matters.
         Check (SA /= SB,
                "two certificates from one CA get different serials");
         Check (SA /= SC and then SB /= SC,
                "and neither collides with the CA's own");

         Check (SA'Length >= Minimum_Octets and then SB'Length >= Minimum_Octets,
                "a serial carries real width, got"
                & Ada.Streams.Stream_Element_Offset'Image (SA'Length)
                & " octets");

         --  RFC 5280 requires a positive serial. The encoding is the content
         --  octets of an INTEGER, so a leading octet at or above 16#80#
         --  would make it negative, and a leading zero would mean the
         --  encoder padded one that was.
         Check (SA (SA'First) < 16#80# and then SB (SB'First) < 16#80#,
                "a serial is positive");
         Check (SA (SA'First) /= 0 and then SB (SB'First) /= 0,
                "and minimally encoded, with no padding octet");
      end;
   end Check_Serial_Numbers;

   --  A certificate is valid from when it was issued, for as long as the
   --  caller asked. The window used to be two literals in the source, so
   --  every certificate ever issued claimed the same decade and issuing
   --  would have started producing already-expired certificates once it ran
   --  out.
   procedure Check_Validity_Window is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.X509.Certificate_Time;

      package X509C renames CryptoLib.X509.Certificates;

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
         return X509C.Decode_DER
           (Buffer (Buffer'First .. Last), CryptoLib.ASN1.Default_Limits, D);
      end Decoded;

      CA_PEM, CA_Key, Short_PEM, Short_Key, Long_PEM, Long_Key :
        Unbounded_String;
      Outcome : CryptoLib.Certificates.Certificate_Status;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("validity-ca", CA_PEM, CA_Key, CryptoLib.Certificates.P384_Key,
           --  Longer than the certificates issued under it, because a leaf
           --  is now held to its issuer's expiry: a CA of the default life
           --  would clamp the long one below 2049 and this would be testing
           --  the clamp rather than the encoding.
           Valid_Days => 12_000);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "short.example",
           [1 => To_Unbounded_String ("short.example")], Short_PEM, Short_Key,
           Valid_Days => 1);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: short issued");

      --  Long enough that notAfter lands past 2049, where UTCTime stops
      --  being unambiguous and the encoding has to change.
      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "long.example",
           [1 => To_Unbounded_String ("long.example")], Long_PEM, Long_Key,
           Valid_Days => 10_000);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: long issued");

      declare
         Short : constant X509C.Certificate := Decoded (To_String (Short_PEM));
         Long  : constant X509C.Certificate := Decoded (To_String (Long_PEM));
      begin
         Check (X509C.Is_Present (Short) and then X509C.Is_Present (Long),
                "both certificates decode");

         --  The lifetime the caller asked for is the lifetime it got: a
         --  one-day certificate and a 10,000-day one cannot share a notAfter.
         Check (X509C.Not_After (Short) /= X509C.Not_After (Long),
                "the requested lifetime decides the expiry");
         Check (CryptoLib.X509.Is_Not_After
                  (X509C.Not_After (Short), X509C.Not_After (Long)),
                "and a shorter one expires first");

         --  Valid at the moment of issue, which a fixed window stops being.
         Check (CryptoLib.X509.Is_Not_After
                  (X509C.Not_Before (Short), X509C.Not_After (Short)),
                "the window is not inverted");
         Check (X509C.Not_Before (Short).Year >= 2026,
                "and starts no earlier than this crate was written, got"
                & Natural'Image (X509C.Not_Before (Short).Year));

         --  Past 2049 a two-digit year stops being unambiguous, so the
         --  encoding has to switch. Reading it back at all proves it did:
         --  a UTCTime carrying "53" would decode as 1953.
         Check (X509C.Not_After (Long).Year > 2049,
                "a long-lived certificate expires past 2049, got"
                & Natural'Image (X509C.Not_After (Long).Year));
         Check (CryptoLib.X509.Is_Not_After
                  (X509C.Not_Before (Long), X509C.Not_After (Long)),
                "and its window is still the right way round, which a "
                & "two-digit year would not have been");
      end;
   end Check_Validity_Window;

   --  A certificate says which key it belongs to and which key signed it.
   --
   --  RFC 5280 requires both -- subjectKeyIdentifier in every CA
   --  certificate, authorityKeyIdentifier in everything but a self-signed
   --  root -- because a name alone stops identifying a certificate as soon
   --  as a CA has more than one. After a re-key, or under a cross-signature,
   --  several certificates share a subject name and differ only by key. The
   --  crate issued neither.
   procedure Check_Key_Identifiers is
      use type CryptoLib.ASN1.Errors.Decode_Status;

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
         return X509C.Decode_DER
           (Buffer (Buffer'First .. Last), CryptoLib.ASN1.Default_Limits, D);
      end Decoded;

      CA_PEM, CA_Key, Leaf_PEM, Leaf_Key : Unbounded_String;
      Outcome : CryptoLib.Certificates.Certificate_Status;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("identifier-ca", CA_PEM, CA_Key, CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "host.example",
           [1 => To_Unbounded_String ("host.example")], Leaf_PEM, Leaf_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: leaf issued");

      declare
         CA   : constant X509C.Certificate := Decoded (To_String (CA_PEM));
         Leaf : constant X509C.Certificate := Decoded (To_String (Leaf_PEM));

         CA_SKI   : constant CryptoLib.ASN1.Octets :=
           XE.Subject_Key_Identifier (CA);
         Leaf_SKI : constant CryptoLib.ASN1.Octets :=
           XE.Subject_Key_Identifier (Leaf);
         Leaf_AKI : constant CryptoLib.ASN1.Octets :=
           XE.Authority_Key_Identifier (Leaf);
         CA_AKI   : constant CryptoLib.ASN1.Octets :=
           XE.Authority_Key_Identifier (CA);
      begin
         Check (X509C.Is_Present (CA) and then X509C.Is_Present (Leaf),
                "both certificates decode");

         --  SHA-1 over the public key bits, which is the derivation 38 of
         --  the 40 system roots carrying one were measured to use.
         Check (CA_SKI'Length = 20 and then Leaf_SKI'Length = 20,
                "each certificate names its own key");
         Check (CA_SKI /= Leaf_SKI,
                "and two different keys get different identifiers");

         --  The link that makes the pair useful: the leaf points at the key
         --  that signed it, which is the CA's own.
         Check (Leaf_AKI = CA_SKI,
                "the leaf names the key that signed it");

         --  A self-signed CA signed itself, so it points at itself.
         Check (CA_AKI = CA_SKI,
                "and a self-signed CA points at its own key");
      end;
   end Check_Key_Identifiers;

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

   --  A certificate longer than 65_535 octets.
   --
   --  The DER length encoder stopped at a two-octet long form, and Byte
   --  truncates rather than complains, so anything larger was given a length
   --  with its high bits dropped. Issuance reported Ok and produced a
   --  certificate no parser could read -- OpenSSL refused it outright. A
   --  subject alternative name list is unbounded, so a caller with enough
   --  names reaches this with no indication that anything went wrong.
   --
   --  Decoding is the whole check: the reader refuses trailing data, so a
   --  certificate whose outer length is short by any amount cannot decode.
   procedure Check_Large_Certificate is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.PEM.Decode_Status;

      package X509C renames CryptoLib.X509.Certificates;

      --  Long names rather than many, because the reader bounds a sequence
      --  at 1024 items and the point here is the byte count, not the count.
      Count : constant := 1000;

      function Long_Name (Index : Positive) return Unbounded_String is
         Number : constant String := Positive'Image (Index);
      begin
         return To_Unbounded_String
           ("h" & Number (Number'First + 1 .. Number'Last) & "."
            & [1 .. 60 => 'a'] & ".example");
      end Long_Name;

      CA_PEM, CA_Key, Leaf_PEM, Leaf_Key : Unbounded_String;
      Names   : CryptoLib.Certificates.Subject_Alternative_Name_List
        (1 .. Count);
      Outcome : CryptoLib.Certificates.Certificate_Status;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("large-ca", CA_PEM, CA_Key, CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      for I in Names'Range loop
         Names (I) := Long_Name (I);
      end loop;

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "large.example", Names,
           Leaf_PEM, Leaf_Key);
      Check (Outcome = CryptoLib.Certificates.Ok,
             "a certificate with a great many names is issued");

      declare
         Text   : constant String := To_String (Leaf_PEM);
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Text)));
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Text'First;
         P      : CryptoLib.PEM.Decode_Status;
         Status : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Text, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, P);
         Check (P = CryptoLib.PEM.Ok, "its armour decodes");

         --  Past the two-octet long form, which is the case that was wrong.
         Check (Last > 65_535,
                "and it really is larger than a two-octet length can hold,"
                & Ada.Streams.Stream_Element_Offset'Image (Last)
                & " octets");

         --  Read back under limits that admit a certificate this size. The
         --  default caps a single string at 64 KB, which is a deliberate
         --  bound on what a caller is willing to decode rather than
         --  anything about the encoding -- and it is why the default limits
         --  will not read a certificate this crate can now write. What is
         --  under test is the length octets, so the bound is lifted here and
         --  left alone everywhere else.
         declare
            Roomy : constant CryptoLib.ASN1.Decode_Limits :=
              (Maximum_Input_Size     => 1024 * 1024,
               Maximum_Nesting_Depth  => 16,
               Maximum_Sequence_Items => 2048,
               Maximum_String_Length  => 1024 * 1024);
            Item  : constant X509C.Certificate :=
              X509C.Decode_DER
                (Buffer (Buffer'First .. Last), Roomy, Status);
         begin
            Check (Status = CryptoLib.ASN1.Errors.Ok
                   and then X509C.Is_Present (Item),
                   "and it decodes, got "
                   & CryptoLib.ASN1.Errors.Status_Image (Status));

            --  The reader refuses trailing data, so decoding at all proves
            --  the outer length octets named the whole certificate. Under
            --  the old encoder this came back short and the remainder read
            --  as trailing rubbish.
            Check (X509C.Extension_Count (Item) >= 4,
                   "with its extensions intact");
         end;
      end;
   end Check_Large_Certificate;

   --  A certificate whose serial number is absurd.
   --
   --  Nothing bounds a serial on the way in, and a CertID carries it, so the
   --  OCSP request builder is handed whatever the certificate says. Its
   --  length emitter stopped at a two-octet long form and converted the
   --  third octet to a Stream_Element rather than masking it, so a length
   --  past 65_535 raised CONSTRAINT_ERROR -- an exception escaping on input
   --  from whoever supplied the certificate.
   procedure Check_Oversized_Serial is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.PEM.Decode_Status;

      package X509C renames CryptoLib.X509.Certificates;
      package CO renames CryptoLib.OCSP;
      subtype Blob is Ada.Streams.Stream_Element_Array;
      subtype Spot is Ada.Streams.Stream_Element_Offset;

      --  Either side of every boundary where the DER length form changes:
      --  short form, one octet, two, three. Each fix in this area was found
      --  by tripping over one value; this walks all of them.
      type Size_List is array (Positive range <>) of Natural;
      Sizes : constant Size_List :=
        [126, 127, 128, 254, 255, 256, 65_534, 65_535, 65_536, 70_000];

      --  Minimal DER length octets, so the spliced certificate is one the
      --  reader will accept: it refuses a length written wider than it needs.
      function Length_Octets (Value : Natural) return Blob is
         Wide  : Blob (1 .. 4);
         First : Spot := 4;
         Rest  : Natural := Value;
      begin
         if Value < 128 then
            return [1 => Ada.Streams.Stream_Element (Value)];
         end if;
         Wide (First) := Ada.Streams.Stream_Element (Rest mod 256);
         Rest := Rest / 256;
         while Rest > 0 loop
            First := First - 1;
            Wide (First) := Ada.Streams.Stream_Element (Rest mod 256);
            Rest := Rest / 256;
         end loop;
         return [1 => Ada.Streams.Stream_Element (16#80# + (5 - First))]
                & Wide (First .. 4);
      end Length_Octets;

      function Wrap (Tag : Ada.Streams.Stream_Element; Content : Blob)
        return Blob
      is ([1 => Tag] & Length_Octets (Natural (Content'Length)) & Content);

      CA_PEM, CA_Key : Unbounded_String;
      Outcome : CryptoLib.Certificates.Certificate_Status;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("serial-size-ca", CA_PEM, CA_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      declare
         Text   : constant String := To_String (CA_PEM);
         Buffer : Blob
           (1 .. Spot (CryptoLib.PEM.Maximum_Decoded_Length (Text)));
         Last   : Spot;
         From   : Positive := Text'First;
         P      : CryptoLib.PEM.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Text, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, P);

         declare
            Real : constant Blob := Buffer (Buffer'First .. Last);

            --  Both headers are 30 82 LL LL at this size. Asserted rather
            --  than assumed: a splice onto a shape that moved would quietly
            --  produce something else and test nothing.
            Header_Ok : constant Boolean :=
              Real'Length > 8
              and then Real (Real'First) = 16#30#
              and then Real (Real'First + 1) = 16#82#
              and then Real (Real'First + 4) = 16#30#
              and then Real (Real'First + 5) = 16#82#;

            TBS_Body : constant Blob :=
              Real (Real'First + 8
                    .. Real'First + 7
                       + Spot (Natural (Real (Real'First + 6)) * 256
                               + Natural (Real (Real'First + 7))));
            Trailer  : constant Blob :=
              Real (TBS_Body'Last + 1 .. Real'Last);

            Version_Length : constant Spot :=
              2 + Spot (Real (Real'First + 9));
            Before_Serial : constant Blob :=
              TBS_Body (TBS_Body'First
                        .. TBS_Body'First + Version_Length - 1);
            After_Serial  : constant Blob :=
              TBS_Body (TBS_Body'First + Version_Length + 2
                        + Spot (Real (Real'First + 8 + Version_Length + 1))
                        .. TBS_Body'Last);

            Roomy : constant CryptoLib.ASN1.Decode_Limits :=
              (Maximum_Input_Size     => 1024 * 1024,
               Maximum_Nesting_Depth  => 16,
               Maximum_Sequence_Items => 2048,
               Maximum_String_Length  => 1024 * 1024);
         begin
            Check (P = CryptoLib.PEM.Ok and then Header_Ok,
                   "fixture: the certificate has the shape this splices");

            for Size of Sizes loop
               declare
                  Big_Serial : constant Blob :=
                    Wrap (16#02#,
                          [1 => 16#01#]
                          & [1 .. Spot (Size) => 16#42#]);
                  Spliced : constant Blob :=
                    Wrap (16#30#,
                          Wrap (16#30#,
                                Before_Serial & Big_Serial & After_Serial)
                          & Trailer);
                  Status : CryptoLib.ASN1.Errors.Decode_Status;
                  Item   : constant X509C.Certificate :=
                    X509C.Decode_DER (Spliced, Roomy, Status);

                  Out_Buffer : Blob (1 .. 128 * 1024);
                  Stop  : Spot;
                  Built : CryptoLib.ASN1.Errors.Decode_Status;
               begin
                  --  If this stopped decoding, the builder would never be
                  --  reached and everything below would pass while testing
                  --  nothing.
                  Check (Status = CryptoLib.ASN1.Errors.Ok
                         and then X509C.Is_Present (Item),
                         "a certificate with a" & Natural'Image (Size)
                         & "-octet serial decodes, got "
                         & CryptoLib.ASN1.Errors.Status_Image (Status));

                  CO.Build_Request
                    (Item, Item, Out_Buffer, Stop, Built);
                  Check (Built = CryptoLib.ASN1.Errors.Ok,
                         "and a request is built for it, got "
                         & CryptoLib.ASN1.Errors.Status_Image (Built));

                  --  The length octets have to name the rest of the request
                  --  exactly. This is what each of the three encoder faults
                  --  got wrong, in three different ways, at three different
                  --  sizes.
                  declare
                     Header : Natural := 2;
                     Stated : Natural := 0;
                     Count  : Natural;
                  begin
                     if Natural (Out_Buffer (2)) < 128 then
                        Stated := Natural (Out_Buffer (2));
                     else
                        Count := Natural (Out_Buffer (2)) - 128;
                        Header := 2 + Count;
                        for I in 1 .. Count loop
                           Stated :=
                             Stated * 256
                             + Natural (Out_Buffer (Spot (2 + I)));
                        end loop;
                     end if;

                     Check (Header + Stated = Natural (Stop),
                            "and its outer length names the whole request:"
                            & Natural'Image (Header + Stated) & " vs"
                            & Spot'Image (Stop));
                  end;
               end;
            end loop;
         end;
      end;
   end Check_Oversized_Serial;

   --  A public point that is not on the curve.
   --
   --  Verification built the point from the coordinate bytes and never
   --  checked that they satisfy the curve equation. Where the key is
   --  vouched for by a CA that hardly matters, but it is not always: a
   --  self-signed certificate and a certificate request are both verified
   --  against a key their own sender chose, and for a request the signature
   --  is the only evidence the requester holds the private key at all.
   --  Arithmetic on a point off the curve happens in a group nobody chose,
   --  and "only the private key could have produced this" does not survive
   --  the move.
   procedure Check_Off_Curve_Key is
      Rng  : CryptoLib.Random.Random_Source;
      Seed : Ada.Streams.Stream_Element_Array (1 .. 48);
      Pub  : Ada.Streams.Stream_Element_Array (1 .. 97);
      Msg  : constant Ada.Streams.Stream_Element_Array (1 .. 6) :=
        [1, 2, 3, 4, 5, 6];
      R, S : Ada.Streams.Stream_Element_Array (1 .. 48);
      St   : CryptoLib.Errors.Status;
   begin
      CryptoLib.Random.Initialize_Production (Rng);
      St := CryptoLib.ECDSA.Generate_Nistp384_Keypair (Rng, Seed, Pub);
      Check (St = CryptoLib.Errors.Ok, "fixture: a P-384 key pair");

      St := CryptoLib.ECDSA.Sign_Nistp384_Raw (Seed, Msg, R, S);
      Check (St = CryptoLib.Errors.Ok, "fixture: it signs");

      --  The honest case, over many keys rather than one. A Montgomery
      --  result is not necessarily the least residue, so comparing the two
      --  sides of the curve equation without normalising them first rejects
      --  keys whose representation happens not to be reduced -- which is
      --  most of the time fine and occasionally not. One key would have
      --  passed that broken check about as often as not.
      declare
         Good : Natural := 0;
         Tries : constant := 40;
      begin
         for Attempt in 1 .. Tries loop
            declare
               Seed_N : Ada.Streams.Stream_Element_Array (1 .. 48);
               Pub_N  : Ada.Streams.Stream_Element_Array (1 .. 97);
               R_N, S_N : Ada.Streams.Stream_Element_Array (1 .. 48);
            begin
               exit when CryptoLib.ECDSA.Generate_Nistp384_Keypair
                           (Rng, Seed_N, Pub_N) /= CryptoLib.Errors.Ok;
               exit when CryptoLib.ECDSA.Sign_Nistp384_Raw
                           (Seed_N, Msg, R_N, S_N) /= CryptoLib.Errors.Ok;
               if CryptoLib.ECDSA.Verify_Nistp384_Raw
                    (Pub_N, Msg, R_N, S_N) = CryptoLib.Errors.Ok
               then
                  Good := Good + 1;
               end if;
            end;
         end loop;

         Check (Good = Tries,
                "every honest key verifies under itself:"
                & Natural'Image (Good) & " of" & Natural'Image (Tries));
      end;

      --  Move x by one. The chance that the result is still a point on the
      --  curve is about one in 2**191, so this is off it.
      declare
         Bent : Ada.Streams.Stream_Element_Array := Pub;
      begin
         Bent (Bent'First + 1) := Bent (Bent'First + 1) xor 1;
         Check (CryptoLib.ECDSA.Verify_Nistp384_Raw (Bent, Msg, R, S)
                /= CryptoLib.Errors.Ok,
                "a key off the curve is refused");
      end;

      --  A coordinate at or above the field prime is not a coordinate. All
      --  ones is comfortably above p for every curve here.
      declare
         Huge : Ada.Streams.Stream_Element_Array := Pub;
      begin
         Huge (Huge'First + 1 .. Huge'First + 48) := [others => 16#FF#];
         Check (CryptoLib.ECDSA.Verify_Nistp384_Raw (Huge, Msg, R, S)
                /= CryptoLib.Errors.Ok,
                "a coordinate outside the field is refused");
      end;

      --  x = y = 0 satisfies nothing: b is not zero on any of these curves.
      declare
         Zeroed : Ada.Streams.Stream_Element_Array := Pub;
      begin
         Zeroed (Zeroed'First + 1 .. Zeroed'Last) := [others => 0];
         Check (CryptoLib.ECDSA.Verify_Nistp384_Raw (Zeroed, Msg, R, S)
                /= CryptoLib.Errors.Ok,
                "the all-zero point is refused");
      end;
   end Check_Off_Curve_Key;

   --  One key, one encoding.
   --
   --  RFC 8032 5.1.3 fails decoding when x = 0 and the sign bit is set:
   --  zero has one square root, not two, so the negated form names the same
   --  point. Accepting both gives one public key two byte strings -- a
   --  difference that anything identifying a key by its bytes can see and
   --  that the arithmetic cannot.
   procedure Check_Ed25519_Encoding is
      Message : constant Ada.Streams.Stream_Element_Array (1 .. 3) :=
        [1, 2, 3];

      --  x = 0 happens only at y = 1 and y = -1, so this is the whole of the
      --  affected set. y = 1 is the identity, and for it the verification
      --  equation reduces to [S]B = R, which S = 0 and R = the identity
      --  satisfy for any message at all.
      Signature : Ada.Streams.Stream_Element_Array (1 .. 64) := [others => 0];
      Canonical : constant Ada.Streams.Stream_Element_Array (1 .. 32) :=
        [1 => 1, others => 0];
      Bent      : Ada.Streams.Stream_Element_Array (1 .. 32) :=
        [1 => 1, others => 0];
   begin
      Signature (1) := 1;
      Bent (32) := 16#80#;

      --  The premise: this signature really does verify under the canonical
      --  encoding. Without it the check below would pass on a signature that
      --  fails for its own reasons and prove nothing.
      Check (CryptoLib.Ed25519.Verify (Canonical, Signature, Message)
             = CryptoLib.Errors.Ok,
             "fixture: the signature verifies under the canonical encoding");

      Check (CryptoLib.Ed25519.Verify (Bent, Signature, Message)
             /= CryptoLib.Errors.Ok,
             "the same key with the sign bit set is refused");
   end Check_Ed25519_Encoding;

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

   --  RFC 5280 section 6.1 policy processing.
   --
   --  A policy identifier on its own asserts something and restricts nothing.
   --  What gives it teeth is policyConstraints, which can demand that every
   --  certificate below it name an acceptable policy; policyMappings, which
   --  lets one CA declare its policy equivalent to another's; and
   --  inhibitAnyPolicy, which withdraws the wildcard. This crate used to
   --  refuse any chain carrying the first or third of those, which was
   --  correct and useless.
   --
   --  Every verdict below was taken from OpenSSL first, with
   --  `openssl verify -policy_check -policy 1.3.6.1.4.1.99999.1`, and this
   --  agrees with it on all of them.
   procedure Check_Policy_Processing is
      package X509C renames CryptoLib.X509.Certificates;
      package XV renames CryptoLib.X509.Validation;
      use type XV.Validation_Failure;

      Pol_Root_DER : constant String :=
        "308201c63082014ba00302010202145727441835ad76033727ea6b84f515747f3320c2300a06082a8648ce3d04" &
        "030230163114301206035504030c0b706f6c6963792d726f6f74301e170d3236303732393033343234335a170d" &
        "3237303532353033343234335a30163114301206035504030c0b706f6c6963792d726f6f743076301006072a86" &
        "48ce3d020106052b8104002203620004fab57ef5a1788133397062176d5925a43cd8595df917f6743c6323355d" &
        "2658e3173fce28a87905f80b9ba83ee1aab697a7bb599368c751864a56fbaa711e5b2726530bc20c83714e3ce3" &
        "718536a74005d731b1489eb8e166434548c44d69b0cfa35a3058300f0603551d130101ff040530030101ff300e" &
        "0603551d0f0101ff04040302010630160603551d20040f300d300b06092b06010401868d1f01301d0603551d0e" &
        "04160414208a7da7f801c4b3c24c5dea13986578cbec0ed6300a06082a8648ce3d040302036900306602310093" &
        "4dbbfa5f698b9aaa2a6349fed0bae3572c3a3fcf09da057a05046c6724f4d40d3e1c36dccecaab036b60672925" &
        "bced023100d96d24eef7e88ed6c3c434743d79d0619f1b54a3bf01ef831d4bef08264efa2a9d989132170c7443" &
        "fcacbe2bb70aee19";

      Pol_Inter_Req_DER : constant String :=
        "308201e53082016ca003020102020111300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343234335a170d3237303532353033343234335a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b8104002203620004e15b58" &
        "46a5c5aa4118c74841b2a4d1cac4c19fcf8b7a326c793b925c6b3e812064cfc41d80da3fe58efa95f36268c9e4" &
        "92ce3f8cd6ad4c07c73320b34b892361a8182b17e63dbc1f53b9b51c559e6730b855011c68eeaa084cac7a4ed5" &
        "2fd898a3818d30818a300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301606" &
        "03551d20040f300d300b06092b06010401868d1f01300f0603551d240101ff04053003800100301d0603551d0e" &
        "041604144a97461dd73c54c4d02a3f0b416a6afc6d0f8e32301f0603551d23041830168014208a7da7f801c4b3" &
        "c24c5dea13986578cbec0ed6300a06082a8648ce3d040302036700306402300a2dfefe083b5e9d75967003b81a" &
        "ba7d546b7834cc7c300881cabe6fe8dec7fece25dcae0366c2f70b9222c290603f70023059ec3865ccd17af7a8" &
        "bc2af98ea4e35513ea24490494f49cc110096c3a8bee972151c7e4d17a7387329f33890c9c02eb";

      Pol_Inter_Plain_DER : constant String :=
        "308201d330820159a003020102020112300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343234335a170d3237303532353033343234335a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b8104002203620004e15b58" &
        "46a5c5aa4118c74841b2a4d1cac4c19fcf8b7a326c793b925c6b3e812064cfc41d80da3fe58efa95f36268c9e4" &
        "92ce3f8cd6ad4c07c73320b34b892361a8182b17e63dbc1f53b9b51c559e6730b855011c68eeaa084cac7a4ed5" &
        "2fd898a37b3079300f0603551d130101ff040530030101ff300e0603551d0f0101ff0404030201063016060355" &
        "1d20040f300d300b06092b06010401868d1f01301d0603551d0e041604144a97461dd73c54c4d02a3f0b416a6a" &
        "fc6d0f8e32301f0603551d23041830168014208a7da7f801c4b3c24c5dea13986578cbec0ed6300a06082a8648" &
        "ce3d040302036800306502307145f1818ae7ef3193b94efdd67dd25ed927f59caa1e8b35e903c94d57318782f6" &
        "89872eb16daba58026fb82533bca3d023100dd8dcffad0f4b8fee4cf608dc1329619253245e550556568450970" &
        "d2a72a37fb798b9b773a0346ede88c91839bc4e712";

      Pol_Inter_Inhibit_DER : constant String :=
        "308201f53082017ba003020102020113300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343432395a170d3237303532353033343432395a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b8104002203620004e15b58" &
        "46a5c5aa4118c74841b2a4d1cac4c19fcf8b7a326c793b925c6b3e812064cfc41d80da3fe58efa95f36268c9e4" &
        "92ce3f8cd6ad4c07c73320b34b892361a8182b17e63dbc1f53b9b51c559e6730b855011c68eeaa084cac7a4ed5" &
        "2fd898a3819c308199300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301606" &
        "03551d20040f300d300b06092b06010401868d1f01300f0603551d240101ff04053003800100300d0603551d36" &
        "0101ff0403020100301d0603551d0e041604144a97461dd73c54c4d02a3f0b416a6afc6d0f8e32301f0603551d" &
        "23041830168014208a7da7f801c4b3c24c5dea13986578cbec0ed6300a06082a8648ce3d040302036800306502" &
        "3100c3b2fb9c7bd0488f4356ba5761f3a79b98e533779f8c2014d0c62891393eda71ed5d84e3e7565bd889fb85" &
        "cfddfd320302307dc6d4f4d3254b9276b1a0459729f6bd6eb558083b79d0c9a8a9b71c56d794078ea20685dc68" &
        "fd87c10ed979f527a6e5";

      Pol_Inter_Map_DER : constant String :=
        "308202093082018fa003020102020114300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343432395a170d3237303532353033343432395a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b8104002203620004e15b58" &
        "46a5c5aa4118c74841b2a4d1cac4c19fcf8b7a326c793b925c6b3e812064cfc41d80da3fe58efa95f36268c9e4" &
        "92ce3f8cd6ad4c07c73320b34b892361a8182b17e63dbc1f53b9b51c559e6730b855011c68eeaa084cac7a4ed5" &
        "2fd898a381b03081ad300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301606" &
        "03551d20040f300d300b06092b06010401868d1f01300f0603551d240101ff0405300380010030210603551d21" &
        "041a3018301606092b06010401868d1f0106092b0601040185b63801301d0603551d0e041604144a97461dd73c" &
        "54c4d02a3f0b416a6afc6d0f8e32301f0603551d23041830168014208a7da7f801c4b3c24c5dea13986578cbec" &
        "0ed6300a06082a8648ce3d0403020368003065023100de613a955ab42e1fb759f2cd1aec7951a15bc5aa8a8744" &
        "3cee4921af808dbe73a7661d0a5f668e02f1ff650d68cc319d023071f25589438e722d60ebddc7d72430ebc2fe" &
        "aa6719b84bc9929fdeb215be9168a99e4421eab72e6dd4de561b20532856";

      Pol_Inter_Map_Crit_DER : constant String :=
        "3082020c30820192a003020102020116300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393037333131365a170d3237303532353037333131365a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b8104002203620004e15b58" &
        "46a5c5aa4118c74841b2a4d1cac4c19fcf8b7a326c793b925c6b3e812064cfc41d80da3fe58efa95f36268c9e4" &
        "92ce3f8cd6ad4c07c73320b34b892361a8182b17e63dbc1f53b9b51c559e6730b855011c68eeaa084cac7a4ed5" &
        "2fd898a381b33081b0300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301606" &
        "03551d20040f300d300b06092b06010401868d1f01300f0603551d240101ff0405300380010030240603551d21" &
        "0101ff041a3018301606092b06010401868d1f0106092b0601040185b63801301d0603551d0e041604144a9746" &
        "1dd73c54c4d02a3f0b416a6afc6d0f8e32301f0603551d23041830168014208a7da7f801c4b3c24c5dea139865" &
        "78cbec0ed6300a06082a8648ce3d0403020368003065023100a076113b47ae93935aa562ab406922d6abed781f" &
        "f0a9ae4c1e2f3d60b23918186f034cba5cbae52ef78df2ace923903b023072e20017edaaa6a03f68413faf7639" &
        "5e4feb6edd171fe0b30f75d112a2fbbd552cd293496d4cb53b5416643392c50c98";

      Pol_Leaf_Policy_DER : constant String :=
        "308201c130820146a003020102020121300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343234335a170d3237303532353033343234335a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b81040022036200043402ce" &
        "6ccea70ea36eb8521e2007faa5beb6e7c3806e6fa37fa5327cb5d3f557feca8c0d8d241091a0ea74e4c0732957" &
        "40bfbfc075897e4da948d1cc6c167840e84238120e8cb80affde05c989c869103e6b1baa065634d40307e610b8" &
        "593fe8a3683066300c0603551d130101ff0402300030160603551d20040f300d300b06092b06010401868d1f01" &
        "301d0603551d0e04160414384bc3b7f08c0a2ad3fc513ff2bec55b1ba8efb2301f0603551d230418301680144a" &
        "97461dd73c54c4d02a3f0b416a6afc6d0f8e32300a06082a8648ce3d04030203690030660231009cf61f07f09c" &
        "8bacb47ca0be767c341452c2032533a6b22b3efc9e002c7d2d11e85eff4d166d392b9f1b6d38db1b7f71023100" &
        "fc4f717bc35b622f8c94e6b6fcea42adf6867f73f35cc262ebe57ed5790e3f42d8daea529862214ec14392f312" &
        "e30b28";

      Pol_Leaf_Other_DER : constant String :=
        "308201c130820146a003020102020121300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343234335a170d3237303532353033343234335a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b81040022036200043402ce" &
        "6ccea70ea36eb8521e2007faa5beb6e7c3806e6fa37fa5327cb5d3f557feca8c0d8d241091a0ea74e4c0732957" &
        "40bfbfc075897e4da948d1cc6c167840e84238120e8cb80affde05c989c869103e6b1baa065634d40307e610b8" &
        "593fe8a3683066300c0603551d130101ff0402300030160603551d20040f300d300b06092b0601040184df5109" &
        "301d0603551d0e04160414384bc3b7f08c0a2ad3fc513ff2bec55b1ba8efb2301f0603551d230418301680144a" &
        "97461dd73c54c4d02a3f0b416a6afc6d0f8e32300a06082a8648ce3d04030203690030660231009968df9936d9" &
        "412143d1b60b2b6b971a6aafc2ae3beeb1065590e1a6b2a5052448ca815b7e798b4eb80f95cb0db95afa023100" &
        "93358650650df7b7736b87dee1ff633b891fba4cfd35193edec3b902299b1fe03eb6e3de21044c271ed4a66766" &
        "d78bac";

      Pol_Leaf_None_DER : constant String :=
        "308201a83082012ea003020102020121300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343234335a170d3237303532353033343234335a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b81040022036200043402ce" &
        "6ccea70ea36eb8521e2007faa5beb6e7c3806e6fa37fa5327cb5d3f557feca8c0d8d241091a0ea74e4c0732957" &
        "40bfbfc075897e4da948d1cc6c167840e84238120e8cb80affde05c989c869103e6b1baa065634d40307e610b8" &
        "593fe8a350304e300c0603551d130101ff04023000301d0603551d0e04160414384bc3b7f08c0a2ad3fc513ff2" &
        "bec55b1ba8efb2301f0603551d230418301680144a97461dd73c54c4d02a3f0b416a6afc6d0f8e32300a06082a" &
        "8648ce3d040302036800306502310086e66099b0cda06383ed72776cb553ec367361e5cc528ca35c7018aedad7" &
        "11f8ce39e5d4d6cf42b1d6f3ae94b327562e023068e4d658e2b643601e5682fad634ae5b82df926e3c7ed1f89e" &
        "c31f435721d06ac80296c50dc5c9b3135dd1863d35d48a";

      Pol_Leaf_Any_DER : constant String :=
        "308201bb30820141a003020102020141300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343432395a170d3237303532353033343432395a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b81040022036200043402ce" &
        "6ccea70ea36eb8521e2007faa5beb6e7c3806e6fa37fa5327cb5d3f557feca8c0d8d241091a0ea74e4c0732957" &
        "40bfbfc075897e4da948d1cc6c167840e84238120e8cb80affde05c989c869103e6b1baa065634d40307e610b8" &
        "593fe8a3633061300c0603551d130101ff0402300030110603551d20040a300830060604551d2000301d060355" &
        "1d0e04160414384bc3b7f08c0a2ad3fc513ff2bec55b1ba8efb2301f0603551d230418301680144a97461dd73c" &
        "54c4d02a3f0b416a6afc6d0f8e32300a06082a8648ce3d0403020368003065023100ce186b844eba08a3db51bc" &
        "0941f289c9dfa619b402d4bd67dfc3520a95c21da82d347292ebddb3c1a6b5e336aa5f3956023048372cefb703" &
        "f4314103946d7bf88e48a26a926adb447bee23e45c2ecb0af47fdae1467e3f0379160167a585854db4ba";

      Pol_Leaf_Mapped_DER : constant String :=
        "308201c130820146a003020102020141300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343432395a170d3237303532353033343432395a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b81040022036200043402ce" &
        "6ccea70ea36eb8521e2007faa5beb6e7c3806e6fa37fa5327cb5d3f557feca8c0d8d241091a0ea74e4c0732957" &
        "40bfbfc075897e4da948d1cc6c167840e84238120e8cb80affde05c989c869103e6b1baa065634d40307e610b8" &
        "593fe8a3683066300c0603551d130101ff0402300030160603551d20040f300d300b06092b0601040185b63801" &
        "301d0603551d0e04160414384bc3b7f08c0a2ad3fc513ff2bec55b1ba8efb2301f0603551d230418301680144a" &
        "97461dd73c54c4d02a3f0b416a6afc6d0f8e32300a06082a8648ce3d0403020369003066023100ee90c48ae9b6" &
        "5209c5242f56cd53e58e17e11ddefd40199f52ded1f32134f53b11ba13ca407435b5e520245043a5f931023100" &
        "cc68368691849c6e3e5dc53902fd817f79a2b95e2bf1546184f1c80b71b6b74fe800fcaecbb79a20f4cf22f6e8" &
        "e725b7";

      Pol_Leaf_None_Plain_DER : constant String :=
        "308201a83082012ea003020102020131300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343331325a170d3237303532353033343331325a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b81040022036200043402ce" &
        "6ccea70ea36eb8521e2007faa5beb6e7c3806e6fa37fa5327cb5d3f557feca8c0d8d241091a0ea74e4c0732957" &
        "40bfbfc075897e4da948d1cc6c167840e84238120e8cb80affde05c989c869103e6b1baa065634d40307e610b8" &
        "593fe8a350304e300c0603551d130101ff04023000301d0603551d0e04160414384bc3b7f08c0a2ad3fc513ff2" &
        "bec55b1ba8efb2301f0603551d230418301680144a97461dd73c54c4d02a3f0b416a6afc6d0f8e32300a06082a" &
        "8648ce3d04030203680030650230036d5757d235d4fe32e612750bbeb248c84f198aa1cba7b6356ab90f967813" &
        "f34484c5623e35449db518c535d2ba387f02310082d568ddeb7909e66d44ff7f1f000079835b0cb96226ecd19b" &
        "fef5c1977bf5ffb01f82ab7ef3b5a9149431a0d21f1b4b";

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

      function Decoded (Hex : String) return X509C.Certificate
      is (X509C.Decode_DER
            (From_Hex (Hex), CryptoLib.ASN1.Default_Limits, Status));

      type Which_Inter is (Req, Plain, Inhibit, Map, Map_Critical);
      type Which_Leaf is (With_Policy, Other_Policy, No_Policy, Any, Mapped,
                          None_Plain);

      type Chain (Inter : Which_Inter; Leaf : Which_Leaf) is
        limited new XV.Path_Source with null record;

      overriding function Length (Source : Chain) return Positive is (3);

      overriding function Certificate_At
        (Source : Chain; Index : Positive) return X509C.Certificate
      is (case Index is
             when 1 =>
               (case Source.Leaf is
                   when With_Policy  => Decoded (Pol_Leaf_Policy_DER),
                   when Other_Policy => Decoded (Pol_Leaf_Other_DER),
                   when No_Policy    => Decoded (Pol_Leaf_None_DER),
                   when Any          => Decoded (Pol_Leaf_Any_DER),
                   when Mapped       => Decoded (Pol_Leaf_Mapped_DER),
                   when None_Plain   => Decoded (Pol_Leaf_None_Plain_DER)),
             when 2 =>
               (case Source.Inter is
                   when Req     => Decoded (Pol_Inter_Req_DER),
                   when Plain   => Decoded (Pol_Inter_Plain_DER),
                   when Inhibit => Decoded (Pol_Inter_Inhibit_DER),
                   when Map     => Decoded (Pol_Inter_Map_DER),
                   when Map_Critical =>
                     Decoded (Pol_Inter_Map_Crit_DER)),
             when others => Decoded (Pol_Root_DER));

      overriding function Is_Trust_Anchor
        (Source : Chain; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Bytes (Item)
          = X509C.Subject_Bytes (Decoded (Pol_Root_DER)));

      At_Time : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 9, Day => 1,
         Hour => 12, Minute => 0, Second => 0);

      function Verdict (Inter : Which_Inter; Leaf : Which_Leaf)
        return XV.Validation_Result
      is (XV.Validate_Path (Chain'(Inter => Inter, Leaf => Leaf), At_Time));
   begin
      --  The control: a chain whose intermediate demands nothing, and a leaf
      --  that names no policy. Without it the refusals below would be
      --  consistent with the chain being broken for some other reason.
      Check (Verdict (Plain, None_Plain).Valid,
             "a chain that demands no policy validates: "
             & XV.Failure_Image (Verdict (Plain, None_Plain).Failure));

      --  requireExplicitPolicy on the intermediate: from here down, every
      --  certificate must name a policy that survives to the leaf.
      Check (Verdict (Req, With_Policy).Valid,
             "a leaf naming the policy its issuer granted validates: "
             & XV.Failure_Image (Verdict (Req, With_Policy).Failure));
      Check (Verdict (Req, With_Policy).Policies.Count = 1,
             "and the policy it establishes is reported, got"
             & Natural'Image (Verdict (Req, With_Policy).Policies.Count));

      --  A policy nobody above it granted is not a policy. This is the
      --  check: the leaf asserts something, and the assertion is worth
      --  nothing because no issuer in the path allowed it.
      Check (not Verdict (Req, Other_Policy).Valid
             and then Verdict (Req, Other_Policy).Failure
                      = XV.Policy_Not_Established,
             "a leaf naming a policy its issuers never granted is refused, "
             & "got " & XV.Failure_Image (Verdict (Req, Other_Policy).Failure));
      Check (not Verdict (Req, No_Policy).Valid,
             "and so is one naming none at all");

      --  anyPolicy satisfies the demand, until a certificate withdraws it.
      Check (Verdict (Req, Any).Valid,
             "anyPolicy satisfies an explicit-policy requirement: "
             & XV.Failure_Image (Verdict (Req, Any).Failure));
      Check (not Verdict (Inhibit, Any).Valid
             and then Verdict (Inhibit, Any).Failure
                      = XV.Policy_Not_Established,
             "unless inhibitAnyPolicy withdrew it, got "
             & XV.Failure_Image (Verdict (Inhibit, Any).Failure));

      --  policyMappings: the intermediate declares its issuer's policy
      --  equivalent to one of its own, and a leaf naming the mapped policy
      --  is then reachable from the root's.
      Check (Verdict (Map, Mapped).Valid,
             "a mapped policy carries through: "
             & XV.Failure_Image (Verdict (Map, Mapped).Failure));
      Check (not Verdict (Map, With_Policy).Valid,
             "and the unmapped one no longer does, because mapping replaced "
             & "what the issuer expects rather than adding to it");

      --  RFC 5280 4.2.1.5 says a conforming CA SHOULD mark policyMappings
      --  critical, so refusing a certificate that does is refusing what the
      --  specification asks for. This crate processes the extension, which
      --  is what entitles it to recognise it: the rule is that an extension
      --  is honoured or the certificate is refused, and honouring it while
      --  leaving it off the recognised list fails certificates for carrying
      --  something that was acted on anyway.
      Check (Verdict (Map_Critical, Mapped).Valid,
             "a critical policyMappings is honoured rather than refused: "
             & XV.Failure_Image (Verdict (Map_Critical, Mapped).Failure));
      Check (not Verdict (Map_Critical, With_Policy).Valid,
             "and it maps, so the unmapped policy no longer reaches the leaf");

      --  The caller's own policy set: RFC 5280's user-initial-policy-set.
      declare
         package PP renames CryptoLib.X509.Policies;

         function Only (Encoded : String) return PP.Accepted_Policies is
            Result : PP.Accepted_Policies := PP.Accept_Any;
         begin
            Result.Count := 1;
            Result.Values (1) := PP.To_Policy (From_Hex (Encoded));
            return Result;
         end Only;

         function Asking (Encoded : String; Leaf : Which_Leaf)
           return XV.Validation_Result
         is (XV.Validate_Path
               (Chain'(Inter => Req, Leaf => Leaf), At_Time,
                (XV.Default_Policy with delta
                   Accepted_Policies => Only (Encoded))));

         Wanted : constant String := "2b06010401868d1f01";
         Other  : constant String := "2b0601040184df5109";
      begin
         Check (Asking (Wanted, With_Policy).Valid,
                "a caller asking for the policy the chain establishes is "
                & "satisfied: "
                & XV.Failure_Image (Asking (Wanted, With_Policy).Failure));

         --  The chain is exactly as valid as before; what changed is what
         --  the caller will accept from it.
         Check (not Asking (Other, With_Policy).Valid
                and then Asking (Other, With_Policy).Failure
                         = XV.Policy_Not_Established,
                "and one asking for a policy it does not is refused, got "
                & XV.Failure_Image (Asking (Other, With_Policy).Failure));

         --  The caller's set is read in the trust anchor's policy domain,
         --  not the leaf's, and a mapping is what connects the two. Asking
         --  for the policy the anchor granted must therefore be satisfied by
         --  a leaf asserting what that policy was mapped to.
         --
         --  Filtering every node against the caller's set breaks exactly
         --  this: the leaf's node names the subject-domain policy, which is
         --  not what was asked for, and deleting it rejects the chain that
         --  policy mapping exists to allow. Section 6.1.5 (g)(iii) matches
         --  only nodes whose parent is anyPolicy for that reason.
         declare
            function Through_Map (Encoded : String)
              return XV.Validation_Result
            is (XV.Validate_Path
                  (Chain'(Inter => Map, Leaf => Mapped), At_Time,
                   (XV.Default_Policy with delta
                      Accepted_Policies => Only (Encoded))));

            Anchor_Policy  : constant String := "2b06010401868d1f01";
            Subject_Policy : constant String := "2b0601040185b63801";
         begin
            Check (Through_Map (Anchor_Policy).Valid,
                   "a mapped chain satisfies a caller asking for the policy "
                   & "the anchor granted, got "
                   & XV.Failure_Image (Through_Map (Anchor_Policy).Failure));

            --  And not the other way round: what the leaf asserts is in the
            --  subject's domain, which is not the domain the caller spoke in.
            Check (not Through_Map (Subject_Policy).Valid,
                   "and not one asking for the policy it was mapped to");
         end;
      end;
   end Check_Policy_Processing;

   --  What happens when there is no randomness.
   --
   --  The RNG is documented to fail closed: no OS source means
   --  Internal_Error and a zeroed buffer, never weak bytes. Nothing tested
   --  that, and the regression it invites is quiet -- somebody making a
   --  failing source "work" by falling back to something deterministic
   --  leaves no trace, and every key generated afterwards is predictable
   --  while every status still reads Ok.
   --
   --  So this checks the failure at the source and then that it propagates:
   --  a key generator handed a source that cannot deliver must refuse rather
   --  than build a key out of whatever the buffer happened to hold.
   procedure Check_Random_Fails_Closed is
      Rng    : CryptoLib.Random.Random_Source;
      Buffer : Ada.Streams.Stream_Element_Array (1 .. 32) := [others => 16#AA#];
   begin
      CryptoLib.Random.Initialize_Failing (Rng);

      Check (CryptoLib.Random.Fill (Rng, Buffer) /= CryptoLib.Errors.Ok,
             "a source that cannot deliver says so");

      --  Zeroed, not left as it was: a caller that ignores the status must
      --  not find the bytes it supplied looking like fresh randomness.
      declare
         Untouched : Boolean := False;
      begin
         for B of Buffer loop
            if B /= 0 then
               Untouched := True;
            end if;
         end loop;
         Check (not Untouched,
                "and leaves nothing behind that could pass for randomness");
      end;

      --  The failure has to reach the caller of a key generator, not be
      --  swallowed into a key made of zeros.
      declare
         Seed   : Ada.Streams.Stream_Element_Array (1 .. 48) :=
           [others => 16#BB#];
         Public : Ada.Streams.Stream_Element_Array (1 .. 97) :=
           [others => 16#CC#];
      begin
         Check (CryptoLib.ECDSA.Generate_Nistp384_Keypair (Rng, Seed, Public)
                /= CryptoLib.Errors.Ok,
                "a P-384 key pair is not generated without randomness");
      end;

      declare
         Seed_25519   : Ada.Streams.Stream_Element_Array (1 .. 32) :=
           [others => 16#BB#];
         Public_25519 : Ada.Streams.Stream_Element_Array (1 .. 32) :=
           [others => 16#CC#];
      begin
         Check (CryptoLib.Ed25519.Generate_Keypair
                  (Rng, Seed_25519, Public_25519)
                /= CryptoLib.Errors.Ok,
                "nor an Ed25519 one");
      end;

      --  And the production source still works, so the checks above are
      --  about the failing mode rather than about these calls always failing.
      declare
         Live   : CryptoLib.Random.Random_Source;
         Sample : Ada.Streams.Stream_Element_Array (1 .. 32) := [others => 0];
         Any    : Boolean := False;
      begin
         CryptoLib.Random.Initialize_Production (Live);
         Check (CryptoLib.Random.Fill (Live, Sample) = CryptoLib.Errors.Ok,
                "the production source delivers");
         for B of Sample loop
            if B /= 0 then
               Any := True;
            end if;
         end loop;
         Check (Any, "and delivers something other than zeros");
      end;
   end Check_Random_Fails_Closed;

   --  What a policy says to a person reading it.
   --
   --  RFC 5280 4.2.1.4 defines two qualifiers: a pointer to the issuer's
   --  certification practice statement, and a notice meant to be displayed.
   --  Neither changes whether a policy applies -- section 6.1 never consults
   --  them -- so they are read for a caller that wants to show why a
   --  certificate claims what it claims. They were parsed past and dropped.
   procedure Check_Policy_Qualifiers is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.X509.Policies.Qualifier_Kind;

      package X509C renames CryptoLib.X509.Certificates;
      package PP renames CryptoLib.X509.Policies;

      Long_Qualifier_DER : constant String :=
        "308203083082028fa00302010202147772a1c377955a4de366da5b5b9c5d8ecc91244a300a06082a8648ce3d04" &
        "030230163114301206035504030c0b706f6c6963792d726f6f74301e170d3236303732393038303635335a170d" &
        "3237303532353038303635335a30163114301206035504030c0b706f6c6963792d726f6f743076301006072a86" &
        "48ce3d020106052b8104002203620004fab57ef5a1788133397062176d5925a43cd8595df917f6743c6323355d" &
        "2658e3173fce28a87905f80b9ba83ee1aab697a7bb599368c751864a56fbaa711e5b2726530bc20c83714e3ce3" &
        "718536a74005d731b1489eb8e166434548c44d69b0cfa382019c30820198300f0603551d130101ff0405300301" &
        "01ff300e0603551d0f0101ff040403020106308201540603551d200482014b308201473082014306092b060104" &
        "01868d1f01308201343082013006082b060105050702011682012268747470733a2f2f6578616d706c652e7465" &
        "73742f6370732f6161616161616161616161616161616161616161616161616161616161616161616161616161" &
        "616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" &
        "616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" &
        "616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" &
        "616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" &
        "6161616161616161616161616161616161616161616161616161616161616161616161616161616161612e6874" &
        "6d6c301d0603551d0e04160414208a7da7f801c4b3c24c5dea13986578cbec0ed6300a06082a8648ce3d040302" &
        "0367003064023060ce4e4b4f493390e21e8e77d05a9860bd3ffd028886b585b10c6b39ddced4e8f20d3d19b9fe" &
        "d21c19c041fe9f3bcda202307bccdcf85917ebc87ebdbcbfa60266b0604aa61ea0bbd8af9035b72e6d3e1b9996" &
        "2e1a61953c62a96fdbd0d07dbaf9f2";

      Qualified_DER : constant String :=
        "30820249308201cea003020102021457dc68c06a8727f75fca6853854da359d207b6fc300a06082a8648ce3d04" &
        "030230163114301206035504030c0b706f6c6963792d726f6f74301e170d3236303732393037343631385a170d" &
        "3237303532353037343631385a30163114301206035504030c0b706f6c6963792d726f6f743076301006072a86" &
        "48ce3d020106052b8104002203620004fab57ef5a1788133397062176d5925a43cd8595df917f6743c6323355d" &
        "2658e3173fce28a87905f80b9ba83ee1aab697a7bb599368c751864a56fbaa711e5b2726530bc20c83714e3ce3" &
        "718536a74005d731b1489eb8e166434548c44d69b0cfa381dc3081d9300f0603551d130101ff040530030101ff" &
        "300e0603551d0f0101ff0404030201063081960603551d2004818e30818b30818806092b06010401868d1f0130" &
        "7b302906082b06010505070201161d68747470733a2f2f6578616d706c652e746573742f6370732e68746d6c30" &
        "4e06082b060105050702023042301a1a104578616d706c652054657374204f726730060201010201021a244973" &
        "7375656420756e64657220746865206578616d706c65207465737420706f6c696379301d0603551d0e04160414" &
        "208a7da7f801c4b3c24c5dea13986578cbec0ed6300a06082a8648ce3d0403020369003066023100d3a5eb9ed0" &
        "6bc532ebf2da5d489183d0d4f082690d1e888f8ea954e0594b77d2a9d2494c620bc7665fec33b9f48809510231" &
        "00e86ff2b3713b9ba9a632c6a0fa424829c0548fee20becea5932b0f3e759885375e1feb99b0a882cd62789cfe" &
        "ea02f666";

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
      Item   : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (Qualified_DER), CryptoLib.ASN1.Default_Limits, Status);
      Named  : constant PP.Policy_Set := PP.Policies_Of (Item);
   begin
      Check (Status = CryptoLib.ASN1.Errors.Ok
             and then Named.Well_Formed
             and then Named.Count = 1,
             "a certificate with a qualified policy decodes");

      --  Both kinds, in the order the certificate carries them.
      Check (Named.Entries (1).Qualifier_Count = 2,
             "both qualifiers are read, got"
             & Natural'Image (Named.Entries (1).Qualifier_Count));

      Check (Named.Entries (1).Qualifiers (1).Kind = PP.CPS_Uri,
             "the first is a practice-statement pointer");
      Check (Named.Entries (1).Qualifiers (1).Text
               (1 .. Named.Entries (1).Qualifiers (1).Length)
             = "https://example.test/cps.html",
             "and it is the URI the certificate carries, got ["
             & Named.Entries (1).Qualifiers (1).Text
                 (1 .. Named.Entries (1).Qualifiers (1).Length) & "]");

      --  A user notice holds an organisation and a list of numbers as well
      --  as the text. The numbers mean something only to whoever published
      --  them; the explicit text is the part written to be read, and it is
      --  the part taken.
      Check (Named.Entries (1).Qualifiers (2).Kind = PP.User_Notice,
             "the second is a notice");
      Check (Named.Entries (1).Qualifiers (2).Text
               (1 .. Named.Entries (1).Qualifiers (2).Length)
             = "Issued under the example test policy",
             "and its explicit text is taken rather than its notice "
             & "reference, got ["
             & Named.Entries (1).Qualifiers (2).Text
                 (1 .. Named.Entries (1).Qualifiers (2).Length) & "]");

      Check (not Named.Entries (1).Qualifiers (1).Truncated
             and then not Named.Entries (1).Qualifiers (2).Truncated,
             "neither was truncated");

      --  A qualifier longer than this can hold. RFC 5280 bounds DisplayText
      --  at 200 characters and says nothing about the length of a CPS URI,
      --  so a certificate carrying a long one is not malformed and must not
      --  be read as though the bound were a promise about the input.
      declare
         Long_Item : constant X509C.Certificate :=
           X509C.Decode_DER
             (From_Hex (Long_Qualifier_DER), CryptoLib.ASN1.Default_Limits,
              Status);
         Long_Set  : constant PP.Policy_Set := PP.Policies_Of (Long_Item);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok
                and then Long_Set.Well_Formed
                and then Long_Set.Entries (1).Qualifier_Count = 1,
                "a certificate with an over-long qualifier still decodes");
         Check (Long_Set.Entries (1).Qualifiers (1).Truncated,
                "and says the text was cut rather than pretending it fit");
         Check (Long_Set.Entries (1).Qualifiers (1).Length
                = PP.Maximum_Qualifier_Text,
                "keeping what it can, got"
                & Natural'Image (Long_Set.Entries (1).Qualifiers (1).Length));
      end;
   end Check_Policy_Qualifiers;

   --  The search skips a path that cannot carry the policies.
   --
   --  Path building already verifies signatures as it goes rather than
   --  trusting a name match, because two certificates can share a subject
   --  name and not a key. Policies are the same shape of problem one level
   --  up: two certificates can share a subject name AND a key, and grant
   --  different policies, which is what cross-signing produces. Taking the
   --  first anchor reached proposes a path the validator then refuses, while
   --  a path that works sits unexamined in the pool.
   --
   --  Both intermediates here have the same subject and the same key, so
   --  both verify the leaf and neither can be told from the other by
   --  signature. They differ only in the policy they grant.
   procedure Check_Policy_Aware_Path_Building is
      package X509C renames CryptoLib.X509.Certificates;
      package PB renames CryptoLib.X509.Path_Building;
      package XV renames CryptoLib.X509.Validation;

      PB_Leaf_DER : constant String :=
        "308201c93082014fa003020102020161300a06082a8648ce3d040302301e311c301a06035504030c1373686172" &
        "65642d696e7465726d656469617465301e170d3236303732393037353430385a170d3237303532353037353430" &
        "385a30173115301306035504030c0c686f73742e6578616d706c653076301006072a8648ce3d020106052b8104" &
        "002203620004f87d3963719d77f4c81524657c92199180906b54fc56ff2c848be3b67a0481de7db8684546488b" &
        "03763c375c507a6cfa64daa5f9f515b82bc6547f955e03f5956d009ea28554beb05e2f85417f91b96fd1b7566f" &
        "8f92c02e82ac82f0e20a64c0a3683066300c0603551d130101ff0402300030160603551d20040f300d300b0609" &
        "2b06010401868d1f01301d0603551d0e041604143e80a30384dc81214a81498674ba57783db8ef85301f060355" &
        "1d2304183016801467499f0fa03b44804b13d5a5c720a449cb6491b4300a06082a8648ce3d0403020368003065" &
        "0230509701daa9f5a45e57494fdecd832333b175af38018267496392437ef78c0f31f8c43a76ab243e0fb3de3b" &
        "bd370e61d5023100f07cb804905a423b25c50694034ff8a84f5d750b29c1b9fcbae179ca179c4ed293563050e2" &
        "bf54d6205769ffcae0e852";

      PB_Inter_Bad_DER : constant String :=
        "308201e93082016fa003020102020152300a06082a8648ce3d0403023011310f300d06035504030c06726f6f74" &
        "2d62301e170d3236303732393037353430385a170d3237303532353037353430385a301e311c301a0603550403" &
        "0c137368617265642d696e7465726d6564696174653076301006072a8648ce3d020106052b8104002203620004" &
        "56750ad1e24e2bbfd349d09ec008ec4506edadee48ed1af3575025622d583de813ad1ef329f4a374f7a1a8c4ac" &
        "ac11604e414a6f51da9fb7ecf34adc160806ca4e6670b08309a3e5d08eebd2256d4a3afe7cfbb818b315a0b0ef" &
        "f0afe4dcd8a7a3818d30818a300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106" &
        "30160603551d20040f300d300b06092b0601040184df5109300f0603551d240101ff04053003800100301d0603" &
        "551d0e0416041467499f0fa03b44804b13d5a5c720a449cb6491b4301f0603551d230418301680145aeb3a2a00" &
        "26debc836959f1a6b2fa00df56e19c300a06082a8648ce3d040302036800306502306714225aba6cdff783b990" &
        "e8c6369c2d7ca531628b2ff65e8ce1246a3379c2aedc6df3fc086038802c67317edd0b28c8023100df0758270b" &
        "6b633c5e27c27acd6bf5e0ee4a5245ddcb9e609e5011a7a9a1836cf2744b8404f5b48b9dd0140470d48243";

      PB_Inter_Good_DER : constant String :=
        "308201e83082016fa003020102020151300a06082a8648ce3d0403023011310f300d06035504030c06726f6f74" &
        "2d61301e170d3236303732393037353430385a170d3237303532353037353430385a301e311c301a0603550403" &
        "0c137368617265642d696e7465726d6564696174653076301006072a8648ce3d020106052b8104002203620004" &
        "56750ad1e24e2bbfd349d09ec008ec4506edadee48ed1af3575025622d583de813ad1ef329f4a374f7a1a8c4ac" &
        "ac11604e414a6f51da9fb7ecf34adc160806ca4e6670b08309a3e5d08eebd2256d4a3afe7cfbb818b315a0b0ef" &
        "f0afe4dcd8a7a3818d30818a300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106" &
        "30160603551d20040f300d300b06092b06010401868d1f01300f0603551d240101ff04053003800100301d0603" &
        "551d0e0416041467499f0fa03b44804b13d5a5c720a449cb6491b4301f0603551d2304183016801473a50636f7" &
        "dc3b6b3e4c411184e7b5a13b9c100d300a06082a8648ce3d0403020367003064023030b37a1d2b20a9e38507cd" &
        "9217deb780c5a192de41b193b1ea4a798da13329226cc396a2908b85aaddf8cb728c1eaae00230525c5b69e632" &
        "1645a8b37d0e348bad381c8d3671975067958d5bf935347aca5bb8633e16ae4d607eb4934a15d0158514";

      PB_Root_A_DER : constant String :=
        "308201bc30820141a003020102021421ea63a70614babf12043ff3fd4bdc41048c4cc1300a06082a8648ce3d04" &
        "03023011310f300d06035504030c06726f6f742d61301e170d3236303732393037353430385a170d3237303532" &
        "353037353430385a3011310f300d06035504030c06726f6f742d613076301006072a8648ce3d020106052b8104" &
        "0022036200045876f37066dba6cc53105ef20479a3c2d895a138f4f807f817e20a836058af4243a7dd42d6898b" &
        "a8753fce34d928f1c6b782c3af94f16020564ada84880c31087f34d527242c8bba1c2342666e6a95fc9ffb610c" &
        "b660ecf8438057489fd7e50fa35a3058300f0603551d130101ff040530030101ff300e0603551d0f0101ff0404" &
        "0302010630160603551d20040f300d300b06092b06010401868d1f01301d0603551d0e0416041473a50636f7dc" &
        "3b6b3e4c411184e7b5a13b9c100d300a06082a8648ce3d0403020369003066023100a4f9d741fe62998fa48577" &
        "2c25d75d47c81781fce06439937676dcef371917871aa705f6d74d20ac782f1f1211e9444a023100c7c4830f99" &
        "df1d17e663ac7c62b7f5c145d5f1e5320dfe54161bd6b5b453efbbaa3201025c068621045d37f35486a94d";

      PB_Root_B_DER : constant String :=
        "308201bc30820141a0030201020214528b48a4bc34c3d22e407d9102994b89fe991205300a06082a8648ce3d04" &
        "03023011310f300d06035504030c06726f6f742d62301e170d3236303732393037353430385a170d3237303532" &
        "353037353430385a3011310f300d06035504030c06726f6f742d623076301006072a8648ce3d020106052b8104" &
        "002203620004aba3973bbdd01cf0db3f15e268007c7793948acf49742f641407bd1fe91e4bb7fc0cd00d7504fd" &
        "767169e6484f549e1cb05d61bbbe1652211f04732e488e1c74f82c25593a9fb2eb341c5c2b04e020d64178179b" &
        "173900ce76fe679e946247d4a35a3058300f0603551d130101ff040530030101ff300e0603551d0f0101ff0404" &
        "0302010630160603551d20040f300d300b06092b06010401868d1f01301d0603551d0e041604145aeb3a2a0026" &
        "debc836959f1a6b2fa00df56e19c300a06082a8648ce3d0403020369003066023100b525ff73e032612f337e21" &
        "ccb7a41434d7705f4f427ce849aaf177d5eb36d0cc5eb2a51b0ced490256eb3d7799807a4802310089ad6f07e8" &
        "1ac21b9bd7ca6e4368609b7cc42bcc1e81092fb67f90603386bfee276e0c30851485358de5c76575e0d6f2";

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

      function Decoded (Hex : String) return X509C.Certificate
      is (X509C.Decode_DER
            (From_Hex (Hex), CryptoLib.ASN1.Default_Limits, Status));

      --  The one that cannot carry the policy comes first, so taking the
      --  first path found is the wrong answer.
      type Pool is limited new PB.Candidate_Source with null record;

      overriding function Count (Source : Pool) return Natural is (4);

      overriding function Candidate
        (Source : Pool; Index : Positive) return X509C.Certificate
      is (case Index is
             when 1      => Decoded (PB_Inter_Bad_DER),
             when 2      => Decoded (PB_Inter_Good_DER),
             when 3      => Decoded (PB_Root_A_DER),
             when others => Decoded (PB_Root_B_DER));

      overriding function Is_Trust_Anchor
        (Source : Pool; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Bytes (Item)
          = X509C.Subject_Bytes (Decoded (PB_Root_A_DER))
          or else X509C.Subject_Bytes (Item)
                  = X509C.Subject_Bytes (Decoded (PB_Root_B_DER)));

      Search : constant PB.Build_Result :=
        PB.Build_Path (Decoded (PB_Leaf_DER), Pool'(null record));
   begin
      --  The premise: both intermediates really are indistinguishable by
      --  key, so the search cannot be picking between them on signatures.
      Check (X509C.Public_Key (Decoded (PB_Inter_Bad_DER))
             = X509C.Public_Key (Decoded (PB_Inter_Good_DER)),
             "fixture: the two intermediates share a key");
      Check (X509C.Subject_Bytes (Decoded (PB_Inter_Bad_DER))
             = X509C.Subject_Bytes (Decoded (PB_Inter_Good_DER)),
             "fixture: and a subject name");

      Check (Search.Found, "a path is found");
      Check (Search.Length = 2,
             "of the leaf, an intermediate and an anchor, got"
             & Natural'Image (Search.Length));

      --  The point: not the first one reached.
      Check (Search.Indices (1) = 2,
             "and it goes through the intermediate that grants the policy "
             & "the leaf asserts, not the one listed first, got"
             & Natural'Image (Search.Indices (1)));

      --  What it proposed has to survive the validator, which is the only
      --  thing entitled to conclude anything.
      declare
         type Found_Path is limited new XV.Path_Source with null record;

         overriding function Length (Source : Found_Path) return Positive
         is (3);

         overriding function Certificate_At
           (Source : Found_Path; Index : Positive) return X509C.Certificate
         is (case Index is
                when 1      => Decoded (PB_Leaf_DER),
                when 2      => Decoded (PB_Inter_Good_DER),
                when others => Decoded (PB_Root_A_DER));

         overriding function Is_Trust_Anchor
           (Source : Found_Path; Item : X509C.Certificate) return Boolean
         is (X509C.Subject_Bytes (Item)
             = X509C.Subject_Bytes (Decoded (PB_Root_A_DER)));

         At_Time : constant CryptoLib.X509.Certificate_Time :=
           (Year => 2026, Month => 9, Day => 1,
            Hour => 12, Minute => 0, Second => 0);

         Verdict : constant XV.Validation_Result :=
           XV.Validate_Path (Found_Path'(null record), At_Time);
      begin
         Check (Verdict.Valid,
                "and the path it proposes validates: "
                & XV.Failure_Image (Verdict.Failure));
      end;
   end Check_Policy_Aware_Path_Building;

   --  A self-issued certificate does not spend the policy allowances.
   --
   --  RFC 5280 6.1.4 (h) decrements explicit_policy, policy_mapping and
   --  inhibit_anyPolicy once per certificate -- unless that certificate is
   --  self-issued, because one a CA wrote for itself does not lengthen the
   --  path. It is the rule that lets a CA change keys without spending the
   --  budget its own policyConstraints handed out.
   --
   --  Constructing a chain whose verdict turns on it takes some care, since
   --  6.1.4 applies the constraint after the decrement and the constraint
   --  value overrides the count. With the tree empty, success needs
   --  explicit_policy to still be at least two entering the wrap-up, which
   --  decrements once more. So: a constraint of two, then one middle
   --  certificate, then a leaf naming no policy. If the middle one is
   --  self-issued the allowance survives; if it is not, it does not.
   --
   --  The two middle certificates differ in nothing but their subject name.
   --  Same key, same extensions, same issuer.
   procedure Check_Self_Issued_Policy_Allowance is
      package X509C renames CryptoLib.X509.Certificates;
      package XV renames CryptoLib.X509.Validation;
      use type XV.Validation_Failure;

      SI_Root_DER : constant String :=
        "308201be30820143a00302010202145472b1d2cdae935174a69f43b7d24d7a0cded637300a06082a8648ce3d04" &
        "030230123110300e06035504030c0773692d726f6f74301e170d3236303732393038313030365a170d32373035" &
        "32353038313030365a30123110300e06035504030c0773692d726f6f743076301006072a8648ce3d020106052b" &
        "8104002203620004c5f1b14fee380c1fa7f26dcf7c1a7445f56686fc578b775dcbb4a86c9e09388931022a69b8" &
        "9019636fd90851eed38b0209e46379f93d7a694b3b1900b11c619f7ee6d0a8726733ab50dd0f5cff7d0644a1ab" &
        "810b543bf6d08838d61b9f010c8fa35a3058300f0603551d130101ff040530030101ff300e0603551d0f0101ff" &
        "04040302010630160603551d20040f300d300b06092b06010401868d1f01301d0603551d0e04160414e4adfd6a" &
        "929eec316667b49362ab4b7cd848021c300a06082a8648ce3d0403020369003066023100f5bd22151a750f679c" &
        "8bccfac5ac798d1871320e49942eafcac76c91da7cd74fd00c20cbe590c5f87be52d800e501cf1023100d10c3c" &
        "0939f57755b78eeb115a51f5e01382c3bf480e0f51da0e2f7bfd3373abbd11fb132ba6f222fb0068545949078b";

      SI_Inter_DER : constant String :=
        "308201df30820165a003020102020171300a06082a8648ce3d04030230123110300e06035504030c0773692d72" &
        "6f6f74301e170d3236303732393038313030365a170d3237303532353038313030365a30133111300f06035504" &
        "030c0873692d696e7465723076301006072a8648ce3d020106052b81040022036200048d820adcf2775e7065ad" &
        "d15b168345189fdddbade134616d11a9b2ff4031a2a9f4fd86a18dca3dca4993318671747d837f912c3df48120" &
        "77448ace4e8bf46d55d97adb98bdb02f6f66740c016037d02497b759e06cf52e6c863041a007007351a3818d30" &
        "818a300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630160603551d20040f30" &
        "0d300b06092b06010401868d1f01300f0603551d240101ff04053003800102301d0603551d0e041604147a0638" &
        "a9b61e586eacf75a52776968f6f801c493301f0603551d23041830168014e4adfd6a929eec316667b49362ab4b" &
        "7cd848021c300a06082a8648ce3d0403020368003065023100863f69f21783c279f19df4aba3049851b8e05c44" &
        "c0a36eb3801d8f339cd34450aeb3e4b2930cbd98623baf79ad14385502306893a3d34e9335203337d8deaf2f12" &
        "4c7dca27ecc00aa0d11a02a757f293dbd1cce1c49c4cca4b4875aea981c46401d2";

      SI_Mid_Self_DER : constant String :=
        "308201b73082013ca00302010202020081300a06082a8648ce3d04030230133111300f06035504030c0873692d" &
        "696e746572301e170d3236303732393038313030365a170d3237303532353038313030365a30133111300f0603" &
        "5504030c0873692d696e7465723076301006072a8648ce3d020106052b81040022036200044d51021871860ab8" &
        "e06affcc44f94af2ead588163ee47c3a925c482aec1c13ec95579fd14f4756e35ebe1a7cfb4077ad849aa1fe83" &
        "51a4b83868c936a4e18e2a38bb540616c7e07a87e34378c2ba3e8c2f79a206758fed5680c8158a7b987c0fa363" &
        "3061300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301d0603551d0e041604" &
        "146d50e83c3aa909d04158d66863af9986458c1307301f0603551d230418301680147a0638a9b61e586eacf75a" &
        "52776968f6f801c493300a06082a8648ce3d0403020369003066023100b1e5538a8c151966ec2e26be905655cf" &
        "b24e82c232d588482018aec16235de375f905ce6f3b187317bb0441c13f90c3d023100f9f497e92d81de6a3c57" &
        "188c267fbc5a95fb07ca65e1ec6af9dcf339230aef20634446dd0dbfa9d512871e292c20716e";

      SI_Mid_Other_DER : constant String :=
        "308201b53082013ca00302010202020082300a06082a8648ce3d04030230133111300f06035504030c0873692d" &
        "696e746572301e170d3236303732393038313030365a170d3237303532353038313030365a30133111300f0603" &
        "5504030c0873692d6f746865723076301006072a8648ce3d020106052b81040022036200044d51021871860ab8" &
        "e06affcc44f94af2ead588163ee47c3a925c482aec1c13ec95579fd14f4756e35ebe1a7cfb4077ad849aa1fe83" &
        "51a4b83868c936a4e18e2a38bb540616c7e07a87e34378c2ba3e8c2f79a206758fed5680c8158a7b987c0fa363" &
        "3061300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301d0603551d0e041604" &
        "146d50e83c3aa909d04158d66863af9986458c1307301f0603551d230418301680147a0638a9b61e586eacf75a" &
        "52776968f6f801c493300a06082a8648ce3d04030203670030640230028880c0cacc17aeada041639e20f4cfe6" &
        "3d5b4194a2554ad27a728831b637a3e65ae23465d87fdb50dca1987f97bc2b023060c8cb52332bcd97ad15f52c" &
        "a4885e743d52d3495d8c6258d22cfc3621b7f9c3b6af40c65d88d2ebc607f3d86e1d6ecd";

      SI_Inter_NoAny_DER : constant String :=
        "308201ed30820174a003020102020172300a06082a8648ce3d04030230123110300e06035504030c0773692d72" &
        "6f6f74301e170d3236303732393038313334335a170d3237303532353038313334335a30133111300f06035504" &
        "030c0873692d696e7465723076301006072a8648ce3d020106052b81040022036200048d820adcf2775e7065ad" &
        "d15b168345189fdddbade134616d11a9b2ff4031a2a9f4fd86a18dca3dca4993318671747d837f912c3df48120" &
        "77448ace4e8bf46d55d97adb98bdb02f6f66740c016037d02497b759e06cf52e6c863041a007007351a3819c30" &
        "8199300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630160603551d20040f30" &
        "0d300b06092b06010401868d1f01300f0603551d240101ff04053003800100300d0603551d360101ff04030201" &
        "00301d0603551d0e041604147a0638a9b61e586eacf75a52776968f6f801c493301f0603551d23041830168014" &
        "e4adfd6a929eec316667b49362ab4b7cd848021c300a06082a8648ce3d0403020367003064023074ceec09e8e5" &
        "888826f130fc7ca86786c103d5b27ea4205015b61a70a645fe9574a609804e369a599b3285c815146d8d023075" &
        "4a2a30b2d5511d5a1e4a06cd5fafcf50da59616d460442c263813b7cf8f5ab468b085d2abbfc720e00d75ed058" &
        "49ff";

      SI_MidAny_Self_DER : constant String :=
        "308201c93082014fa00302010202020083300a06082a8648ce3d04030230133111300f06035504030c0873692d" &
        "696e746572301e170d3236303732393038313334335a170d3237303532353038313334335a30133111300f0603" &
        "5504030c0873692d696e7465723076301006072a8648ce3d020106052b81040022036200044d51021871860ab8" &
        "e06affcc44f94af2ead588163ee47c3a925c482aec1c13ec95579fd14f4756e35ebe1a7cfb4077ad849aa1fe83" &
        "51a4b83868c936a4e18e2a38bb540616c7e07a87e34378c2ba3e8c2f79a206758fed5680c8158a7b987c0fa376" &
        "3074300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630110603551d20040a30" &
        "0830060604551d2000301d0603551d0e041604146d50e83c3aa909d04158d66863af9986458c1307301f060355" &
        "1d230418301680147a0638a9b61e586eacf75a52776968f6f801c493300a06082a8648ce3d0403020368003065" &
        "023100db90d2118496b871a7d41e94869e024f62db758962b477ef63067460f75eee2da89698fe349b7ead75d5" &
        "89f2a97ccdca02307af04b39675a429ee3ba5a0de4d9eed5a9e7e5439aceb164c23fe627035712e696acbc0d15" &
        "b21fae567137b4eb7bf15f";

      SI_MidAny_Other_DER : constant String :=
        "308201ca3082014fa00302010202020084300a06082a8648ce3d04030230133111300f06035504030c0873692d" &
        "696e746572301e170d3236303732393038313334335a170d3237303532353038313334335a30133111300f0603" &
        "5504030c0873692d6f746865723076301006072a8648ce3d020106052b81040022036200044d51021871860ab8" &
        "e06affcc44f94af2ead588163ee47c3a925c482aec1c13ec95579fd14f4756e35ebe1a7cfb4077ad849aa1fe83" &
        "51a4b83868c936a4e18e2a38bb540616c7e07a87e34378c2ba3e8c2f79a206758fed5680c8158a7b987c0fa376" &
        "3074300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630110603551d20040a30" &
        "0830060604551d2000301d0603551d0e041604146d50e83c3aa909d04158d66863af9986458c1307301f060355" &
        "1d230418301680147a0638a9b61e586eacf75a52776968f6f801c493300a06082a8648ce3d0403020369003066" &
        "02310089abe10f6e6457d34be715571171f4241f0229a83ff84b22671ee70296b5910866bec983e16c69d0185d" &
        "591123c295b6023100c662dbd27f6321ada0f347660821d2018e895c150368beda50044c1cfa0ba116cf5cc2ab" &
        "4beff2f219a7473cbb98870c";

      SI_LeafAny_Self_DER : constant String :=
        "308201be30820145a00302010202020092300a06082a8648ce3d04030230133111300f06035504030c0873692d" &
        "696e746572301e170d3236303732393038313334335a170d3237303532353038313334335a3017311530130603" &
        "5504030c0c686f73742e6578616d706c653076301006072a8648ce3d020106052b81040022036200043533ae65" &
        "6cce864ebe5ec01abcd8be7da1900054dddbca9abfb51811f8f627686cfb5ef640120b25abb03ffc64ca4e1a25" &
        "230a35a74b76ee5c38326e61982a54201701b3659857b9f29e875a758ba8456d2a0de90e1c47eba92bc0b70994" &
        "e1e6a3683066300c0603551d130101ff0402300030160603551d20040f300d300b06092b06010401868d1f0130" &
        "1d0603551d0e041604142318475bea76beeb0af07d63a5ac5fcf840c4bb1301f0603551d230418301680146d50" &
        "e83c3aa909d04158d66863af9986458c1307300a06082a8648ce3d040302036700306402302585ffdc3cc6f971" &
        "b8f05bfc16526721500ebea572700f30c1b2d73cb52cdfd60e6aa939f952a0b4c10c198957431c860230402d69" &
        "0bc1ccdf6cbc8add97c5e4364be32d0432103314a1ab1ecd7642de909dea3cf72789185d0a72c788f83088955f";

      SI_LeafAny_Other_DER : constant String :=
        "308201c030820145a00302010202020092300a06082a8648ce3d04030230133111300f06035504030c0873692d" &
        "6f74686572301e170d3236303732393038313334335a170d3237303532353038313334335a3017311530130603" &
        "5504030c0c686f73742e6578616d706c653076301006072a8648ce3d020106052b81040022036200043533ae65" &
        "6cce864ebe5ec01abcd8be7da1900054dddbca9abfb51811f8f627686cfb5ef640120b25abb03ffc64ca4e1a25" &
        "230a35a74b76ee5c38326e61982a54201701b3659857b9f29e875a758ba8456d2a0de90e1c47eba92bc0b70994" &
        "e1e6a3683066300c0603551d130101ff0402300030160603551d20040f300d300b06092b06010401868d1f0130" &
        "1d0603551d0e041604142318475bea76beeb0af07d63a5ac5fcf840c4bb1301f0603551d230418301680146d50" &
        "e83c3aa909d04158d66863af9986458c1307300a06082a8648ce3d0403020369003066023100b298db0acf51c2" &
        "ff1b8d23465e1cc0c82597ae1a3e100b3cc0e8b3772592b737a698869b9ffe01bf1bd5d81de8e979cf023100fd" &
        "acd518e6bf8c242be13abc2a5b833acec2cf97a2ed3b0344cc2baa5cb5458f20d81495b9998e4ef34183c557b7" &
        "5963";

      SI_Leaf_Self_DER : constant String :=
        "308201a73082012da00302010202020091300a06082a8648ce3d04030230133111300f06035504030c0873692d" &
        "696e746572301e170d3236303732393038313030365a170d3237303532353038313030365a3017311530130603" &
        "5504030c0c686f73742e6578616d706c653076301006072a8648ce3d020106052b81040022036200043533ae65" &
        "6cce864ebe5ec01abcd8be7da1900054dddbca9abfb51811f8f627686cfb5ef640120b25abb03ffc64ca4e1a25" &
        "230a35a74b76ee5c38326e61982a54201701b3659857b9f29e875a758ba8456d2a0de90e1c47eba92bc0b70994" &
        "e1e6a350304e300c0603551d130101ff04023000301d0603551d0e041604142318475bea76beeb0af07d63a5ac" &
        "5fcf840c4bb1301f0603551d230418301680146d50e83c3aa909d04158d66863af9986458c1307300a06082a86" &
        "48ce3d04030203680030650230248d46c68e75e3e512d3324b483943fa1d627ea99925e6d5cd576ccf667c5779" &
        "8745b20c2387871cbc6393b108e0f9b5023100953d386784f3bc27fe4a1653413a1de3ffe2af72a24ed68b3723" &
        "32a79876fcbfb6aed73ccc0383eafdd83cc673d8b4ea";

      SI_Leaf_Other_DER : constant String :=
        "308201a63082012da00302010202020091300a06082a8648ce3d04030230133111300f06035504030c0873692d" &
        "6f74686572301e170d3236303732393038313030365a170d3237303532353038313030365a3017311530130603" &
        "5504030c0c686f73742e6578616d706c653076301006072a8648ce3d020106052b81040022036200043533ae65" &
        "6cce864ebe5ec01abcd8be7da1900054dddbca9abfb51811f8f627686cfb5ef640120b25abb03ffc64ca4e1a25" &
        "230a35a74b76ee5c38326e61982a54201701b3659857b9f29e875a758ba8456d2a0de90e1c47eba92bc0b70994" &
        "e1e6a350304e300c0603551d130101ff04023000301d0603551d0e041604142318475bea76beeb0af07d63a5ac" &
        "5fcf840c4bb1301f0603551d230418301680146d50e83c3aa909d04158d66863af9986458c1307300a06082a86" &
        "48ce3d04030203670030640230545d57151e1dcb206ee398b91e4cbdc5a0fe6c4ed465e35a5bf37f6e85ba99aa" &
        "62bdb12fa3e631659c22676bc2502e5e02305380e6a691e72b7c456e5157ed153231abcd50ea8d5d4154cf719c" &
        "acdcb2928c0b6f327de6f3f7a8046e2dfb30fedfb4";

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

      function Decoded (Hex : String) return X509C.Certificate
      is (X509C.Decode_DER
            (From_Hex (Hex), CryptoLib.ASN1.Default_Limits, Status));

      --  Two scenarios, each with a self-issued and a plain middle
      --  certificate. Allowance: does a self-issued certificate spend the
      --  explicit-policy countdown. Wildcard: may it still use anyPolicy
      --  after inhibitAnyPolicy reached zero.
      type Which is (Self, Other);
      type Scenario is (Allowance, Wildcard);

      type Four (Case_Kind : Scenario; Kind : Which) is
        limited new XV.Path_Source with null record;

      overriding function Length (Source : Four) return Positive is (4);

      overriding function Certificate_At
        (Source : Four; Index : Positive) return X509C.Certificate
      is (case Index is
             when 1 =>
               (case Source.Case_Kind is
                   when Allowance =>
                     (if Source.Kind = Self then Decoded (SI_Leaf_Self_DER)
                      else Decoded (SI_Leaf_Other_DER)),
                   when Wildcard =>
                     (if Source.Kind = Self
                      then Decoded (SI_LeafAny_Self_DER)
                      else Decoded (SI_LeafAny_Other_DER))),
             when 2 =>
               (case Source.Case_Kind is
                   when Allowance =>
                     (if Source.Kind = Self then Decoded (SI_Mid_Self_DER)
                      else Decoded (SI_Mid_Other_DER)),
                   when Wildcard =>
                     (if Source.Kind = Self
                      then Decoded (SI_MidAny_Self_DER)
                      else Decoded (SI_MidAny_Other_DER))),
             when 3 =>
               (case Source.Case_Kind is
                   when Allowance => Decoded (SI_Inter_DER),
                   when Wildcard  => Decoded (SI_Inter_NoAny_DER)),
             when others => Decoded (SI_Root_DER));

      overriding function Is_Trust_Anchor
        (Source : Four; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Bytes (Item)
          = X509C.Subject_Bytes (Decoded (SI_Root_DER)));

      At_Time : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 9, Day => 1,
         Hour => 12, Minute => 0, Second => 0);

      function Verdict
        (Case_Kind : Scenario; Kind : Which) return XV.Validation_Result
      is (XV.Validate_Path
            (Four'(Case_Kind => Case_Kind, Kind => Kind), At_Time));
   begin
      --  The premises, asserted rather than assumed: one middle certificate
      --  is self-issued and the other is not, and they are otherwise the
      --  same certificate.
      Check (X509C.Is_Self_Issued (Decoded (SI_Mid_Self_DER)),
             "fixture: the one middle certificate is self-issued");
      Check (not X509C.Is_Self_Issued (Decoded (SI_Mid_Other_DER)),
             "fixture: and the other is not");
      Check (X509C.Public_Key (Decoded (SI_Mid_Self_DER))
             = X509C.Public_Key (Decoded (SI_Mid_Other_DER)),
             "fixture: they carry the same key");

      --  The allowance survives a certificate that did not lengthen the
      --  path.
      Check (Verdict (Allowance, Self).Valid,
             "a self-issued certificate does not spend the explicit-policy "
             & "allowance: "
             & XV.Failure_Image (Verdict (Allowance, Self).Failure));

      --  And is spent by one that did. OpenSSL agrees on both, with
      --  openssl verify -policy_check over the same two chains.
      Check (not Verdict (Allowance, Other).Valid
             and then Verdict (Allowance, Other).Failure
                      = XV.Policy_Not_Established,
             "and one that is not self-issued does spend it, got "
             & XV.Failure_Image (Verdict (Allowance, Other).Failure));

      --  The other half of the rule, 6.1.3 (d)(2): a self-issued
      --  certificate may still assert anyPolicy after inhibitAnyPolicy has
      --  reached zero, because it is the same CA rather than a step further
      --  down the path. Here the intermediate withdraws the wildcard and the
      --  middle certificate uses it anyway.
      Check (Verdict (Wildcard, Self).Valid,
             "a self-issued certificate may still use anyPolicy after it "
             & "was inhibited: "
             & XV.Failure_Image (Verdict (Wildcard, Self).Failure));
      Check (not Verdict (Wildcard, Other).Valid
             and then Verdict (Wildcard, Other).Failure
                      = XV.Policy_Not_Established,
             "and one that is not self-issued may not, got "
             & XV.Failure_Image (Verdict (Wildcard, Other).Failure));
   end Check_Self_Issued_Policy_Allowance;

   --  An algorithm this crate cannot verify says so.
   --
   --  "Could not check" and "the signature is bad" are different answers and
   --  the second is a claim this has no right to make. Both certificates
   --  below are perfectly good and made by OpenSSL: one is signed with
   --  sha1WithRSAEncryption, which this does not verify and will not start
   --  verifying, and the other carries an X25519 key, which is not a signing
   --  key at all. This test used to use Ed448 for both, until Ed448 became
   --  something this crate can decide -- which is the right way for the
   --  example to go stale.
   procedure Check_Unsupported_Algorithm is
      package XS renames CryptoLib.X509.Signatures;
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.Identities.Identity_Status;
      use type CryptoLib.X509.Public_Key_Algorithm;
      use type CryptoLib.X509.Signature_Algorithm;
      use type XS.Verification_Result;

      package X509C renames CryptoLib.X509.Certificates;
      package ID renames CryptoLib.Identities;

      SHA1_Cert_DER : constant String :=
        "308202fc308201e4a003020102021421f332997071016a38d94b94edf8ab92c999e32d300d06092a864886f7" &
        "0d010105050030163114301206035504030c0b53484131205369676e6564301e170d32363037323930393538" &
        "34375a170d3334313031353039353834375a30163114301206035504030c0b53484131205369676e65643082" &
        "0122300d06092a864886f70d01010105000382010f003082010a0282010100da33c333676622516409e1b1c2" &
        "0b1029a1260b7d3d8c6e535ba9d8c123f2921102a4222477e682bcb7dd7fdd8a3bec2992d630a72967d58c43" &
        "0982257f34a330dd9e0079f9b43b46470ab57b6399c9d1cd3e5764cb9ef9d2193ca4b6be80d3bfa3eddae0fc" &
        "44b30ff364b5e47ba5c68105632ac2e665435dd50d79cc7b0197780d4c6e6d5d5c7eb41abc03cbe5cb4db682" &
        "4dea94e25ac87f2afe22ac9ee871996e65d6f2a2651b96955401ece8863e4255a7048b3932118d08442cb9a4" &
        "ea5ba7778e4f906c607877d9dc8601b95b09974d67c62d202e68073712dd53025937a6346d0eccced5d5ae9b" &
        "7dc49d165fdae502e1533b268a2ead1f17bca74e8d185d0203010001a3423040300f0603551d130101ff0405" &
        "30030101ff300e0603551d0f0101ff040403020204301d0603551d0e04160414ea4007693b0884491bf35172" &
        "c8a416b868841226300d06092a864886f70d01010505000382010100cb01e18a312a21771da0ed7b487449b8" &
        "ae2cd45fa7992a22c0c67952753dd03132a4914cfc8111557fc4ea6f0b6778f4c32d029d55f7ac2d20e4131a" &
        "bb7ece7f5559a5d07bec66ee7f30b2f8e40fcc6c31584da6cf4db6f2a4c398520f9c906ee20e662358c2c6aa" &
        "83683f9ddbec30fb4e52df39a0110d7c66c3fe1789547f0431c3ff20bcd08c92def66a0f1eeeb8e94821ee45" &
        "be0ef394ed24821d83762f5c3ba499a410772553600d9575878c3e10e2c8ebb0b4daae1067facee8cb3927f9" &
        "1c0a34495965f372b45a95a13d649ef2313670c76e768e5b4fdd8151fcf774e8af5ed63f80c3b46d0602cc6d" &
        "2108a034c370e963bcaa5a25fe3f5ff02d521dbf";

      X25519_Chain_PEM : constant String :=
        "-----BEGIN CERTIFICATE-----" & ASCII.LF &
        "MIICETCB+qADAgECAhQSIUnuxGQXhq2YuXB6IckuDwRUjzANBgkqhkiG9w0BAQsF" & ASCII.LF &
        "ADAWMRQwEgYDVQQDDAtTSEExIFNpZ25lZDAeFw0yNjA3MjkwOTU4NDdaFw0zMjAx" & ASCII.LF &
        "MTkwOTU4NDdaMBgxFjAUBgNVBAMMDXgyNTUxOSBob2xkZXIwKjAFBgMrZW4DIQC/" & ASCII.LF &
        "KhbOXlLYkhUu7UksLji4GlugZT/JYb447bzavK+oXaNQME4wDAYDVR0TAQH/BAIw" & ASCII.LF &
        "ADAdBgNVHQ4EFgQU+SqUNazzFpun0XnPECp6MhZ8vggwHwYDVR0jBBgwFoAU6kAH" & ASCII.LF &
        "aTsIhEkb81FyyKQWuGiEEiYwDQYJKoZIhvcNAQELBQADggEBALGX9WDd+laChTfc" & ASCII.LF &
        "WvYM9mrZpwEowuohuQUZRdIj7FjW0Zju1Vg+RkJpNknlu6dlNaIxNeWDf4p2mDD6" & ASCII.LF &
        "ujQ5HQHqkyBE/zdc8jMo5U5K2Z3DyQs/rnArcQ4u3jggUOWA/Vfn+83tjJciT5WQ" & ASCII.LF &
        "k8u/YDheEPE8WzEhb+O1FLVOf7/o45gK+r3BQNavkVy40RAc8VviZxX4sM9bKk11" & ASCII.LF &
        "bjSPGxOwwyen6+9KYzg6FthFaVglM+O+M3cZjY5i9v6qcna5JFxJtv5HvzeKheHR" & ASCII.LF &
        "w1s4wNdIDgIr+5i/TsIQeNklB0fwIjgdcf1smCFH5kB1XnmeIlPFrzdG3cZVLOaN" & ASCII.LF &
        "WnAlpL0=" & ASCII.LF &
        "-----END CERTIFICATE-----";

      X25519_Key_PEM : constant String :=
        "-----BEGIN PRIVATE KEY-----" & ASCII.LF &
        "MC4CAQAwBQYDK2VuBCIEIHApGfeg/4Sj6ndg4fW3n6pvFEPUJB26+YZqpezUHah+" & ASCII.LF &
        "-----END PRIVATE KEY-----";

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
      Cert   : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (SHA1_Cert_DER), CryptoLib.ASN1.Default_Limits, Status);
   begin
      --  It decodes. A certificate carrying a key this crate cannot use is
      --  still a certificate, and its other fields still mean what they say.
      Check (Status = CryptoLib.ASN1.Errors.Ok
             and then X509C.Is_Present (Cert),
             "a certificate signed with an algorithm this does not verify "
             & "still decodes: "
             & CryptoLib.ASN1.Errors.Status_Image (Status));
      Check (X509C.Signature_Algorithm_Of (Cert)
             = CryptoLib.X509.Unknown_Signature_Algorithm,
             "and the algorithm it was signed with is named as one this does "
             & "not know rather than guessed at");

      --  The signature is genuine -- OpenSSL made it -- and unverifiable
      --  here. Reporting Invalid_Signature would be saying the certificate
      --  was altered, which this cannot know.
      Check (not XS.Is_Supported (X509C.Signature_Algorithm_Of (Cert)),
             "the algorithm is not one this claims to decide");
      Check (XS.Verify_Certificate_Signature (Cert, Cert)
             = XS.Unsupported_Algorithm,
             "a self-signature this crate cannot check is reported as "
             & "unchecked, not as bad, got "
             & XS.Result_Image (XS.Verify_Certificate_Signature (Cert, Cert)));

      --  Same distinction one level up. The key really does belong to the
      --  certificate; Identities cannot establish that, and says so with a
      --  status of its own rather than the one meaning "these do not match".
      declare
         Item : ID.Local_Identity;
         St   : ID.Identity_Status;
      begin
         ID.Decode (X25519_Chain_PEM, X25519_Key_PEM, Item, St);
         Check (St = ID.Unsupported_Key,
                "an identity whose key this cannot check reports unsupported "
                & "rather than mismatched, got " & ID.Status_Image (St));
         Check (not ID.Is_Present (Item),
                "and nothing is handed back");
      end;
   end Check_Unsupported_Algorithm;

   --  Not verified is not the same as verified and wrong.
   --
   --  X509.Signatures answers with four different failures where a lesser
   --  interface would answer with one. Algorithm_Mismatch means the
   --  algorithm named and the key handed over cannot go together;
   --  Malformed_Signature means the bytes are not shaped like a signature
   --  for that algorithm; Missing_Input means a certificate that did not
   --  decode was passed. None of them means the signature is bad, and all
   --  three had no test -- so any of them could have collapsed into
   --  Invalid_Signature, which is this crate asserting a certificate was
   --  altered when it has established nothing of the sort.
   procedure Check_Verification_Failure_Kinds is
      package XS renames CryptoLib.X509.Signatures;
      package X509C renames CryptoLib.X509.Certificates;
      use type XS.Verification_Result;

      Rng     : CryptoLib.Random.Random_Source;
      Seed    : Ada.Streams.Stream_Element_Array (1 .. 32);
      Public  : Ada.Streams.Stream_Element_Array (1 .. 32);
      Message : constant Ada.Streams.Stream_Element_Array (1 .. 5) :=
        [1, 2, 3, 4, 5];
      Signed  : Ada.Streams.Stream_Element_Array (1 .. 64);
   begin
      CryptoLib.Random.Initialize_Production (Rng);
      Check (CryptoLib.Ed25519.Generate_Keypair (Rng, Seed, Public)
             = CryptoLib.Errors.Ok,
             "fixture: an Ed25519 key pair");
      Check (CryptoLib.Ed25519.Sign (Seed, Public, Message, Signed)
             = CryptoLib.Errors.Ok,
             "fixture: it signs");

      --  The control. Without it the refusals below would be consistent
      --  with nothing working at all.
      Check (XS.Verify_With_Key
               (Message, Signed, CryptoLib.X509.Ed25519_Signature,
                CryptoLib.X509.Ed25519, Public)
             = XS.Valid,
             "the signature verifies under its own key and algorithm");

      --  Altered message: this one really is a bad signature, and saying so
      --  is correct. It is here so the distinctions below mean something.
      declare
         Other : Ada.Streams.Stream_Element_Array := Message;
      begin
         Other (Other'First) := Other (Other'First) xor 1;
         Check (XS.Verify_With_Key
                  (Other, Signed, CryptoLib.X509.Ed25519_Signature,
                   CryptoLib.X509.Ed25519, Public)
                = XS.Invalid_Signature,
                "an altered message is a bad signature, got "
                & XS.Result_Image
                    (XS.Verify_With_Key
                       (Other, Signed, CryptoLib.X509.Ed25519_Signature,
                        CryptoLib.X509.Ed25519, Public)));
      end;

      --  An ECDSA signature algorithm over an Ed25519 key. Nothing was
      --  checked, and reporting a bad signature would say the opposite.
      Check (XS.Verify_With_Key
               (Message, Signed, CryptoLib.X509.ECDSA_With_SHA256,
                CryptoLib.X509.Ed25519, Public)
             = XS.Algorithm_Mismatch,
             "an algorithm the key cannot carry is a mismatch, not a bad "
             & "signature, got "
             & XS.Result_Image
                 (XS.Verify_With_Key
                    (Message, Signed, CryptoLib.X509.ECDSA_With_SHA256,
                     CryptoLib.X509.Ed25519, Public)));

      --  An ECDSA signature has to be a SEQUENCE of two integers. Bytes
      --  that are not are not a failed signature; they are not a signature.
      declare
         P384_Key : Ada.Streams.Stream_Element_Array (1 .. 97) :=
           [others => 0];
         Rubbish  : constant Ada.Streams.Stream_Element_Array (1 .. 8) :=
           [others => 16#41#];
      begin
         P384_Key (P384_Key'First) := 16#04#;
         Check (XS.Verify_With_Key
                  (Message, Rubbish, CryptoLib.X509.ECDSA_With_SHA384,
                   CryptoLib.X509.ECDSA_P384, P384_Key)
                = XS.Malformed_Signature,
                "signature bytes of the wrong shape are malformed, not "
                & "invalid, got "
                & XS.Result_Image
                    (XS.Verify_With_Key
                       (Message, Rubbish, CryptoLib.X509.ECDSA_With_SHA384,
                        CryptoLib.X509.ECDSA_P384, P384_Key)));
      end;

      --  A certificate that did not decode carries no key to check against.
      declare
         Status : CryptoLib.ASN1.Errors.Decode_Status;
         Nothing : constant Ada.Streams.Stream_Element_Array (1 .. 0) :=
           [others => 0];
         Absent  : constant X509C.Certificate :=
           X509C.Decode_DER (Nothing, CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (not X509C.Is_Present (Absent),
                "fixture: an empty input decodes to nothing");
         Check (XS.Verify_Signed_Data
                  (Message, Signed, CryptoLib.X509.Ed25519_Signature, Absent)
                = XS.Missing_Input,
                "and verifying against it reports missing input, got "
                & XS.Result_Image
                    (XS.Verify_Signed_Data
                       (Message, Signed, CryptoLib.X509.Ed25519_Signature,
                        Absent)));
      end;
   end Check_Verification_Failure_Kinds;

   --  A policy tree wider than this crate will hold.
   --
   --  The bound exists because the tree is built from certificates somebody
   --  else wrote and must not grow without end. Reaching it is reported and
   --  refused rather than truncated: a partial tree is missing exactly the
   --  nodes that pruning would have removed, so answering from one can only
   --  ever be too permissive.
   --
   --  This is a real divergence and worth stating as one. OpenSSL accepts
   --  the chain below; this refuses it. Exhausted is how a caller tells that
   --  apart from the certificates failing on their own merits -- the first
   --  is this implementation's limit, the second is not, and they call for
   --  different things to be done about them.
   procedure Check_Policy_Tree_Bound is
      package X509C renames CryptoLib.X509.Certificates;
      package XV renames CryptoLib.X509.Validation;
      use type XV.Validation_Failure;

      EX_Root_DER : constant String :=
        "308201693082010ea0030201020214258aa8101cb678c72721299bd717e683a715057a300a06082a8648ce3d04" &
        "030230123110300e06035504030c0765782d726f6f74301e170d3236303732393038333334315a170d32373035" &
        "32353038333334315a30123110300e06035504030c0765782d726f6f743059301306072a8648ce3d020106082a" &
        "8648ce3d0301070342000423f87ab29ecf1e6cbe382570602a675d04e31cd3e7a33351f75c266537312873dc77" &
        "ae00b968e993ea0eecc3d07551ea64d539ca88810b7c5b1d9758807493e5a3423040300f0603551d130101ff04" &
        "0530030101ff300e0603551d0f0101ff040403020106301d0603551d0e04160414137a5ce002458b4a02a927d3" &
        "379fb533e8f980f4300a06082a8648ce3d0403020349003046022100dc19551b600487325853796e2ee38b741f" &
        "7e3c9d49ef67cb47fa6eb45c33feb10221009a53ca584544b77b244fa1c2481b1bb16a0ffdf555c1007bb017c9" &
        "2c2c580a38";

      EX_C1_DER : constant String :=
        "30820247308201eda003020102020200a1300a06082a8648ce3d04030230123110300e06035504030c0765782d" &
        "726f6f74301e170d3236303732393038333334315a170d3237303532353038333334315a3010310e300c060355" &
        "04030c0565782d63313059301306072a8648ce3d020106082a8648ce3d030107034200041d8a2619a23951a09a" &
        "00dc1bed7c4c59047f1e8fa693792c989983ca371c6210fc5182095e4a15d5cf3808435b125d1e946d90f5c206" &
        "f479b663383a38191a63a38201333082012f300f0603551d130101ff040530030101ff300e0603551d0f0101ff" &
        "0404030201063081cb0603551d200481c33081c0300a06082b06010401a70801300a06082b06010401a7090130" &
        "0a06082b06010401a70a01300a06082b06010401a70b01300a06082b06010401a70c01300a06082b06010401a7" &
        "0d01300a06082b06010401a70e01300a06082b06010401a70f01300a06082b06010401a71001300a06082b0601" &
        "0401a71101300a06082b06010401a71201300a06082b06010401a71301300a06082b06010401a71401300a0608" &
        "2b06010401a71501300a06082b06010401a71601300a06082b06010401a71701301d0603551d0e04160414b1b8" &
        "23bd89082af24e093638e614da17ce2ab875301f0603551d23041830168014137a5ce002458b4a02a927d3379f" &
        "b533e8f980f4300a06082a8648ce3d0403020348003045022041c1e75429a7c3c05ca8475f9f88b4c7f5598c3e" &
        "7431860a425f33ea0a61404e022100a7fc6c3d0901714ac2734364557b32dfc4218e25be804f85f243dac368ca" &
        "bae6";

      EX_C2_DER : constant String :=
        "308201863082012ca003020102020200a2300a06082a8648ce3d0403023010310e300c06035504030c0565782d" &
        "6331301e170d3236303732393038333334315a170d3237303532353038333334315a3010310e300c0603550403" &
        "0c0565782d63323059301306072a8648ce3d020106082a8648ce3d0301070342000451db26ea2e413733d7c6e9" &
        "d07b06b08f5df72df69b4e10d0ee49a4980f388ff02483861446fd20d518c3be5f05f1a27abfced023306fd500" &
        "8630749610138492a3763074300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106" &
        "30110603551d20040a300830060604551d2000301d0603551d0e041604141b2aac4c9eea97e063695b33838fdb" &
        "8be4a2d5cb301f0603551d23041830168014b1b823bd89082af24e093638e614da17ce2ab875300a06082a8648" &
        "ce3d0403020348003045022100dc141147ef634d4fbbe89af902deea720a917be8047350b642b8b4d0cfa8ae55" &
        "022049425ef4466ca029bc3419e20c535a97e65adbc07f49b46d2996b771bc0f8e36";

      EX_C3_DER : constant String :=
        "308201873082012ca003020102020200a3300a06082a8648ce3d0403023010310e300c06035504030c0565782d" &
        "6332301e170d3236303732393038333334315a170d3237303532353038333334315a3010310e300c0603550403" &
        "0c0565782d63333059301306072a8648ce3d020106082a8648ce3d030107034200048cddee079b2fefa50d3a68" &
        "9ff693bd9b81979ce7a5415b202cc7a77f1ad95002896c947821fa2559c62977aca714802f6426ce8e83669506" &
        "6244e6d8dc2d1cc7a3763074300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106" &
        "30110603551d20040a300830060604551d2000301d0603551d0e04160414a5db2091914df88362860a8eb50d77" &
        "d03d9de3b5301f0603551d230418301680141b2aac4c9eea97e063695b33838fdb8be4a2d5cb300a06082a8648" &
        "ce3d0403020349003046022100922be191dc6f1bf2034c76700a87851e4c69f009f9db2be9e0df2a770411f89b" &
        "022100ea59de8c1f19e253d2fa8bf341e83c39098f3330335e847c785e35585c6b6a35";

      EX_Leaf_DER : constant String :=
        "308201753082011ba003020102020200a4300a06082a8648ce3d0403023010310e300c06035504030c0565782d" &
        "6333301e170d3236303732393038333334315a170d3237303532353038333334315a30123110300e0603550403" &
        "0c0765782d6c6561663059301306072a8648ce3d020106082a8648ce3d0301070342000471fa7e6cdc9e7bed4f" &
        "e3448926d3af91e0bc41f6e01977b1c3546c38b984c5fe0e5f97e3cfdfc0c4c308dffe3858a74d74f26de0ad73" &
        "7b8048d56b312a6c592aa3633061300c0603551d130101ff0402300030110603551d20040a300830060604551d" &
        "2000301d0603551d0e04160414e3b8a5632e9979a915046d66332f2e33f3c47974301f0603551d230418301680" &
        "14a5db2091914df88362860a8eb50d77d03d9de3b5300a06082a8648ce3d0403020348003045022062f75565c1" &
        "48b13724cea67660270eabbd6db17952df724d6117b0c5bfc1718b022100b79a98c915ab8f100d541e2e7f0637" &
        "cc057fe1c7ab56ce8a111fd97158f98b19";

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

      function Decoded (Hex : String) return X509C.Certificate
      is (X509C.Decode_DER
            (From_Hex (Hex), CryptoLib.ASN1.Default_Limits, Status));

      --  Sixteen policies at the first level, widened by anyPolicy at each
      --  level below it: 1 + 16 + 16 + 16 + 16 nodes against a bound of 64.
      type Wide is limited new XV.Path_Source with null record;

      overriding function Length (Source : Wide) return Positive is (5);

      overriding function Certificate_At
        (Source : Wide; Index : Positive) return X509C.Certificate
      is (case Index is
             when 1      => Decoded (EX_Leaf_DER),
             when 2      => Decoded (EX_C3_DER),
             when 3      => Decoded (EX_C2_DER),
             when 4      => Decoded (EX_C1_DER),
             when others => Decoded (EX_Root_DER));

      overriding function Is_Trust_Anchor
        (Source : Wide; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Bytes (Item)
          = X509C.Subject_Bytes (Decoded (EX_Root_DER)));

      At_Time : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 9, Day => 1,
         Hour => 12, Minute => 0, Second => 0);

      Verdict : constant XV.Validation_Result :=
        XV.Validate_Path (Wide'(null record), At_Time);
   begin
      --  The premise: the first certificate really does carry enough
      --  policies to widen the tree past the bound. Sixteen is also the
      --  most one certificate may assert, so this is the widest a single
      --  level can get.
      declare
         Named : constant CryptoLib.X509.Policies.Policy_Set :=
           CryptoLib.X509.Policies.Policies_Of (Decoded (EX_C1_DER));
      begin
         Check (Named.Well_Formed
                and then Named.Count = CryptoLib.X509.Policies.Maximum_Policies,
                "fixture: the first certificate asserts a full set of "
                & "policies, got" & Natural'Image (Named.Count));
      end;

      --  Refused, and said to be refused for this reason rather than for
      --  anything the certificates did.
      Check (not Verdict.Valid,
             "a tree wider than the bound is refused rather than answered "
             & "from in part");
      Check (Verdict.Policies.Exhausted,
             "and the refusal says the bound was reached, not that the "
             & "chain establishes no policy");
      Check (Verdict.Failure = XV.Policy_Not_Established,
             "reported as a policy failure, got "
             & XV.Failure_Image (Verdict.Failure));
   end Check_Policy_Tree_Bound;

   --  A policy set is a set, at both ends.
   --
   --  Coming in: RFC 5280 4.2.1.4 says a policy OID must not appear twice
   --  in one extension, and OpenSSL refuses one that does (error 42,
   --  "invalid or inconsistent certificate policy extension"). Accepting
   --  it would leave this the more permissive of the two on input the RFC
   --  forbids outright, which is the wrong direction for this library to
   --  differ in.
   --
   --  Going out: two nodes can carry the same policy without anything
   --  being wrong -- two mappings converging on one subject policy is the
   --  ordinary way to arrive there -- and the reported set listed it once
   --  per node. Nothing was refused that should have been accepted, so
   --  this is not an unsound verdict; it is a caller counting the list and
   --  reading a repetition as breadth.
   procedure Check_Policy_Set_Is_A_Set is
      package X509C renames CryptoLib.X509.Certificates;
      package PP renames CryptoLib.X509.Policies;
      package XV renames CryptoLib.X509.Validation;
      use type CryptoLib.ASN1.Errors.Decode_Status;

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

      Dup_Policy_DER : constant String :=
        "308201a030820146a00302010202146f3c7cb756844c0a8daf62f2208802ba31ac25ac300a06082a8648ce3d04" &
        "03023011310f300d06035504030c065020526f6f74301e170d3236303732393038343531395a170d3334313031" &
        "353038343531395a3011310f300d06035504030c064475702043413059301306072a8648ce3d020106082a8648" &
        "ce3d030107034200048b245cf0e8e82860e05d6391e4747088bea4efe6894425cc78ea2598d7c60f5777a3eede" &
        "abf4bbcf66ce81a56ed8fde1207630ec6ea5b42e2af72d898ac5b0e7a37c307a300f0603551d130101ff040530" &
        "030101ff300e0603551d0f0101ff04040302020430170603551d200410300e300506032a0304300506032a0304" &
        "301d0603551d0e041604143aa5eb3b237e63b3f2a0710f36e2ee6d60625cc6301f0603551d2304183016801402" &
        "2ece54b366f27ede1b920700fb928139116f3f300a06082a8648ce3d04030203480030450220231e243cb54f35" &
        "131612fabafd2f527a87c66c5cbe31e9e224ae8aa24c5a1132022100d8931fda0f0bc878d3d8f9a4d88a015eac" &
        "589d43e60285c4282ce615d5a45068";

      CV_Root_DER : constant String :=
        "308201673082010ca003020102021438712a03489d5b69aefec58a74228f323acc452d300a06082a8648ce3d04" &
        "03023011310f300d06035504030c065020526f6f74301e170d3236303732393038343531395a170d3336303732" &
        "363038343531395a3011310f300d06035504030c065020526f6f743059301306072a8648ce3d020106082a8648" &
        "ce3d03010703420004456418d55e203fe65b9f8c38fb141be790aebcb087d03965a3e6f8f3e555aeb6a24623d5" &
        "aaf702768805759cbc5186201d8b054de710825cd2b80dc2ca9b6950a3423040300f0603551d130101ff040530" &
        "030101ff300e0603551d0f0101ff040403020204301d0603551d0e04160414022ece54b366f27ede1b920700fb" &
        "928139116f3f300a06082a8648ce3d0403020349003046022100f7618559ffeac694358047b4e91c751e63f9c8" &
        "a94cb85592c13596b05980ab5b02210097f23bcf1b16a617cf03076c9b638540ff7f1457a268770df533e00e2f" &
        "0ee7cd";

      CV_AB_DER : constant String :=
        "3082019f30820145a00302010202146f3c7cb756844c0a8daf62f2208802ba31ac25ad300a06082a8648ce3d04" &
        "03023011310f300d06035504030c065020526f6f74301e170d3236303732393038343531395a170d3334313031" &
        "353038343531395a3010310e300c06035504030c0541422043413059301306072a8648ce3d020106082a8648ce" &
        "3d030107034200048b245cf0e8e82860e05d6391e4747088bea4efe6894425cc78ea2598d7c60f5777a3eedeab" &
        "f4bbcf66ce81a56ed8fde1207630ec6ea5b42e2af72d898ac5b0e7a37c307a300f0603551d130101ff04053003" &
        "0101ff300e0603551d0f0101ff04040302020430170603551d200410300e300506032a0301300506032a030230" &
        "1d0603551d0e041604143aa5eb3b237e63b3f2a0710f36e2ee6d60625cc6301f0603551d23041830168014022e" &
        "ce54b366f27ede1b920700fb928139116f3f300a06082a8648ce3d040302034800304502205b1b6cea73d3c0e9" &
        "0684665b6b05f52c756b21594af01cf309dbe10f37fb4400022100b72a6346f917f03829b91c9b527f779a028b" &
        "42f0169017bd2a14a4039a9cceeb";

      CV_Map_DER : constant String :=
        "308201c53082016aa0030201020214140f080672287aeb0d12b20eca69618ad6ccb75a300a06082a8648ce3d04" &
        "03023010310e300c06035504030c054142204341301e170d3236303732393038343531395a170d333431303135" &
        "3038343531395a3011310f300d06035504030c064d61702043413059301306072a8648ce3d020106082a8648ce" &
        "3d03010703420004c57bfeab6876597b9837d11e2a014c5635b7ba4e23e656fc0fdef9102c24bb86510273b3ab" &
        "993e7ea30dd8d2abf6ef31ec6906ecece4b4936c3a6a446825caa1a381a030819d300f0603551d130101ff0405" &
        "30030101ff300e0603551d0f0101ff04040302020430170603551d200410300e300506032a0301300506032a03" &
        "0230210603551d21041a3018300a06032a030106032a0309300a06032a030206032a0309301d0603551d0e0416" &
        "04144213281531333a76ba243992cc9b3570024d80c9301f0603551d230418301680143aa5eb3b237e63b3f2a0" &
        "710f36e2ee6d60625cc6300a06082a8648ce3d0403020349003046022100b978f747358fef7b843c5951d2729f" &
        "e2157a9032234fab5054e0342c719e7ac6022100f173dc4da3833c5873004bbff6cae519f7855859d83e46ac6e" &
        "6ba2b79752e4c5";

      CV_Leaf_DER : constant String :=
        "308201883082012fa0030201020214793d3836dd484ab712ce6e5876bfb95ec73531a2300a06082a8648ce3d04" &
        "03023011310f300d06035504030c064d6170204341301e170d3236303732393038343533375a170d3334313031" &
        "353038343533375a30143112301006035504030c09782e6578616d706c653059301306072a8648ce3d02010608" &
        "2a8648ce3d03010703420004985fb7103ef3a20f32fa4ea636bbf614aff1c998e56410209b6882f4c19a7ce09d" &
        "a8e95ee119f295fccf4de59e46c8ff212667609ce4a4fa53ee6a20cef93f42a3623060300c0603551d130101ff" &
        "0402300030100603551d2004093007300506032a0309301d0603551d0e041604147471bbec40749113341508ee" &
        "601bd5dc5eb116a2301f0603551d230418301680144213281531333a76ba243992cc9b3570024d80c9300a0608" &
        "2a8648ce3d0403020347003044022100e31cbbf268a7036a8207c8cd98cae7c385741d59199e43b2d6670a9185" &
        "c7d747021f2d41fa8ca8245f053189b898a850d014d075387846b95be31ff57f3f8fa7c6";

      Status : CryptoLib.ASN1.Errors.Decode_Status;

      function Decoded (Hex : String) return X509C.Certificate
      is (X509C.Decode_DER
            (From_Hex (Hex), CryptoLib.ASN1.Default_Limits, Status));

      --  root -> {1.2.3.1, 1.2.3.2} -> both mapped to 1.2.3.9 -> 1.2.3.9
      type Converging is limited new XV.Path_Source with null record;

      overriding function Length (Source : Converging) return Positive is (4);

      overriding function Certificate_At
        (Source : Converging; Index : Positive) return X509C.Certificate
      is (case Index is
             when 1      => Decoded (CV_Leaf_DER),
             when 2      => Decoded (CV_Map_DER),
             when 3      => Decoded (CV_AB_DER),
             when others => Decoded (CV_Root_DER));

      overriding function Is_Trust_Anchor
        (Source : Converging; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Bytes (Item)
          = X509C.Subject_Bytes (Decoded (CV_Root_DER)));

      At_Time : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 9, Day => 1,
         Hour => 12, Minute => 0, Second => 0);
   begin
      --  Coming in: 1.2.3.4 twice in one extension.
      declare
         Doubled : constant PP.Policy_Set :=
           PP.Policies_Of (Decoded (Dup_Policy_DER));
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok,
                "the certificate itself decodes -- the duplicate is a policy "
                & "question, not a DER one");
         Check (Doubled.Present,
                "and the extension is there to be judged");
         Check (not Doubled.Well_Formed,
                "a policy asserted twice makes the set unusable rather than "
                & "being folded down to one");
      end;

      --  Going out: two mappings, one destination, reported once.
      declare
         Verdict : constant XV.Validation_Result :=
           XV.Validate_Path (Converging'(null record), At_Time);
      begin
         Check (Verdict.Valid,
                "converging mappings are ordinary and the path holds, got "
                & XV.Failure_Image (Verdict.Failure));
         Check (Verdict.Policies.Count = 1,
                "the policy both mappings arrive at is reported once, got"
                & Natural'Image (Verdict.Policies.Count));
         Check (not Verdict.Policies.Exhausted,
                "and nothing about this reached a bound");
      end;
   end Check_Policy_Set_Is_A_Set;

   --  SkipCerts, read by hand and so read wrongly.
   --
   --  Both policyConstraints fields are context-tagged INTEGERs carrying an
   --  INTEGER's content without an INTEGER's tag, so the shared reader --
   --  which rejects a negative value, insists on the minimal form, and
   --  guards its own accumulation -- could not be called and the bytes were
   --  folded by hand instead. The hand-written loop did none of the three.
   --  A four-octet field reaches 4294967295 and Natural stops at
   --  2147483647, so a certificate could raise CONSTRAINT_ERROR out of a
   --  parser whose whole contract is that it does not: anyone can put four
   --  octets in an extension.
   --
   --  If any of this crashes rather than fails, the suite dies here, which
   --  is the outcome being guarded against.
   procedure Check_Policy_Constraint_Skipcerts is
      package X509C renames CryptoLib.X509.Certificates;
      package PP renames CryptoLib.X509.Policies;

      Skip_Negative_DER : constant String :=
        "3082016d30820114a003020102021411e4e06fd4d42c37f49055a01d0252baf2727c69300a06082a8648ce3d04" &
        "030230133111300f06035504030c084f766572666c6f77301e170d3236303732393038353135305a170d333431" &
        "3031353038353135305a30133111300f06035504030c084f766572666c6f773059301306072a8648ce3d020106" &
        "082a8648ce3d03010703420004616e1c07a40b382e5a6b6cbd16ccb32d1035c52f6c7cec204e75d6623d97aec4" &
        "f0d33d2af1e46da7b892fcf24489dab8f038c39218fba2ad11e06d3a9c0e6815a3463044300f0603551d130101" &
        "ff040530030101ff30120603551d240101ff04083006800480000000301d0603551d0e041604144d81fe58bc05" &
        "ce60d8225766eeb6c37877cfefc5300a06082a8648ce3d0403020347003044022002773f3c71a3b6a61f010cfc" &
        "f3fe352a2064f2d07e90f00e4b61a8e62105067d022060132cf2b1249bf79fcefdcac6f91f36e9269160446f6b" &
        "fafe780d559b5b4c4a";

      Skip_Huge_DER : constant String :=
        "3082016030820107a00302010202146c79d5de8ad1b36736a50ecd6ebead7486953767300a06082a8648ce3d04" &
        "0302300c310a300806035504030c0154301e170d3236303732393038353334345a170d33343130313530383533" &
        "34345a300c310a300806035504030c01543059301306072a8648ce3d020106082a8648ce3d0301070342000461" &
        "6e1c07a40b382e5a6b6cbd16ccb32d1035c52f6c7cec204e75d6623d97aec4f0d33d2af1e46da7b892fcf24489" &
        "dab8f038c39218fba2ad11e06d3a9c0e6815a3473045300f0603551d130101ff040530030101ff30130603551d" &
        "240101ff04093007800500ffffffff301d0603551d0e041604144d81fe58bc05ce60d8225766eeb6c37877cfef" &
        "c5300a06082a8648ce3d0403020347003044022014020108045a4a5523786cdde89c7b1e1abd491b38afc4b068" &
        "d7c7c0b5f9a61102204c8b942529e8a08dcb928717847c4fa6cd06f984798acfcb7abe1a33f54b2362";

      Skip_Non_Minimal_DER : constant String :=
        "3082015d30820104a00302010202141e0f9c28b63b2fb1d3312894e0320d449078be36300a06082a8648ce3d04" &
        "0302300c310a300806035504030c0154301e170d3236303732393038353430315a170d33343130313530383534" &
        "30315a300c310a300806035504030c01543059301306072a8648ce3d020106082a8648ce3d0301070342000461" &
        "6e1c07a40b382e5a6b6cbd16ccb32d1035c52f6c7cec204e75d6623d97aec4f0d33d2af1e46da7b892fcf24489" &
        "dab8f038c39218fba2ad11e06d3a9c0e6815a3443042300f0603551d130101ff040530030101ff30100603551d" &
        "240101ff0406300480020001301d0603551d0e041604144d81fe58bc05ce60d8225766eeb6c37877cfefc5300a" &
        "06082a8648ce3d040302034700304402207b9aea4da0777599d00a09fd972498aa6d4da5759ab3e4c428f0af00" &
        "a88250850220574018d1249aae8989915afb20ac01b0b3c384832dc0a4078f6f85327e67fc24";

      Skip_Plain_DER : constant String :=
        "3082015d30820103a0030201020214536596ec8bbf720a5e3a2db18d3ada585bfd7a75300a06082a8648ce3d04" &
        "0302300c310a300806035504030c0154301e170d3236303732393038353430315a170d33343130313530383534" &
        "30315a300c310a300806035504030c01543059301306072a8648ce3d020106082a8648ce3d0301070342000461" &
        "6e1c07a40b382e5a6b6cbd16ccb32d1035c52f6c7cec204e75d6623d97aec4f0d33d2af1e46da7b892fcf24489" &
        "dab8f038c39218fba2ad11e06d3a9c0e6815a3433041300f0603551d130101ff040530030101ff300f0603551d" &
        "240101ff04053003800105301d0603551d0e041604144d81fe58bc05ce60d8225766eeb6c37877cfefc5300a06" &
        "082a8648ce3d0403020348003045022100d428d89fdcd24eb41b89d438547fafcacdd4bceb5be1d41603fa25b7" &
        "3dcb1f850220205e3891d01c91ba2d35d5c82662fb4aa2d9b061c29677dc1cc2a42daad4170a";

      Status : CryptoLib.ASN1.Errors.Decode_Status;

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

      function Constraints (Hex : String) return PP.Policy_Constraints
      is (PP.Constraints_Of
            (X509C.Decode_DER
               (From_Hex (Hex), CryptoLib.ASN1.Default_Limits, Status)));
   begin
      --  0x80000000: one past what Natural holds, and with the top bit set
      --  it is a negative INTEGER, which SkipCerts (0..MAX) does not allow.
      --  Malformed, not merely large.
      declare
         Negative : constant PP.Policy_Constraints :=
           Constraints (Skip_Negative_DER);
      begin
         Check (Negative.Present, "the extension is there to be judged");
         Check (not Negative.Well_Formed,
                "a negative SkipCerts is refused rather than folded into a "
                & "positive one");
      end;

      --  4294967295, written the long way and genuinely positive. A CA
      --  meaning "never" this way is not writing a bad certificate, so it
      --  is clamped rather than refused -- any value at or past the length
      --  of the path counts down identically.
      declare
         Huge : constant PP.Policy_Constraints := Constraints (Skip_Huge_DER);
      begin
         Check (Huge.Well_Formed,
                "a large but valid SkipCerts is usable");
         Check (Huge.Has_Require_Explicit
                and then Huge.Require_Explicit = Natural'Last,
                "clamped to what Natural holds, got"
                & Natural'Image (Huge.Require_Explicit));
      end;

      --  A leading zero octet that clears no sign bit is not the minimal
      --  form, and DER has exactly one encoding per value.
      declare
         Padded : constant PP.Policy_Constraints :=
           Constraints (Skip_Non_Minimal_DER);
      begin
         Check (not Padded.Well_Formed,
                "a non-minimal SkipCerts is refused, as it would be with "
                & "its own INTEGER tag on it");
      end;

      --  And the ordinary case still reads as itself.
      declare
         Plain : constant PP.Policy_Constraints := Constraints (Skip_Plain_DER);
      begin
         Check (Plain.Well_Formed
                and then Plain.Has_Require_Explicit
                and then Plain.Require_Explicit = 5,
                "an ordinary SkipCerts is unaffected, got"
                & Natural'Image (Plain.Require_Explicit));
      end;
   end Check_Policy_Constraint_Skipcerts;

   --  A depth restriction on a subtree, silently skipped.
   --
   --  GeneralSubtree is SEQUENCE { base, minimum [0] DEFAULT 0,
   --  maximum [1] OPTIONAL }. The base was read and whatever followed it
   --  was left where it lay, so a minimum or a maximum went unnoticed
   --  rather than unapplied. On a permitted subtree that is the wrong
   --  direction: the minimum narrows what the CA allowed, and skipping it
   --  permits names the CA did not.
   --
   --  RFC 5280 4.2.1.10 says the minimum MUST be zero and the maximum MUST
   --  be absent, and DER omits a DEFAULT that holds, so no conforming
   --  certificate encodes either and refusing them turns nothing away that
   --  ought to be let through. OpenSSL does not even print them.
   procedure Check_Name_Constraint_Depth_Fields is
      package X509C renames CryptoLib.X509.Certificates;
      package XV renames CryptoLib.X509.Validation;
      use type XV.Validation_Failure;

      NC_Min_CA_DER : constant String :=
        "308201893082012ea00302010202145f13d4c64ff6773e61fd40ae198e01e7e79aa283300a06082a8648ce3d04" &
        "03023011310f300d06035504030c064e43204d696e301e170d3236303732393039303735325a170d3334313031" &
        "353039303735325a3011310f300d06035504030c064e43204d696e3059301306072a8648ce3d020106082a8648" &
        "ce3d030107034200043eaa1ca1862169e02c4e8f933225cd1a8b335ab26ca7c7c03face181777c71684a6f5ade" &
        "c3181b5ea11e44c1f3840eeddc2152c42bae3ec43f8d01f0928c6296a3643062300f0603551d130101ff040530" &
        "030101ff300e0603551d0f0101ff04040302020430200603551d1e0101ff04163014a0123010820b6578616d70" &
        "6c652e636f6d800101301d0603551d0e041604148e2ea5a21f944a8341efa6f0df04aa6d96c5a2a0300a06082a" &
        "8648ce3d04030203490030460221009c344933da2f2b9a10badddc5ae256d4c30a0a479913597e29a770d09797" &
        "192f022100c97d516a75214f271e475ca9a92bc4ed787adef504d1343bfee918c615d11671";

      NC_Min_Leaf_DER : constant String :=
        "3082019b30820141a0030201020214091885003ffa3413cb5ca0510c88e1d709e70a0e300a06082a8648ce3d04" &
        "03023011310f300d06035504030c064e43204d696e301e170d3236303732393039303832395a170d3332303131" &
        "393039303832395a301b3119301706035504030c10686f73742e6578616d706c652e636f6d3059301306072a86" &
        "48ce3d020106082a8648ce3d0301070342000416bfbd49d4557c57e7b21756b7791b113e63cf027787722edd3f" &
        "f9c41dc9bc5b13e577d727bb59e03acafb1b2f1e4d1eced69166effc36e9ddee3648ea991df2a36d306b300c06" &
        "03551d130101ff04023000301b0603551d11041430128210686f73742e6578616d706c652e636f6d301d060355" &
        "1d0e04160414971536a1ddd56b38ba2176034ad59a060ebf0cab301f0603551d230418301680148e2ea5a21f94" &
        "4a8341efa6f0df04aa6d96c5a2a0300a06082a8648ce3d0403020348003045022069f3544e54c82ab2b53729d4" &
        "9ea0260166fb2f2a582e72e61cb82d4b9dabca560221009690069ac763d69c2791508640b9ab51c47c6bdb8d56" &
        "bf3e5705e4182cdb8894";

      NC_Plain_CA_DER : constant String :=
        "308201893082012fa0030201020214316593b98b00241c04be3e68624fc73da069af77300a06082a8648ce3d04" &
        "030230133111300f06035504030c084e4320506c61696e301e170d3236303732393039303735325a170d333431" &
        "3031353039303735325a30133111300f06035504030c084e4320506c61696e3059301306072a8648ce3d020106" &
        "082a8648ce3d030107034200043eaa1ca1862169e02c4e8f933225cd1a8b335ab26ca7c7c03face181777c7168" &
        "4a6f5adec3181b5ea11e44c1f3840eeddc2152c42bae3ec43f8d01f0928c6296a361305f300f0603551d130101" &
        "ff040530030101ff300e0603551d0f0101ff040403020204301d0603551d1e0101ff04133011a00f300d820b65" &
        "78616d706c652e636f6d301d0603551d0e041604148e2ea5a21f944a8341efa6f0df04aa6d96c5a2a0300a0608" &
        "2a8648ce3d040302034800304502205eda2f9745df5b9b43b8ec3f7854ac014b820d4468a4a0da9e1b16c7f2fa" &
        "2a7d0221008d4ca3d920a0d3452df05f2bb584c736511bf2d334e206c772268099ccac3202";

      NC_Plain_Leaf_DER : constant String :=
        "3082019d30820143a003020102021416dea706705425e9261be59927526fbd90610c20300a06082a8648ce3d04" &
        "030230133111300f06035504030c084e4320506c61696e301e170d3236303732393039303832395a170d333230" &
        "3131393039303832395a301b3119301706035504030c10686f73742e6578616d706c652e636f6d305930130607" &
        "2a8648ce3d020106082a8648ce3d0301070342000416bfbd49d4557c57e7b21756b7791b113e63cf027787722e" &
        "dd3ff9c41dc9bc5b13e577d727bb59e03acafb1b2f1e4d1eced69166effc36e9ddee3648ea991df2a36d306b30" &
        "0c0603551d130101ff04023000301b0603551d11041430128210686f73742e6578616d706c652e636f6d301d06" &
        "03551d0e04160414971536a1ddd56b38ba2176034ad59a060ebf0cab301f0603551d230418301680148e2ea5a2" &
        "1f944a8341efa6f0df04aa6d96c5a2a0300a06082a8648ce3d0403020348003045022100b572247d37ddd569e7" &
        "0a4157fa7920ac79e78cdaa6d86b3f11b3f7246ed3bb5602207674615be7de3e53edfcef686286de5190d25b0f" &
        "b1e41b5895455233741311f1";

      Status : CryptoLib.ASN1.Errors.Decode_Status;

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

      function Decoded (Hex : String) return X509C.Certificate
      is (X509C.Decode_DER
            (From_Hex (Hex), CryptoLib.ASN1.Default_Limits, Status));

      --  permittedSubtrees DNS:example.com, carrying minimum 1.
      type With_Minimum is limited new XV.Path_Source with null record;

      overriding function Length (Source : With_Minimum) return Positive is (2);

      overriding function Certificate_At
        (Source : With_Minimum; Index : Positive) return X509C.Certificate
      is (if Index = 1 then Decoded (NC_Min_Leaf_DER)
          else Decoded (NC_Min_CA_DER));

      overriding function Is_Trust_Anchor
        (Source : With_Minimum; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Bytes (Item)
          = X509C.Subject_Bytes (Decoded (NC_Min_CA_DER)));

      --  The same constraint written the way the RFC asks for.
      type Without_Minimum is limited new XV.Path_Source with null record;

      overriding function Length
        (Source : Without_Minimum) return Positive is (2);

      overriding function Certificate_At
        (Source : Without_Minimum; Index : Positive) return X509C.Certificate
      is (if Index = 1 then Decoded (NC_Plain_Leaf_DER)
          else Decoded (NC_Plain_CA_DER));

      overriding function Is_Trust_Anchor
        (Source : Without_Minimum; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Bytes (Item)
          = X509C.Subject_Bytes (Decoded (NC_Plain_CA_DER)));

      At_Time : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 9, Day => 1,
         Hour => 12, Minute => 0, Second => 0);
   begin
      --  Both leaves are host.example.com, inside the subtree either way,
      --  so the only thing separating these two verdicts is the minimum.
      declare
         Verdict : constant XV.Validation_Result :=
           XV.Validate_Path (With_Minimum'(null record), At_Time);
      begin
         Check (not Verdict.Valid,
                "a subtree carrying a depth restriction is not quietly "
                & "treated as one without");
         Check (Verdict.Failure = XV.Unsupported_Name_Constraint,
                "and says the constraint went unapplied rather than blaming "
                & "the name, got " & XV.Failure_Image (Verdict.Failure));
      end;

      declare
         Verdict : constant XV.Validation_Result :=
           XV.Validate_Path (Without_Minimum'(null record), At_Time);
      begin
         Check (Verdict.Valid,
                "while the same subtree without one still admits the same "
                & "name, got " & XV.Failure_Image (Verdict.Failure));
      end;
   end Check_Name_Constraint_Depth_Fields;

   --  A key too small to be worth checking the signature of.
   --
   --  RSA is the one key algorithm here whose strength does not come with
   --  the algorithm: the curves are named and Ed25519 is one size, but a
   --  certificate may carry any modulus at all and nothing refused a small
   --  one. The signature over a 512-bit modulus verifies perfectly well --
   --  that is the whole problem, since a modulus that can be factored is
   --  one anyone can sign with.
   --
   --  Applied to every certificate rather than only the leaf: a chain is no
   --  stronger than the weakest key that signed a link of it. OpenSSL
   --  refuses this chain at its default security level (error 66, "EE
   --  certificate key too weak"); before this it was accepted here.
   procedure Check_Weak_RSA_Key is
      package X509C renames CryptoLib.X509.Certificates;
      package XV renames CryptoLib.X509.Validation;
      package XS renames CryptoLib.X509.Signatures;
      use type XV.Validation_Failure;

      Weak_Root_DER : constant String :=
        "3082016e30820118a0030201020214255e0cbefa30a554023c49086e7bd8d50d30e3cc300d06092a864886f70d" &
        "01010b050030143112301006035504030c095765616b20526f6f74301e170d3236303732393039323034345a17" &
        "0d3334313031353039323034345a30143112301006035504030c095765616b20526f6f74305c300d06092a8648" &
        "86f70d0101010500034b00304802410098bfdd9b654f2ca70ec248d2202d67d571ff02c74cd0f05466252ea9dd" &
        "66b98c0e424d4eee92c1e87fa98440180f6583f844b383b9422e761e8c3139fe39bcbb0203010001a342304030" &
        "0f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020204301d0603551d0e04160414a8ed" &
        "953af6ad5f47cdf5d572baa02ca424dd243e300d06092a864886f70d01010b05000341001213acb161bdaf2606" &
        "88dabe334e04f60e27b081630a00da544ec778c8f78239c3a12a2681848adcc43144c0aba74100ead0b283469c" &
        "f39c594e7d6757ecbfb7";

      Weak_Leaf_DER : constant String :=
        "3082019830820142a00302010202145b733aeb636206a4199b89aae41add3c72156d05300d06092a864886f70d" &
        "01010b050030143112301006035504030c095765616b20526f6f74301e170d3236303732393039323034345a17" &
        "0d3332303131393039323034345a30173115301306035504030c0c7765616b2e6578616d706c65305c300d0609" &
        "2a864886f70d0101010500034b003048024100cc65b5c45a320be757f2e41166c98c631ef14e24f5508e788b53" &
        "20989381716396a8101d70d4c5d284a2c0b18d0539dc8aac39212afa023eb814521a9646a3610203010001a369" &
        "3067300c0603551d130101ff0402300030170603551d110410300e820c7765616b2e6578616d706c65301d0603" &
        "551d0e04160414fb2e08b1e99d078247bf45072df3e6274f518812301f0603551d23041830168014a8ed953af6" &
        "ad5f47cdf5d572baa02ca424dd243e300d06092a864886f70d01010b05000341005b8b8b4b5b77184b1fc69c48" &
        "8b0e776ac7f4cb2853f862998b2d07389d6512c6f7de2a64e2617ec06d2efe9f8ee5edf626d4acc66239855058" &
        "5dd2fb0b684ec2";

      Status : CryptoLib.ASN1.Errors.Decode_Status;

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

      function Decoded (Hex : String) return X509C.Certificate
      is (X509C.Decode_DER
            (From_Hex (Hex), CryptoLib.ASN1.Default_Limits, Status));

      type Weak is limited new XV.Path_Source with null record;

      overriding function Length (Source : Weak) return Positive is (2);

      overriding function Certificate_At
        (Source : Weak; Index : Positive) return X509C.Certificate
      is (if Index = 1 then Decoded (Weak_Leaf_DER)
          else Decoded (Weak_Root_DER));

      overriding function Is_Trust_Anchor
        (Source : Weak; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Bytes (Item)
          = X509C.Subject_Bytes (Decoded (Weak_Root_DER)));

      At_Time : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 9, Day => 1,
         Hour => 12, Minute => 0, Second => 0);
   begin
      --  The size is read off the modulus, not guessed from the encoding's
      --  length, so a leading zero holding the INTEGER positive does not
      --  read as eight more bits of key.
      Check (XS.RSA_Modulus_Bits (X509C.Public_Key (Decoded (Weak_Root_DER)))
             = 512,
             "the modulus is measured in significant bits, got"
             & Natural'Image
                 (XS.RSA_Modulus_Bits
                    (X509C.Public_Key (Decoded (Weak_Root_DER)))));
      Check (XS.RSA_Modulus_Bits (From_Hex ("3003020101")) = 0,
             "and something that is not an RSA key measures zero rather "
             & "than passing for a large one");

      --  Refused by default.
      declare
         Verdict : constant XV.Validation_Result :=
           XV.Validate_Path (Weak'(null record), At_Time);
      begin
         Check (not Verdict.Valid,
                "a 512-bit chain is refused out of the box");
         Check (Verdict.Failure = XV.Weak_Key,
                "and says the key was the problem rather than the "
                & "signature, got " & XV.Failure_Image (Verdict.Failure));
      end;

      --  And the floor is the only thing refusing it: the signatures
      --  themselves are perfectly good, which is what makes a weak key
      --  worth refusing in the first place.
      declare
         Verdict : constant XV.Validation_Result :=
           XV.Validate_Path
             (Weak'(null record), At_Time,
              (XV.Default_Policy with delta Minimum_RSA_Bits => 0));
      begin
         Check (Verdict.Valid,
                "with the floor lifted the same chain verifies, got "
                & XV.Failure_Image (Verdict.Failure));
      end;
   end Check_Weak_RSA_Key;

   --  One comparison for a serial number, shared by both revocation paths.
   --
   --  A serial reaches a revocation check from two directions -- the
   --  certificate, and whatever a CA or a responder wrote about it -- and
   --  those are written by different implementations. The CRL path compared
   --  them as numbers and the OCSP path compared the octets, so the two
   --  could disagree about whether an answer was even about this
   --  certificate.
   --
   --  Leniency is the safe direction here, which is why the numeric reading
   --  is the one kept. A padded encoding read as a different certificate
   --  means an answer about this one is not found, and not finding a
   --  revocation looks exactly like not being revoked -- silently, and
   --  pointing the wrong way. Reading two different serials as the same
   --  number is not something this can do.
   procedure Check_Serial_Comparison is
      function S (Data : Ada.Streams.Stream_Element_Array)
        return Ada.Streams.Stream_Element_Array is (Data);

      Nothing : constant Ada.Streams.Stream_Element_Array (1 .. 0) :=
        [others => 0];
   begin
      Check (CryptoLib.X509.Same_Serial (S ([16#01#]), S ([16#00#, 16#01#])),
             "a padded serial is the same number as the bare one");
      Check (CryptoLib.X509.Same_Serial
               (S ([16#00#, 16#00#, 16#FF#]), S ([16#FF#])),
             "however many zeros it was padded with");
      Check (CryptoLib.X509.Same_Serial (S ([16#12#, 16#34#]),
                                         S ([16#12#, 16#34#])),
             "and an unpadded pair still matches itself");

      Check (not CryptoLib.X509.Same_Serial (S ([16#01#]), S ([16#02#])),
             "two different serials do not match");
      Check (not CryptoLib.X509.Same_Serial
                   (S ([16#01#]), S ([16#01#, 16#01#])),
             "nor do two whose values differ by a trailing octet");

      --  RFC 5280 requires a positive serial, so zero is not one. Matching
      --  it against another zero would make every unparsed serial agree
      --  with every other.
      Check (not CryptoLib.X509.Same_Serial (S ([16#00#]), S ([16#00#])),
             "a zero serial matches nothing, itself included");
      Check (not CryptoLib.X509.Same_Serial (Nothing, S ([16#01#])),
             "and an empty one is not a number at all");
   end Check_Serial_Comparison;

   --  A constraint that could never have reached this certificate.
   --
   --  A subtree naming a form this cannot apply -- an EDI party, an
   --  x400Address, a registered identifier -- used to fail the chain on
   --  sight. But a subtree restricts only names of its own type, which this
   --  file says a few lines further down and then did not act on: a
   --  registered-identifier subtree cannot reach a DNS name, so a
   --  certificate carrying nothing but DNS names is inside every constraint
   --  that could apply to it. Refusing it turned away chains OpenSSL admits
   --  and RFC 5280 does not constrain.
   --
   --  What decides it is whether the certificate carries a name of a form
   --  this cannot model. If it does, the constraint might have caught it
   --  and cannot be checked, and the chain fails as before.
   procedure Check_Unapplicable_Name_Constraint is
      package X509C renames CryptoLib.X509.Certificates;
      package XV renames CryptoLib.X509.Validation;
      use type XV.Validation_Failure;

      RID_CA_DER : constant String :=
        "3082018d30820132a00302010202144ad6c368bc3a5310b702d3c8a525283f6d059134300a06082a8648ce3d04" &
        "03023011310f300d06035504030c06524944204341301e170d3236303732393039333434305a170d3334313031" &
        "353039333434305a3011310f300d06035504030c065249442043413059301306072a8648ce3d020106082a8648" &
        "ce3d03010703420004d4d11e1f569d040dad1737de150c59b319d19959ecfe91884a236539153a332fea1a708e" &
        "04293571b861113274e141a3bdaa088bf36615221b4c4178f45afa36a3683066300f0603551d130101ff040530" &
        "030101ff300e0603551d0f0101ff04040302020430240603551d1e0101ff041a3018a016300d820b6578616d70" &
        "6c652e636f6d300588032a0304301d0603551d0e041604144c78c3d8a1d5ed92202b440ab68795c367ba2c3130" &
        "0a06082a8648ce3d0403020349003046022100d14fc517f5e944e5592b5b77f810baeb5c5d6c2e908ff57224c1" &
        "0a570d960ef8022100d08a46d0afb2060de55b3cffa96302c0dd272b21464c9a3a78194f470c7ce258";

      RID_Plain_Leaf_DER : constant String :=
        "3082019b30820141a00302010202140bd161fb93e5d7aee9448b72a39415ded759cf28300a06082a8648ce3d04" &
        "03023011310f300d06035504030c06524944204341301e170d3236303732393039333435315a170d3332303131" &
        "393039333435315a301b3119301706035504030c10686f73742e6578616d706c652e636f6d3059301306072a86" &
        "48ce3d020106082a8648ce3d03010703420004955478fa987d715bca1af1fff19facffde33e741ab3fbf4badc7" &
        "e13e5441d8d082dd475cb1d18be0af76ec111c9745e45d1341612e41ff93709f4903aea8bd52a36d306b300c06" &
        "03551d130101ff04023000301b0603551d11041430128210686f73742e6578616d706c652e636f6d301d060355" &
        "1d0e041604144fd1c61613a7c100678942333f5a505a9c261928301f0603551d230418301680144c78c3d8a1d5" &
        "ed92202b440ab68795c367ba2c31300a06082a8648ce3d0403020348003045022100dcbbfeb033fde51e705d0a" &
        "79422c9331e630332f70ec67607445c4e1388e3e880220287c1ddb2d486c20ba96a44c307911ca9d15f99ffb04" &
        "3d19fb7e2723335c662e";

      RID_Named_Leaf_DER : constant String :=
        "308201a030820146a00302010202140bd161fb93e5d7aee9448b72a39415ded759cf2a300a06082a8648ce3d04" &
        "03023011310f300d06035504030c06524944204341301e170d3236303732393039333634355a170d3332303131" &
        "393039333634355a301b3119301706035504030c10686f73742e6578616d706c652e636f6d3059301306072a86" &
        "48ce3d020106082a8648ce3d03010703420004955478fa987d715bca1af1fff19facffde33e741ab3fbf4badc7" &
        "e13e5441d8d082dd475cb1d18be0af76ec111c9745e45d1341612e41ff93709f4903aea8bd52a3723070300c06" &
        "03551d130101ff0402300030200603551d11041930178210686f73742e6578616d706c652e636f6d88032a0304" &
        "301d0603551d0e041604144fd1c61613a7c100678942333f5a505a9c261928301f0603551d230418301680144c" &
        "78c3d8a1d5ed92202b440ab68795c367ba2c31300a06082a8648ce3d0403020348003045022100c1e24fe2ba46" &
        "9652f4abe5a01c34f342fba967eefc61e7f31c5741851114dc9502205caef3c210d2329f15f2007314190a25e9" &
        "2ba61ec0f31eebcee7d5f1fb9b50c9";

      RID_Outside_Leaf_DER : constant String :=
        "308201a230820147a00302010202140bd161fb93e5d7aee9448b72a39415ded759cf29300a06082a8648ce3d04" &
        "03023011310f300d06035504030c06524944204341301e170d3236303732393039333632375a170d3332303131" &
        "393039333632375a301e311c301a06035504030c13686f73742e656c736577686572652e746573743059301306" &
        "072a8648ce3d020106082a8648ce3d03010703420004955478fa987d715bca1af1fff19facffde33e741ab3fbf" &
        "4badc7e13e5441d8d082dd475cb1d18be0af76ec111c9745e45d1341612e41ff93709f4903aea8bd52a370306e" &
        "300c0603551d130101ff04023000301e0603551d11041730158213686f73742e656c736577686572652e746573" &
        "74301d0603551d0e041604144fd1c61613a7c100678942333f5a505a9c261928301f0603551d23041830168014" &
        "4c78c3d8a1d5ed92202b440ab68795c367ba2c31300a06082a8648ce3d0403020349003046022100b5401c2edd" &
        "57aab2e8f4f52948e310b9355a95e98f7b2489d715d92ccbac4fca022100ba190ac8910c331027ff3d0264350a" &
        "cb7c7ebd6b00df9c28b1a256662dd63a2e";

      Status : CryptoLib.ASN1.Errors.Decode_Status;

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

      function Decoded (Hex : String) return X509C.Certificate
      is (X509C.Decode_DER
            (From_Hex (Hex), CryptoLib.ASN1.Default_Limits, Status));

      --  One CA throughout: permitted DNS:example.com and a registered
      --  identifier this cannot apply. Only the leaf changes.
      type Under_CA (Leaf : Natural) is limited new XV.Path_Source
        with null record;

      overriding function Length (Source : Under_CA) return Positive is (2);

      overriding function Certificate_At
        (Source : Under_CA; Index : Positive) return X509C.Certificate
      is (if Index /= 1 then Decoded (RID_CA_DER)
          elsif Source.Leaf = 1 then Decoded (RID_Plain_Leaf_DER)
          elsif Source.Leaf = 2 then Decoded (RID_Named_Leaf_DER)
          else Decoded (RID_Outside_Leaf_DER));

      overriding function Is_Trust_Anchor
        (Source : Under_CA; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Bytes (Item) = X509C.Subject_Bytes (Decoded (RID_CA_DER)));

      At_Time : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 9, Day => 1,
         Hour => 12, Minute => 0, Second => 0);
   begin
      --  Only DNS names, all inside the permitted subtree. The registered
      --  identifier subtree has nothing to say about it.
      declare
         Verdict : constant XV.Validation_Result :=
           XV.Validate_Path (Under_CA'(Leaf => 1), At_Time);
      begin
         Check (Verdict.Valid,
                "a subtree that cannot reach any name this certificate "
                & "carries does not refuse it, got "
                & XV.Failure_Image (Verdict.Failure));
      end;

      --  Now the certificate carries a registered identifier of its own, so
      --  the constraint is one that might have caught it.
      declare
         Verdict : constant XV.Validation_Result :=
           XV.Validate_Path (Under_CA'(Leaf => 2), At_Time);
      begin
         Check (not Verdict.Valid,
                "but once the certificate carries a name of that form the "
                & "unapplied constraint fails the chain");
         Check (Verdict.Failure = XV.Unsupported_Name_Constraint,
                "saying it could not be applied rather than that a name was "
                & "outside it, got " & XV.Failure_Image (Verdict.Failure));
      end;

      --  And the constraint this can apply still applies.
      declare
         Verdict : constant XV.Validation_Result :=
           XV.Validate_Path (Under_CA'(Leaf => 3), At_Time);
      begin
         Check (not Verdict.Valid,
                "a name outside the permitted subtree is still caught");
         Check (Verdict.Failure = XV.Name_Constraint_Violation,
                "and named as the violation it is, got "
                & XV.Failure_Image (Verdict.Failure));
      end;
   end Check_Unapplicable_Name_Constraint;

   --  Ed448 (RFC 8032 PureEdDSA over edwards448).
   --
   --  The vectors were produced by an implementation written from the spec
   --  and checked against pyca/OpenSSL before any Ada existed, which is the
   --  order that catches a transcription error rather than enshrining it.
   --  Ed448 signing is deterministic, so agreement is byte-for-byte and not
   --  merely "both verify".
   --
   --  The curve constants were derived rather than copied. The base point
   --  was recovered from a real key as s^-1 * A, which only needs p and d,
   --  and then confirmed by L * B landing on the neutral element -- so a
   --  mistyped digit in any of p, d, L or B would have shown up before a
   --  line of this was ported. That check is worth naming because a wrong
   --  curve order and a mistranscribed point addition have each cost real
   --  time in this crate before.
   procedure Check_Ed448 is
      package E4 renames CryptoLib.Ed448;

      Seed_1 : constant String :=
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" &
        "00000000000000000000000000";
      Pub_1 : constant String :=
        "5b3afe03878a49b28232d4f1a442aebde109f807acef7dfd9a7f65b962fe52d6547312cacecff04337508f9d" &
        "2529a8f1669169b21c32c48000";
      Msg_1 : constant String := "";
      Sig_1 : constant String :=
        "ce6ab231690d322c4b4f5249765090bcea87613b7e98c8e22ff868dae0a6141e8a8e59de31db6672f891129f" &
        "483d8fae3e12e015e36d283580a529127d375a3788843126e3e8d666a2e79ea10c7ae910776e8be9f1c1241c" &
        "0a70588cffc9610272fc0488c5c877b97c9e51b0ed0d73391200";
      Seed_2 : constant String :=
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b" &
        "2c2d2e2f303132333435363738";
      Pub_2 : constant String :=
        "18d0a70e42a742dfb561279893385061d7b4dad8f6feed4791eaab66b2f4a4f02fc09462a8bfb1842d0bac60" &
        "e8a1b3e55ba2407f33226f3800";
      Msg_2 : constant String :=
        "616263";
      Sig_2 : constant String :=
        "824d0bd89164ff94dc74449cdf96347d22291de67166901ddc348505e37e7185b59580d906b70a9a2dd7c9b7" &
        "a96c3539faa4d357903ca1a40023c3683b761d292a5854a09f6dd6466f1c1b881e1a621dc04ce89cc156b8fa" &
        "c7d197f9cb66fbc85d8d8a049b71df4e16e12e9171e66af02b00";
      Seed_3 : constant String :=
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" &
        "ffffffffffffffffffffffffff";
      Pub_3 : constant String :=
        "b9a5f530a156f166413bf82aeb0137c42376011583fe53f12ed1530300248e808369d2d0672fd7a25cfb5c0f" &
        "e1220b508248bb226e7e26dc80";
      Msg_3 : constant String :=
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b" &
        "2c2d2e2f303132333435363738393a3b3c3d3e3f";
      Sig_3 : constant String :=
        "97e2cb5f40b4dd1641c58ae8a1a83ad19b3a5db47412cd0d87cf2bfadfb869bb5b12e33198101b745635d707" &
        "beef7e707ecd1a4fcbf08ab680fb352ab005c8bbf1968d2ca66f0a53b4bafd776e4e40725281f6c6a3fc125d" &
        "40185bfdcc473cada899c032ed46749a4b18a728550c82453500";

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

      function Hex (Data : Ada.Streams.Stream_Element_Array) return String is
         Symbols : constant String := "0123456789abcdef";
         Result  : String (1 .. 2 * Natural (Data'Length));
         At_Byte : Natural := 0;
      begin
         for B of Data loop
            At_Byte := At_Byte + 1;
            Result (2 * At_Byte - 1) := Symbols (Natural (B) / 16 + 1);
            Result (2 * At_Byte) := Symbols (Natural (B) mod 16 + 1);
         end loop;
         return Result;
      end Hex;

      procedure One_Vector
        (Index : Positive; Seed : String; Pub : String;
         Msg : String; Sig : String)
      is
         Public_Key : Ada.Streams.Stream_Element_Array (1 .. 57);
         Signature  : Ada.Streams.Stream_Element_Array (1 .. 114);
         Status     : CryptoLib.Errors.Status;
      begin
         Status := E4.Public_Key_From_Seed (From_Hex (Seed), Public_Key);
         Check (Status = CryptoLib.Errors.Ok and then Hex (Public_Key) = Pub,
                "Ed448 vector" & Positive'Image (Index)
                & ": the public key derived from the seed");

         Status :=
           E4.Sign (From_Hex (Seed), Public_Key, From_Hex (Msg), Signature);
         Check (Status = CryptoLib.Errors.Ok and then Hex (Signature) = Sig,
                "Ed448 vector" & Positive'Image (Index)
                & ": the signature, byte for byte");

         Check (E4.Verify (From_Hex (Pub), From_Hex (Sig), From_Hex (Msg))
                = CryptoLib.Errors.Ok,
                "Ed448 vector" & Positive'Image (Index)
                & ": and it verifies");
      end One_Vector;
   begin
      One_Vector (1, Seed_1, Pub_1, Msg_1, Sig_1);
      One_Vector (2, Seed_2, Pub_2, Msg_2, Sig_2);
      One_Vector (3, Seed_3, Pub_3, Msg_3, Sig_3);

      --  A signature is for one message and one key.
      declare
         Signature : Ada.Streams.Stream_Element_Array (1 .. 114) :=
           From_Hex (Sig_2);
      begin
         Check (E4.Verify (From_Hex (Pub_2), Signature, From_Hex (Msg_3))
                /= CryptoLib.Errors.Ok,
                "a signature does not carry over to another message");
         Check (E4.Verify (From_Hex (Pub_1), Signature, From_Hex (Msg_2))
                /= CryptoLib.Errors.Ok,
                "nor to another key");

         Signature (4) := Signature (4) xor 1;
         Check (E4.Verify (From_Hex (Pub_2), Signature, From_Hex (Msg_2))
                /= CryptoLib.Errors.Ok,
                "and one bit of it is enough to break it");
      end;

      --  One signature has one encoding. S is reduced mod L, so an S at or
      --  above L is a second name for a signature that already has one, and
      --  the spare bits of the final octets are not free space.
      declare
         Order_Encoded : constant String :=
           "f34458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffff"
           & "ffffffffffffffffffffffffffffffffffffffffffffff3f00";
         At_Order  : Ada.Streams.Stream_Element_Array (1 .. 114) :=
           From_Hex (Sig_2);
         Spare_Set : Ada.Streams.Stream_Element_Array (1 .. 57) :=
           From_Hex (Pub_2);
         Top_Set   : Ada.Streams.Stream_Element_Array (1 .. 114) :=
           From_Hex (Sig_2);
      begin
         At_Order (58 .. 114) := From_Hex (Order_Encoded);
         Check (E4.Verify (From_Hex (Pub_2), At_Order, From_Hex (Msg_2))
                /= CryptoLib.Errors.Ok,
                "an S equal to the group order is refused");

         Spare_Set (57) := Spare_Set (57) or 1;
         Check (E4.Verify (Spare_Set, From_Hex (Sig_2), From_Hex (Msg_2))
                /= CryptoLib.Errors.Ok,
                "so is a public key with spare bits set in its final octet");

         Top_Set (114) := 1;
         Check (E4.Verify (From_Hex (Pub_2), Top_Set, From_Hex (Msg_2))
                /= CryptoLib.Errors.Ok,
                "and an S whose top octet is not zero");
      end;

      --  Wrong lengths are refused rather than read as far as they go.
      declare
         Short_Sig : constant Ada.Streams.Stream_Element_Array (1 .. 113) :=
           [others => 0];
      begin
         Check (E4.Verify (From_Hex (Pub_2), Short_Sig, From_Hex (Msg_2))
                /= CryptoLib.Errors.Ok,
                "a signature of the wrong length is refused");
      end;
   end Check_Ed448;

   --  An Ed448 certificate, which is the point of having the primitive.
   --
   --  OpenSSL issued this chain; the signature this checks is one an
   --  independent implementation produced over bytes it chose.
   procedure Check_Ed448_Certificate is
      package X509C renames CryptoLib.X509.Certificates;
      package XV renames CryptoLib.X509.Validation;
      package XS renames CryptoLib.X509.Signatures;
      package ID renames CryptoLib.Identities;
      use type XS.Verification_Result;
      use type CryptoLib.X509.Public_Key_Algorithm;
      use type ID.Identity_Status;

      E448_Leaf_PEM : constant String :=
        "-----BEGIN CERTIFICATE-----" & ASCII.LF &
        "MIIBpDCCASSgAwIBAgIUQLczDWL7WwuZoYVM4WsLqa7MwWIwBQYDK2VxMBUxEzAR" & ASCII.LF &
        "BgNVBAMMCkVkNDQ4IFJvb3QwHhcNMjYwNzI5MDk1NDQ4WhcNMzIwMTE5MDk1NDQ4" & ASCII.LF &
        "WjAYMRYwFAYDVQQDDA1lZDQ0OC5leGFtcGxlMEMwBQYDK2VxAzoANsYQp79ULh3d" & ASCII.LF &
        "SjdMmNmFUG1+o2Q5SSCXICPq8UUqzOYBYHeJ7hNF32pZzaGPBjzs2Z+SamfvyS0A" & ASCII.LF &
        "o2owaDAMBgNVHRMBAf8EAjAAMBgGA1UdEQQRMA+CDWVkNDQ4LmV4YW1wbGUwHQYD" & ASCII.LF &
        "VR0OBBYEFNb187dyLV9qCvIGD4F3TJR0WLUqMB8GA1UdIwQYMBaAFMbdgp4UBnjX" & ASCII.LF &
        "ERu+ekkzVsgRgRsVMAUGAytlcQNzAJMzV/lMPoEHUcr1PaG6vEbABaXpt5YnsLan" & ASCII.LF &
        "6gdTjwBoGMzeoSJNgElR+VgnUzhMFksq9RbPy3KFgPsA1OPP3RxrFlAhuBi4cmPR" & ASCII.LF &
        "jsn91H3D6FErtsx6azAZ9tTrESyu0MCqMMmGyNuLdEKBFNJO+XIKAA==" & ASCII.LF &
        "-----END CERTIFICATE-----";
      E448_Key_PEM : constant String :=
        "-----BEGIN PRIVATE KEY-----" & ASCII.LF &
        "MEcCAQAwBQYDK2VxBDsEOYyTXKOV7SfQx6zlvUpFDYciMQ6W+mNHXbEDe8xPX6kz" & ASCII.LF &
        "OCUb0dKHgHnuElzHtXQCKo9TeCtrBOQFOg==" & ASCII.LF &
        "-----END PRIVATE KEY-----";
      E448_Other_Key_PEM : constant String :=
        "-----BEGIN PRIVATE KEY-----" & ASCII.LF &
        "MEcCAQAwBQYDK2VxBDsEOZEzccND4JxGmKYY52TJ9TBSiT5dO9S6x5f97ovYOgNO" & ASCII.LF &
        "INbtgil2L/8dqEoW1wfU5o8SWe9sFGpciQ==" & ASCII.LF &
        "-----END PRIVATE KEY-----";

      E448_Root_DER : constant String :=
        "308201783081f9a00302010202145772562f5003d8e4686dca2c57baa102163cd987300506032b6571301531" &
        "13301106035504030c0a456434343820526f6f74301e170d3236303732393039353434385a170d3334313031" &
        "353039353434385a30153113301106035504030c0a456434343820526f6f743043300506032b6571033a0045" &
        "d2095f56d2bea5572d69c011ed8de923301a8f561ea57ed3e13ed04bd8000dc36b78dea17a1f6e9e2d854971" &
        "4bc9fe07179d46c3f6b56180a3423040300f0603551d130101ff040530030101ff300e0603551d0f0101ff04" &
        "0403020204301d0603551d0e04160414c6dd829e140678d7111bbe7a493356c811811b15300506032b657103" &
        "7300f3c873adf2a0a171f80f20e5b47bef9bc07a1cfe0991ab570b7ddeec0628e5f8afc1857ddfce5e0945c1" &
        "e448d20f9694e9fd8c0c385c0cbb802352d13e94faa9108b4115e884137593d9b2919ce27a9325fae140a584" &
        "ac987ec46919dbc1889cde500a9af25c7bc3ef52dfb6263d6d182f00";

      E448_Leaf_DER : constant String :=
        "308201a430820124a003020102021440b7330d62fb5b0b99a1854ce16b0ba9aeccc162300506032b65713015" &
        "3113301106035504030c0a456434343820526f6f74301e170d3236303732393039353434385a170d33323031" &
        "31393039353434385a30183116301406035504030c0d65643434382e6578616d706c653043300506032b6571" &
        "033a0036c610a7bf542e1ddd4a374c98d985506d7ea364394920972023eaf1452acce601607789ee1345df6a" &
        "59cda18f063cecd99f926a67efc92d00a36a3068300c0603551d130101ff0402300030180603551d11041130" &
        "0f820d65643434382e6578616d706c65301d0603551d0e04160414d6f5f3b7722d5f6a0af2060f81774c9474" &
        "58b52a301f0603551d23041830168014c6dd829e140678d7111bbe7a493356c811811b15300506032b657103" &
        "7300933357f94c3e810751caf53da1babc46c005a5e9b79627b0b6a7ea07538f006818ccdea1224d804951f9" &
        "582753384c164b2af516cfcb728580fb00d4e3cfdd1c6b165021b818b87263d18ec9fdd47dc3e8512bb6cc7a" &
        "6b3019f6d4eb112caed0c0aa30c986c8db8b74428114d24ef9720a00";

      Status : CryptoLib.ASN1.Errors.Decode_Status;

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

      function Decoded (Hex : String) return X509C.Certificate
      is (X509C.Decode_DER
            (From_Hex (Hex), CryptoLib.ASN1.Default_Limits, Status));

      type Ed448_Chain is limited new XV.Path_Source with null record;

      overriding function Length (Source : Ed448_Chain) return Positive is (2);

      overriding function Certificate_At
        (Source : Ed448_Chain; Index : Positive) return X509C.Certificate
      is (if Index = 1 then Decoded (E448_Leaf_DER) else Decoded (E448_Root_DER));

      overriding function Is_Trust_Anchor
        (Source : Ed448_Chain; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Bytes (Item)
          = X509C.Subject_Bytes (Decoded (E448_Root_DER)));

      At_Time : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 9, Day => 1,
         Hour => 12, Minute => 0, Second => 0);
   begin
      Check (X509C.Public_Key_Algorithm_Of (Decoded (E448_Leaf_DER))
             = CryptoLib.X509.Ed448,
             "the certificate names an Ed448 key");
      Check (XS.Is_Supported (CryptoLib.X509.Ed448_Signature),
             "and Ed448 counts as an algorithm this can decide, which is "
             & "what tells a caller it was checked rather than skipped");
      Check (XS.Verify_Certificate_Signature
               (Decoded (E448_Leaf_DER), Decoded (E448_Root_DER)) = XS.Valid,
             "the issuer's signature over it verifies");

      declare
         Verdict : constant XV.Validation_Result :=
           XV.Validate_Path (Ed448_Chain'(null record), At_Time);
      begin
         Check (Verdict.Valid,
                "and the chain validates, got "
                & XV.Failure_Image (Verdict.Failure));
      end;

      --  An Ed448 key is now checked against its certificate rather than
      --  shrugged at. The difference that matters is the second answer
      --  below: "these do not go together" is a finding, where
      --  Unsupported_Key was only ever an admission of not looking.
      declare
         Item : ID.Local_Identity;
         St   : ID.Identity_Status;
      begin
         ID.Decode (E448_Leaf_PEM, E448_Key_PEM, Item, St);
         Check (St = ID.Ok and then ID.Is_Present (Item),
                "an Ed448 key is recognised as belonging to its leaf, got "
                & ID.Status_Image (St));
      end;

      declare
         Item : ID.Local_Identity;
         St   : ID.Identity_Status;
      begin
         ID.Decode (E448_Leaf_PEM, E448_Other_Key_PEM, Item, St);
         Check (St = ID.Key_Mismatch,
                "and another Ed448 key is reported as not belonging to it, "
                & "not as one that could not be checked, got "
                & ID.Status_Image (St));
         Check (not ID.Is_Present (Item), "with nothing handed back");
      end;
   end Check_Ed448_Certificate;

   --  Signing a request somebody else wrote.
   --
   --  Only the refusal of a malformed request was pinned before, so the
   --  whole working path was untested: which key shape a request carries is
   --  discovered by trying each width in turn, and nothing checked that a
   --  request came back out as a certificate for the key it asked about.
   --  Getting that wrong issues a certificate for the wrong key, which is
   --  the one mistake a CA must not make.
   --
   --  Ed448 is here because it did not work. The width was never tried, so
   --  an Ed448 request was refused whatever the CA was -- and it could not
   --  have worked earlier anyway, since the proof of possession below is an
   --  Ed448 signature and this crate could not check one until recently.
   procedure Check_CSR_Signing is
      package X509C renames CryptoLib.X509.Certificates;
      use type CryptoLib.X509.Public_Key_Algorithm;
      use type CryptoLib.PEM.Decode_Status;

      CSR_Ed25519_PEM : constant String :=
        "-----BEGIN CERTIFICATE REQUEST-----" & ASCII.LF &
        "MIGVMEkCAQAwFjEUMBIGA1UEAwwLY3NyLmV4YW1wbGUwKjAFBgMrZXADIQBBJpvj" & ASCII.LF &
        "aZxK7SwC8CaIrLz4i3VkyTsS5Ye0XbklAWR4xaAAMAUGAytlcANBAD7itkSYJMpQ" & ASCII.LF &
        "1mMRDkJDhzFhJLlfw/wlENMXrdpzof7u/CKUOau7MH3hvXAClMOOG2bZGA9XhN83" & ASCII.LF &
        "uTKPDkS8Fw8=" & ASCII.LF &
        "-----END CERTIFICATE REQUEST-----";
      CSR_P384_PEM : constant String :=
        "-----BEGIN CERTIFICATE REQUEST-----" & ASCII.LF &
        "MIIBDTCBlQIBADAWMRQwEgYDVQQDDAtjc3IuZXhhbXBsZTB2MBAGByqGSM49AgEG" & ASCII.LF &
        "BSuBBAAiA2IABFi3dHDRyk+Dz18vqqw9bsGzjLJtbFBfcBV0mVLbpId0fu2kEriP" & ASCII.LF &
        "1strUf45B1XBcWJ+C2TSJp33iMQC4tutrr2rJDXzHm4Uv1I20NJFWI8pafnkXK7K" & ASCII.LF &
        "HnLtP8yccD8eg6AAMAoGCCqGSM49BAMCA2cAMGQCMG8MmYT9rRbmR02tbgqG8t9s" & ASCII.LF &
        "rc6Pw4tiwIKA7IgI6n0GST6UbigyR6vTEwjKkaOBVQIwNm8h1jfbSAAnyIXfWzHM" & ASCII.LF &
        "yU2TZ0M9TknrtxSFba6jEgMA1cj4t8kfPN+X9sFChPPd" & ASCII.LF &
        "-----END CERTIFICATE REQUEST-----";
      CSR_Ed448_PEM : constant String :=
        "-----BEGIN CERTIFICATE REQUEST-----" & ASCII.LF &
        "MIHgMGICAQAwFjEUMBIGA1UEAwwLY3NyLmV4YW1wbGUwQzAFBgMrZXEDOgANH4DL" & ASCII.LF &
        "Cg5y24zB0yCYnWMlf6CVxn2+dh9q/uDI8pi6uwTgXc24ANumjZSyuSScgvBSwKxM" & ASCII.LF &
        "BgOMgQCgADAFBgMrZXEDcwCiHVlUdTjRU8vk0KbthD7WYlBi4u9mTp7GQEHIjR0R" & ASCII.LF &
        "9NlFfTxY/3vY3VLRcZOkeBIkuvr5iJ6EeoD53Wi6dd02QG+K9BMGLQ2URuJWpzaF" & ASCII.LF &
        "YAWCJiwoap6pUSg3bUe6wUOkMnPzurMPfMLXo439xNeDGQA=" & ASCII.LF &
        "-----END CERTIFICATE REQUEST-----";
      CSR_Ed448_Tampered_PEM : constant String :=
        "-----BEGIN CERTIFICATE REQUEST-----" & ASCII.LF &
        "MIHgMGICAQAwFjEUMBIGA1UEAwwLY3NyLmV4YW1wbGUwQzAFBgMrZXEDOgANH4DL" & ASCII.LF &
        "Cg5y24zB0yCYnWMlf6CVxn2+dh9q/uDI8pi6uwTgXc24ANumjZSyuSScgvBSwKxM" & ASCII.LF &
        "BgOMgQCgADAFBgMrZXEDcwCiHVlUdTjRU8vk0KbthD7WYlBi4u9mTp7GQEHIjR0R" & ASCII.LF &
        "9NlFfTxY/3vY3VLRcZOkeBIkuvr5iJ6EeoD53Wi6dd02QG+K9BMGLQ2URuJWpzaF" & ASCII.LF &
        "YAWCJiwoap6pUSg3bUe6wUOkMnPzurMPfMLXo439xNeDGQE=" & ASCII.LF &
        "-----END CERTIFICATE REQUEST-----";

      CSR_RSA_PEM : constant String :=
        "-----BEGIN CERTIFICATE REQUEST-----" & ASCII.LF &
        "MIICYzCCAUsCAQAwHjEcMBoGA1UEAwwTcnNhLnJlcXVlc3QuZXhhbXBsZTCCASIw" & ASCII.LF &
        "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMHCQpPTVm3pD0d9FUhUKBFZ+rPq" & ASCII.LF &
        "u5LusbTg+eAHU6j4m3yqjeTdRfLdwBPLDssTcFB7m26r3v9RiJvEbpgnAlA1n8L6" & ASCII.LF &
        "7xP8lfJeCOqCsGD4AVdE+WWUtUakOu5zuxGxbIy1/xY6Q64KFSbul2gT3nmnPBtx" & ASCII.LF &
        "ECpi44QVvr4SfAhmdNe8U6zvAnuA8D8ooFsIY/lT7tiKHnutkpnKfM+2CuHR3vcK" & ASCII.LF &
        "x/KMUEdY5segc44Cr2+BjvUyFEGYvh6teBoccOMMtr4C+wvmpsy0TszZDsl4L176" & ASCII.LF &
        "2XWcvfUKqEYEm3vpcgrWDONH+kKE4T/wiJFL7PtafRWpGvL5/M5dCTaVwFECAwEA" & ASCII.LF &
        "AaAAMA0GCSqGSIb3DQEBCwUAA4IBAQBPwYA3lAy0jS4hqUPnRz4xkMhPwer0LUaS" & ASCII.LF &
        "fEvOpbjqulmZfDBUQkfIFlve/JqRINCFUCH8gMR8/cFcL0eOhKIuax85tC75lgnP" & ASCII.LF &
        "Z+5bb/JN39u+JfTR5ouKwd+w9YFnslLr6a0X9OVu3Ids1bzZ15w+E30n/oy9YJHB" & ASCII.LF &
        "3nOPO2ZudZSxhi9+Y7jHSHHKMmAnzfShC+m909cuJCY2h1T9AD4d8ATghwGudXz2" & ASCII.LF &
        "ZrB+acI/Gw1Fdkxlx0F5WLvbQ1kfo1yqViQn2LChsB5Pmr0mVWRRnouVVTN8kx+x" & ASCII.LF &
        "LwEiIpsn8CcZ3Mipis3VpJ680SQybRVZXHuTs8SH7amS2CCUPc8f" & ASCII.LF &
        "-----END CERTIFICATE REQUEST-----";
      CSR_Spaced_Name_PEM : constant String :=
        "-----BEGIN CERTIFICATE REQUEST-----" & ASCII.LF &
        "MIICYjCCAUoCAQAwHTEbMBkGA1UEAwwSZXZpbC50ZXN0IGF0dGFja2VyMIIBIjAN" & ASCII.LF &
        "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwcJCk9NWbekPR30VSFQoEVn6s+q7" & ASCII.LF &
        "ku6xtOD54AdTqPibfKqN5N1F8t3AE8sOyxNwUHubbqve/1GIm8RumCcCUDWfwvrv" & ASCII.LF &
        "E/yV8l4I6oKwYPgBV0T5ZZS1RqQ67nO7EbFsjLX/FjpDrgoVJu6XaBPeeac8G3EQ" & ASCII.LF &
        "KmLjhBW+vhJ8CGZ017xTrO8Ce4DwPyigWwhj+VPu2Ioee62Smcp8z7YK4dHe9wrH" & ASCII.LF &
        "8oxQR1jmx6BzjgKvb4GO9TIUQZi+Hq14Ghxw4wy2vgL7C+amzLROzNkOyXgvXvrZ" & ASCII.LF &
        "dZy99QqoRgSbe+lyCtYM40f6QoThP/CIkUvs+1p9Faka8vn8zl0JNpXAUQIDAQAB" & ASCII.LF &
        "oAAwDQYJKoZIhvcNAQELBQADggEBADfiNY+VdyXZIGnRbzjjktEeUCq0lUdwwVbV" & ASCII.LF &
        "ybkl6IMMNw1BULUP1URRUwryWCwaRUyK+q36U4PeE+CI9TmtKErAVoXeNu8q/zox" & ASCII.LF &
        "DLQCwipPpeMuxM515axvMNMzwykPSl/QP6sfxBjuRcjy2jneslQsnOswBYJLh5tj" & ASCII.LF &
        "jJ8yo1k7rzux1RY6664BSEoQP3DnZpKiorni1sUJVjJRgViQ6iRG2mRrvAj7QOoB" & ASCII.LF &
        "l0I+uRR80TllKTruvHL3SnSiEqMe+cKJjHyrMiGTDZ3or8yYwcbeBYV5lOmCAPhK" & ASCII.LF &
        "FBabLd9d9PsQKF71JI0X8KzIGU0M+6XtKQasiqDpBJsr5BTnmdE=" & ASCII.LF &
        "-----END CERTIFICATE REQUEST-----";
      CA_Cert, CA_Key : Unbounded_String;

      --  The issued certificate's own subject key algorithm, read back from
      --  the DER rather than assumed from what went in.
      function Issued_Key_Kind (Certificate_PEM : String)
        return CryptoLib.X509.Public_Key_Algorithm
      is
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Certificate_PEM)));
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Certificate_PEM'First;
         Armour : CryptoLib.PEM.Decode_Status;
         Status : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Certificate_PEM, CryptoLib.PEM.Certificate_Label, From, Buffer,
            Last, Armour);
         if Armour /= CryptoLib.PEM.Ok then
            return CryptoLib.X509.Unknown_Public_Key_Algorithm;
         end if;
         return X509C.Public_Key_Algorithm_Of
                  (X509C.Decode_DER
                     (Buffer (Buffer'First .. Last),
                      CryptoLib.ASN1.Default_Limits, Status));
      end Issued_Key_Kind;

      procedure One_Request
        (Label    : String;
         Request  : String;
         Expected : CryptoLib.X509.Public_Key_Algorithm)
      is
         Issued : Unbounded_String;
      begin
         Check (CryptoLib.Certificates.Sign_CSR
                  (To_String (CA_Cert), To_String (CA_Key), Request, Issued)
                = CryptoLib.Certificates.Ok,
                Label & " request is signed");
         Check (Issued_Key_Kind (To_String (Issued)) = Expected,
                Label & " certificate carries the key the request asked "
                & "about, not the CA's");
         Check (OpenSSL_Interop.Chain_Verifies
                  (To_String (CA_Cert), To_String (Issued)),
                Label & " certificate verifies against its CA in OpenSSL");
      end One_Request;
   begin
      Check (CryptoLib.Certificates.Create_Local_CA ("csr-signing-ca",
                                                     CA_Cert, CA_Key)
             = CryptoLib.Certificates.Ok,
             "a CA to sign requests with");

      One_Request ("an Ed25519", CSR_Ed25519_PEM, CryptoLib.X509.Ed25519);
      One_Request ("a P-384", CSR_P384_PEM, CryptoLib.X509.ECDSA_P384);
      One_Request ("an Ed448", CSR_Ed448_PEM, CryptoLib.X509.Ed448);

      --  RSA, which this crate can verify but cannot generate. Signing a
      --  request needs neither: the CA signs with its own key and the
      --  subject's goes in as the request encoded it. Refused outright until
      --  the widths stopped being tried one at a time.
      One_Request ("an RSA", CSR_RSA_PEM, CryptoLib.X509.RSA);

      --  The name in the request becomes the name in the certificate, so a
      --  request cannot ask for one that is not a name. "evil.test
      --  attacker" is a dNSName no resolver will ever answer for and two
      --  parsers may disagree about -- the same hazard as a NUL in a name,
      --  which this crate refuses elsewhere. The profile paths have always
      --  checked the names they are given; this one signed whatever the
      --  request put in its common name.
      declare
         Issued : Unbounded_String;
      begin
         Check (CryptoLib.Certificates.Sign_CSR
                  (To_String (CA_Cert), To_String (CA_Key),
                   CSR_Spaced_Name_PEM, Issued)
                /= CryptoLib.Certificates.Ok,
                "a request whose common name is not a name is refused");
         Check (Length (Issued) = 0,
                "and nothing is issued carrying it");
      end;

      --  A request is a claim to hold a key, and its signature is the only
      --  thing behind that claim. Signing one that does not check would
      --  certify a key to whoever asked rather than to whoever holds it.
      declare
         Issued : Unbounded_String;
      begin
         Check (CryptoLib.Certificates.Sign_CSR
                  (To_String (CA_Cert), To_String (CA_Key),
                   CSR_Ed448_Tampered_PEM, Issued)
                /= CryptoLib.Certificates.Ok,
                "a request whose own signature does not check is refused");
         Check (Length (Issued) = 0,
                "and no certificate comes out of it");
      end;
   end Check_CSR_Signing;

   --  A certificate must not outlive the one that signed it.
   --
   --  Issuing asked only how long the caller wanted, so a CA with two days
   --  left would happily sign a leaf claiming 397. The moment the CA
   --  expires the chain stops verifying, so the rest of that year is
   --  validity the certificate states and does not have -- and nothing said
   --  so, at issuing time or later. This crate already computes the window
   --  from the clock rather than writing a decade into the source for the
   --  same reason.
   --
   --  Clamped rather than refused: the caller asked for a certificate good
   --  for up to that long, and a shorter one that works beats a longer one
   --  that cannot.
   procedure Check_Validity_Not_Past_Issuer is
      package X509C renames CryptoLib.X509.Certificates;
      use type CryptoLib.PEM.Decode_Status;

      function Expiry (Certificate_PEM : String)
        return CryptoLib.X509.Certificate_Time
      is
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Certificate_PEM)));
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Certificate_PEM'First;
         Armour : CryptoLib.PEM.Decode_Status;
         Status : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Certificate_PEM, CryptoLib.PEM.Certificate_Label, From, Buffer,
            Last, Armour);
         if Armour /= CryptoLib.PEM.Ok then
            return (others => 0);
         end if;
         return X509C.Not_After
                  (X509C.Decode_DER
                     (Buffer (Buffer'First .. Last),
                      CryptoLib.ASN1.Default_Limits, Status));
      end Expiry;

      Forever_CA_PEM : constant String :=
        "-----BEGIN CERTIFICATE-----" & ASCII.LF &
        "MIIBEDCBw6ADAgECAhRIsMOpcUPLN2HirLi3TmMn5IgvSjAFBgMrZXAwFTETMBEG" & ASCII.LF &
        "A1UEAwwKRm9yZXZlciBDQTAgFw0yMDAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1" & ASCII.LF &
        "OVowFTETMBEGA1UEAwwKRm9yZXZlciBDQTAqMAUGAytlcAMhAILRKIiOp48mey16" & ASCII.LF &
        "LkTZ4/nE9oFe5nVvUUYXK+N7HEtIoyMwITAPBgNVHRMBAf8EBTADAQH/MA4GA1Ud" & ASCII.LF &
        "DwEB/wQEAwIBBjAFBgMrZXADQQAUFqdL6oObX9i0AkQhVS9lCf/jx/YB9bCGIJfc" & ASCII.LF &
        "30XoMCg4VUVbDPzhaGXvxJrXZIzBLxD20x8pGn/PRfX0vZMD" & ASCII.LF &
        "-----END CERTIFICATE-----";
      Forever_Key_PEM : constant String :=
        "-----BEGIN PRIVATE KEY-----" & ASCII.LF &
        "MC4CAQAwBQYDK2VwBCIEILZ+QZgzg6qYQGeXmkxYe16XLRdxIClgNw43MsJiuzHW" & ASCII.LF &
        "-----END PRIVATE KEY-----";
      Short_CA, Short_Key, Leaf, Leaf_Key : Unbounded_String;
      Long_CA, Long_Key, Long_Leaf, Long_Leaf_Key : Unbounded_String;
      Ever_Leaf, Ever_Key : Unbounded_String;
   begin
      --  A CA with two days left, asked for a leaf good for over a year.
      Check (CryptoLib.Certificates.Create_Local_CA
               ("short-lived-ca", Short_CA, Short_Key,
                CryptoLib.Certificates.Ed25519_Key, 2)
             = CryptoLib.Certificates.Ok,
             "a CA with two days left");
      Check (CryptoLib.Certificates.Issue_Server_Certificate
               (To_String (Short_CA), To_String (Short_Key), "brief.example",
                [1 => To_Unbounded_String ("brief.example")],
                Leaf, Leaf_Key, 397)
             = CryptoLib.Certificates.Ok,
             "still issues rather than refusing");
      Check (CryptoLib.X509.Is_Not_After
               (Expiry (To_String (Leaf)), Expiry (To_String (Short_CA))),
             "and the leaf does not outlast the CA that signed it");

      --  The ordinary case is untouched: a leaf under a long-lived CA gets
      --  the window it asked for, not the CA's.
      Check (CryptoLib.Certificates.Create_Local_CA
               ("long-lived-ca", Long_CA, Long_Key)
             = CryptoLib.Certificates.Ok,
             "a CA with ten years left");
      Check (CryptoLib.Certificates.Issue_Server_Certificate
               (To_String (Long_CA), To_String (Long_Key), "usual.example",
                [1 => To_Unbounded_String ("usual.example")],
                Long_Leaf, Long_Leaf_Key, 397)
             = CryptoLib.Certificates.Ok,
             "issues a leaf as usual");
      Check (not CryptoLib.X509.Is_Not_After
                   (Expiry (To_String (Long_CA)),
                    Expiry (To_String (Long_Leaf))),
             "whose window is its own and shorter than the CA's, not "
             & "clamped to it");

      --  A CA that says it never expires, which RFC 5280 spells 99991231.
      --  The ceiling is worked out as a clock time and no clock here reaches
      --  the year 9999, so this is the case where the bound cannot be
      --  computed -- and the right answer is to leave the certificate alone,
      --  because nothing issued today can run past a CA that never ends.
      --  Worth pinning because it arrives through an exception handler
      --  rather than a test on the year, and because the only other way in
      --  was a date like the 31st of February, which no longer parses.
      Check (CryptoLib.Certificates.Issue_Server_Certificate
               (Forever_CA_PEM, Forever_Key_PEM, "under.forever",
                [1 => To_Unbounded_String ("under.forever")],
                Ever_Leaf, Ever_Key, 397)
             = CryptoLib.Certificates.Ok,
             "a CA that never expires still issues");
      Check (Expiry (To_String (Ever_Leaf)).Year < 9999,
             "and the certificate gets a window of its own rather than the "
             & "CA's, got"
             & Natural'Image (Expiry (To_String (Ever_Leaf)).Year));

      --  The window it asked for, to the day: the same 397 days as the leaf
      --  issued above under an ordinary CA. Checking only that it is short
      --  of 9999 would pass just as well if the unreadable expiry had been
      --  read as "expires now", which is the other way this can go wrong.
      Check (Expiry (To_String (Ever_Leaf)).Year
             = Expiry (To_String (Long_Leaf)).Year
             and then Expiry (To_String (Ever_Leaf)).Month
                      = Expiry (To_String (Long_Leaf)).Month
             and then Expiry (To_String (Ever_Leaf)).Day
                      = Expiry (To_String (Long_Leaf)).Day,
             "and it is the same window a leaf gets under an ordinary CA, "
             & "not one cut back to the moment of issue");
   end Check_Validity_Not_Past_Issuer;

   --  A date that does not exist is not a time.
   --
   --  The day was checked against 31 and no further, so the 31st of
   --  February decoded happily. Nothing downstream notices: times are
   --  compared field by field, so a notAfter of 31 February keeps a
   --  certificate valid for the days after February has ended, and the
   --  number was chosen by whoever wrote the certificate. OpenSSL calls the
   --  same encoding a bad time value.
   --
   --  It also quietly disabled the issuer-expiry ceiling, which has to turn
   --  the CA's notAfter into a clock time and cannot turn that into one.
   procedure Check_Impossible_Dates is
      use type CryptoLib.ASN1.Errors.Decode_Status;

      --  A GeneralizedTime carrying exactly these characters.
      function Reads (Text : String) return Boolean is
         Data   : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Text'Length + 2));
         Cursor : Ada.Streams.Stream_Element_Offset := 1;
         Value  : CryptoLib.X509.Certificate_Time;
         Status : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         Data (1) := 16#18#;
         Data (2) := Ada.Streams.Stream_Element (Text'Length);
         for I in Text'Range loop
            Data (2 + Ada.Streams.Stream_Element_Offset (I - Text'First + 1)) :=
              Character'Pos (Text (I));
         end loop;
         CryptoLib.X509.Times.Read
           (Data, Cursor, Data'Last, 0, CryptoLib.ASN1.Default_Limits,
            Value, Status);
         return Status = CryptoLib.ASN1.Errors.Ok;
      end Reads;
   begin
      Check (not Reads ("20260231000000Z"),
             "the 31st of February is refused");
      Check (not Reads ("20260230000000Z"),
             "and the 30th");
      Check (not Reads ("20260431000000Z"),
             "and the 31st of a month with thirty days");
      Check (not Reads ("20260000000000Z"),
             "and a zeroth day");

      --  The leap year rule is the Gregorian one, not "divisible by four".
      Check (Reads ("20240229000000Z"),
             "the 29th of February stands in a leap year");
      Check (not Reads ("20250229000000Z"),
             "and not in an ordinary one");
      Check (not Reads ("21000229000000Z"),
             "not in 2100, which is divisible by four and not a leap year");
      Check (Reads ("20000229000000Z"),
             "and does stand in 2000, which is divisible by four hundred");

      --  Dates that do exist still decode, or this would be refusing real
      --  certificates rather than impossible ones.
      Check (Reads ("20260131000000Z"), "the 31st of January is a date");
      Check (Reads ("20260430000000Z"), "so is the 30th of April");
      Check (Reads ("20261231235959Z"), "and the last second of a year");
   end Check_Impossible_Dates;

   --  A statement that never says when it expires does not last for ever.
   --
   --  nextUpdate is optional in a CRL and in an OCSP response, and freshness
   --  was judged only against it: a list carrying one was refused once it
   --  passed, and a list carrying none had no window to be outside of. Two
   --  lists of the same age got opposite answers, the older-looking one
   --  being the one that admitted when it expired.
   --
   --  Nothing has to be forged to use this. The CRL below is genuine and
   --  correctly signed -- the issuer really did say "nothing revoked", in
   --  2016 -- and replaying it is how a certificate revoked since keeps
   --  working. Which is the sentence this package's own summary opens with.
   procedure Check_Undated_Statement_Ages is
      package X509C renames CryptoLib.X509.Certificates;
      package XC renames CryptoLib.X509.CRLs;
      package RV renames CryptoLib.X509.Revocation;
      use type RV.Revocation_Answer;

      Old_CRL_No_Next_DER : constant String :=
        "307c3030020101300506032b657030153113301106035504030c0a416e6369656e74204341170d3136303130" &
        "313030303030305a300506032b6570034100d42aad219f0f54efd41f288648bbabecc7d2b4433fbe33de7b7f" &
        "f9043bd6e2f4adf2fb9ee9fcdb37594779c7512c3d7d983c22692d253f62662260dc60710208";

      CRL_CA_DER : constant String :=
        "3082010e3081c1a0030201020214577aeb858a37d5fd81ef133d2f79f41b352b0865300506032b6570301531" &
        "13301106035504030c0a416e6369656e74204341301e170d3135303130313030303030305a170d3335303130" &
        "313030303030305a30153113301106035504030c0a416e6369656e74204341302a300506032b657003210066" &
        "cac3f61035489eb5047b43fe568288970990887c3b28dfe059572c9d7fc8b9a3233021300f0603551d130101" &
        "ff040530030101ff300e0603551d0f0101ff040403020106300506032b65700341006c648e89b0c39a67a31f" &
        "d67e7799560c095dd91d8625d0ec851229ac49a3ffe223a980f08e75f8903eff5e7bb2267bcb1a2b5661dd19" &
        "af7a9a5bfe53dea8df03";

      CRL_Leaf_DER : constant String :=
        "3081d930818ca00302010202021092300506032b657030153113301106035504030c0a416e6369656e742043" &
        "41301e170d3135303130313030303030305a170d3335303130313030303030305a3017311530130603550403" &
        "0c0c6c6561662e6578616d706c65302a300506032b657003210066cac3f61035489eb5047b43fe5682889709" &
        "90887c3b28dfe059572c9d7fc8b9300506032b65700341007c3a46fa18d9399201c207d4b39510689c321d00" &
        "e21238c63b6bf631429e79665f98463750a4792e8c4b887dcda8aaf423a7651b38e5b889186a829c34cf280c";

      OCSP_No_Next_DER : constant String :=
        "308202700a0100a08202693082026506092b06010505073001010482025630820252307fa118301631143012" &
        "06035504030c0b4f43535020416765204341180f32303236303732393131303935355a30523050303b300906" &
        "052b0e03021a050004148aa32804b8ef3e1a72a802fa517db805a64d6b860414cd92b608f1fd749014a411de" &
        "eaafcf1b3c5e589702021e618000180f32303236303732393131303935355a300a06082a8648ce3d04030203" &
        "4700304402206faf3ddabc08070db84eac39ad1a082a490917774f3f6c95edf7ea471823f6cc02205ab938e7" &
        "357de2d8b5a8aea5cdf2fd7ac00741f3e45ef854bf3fd984acfa99a1a0820178308201743082017030820116" &
        "a0030201020214727b3004679aafba2769bea705a91b243a8dba81300a06082a8648ce3d0403023016311430" &
        "1206035504030c0b4f43535020416765204341301e170d3236303732393131303935355a170d333431303135" &
        "3131303935355a30163114301206035504030c0b4f435350204167652043413059301306072a8648ce3d0201" &
        "06082a8648ce3d030107034200049dd9b1bdb250fafd0132582cc4ec06f590ef980cb19c5b94391cc539af61" &
        "a1ba333bc63a9dd6ac1fc8d721e114626be9cc45eb735e1029ede22b1811f760bc57a3423040300f0603551d" &
        "130101ff040530030101ff300e0603551d0f0101ff040403020106301d0603551d0e04160414cd92b608f1fd" &
        "749014a411deeaafcf1b3c5e5897300a06082a8648ce3d0403020348003045022067c206a7d209626c102be4" &
        "8f757a7a4afaf209562d73be0b43ba70bcbf4f5b8b0221008f76d1f212b8e471977a9f57aaf00673b53777bd" &
        "5fc36c3dfdb60f170726a0cc";

      OCSP_CA_DER : constant String :=
        "3082017030820116a0030201020214727b3004679aafba2769bea705a91b243a8dba81300a06082a8648ce3d" &
        "04030230163114301206035504030c0b4f43535020416765204341301e170d3236303732393131303935355a" &
        "170d3334313031353131303935355a30163114301206035504030c0b4f435350204167652043413059301306" &
        "072a8648ce3d020106082a8648ce3d030107034200049dd9b1bdb250fafd0132582cc4ec06f590ef980cb19c" &
        "5b94391cc539af61a1ba333bc63a9dd6ac1fc8d721e114626be9cc45eb735e1029ede22b1811f760bc57a342" &
        "3040300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301d0603551d0e0416" &
        "0414cd92b608f1fd749014a411deeaafcf1b3c5e5897300a06082a8648ce3d0403020348003045022067c206" &
        "a7d209626c102be48f757a7a4afaf209562d73be0b43ba70bcbf4f5b8b0221008f76d1f212b8e471977a9f57" &
        "aaf00673b53777bd5fc36c3dfdb60f170726a0cc";

      OCSP_Leaf_DER : constant String :=
        "3082016e30820113a00302010202021e61300a06082a8648ce3d04030230163114301206035504030c0b4f43" &
        "535020416765204341301e170d3236303732393131303935355a170d3332303131393131303935355a301731" &
        "15301306035504030c0c6c6561662e6578616d706c653059301306072a8648ce3d020106082a8648ce3d0301" &
        "07034200046d43ecd744c212d59a835dc92090d5431edd8c4085918fef3e90613dec37b48d3b7fc556b1beae" &
        "e9b13a66eb9dec3d9d16e37bbbb6c8161188a0e915504835ada350304e300c0603551d130101ff0402300030" &
        "1d0603551d0e04160414032c9886bbda604bc235e452d5697eabedc5e673301f0603551d23041830168014cd" &
        "92b608f1fd749014a411deeaafcf1b3c5e5897300a06082a8648ce3d04030203490030460221008ee8ca58a3" &
        "4bfaf8306e32e6eecf1a06b1464578a1a79a6cc42f43243387b17c022100c265d327bb504ff33138c5436790" &
        "3cc9297164c077c20ac285785052130cdba1";
      Status : CryptoLib.ASN1.Errors.Decode_Status;

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

      Leaf : constant X509C.Certificate :=
        X509C.Decode_DER (From_Hex (CRL_Leaf_DER),
                          CryptoLib.ASN1.Default_Limits, Status);
      CA   : constant X509C.Certificate :=
        X509C.Decode_DER (From_Hex (CRL_CA_DER),
                          CryptoLib.ASN1.Default_Limits, Status);
      List : constant XC.Revocation_List :=
        XC.Decode_DER (From_Hex (Old_CRL_No_Next_DER),
                       CryptoLib.ASN1.Default_Limits, Status);

      --  The list was issued on the first of January 2016.
      Ten_Years_On : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 1, Day => 2,
         Hour => 0, Minute => 0, Second => 0);
      Next_Day     : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2016, Month => 1, Day => 2,
         Hour => 0, Minute => 0, Second => 0);
   begin
      Check (XC.Is_Present (List) and then X509C.Is_Present (Leaf)
             and then X509C.Is_Present (CA),
             "fixture: the list, its issuer and a certificate all decode");
      Check (not XC.Has_Next_Update (List),
             "fixture: and the list never says when it expires");

      --  The day after it was issued it is worth believing.
      Check (RV.Check_Against_CRL (Leaf, CA, List, Next_Day) = RV.Not_Revoked,
             "a list without a nextUpdate is believed while it is fresh, got "
             & RV.Answer_Image
                 (RV.Check_Against_CRL (Leaf, CA, List, Next_Day)));

      --  Ten years later it is not, and it says so as staleness rather than
      --  as an answer about the certificate.
      Check (RV.Check_Against_CRL (Leaf, CA, List, Ten_Years_On) = RV.Stale,
             "and is stale ten years on rather than still saying nothing was "
             & "revoked, got "
             & RV.Answer_Image
                 (RV.Check_Against_CRL (Leaf, CA, List, Ten_Years_On)));

      --  The age is the only thing refusing it: the signature, the issuer
      --  and the scope are all fine, which is what makes replaying it work.
      Check (RV.Check_Against_CRL
               (Leaf, CA, List, Ten_Years_On,
                Maximum_Age_Days => 4_000) = RV.Not_Revoked,
             "and a caller who says it may be that old gets the answer, so "
             & "nothing else about the list is what was refused");

      --  The same for OCSP, where a response without a nextUpdate is not an
      --  oddity but what "openssl ocsp" produces unless told otherwise. RFC
      --  6960 reads the omission as newer information being available all
      --  the time, which is the opposite of what believing it for ever does.
      declare
         Reply : CryptoLib.OCSP.Response :=
           CryptoLib.OCSP.Decode_Response
             (From_Hex (OCSP_No_Next_DER), CryptoLib.ASN1.Default_Limits,
              Status);
         Resp_Leaf : constant X509C.Certificate :=
           X509C.Decode_DER (From_Hex (OCSP_Leaf_DER),
                             CryptoLib.ASN1.Default_Limits, Status);
         Resp_CA   : constant X509C.Certificate :=
           X509C.Decode_DER (From_Hex (OCSP_CA_DER),
                             CryptoLib.ASN1.Default_Limits, Status);
         Days_Later : constant CryptoLib.X509.Certificate_Time :=
           (Year => 2026, Month => 8, Day => 1,
            Hour => 12, Minute => 0, Second => 0);
         Years_Later : constant CryptoLib.X509.Certificate_Time :=
           (Year => 2036, Month => 8, Day => 1,
            Hour => 12, Minute => 0, Second => 0);
      begin
         Check (not CryptoLib.OCSP.Has_Next_Update (Reply),
                "fixture: the response names no nextUpdate");
         Check (RV.Check_Against_OCSP (Resp_Leaf, Resp_CA, Reply, Days_Later)
                = RV.Not_Revoked,
                "a response without a nextUpdate answers while it is fresh, "
                & "got "
                & RV.Answer_Image
                    (RV.Check_Against_OCSP
                       (Resp_Leaf, Resp_CA, Reply, Days_Later)));
         Check (RV.Check_Against_OCSP (Resp_Leaf, Resp_CA, Reply, Years_Later)
                = RV.Stale,
                "and is stale ten years on rather than still speaking for "
                & "the certificate, got "
                & RV.Answer_Image
                    (RV.Check_Against_OCSP
                       (Resp_Leaf, Resp_CA, Reply, Years_Later)));
      end;
   end Check_Undated_Statement_Ages;

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
      end;
   end Check_Bcrypt_PBKDF;

   --  The comparison every tag check goes through.
   --
   --  Its shape is held to a jump budget by check_constant_time, so it
   --  cannot quietly acquire an early return; that says nothing about
   --  whether it answers correctly, and nothing named it. A tamper test on
   --  an AEAD reaches it, but only for the byte that test happens to
   --  disturb.
   procedure Check_Constant_Time_Equal is
      A : constant Ada.Streams.Stream_Element_Array (1 .. 8) :=
        [1, 2, 3, 4, 5, 6, 7, 8];
      Empty : constant Ada.Streams.Stream_Element_Array (1 .. 0) :=
        [others => 0];

      function Differing_At (Where : Positive) return Boolean is
         B : Ada.Streams.Stream_Element_Array (1 .. 8) := A;
      begin
         B (Ada.Streams.Stream_Element_Offset (Where)) :=
           B (Ada.Streams.Stream_Element_Offset (Where)) xor 16#80#;
         return CryptoLib.Constant_Time.Equal (A, B);
      end Differing_At;
   begin
      Check (CryptoLib.Constant_Time.Equal (A, A),
             "a value equals itself");

      --  Every position, because a comparison that stops early or runs one
      --  short is right about all the others.
      for Where in 1 .. 8 loop
         Check (not Differing_At (Where),
                "a difference at byte" & Natural'Image (Where) & " is seen");
      end loop;

      Check (not CryptoLib.Constant_Time.Equal (A, A (1 .. 7)),
             "a shorter value is not equal to a longer one");
      Check (not CryptoLib.Constant_Time.Equal (A (1 .. 7), A),
             "nor the other way round");
      Check (CryptoLib.Constant_Time.Equal (Empty, Empty),
             "two empty values are equal, which is what the contract says");
   end Check_Constant_Time_Equal;

   --  A peer value that would make the shared secret worthless.
   --
   --  Group 16 rejects a public value outside (1, p-1): zero and one give a
   --  shared secret of zero or one whatever the private exponent is, and a
   --  value at or above the prime is not a group element. The check is
   --  written and was never exercised -- the only DH test is a round trip,
   --  where both sides behave and which passes just as well with no
   --  validation at all.
   procedure Check_DH_Peer_Validation is
      Rng    : CryptoLib.Random.Random_Source;
      Priv   : CryptoLib.Buffers.Packet_Buffer;
      Pub    : CryptoLib.Buffers.Packet_Buffer;
      Shared : CryptoLib.Buffers.Packet_Buffer;

      --  The peer value is given as a sign byte and magnitude, big-endian,
      --  which is what Generate_Group16_Keypair hands back.
      function Refuses (Peer : Ada.Streams.Stream_Element_Array)
        return Boolean
      is (CryptoLib.Diffie_Hellman.Compute_Group16_Shared_Secret
            (CryptoLib.Buffers.To_Array (Priv), Peer, Shared)
          /= CryptoLib.Errors.Ok);

      At_Or_Above_Prime : constant Ada.Streams.Stream_Element_Array
        (1 .. 512) := [others => 16#FF#];
   begin
      CryptoLib.Random.Initialize_Production (Rng);
      Check (CryptoLib.Diffie_Hellman.Generate_Group16_Keypair
               (Rng, Priv, Pub) = CryptoLib.Errors.Ok,
             "a group16 keypair to answer with");

      Check (Refuses ([1 => 0]),
             "a peer value of zero is refused, since every secret from it "
             & "is zero");
      Check (Refuses ([1 => 1]),
             "and a peer value of one, since every secret from it is one");
      Check (Refuses (At_Or_Above_Prime),
             "and one at or above the prime, which is not a group element");

      --  And the check is not simply refusing everything: a real public
      --  value, and the smallest legitimate one, both go through.
      Check (not Refuses ([1 => 2]),
             "while two is inside the group and is accepted");
      Check (not Refuses (CryptoLib.Buffers.To_Array (Pub)),
             "as is a public value this crate generated itself");
   end Check_DH_Peer_Validation;

   --  OpenSSH key fingerprints, which nothing here was checking.
   --
   --  Two formats a person reads off a terminal and compares by eye before
   --  trusting a host or a key. Neither was named anywhere in the suite, so
   --  a fingerprint that came out subtly wrong -- a dropped leading zero, a
   --  stray base64 pad -- would have been nobody's failing test. Both turn
   --  out to be right; the vectors are what ssh-keygen prints for the same
   --  key blobs.
   procedure Check_OpenSSH_Fingerprints is
      Ed25519_Blob : constant String :=
        "0000000b7373682d6564323535313900000020eb6126b8dc505698a087af84a720a8c5aeb063841fa5da" &
        "508e0b7fe010d74d2e";

      RSA_Blob : constant String :=
        "000000077373682d727361000000030100010000010100a3c354fc7002a2c2769f65b0c2392f7b45807f" &
        "1164921fdea956c8d5e60aab71fb74aaf25b235d14ffb3dede12fcbf0db3e8e9a854a30498faeeef5f82" &
        "3745a2d566f395d194de6dc99b3626deee3bc48e5b8cf751e082eb053fabb0aae812f5335228262dac97" &
        "baebe3f284b8f858606bcff749baae69df21a6bf9fc2c1d0d27a22e709ad0d5ff1f63305c318f905d77e" &
        "3906b463ceffcd1b29f9d1597e3c2861197ef2f0cb5fb05249a428ce5636195095e493543db80f42c71d" &
        "f49d040b5677eb283a94db17ccdb6dc576bea2779883b1ee8eab385adf1e27cb51f5aa877b06691c187e" &
        "8de9578dd1a60d2b7d4e4384f75832214d84eaf64484721e8947e3";

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

      procedure One_Key (Label : String; Blob : String;
                         Sha : String; Md5 : String)
      is
         Rendered : Unbounded_String;
      begin
         Check (CryptoLib.Fingerprints.SHA256_OpenSSH
                  (From_Hex (Blob), Rendered) = CryptoLib.Errors.Ok
                and then To_String (Rendered) = Sha,
                Label & " SHA-256 fingerprint matches ssh-keygen, got "
                & To_String (Rendered));
         Check (CryptoLib.Fingerprints.MD5_OpenSSH
                  (From_Hex (Blob), Rendered) = CryptoLib.Errors.Ok
                and then To_String (Rendered) = Md5,
                Label & " MD5 fingerprint matches ssh-keygen, got "
                & To_String (Rendered));
      end One_Key;
   begin
      One_Key ("an Ed25519 key", Ed25519_Blob,
               "SHA256:BHKvdl5CunT7Uf2fAFIKoEp3Q9WH05aP9/IrGD8ESdw",
               "MD5:07:bb:7e:50:c1:0d:07:42:26:98:20:16:d4:2b:2b:cd");
      One_Key ("an RSA key", RSA_Blob,
               "SHA256:kA5XpZeuWAnvQ13w1n/x3mj1Il9YZ++ykGiDWcum8Cw",
               "MD5:8b:80:12:64:88:49:71:03:7d:fc:18:9c:4d:ec:41:78");

      --  The SHA-256 form is unpadded base64: 32 bytes is not a multiple of
      --  three, so a padded rendering would end in "=" and not match what
      --  anybody compares against.
      declare
         Rendered : Unbounded_String;
      begin
         Check (CryptoLib.Fingerprints.SHA256_OpenSSH
                  (From_Hex (Ed25519_Blob), Rendered) = CryptoLib.Errors.Ok
                and then Element (Rendered, Length (Rendered)) /= '=',
                "and carries no base64 padding");
      end;
   end Check_OpenSSH_Fingerprints;

   --  Group 14, which nothing was checking, against arithmetic done
   --  elsewhere.
   --
   --  The suite tested groups 16 and 18 and left 1 and 14 alone, while the
   --  table listed all four. Group 14 is the one an SSH client actually
   --  negotiates most of the time.
   --
   --  A round trip between two honest sides is self-consistent and would
   --  pass with the wrong prime, so this fixes the private exponent and the
   --  peer value and writes down the answer: 2 raised to 0x012345 modulo the
   --  RFC 3526 group 14 prime, computed independently. A single wrong digit
   --  anywhere in that 2048-bit constant changes it.
   procedure Check_DH_Group14 is

      Expected : constant String :=
           "00a65579621dbc9f9c2493b937c6e20f4898caeff728c042dd49710c60e201cdd5ec5122cf6938be4eaf"
           & "e9a8c8cf5bbe6a398bce7d4febcaa0d91299550a00e3356f38539f29bd6004a29149242b31760ece6132"
           & "9da815e0be47b7ea8c2e4831d8e22dda2eca6458ca9659d5c9921628418cadfc06045bf436cb5c8c32e0"
           & "cf38cb18a53efb236ba44c7fa0f7d13815b6bcd1c00bb8734cda61c33dc99d958891753223e13d9e40df"
           & "127b0abacae29e58ccf5f9962e0afc734deb0619fa7335386e4c89d6e2547f46329f79531adac79524ac"
           & "4d008384edcb9aa9516d7c2ef63ddd2f136d64701af9a37d51c537548e458dc67c3b6fbc52c871ba3357"
           & "23b34196e2";

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

      Fixed_Private : Ada.Streams.Stream_Element_Array (1 .. 256) :=
        [others => 0];
      Shared : CryptoLib.Buffers.Packet_Buffer;
   begin
      --  0x012345, right aligned in the fixed-width exponent.
      Fixed_Private (254) := 16#01#;
      Fixed_Private (255) := 16#23#;
      Fixed_Private (256) := 16#45#;

      Check (CryptoLib.Diffie_Hellman.Compute_Group14_Shared_Secret
               (Fixed_Private, [1 => 2], Shared) = CryptoLib.Errors.Ok,
             "group14 computes a shared secret from a fixed exponent");
      Check (CryptoLib.Buffers.To_Array (Shared) = From_Hex (Expected),
             "and it is the value an independent modexp over the RFC 3526 "
             & "group 14 prime gives");

      --  The same degenerate peers the group16 check refuses.
      Check (CryptoLib.Diffie_Hellman.Compute_Group14_Shared_Secret
               (Fixed_Private, [1 => 0], Shared) /= CryptoLib.Errors.Ok,
             "a peer value of zero is refused here too");
      Check (CryptoLib.Diffie_Hellman.Compute_Group14_Shared_Secret
               (Fixed_Private, [1 => 1], Shared) /= CryptoLib.Errors.Ok,
             "and a peer value of one");
   end Check_DH_Group14;

   --  Group 1, the last of the four the table lists.
   --
   --  Pinned the same way as group 14 and for the same reason: a round trip
   --  proves two sides agree, not that they agree on the right number. This
   --  fixes the exponent and the peer and writes the answer down -- 2 raised
   --  to 0x012345 modulo the 1024-bit MODP prime -- so a wrong digit in the
   --  constant shows up here rather than as a quiet interoperability failure
   --  against something that has the prime right.
   --
   --  Group 1 is legacy and weak at 1024 bits. It is pinned because it is
   --  offered, not because it should be chosen.
   procedure Check_DH_Group1 is
      Expected : constant String :=
           "0097b82fdcff8313a9d7121615b4ee9ac1b5b517db2bd8d095756a09c46ff207ff150d4e3d21c2f43b8e"
           & "94fc51aeb81afd35860d5e2bbb0b5c403d60340026326719e2af4bbaf6d65878dc49c916533970c1c103"
           & "6dd5f65684a8b68853dd8f1e163f878e87899ca39af653bc5e0bb37d5db7a2b2f702b75f9d9493ba64ae"
           & "e2c79d";

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

      Fixed_Private : Ada.Streams.Stream_Element_Array (1 .. 128) :=
        [others => 0];
      Shared : CryptoLib.Buffers.Packet_Buffer;
   begin
      Fixed_Private (126) := 16#01#;
      Fixed_Private (127) := 16#23#;
      Fixed_Private (128) := 16#45#;

      Check (CryptoLib.Diffie_Hellman.Compute_Group1_Shared_Secret
               (Fixed_Private, [1 => 2], Shared) = CryptoLib.Errors.Ok,
             "group1 computes a shared secret from a fixed exponent");
      Check (CryptoLib.Buffers.To_Array (Shared) = From_Hex (Expected),
             "and it is the value an independent modexp over the 1024-bit "
             & "MODP prime gives");

      Check (CryptoLib.Diffie_Hellman.Compute_Group1_Shared_Secret
               (Fixed_Private, [1 => 0], Shared) /= CryptoLib.Errors.Ok,
             "a peer value of zero is refused in group1 too");
      Check (CryptoLib.Diffie_Hellman.Compute_Group1_Shared_Secret
               (Fixed_Private, [1 => 1], Shared) /= CryptoLib.Errors.Ok,
             "and a peer value of one");
   end Check_DH_Group1;

   --  The X25519 entry point callers actually use.
   --
   --  The suite reached the primitive through Compute_Raw, which takes a raw
   --  scalar; Shared_Secret takes the opaque private key Generate_Keypair
   --  hands back, and is what a caller doing key exchange calls. It clamps
   --  and fails closed on its own, and neither had been exercised through
   --  this door -- a wrapper that dropped the low-order check would have
   --  looked fine from the primitive's tests.
   procedure Check_X25519_Shared_Secret is
      use type CryptoLib.Curve25519.Public_Key;

      Rng : CryptoLib.Random.Random_Source;

      A_Private, B_Private : CryptoLib.Curve25519.Private_Key;
      A_Public, B_Public   : CryptoLib.Curve25519.Public_Key;
      A_Secret, B_Secret   : CryptoLib.Curve25519.Public_Key;

      Low_Order : constant CryptoLib.Curve25519.Public_Key := [others => 0];
   begin
      CryptoLib.Random.Initialize_Production (Rng);
      Check (CryptoLib.Curve25519.Generate_Keypair (Rng, A_Private, A_Public)
             = CryptoLib.Errors.Ok
             and then CryptoLib.Curve25519.Generate_Keypair
                        (Rng, B_Private, B_Public) = CryptoLib.Errors.Ok,
             "two X25519 keypairs");

      Check (CryptoLib.Curve25519.Shared_Secret (A_Private, B_Public, A_Secret)
             = CryptoLib.Errors.Ok
             and then CryptoLib.Curve25519.Shared_Secret
                        (B_Private, A_Public, B_Secret)
                      = CryptoLib.Errors.Ok,
             "each side computes a secret from the other's public key");
      Check (A_Secret = B_Secret,
             "and the two sides arrive at the same one");

      --  The all-zero peer point: the shared secret would be all-zero, and
      --  a key exchange that accepted it would key itself with a constant
      --  the peer chose.
      Check (CryptoLib.Curve25519.Shared_Secret
               (A_Private, Low_Order, A_Secret) /= CryptoLib.Errors.Ok,
             "a low-order peer point is refused through this door as well");
      Check (A_Secret = [1 .. 32 => 0],
             "and the secret is zeroed rather than left as whatever the "
             & "ladder produced");

      CryptoLib.Curve25519.Clear (A_Private);
      CryptoLib.Curve25519.Clear (B_Private);
   end Check_X25519_Shared_Secret;

   --  The chain checks nothing was asserting.
   --
   --  Path_Length_Exceeded, Invalid_Basic_Constraints and Invalid_Key_Usage
   --  are three of the oldest questions X.509 asks -- how deep may this CA
   --  delegate, is the issuer a CA at all, is it allowed to sign
   --  certificates -- and no test named any of them. They work. Nothing
   --  would have said so if they stopped.
   --
   --  Each chain below is one an attacker would build, and OpenSSL refuses
   --  all four.
   procedure Check_Chain_Constraint_Bypasses is
      package X509C renames CryptoLib.X509.Certificates;
      package XV renames CryptoLib.X509.Validation;
      use type XV.Validation_Failure;

      Len0_Root_DER : constant String :=
        "3082016f30820115a0030201020214690ed1841f04a45804ebb557f0c83b8fa695a755300a06082a8648" &
        "ce3d04030230143112301006035504030c094c656e3020526f6f74301e170d3236303732393131353635" &
        "365a170d3334313031353131353635365a30143112301006035504030c094c656e3020526f6f74305930" &
        "1306072a8648ce3d020106082a8648ce3d03010703420004cd75bd0da20c5fcd91f18b814c2757b4c7db" &
        "5a15e73d765e4541f1c4a29b2f8a0b496a32cef7647a199c08346947689523416b0d99a2d1758d0f34ac" &
        "7ee37abda345304330120603551d130101ff040830060101ff020100300e0603551d0f0101ff04040302" &
        "0204301d0603551d0e04160414adbcc4910226acf0e9296785ee777b96efe3bf28300a06082a8648ce3d" &
        "04030203480030450221008bb75c643a4c4192cbe9baae18440f256dd7f0666ceb3fa8c3f0c97749b618" &
        "6702204561e485d5d7e895f4f0193a8169a5fe3a2176adab830fc58af3d29f4a41cbad";

      Len0_Inter_DER : constant String :=
        "3082018e30820135a003020102021443d5d6a988536afc0a43fab23b9403399437190a300a06082a8648" &
        "ce3d04030230143112301006035504030c094c656e3020526f6f74301e170d3236303732393131353635" &
        "365a170d3332303131393131353635365a30163114301206035504030c0b457874726120496e74657230" &
        "59301306072a8648ce3d020106082a8648ce3d0301070342000433ebd00a784f41a1ba1dc0707c4ea79e" &
        "ec188fa5a4f5885cdbcd3806be3dc0db0955c21b7875e2b1e6f751f5aa15c4d2693adadfce4a74291e01" &
        "5a0eb5731402a3633061300f0603551d130101ff040530030101ff300e0603551d0f0101ff0404030202" &
        "04301d0603551d0e04160414aa2fcce67c3a21569341ed348b0cb465ea9cce1f301f0603551d23041830" &
        "168014adbcc4910226acf0e9296785ee777b96efe3bf28300a06082a8648ce3d04030203470030440220" &
        "6173b33bbc95b8dc76d42dd92606fddca40cdd0e08c93778ce12bbe99c49a26102203e655e3b10cf8a29" &
        "dcca7475ec57454ea795ea7a0ebe0bab5a21da299f18a8a6";

      Len0_Leaf_DER : constant String :=
        "308201a030820146a0030201020214711ff84d161a762b0dbb338664a3be3eb6dbbd3c300a06082a8648" &
        "ce3d04030230163114301206035504030c0b457874726120496e746572301e170d323630373239313135" &
        "3635365a170d3332303131393131353635365a301b3119301706035504030c10686f73742e6578616d70" &
        "6c652e636f6d3059301306072a8648ce3d020106082a8648ce3d030107034200047a9fefa5958775b469" &
        "d028962a7129fa68421df7a2ce5ea0aeeb0c9114dfc72f9453cb376acdd67a378dc261290bf05f943f3c" &
        "7c62c8298a6b69ff57f6daa3c9a36d306b300c0603551d130101ff04023000301b0603551d1104143012" &
        "8210686f73742e6578616d706c652e636f6d301d0603551d0e04160414dd288838f636c9d009a8686fb0" &
        "ecad1a35b83905301f0603551d23041830168014aa2fcce67c3a21569341ed348b0cb465ea9cce1f300a" &
        "06082a8648ce3d0403020348003045022100a0a67504604b313169110b0e6a8a2843e70874913c374d05" &
        "ea151c8921a09be702201d39aa9381e8ec4a070b1bface211f1e3813a35d8803bf95f88fd826cfdff113";

      NC_Root_DER : constant String :=
        "308201873082012da00302010202143e123bb37b6caf84d51d4c5d9fd398aeaddf1733300a06082a8648" &
        "ce3d04030230123110300e06035504030c074e4320526f6f74301e170d3236303732393131353635365a" &
        "170d3334313031353131353635365a30123110300e06035504030c074e4320526f6f743059301306072a" &
        "8648ce3d020106082a8648ce3d03010703420004cd75bd0da20c5fcd91f18b814c2757b4c7db5a15e73d" &
        "765e4541f1c4a29b2f8a0b496a32cef7647a199c08346947689523416b0d99a2d1758d0f34ac7ee37abd" &
        "a361305f300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020204301d060355" &
        "1d1e0101ff04133011a00f300d820b6578616d706c652e636f6d301d0603551d0e04160414adbcc49102" &
        "26acf0e9296785ee777b96efe3bf28300a06082a8648ce3d040302034800304502206bfecd47bfc6dcc4" &
        "70d977ce573810c5825faca9956cef6a8423369f5db58052022100b6dd016810e498f249438280c8b04e" &
        "b34ddbf7c48205f6f5ca925529c4df42a6";

      NoSign_Inter_DER : constant String :=
        "3082018e30820135a0030201020214201f05f60f265bd1b925ff010c47b1641fb8693d300a06082a8648" &
        "ce3d04030230123110300e06035504030c074e4320526f6f74301e170d3236303732393131353830385a" &
        "170d3332303131393131353830385a30183116301406035504030c0d4e6f205369676e20496e74657230" &
        "59301306072a8648ce3d020106082a8648ce3d0301070342000433ebd00a784f41a1ba1dc0707c4ea79e" &
        "ec188fa5a4f5885cdbcd3806be3dc0db0955c21b7875e2b1e6f751f5aa15c4d2693adadfce4a74291e01" &
        "5a0eb5731402a3633061300f0603551d130101ff040530030101ff300e0603551d0f0101ff0404030207" &
        "80301d0603551d0e04160414aa2fcce67c3a21569341ed348b0cb465ea9cce1f301f0603551d23041830" &
        "168014adbcc4910226acf0e9296785ee777b96efe3bf28300a06082a8648ce3d04030203470030440220" &
        "46577421c0961d235aef6aa7820b619fbdc25af0fae401df8b2fe17c6f2b9fc7022047dc4ff4c9cb4dc0" &
        "536fa55904f9059c69d787b6660861e4563472f99e016743";

      NoSign_Leaf_DER : constant String :=
        "308201a330820148a00302010202145ff94cb5f18b8e4762f9cec4fac9f9d304084474300a06082a8648" &
        "ce3d04030230183116301406035504030c0d4e6f205369676e20496e746572301e170d32363037323931" &
        "31353830385a170d3332303131393131353830385a301b3119301706035504030c10686f73742e657861" &
        "6d706c652e636f6d3059301306072a8648ce3d020106082a8648ce3d030107034200047a9fefa5958775" &
        "b469d028962a7129fa68421df7a2ce5ea0aeeb0c9114dfc72f9453cb376acdd67a378dc261290bf05f94" &
        "3f3c7c62c8298a6b69ff57f6daa3c9a36d306b300c0603551d130101ff04023000301b0603551d110414" &
        "30128210686f73742e6578616d706c652e636f6d301d0603551d0e04160414dd288838f636c9d009a868" &
        "6fb0ecad1a35b83905301f0603551d23041830168014aa2fcce67c3a21569341ed348b0cb465ea9cce1f" &
        "300a06082a8648ce3d04030203490030460221008c2b697165a5279e6a28d223b9f1f27c5a22dccd218b" &
        "01eaabe436d66c8b7822022100b35413738ae7218be68245f6c8289712b61da535b9c926ba79bd95d586" &
        "203009";

      NotCA_Inter_DER : constant String :=
        "308201873082012da0030201020214201f05f60f265bd1b925ff010c47b1641fb8693e300a06082a8648" &
        "ce3d04030230123110300e06035504030c074e4320526f6f74301e170d3236303732393131353830385a" &
        "170d3332303131393131353830385a30133111300f06035504030c084e6f742041204341305930130607" &
        "2a8648ce3d020106082a8648ce3d0301070342000433ebd00a784f41a1ba1dc0707c4ea79eec188fa5a4" &
        "f5885cdbcd3806be3dc0db0955c21b7875e2b1e6f751f5aa15c4d2693adadfce4a74291e015a0eb57314" &
        "02a360305e300c0603551d130101ff04023000300e0603551d0f0101ff040403020204301d0603551d0e" &
        "04160414aa2fcce67c3a21569341ed348b0cb465ea9cce1f301f0603551d23041830168014adbcc49102" &
        "26acf0e9296785ee777b96efe3bf28300a06082a8648ce3d0403020348003045022100c44fd96cbd955c" &
        "60250a51dba6bfc3651b1dc09a69f1547e55c47fbf0cc4c1d40220745439dbeaea43471d28e931e705a0" &
        "28dd98974991865260e420ff2dca178781";

      NotCA_Leaf_DER : constant String :=
        "3082019e30820143a0030201020214120667dceb6184dc84f601fa4f33991979893bb3300a06082a8648" &
        "ce3d04030230133111300f06035504030c084e6f742041204341301e170d323630373239313135383038" &
        "5a170d3332303131393131353830385a301b3119301706035504030c10686f73742e6578616d706c652e" &
        "636f6d3059301306072a8648ce3d020106082a8648ce3d030107034200047a9fefa5958775b469d02896" &
        "2a7129fa68421df7a2ce5ea0aeeb0c9114dfc72f9453cb376acdd67a378dc261290bf05f943f3c7c62c8" &
        "298a6b69ff57f6daa3c9a36d306b300c0603551d130101ff04023000301b0603551d1104143012821068" &
        "6f73742e6578616d706c652e636f6d301d0603551d0e04160414dd288838f636c9d009a8686fb0ecad1a" &
        "35b83905301f0603551d23041830168014aa2fcce67c3a21569341ed348b0cb465ea9cce1f300a06082a" &
        "8648ce3d0403020349003046022100caf8a3066dbb8553491bd36e5495eced74f7cd584c97e0a47ad79c" &
        "c0b824fcf9022100bb1b53376d51487a7c6fc373bc72dd5c2ad207a810fe20282a290cdc2b6512f7";

      Rogue_Inter_DER : constant String :=
        "308201ae30820155a0030201020214201f05f60f265bd1b925ff010c47b1641fb8693f300a06082a8648" &
        "ce3d04030230123110300e06035504030c074e4320526f6f74301e170d3236303732393131353933315a" &
        "170d3332303131393131353933315a30163114301206035504030c0b526f67756520496e746572305930" &
        "1306072a8648ce3d020106082a8648ce3d0301070342000433ebd00a784f41a1ba1dc0707c4ea79eec18" &
        "8fa5a4f5885cdbcd3806be3dc0db0955c21b7875e2b1e6f751f5aa15c4d2693adadfce4a74291e015a0e" &
        "b5731402a38184308181300f0603551d130101ff040530030101ff300e0603551d0f0101ff0404030202" &
        "04301e0603551d11041730158213726f6775652e61747461636b65722e74657374301d0603551d0e0416" &
        "0414aa2fcce67c3a21569341ed348b0cb465ea9cce1f301f0603551d23041830168014adbcc4910226ac" &
        "f0e9296785ee777b96efe3bf28300a06082a8648ce3d04030203470030440220747de90d9eec3f9c2885" &
        "08482082ad8aa0e293b5e929166fc369b609dd89c37c02206163971cda614fbc7cea4b1e3617692cd47c" &
        "36fb748f125ef6ba31ca8ffafae2";

      Rogue_Leaf_DER : constant String :=
        "308201a130820146a0030201020214080d97a7eae74b03ff8233adcd831314b89e39f5300a06082a8648" &
        "ce3d04030230163114301206035504030c0b526f67756520496e746572301e170d323630373239313135" &
        "3933315a170d3332303131393131353933315a301b3119301706035504030c10686f73742e6578616d70" &
        "6c652e636f6d3059301306072a8648ce3d020106082a8648ce3d030107034200047a9fefa5958775b469" &
        "d028962a7129fa68421df7a2ce5ea0aeeb0c9114dfc72f9453cb376acdd67a378dc261290bf05f943f3c" &
        "7c62c8298a6b69ff57f6daa3c9a36d306b300c0603551d130101ff04023000301b0603551d1104143012" &
        "8210686f73742e6578616d706c652e636f6d301d0603551d0e04160414dd288838f636c9d009a8686fb0" &
        "ecad1a35b83905301f0603551d23041830168014aa2fcce67c3a21569341ed348b0cb465ea9cce1f300a" &
        "06082a8648ce3d0403020349003046022100b77f7ae9cf1b07f6ca5be3d0a7539815d435ca8b8c538456" &
        "036b723d445addb4022100a71d2f09b05305121238f5cd6ebc753ab62a6d45c3af4a5fd072fd8e5c2425" &
        "e6";

      Status : CryptoLib.ASN1.Errors.Decode_Status;

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

      function Decoded (Hex : String) return X509C.Certificate
      is (X509C.Decode_DER
            (From_Hex (Hex), CryptoLib.ASN1.Default_Limits, Status));

      type Which is (Overlong, Not_A_CA, Cannot_Sign, Rogue_Name);

      type Three (Kind : Which) is limited new XV.Path_Source with null record;

      overriding function Length (Source : Three) return Positive is (3);

      overriding function Certificate_At
        (Source : Three; Index : Positive) return X509C.Certificate
      is (case Source.Kind is
             when Overlong =>
               (case Index is
                   when 1 => Decoded (Len0_Leaf_DER),
                   when 2 => Decoded (Len0_Inter_DER),
                   when others => Decoded (Len0_Root_DER)),
             when Not_A_CA =>
               (case Index is
                   when 1 => Decoded (NotCA_Leaf_DER),
                   when 2 => Decoded (NotCA_Inter_DER),
                   when others => Decoded (NC_Root_DER)),
             when Cannot_Sign =>
               (case Index is
                   when 1 => Decoded (NoSign_Leaf_DER),
                   when 2 => Decoded (NoSign_Inter_DER),
                   when others => Decoded (NC_Root_DER)),
             when Rogue_Name =>
               (case Index is
                   when 1 => Decoded (Rogue_Leaf_DER),
                   when 2 => Decoded (Rogue_Inter_DER),
                   when others => Decoded (NC_Root_DER)));

      overriding function Is_Trust_Anchor
        (Source : Three; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Bytes (Item)
          = X509C.Subject_Bytes
              (Decoded (if Source.Kind = Overlong
                        then Len0_Root_DER else NC_Root_DER)));

      At_Time : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 9, Day => 1,
         Hour => 12, Minute => 0, Second => 0);

      function Verdict (Kind : Which) return XV.Validation_Result
      is (XV.Validate_Path (Three'(Kind => Kind), At_Time));
   begin
      --  A root that says pathlen:0 has said no CA below it may issue
      --  another. The intermediate is genuine, signed by that root, and
      --  issues anyway.
      Check (not Verdict (Overlong).Valid
             and then Verdict (Overlong).Failure = XV.Path_Length_Exceeded,
             "a CA issuing below a pathlen:0 root is refused, got "
             & XV.Failure_Image (Verdict (Overlong).Failure));

      --  An issuer whose own basic constraints say it is not a CA. Its
      --  signature over the leaf is perfectly good, which is the point.
      Check (not Verdict (Not_A_CA).Valid
             and then Verdict (Not_A_CA).Failure
                      = XV.Invalid_Basic_Constraints,
             "an issuer that is not a CA is refused, got "
             & XV.Failure_Image (Verdict (Not_A_CA).Failure));

      --  A CA whose key usage does not include keyCertSign. It signed the
      --  leaf; it was never permitted to.
      Check (not Verdict (Cannot_Sign).Valid
             and then Verdict (Cannot_Sign).Failure = XV.Invalid_Key_Usage,
             "a CA without keyCertSign is refused, got "
             & XV.Failure_Image (Verdict (Cannot_Sign).Failure));

      --  Name constraints reach the intermediate itself, not only the leaf.
      --  Here the leaf is inside the permitted subtree and the CA that
      --  issued it is not.
      Check (not Verdict (Rogue_Name).Valid
             and then Verdict (Rogue_Name).Failure
                      = XV.Name_Constraint_Violation,
             "a constrained CA cannot issue an intermediate named outside "
             & "its own subtree, got "
             & XV.Failure_Image (Verdict (Rogue_Name).Failure));
   end Check_Chain_Constraint_Bypasses;

   --  A certificate that names one algorithm twice and disagrees with
   --  itself.
   --
   --  The signature algorithm appears in two places: inside the TBS, where
   --  it is covered by the signature, and outside it, where it is not. Only
   --  the inner one is protected, so the outer one is free for anybody to
   --  change after the fact. RFC 5280 requires them to be the same, and a
   --  verifier that reads the algorithm from the unprotected copy is being
   --  told how to check a signature by whoever last touched the file.
   --
   --  Both certificates below carry the same edit; one applies it to the
   --  outer copy alone and the other to both. The consistent one decodes,
   --  which is what makes this a test of the disagreement rather than of the
   --  edit.
   procedure Check_Signature_Algorithm_Agreement is
      package X509C renames CryptoLib.X509.Certificates;
      use type CryptoLib.ASN1.Errors.Decode_Status;

      Alg_Mismatched_DER : constant String :=
        "308201853082012ba003020102021433cde67db76ddf4e1f2be6917a34aa4fb7101bb1300a06082a8648" &
        "ce3d04030230183116301406035504030c0d416c6720436f6e667573696f6e301e170d32363037323931" &
        "32303332315a170d3332303131393132303332315a30183116301406035504030c0d416c6720436f6e66" &
        "7573696f6e3059301306072a8648ce3d020106082a8648ce3d03010703420004fa4d50277869e9712522" &
        "68073b4cd40fdb5ab5a49699d13d0508e83a1ac8bd02570dec8c642cd0490632c1dcdab8e6fe0185bfa1" &
        "4e4658c071eacbff3b750fc2a3533051301d0603551d0e04160414acf3f2269ab96aa3ba990a0c4850cf" &
        "91ae9ef11d301f0603551d23041830168014acf3f2269ab96aa3ba990a0c4850cf91ae9ef11d300f0603" &
        "551d130101ff040530030101ff300a06082a8648ce3d0403040348003045022022f4576a4b39c5dea9b8" &
        "9aad54bc71d84016bfa1e8a17cb25e122546d421f93d022100f909605c27251ae25103d0f741b8dc4c3a" &
        "d4b2a4a779f21d3e63f580a5a41d41";

      Alg_Agreed_DER : constant String :=
        "308201853082012ba003020102021433cde67db76ddf4e1f2be6917a34aa4fb7101bb1300a06082a8648" &
        "ce3d04030430183116301406035504030c0d416c6720436f6e667573696f6e301e170d32363037323931" &
        "32303332315a170d3332303131393132303332315a30183116301406035504030c0d416c6720436f6e66" &
        "7573696f6e3059301306072a8648ce3d020106082a8648ce3d03010703420004fa4d50277869e9712522" &
        "68073b4cd40fdb5ab5a49699d13d0508e83a1ac8bd02570dec8c642cd0490632c1dcdab8e6fe0185bfa1" &
        "4e4658c071eacbff3b750fc2a3533051301d0603551d0e04160414acf3f2269ab96aa3ba990a0c4850cf" &
        "91ae9ef11d301f0603551d23041830168014acf3f2269ab96aa3ba990a0c4850cf91ae9ef11d300f0603" &
        "551d130101ff040530030101ff300a06082a8648ce3d0403040348003045022022f4576a4b39c5dea9b8" &
        "9aad54bc71d84016bfa1e8a17cb25e122546d421f93d022100f909605c27251ae25103d0f741b8dc4c3a" &
        "d4b2a4a779f21d3e63f580a5a41d41";

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

      Mismatched_Status : CryptoLib.ASN1.Errors.Decode_Status;
      Agreed_Status     : CryptoLib.ASN1.Errors.Decode_Status;

      Mismatched : constant X509C.Certificate :=
        X509C.Decode_DER (From_Hex (Alg_Mismatched_DER),
                          CryptoLib.ASN1.Default_Limits, Mismatched_Status);
      Agreed     : constant X509C.Certificate :=
        X509C.Decode_DER (From_Hex (Alg_Agreed_DER),
                          CryptoLib.ASN1.Default_Limits, Agreed_Status);
   begin
      Check (Mismatched_Status /= CryptoLib.ASN1.Errors.Ok,
             "a certificate whose outer signature algorithm differs from the "
             & "one inside the TBS does not decode, got "
             & CryptoLib.ASN1.Errors.Status_Image (Mismatched_Status));
      Check (not X509C.Is_Present (Mismatched),
             "and nothing is handed back to be asked questions about");

      --  The same substitution made in both places, so the certificate
      --  disagrees with nothing. It decodes; only the disagreement was
      --  fatal.
      Check (Agreed_Status = CryptoLib.ASN1.Errors.Ok
             and then X509C.Is_Present (Agreed),
             "while the same algorithm named consistently decodes, got "
             & CryptoLib.ASN1.Errors.Status_Image (Agreed_Status));
   end Check_Signature_Algorithm_Agreement;

   --  A real OpenSSH private key, opened with nothing but this crate.
   --
   --  SECURITY.md used to claim bcrypt was "proven by decrypting a real
   --  OpenSSH key". That proof lived somewhere else, and when the KAT was
   --  added a few commits ago the claim was narrowed to match what is
   --  actually here. This puts the original claim back, earned: the key
   --  below came out of ssh-keygen, and what opens it is bcrypt_pbkdf for
   --  the key material and AES-256-CTR for the blob, both from this crate.
   --
   --  Two primitives against a third party's artifact catches what neither
   --  KAT can. A vector proves each one computes what its own specification
   --  says; this proves they agree with what OpenSSH actually wrote, in the
   --  order and the widths it wrote it -- 32 bytes of key and 16 of IV cut
   --  from one 48-byte derivation.
   procedure Check_OpenSSH_Key_Unlock is
      OpenSSH_Salt : constant String :=
        "2a44a1b83faf7d1cac356a66592e5cca";
      OpenSSH_Blob : constant String :=
        "bbe192ee2b44570b362c32d3bedb15f91cdc535243911677e733050c34c02d6f698ff951949d4e5587c8" &
        "23f77312e30943e8abcc2c2dedb45eb45d65f5336fb34df2c484559b53b24cbc71fc5e70404c8c2cda85" &
        "a6bf7b22e6186804a6a4101a5dfb2111a38898a7e1714fbbefc96c4d1e883a11340f03ed5a2ef5f8b762" &
        "ff300d194299eb451ab501170e1edb0bd4bb19e8ba5a5654e33ec1ce9d3f7c9ebe5f";
      OpenSSH_Rounds : constant := 24;

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

      --  The passphrase given to ssh-keygen.
      Passphrase : constant String := "correct horse";

      procedure Open_With (Pass : String; Ok : out Boolean;
                           Names_The_Key : out Boolean)
      is
         Material : Ada.Streams.Stream_Element_Array (1 .. 48);
         Blob     : constant Ada.Streams.Stream_Element_Array :=
           From_Hex (OpenSSH_Blob);
         Plain    : Ada.Streams.Stream_Element_Array (Blob'Range);
         Context  : CryptoLib.Ciphers.Cipher_State;
         Status   : CryptoLib.Errors.Status;
      begin
         Ok := False;
         Names_The_Key := False;

         Status :=
           CryptoLib.BCrypt_PBKDF.Derive
             (Pass, From_Hex (OpenSSH_Salt),
              Interfaces.Unsigned_32 (OpenSSH_Rounds), Material);
         if Status /= CryptoLib.Errors.Ok then
            return;
         end if;

         --  OpenSSH cuts one derivation into the key and the IV.
         Status :=
           CryptoLib.Ciphers.Initialize
             (Context, "aes256-ctr", CryptoLib.Ciphers.Client_To_Server,
              Material (1 .. 32), Material (33 .. 48));
         if Status /= CryptoLib.Errors.Ok then
            return;
         end if;

         Status := CryptoLib.Ciphers.Decrypt (Context, Blob, Plain);
         if Status /= CryptoLib.Errors.Ok then
            return;
         end if;

         --  The two check words OpenSSH writes at the head of the private
         --  section, equal only when the passphrase was right.
         Ok := Plain (Plain'First .. Plain'First + 3)
               = Plain (Plain'First + 4 .. Plain'First + 7);

         --  And past them, the key type as a length-prefixed string.
         declare
            Kind : constant Ada.Streams.Stream_Element_Array :=
              Plain (Plain'First + 8 .. Plain'First + 22);
         begin
            Names_The_Key :=
              Kind = From_Hex ("0000000b7373682d65643235353139");
         end;
      end Open_With;

      Unlocked, Named : Boolean;
   begin
      Open_With (Passphrase, Unlocked, Named);
      Check (Unlocked,
             "a key written by ssh-keygen opens with bcrypt_pbkdf and "
             & "AES-256-CTR from this crate");
      Check (Named,
             "and what comes out names itself ssh-ed25519, so the plaintext "
             & "is the key and not merely self-consistent");

      Open_With ("wrong horse", Unlocked, Named);
      Check (not Unlocked,
             "the wrong passphrase does not open it");
   end Check_OpenSSH_Key_Unlock;

   --  A signature OpenSSH made, checked here.
   --
   --  The Ed25519 vectors prove this computes what RFC 8032 says. They do
   --  not prove it agrees with what another implementation actually emits
   --  over bytes that implementation chose to frame its own way. This is
   --  ssh-keygen -Y sign: the signature is over the SSHSIG structure --
   --  a magic string, the namespace, the hash name and the SHA-512 of the
   --  file -- none of which this crate assembled.
   procedure Check_OpenSSH_Signature is
      SSHSIG_Public : constant String :=
        "b91b800e2174fc90ce2ef7f072a481cde08ef64e57a829ad260f9afd19f9199c";
      SSHSIG_Signature : constant String :=
        "6d79e9ebdc4545ab74b5070c58e910d0f39d0b66deac7415f8adb55e6fd77a718ffcf1ee5b1f56a2097e" &
        "57a347521d03af7a1e93e8414dae6682571f86f45108";
      SSHSIG_Signed : constant String :=
        "5353485349470000000963727970746f6c6962000000000000000673686135313200000040c91009ba89" &
        "2e18933ebd13f0d3228cde25b72da75dae9195ab38b62e46f6290f157b8f0dd6fa25e0fe25499b55f6b5" &
        "02158d23818827c7652194a69fe938d1c6";

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

      Signature : Ada.Streams.Stream_Element_Array (1 .. 64) :=
        From_Hex (SSHSIG_Signature);
      Signed    : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (SSHSIG_Signed'Length / 2)) :=
        From_Hex (SSHSIG_Signed);
   begin
      Check (CryptoLib.Ed25519.Verify
               (From_Hex (SSHSIG_Public), Signature, Signed)
             = CryptoLib.Errors.Ok,
             "a signature written by ssh-keygen verifies here");

      Signature (11) := Signature (11) xor 1;
      Check (CryptoLib.Ed25519.Verify
               (From_Hex (SSHSIG_Public), Signature, Signed)
             /= CryptoLib.Errors.Ok,
             "and one bit of it is enough to break it");
      Signature (11) := Signature (11) xor 1;

      Signed (Signed'Last) := Signed (Signed'Last) xor 1;
      Check (CryptoLib.Ed25519.Verify
               (From_Hex (SSHSIG_Public), Signature, Signed)
             /= CryptoLib.Errors.Ok,
             "as is one bit of what was signed");
   end Check_OpenSSH_Signature;

   --  The ECDSA entry points that pick their own digest.
   --
   --  Verify_Signature takes the digest from the caller and is well covered.
   --  The Nistp*_Raw wrappers do not: they pair the curve with a digest
   --  themselves, which is what SSH means by ecdsa-sha2-nistp256 and what
   --  ssh_lib calls. P-384's wrapper was exercised; the other two were the
   --  only users of their branch of that pairing, so a curve wired to the
   --  wrong hash would have verified nothing anybody here asked about while
   --  failing against every signature made elsewhere.
   --
   --  The signatures below were made by pyca over the matching digest, so
   --  they only verify if the pairing agrees with the rest of the world.
   procedure Check_ECDSA_Raw_Entry_Points is
      P256_Point : constant String :=
        "04114f0722565bc55edc6866d91d24d465e4b14325f7eb85707a153773b9ebe2f1f338c2f3ae68502eb2" &
        "9d1d197bd3875efdb5917d3dd4a1702bf3774140e3edc7";
      P256_R : constant String :=
        "06e75b9a986021357108920b8320a199ba8574b237c439c0b3e53a5bb46de3c3";
      P256_S : constant String :=
        "50174c2670a3400e4df61149f809b73b6ebb08c96309c3aef9aba153bfd606c5";
      P521_Point : constant String :=
        "0401ce4e8335ea49fd856fdff7ec6698aff6699616d2ac27e12b2baa96fa4356ef9beb083c2ad4e9be98" &
        "b8dd7234d434d528263fb684b3ed36a24b1b29292dfdfeb1e200bbd7d73f7572a32b74bcbd800b38f5e5" &
        "50369a5d35e4591367b004bd116f54248243e4ca9dadcd1c3c54213966d4b110693d5b5257c4e5f373fd" &
        "11a0a5eb351474";
      P521_R : constant String :=
        "01eff7360bfd44c7b6ca30eb4e8ae8b17e799e4f9f0e2b3cb27b8bfa9d25f8285e792ad642339b800f54" &
        "267b47f2d46ce2cd43c8c880464d5f6bb2ae03ecb129bbba";
      P521_S : constant String :=
        "018cd9ed5c5d7bae1396d480d7ae3a6b9ebc4d0481839b85917ad2ce85389c4d7e259da32e1a297c771e" &
        "e4669272996ecce03018e22d7e19edd3f9e87403b4259054";
      EC_Message : constant String :=
        "72617720656364736120656e74727920706f696e7420636865636b";

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
      Check (CryptoLib.ECDSA.Verify_Nistp256_Raw
               (From_Hex (P256_Point), From_Hex (EC_Message),
                From_Hex (P256_R), From_Hex (P256_S))
             = CryptoLib.Errors.Ok,
             "P-256 through its own entry point pairs the curve with SHA-256");

      Check (CryptoLib.ECDSA.Verify_Nistp521_Raw
               (From_Hex (P521_Point), From_Hex (EC_Message),
                From_Hex (P521_R), From_Hex (P521_S))
             = CryptoLib.Errors.Ok,
             "and P-521 with SHA-512");

      --  A signature is for one message, whichever door it comes through.
      Check (CryptoLib.ECDSA.Verify_Nistp256_Raw
               (From_Hex (P256_Point), From_Hex (P521_Point),
                From_Hex (P256_R), From_Hex (P256_S))
             /= CryptoLib.Errors.Ok,
             "and neither verifies over something else");
   end Check_ECDSA_Raw_Entry_Points;

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
              (XV.Default_Policy with delta Maximum_Path_Length => 1));
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
      end;

      --  A star that is only part of a label is not a wildcard. Reading it
      --  as one is how "www*.example.com" comes to speak for every host
      --  whose name starts with www, which is not what the issuer wrote.
      declare
         Partial : constant X509C.Certificate :=
           Leaf_With ([1 => To_Unbounded_String ("www*.example.com")]);
      begin
         Check (XI.Match_DNS_Name (Partial, "www1.example.com") = XI.No_Match,
                "a star sharing a label with other characters matches "
                & "nothing under it");
         Check (XI.Match_DNS_Name (Partial, "www.example.com") = XI.No_Match,
                "not even the name it looks like a prefix of");
      end;

      --  The same thing with the star at the front of the label. This one
      --  does start with a star, so it gets past any check that only looks
      --  at the first character.
      --
      --  Wildcard_Matches carries a guard for exactly this shape, requiring
      --  the whole first label to be the star. That guard turns out to be
      --  unreachable: the name is refused as unusable before matching is
      --  attempted, and the only names that reach Wildcard_Matches at all
      --  are well-formed bare-star wildcards. Deleting it changes nothing
      --  any test can see. It is right to keep and worth knowing about,
      --  since an unreachable guard is one nobody is checking.
      declare
         Leading : constant X509C.Certificate :=
           Leaf_With ([1 => To_Unbounded_String ("*x.example.com")]);
      begin
         --  Reported as unusable rather than merely not matching. A name
         --  with a star stuck to other characters is not a name, and a
         --  certificate carrying one is worth being suspicious of -- saying
         --  "no match" would let it pass as an ordinary mismatch.
         Check (XI.Match_DNS_Name (Leading, "foo.example.com")
                = XI.Malformed_Identity,
                "a star at the head of a longer label makes the name "
                & "unusable, got "
                & XI.Result_Image
                    (XI.Match_DNS_Name (Leading, "foo.example.com")));
         Check (XI.Match_DNS_Name (Leading, "ax.example.com")
                /= XI.Matched,
                "and it certainly does not match by completing the label");
      end;

      --  A wildcard has to be the leftmost label. One buried in the middle
      --  would otherwise reach across a level the issuer never named.
      declare
         Middle : constant X509C.Certificate :=
           Leaf_With ([1 => To_Unbounded_String ("a.*.example.com")]);
      begin
         Check (XI.Match_DNS_Name (Middle, "a.b.example.com") = XI.No_Match,
                "a wildcard in the middle of a name matches nothing");
      end;

      --  A wildcard needs a real domain under it. "*.com" would otherwise
      --  be a certificate for every name in the registry.
      declare
         Too_Wide : constant X509C.Certificate :=
           Leaf_With ([1 => To_Unbounded_String ("*.com")]);
      begin
         Check (XI.Match_DNS_Name (Too_Wide, "foo.com") = XI.No_Match,
                "a wildcard over a single label matches nothing");
      end;

      declare
         Wild : constant X509C.Certificate :=
           Leaf_With ([1 => To_Unbounded_String ("*.example.com")]);
      begin

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
   --  When a certificate was revoked, and why -- from a CRL and from an OCSP
   --  response about the same certificates, which must agree.
   --
   --  The time matters on its own: a signature made before the revocation
   --  took effect may still stand, and a caller judging one needs that time
   --  rather than the moment the statement was published. The reason matters
   --  because Key_Compromise discredits every signature the key ever made,
   --  while Superseded or Cessation_Of_Operation leave earlier ones alone.
   procedure Check_Revocation_Details is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.OCSP.Verification_Result;
      use type CryptoLib.X509.Certificate_Time;
      use type CryptoLib.X509.Revocation_Reason;
      use type CryptoLib.X509.Revocation.Revocation_Answer;
      use type CryptoLib.X509.Signatures.Verification_Result;

      package X509C renames CryptoLib.X509.Certificates;
      package XC renames CryptoLib.X509.CRLs;
      package XR renames CryptoLib.X509.Revocation;
      package CO renames CryptoLib.OCSP;

      Reason_CA_DER : constant String :=
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

      Reason_Leaf_DER : constant String :=
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

      Reason_Second_DER : constant String :=
        "308202a43082018c02021001300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d74" &
        "6573742d6361301e170d3236303732383232313431375a170d3237303732383232313431375a30193117301506" &
        "035504030c0e7365636f6e642e6578616d706c6530820122300d06092a864886f70d01010105000382010f0030" &
        "82010a0282010100a169fd82209088be49800f464b442f6e1d1fdd823084ff0a76bfbc7ec44287274a752dba1d" &
        "1926442087bff21dd051ce99fdf42f8cb4b30426d8240f922287b089d4e37a4add7ba8181dfc701369be8291e5" &
        "7166ba7922d556eed539d1c2627b160cdd7c71ba8598319435dc4c2087d062ed23a84313fae6666f45b3050b88" &
        "46c8b8fc2fca5b4e5018545e10a3cb8c7cdfbfa133cadb29acd896362cafb931bdfb31b4be226ba91567d38499" &
        "84b6fc1f6f9211550ea01e522aeaf7523e23c59e22ed3fc55bbdcd1e4a7019ad93f5c2c8cb603d849af6c0c0d6" &
        "99147c7c0073baaf455e0259cf099305383c5bebcf32113e1d82db30e615de58a0eed56dbb5b37020301000130" &
        "0d06092a864886f70d01010b050003820101006066b5357a33b4941a2fd365f2792c297d6e82829fc3ac6bdd8c" &
        "fc5efe3861139b38592af36fd731af2ee9f4a09689f01604097636072dac2cb00a319eded804527a0631c7ef52" &
        "1f610c466cc33d8bdc9aaaf3e77b13b5ff004a51f837af3c6cba3ba6bf882e293e2d23a35c5654b4827341e1fd" &
        "3afd7be93bb546b93bdf0983a8cbdde40b23ffd240220362c028f824e44fa2792a6a5fee2af6878df9c401ffba" &
        "c2681e43effd2c225cc03b7bbb09affc9e1b962feef1da1dbc1f23597487d936c21e712fd4085290cc5f5eef03" &
        "237d417b683db649c246f384d9190d16873cb75c50abe79b62e349772306da7e154bc2655aa9306c63ea33ce84" &
        "0832a2c904";

      Reason_CRL_DER : constant String :=
        "308201aa308193020101300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d746573" &
        "742d6361170d3236303732383232333530315a170d3236303832373232333530315a3038301302021000170d32" &
        "36303732383230313534375a302102021001170d3236303732383232333530315a300c300a0603551d1504030a" &
        "0101a00f300d300b0603551d14040402021001300d06092a864886f70d01010b050003820101007a95fd172721" &
        "41f2fb843e9bca2032f064e9fc48a1a09e47042bf2acf47f6c704776cb513d6991b0b9f08966af640a5be77c75" &
        "c497905b1087b1114a0ebab6616ddd0740085ae706dc9095b3596928ea9353484d4a07867174a3e17e745d61fe" &
        "3e3038fbe8e365e370ae1b989da8d11cd3cb2aa46ebdbad1b0af01581925c221270b488651bdfd13574ca3b91c" &
        "feb81e99c5d3d450de6cc66d93a1bf42f22683d81597a58be41fc8bf78cc038b73e30b3226bb5e4b8ee8f06a09" &
        "b8463b8bcb6095eff4dc439313f5834791ae09b92d169059b6d08af52d1ac727d373a3bd52e38dae47120addd9" &
        "dd397ac90f72edbc0b651c50b149f9c9a989029b3419a7d65e";

      Reason_Response_DER : constant String :=
        "308204f60a0100a08204ef308204eb06092b0601050507300101048204dc308204d83081a8a118301631143012" &
        "06035504030c0b63726c2d746573742d6361180f32303236303732383232333535325a307b3079303b30090605" &
        "2b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b24380aa8a0cd3392" &
        "6e4452de852f02021001a116180f32303236303732383232333530315aa0030a0101180f323032363037323832" &
        "32333535325aa011180f32303236303832373232333535325a300d06092a864886f70d01010b05000382010100" &
        "80a8a22a0fdfd1ad318eab14f12e354c63021234ae50e3b4b1ca9f7102dc9df6327c8f7df5b5ccc2e3c5afdb6c" &
        "c94cf1dbfd7c1f46d86d3a95dc2eb2668b0d3a2eadfeeaed734da38c84dbd94dfe8acf0458adcb48fcec6d970b" &
        "39e55f6a27bfe3838f5edc746c2a6c9ffa785066e68540e89124f7a44e27b4fdecf86a59b41f9b3ec3b5663687" &
        "348a1f4b4a13a5c3f2156429037d67f55e39846ccc07432f3f0bff4bf84517ddf3994fc61c72b6d1f9a7d0a36f" &
        "a331d3eaad39c6cc6f2845801461af6bd4a0152e9731fd4b39d25f66a394cc6a24b38db2cc5b5dd77acc620233" &
        "14469b08e952941688585c1788af20ecd72ac1db95c69944b073cabf27d188a0820315308203113082030d3082" &
        "01f5a0030201020214695a2eb222fd6509af65d97b7099306d68b399eb300d06092a864886f70d01010b050030" &
        "163114301206035504030c0b63726c2d746573742d6361301e170d3236303732383230313534375a170d333630" &
        "3732353230313534375a30163114301206035504030c0b63726c2d746573742d636130820122300d06092a8648" &
        "86f70d01010105000382010f003082010a0282010100b5e60ee7058f7f9e991a038feeac5eb95d99b6b52f543a" &
        "4cf379d9b84ab68125a82424b27f07a1f6a39f6f6e5ac4df194a06d3683fafc31123427f768f6024aa6b2d5f75" &
        "9d0629a578497370038d70020ea20e261a913c332504d70327b2cd747a2ae0f415764976ae21d8c34874405cfa" &
        "befd83ffc5b03de5c6521a611c333189ead8755a0bf56113ad088deb953cf1febb465a377d256bad055bf62772" &
        "7ccfffa616cfe8edc009a49f318a6c1e935dc42b69ab1d2aa9ee2173defdf45fbb595b99aced529fca129587fa" &
        "c967025980f7617070edde4748fa62cd395a608475ba22bd65c29f1fabdefe5e8aeed28baa170388bca8bb6490" &
        "db6bacea3473ed8f0203010001a3533051301d0603551d0e04160414a1f6d41f7e7b24380aa8a0cd33926e4452" &
        "de852f301f0603551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300f0603551d130101" &
        "ff040530030101ff300d06092a864886f70d01010b050003820101005f484fd12f7d522aa3787c0ee05c3e0606" &
        "7d91b3f51a3747e1ffcd7d57e839f17a9bfcf878faa9c4af435426aa06ed4907dfb9c29ca36c6b53af27ce2251" &
        "6b5bd4cb19e9d912893e3800a1f7acc3abefbc18a6c899793b6ff9d378f2a77e0feb03659f8a2409bee7a48047" &
        "73be1f8428608fb9041ac74581b1943d0d90dd2939be1b74015bcd676cf483167988523fba452b255b49146d3c" &
        "5be21408d8c9848f6794a4fa588ab2d6d326bc7d92920c3547d3f4d9270c01ec4d368c98e11a611f40cd6672de" &
        "148b3bf435f812eda7e9e5d383ff2eefcf1384d136c45b1c062f731fc3414a237cf1b971994cced2b6852b3f43" &
        "14e9335fc96ba21fd8949c58f5c5";

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
      CA     : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (Reason_CA_DER), CryptoLib.ASN1.Default_Limits, Status);
      Leaf   : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (Reason_Leaf_DER), CryptoLib.ASN1.Default_Limits, Status);
      Second : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (Reason_Second_DER), CryptoLib.ASN1.Default_Limits,
           Status);
      List   : constant XC.Revocation_List :=
        XC.Decode_DER
          (From_Hex (Reason_CRL_DER), CryptoLib.ASN1.Default_Limits, Status);

      --  Inside the CRL's window: thisUpdate 2026-07-28, nextUpdate
      --  2026-08-27, both as OpenSSL wrote them.
      Inside : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 8, Day => 1,
         Hour => 12, Minute => 0, Second => 0);

      Scoped_CRL_DER : constant String :=
        "30820180306a020101300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d74657374" &
        "2d6361170d3236303732383232353330385a170d3236303832373232353330385aa020301e300f0603551d1c01" &
        "01ff040530038201ff300b0603551d14040402022000300d06092a864886f70d01010b050003820101003fdb81" &
        "9f241451c144f655f468651da90a1e5009fc9564925c5849a2d061025e1511cd0eddcbfa07b325b352dd79d06a" &
        "20fd8b3135aeea4cb32f879ac49a9bd23a21626bfe06baa9bd96a037245980741f4d66affe4b4319b0ed467b2e" &
        "32615986c25ff8c0b295df910e640ac08b7d2d5035120640265597f73dd1891f8895fe626b0fac8dbca132286b" &
        "e2a62e85e190d1e7d0d1bbaedf217a6494ed1efe86aea9953d900d2c08635fa8e027306c08a6da815215135f64" &
        "18bc8d84542ad6f12a7fe9d3488b5c0f1ef8746e062ce93d0a6add3ddeb512773690a347b59d05a18ecd0ea465" &
        "695e35231c67a5e38f5e24560a02d031f92143ce973aa48a0b41648a";

      From_List : CryptoLib.X509.Revocation_Details;
      From_OCSP : CryptoLib.X509.Revocation_Details;
   begin
      Check (Status = CryptoLib.ASN1.Errors.Ok and then XC.Is_Present (List),
             "fixture: the two-entry CRL decodes");
      Check (XC.Entry_Count (List) = 2,
             "the list revokes two certificates, got"
             & Natural'Image (XC.Entry_Count (List)));

      --  An entry that gives no reason. Has_Reason must stay False: an
      --  issuer that said nothing did not say "unspecified", and reading the
      --  default as a statement puts words in its mouth.
      declare
         Info : constant CryptoLib.X509.Revocation_Details :=
           XC.Find_Revocation (List, X509C.Serial_Number (Leaf));
      begin
         Check (Info.Present, "the first certificate is on the list");
         Check (Info.Revoked_At.Year = 2026
                and then Info.Revoked_At.Month = 7
                and then Info.Revoked_At.Day = 28
                and then Info.Revoked_At.Hour = 20
                and then Info.Revoked_At.Minute = 15
                and then Info.Revoked_At.Second = 47,
                "its revocation time is the one OpenSSL wrote");
         Check (not Info.Has_Reason,
                "it gives no reason, and none is invented");
      end;

      --  An entry that does give one.
      From_List := XC.Find_Revocation (List, X509C.Serial_Number (Second));
      Check (From_List.Present, "the second certificate is on the list too");
      Check (From_List.Revoked_At.Year = 2026
             and then From_List.Revoked_At.Month = 7
             and then From_List.Revoked_At.Day = 28
             and then From_List.Revoked_At.Hour = 22
             and then From_List.Revoked_At.Minute = 35
             and then From_List.Revoked_At.Second = 1,
             "with its own revocation time, not the other entry's");
      Check (From_List.Has_Reason
             and then From_List.Reason = CryptoLib.X509.Key_Compromise,
             "and the reason the issuer gave, "
             & CryptoLib.X509.Reason_Image (From_List.Reason));

      --  A serial the list says nothing about must not come back carrying
      --  some other entry's time.
      declare
         Info : constant CryptoLib.X509.Revocation_Details :=
           XC.Find_Revocation (List, X509C.Serial_Number (CA));
      begin
         Check (not Info.Present,
                "a certificate not on the list is not revoked");
         Check (Info.Revoked_At.Year = 0 and then not Info.Has_Reason,
                "and carries no time or reason from anyone else");
      end;

      --  The same two facts from an OCSP response about the same
      --  certificate. The two sources are parsed by different code and must
      --  land on the same answer; if they can disagree, one of them is wrong
      --  and a caller has no way to tell which.
      declare
         Reply : CO.Response :=
           CO.Decode_Response
             (From_Hex (Reason_Response_DER), CryptoLib.ASN1.Default_Limits,
              Status);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok,
                "fixture: the response decodes");
         Check (CO.Verify (Reply, Second, CA) = CO.Accepted,
                "the response is accepted before its contents are read");

         From_OCSP := CO.Revocation_Of (Reply);
         Check (From_OCSP.Present,
                "the response says when the revocation took effect");
         Check (From_OCSP.Revoked_At = From_List.Revoked_At,
                "and it is the time the CRL gave");
         Check (From_OCSP.Has_Reason = From_List.Has_Reason
                and then From_OCSP.Reason = From_List.Reason,
                "and the reason the CRL gave, "
                & CryptoLib.X509.Reason_Image (From_OCSP.Reason));
      end;

      --  The same, through the front door, which is where a caller lands.
      declare
         Reply  : CO.Response :=
           CO.Decode_Response
             (From_Hex (Reason_Response_DER), CryptoLib.ASN1.Default_Limits,
              Status);
         Detail : CryptoLib.X509.Revocation_Details;
         Answer : XR.Revocation_Answer;
      begin
         Answer :=
           XR.Check_Against_CRL (Second, CA, List, Inside, Detail);
         Check (Answer = XR.Revoked,
                "the list revokes it: " & XR.Answer_Image (Answer));
         Check (Detail.Present
                and then Detail.Reason = CryptoLib.X509.Key_Compromise,
                "and says why without a second lookup");

         Answer :=
           XR.Check_Against_OCSP (Second, CA, Reply, Inside, Detail);
         Check (Answer = XR.Revoked,
                "the response revokes it: " & XR.Answer_Image (Answer));
         Check (Detail.Present
                and then Detail.Reason = CryptoLib.X509.Key_Compromise,
                "and says why too");

         --  A certificate the statement does not revoke must leave the
         --  details empty rather than keep the last certificate's.
         Answer := XR.Check_Against_CRL (CA, CA, List, Inside, Detail);
         Check (Answer /= XR.Revoked,
                "the CA is not revoked by its own list");
         Check (not Detail.Present,
                "and no revocation details are left behind from the last "
                & "question");
      end;

      --  A CRL that says, critically, that it covers only part of what its
      --  issuer signed. It is properly signed, in its own window, and lists
      --  nothing -- so every other check passes and an absent serial reads
      --  as "not revoked". It is not: the list never covered end-entity
      --  certificates, and reading silence as absolution is how a revoked
      --  certificate keeps working.
      declare
         Scoped : constant XC.Revocation_List :=
           XC.Decode_DER
             (From_Hex (Scoped_CRL_DER), CryptoLib.ASN1.Default_Limits,
              Status);
         Detail : CryptoLib.X509.Revocation_Details;
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok
                and then XC.Is_Present (Scoped),
                "a scoped CRL still decodes -- it is well formed");
         Check (XC.Verify_Signature (Scoped, CA)
                = CryptoLib.X509.Signatures.Valid,
                "and its issuer really signed it");
         Check (XC.Entry_Count (Scoped) = 0,
                "and it lists nothing, which is the trap");

         Check (XC.Has_Unsupported_Critical_Extension (Scoped),
                "its critical scoping extension is noticed");

         --  The certificate this asks about is revoked on the real list.
         declare
            Answer : constant XR.Revocation_Answer :=
              XR.Check_Against_CRL (Leaf, CA, Scoped, Inside, Detail);
         begin
            Check (Answer = XR.Unsupported_Statement,
                   "so the list answers nothing rather than 'not revoked', "
                   & "got " & XR.Answer_Image (Answer));
            Check (not Detail.Present,
                   "and carries no revocation details either");
         end;

         --  The ordinary list is unaffected: this must refuse scoped CRLs,
         --  not CRLs.
         Check (not XC.Has_Unsupported_Critical_Extension (List),
                "an ordinary CRL carries nothing critical this cannot read");
         Check (XR.Check_Against_CRL (Leaf, CA, List, Inside, Detail)
                = XR.Revoked,
                "and still answers");
      end;
   end Check_Revocation_Details;

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

      --  For the separation check at the end.
      package XV renames CryptoLib.X509.Validation;

      type Revoked_Path is limited new XV.Path_Source with null record;

      overriding function Length (Source : Revoked_Path) return Positive
      is (2);

      overriding function Certificate_At
        (Source : Revoked_Path; Index : Positive) return X509C.Certificate
      is (if Index = 1
          then X509C.Decode_DER
                 (From_Hex (CRL_Leaf_DER), CryptoLib.ASN1.Default_Limits,
                  Status)
          else X509C.Decode_DER
                 (From_Hex (CRL_CA_DER), CryptoLib.ASN1.Default_Limits,
                  Status));

      overriding function Is_Trust_Anchor
        (Source : Revoked_Path; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Bytes (Item)
          = X509C.Subject_Bytes
              (X509C.Decode_DER
                 (From_Hex (CRL_CA_DER), CryptoLib.ASN1.Default_Limits,
                  Status)));
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
      --  Path validation does not consult revocation, and that is a
      --  decision rather than an oversight: the material has to come from
      --  somewhere, fetching it is the application's, and a validator that
      --  went to the network would make every validation a request that can
      --  hang. What it must not do is imply otherwise.
      --
      --  So: a certificate this very CRL revokes still passes Validate_Path.
      --  A caller reading a valid result as "not revoked" is reading
      --  something that was never checked, and the day Validate_Path starts
      --  consulting a CRL it did not receive, this check is what says so.
      declare
         use type XV.Validation_Failure;
         use type CryptoLib.X509.Revocation.Revocation_Answer;

         Inside : constant CryptoLib.X509.Certificate_Time :=
           (Year => 2026, Month => 8, Day => 1,
            Hour => 0, Minute => 0, Second => 0);

         Verdict : constant XV.Validation_Result :=
           XV.Validate_Path (Revoked_Path'(null record), Inside);
      begin
         --  The premise: the CRL really does revoke this certificate.
         Check (CryptoLib.X509.Revocation.Check_Against_CRL
                  (Leaf, CA, List, Inside)
                = CryptoLib.X509.Revocation.Revoked,
                "fixture: the list revokes the leaf");

         Check (Verdict.Valid,
                "and path validation still accepts it, because revocation "
                & "is not among the things it checks: "
                & XV.Failure_Image (Verdict.Failure));
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

      OCSP_Multi : constant String :=
        "308205310a0100a082052a3082052606092b060105050730010104820517308205133081e3a118301631143012" &
        "06035504030c0b63726c2d746573742d6361180f32303236303732383232313431375a3081b53061303b300906" &
        "052b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b24380aa8a0cd33" &
        "926e4452de852f02021000a111180f32303236303732383230313534375a180f32303236303732383232313431" &
        "375a3050303b300906052b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f" &
        "7e7b24380aa8a0cd33926e4452de852f020210018000180f32303236303732383232313431375a300d06092a86" &
        "4886f70d01010b0500038201010066d7702b438d1c953ceff5ac8fde94cdce5a59909635095ff97bc3ab45bfbd" &
        "9763ac36de742e8514e2ab4acd9f3e91fde41c95cf47a7ac51ece4d9b9ded05de39a5b5a2e1192414362342c9e" &
        "2f2e563f4750185010bcbaefc6836a83a2a23d1d9f6e6c863a26744dbb9447978d60825d4dfc3e87ab600cebb9" &
        "aeb2abd34fa64ebff72537c083d6f72d170ba198be581b430caabbc4b4b8d511044c41126cc632e1727d0ce983" &
        "11cf07b2cbacc47739b24ac76fc8f264a75bf7250139fc380e7e571c111a1c5f556576a65872cd7dfc0a9e973a" &
        "211551470034f4a01df0896f64e37a68031d8253755c2ef26ed4dc6598f3021e1fdd0cbe9214765e856736c0b2" &
        "a0820315308203113082030d308201f5a0030201020214695a2eb222fd6509af65d97b7099306d68b399eb300d" &
        "06092a864886f70d01010b050030163114301206035504030c0b63726c2d746573742d6361301e170d32363037" &
        "32383230313534375a170d3336303732353230313534375a30163114301206035504030c0b63726c2d74657374" &
        "2d636130820122300d06092a864886f70d01010105000382010f003082010a0282010100b5e60ee7058f7f9e99" &
        "1a038feeac5eb95d99b6b52f543a4cf379d9b84ab68125a82424b27f07a1f6a39f6f6e5ac4df194a06d3683faf" &
        "c31123427f768f6024aa6b2d5f759d0629a578497370038d70020ea20e261a913c332504d70327b2cd747a2ae0" &
        "f415764976ae21d8c34874405cfabefd83ffc5b03de5c6521a611c333189ead8755a0bf56113ad088deb953cf1" &
        "febb465a377d256bad055bf627727ccfffa616cfe8edc009a49f318a6c1e935dc42b69ab1d2aa9ee2173defdf4" &
        "5fbb595b99aced529fca129587fac967025980f7617070edde4748fa62cd395a608475ba22bd65c29f1fabdefe" &
        "5e8aeed28baa170388bca8bb6490db6bacea3473ed8f0203010001a3533051301d0603551d0e04160414a1f6d4" &
        "1f7e7b24380aa8a0cd33926e4452de852f301f0603551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e" &
        "4452de852f300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003820101005f484f" &
        "d12f7d522aa3787c0ee05c3e06067d91b3f51a3747e1ffcd7d57e839f17a9bfcf878faa9c4af435426aa06ed49" &
        "07dfb9c29ca36c6b53af27ce22516b5bd4cb19e9d912893e3800a1f7acc3abefbc18a6c899793b6ff9d378f2a7" &
        "7e0feb03659f8a2409bee7a4804773be1f8428608fb9041ac74581b1943d0d90dd2939be1b74015bcd676cf483" &
        "167988523fba452b255b49146d3c5be21408d8c9848f6794a4fa588ab2d6d326bc7d92920c3547d3f4d9270c01" &
        "ec4d368c98e11a611f40cd6672de148b3bf435f812eda7e9e5d383ff2eefcf1384d136c45b1c062f731fc3414a" &
        "237cf1b971994cced2b6852b3f4314e9335fc96ba21fd8949c58f5c5";

      OCSP_Second_DER : constant String :=
        "308202a43082018c02021001300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d74" &
        "6573742d6361301e170d3236303732383232313431375a170d3237303732383232313431375a30193117301506" &
        "035504030c0e7365636f6e642e6578616d706c6530820122300d06092a864886f70d01010105000382010f0030" &
        "82010a0282010100a169fd82209088be49800f464b442f6e1d1fdd823084ff0a76bfbc7ec44287274a752dba1d" &
        "1926442087bff21dd051ce99fdf42f8cb4b30426d8240f922287b089d4e37a4add7ba8181dfc701369be8291e5" &
        "7166ba7922d556eed539d1c2627b160cdd7c71ba8598319435dc4c2087d062ed23a84313fae6666f45b3050b88" &
        "46c8b8fc2fca5b4e5018545e10a3cb8c7cdfbfa133cadb29acd896362cafb931bdfb31b4be226ba91567d38499" &
        "84b6fc1f6f9211550ea01e522aeaf7523e23c59e22ed3fc55bbdcd1e4a7019ad93f5c2c8cb603d849af6c0c0d6" &
        "99147c7c0073baaf455e0259cf099305383c5bebcf32113e1d82db30e615de58a0eed56dbb5b37020301000130" &
        "0d06092a864886f70d01010b050003820101006066b5357a33b4941a2fd365f2792c297d6e82829fc3ac6bdd8c" &
        "fc5efe3861139b38592af36fd731af2ee9f4a09689f01604097636072dac2cb00a319eded804527a0631c7ef52" &
        "1f610c466cc33d8bdc9aaaf3e77b13b5ff004a51f837af3c6cba3ba6bf882e293e2d23a35c5654b4827341e1fd" &
        "3afd7be93bb546b93bdf0983a8cbdde40b23ffd240220362c028f824e44fa2792a6a5fee2af6878df9c401ffba" &
        "c2681e43effd2c225cc03b7bbb09affc9e1b962feef1da1dbc1f23597487d936c21e712fd4085290cc5f5eef03" &
        "237d417b683db649c246f384d9190d16873cb75c50abe79b62e349772306da7e154bc2655aa9306c63ea33ce84" &
        "0832a2c904";

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

      OCSP_Nonce_Request : constant String :=
        "30683066303f303d303b300906052b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414" &
        "a1f6d41f7e7b24380aa8a0cd33926e4452de852f02021000a2233021301f06092b060105050730010204120410" &
        "7fd8286787dd2b097e24bc1c0437e57b";

      OCSP_Nonce_Response : constant String :=
        "308205160a0100a082050f3082050b06092b0601050507300101048204fc308204f83081c8a118301631143012" &
        "06035504030c0b63726c2d746573742d6361180f32303236303732383232343130395a30763074303b30090605" &
        "2b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b24380aa8a0cd3392" &
        "6e4452de852f02021000a111180f32303236303732383230313534375a180f3230323630373238323234313039" &
        "5aa011180f32303236303832373232343130395aa1233021301f06092b0601050507300102041204107fd82867" &
        "87dd2b097e24bc1c0437e57b300d06092a864886f70d01010b0500038201010068b3c8fa8dde21a743f5eedd73" &
        "3a681dcbc6e188f739590f30dd2dc495cf9ead37f99b1f31ad0185ccb38fbf752de366d5b06a9c7dfbb3d75718" &
        "017343e06f71af78054f98fce4585277957e193cee24fe98c0417807d349efc09993533dd0b3daf47a73e63176" &
        "9b066f08e812af0ca47ac1630390166cb8120be2c1dc6a9f801e92495a1c44110fdd39524a72f7920ec2ecfa9e" &
        "459b7e0a774c87d8968e294acf799db314f391a612942210f53172d79367826822eb7d60db5c362a507aefd935" &
        "59913c5bc91e1a37e08cd5c258ed13166778accab6dd4d10b6de573acff07ac70b0b571845f7552b75fd924c38" &
        "02414f14b9e83fc0fd862856ee49a8db8c1aa0820315308203113082030d308201f5a0030201020214695a2eb2" &
        "22fd6509af65d97b7099306d68b399eb300d06092a864886f70d01010b050030163114301206035504030c0b63" &
        "726c2d746573742d6361301e170d3236303732383230313534375a170d3336303732353230313534375a301631" &
        "14301206035504030c0b63726c2d746573742d636130820122300d06092a864886f70d01010105000382010f00" &
        "3082010a0282010100b5e60ee7058f7f9e991a038feeac5eb95d99b6b52f543a4cf379d9b84ab68125a82424b2" &
        "7f07a1f6a39f6f6e5ac4df194a06d3683fafc31123427f768f6024aa6b2d5f759d0629a578497370038d70020e" &
        "a20e261a913c332504d70327b2cd747a2ae0f415764976ae21d8c34874405cfabefd83ffc5b03de5c6521a611c" &
        "333189ead8755a0bf56113ad088deb953cf1febb465a377d256bad055bf627727ccfffa616cfe8edc009a49f31" &
        "8a6c1e935dc42b69ab1d2aa9ee2173defdf45fbb595b99aced529fca129587fac967025980f7617070edde4748" &
        "fa62cd395a608475ba22bd65c29f1fabdefe5e8aeed28baa170388bca8bb6490db6bacea3473ed8f0203010001" &
        "a3533051301d0603551d0e04160414a1f6d41f7e7b24380aa8a0cd33926e4452de852f301f0603551d23041830" &
        "168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300f0603551d130101ff040530030101ff300d06092a" &
        "864886f70d01010b050003820101005f484fd12f7d522aa3787c0ee05c3e06067d91b3f51a3747e1ffcd7d57e8" &
        "39f17a9bfcf878faa9c4af435426aa06ed4907dfb9c29ca36c6b53af27ce22516b5bd4cb19e9d912893e3800a1" &
        "f7acc3abefbc18a6c899793b6ff9d378f2a77e0feb03659f8a2409bee7a4804773be1f8428608fb9041ac74581" &
        "b1943d0d90dd2939be1b74015bcd676cf483167988523fba452b255b49146d3c5be21408d8c9848f6794a4fa58" &
        "8ab2d6d326bc7d92920c3547d3f4d9270c01ec4d368c98e11a611f40cd6672de148b3bf435f812eda7e9e5d383" &
        "ff2eefcf1384d136c45b1c062f731fc3414a237cf1b971994cced2b6852b3f4314e9335fc96ba21fd8949c58f5" &
        "c5";

      OCSP_Critical_Response : constant String :=
        "308205280a0100a08205213082051d06092b06010505073001010482050e3082050a3081daa118301631143012" &
        "06035504030c0b63726c2d746573742d6361180f32303236303732383232343130395a30763074303b30090605" &
        "2b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b24380aa8a0cd3392" &
        "6e4452de852f02021000a111180f32303236303732383230313534375a180f3230323630373238323234313039" &
        "5aa011180f32303236303832373232343130395aa1353033301f06092b0601050507300102041204107fd82867" &
        "87dd2b097e24bc1c0437e57b301006092b06010505073001630101ff0400300d06092a864886f70d01010b0500" &
        "03820101003829713f5834725861c9a813a729eb5d4f91bf175b0f9b9611c4638e749525a353a9d0827a5c8333" &
        "09b7bb9cf75266a4a780b7d714d278705e1ff85014ae083a8bdf55064d0951684cbc3362473663c3c01d8d70d4" &
        "6ede6b058933f8d112baa790cf4c2ebe41636538e07edeec0ea0895b65de3dcbbe5204ec0baef590fb2a2a70be" &
        "4c914261d40f3db0df8d05a3d3c841cf4e47d77acd4d724c0c73a0e3486454b7253ef2239a57337c3f1bdab14f" &
        "3e6a4fc7d5182b9b17ef6946302e9ecca58c3fa2a37aff28d87d1948762ad60f0bc94f1e3fb09573250f7c7895" &
        "3eded381b7f7d81c968e32255a2809580349421faf29cbe3eb26ce784e5e9e3a62d469ada08203153082031130" &
        "82030d308201f5a0030201020214695a2eb222fd6509af65d97b7099306d68b399eb300d06092a864886f70d01" &
        "010b050030163114301206035504030c0b63726c2d746573742d6361301e170d3236303732383230313534375a" &
        "170d3336303732353230313534375a30163114301206035504030c0b63726c2d746573742d636130820122300d" &
        "06092a864886f70d01010105000382010f003082010a0282010100b5e60ee7058f7f9e991a038feeac5eb95d99" &
        "b6b52f543a4cf379d9b84ab68125a82424b27f07a1f6a39f6f6e5ac4df194a06d3683fafc31123427f768f6024" &
        "aa6b2d5f759d0629a578497370038d70020ea20e261a913c332504d70327b2cd747a2ae0f415764976ae21d8c3" &
        "4874405cfabefd83ffc5b03de5c6521a611c333189ead8755a0bf56113ad088deb953cf1febb465a377d256bad" &
        "055bf627727ccfffa616cfe8edc009a49f318a6c1e935dc42b69ab1d2aa9ee2173defdf45fbb595b99aced529f" &
        "ca129587fac967025980f7617070edde4748fa62cd395a608475ba22bd65c29f1fabdefe5e8aeed28baa170388" &
        "bca8bb6490db6bacea3473ed8f0203010001a3533051301d0603551d0e04160414a1f6d41f7e7b24380aa8a0cd" &
        "33926e4452de852f301f0603551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300f0603" &
        "551d130101ff040530030101ff300d06092a864886f70d01010b050003820101005f484fd12f7d522aa3787c0e" &
        "e05c3e06067d91b3f51a3747e1ffcd7d57e839f17a9bfcf878faa9c4af435426aa06ed4907dfb9c29ca36c6b53" &
        "af27ce22516b5bd4cb19e9d912893e3800a1f7acc3abefbc18a6c899793b6ff9d378f2a77e0feb03659f8a2409" &
        "bee7a4804773be1f8428608fb9041ac74581b1943d0d90dd2939be1b74015bcd676cf483167988523fba452b25" &
        "5b49146d3c5be21408d8c9848f6794a4fa588ab2d6d326bc7d92920c3547d3f4d9270c01ec4d368c98e11a611f" &
        "40cd6672de148b3bf435f812eda7e9e5d383ff2eefcf1384d136c45b1c062f731fc3414a237cf1b971994cced2" &
        "b6852b3f4314e9335fc96ba21fd8949c58f5c5";

      OCSP_Critical_Single : constant String :=
        "3082052e0a0100a08205273082052306092b060105050730010104820514308205103081e0a118301631143012" &
        "06035504030c0b63726c2d746573742d6361180f32303236303732383232343130395a30818d30818a303b3009" &
        "06052b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b24380aa8a0cd" &
        "33926e4452de852f02021000a111180f32303236303732383230313534375a180f323032363037323832323431" &
        "30395aa011180f32303236303832373232343130395aa1143012301006092b06010505073001630101ff0400a1" &
        "233021301f06092b0601050507300102041204107fd8286787dd2b097e24bc1c0437e57b300d06092a864886f7" &
        "0d01010b050003820101006a2c78c204cb36d61eac84655d9d60c9276097853ed6298d3eb8c2850703fc5365de" &
        "acc2dbfaa02fa9b31ab5e868c6456d59e243a9ab558e6adeaabc7ac53c92ce56b249b89fd6a6ff6e7bb4ad23e2" &
        "f4332605251d744da2efc49a06abb62b91ae75acd78f1a597ada5c62988b9871de7d995787a5212e32a75221ed" &
        "08dbb8b4723db228d2df8d85700acb7cca6019d43c4f0230f9081ae2c1771c455e7eaa4fdc846e9a5b7a668ba3" &
        "0bf6944c643aa854d239419b1c917cbc874f7b9f4aed7e670fece44acde038281f0150bf981519062f1e2ddcbd" &
        "a0187d55c26e4fbe8ed5950f46597969b82d6f85d39de60074f19fb262e424d728db7a3bf76d6053f17ca08203" &
        "15308203113082030d308201f5a0030201020214695a2eb222fd6509af65d97b7099306d68b399eb300d06092a" &
        "864886f70d01010b050030163114301206035504030c0b63726c2d746573742d6361301e170d32363037323832" &
        "30313534375a170d3336303732353230313534375a30163114301206035504030c0b63726c2d746573742d6361" &
        "30820122300d06092a864886f70d01010105000382010f003082010a0282010100b5e60ee7058f7f9e991a038f" &
        "eeac5eb95d99b6b52f543a4cf379d9b84ab68125a82424b27f07a1f6a39f6f6e5ac4df194a06d3683fafc31123" &
        "427f768f6024aa6b2d5f759d0629a578497370038d70020ea20e261a913c332504d70327b2cd747a2ae0f41576" &
        "4976ae21d8c34874405cfabefd83ffc5b03de5c6521a611c333189ead8755a0bf56113ad088deb953cf1febb46" &
        "5a377d256bad055bf627727ccfffa616cfe8edc009a49f318a6c1e935dc42b69ab1d2aa9ee2173defdf45fbb59" &
        "5b99aced529fca129587fac967025980f7617070edde4748fa62cd395a608475ba22bd65c29f1fabdefe5e8aee" &
        "d28baa170388bca8bb6490db6bacea3473ed8f0203010001a3533051301d0603551d0e04160414a1f6d41f7e7b" &
        "24380aa8a0cd33926e4452de852f301f0603551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de" &
        "852f300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003820101005f484fd12f7d" &
        "522aa3787c0ee05c3e06067d91b3f51a3747e1ffcd7d57e839f17a9bfcf878faa9c4af435426aa06ed4907dfb9" &
        "c29ca36c6b53af27ce22516b5bd4cb19e9d912893e3800a1f7acc3abefbc18a6c899793b6ff9d378f2a77e0feb" &
        "03659f8a2409bee7a4804773be1f8428608fb9041ac74581b1943d0d90dd2939be1b74015bcd676cf483167988" &
        "523fba452b255b49146d3c5be21408d8c9848f6794a4fa588ab2d6d326bc7d92920c3547d3f4d9270c01ec4d36" &
        "8c98e11a611f40cd6672de148b3bf435f812eda7e9e5d383ff2eefcf1384d136c45b1c062f731fc3414a237cf1" &
        "b971994cced2b6852b3f4314e9335fc96ba21fd8949c58f5c5";

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

      --  A responder may answer about several certificates at once, so the
      --  reply has to be searched rather than its first entry taken. Asking
      --  about the second certificate in this reply used to give
      --  Wrong_Certificate -- fail-closed, but an answer that was there and
      --  was not found.
      declare
         Second : constant X509C.Certificate :=
           X509C.Decode_DER
             (From_Hex (OCSP_Second_DER), CryptoLib.ASN1.Default_Limits,
              Status);
         First_Item : CO.Response :=
           CO.Decode_Response
             (From_Hex (OCSP_Multi), CryptoLib.ASN1.Default_Limits, Status);
         Second_Item : CO.Response :=
           CO.Decode_Response
             (From_Hex (OCSP_Multi), CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok,
                "a reply covering two certificates decodes");

         Check (CO.Verify (First_Item, Leaf, CA) = CO.Accepted,
                "the first certificate is answered, got "
                & CO.Result_Image (CO.Verify (First_Item, Leaf, CA)));
         Check (CO.Certificate_Status_Of (First_Item) = CO.Revoked,
                "and it is the revoked one");

         Check (CO.Verify (Second_Item, Second, CA) = CO.Accepted,
                "the second certificate is answered too, got "
                & CO.Result_Image (CO.Verify (Second_Item, Second, CA)));
         Check (CO.Certificate_Status_Of (Second_Item) = CO.Good,
                "and it is good -- the status is its own rather than the "
                & "first entry's");
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

      --  A nonce ties a response to the question that was asked. Without one
      --  a response stands on its own for as long as it is current, so an
      --  answer captured before a certificate was revoked can be presented
      --  again afterwards and still check out.
      declare
         Sent : constant Ada.Streams.Stream_Element_Array :=
           From_Hex ("7fd8286787dd2b097e24bc1c0437e57b");
         Other : constant Ada.Streams.Stream_Element_Array :=
           From_Hex ("00112233445566778899aabbccddeeff");
         Built : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CO.Maximum_Request_Length));
         Last  : Ada.Streams.Stream_Element_Offset;
         St    : CryptoLib.ASN1.Errors.Decode_Status;
         Want  : constant Ada.Streams.Stream_Element_Array :=
           From_Hex (OCSP_Nonce_Request);
      begin
         --  Same certificate, same nonce, same bytes OpenSSL writes. The
         --  nonce sits in requestExtensions with its value wrapped twice --
         --  an OCTET STRING inside the extension's OCTET STRING -- and
         --  getting that nesting wrong produces a request a responder reads
         --  as carrying no nonce at all.
         CO.Build_Request (Leaf, CA, Built, Last, St, Sent);
         Check (St = CryptoLib.ASN1.Errors.Ok,
                "a request carrying a nonce is built");
         Check (Built (Built'First .. Last) = Want,
                "and is byte-identical to the one OpenSSL builds");

         --  RFC 8954 bounds the nonce at 32 octets. A longer one is refused
         --  rather than truncated: a truncated nonce is a different nonce,
         --  and the caller would compare against what it meant to send.
         declare
            Too_Long : constant Ada.Streams.Stream_Element_Array
              (1 .. CO.Maximum_Nonce_Length + 1) := [others => 16#41#];
         begin
            CO.Build_Request (Leaf, CA, Built, Last, St, Too_Long);
            Check (St /= CryptoLib.ASN1.Errors.Ok,
                   "an over-long nonce is refused rather than trimmed");
         end;

         declare
            Reply : CO.Response :=
              CO.Decode_Response
                (From_Hex (OCSP_Nonce_Response),
                 CryptoLib.ASN1.Default_Limits, Status);
            Plain : CO.Response :=
              CO.Decode_Response
                (From_Hex (OCSP_Direct), CryptoLib.ASN1.Default_Limits,
                 Status);
         begin
            Check (Status = CryptoLib.ASN1.Errors.Ok,
                   "fixture: the response decodes");
            Check (CO.Has_Nonce (Reply),
                   "the responder echoed a nonce");
            Check (CO.Nonce (Reply) = Sent,
                   "and it is the nonce that was sent");

            Check (CO.Verify (Reply, Leaf, CA, Sent) = CO.Accepted,
                   "a response carrying the nonce sent is accepted, got "
                   & CO.Result_Image (CO.Verify (Reply, Leaf, CA, Sent)));

            --  The whole point: a well-formed, correctly signed, current
            --  response that answers the wrong question is refused.
            Check (CO.Verify (Reply, Leaf, CA, Other) = CO.Nonce_Mismatch,
                   "a response carrying a different nonce is refused, got "
                   & CO.Result_Image (CO.Verify (Reply, Leaf, CA, Other)));

            --  Missing is reported apart from mismatched, because a
            --  responder serving pre-signed answers omits the nonce as a
            --  matter of course and a caller may decide to live with that.
            Check (CO.Verify (Plain, Leaf, CA, Sent) = CO.Nonce_Missing,
                   "a response carrying no nonce is reported as missing, got "
                   & CO.Result_Image (CO.Verify (Plain, Leaf, CA, Sent)));

            --  A caller that sent no nonce has nothing to compare against,
            --  and demanding one anyway would refuse every stapled response.
            Check (CO.Verify (Reply, Leaf, CA) = CO.Accepted,
                   "checking no nonce still accepts a response that has one");
            Check (CO.Verify (Plain, Leaf, CA) = CO.Accepted,
                   "and one that has none");
         end;
      end;

      --  A critical extension is the responder saying that ignoring it
      --  changes what the response means. Both fixtures are genuinely
      --  signed -- OpenSSL reports "Response verify OK" on each -- and
      --  differ from the accepted response above only by carrying one
      --  unrecognised critical extension, so nothing but this check stands
      --  between them and being read as ordinary answers.
      declare
         In_Response : CO.Response :=
           CO.Decode_Response
             (From_Hex (OCSP_Critical_Response),
              CryptoLib.ASN1.Default_Limits, Status);
         In_Entry : CO.Response :=
           CO.Decode_Response
             (From_Hex (OCSP_Critical_Single),
              CryptoLib.ASN1.Default_Limits, Status);
         Clean : CO.Response :=
           CO.Decode_Response
             (From_Hex (OCSP_Nonce_Response), CryptoLib.ASN1.Default_Limits,
              Status);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok,
                "fixtures carrying critical extensions still decode");

         --  In the response's own extensions.
         Check (CO.Has_Unsupported_Critical_Extension (In_Response),
                "a critical extension on the response is noticed");
         Check (CO.Verify (In_Response, Leaf, CA) = CO.Unsupported_Extension,
                "and the response is refused, got "
                & CO.Result_Image (CO.Verify (In_Response, Leaf, CA)));

         --  And in the entry about this certificate. These sit behind an
         --  optional nextUpdate, so a reader that peeks at nextUpdate
         --  without stepping over it never reaches them at all.
         Check (CO.Has_Unsupported_Critical_Extension (In_Entry),
                "a critical extension on the entry is noticed too");
         Check (CO.Verify (In_Entry, Leaf, CA) = CO.Unsupported_Extension,
                "and that response is refused as well, got "
                & CO.Result_Image (CO.Verify (In_Entry, Leaf, CA)));

         --  This must refuse those responses, not responses.
         Check (not CO.Has_Unsupported_Critical_Extension (Clean),
                "an ordinary response carries nothing critical this cannot "
                & "read");
         Check (CO.Verify (Clean, Leaf, CA) = CO.Accepted,
                "and is still accepted");
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

      --  An RSA identity, which is what most servers are configured with.
      --  Matching one needs no derivation: an RSA private key carries its own
      --  modulus and exponent, so the question is a comparison against the
      --  two integers in the certificate.
      declare
      RSA_Leaf_PEM : constant String :=
        "-----BEGIN CERTIFICATE-----" & ASCII.LF &
        "MIICuDCCAaACFAppZCkVsFVYh/Q8rXNvWMAD5p3rMA0GCSqGSIb3DQEBDAUAMBYx" & ASCII.LF &
        "FDASBgNVBAMMC3JzYS10ZXN0LWNhMB4XDTI2MDcyODE5MDMyNFoXDTI3MDcyODE5" & ASCII.LF &
        "MDMyNFowGzEZMBcGA1UEAwwQbGVhZi5yc2EuZXhhbXBsZTCCASIwDQYJKoZIhvcN" & ASCII.LF &
        "AQEBBQADggEPADCCAQoCggEBAL0PmgpIoMyy+119Tl2IuJmaZBQosmMiazvJqC+A" & ASCII.LF &
        "w1Q/35AsX4a+lnnloFwXtCFvvfRhFXxOLSgHuXLfQFa1cu4UWCpQQL+NLcp7ymXu" & ASCII.LF &
        "6XR89USlUNtR1sz2NXaM+g4ufTZ6fN7HBaCrCMv9dUrD6LtXUhL37zDecH//mkrA" & ASCII.LF &
        "PWtpm6FwRJv/KJgHODwv/kSLRG6UEtFik1Phro/L/9+HF3EULATMzrJUqdovR8HT" & ASCII.LF &
        "1KYDgU4CldGjOjZkw6ZoxmV+3L2d+pNT1F7kP4I98UPdALnr8qfWnLZBh76DoDWc" & ASCII.LF &
        "Czdvm4NfrunInxLrVqNB81lcYJIgpzs1AqpyPz83GUxlWLsCAwEAATANBgkqhkiG" & ASCII.LF &
        "9w0BAQwFAAOCAQEARn/i3pR71kW0nZ1kCb46LS1WiELjUdofM2XcU6/31LHTDsh7" & ASCII.LF &
        "Lc2QuuZuFLk03b5OFEUvawoaMKybtJpPQOJvSuJGvKyfFRNIgnRneWJmpPfM09za" & ASCII.LF &
        "Ubf/AnjZmyZMxJHthFm+4ap3/BEFoPRpVC38c7TwUS3LYl+P3Yp2Ihh5DXpPUiCU" & ASCII.LF &
        "A4yX4mbW3k8iRgcETeyLHtORF2x0fzrulKjD8zdxFFFwsehba9JbMU8w6DhpXLX0" & ASCII.LF &
        "QYt6k0zCkr0tqwxnSjA97/uXvtptXb/K5V/WRK+mbbfUxbz8PKwan6zkWBjwT9Hu" & ASCII.LF &
        "/RjLDgPBgAA6BeNlZY3XkYFFz3w4MSz1sdeVew==" & ASCII.LF &
        "-----END CERTIFICATE-----";

      RSA_Leaf_Key : constant String :=
        "-----BEGIN PRIVATE KEY-----" & ASCII.LF &
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC9D5oKSKDMsvtd" & ASCII.LF &
        "fU5diLiZmmQUKLJjIms7yagvgMNUP9+QLF+GvpZ55aBcF7Qhb730YRV8Ti0oB7ly" & ASCII.LF &
        "30BWtXLuFFgqUEC/jS3Ke8pl7ul0fPVEpVDbUdbM9jV2jPoOLn02enzexwWgqwjL" & ASCII.LF &
        "/XVKw+i7V1IS9+8w3nB//5pKwD1raZuhcESb/yiYBzg8L/5Ei0RulBLRYpNT4a6P" & ASCII.LF &
        "y//fhxdxFCwEzM6yVKnaL0fB09SmA4FOApXRozo2ZMOmaMZlfty9nfqTU9Re5D+C" & ASCII.LF &
        "PfFD3QC56/Kn1py2QYe+g6A1nAs3b5uDX67pyJ8S61ajQfNZXGCSIKc7NQKqcj8/" & ASCII.LF &
        "NxlMZVi7AgMBAAECggEASWRiFvXkvjII1F0Na8/kYXSGvzChN0yoNhhtWqtwqCb3" & ASCII.LF &
        "gX9IQgWAYqeaXcWx3n0DT3fUoGG0s+Jzwj0aO87KY9Ov+hUXXYTPrtfpVTKum9La" & ASCII.LF &
        "X6CRR+J4MS6uyGunspOndduM1+qIq7tZed7VhoWQthEKwmRPDTh8kaPG4JfKAATe" & ASCII.LF &
        "yXaIJYxuwc1UvAyL23hlw2yLRtAzbpGC6W4MlK82JPMYRMhm8vauFktU3gigKBjc" & ASCII.LF &
        "9n10vwsMd5H8qU8jFS6knhiboQS2tnsrp0vyNDmILWxywtkm3nDK1xYDfzfP2Efb" & ASCII.LF &
        "QuM5SPXz0p0Nr7f487gdv63nF84oB82/EejrmQlGeQKBgQDvBtpMjhOSMhoIvtQJ" & ASCII.LF &
        "/QHcyEJUif2ybR/A1oAu0//qWGlYoY6liLBHsphffcfw0dXS71I/bAOxehtqjSN6" & ASCII.LF &
        "rbtfYw4Mg/GCDkiyHfM54Rn2nS3JKFgAvG6LQDBw/WbucKocGhlLA7Z20+ORCkgA" & ASCII.LF &
        "JMGPn2Kr/6IQ+vZSEhBBpCT3RQKBgQDKfHIHlw5j/iQZ6XAKNywsad7sUj8m2R+Y" & ASCII.LF &
        "dwE7tc7FxeQJ9TPhLpOUGuqlUPta+Lmo8VC4pGUleQjGUGe3M8Q8fleaUuE+FljR" & ASCII.LF &
        "BGFSXd01QCqk3w8Zerz8orPMdsC6mxVHHTe8zIzPqQzR+grrMFPXOB3RoyUQMgRd" & ASCII.LF &
        "ejC3+x4P/wKBgDYVmd2KpFkHJyblbvsXmY1IbuHMG3B9CptKrdRqudRfzu50F9/S" & ASCII.LF &
        "zvhaK+onfs8526UP689X9Hn7BCsW5nlCyEvsEOi6DjJ8YuySpE9rZMGNjSegDlGU" & ASCII.LF &
        "UXsGui9G1zyKl6MmMKTtoSLADRTre6E0r+t8iAodHKG093lYhv8jUg31AoGAMcCo" & ASCII.LF &
        "KBNGtu0QI8nG/MuXsAYHf1uqJrp81/KNvAUtHE1Gfefg6niOTHrcougmCrFItSku" & ASCII.LF &
        "I2BJdg6qSEgjY9F1a0PD9KherenBwwHng9yKaPYuRDqGtEUDQLQdp6SaMH/Al6un" & ASCII.LF &
        "MV21T6UDAGkG28kRILWqJgOHLNaNWgaXB+3M8jMCgYAleeSjeMEtygS6DnysgsDy" & ASCII.LF &
        "oXP1zYgSmCnpSiK/DkiL+yaoTQf+KxFdxxAZPEmeWD+VW4p2vzOvhWhJq6f87EoF" & ASCII.LF &
        "ArUwd/weVJXE9H+qGuqoIpJ/CnvIPRkzPGm9DxsY95w7DkLgn6tvz8OWfNU1+Sg4" & ASCII.LF &
        "K7QNFJW77PZJbezJ2ZRh6g==" & ASCII.LF &
        "-----END PRIVATE KEY-----";

      RSA_Other_Key : constant String :=
        "-----BEGIN PRIVATE KEY-----" & ASCII.LF &
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCnqIxwFIbJAdX0" & ASCII.LF &
        "kudx7n6KPClXjH89E0vsXbw0EhUksfU9B2UNOk75v1omI3FgfTk8pKLvS9LxkZPR" & ASCII.LF &
        "gIDJctkHfRNhJvvqD9psM8It9JIWtBW8fCgh072IFEQIjlA8+Af99PG5O4OEHlzm" & ASCII.LF &
        "dJT1dkP7Do838wt36s/TWLGOiBxm2J98omFWCOiWPhvpxVHpXXSxKXgVX2edtpa1" & ASCII.LF &
        "OHpoTLrBcgNYYDUMeldkgEIKqEQ9s4G5jgkyoPpP/7GWDx+WsGuRFD/zN+Q9aCbC" & ASCII.LF &
        "KIYVdqLHpUkbDS/EyMMEUiguhDzQ/EpahN9/XhMmTe66bC1sS3kux6CgD2N3DV4a" & ASCII.LF &
        "xjnR2hKfAgMBAAECggEABe1JCa1JsB46GHgZA0erF+siJJyS4u9yGUKdcWz/BY0R" & ASCII.LF &
        "xLzxYl/tUTOyiPNrAdfR1JL9YsULb/7CR8wcwWjBKcKbxmBA1F8H5n6HhTH5xO1M" & ASCII.LF &
        "Cp2/ZwxVM7pQejAnWTOerk7UCZHqoRqk4U2KkCLeKsHlzjrvuacgMbIXYZjuNOex" & ASCII.LF &
        "nkAz0OFf4ogHiplsSBsA7oeL34ZDlg/QFHlss531Mo5WESJEwVhe1kW4vhW9NyOI" & ASCII.LF &
        "lFpBAfs8Xr7PEL8XEoIagTNi3h3SR8QtReSfflWrSuUPCHQ4GpFs2EnUb/7OGrAH" & ASCII.LF &
        "RynjnZ0yNEtcYwrei0wPjdizlGpTvIAHIlsOuzaaAQKBgQDj+p1vdDML8v1o8SyF" & ASCII.LF &
        "+0P7d4cTwNaWoZQD95oaaO4Rj2GTvxJLoVF0/LnyEtuyFLQsKccP+4/mfYuV6n4E" & ASCII.LF &
        "Q9qkQdgXnHRhr1tArLQ9b7s9UCsE2ShxbQlgestNM06oW+keE3nvGCUX6xEP1KhI" & ASCII.LF &
        "yrHIWzRau4UN32LgGAxxue26wwKBgQC8Q/CP0VmqtA7KXwgf6nc8xLg50zzN2uAg" & ASCII.LF &
        "aR7zxZ4KYFkHs5wcpMJSpMu5n+w0zbApMtLBw4D+kILY4/3bJZ9NTx1Ml7+TnfSm" & ASCII.LF &
        "vTNVwc1tLvPdoyAV0FR9C0OuZ2dK7BZ93pq4afYsN0ODfmwG9JVPM4wLKV5LpQpE" & ASCII.LF &
        "dysqDW7y9QKBgETiQpOcjpf7san1xTgudZoTwZKsX6pf4/NW6w8zyUsxAZC82PBV" & ASCII.LF &
        "K+GnQx/rpsomC1KUxPsFTbOdF4ISukTbo8KhyoNH2LpzW6UtCcDOc8rQ4E60ts2e" & ASCII.LF &
        "3ohyUd9fs1KXgtZ9mAgwSXTyp9MatEZaSGF7fVQ0+Lz6VEvVuFzciwI1AoGBAJLu" & ASCII.LF &
        "QzU7IkwDsvdmK6UdDGo07cLThcTzabBh2nJObQWUJGfKWbBRNgfh7c21blfXoADH" & ASCII.LF &
        "VY0709TZXAWCCoGaXzWq5Sb919qRkHsBdqsbUgRAfLshsMzVhtsAi5X1xbvHfdZG" & ASCII.LF &
        "gWIj8KiZiOt7Izxabp0dkdK0Oo+3AshkaR+s1EZxAoGBAKqCwAIH+HU0YF7MmjK0" & ASCII.LF &
        "lJKGNKoy7WhxA4RESQkWv5Zet9i0sqPlz5ajKDZRcJBWBaxLIZo9oolXUlJltdfN" & ASCII.LF &
        "5kgKVRcPV00ThGuuZKUHpSURmZS+iP0i6Rrx51ZKdb/T+Jf0CU2vPauaxcZ17ekc" & ASCII.LF &
        "k3VQLvwKPdHckJ89GRA83oLh" & ASCII.LF &
        "-----END PRIVATE KEY-----";
         Item : ID.Local_Identity;
         St   : ID.Identity_Status;
      begin
         ID.Decode (RSA_Leaf_PEM, RSA_Leaf_Key, Item, St);
         Check (St = ID.Ok,
                "an RSA certificate and its own key check out, got "
                & ID.Status_Image (St));
         Check (ID.Key_Algorithm_Of (Item) = CryptoLib.X509.RSA,
                "and the key is reported as RSA");

         --  A different RSA key of the same size. The failure has to be a
         --  mismatch rather than an inability to tell, or a caller cannot
         --  distinguish "wrong key" from "not checked".
         ID.Decode (RSA_Leaf_PEM, RSA_Other_Key, Item, St);
         Check (St = ID.Key_Mismatch,
                "another RSA key of the same size is a mismatch, not an "
                & "unchecked identity, got " & ID.Status_Image (St));
      end;

      --  The other two curves. Matching these needs the public point
      --  derived from the scalar, which is the same arithmetic on all three
      --  and was only ever offered for one of them.
      declare
         P256_Leaf : constant String :=
           "-----BEGIN CERTIFICATE-----" & ASCII.LF &
           "MIIBKDCBzwIUDNb25fQiF6PjOrD6qfSpFj2KY5EwCgYIKoZIzj0EAwIwEjEQMA4G" & ASCII.LF &
           "A1UEAwwHcDI1Ni1jYTAeFw0yNjA3MjgxOTExMzFaFw0yNzA3MjgxOTExMzFaMBwx" & ASCII.LF &
           "GjAYBgNVBAMMEWxlYWYucDI1Ni5leGFtcGxlMFkwEwYHKoZIzj0CAQYIKoZIzj0D" & ASCII.LF &
           "AQcDQgAEjQ6HgkMnOkYjt9ywJo2fiNj4nvi+jFMmxbbWvAVuYcWfaCXlXIMKEkwz" & ASCII.LF &
           "LUIDfkxvRTO4aP8CoDpkCpA6Vzc6TDAKBggqhkjOPQQDAgNIADBFAiEAkXYM7UH4" & ASCII.LF &
           "P7G31aw72aKYI9Phky02Lx1WmDcfIrvz1pICIEtkjpugplNQ62ZgEfUl4k+00f1s" & ASCII.LF &
           "p71JQPavUV5SbzxV" & ASCII.LF &
           "-----END CERTIFICATE-----";

         P256_Key : constant String :=
           "-----BEGIN PRIVATE KEY-----" & ASCII.LF &
           "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgyfvjdmW+qhTmVjFM" & ASCII.LF &
           "vLt3ubIrMpcVGK7QvaHIqobtI4ihRANCAASNDoeCQyc6RiO33LAmjZ+I2Pie+L6M" & ASCII.LF &
           "UybFtta8BW5hxZ9oJeVcgwoSTDMtQgN+TG9FM7ho/wKgOmQKkDpXNzpM" & ASCII.LF &
           "-----END PRIVATE KEY-----";

         P256_Alt : constant String :=
           "-----BEGIN PRIVATE KEY-----" & ASCII.LF &
           "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZ1wL8wt312RjJ85J" & ASCII.LF &
           "skUbZx0VurwfmgPMLk32oYqWeu+hRANCAATYB8yQPFjLsmtkyPJTkNw4inikSlxR" & ASCII.LF &
           "ICjnFj/zr+knrgoWNbHCtEcNHKkl08X0RLqOQ1Jt10iN3XcMlDQhJqjY" & ASCII.LF &
           "-----END PRIVATE KEY-----";

         P521_Leaf : constant String :=
           "-----BEGIN CERTIFICATE-----" & ASCII.LF &
           "MIIBsTCCARICFB0q89Xz7gyESR358e7GIzg9InzhMAoGCCqGSM49BAMCMBIxEDAO" & ASCII.LF &
           "BgNVBAMMB3A1MjEtY2EwHhcNMjYwNzI4MTkxMTMxWhcNMjcwNzI4MTkxMTMxWjAc" & ASCII.LF &
           "MRowGAYDVQQDDBFsZWFmLnA1MjEuZXhhbXBsZTCBmzAQBgcqhkjOPQIBBgUrgQQA" & ASCII.LF &
           "IwOBhgAEAWeV2y073JLStpmKqOgllO86I0HGwH1rufdQgsEpCmnQ96hipf/+jdqi" & ASCII.LF &
           "DUvSoS6vDKIxrN7+icu/TPKxAIF482OfAAmK76cP29aM0LUHbuX6yC6oya4GfaRg" & ASCII.LF &
           "m3VmkUszvKW1Hdkf4D+WEde13jgxn2/fWc0dHLMlEC1WLLEpQvSa0g8MMAoGCCqG" & ASCII.LF &
           "SM49BAMCA4GMADCBiAJCAIowN9YZvYhNDpT1czUiM++cbk8KGHXAvFYnN6C3ErnT" & ASCII.LF &
           "TrAgX9ZBBhcnPIIhiEc7R+ARydGZrwSHWL1WNEMy0YL6AkIAqL87ZPB5Qk6QUML9" & ASCII.LF &
           "yj2fVE7rOSzy1WyjlLFCdWlv+97luri69Fc+4XqRFhC2GFz7IwNF9eeMbeEvGeU/" & ASCII.LF &
           "70Nhi3Y=" & ASCII.LF &
           "-----END CERTIFICATE-----";

         P521_Key : constant String :=
           "-----BEGIN PRIVATE KEY-----" & ASCII.LF &
           "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAIgx2sfzzwK3Wolda" & ASCII.LF &
           "+75K1hINe6fq3ZD6xKeEZCR2kaH9AJ0h8JrV1elkLILJWLBawH1UcvMaUp/rTpSZ" & ASCII.LF &
           "MRjU2aWhgYkDgYYABAFnldstO9yS0raZiqjoJZTvOiNBxsB9a7n3UILBKQpp0Peo" & ASCII.LF &
           "YqX//o3aog1L0qEurwyiMaze/onLv0zysQCBePNjnwAJiu+nD9vWjNC1B27l+sgu" & ASCII.LF &
           "qMmuBn2kYJt1ZpFLM7yltR3ZH+A/lhHXtd44MZ9v31nNHRyzJRAtViyxKUL0mtIP" & ASCII.LF &
           "DA==" & ASCII.LF &
           "-----END PRIVATE KEY-----";
         Item : ID.Local_Identity;
         St   : ID.Identity_Status;
      begin
         ID.Decode (P256_Leaf, P256_Key, Item, St);
         Check (St = ID.Ok,
                "a P-256 certificate and its own key check out, got "
                & ID.Status_Image (St));
         Check (ID.Key_Algorithm_Of (Item) = CryptoLib.X509.ECDSA_P256,
                "and the curve is reported");

         ID.Decode (P521_Leaf, P521_Key, Item, St);
         Check (St = ID.Ok,
                "a P-521 certificate and its own key check out, got "
                & ID.Status_Image (St));

         --  A different key on the same curve, which is the case that needs
         --  the derivation rather than a look at the algorithm.
         ID.Decode (P256_Leaf, P256_Alt, Item, St);
         Check (St = ID.Key_Mismatch,
                "another P-256 key is a mismatch, not an unchecked identity, "
                & "got " & ID.Status_Image (St));

         --  A key from a different curve fails earlier, on the algorithm.
         ID.Decode (P256_Leaf, P521_Key, Item, St);
         Check (St = ID.Key_Mismatch,
                "a key from another curve does not match either");
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
           Bundle, Iterations => 4_096);
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


   --  A constrained CA, and the certificates it may and may not certify.
   --
   --  The extension is normally critical, and until it was enforced a chain
   --  carrying it could not be validated at all -- correctly, since
   --  recognising a constraint without applying it is worse than refusing.
   procedure Check_Name_Constraints is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.X509.Validation.Validation_Failure;

      package X509C renames CryptoLib.X509.Certificates;
      package XV renames CryptoLib.X509.Validation;

      NC_CA : constant String :=
        "3082033f30820227a0030201020214729dd4801a54586b73e69c048bc99eaeb8357e52300d06092a864886f70d" &
        "01010b050030123110300e06035504030c076e632d726f6f74301e170d3236303732383231343834355a170d33" &
        "36303732353231343834355a301a3118301606035504030c0f6e632d696e7465726d6564696174653082012230" &
        "0d06092a864886f70d01010105000382010f003082010a0282010100f25a28ff863d5122743363eb7b815d4b49" &
        "bbf25bf9d4c9a67acea1d03c869468645ebba4ce16de248dc0667fc5c3630187ff2ad73a0488f4728b3794d279" &
        "ede6e431f096a23ce4037621828b762db7e1d83649616e1753ddff36db01170dd53e86545cecb1b153fee190c2" &
        "3bfb4beb1a03629049d049b7013332fbf4effb038a6095800f20168feca771b27071c565acf9d426b4ac0ba414" &
        "3a25646d3f58c03b69e903a2a838dc56028e4bbd2e36eb573ba4b2d3409c89a0e77b3d9ecea3a86cdb86f80cf9" &
        "94bc6f504c30a27276815d5514bd6df3f6d5b71ed7acaa523a0924c9f87ab479838628c5012ed265e4ceee7968" &
        "169ec9595e8433f2b0f516f8b8ff0203010001a38184308181300f0603551d130101ff040530030101ff300e06" &
        "03551d0f0101ff040403020204301e0603551d1e0101ff04143012a010300e820c2e6578616d706c652e636f6d" &
        "301d0603551d0e04160414a83004ae9ec44164bd55c5536ba175f1afa07427301f0603551d2304183016801460" &
        "feba9da8bbc8d72217d5d3f13c65afc74d1198300d06092a864886f70d01010b050003820101005a895876b444" &
        "80fb93cc63339f84d95bd369f13970b13b4c61243d82bc4e6f93c84b1c002b3d711fefcb1855ae62ac328743eb" &
        "85cb40037fe1291c8f87b13f220f35860df8be34a216499517eff85e6d76eaa0030b85cc6d0a31ca1dd44c8728" &
        "b0e46c72ec3c7a68422b444ebb6851ed242c9b609c36f10ce54eaa8cbcb59382f29d46b382c1498ff4f4d5c66f" &
        "84b3d2f7763cb5a6f6800a3926055ecb360561355006a4c0e4f7b5aca8d0866bc76bb80cfaa65e5bd29c81e32f" &
        "8ec44af7e69d46b3943f9baa2125ac8362d1e745d773e9a72695bfdf2770a36ab27a74b7df27b4c181af0829a7" &
        "72151a9c5821ff7c279564f9115d649015c84281616a17f7b8";

      NC_Inside : constant String :=
        "3082034130820229a0030201020214225bf909f00ff47d3f234a3cf54b618d148506e2300d06092a864886f70d" &
        "01010b0500301a3118301606035504030c0f6e632d696e7465726d656469617465301e170d3236303732383231" &
        "343834365a170d3237303732383231343834365a301d311b301906035504030c12696e736964652e6578616d70" &
        "6c652e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100ba447093e8b1" &
        "9cccf0db9ccbdbd0c912876e3835fccb23eda5b1f3cb69d549b30cbdcf64564c798ddba331fc4551006c75e3df" &
        "3c9e39ae6eeabeded8f4842d5a1dd03cf6459b6cab0343e2410161b2bf8228e11853cf34769ec47f169d9a9785" &
        "d30eeaa67488e132845f886ef64be1569511aaa2000eaf1db00fc017407d106bf762bf10e32bbc6e15aa6c1b66" &
        "a00fe50cbd98680273c8ada27859158b2baa826cd013cca8c8ee29c220a61a998b36306f37931b565ab449de03" &
        "216e77d9d9fbf8ec77fb0e29a6b4d3cb6248e258a17c5c658f2d3505c179c95cb29f7bbd16bfc771e0eaf07183" &
        "7926519d850b0579811af9cebb5a705b83eb4e8bf35590b5b90203010001a37c307a30090603551d1304023000" &
        "300e0603551d0f0101ff040403020780301d0603551d11041630148212696e736964652e6578616d706c652e63" &
        "6f6d301d0603551d0e04160414fd77aefe3c132a53c3de1fe63b231801c4a5a3cc301f0603551d230418301680" &
        "14a83004ae9ec44164bd55c5536ba175f1afa07427300d06092a864886f70d01010b050003820101009c97f72d" &
        "3e0cc4ae05b2ca68c7f130d837e8ab09fdc099e929a3e4aa4447525bf28e84347ae0a8ad23067ee41d385ff6fc" &
        "1cceefd3d2fe1c455b59c495e1ddc24c8d7fe8ad4ac9e670f298de3d7814a7c186dd3d1a70347d9508551fa76d" &
        "6e982a777b09c18b26e622a5f006f24763908d11d888bb85e69dacad81aead3cad84731af8a09de2a7b0a795a9" &
        "78aa5bcd5dc66d8fbaf61cac43a62e3e441941008f08cd430460aaf28901ea3a93c1569d025b19e7d7fe6adb07" &
        "f36591825f48bd236aec8d417512e0a8674a43456e81fb2de7749db2337caedfc5b8e9064b7d6526c3a91c50b7" &
        "ece11417cca373604f9a991203c3fd5b3341ac6a54e4795704664d";

      NC_Outside : constant String :=
        "3082033f30820227a0030201020214225bf909f00ff47d3f234a3cf54b618d148506e3300d06092a864886f70d" &
        "01010b0500301a3118301606035504030c0f6e632d696e7465726d656469617465301e170d3236303732383231" &
        "343834365a170d3237303732383231343834365a301c311a301806035504030c116f7574736964652e6576696c" &
        "2e7465737430820122300d06092a864886f70d01010105000382010f003082010a0282010100adb37c5bc78aef" &
        "d46fe8d7fbbe12ff9c5735d959c24bf0676390c2ca2da45916a4bc0e5b325624b41eba751794529e8692f8d3bf" &
        "34ba3c16e80aa72d23fc7f8399b10dc9c85f27ebb61d771b17ccd4ca1bd526630c46f31719030ea108bc39ddc0" &
        "2dac063c38179871871fa3f1c8afb64cc368bf6ed8ab9357ae54a88c301965c05f51e2aedac6b4363240bdc304" &
        "f454cde3cc4d46109fd83f20b1cc450ddce3402dfcaff14391ffbca2f1e0aa1cc803fd715e097c19b97aa45b19" &
        "397857d15aeddd3784136bc1761aa32be7be94f4da92fa38418ba40e8e1287129ed73ca940f5dc8d7b67b212b3" &
        "f042fbdcd4deb9ff013dd8bab2b30bf0f8bc317005092b530203010001a37b307930090603551d130402300030" &
        "0e0603551d0f0101ff040403020780301c0603551d110415301382116f7574736964652e6576696c2e74657374" &
        "301d0603551d0e0416041400e5f0013eb285d0b44f0d7d6496e6f63050a32e301f0603551d23041830168014a8" &
        "3004ae9ec44164bd55c5536ba175f1afa07427300d06092a864886f70d01010b050003820101002537d9f42cf7" &
        "09aed70437ef6710a50f9e239af128b614c92c7b7a4d37b29b4322d02b516f146e58831532b0d9b5e13238896f" &
        "92ffbb2892083d25c4fbab76790492c06f56084147f8501559380ce82dd5f542fa013b788d6c619af9d29fb9ef" &
        "f75e5f9cbfa4b139214a0bda03d548845749237a0a42d8a6aefb099a79f5055f54a99171429fbd8b6f0544da69" &
        "507f88917de8d60116a215b5be0547ec028230a9f7177471e29b64c75881835c15e8a3248f5ea5c8ed9a19cd0a" &
        "964674ed7ffbfc360632303045de2df563c508b00f85866ce79947a4f91925beff55c795101f1807897a1085bc" &
        "ecb3ae927e7dce902ac25f465131404bf70d2f85410b83dc38";

      NC_Lookalike : constant String :=
        "3082033930820221a0030201020214225bf909f00ff47d3f234a3cf54b618d148506e4300d06092a864886f70d" &
        "01010b0500301a3118301606035504030c0f6e632d696e7465726d656469617465301e170d3236303732383231" &
        "353030385a170d3237303732383231353030385a30193117301506035504030c0e6e6f746578616d706c652e63" &
        "6f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100c3faab3828201b6e220b" &
        "e59dc85b8852ce176d2060a25146abcf9dcd69cb6b6dd8cda19dc5a232d3dd40f29e5e3cff41e374bb88810381" &
        "1e375763e84c87ad2483c1a6b4f4e5b7b686f612ea96d965d83657e972a7e004b7dc90f8e9349d43ee11aa77ae" &
        "d0c87a9ebf5e5987b59adbd3ebb6c2e0c7966d5382e8963567f1c8f56d6707048174e4887a0854af3dd162651b" &
        "076ee44cc8860e12bb6921298446c9304c97da0beb5a75a4a67af20ca47e3ff48914eac17965f6f2352f337a76" &
        "37d9d6658ace31a92c77b5fac6461aa93b54b2fe7c38b5511311eb97754695805f1e45223516adcb9160695de8" &
        "7dbc33546fabc92b5f9d97667446bccb7ae218b9510203010001a378307630090603551d1304023000300e0603" &
        "551d0f0101ff04040302078030190603551d1104123010820e6e6f746578616d706c652e636f6d301d0603551d" &
        "0e04160414f8a504e083d1f448f637fc47cdf6d52601991054301f0603551d23041830168014a83004ae9ec441" &
        "64bd55c5536ba175f1afa07427300d06092a864886f70d01010b05000382010100f0cc5a41561f03642851d557" &
        "cbac20c4881e7f7f5434da93561b0fda53418ced35b8100ac8e7b4b307f21d08c1215a0e64d5fdfbc6398c3525" &
        "caefa1fd8970e23edbe7645eb5734e651186334b1606b77ff15102bbf6e3e5453020eb835ff22c6a80a48973a9" &
        "a489ec5991ea4e1ec076d9aa6bd9eea1cd1716cf6f8dc286f5727d11f242fdf3b8116f0dc214005e6f8857d38d" &
        "25635a44b8dd9fd2b50ea45c1efb12bcd331d6d91031c8a5bab5e0965f858186d10fd48ab66ae8c07f000fc78c" &
        "e5dfd8f8ea41a60dbbae26882e87f4f88cf9f3365ea0f6ca509e864b1a1c48f0a0e5ad7959bf1c3c34ff2a8032" &
        "dab5189a0d7a6b78c5dbabd5e72b0f48f19b24";

      NC_CN_Outside : constant String :=
        "3082032130820209a0030201020214225bf909f00ff47d3f234a3cf54b618d148506e5300d06092a864886f70d" &
        "01010b0500301a3118301606035504030c0f6e632d696e7465726d656469617465301e170d3236303732383231" &
        "353234395a170d3237303732383231353234395a301c311a301806035504030c116f7574736964652e6576696c" &
        "2e7465737430820122300d06092a864886f70d01010105000382010f003082010a0282010100b3c8a427dbf6ca" &
        "44c1d40b899b1afe1c41a38fb86c10b9d5f7c0993da39ca977943c446f91d38dd9ee0adb6d9c4547d3c0776941" &
        "15ffba5a24745374c60468ea6cc714202109e07436287a2b22d8279ed4bc2ca248d0b10541fbac1f34251f91a0" &
        "1609838d325d685929f593ba99ce3cfacdb9e8bdff28ebd7381b33573cafbc2a2cbb0cde0a487f74f3145724f3" &
        "91d905ff95b664c6546586a13a2d524e46099b6912fff41e66751a3ecc67f55e7a81912c076fbe31c70eae6504" &
        "51007651e7dc2005d49f7dcd75bff6a4ae1edc275d3c27d877cbf1cca84b4b02507324ce984e4bd7866a78f5de" &
        "3c5adc70382363bf62d405cdedfa17ddc3934f9e765663370203010001a35d305b30090603551d130402300030" &
        "0e0603551d0f0101ff040403020780301d0603551d0e04160414cb3d0ef880a69090f1417ed3080eed86e282e0" &
        "51301f0603551d23041830168014a83004ae9ec44164bd55c5536ba175f1afa07427300d06092a864886f70d01" &
        "010b05000382010100c7315c2a309ddb3f4bbe50af9c565d46eba021d4bfd4ac4e8e5a9e5d05486f0fcb94f219" &
        "a54627e800725fd0d5625638375ce620d9746b056aa00a6464486b24e8119d66408364976392781917fa4a7602" &
        "f9a3338b42cf7a419782046af16d2b6f3ead8fd390f02fd6c1e075fe44d9fde6328140654f41f48a926a133aab" &
        "bfd0afedacb5811ba7c5711e64edee20b8e756daf91da0ff7c216bf56b7c422b20e2283a12e57792db355c9109" &
        "e013af1eea1f1d240d95f11aa236ea474db16cf25c74017e39d197030b1a63db4842e393c5032898f6b0fac892" &
        "f6531c0d44636e495ba3d7af542cea339688cb6be6ff733cf71cf5a5aa20bbc0ddd5fc87e54a0726";

      NC_CN_Inside : constant String :=
        "308203223082020aa0030201020214225bf909f00ff47d3f234a3cf54b618d148506e6300d06092a864886f70d" &
        "01010b0500301a3118301606035504030c0f6e632d696e7465726d656469617465301e170d3236303732383231" &
        "353530335a170d3237303732383231353530335a301d311b301906035504030c12696e736964652e6578616d70" &
        "6c652e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100bf72ceeb0601" &
        "dd22c4c7c0bf10ff504d4c7575de778247e697a86e7ce9edc065ef13a9801c32468f0b8910dccfdbc532dc3cad" &
        "0043fc59b735b4012588b29ac2795bdfa1bab59354d06249570ebb015a71d99a1e0dbf83fdce0960f14fc56969" &
        "555f80485d1f5b3007de61237dfd2500377295b68a992d9276483742bae9ad58e8770a0945c5efb394bd737441" &
        "c95073613e793a1e633b329167cf027cf368716ff64727a26f4df1f80ffaf6922b6a753ea38f3354cfeb599d85" &
        "27258573b855b7a2ecf36c6e831304d5c84cdc0fe1f06bd4cc02b5bc28a9f14b1922b640cf55bb47013f807917" &
        "7669eee688438a2c9104b78edd160743f6075205f2b6ea01950203010001a35d305b30090603551d1304023000" &
        "300e0603551d0f0101ff040403020780301d0603551d0e04160414727c8d5f04ff913e7ea0cb018adf811bf2d7" &
        "d559301f0603551d23041830168014a83004ae9ec44164bd55c5536ba175f1afa07427300d06092a864886f70d" &
        "01010b0500038201010011d80d06a31ea98f284de3bdc7280b6ca8f83db10c2b74008ff024fd0f622ccb9ac5d9" &
        "ea54900381ba858a3498aa315741623fe00ce337e21967a280129e87e7fe2bd9f65c882299e9d34448e10146c8" &
        "05b36df68126e24ee38276a8040965f9cf80f5c00189e64c6f39ab3e379a49b9724913a24f0da6c57361f571b3" &
        "9bb6f1d1804e146a2a74c51640b1993fd24d157a2aee440267723435ae11f87bc9649c4d8166307c9e2cbc589a" &
        "36f2ab780a1ea7097ca6a0c17a7c01d671e6198c440eaf29ccecf456b53fc123357646509d1bcebee3dad6e8e2" &
        "230f3fa00f19ae8369f51dfa9f6702facacf936a925373eff9f4e4ae2bd3973da87c821d89409b9e7c";

      NC_CN_Org : constant String :=
        "308203243082020ca0030201020214225bf909f00ff47d3f234a3cf54b618d148506e7300d06092a864886f70d" &
        "01010b0500301a3118301606035504030c0f6e632d696e7465726d656469617465301e170d3236303732383231" &
        "353530335a170d3237303732383231353530335a301f311d301b06035504030c144578616d706c65204c746420" &
        "5061796d656e747330820122300d06092a864886f70d01010105000382010f003082010a0282010100bf228043" &
        "53d918c8d33d79091210152a801f8aeceb8cd16822033f2443dde78c785b4920dcc892cbba0689774f40a68d79" &
        "837a973f8d9f3622473cf9e912022019b7e2d1095787c7316402e1b94fe0dff6d02da2a2daec699f36a86c2895" &
        "47b2c5e8347e1be1b8f80bf8117b4b8daa93ce406111637fe86fa5604ce51b4bee8899ab5cddb9b71bcdcb7e35" &
        "aeb55ed0cbcb149fc77270ce8e28b44009c8fb47aae3a82be4a50d84183598c0e9df7af5e9579417d686e9edc3" &
        "ba65cdb73bdd88c1cf2d7b301391067d1a5479b16480f5d7f138d176fb6d7dff0e588937f6f369bf29ca35f395" &
        "8cc38a8e0e90f2cf57d477451053915ed51b7efc0badc5ae5f83030203010001a35d305b30090603551d130402" &
        "3000300e0603551d0f0101ff040403020780301d0603551d0e041604141acefde153ff30854cb8c06d2a431f31" &
        "179f5712301f0603551d23041830168014a83004ae9ec44164bd55c5536ba175f1afa07427300d06092a864886" &
        "f70d01010b05000382010100947a3146e951ab5abf0784ef06d838b6f4dc5f746f9f31537189958e824672e0ec" &
        "4c71bad2e419a1c574efb69af3ea62a0bfe632c1aa2180c2636ed23916bc39ad33cb2ce45bec4b27d4890b2730" &
        "a805481e0be2319addb66dd7dc8ae2159a8f5442c348edfc1f727126e48c55e3e8d90e5f5d5fd5c668c400bed8" &
        "b6c8863cd5e6a54f1cfe5e2b1c52ce7502fa44d643a85e4d720d2c4f1c44d29c442c80b40e92f48e70a8b7fc7b" &
        "44dabaddf397d5f12d18102b03e3796bd7cd5a8da5c1ec980a0bdd2472deef46a2cfa92ac4a9c4880e88732974" &
        "c6df6e3a6913c5b77864edc913b84d115cf33c8e741e5ad25cff46dc0dc363ed77fc1ae208ca99aa819b08";

      NC_DN_CA : constant String :=
        "3082035830820240a0030201020214729dd4801a54586b73e69c048bc99eaeb8357e59300d06092a864886f70d" &
        "01010b050030123110300e06035504030c076e632d726f6f74301e170d3236303732383231353930395a170d33" &
        "36303732353231353930395a301a3118301606035504030c0f6e632d696e7465726d6564696174653082012230" &
        "0d06092a864886f70d01010105000382010f003082010a0282010100f25a28ff863d5122743363eb7b815d4b49" &
        "bbf25bf9d4c9a67acea1d03c869468645ebba4ce16de248dc0667fc5c3630187ff2ad73a0488f4728b3794d279" &
        "ede6e431f096a23ce4037621828b762db7e1d83649616e1753ddff36db01170dd53e86545cecb1b153fee190c2" &
        "3bfb4beb1a03629049d049b7013332fbf4effb038a6095800f20168feca771b27071c565acf9d426b4ac0ba414" &
        "3a25646d3f58c03b69e903a2a838dc56028e4bbd2e36eb573ba4b2d3409c89a0e77b3d9ecea3a86cdb86f80cf9" &
        "94bc6f504c30a27276815d5514bd6df3f6d5b71ed7acaa523a0924c9f87ab479838628c5012ed265e4ceee7968" &
        "169ec9595e8433f2b0f516f8b8ff0203010001a3819d30819a300f0603551d130101ff040530030101ff300e06" &
        "03551d0f0101ff04040302020430370603551d1e0101ff042d302ba0293027a4253023310b3009060355040613" &
        "02444b31143012060355040a0c0b4578616d706c65204c7464301d0603551d0e04160414a83004ae9ec44164bd" &
        "55c5536ba175f1afa07427301f0603551d2304183016801460feba9da8bbc8d72217d5d3f13c65afc74d119830" &
        "0d06092a864886f70d01010b0500038201010061d04bcc6a902b0799a1c587f2cba8ab664817e580004f88c6e1" &
        "16303a9411af2465941e4d57c8cbc5a578dbd150c3ff687e06a101ea321f7efe55475c83fcf3debf5cea394220" &
        "86680ef1fefc1d88df869f89dfd22a86cf817cffd3e88f18a5a89f002caa3a5f271ec8a58e4ce72670d0373ef6" &
        "caa42b3b8549fd2ddff0b691971a0572aa8c787f0f976eaa3b67f253fe075b3444167d45482c40954c784208b7" &
        "d8b7439cdb3bacbeb6b00c1a20abd16deebd90b557ca964b861fe928d9644ce6d8baccaca0445fbb8ee87a67c5" &
        "eec2c2a83aeb6a4297eb16b3157178b3121a04d4c71bacec04c8ea4002130817aa6842f752e7fcf9c2f3b83618" &
        "078a99c53b";

      NC_DN_Inside : constant String :=
        "3082034130820229a00302010202144b1efa83ff472588a7b5ec65041b57c341737eae300d06092a864886f70d" &
        "01010b0500301a3118301606035504030c0f6e632d696e7465726d656469617465301e170d3236303732383231" &
        "353931305a170d3237303732383231353931305a303c310b300906035504061302444b31143012060355040a0c" &
        "0b4578616d706c65204c74643117301506035504030c0e696e2e6578616d706c652e636f6d30820122300d0609" &
        "2a864886f70d01010105000382010f003082010a0282010100f3538c0f7d6a9f1584ed48feb29a7a2814b06afe" &
        "db1d37fa34928f6b7ed50f428bc01d8bfcce9929876f443190ddb9841f4e257c69128af2165297eafc05190779" &
        "70709d55677aebd3eb38f5adefdfc0a891dad716fc5f7b4c23bda5a80e6f140edb4380ff4eb47e1f00fdacf1c6" &
        "f0284599f36497cf55bff64b3aaa7d30f8821367f279052ce2d9f0a8caef69a39892f55f76bb495035c41fc769" &
        "130fe9c51bb658b1e72e5e51996bb4b1d8b9f481148e028ad0afaf77422f977cfaccc6d51bd95aae47bf49dfe7" &
        "d44dbd79ebb748890513b1f554ac4eeb16629e865e7e9f6fde6ed74b925f07ce92b5e2fc0b5644bc70e64e5f2a" &
        "9356b80426033f3824f7990203010001a35d305b30090603551d1304023000300e0603551d0f0101ff04040302" &
        "0780301d0603551d0e04160414faf0aa1138db982b4bf9973d05a3f369b4c08f35301f0603551d230418301680" &
        "14a83004ae9ec44164bd55c5536ba175f1afa07427300d06092a864886f70d01010b05000382010100d5c8229c" &
        "d13eac8ae4d1d545a3bd764bed38c6f50018c1821abb2407f06fc7d8ce505eda09f48662c57c082d7d4eb77e3b" &
        "d5a635375cd3c7909bb139545e86947ff47bf84a64c5d23b9983d59dde1bfbe277a992540aa636aaa28f611343" &
        "b7d102ea931283f80d2460cdc8ca6540d3292912a627aad66b3d6cfc5d029428e77162f84a6c17e756dcbb516d" &
        "3f2351074cbaa3387fd094fd33f6710741b4a916020fcf74d08663781ca928af0cd09219719f35afe26ddb7a84" &
        "fed60a284303ef4b0d12ccaf4cce14b4c1b11e2a17fbb147c8d21eb12ba2bfaf62458327fd46d0965bc0bbe0f6" &
        "89f8d4c92122e274d27acac7043e3854ded143c8546b952dd06c9f";

      NC_DN_Outside : constant String :=
        "3082034030820228a00302010202144b1efa83ff472588a7b5ec65041b57c341737eaf300d06092a864886f70d" &
        "01010b0500301a3118301606035504030c0f6e632d696e7465726d656469617465301e170d3236303732383231" &
        "353931305a170d3237303732383231353931305a303b310b300906035504061302444b31123010060355040a0c" &
        "094f74686572204c74643118301606035504030c0f6f75742e6578616d706c652e636f6d30820122300d06092a" &
        "864886f70d01010105000382010f003082010a0282010100984497d9c2ae1574cab962d3dc4043268363ac3b71" &
        "6ceb798b68aa0b9b600696dd3112f3e7071c95dabaea67c19f6d5e420e9a5e86b60d0fe988f56ed41bbbe498a9" &
        "f9e55398497fd1bdf4c70f6dd6eaf302b54b24375ad948592b61972914c237459da50e060155439c7d98b7c81a" &
        "42d92bcb9e8afb1ccb8ef4bf639224e21e173b693e2fbbfb7a665a405cad0255cb872df76d622cf5868872a239" &
        "84f7f2534eb63e3dafcd66e114ce49ebe10c2556e14b27b4a280b05dc47b563434998ce66f878df8a2e0d04248" &
        "9897ae8d88595d7b98cf016f145e7bd85595841e50cdefddd71cf85d1c00d84b4e0b793ee566f46cbfe161017c" &
        "d4fe3ca56cb2be0f250d0203010001a35d305b30090603551d1304023000300e0603551d0f0101ff0404030207" &
        "80301d0603551d0e0416041464084e16d2d043ada30fe6f68890b97e759ee3b0301f0603551d23041830168014" &
        "a83004ae9ec44164bd55c5536ba175f1afa07427300d06092a864886f70d01010b05000382010100075e3d5674" &
        "998a0eed88d6f1d3c793ae6cca3491abf020a2174dfd2e7e47a6f38262ba4e724ea667a78ce236719e5bc54eea" &
        "8dbe31aace2cae1d9174903e06761897b1fa9029f8cc8bd5b258f2d84369e35c00a4b63fd91b5ee0c4738adab0" &
        "7048c881adec9a550ef09a9ca6f605015b5165520c35e2bb9d31ec545f107baf260bed071e55b879c81863801f" &
        "92aa504e8ede678cc4c53c70c6aee781cd36d3ca16d7c65bbe7279cc1f360f11cc086bcf871c66b699b85d846d" &
        "6b2a08598cb9f93c486cbcbce208a162e008105e70f392afb9ad7254573c2849cd71d750205daf8d6156e9ffc2" &
        "3a10437c897b8bb2a48c22f0fbe62d94bb1712090855085f6245";

      NC_URI_CA : constant String :=
        "3082033f30820227a0030201020214729dd4801a54586b73e69c048bc99eaeb8357e5a300d06092a864886f70d" &
        "01010b050030123110300e06035504030c076e632d726f6f74301e170d3236303732383232303032335a170d33" &
        "36303732353232303032335a301a3118301606035504030c0f6e632d696e7465726d6564696174653082012230" &
        "0d06092a864886f70d01010105000382010f003082010a0282010100f25a28ff863d5122743363eb7b815d4b49" &
        "bbf25bf9d4c9a67acea1d03c869468645ebba4ce16de248dc0667fc5c3630187ff2ad73a0488f4728b3794d279" &
        "ede6e431f096a23ce4037621828b762db7e1d83649616e1753ddff36db01170dd53e86545cecb1b153fee190c2" &
        "3bfb4beb1a03629049d049b7013332fbf4effb038a6095800f20168feca771b27071c565acf9d426b4ac0ba414" &
        "3a25646d3f58c03b69e903a2a838dc56028e4bbd2e36eb573ba4b2d3409c89a0e77b3d9ecea3a86cdb86f80cf9" &
        "94bc6f504c30a27276815d5514bd6df3f6d5b71ed7acaa523a0924c9f87ab479838628c5012ed265e4ceee7968" &
        "169ec9595e8433f2b0f516f8b8ff0203010001a38184308181300f0603551d130101ff040530030101ff300e06" &
        "03551d0f0101ff040403020204301e0603551d1e0101ff04143012a010300e860c2e6578616d706c652e636f6d" &
        "301d0603551d0e04160414a83004ae9ec44164bd55c5536ba175f1afa07427301f0603551d2304183016801460" &
        "feba9da8bbc8d72217d5d3f13c65afc74d1198300d06092a864886f70d01010b0500038201010085ca15f1caa8" &
        "6b63b217bd7aff1bdef4db1fadbc9a12fb896309aae6daf586097c5ca8c3c7b930dd358064c42c072b37c88b8c" &
        "c512ce06a9b86069a0455fd9b96366f66a9dd4fa1baff8ca1be6d21b118b76bd2b11e7f3d008ac336c65e85448" &
        "5d513f67ae8799421497960ba9f835dad70d7595d4af7c2e6b431dfd9b88f507045e2f7716e4d0cfbdc124c434" &
        "2be2a87e739f3550f1dba4740c02627db33538950877d22ce4bb092b3c9cf8e57336452e59d79202f59caf97ce" &
        "a61ba2f27eda675ac87a2ccab21e5ce91e990733dbfd9a2467018b58b9725af9aed593d6fc1ef86092c2f80615" &
        "52575edef850ab820765a4ea3ea3075f29847aedb141b2403e";

      NC_URI_Inside : constant String :=
        "308203453082022da00302010202145778eca098da68b36e73bedb8a9db6422f3aa137300d06092a864886f70d" &
        "01010b0500301a3118301606035504030c0f6e632d696e7465726d656469617465301e170d3236303732383232" &
        "303032335a170d3237303732383232303032335a30153113301106035504030c0a7572692d696e736964653082" &
        "0122300d06092a864886f70d01010105000382010f003082010a0282010100a2a0c1ea1b96738be83742a97517" &
        "e448864e435a8b5ec2c0adf2c6bf2a4b3cbd8b05391d509fda551dd4c8f411810835f2bbc5eae812e46191e066" &
        "7b08c6dd68baa76d505300d3c7ef94e2cde8f436ba2e326ef72e1d0126c18c896ebc47721d569fa798057013dc" &
        "f5c62b83266d8f7e262d0ef1ba8b7bae5429374c557c6aa4910460794ff9a0632d14149644ef10aa630f77a774" &
        "fb7188c8bed2fa76be160bec6a4286f5849ccc8fbb1c15d00b4d62e70f8d5d7ad6445bc4b6bc6119f34d95bc13" &
        "8c70154e9aa6350fc99afa132a6aca6b2ed2a5de3bfe2e1f813946adc59e268b2789751bcf6eb8a8b9995686d3" &
        "704e827aa4c08aebbfacd38dc297b07f630203010001a3818730818430090603551d1304023000300e0603551d" &
        "0f0101ff04040302078030270603551d110420301e861c68747470733a2f2f7777772e6578616d706c652e636f" &
        "6d2f70617468301d0603551d0e04160414cb48de9bea1dd73cad4438ce2e70da6373bd9020301f0603551d2304" &
        "1830168014a83004ae9ec44164bd55c5536ba175f1afa07427300d06092a864886f70d01010b05000382010100" &
        "3717bf8edcc48064a8b92313af1ce9ab1417891f2c92a6827b74c8031b808cf763270ef76d638c7f9923544e5e" &
        "f3ed4e7d165cb579adcee127144c8277af0202b6b56173a766dae8c9ffe9b3f9bdc8e0d39701e57c538fc91073" &
        "7ea0f6f21d6745ba7081bf9a4ff93fa3ee30ccb90888790e957b7f107fe4f129a7a79f545c9c7411446ffa5526" &
        "bc975b50caa141e58e38128ec7e6020560d561afedc2aacaf8648255a6ac5ec0cf65092af3757ab13984fad9b2" &
        "f33d56c642d919debe353dcb1f516aee91c4f95149454dd9498f085bfad57845857816100be186edee7a63b354" &
        "c6a02d65deaaa06c6b72fe945f3dc6ec7bec1d13260e24417cc537c8c08a43";

      NC_URI_Outside : constant String :=
        "308203443082022ca00302010202145778eca098da68b36e73bedb8a9db6422f3aa138300d06092a864886f70d" &
        "01010b0500301a3118301606035504030c0f6e632d696e7465726d656469617465301e170d3236303732383232" &
        "303032335a170d3237303732383232303032335a30163114301206035504030c0b7572692d6f75747369646530" &
        "820122300d06092a864886f70d01010105000382010f003082010a0282010100bdcf160b3726aa01518049936e" &
        "6dc8aa7669b7a998a7cf68664ea7c6ddf8905de5067a80a8b0579215ee47c75b8f1ee466219e729172e5714ce7" &
        "32cc4b7e5addc34323f664e5ab7a3f08253515cef1f1df9e19b7058ac73fab7ffa52bc8d56df3219834a63ca9a" &
        "4ba635a6a7fa4ff219813f700fb47a70023b2d452ca14e6fdc6ba6c7277181bafeb0d09ce8a0cce8e4af901f35" &
        "f4814ee89c11487ff4987d8770f48c718f4220e45fab249f0cbe5c939bc474ad3af2750e08c9b1f629df51713b" &
        "dba28932246bff7c4625f6c39d2710a346ed58280808c6a18bb20be8716515d011ca43c68340a2bbf4ca223401" &
        "c1a922dcd93e6131411bcdb127683367744d0203010001a3818530818230090603551d1304023000300e060355" &
        "1d0f0101ff04040302078030250603551d11041e301c861a68747470733a2f2f7777772e6576696c2e74657374" &
        "2f70617468301d0603551d0e041604149c4a5ede9436c4892287c44da0a4209b25fb7913301f0603551d230418" &
        "30168014a83004ae9ec44164bd55c5536ba175f1afa07427300d06092a864886f70d01010b0500038201010093" &
        "dde370784a8cee2eba6c08850cc1e0773cc97df10499b453b70cc8d4acfc1b7f28324e3713fa2f20298ab0abd2" &
        "32652d6f632e02b99e9787151f59fe17c4a77163adba2343c3a7aaada7a6c67ac03303c5557524ff364cbcbe1e" &
        "4a3957fe29fdc1130176b17c3e3b4c8b07a896a3f686e4bad11d3db228c331c67efc4d4c0b1c165538f5c784ff" &
        "264119e90b9ffd162cd96035cfcfe5c493d444bac1abd0ce675d960b28ac7a726e44d5b755b16969de56dfffdf" &
        "97d8e7623a5b341b3b388ad89b03fbdf909e491addc66620fadd960608cb326e45cf9902c396b9e7193a670cc9" &
        "f01ee3b374b72d4524ace8045d484e2bcb68fe931b29ce691b8e153f06f4";

      NC_URI_Userinfo : constant String :=
        "3082034e30820236a00302010202145778eca098da68b36e73bedb8a9db6422f3aa139300d06092a864886f70d" &
        "01010b0500301a3118301606035504030c0f6e632d696e7465726d656469617465301e170d3236303732383232" &
        "303032345a170d3237303732383232303032345a30173115301306035504030c0c7572692d75736572696e666f" &
        "30820122300d06092a864886f70d01010105000382010f003082010a0282010100b4f72b0206d1fbae18524cf2" &
        "7edcfc0abc5291845a6b7404ff5543c22dca776ab3a945686467b5137670932da35278e7e041bb2bc40d3ca90d" &
        "5f446451de4243dd7a7845babe8ca2c9099c3cab78c746eb48d73a7bd6cd5ec8b772b116a2aff779b6779bbd43" &
        "451a0f37730b136978fac66539a0c85e59c3cea94a85d04a955ba5229f19dd517b836b0b932915e49e9cddf333" &
        "01886b7ba80ef2c6cf027082bc76dbec02265ec6979944b755173dec666e966f1bdd52c8b4a6a2da6942d02b64" &
        "c9e9b46a8d43e22914449210116591e91c66ee593fd8e16a01ec098962788edaece76d783c893c90f2a945c3ee" &
        "a40621439b915fcaa64d9def2f3eea33f1b2b50203010001a3818e30818b30090603551d1304023000300e0603" &
        "551d0f0101ff040403020780302e0603551d1104273025862368747470733a2f2f75736572407372762e657861" &
        "6d706c652e636f6d3a383434332f78301d0603551d0e041604146ba04546d9e0790bc0e42b42d93ea2b8e456d5" &
        "49301f0603551d23041830168014a83004ae9ec44164bd55c5536ba175f1afa07427300d06092a864886f70d01" &
        "010b05000382010100a1f171f7b7bfb99526cb7832ac0b0cb192c0e428cd936539797c5306676fd5aec812355a" &
        "e4d0f286e1d09e6b7c970922ca5d7b46bf24fd91145424ace7657c1181e10ecdcff5f00956c236557c357c1f64" &
        "d498de9588fa4e9ff4ac8a1396f384b33933282c7d6df201ffcb72b518f5ef3ed71909d20e98a4c09ba8e3d839" &
        "3bf1604eec6478ed64b61385b89a6b465ee530dcbe50c051283ebb2ba5ec09a6c3e5f963b3eb6895d6545287ec" &
        "864100abb5931e19f39c357902f59a931a5c2883904b6d55ea877e22fca29ff707095902475e993eba68fe58d1" &
        "4f869d863401b611d00552e06fc41c2677443a22de6aab786e294288bef07ce7cc5c7240e62de3e3";

      NC_M_CA_HOST_OK : constant String :=
        "3082033e30820226a0030201020214729dd4801a54586b73e69c048bc99eaeb8357e62300d06092a864886f70d" &
        "01010b050030123110300e06035504030c076e632d726f6f74301e170d3236303732383232303530395a170d33" &
        "36303732353232303530395a301a3118301606035504030c0f6e632d696e7465726d6564696174653082012230" &
        "0d06092a864886f70d01010105000382010f003082010a0282010100f25a28ff863d5122743363eb7b815d4b49" &
        "bbf25bf9d4c9a67acea1d03c869468645ebba4ce16de248dc0667fc5c3630187ff2ad73a0488f4728b3794d279" &
        "ede6e431f096a23ce4037621828b762db7e1d83649616e1753ddff36db01170dd53e86545cecb1b153fee190c2" &
        "3bfb4beb1a03629049d049b7013332fbf4effb038a6095800f20168feca771b27071c565acf9d426b4ac0ba414" &
        "3a25646d3f58c03b69e903a2a838dc56028e4bbd2e36eb573ba4b2d3409c89a0e77b3d9ecea3a86cdb86f80cf9" &
        "94bc6f504c30a27276815d5514bd6df3f6d5b71ed7acaa523a0924c9f87ab479838628c5012ed265e4ceee7968" &
        "169ec9595e8433f2b0f516f8b8ff0203010001a38183308180300f0603551d130101ff040530030101ff300e06" &
        "03551d0f0101ff040403020204301d0603551d1e0101ff04133011a00f300d810b6578616d706c652e636f6d30" &
        "1d0603551d0e04160414a83004ae9ec44164bd55c5536ba175f1afa07427301f0603551d2304183016801460fe" &
        "ba9da8bbc8d72217d5d3f13c65afc74d1198300d06092a864886f70d01010b05000382010100712d9fb54047d1" &
        "57beefe10f035f659a56a9c2a2e592465312dd7844275f067bbabc6dd5fa83125ca41afddfd6bbce9b8fad5c48" &
        "0846d83a55b27ca38d140c58288662d9d0972d877796cfb452d0b71f52950bfabfb7bfed09d76c121741665455" &
        "11e321741dcf0400a15429a9dcb6f83350136924e0e74350be8c0ca7f7ab171558df2374c6df0b94d3b17b0513" &
        "3a3a070764bdfabda8ee851a9562aaa94f3afb6fc30a6ebc18eb82a51583aba6858f85398e32a7c3b7d49ff1dc" &
        "2df4fa072aca6910b6e739b6bdb3d9c95d1e9e9d2eb131bc4fdcb646dbb861d716a55788f4cdaa20041a7fb8a0" &
        "f6c1b433a99f9db1d070700911eae48cfad7646ce1844b7e";

      NC_M_Leaf_HOST_OK : constant String :=
        "308203323082021aa003020102021472846ea19093f8ece45b492fb223e78d5887901c300d06092a864886f70d" &
        "01010b0500301a3118301606035504030c0f6e632d696e7465726d656469617465301e170d3236303732383232" &
        "303530395a170d3237303732383232303530395a300f310d300b06035504030c046d61696c30820122300d0609" &
        "2a864886f70d01010105000382010f003082010a0282010100b4a238411428671045e6b0736cf7e157a8f26dba" &
        "3b0d4817e0946f9f617ca3df2f7903712fe29bd122e1389fba9aa673a61099bd7ed9cd8e2bb067ea377b199f0c" &
        "c3fd10b7f80c98f8de4d1f5af23c88a2a71b46b8724b7d7d670d7aed7ec13c8839c48b79cb59a6aec40c4709ab" &
        "f49f741b4ef51b2f2e6cf1003be32d06fbd7e1d73a1a61fdb01be74b5a74573e4c4384c86b6bdcda6d6d126dc8" &
        "8a4f7a7b516e1f0e93d3afd0c48f6b11177f0937ede53d4ffe37f9bcaa44678cf9d9606538d8d73b96c4bd1ddb" &
        "d07389ba859fb75572a0e9d41ae0ea8c05d661e34bcb1ec18d8b39551b67c142ee0b7452b95f265646c03eebe8" &
        "7f73b35b7d9e3b4c14c1b10203010001a37b307930090603551d1304023000300e0603551d0f0101ff04040302" &
        "0780301c0603551d11041530138111616c696365406578616d706c652e636f6d301d0603551d0e04160414f666" &
        "ba6b2be13d77f0d26c2fe99e96d55a3726b6301f0603551d23041830168014a83004ae9ec44164bd55c5536ba1" &
        "75f1afa07427300d06092a864886f70d01010b050003820101002aab1ae6ec7fe264fe96de4d5e38af28a38a6b" &
        "58b51ef7f3ebdef927c2fc490890acc595e189a6d338e7cd3560170b073c3986d2fd23228f1afa7a353fe72dcf" &
        "ec7cb2508a30634aae4e4d695d050b9693f8fd94732da94f7f4eb87680b28870400ae0966a4e1e56492883b8cb" &
        "c3b3d33d294212e5d18ea88f8de9f2148850dfe5536829d2c95b459229ae5e0497c859f597bf26b091d5dd1b57" &
        "ddbbb0e291504264a50bf86f39fd7b192a1cd356103c654a85c074c9c4628b0a33e2a5d051da719130a8e90861" &
        "bd0674a634a6ccd38b895a04c228fb9d4d2b2d58d4ce5e220c24c69c20ec1c01b8b9e7e31e0092c0666988af28" &
        "a7e860dd0e35b002a15e22d5";

      NC_M_CA_HOST_NO : constant String :=
        "3082033e30820226a0030201020214729dd4801a54586b73e69c048bc99eaeb8357e63300d06092a864886f70d" &
        "01010b050030123110300e06035504030c076e632d726f6f74301e170d3236303732383232303530395a170d33" &
        "36303732353232303530395a301a3118301606035504030c0f6e632d696e7465726d6564696174653082012230" &
        "0d06092a864886f70d01010105000382010f003082010a0282010100f25a28ff863d5122743363eb7b815d4b49" &
        "bbf25bf9d4c9a67acea1d03c869468645ebba4ce16de248dc0667fc5c3630187ff2ad73a0488f4728b3794d279" &
        "ede6e431f096a23ce4037621828b762db7e1d83649616e1753ddff36db01170dd53e86545cecb1b153fee190c2" &
        "3bfb4beb1a03629049d049b7013332fbf4effb038a6095800f20168feca771b27071c565acf9d426b4ac0ba414" &
        "3a25646d3f58c03b69e903a2a838dc56028e4bbd2e36eb573ba4b2d3409c89a0e77b3d9ecea3a86cdb86f80cf9" &
        "94bc6f504c30a27276815d5514bd6df3f6d5b71ed7acaa523a0924c9f87ab479838628c5012ed265e4ceee7968" &
        "169ec9595e8433f2b0f516f8b8ff0203010001a38183308180300f0603551d130101ff040530030101ff300e06" &
        "03551d0f0101ff040403020204301d0603551d1e0101ff04133011a00f300d810b6578616d706c652e636f6d30" &
        "1d0603551d0e04160414a83004ae9ec44164bd55c5536ba175f1afa07427301f0603551d2304183016801460fe" &
        "ba9da8bbc8d72217d5d3f13c65afc74d1198300d06092a864886f70d01010b050003820101006b68193fc93d22" &
        "a490170a3e4c034b356737ef53178e4850687c1dec7c756abed2d0301b02ca2fc9ed94836f5dc638c49002498d" &
        "97cfbf76a06540135c3ff51322dc7ae4eeed9582c826b77b6e8533f115eb361198eb1202098a24fef5000159e2" &
        "e08e766aa5de7aa65b582219b5574760a9b777e0fa5d501c4311db84510d1683530d88e341ba7900bdfbc45368" &
        "7e46321006526cf36e17c116c1c0b11e39437790700fd6152597f434d16a6c78a7bbb4b550013cf053cec50833" &
        "93bb71f1723bcf6f1f0a06fa71ce6b871a9a30eba7f658654afec5e91f89d157dedfb9b8a0eefbd6b005f614e5" &
        "cf9dfed88b9a23bf37b0f830764cacbe706c9c62c51a15bd";

      NC_M_Leaf_HOST_NO : constant String :=
        "3082033830820220a00302010202141c8c0d75bb441824693b41c2d46ed42d641f3f32300d06092a864886f70d" &
        "01010b0500301a3118301606035504030c0f6e632d696e7465726d656469617465301e170d3236303732383232" &
        "303531305a170d3237303732383232303531305a300f310d300b06035504030c046d61696c30820122300d0609" &
        "2a864886f70d01010105000382010f003082010a0282010100e8a4ddf158a9b29b4b501092b4def0ab62e21a3d" &
        "9565687ed5a9c2a54423dbcadf88e1ad252fff0de4f5090b33bb6111708048253095ca1ff37c3e7ee8022192d8" &
        "ebe54facb7e5b6dbe4563ec54eb2322576a07a2957947e14c7742e266592a21bd1704e6d8cca6df36f1f003533" &
        "02b1620652d00b863d3a5b824dc51c557fe6edcc093cb18eb42cf2e07743bd9ee8cc15d70f83314a7a79f7eda4" &
        "3525d8e5c28a1e8c98abadcb4c6e47fd09f33aec40e1b81f2d21513a08b804318f1f5d6d877ba0a33c8cfa09b0" &
        "784a0bbe06539780b485aa747957c0fadd115d96b81e119c3decdf0786e90e12ba4739e0bfdce67f92828651f1" &
        "9f07f912e7472a46a004d90203010001a38180307e30090603551d1304023000300e0603551d0f0101ff040403" &
        "02078030210603551d11041a30188116616c696365406d61696c2e6578616d706c652e636f6d301d0603551d0e" &
        "0416041474feb7afda364bd8d9b68a07147fc2300c58b6f6301f0603551d23041830168014a83004ae9ec44164" &
        "bd55c5536ba175f1afa07427300d06092a864886f70d01010b0500038201010062233bcfa0bcd9cc8cb72d0955" &
        "4c851aef5407484d8deeb8eb698dc93d8cc84638de8e9a3a78050da00fdb3afa1d11cd3dbb2b243ef416a9681b" &
        "5ed91183edc9c2e6e0f89c9891a2de15f59388cf9bb2434108034431387d4f6d530c0655268a5fc3910dae062b" &
        "3efb6ceed1ef2eb4e5bcda56f711224b4e8083458e03c5e5b5444f1ff79a305ee4e91666f4a8ca3094749d3840" &
        "82eb8167584d0f32d03e5909e97f59c064fdecc99517061ff82b51e42ef79fd7788257e5a257249304ff013b30" &
        "31c7c1475ce438008c6991ddbe1406e6f1b4bb4656e285df88a3624655b4cc27520ea1b9be7b880c819ab21fb7" &
        "c2a46f33dd56d64f7565eae330b0dd813767";

      NC_M_CA_DOM_OK : constant String :=
        "3082033f30820227a0030201020214729dd4801a54586b73e69c048bc99eaeb8357e64300d06092a864886f70d" &
        "01010b050030123110300e06035504030c076e632d726f6f74301e170d3236303732383232303531305a170d33" &
        "36303732353232303531305a301a3118301606035504030c0f6e632d696e7465726d6564696174653082012230" &
        "0d06092a864886f70d01010105000382010f003082010a0282010100f25a28ff863d5122743363eb7b815d4b49" &
        "bbf25bf9d4c9a67acea1d03c869468645ebba4ce16de248dc0667fc5c3630187ff2ad73a0488f4728b3794d279" &
        "ede6e431f096a23ce4037621828b762db7e1d83649616e1753ddff36db01170dd53e86545cecb1b153fee190c2" &
        "3bfb4beb1a03629049d049b7013332fbf4effb038a6095800f20168feca771b27071c565acf9d426b4ac0ba414" &
        "3a25646d3f58c03b69e903a2a838dc56028e4bbd2e36eb573ba4b2d3409c89a0e77b3d9ecea3a86cdb86f80cf9" &
        "94bc6f504c30a27276815d5514bd6df3f6d5b71ed7acaa523a0924c9f87ab479838628c5012ed265e4ceee7968" &
        "169ec9595e8433f2b0f516f8b8ff0203010001a38184308181300f0603551d130101ff040530030101ff300e06" &
        "03551d0f0101ff040403020204301e0603551d1e0101ff04143012a010300e810c2e6578616d706c652e636f6d" &
        "301d0603551d0e04160414a83004ae9ec44164bd55c5536ba175f1afa07427301f0603551d2304183016801460" &
        "feba9da8bbc8d72217d5d3f13c65afc74d1198300d06092a864886f70d01010b0500038201010025843fcd9580" &
        "022bb8cf134e435d827b89b0383432301221b9f1993e76e4239850959888f8f1e8956470eb8a6c19e7310fefd6" &
        "307056e99c1978db47744fcb9533279a9d5486a5a7b73c7288e562522fa4b8df184dcf40017aaed9ba2709fdb1" &
        "614f1dcd191440a27dbf3edd033c55e41a562b14b7d0869a6f8529c0f57b09a36e093dd1055463a598ee8edf5c" &
        "ff13df2316154e7389783672b92ec5da8bd5e4f08f8dd5202f1c529b032eb0a96ddff32c3b107cf62eab6edf0c" &
        "65610b6ffc5f429585d832054fd725264c9a29ef84fc134b7b17252d6f5761f4932157741534c7b50bb0882bea" &
        "4a142080d7d8481d48118cee3346dee6de9eecfd9b50794352";

      NC_M_Leaf_DOM_OK : constant String :=
        "3082033830820220a003020102021464ae330634d107ffc49552b4515b3ff0c0f8b4d0300d06092a864886f70d" &
        "01010b0500301a3118301606035504030c0f6e632d696e7465726d656469617465301e170d3236303732383232" &
        "303531305a170d3237303732383232303531305a300f310d300b06035504030c046d61696c30820122300d0609" &
        "2a864886f70d01010105000382010f003082010a0282010100cef937bc71b1bb208ee36be97fbd675870395425" &
        "5ff9d07c80fc88fa1455dc6ea9ab30fa6fb9ad33a3398e9479f43fbd50bc8f8cf70efa37e7bd2619b9753cbb3c" &
        "23f2219b5df62641d83a05f722123d2a42f9bd0b063ed7baf6af38521667a2031224fbd73075fc4765b073dcd6" &
        "858c64937961272f744118a8a417f8d55bc536ceab591b1b056df8e759d4bb7c67d3a91dfed32453e9f1de12ae" &
        "70ada4f6a00962ba44958801bde83e8d6d919835b8db3ecb66116ade42c61f47b60d889eb252f81d461c81830b" &
        "f9f4c727e6281b6b59daf0301756900c85101acc5735a2404f5ff7aed2aa57ebed947b487d68dcfbae0b1320c2" &
        "500b4b6f6f79e85c21b13f0203010001a38180307e30090603551d1304023000300e0603551d0f0101ff040403" &
        "02078030210603551d11041a30188116616c696365406d61696c2e6578616d706c652e636f6d301d0603551d0e" &
        "0416041407da97d5e38c42eb475b4ca02be2a08d4807038a301f0603551d23041830168014a83004ae9ec44164" &
        "bd55c5536ba175f1afa07427300d06092a864886f70d01010b05000382010100d0614f1acff027ad6fa354acbe" &
        "21a688bd6354e60365b3c8db22e9ee7c696fc7e2068e567733d26a52073031412ec4195ff3446011c249977a16" &
        "de038280b68cd9432b1be6b2fba3e31c1229aef17adf0278ff30bb1dfaa980d3c474446ff1ea7d6ff682b672f2" &
        "683bb8dd308bdda7aa6b75b40a1eb0c29666795e60c5b7b3b3aec0221570e8134899a62449a35ac85d6346033c" &
        "009e4a2f917c177ddd08eba45c00081a62e770a2c26d252ed0778bfe29490b38da31dce07fc807e2605637efd4" &
        "ec06a3cb839b3d6f5fecbecd5826f1c2808313e94158aef0f39f7a27efe360ee41e927c0626253b658ef5f7a1e" &
        "3f0a8ef7357f4c599d0059525759320a0f71";

      NC_M_CA_DOM_NO : constant String :=
        "3082033f30820227a0030201020214729dd4801a54586b73e69c048bc99eaeb8357e65300d06092a864886f70d" &
        "01010b050030123110300e06035504030c076e632d726f6f74301e170d3236303732383232303531305a170d33" &
        "36303732353232303531305a301a3118301606035504030c0f6e632d696e7465726d6564696174653082012230" &
        "0d06092a864886f70d01010105000382010f003082010a0282010100f25a28ff863d5122743363eb7b815d4b49" &
        "bbf25bf9d4c9a67acea1d03c869468645ebba4ce16de248dc0667fc5c3630187ff2ad73a0488f4728b3794d279" &
        "ede6e431f096a23ce4037621828b762db7e1d83649616e1753ddff36db01170dd53e86545cecb1b153fee190c2" &
        "3bfb4beb1a03629049d049b7013332fbf4effb038a6095800f20168feca771b27071c565acf9d426b4ac0ba414" &
        "3a25646d3f58c03b69e903a2a838dc56028e4bbd2e36eb573ba4b2d3409c89a0e77b3d9ecea3a86cdb86f80cf9" &
        "94bc6f504c30a27276815d5514bd6df3f6d5b71ed7acaa523a0924c9f87ab479838628c5012ed265e4ceee7968" &
        "169ec9595e8433f2b0f516f8b8ff0203010001a38184308181300f0603551d130101ff040530030101ff300e06" &
        "03551d0f0101ff040403020204301e0603551d1e0101ff04143012a010300e810c2e6578616d706c652e636f6d" &
        "301d0603551d0e04160414a83004ae9ec44164bd55c5536ba175f1afa07427301f0603551d2304183016801460" &
        "feba9da8bbc8d72217d5d3f13c65afc74d1198300d06092a864886f70d01010b050003820101000ef79c04f58c" &
        "0e6d7550d013398068669170949f65dd38b08c35d56d49224b2a5f908b1a091ef7a95ab96afd8e8bfeaec47413" &
        "6605736e98262ce0b95e2115c6ba5d64d6066c1ec74cd68ea1b986c4e3a4818460aa9a35b719835dc2476f4561" &
        "6a44aa8b36dff8451219d58a28923a2642172994f7210d5eb89f5389a24876f9a55583006809edb4887820cbee" &
        "965a951faee4446efbd6df96dcb92be97fe7cd516c812cac4358bff6ab89babc84e7649be18552ec86f2bd801e" &
        "c871a67afdb152e013b36f9888ff10dc21e9027f6fe595fbba6edc3946917c18b2cf69112d70564fef25b9e29d" &
        "15ea14425eb56beb3030a25f495fef4be4a2539efe074ff28d";

      NC_M_Leaf_DOM_NO : constant String :=
        "308203323082021aa003020102021418f93f13863b658c42d5a0b7607140c617acc764300d06092a864886f70d" &
        "01010b0500301a3118301606035504030c0f6e632d696e7465726d656469617465301e170d3236303732383232" &
        "303531305a170d3237303732383232303531305a300f310d300b06035504030c046d61696c30820122300d0609" &
        "2a864886f70d01010105000382010f003082010a0282010100d11fea55f43b40affeb552e174d1eea16699ff95" &
        "46d0633bd1c8f4c1e6b091a33f34f0474fbbdde13bc1cdd90ac26a47a5d5af7929d705635a935f8624b265ce38" &
        "ea4af0d247fef86c9bd489b50f136ea4bfe8939c90cf439064e0f753c8569dde771fb030f5b32ff0bc72eeca20" &
        "c985aacd67434b5c66e4d876d9000b3f790b01dc4ea826d017f70aee20bdc54acef0fb1ff63957a4c992c1a95c" &
        "6e10945467d28e6c3995afadad5c106b45e4cdef2dd76999f7d558f46f894a458154943d7713d71f35fb1b1ee1" &
        "a37bddfa4cd0b48ff2fe4a4da58ea9b691500c6880f7798f85f765516beefc612f8b32a7d3f023df55118da922" &
        "ed5365fc67b282fc2a20df0203010001a37b307930090603551d1304023000300e0603551d0f0101ff04040302" &
        "0780301c0603551d11041530138111616c696365406578616d706c652e636f6d301d0603551d0e04160414fd11" &
        "391cb8c6785fa05ba2e96d1796c2e28d8482301f0603551d23041830168014a83004ae9ec44164bd55c5536ba1" &
        "75f1afa07427300d06092a864886f70d01010b050003820101000cdfc5b48221476d88dbfe124884de439744ad" &
        "de99440bd0c0688a6a9d4bf1e97abc6ce679b1fcc8bf97bfaaf6306f3e37e5b798ee96f7510ebd1744b26bda49" &
        "74b4d9f29375370905e9df0ab4e747a2914b163373dfe06cad0b08d7c5eb471515cfe25176a098376c768d830a" &
        "df652c021a535a4286ad84a003bdfe0f6586b26b34e813dbef93f8098d08c67cd25cb46a8b38a0f98bd3df39cb" &
        "b37bc34bfc1968199638af811ce80b4d048c16a852fc944a0c82746ed0da967e8a368f869ddb2055cbe954e3e6" &
        "b1485180f52ce08d8ba1dca6ac11107a88c0587296b0c309c28148ca56eee009a129996cc2282a11c140a98c56" &
        "316b72bb6966c7ec0d8c565c";

      NC_M_CA_BOX_OK : constant String :=
        "308203433082022ba0030201020214729dd4801a54586b73e69c048bc99eaeb8357e66300d06092a864886f70d" &
        "01010b050030123110300e06035504030c076e632d726f6f74301e170d3236303732383232303531305a170d33" &
        "36303732353232303531305a301a3118301606035504030c0f6e632d696e7465726d6564696174653082012230" &
        "0d06092a864886f70d01010105000382010f003082010a0282010100f25a28ff863d5122743363eb7b815d4b49" &
        "bbf25bf9d4c9a67acea1d03c869468645ebba4ce16de248dc0667fc5c3630187ff2ad73a0488f4728b3794d279" &
        "ede6e431f096a23ce4037621828b762db7e1d83649616e1753ddff36db01170dd53e86545cecb1b153fee190c2" &
        "3bfb4beb1a03629049d049b7013332fbf4effb038a6095800f20168feca771b27071c565acf9d426b4ac0ba414" &
        "3a25646d3f58c03b69e903a2a838dc56028e4bbd2e36eb573ba4b2d3409c89a0e77b3d9ecea3a86cdb86f80cf9" &
        "94bc6f504c30a27276815d5514bd6df3f6d5b71ed7acaa523a0924c9f87ab479838628c5012ed265e4ceee7968" &
        "169ec9595e8433f2b0f516f8b8ff0203010001a38188308185300f0603551d130101ff040530030101ff300e06" &
        "03551d0f0101ff04040302020430220603551d1e0101ff04183016a01430128110726f6f74406578616d706c65" &
        "2e636f6d301d0603551d0e04160414a83004ae9ec44164bd55c5536ba175f1afa07427301f0603551d23041830" &
        "16801460feba9da8bbc8d72217d5d3f13c65afc74d1198300d06092a864886f70d01010b050003820101003721" &
        "ab73a3d7f3b40efb094cb2763128918462cdce7d2788dad00297b80eff82ebda23530bea2974929997980a5853" &
        "e71c15b24b648852b062fc8c5124e344b5304da177b2ae81561bd3625e1b2fd1f0910d7ded5900264d509f9592" &
        "5cd682617efc4dd2e29bb5e23c8a208379d4ba6d656eaae01aa7edb034d8a9b39ffe4d9e3715d271ffd5c60cdb" &
        "a63210929acccf99cdf7dde614ed8e20d4569ddd5789ecd8b2dd69bf7c8a9f03c737f2f1a1efa366b8bba95422" &
        "6a8d3c441e61275136729b6c73fb78c7bb80096b8fb07815ef2476f50e3e820d09d5badb11c48fb017b410f2e7" &
        "476761c266dfe9f7bbcf4e9051f62ae7c7fd91b0edf754c0da2bbb197f";

      NC_M_Leaf_BOX_OK : constant String :=
        "3082033130820219a0030201020214259a2bd41858775d2c1e2fab024154b5268fe294300d06092a864886f70d" &
        "01010b0500301a3118301606035504030c0f6e632d696e7465726d656469617465301e170d3236303732383232" &
        "303531305a170d3237303732383232303531305a300f310d300b06035504030c046d61696c30820122300d0609" &
        "2a864886f70d01010105000382010f003082010a0282010100d0a0f49a0b9a641116648bdafc87f11f6695a8e5" &
        "5c1d38cb29ca66d5c350cd3995ef9af59b37f90236f92a7d2c9a0a0fe2ee586d74105a96f1a899c5f851b9b464" &
        "f52312dbdec054d62ddccc04fa4990203d190df42356f24e8d1585adbcfccf3e666128c6f0e633e00af4c76dc3" &
        "ea62c29fad090ac822775071e110f9478af4d36dcfd88af1df263dc31751edbf7960a53afdbd104f242f487f5c" &
        "515d57fcf2483bc6b2e515a620089fb021e139c08f23d7bcb30b6b5de6507079b26c4dae6f0e4f024b3a681481" &
        "e76d4a317be9bf6d30e95ef45741056ab0a3ecb25dafe2abfbfdbb25789656f86fd1a01333992d6acae82b8cc4" &
        "f8a41bc941f74c6761597b0203010001a37a307830090603551d1304023000300e0603551d0f0101ff04040302" &
        "0780301b0603551d11041430128110726f6f74406578616d706c652e636f6d301d0603551d0e041604147f5ace" &
        "084a32507bd0312c16e803c98b744c94e4301f0603551d23041830168014a83004ae9ec44164bd55c5536ba175" &
        "f1afa07427300d06092a864886f70d01010b05000382010100c64a63ac3987c2a1efa674e6696a1a3dc45ec87c" &
        "5790d3362b4b54de14be6dd2a45e7c0bc2030c0a731fca8dcec06b1d770b4a1f2a12bda5b326d766f96ff934e8" &
        "0d8be4af8733af55bb2231585da64572525e817688b9af4b13fb7b365594b54d51d57f73edd8265688b584104c" &
        "db7c23081106d8b58e7c735019bed91e863d994ba38881bc0d93565830156401b0b4148a60015aeb0d99bdf3be" &
        "1c23c1351cd916fba2f4127cd56e72e7069dfa214980be7db9c2c31371600e2b4dfeb0e311118b5a2d8fdec6cf" &
        "5fc3f2d988def6a96526ee50f54fe4401a97bacbdcfe5a217ebe43c41b757d22336ea00a53c167901e029eb9f0" &
        "992609a6219464cbb7a188";

      NC_M_CA_BOX_NO : constant String :=
        "308203433082022ba0030201020214729dd4801a54586b73e69c048bc99eaeb8357e67300d06092a864886f70d" &
        "01010b050030123110300e06035504030c076e632d726f6f74301e170d3236303732383232303531305a170d33" &
        "36303732353232303531305a301a3118301606035504030c0f6e632d696e7465726d6564696174653082012230" &
        "0d06092a864886f70d01010105000382010f003082010a0282010100f25a28ff863d5122743363eb7b815d4b49" &
        "bbf25bf9d4c9a67acea1d03c869468645ebba4ce16de248dc0667fc5c3630187ff2ad73a0488f4728b3794d279" &
        "ede6e431f096a23ce4037621828b762db7e1d83649616e1753ddff36db01170dd53e86545cecb1b153fee190c2" &
        "3bfb4beb1a03629049d049b7013332fbf4effb038a6095800f20168feca771b27071c565acf9d426b4ac0ba414" &
        "3a25646d3f58c03b69e903a2a838dc56028e4bbd2e36eb573ba4b2d3409c89a0e77b3d9ecea3a86cdb86f80cf9" &
        "94bc6f504c30a27276815d5514bd6df3f6d5b71ed7acaa523a0924c9f87ab479838628c5012ed265e4ceee7968" &
        "169ec9595e8433f2b0f516f8b8ff0203010001a38188308185300f0603551d130101ff040530030101ff300e06" &
        "03551d0f0101ff04040302020430220603551d1e0101ff04183016a01430128110726f6f74406578616d706c65" &
        "2e636f6d301d0603551d0e04160414a83004ae9ec44164bd55c5536ba175f1afa07427301f0603551d23041830" &
        "16801460feba9da8bbc8d72217d5d3f13c65afc74d1198300d06092a864886f70d01010b05000382010100368d" &
        "0bf75c31f0a6bb3361489b9d28af1affc9acf94781372f0d527464d56cbdf93b5e634f9bad7ecf8984a3123830" &
        "00a5bd8bef7453c67d13beac2c912fb976ef7914a9648c53f3c18f573555faa0a3b704decb9d3434d9f85d0e25" &
        "0b76bdd14531d05950197a4c47c1222770c95783caf3f0aeb80657bf19cf60a6687f0759763b8a6b366c6652b0" &
        "e4738552f4ba77709a6ad471547430cfad052c5390ad91e58e42ef987a437d262a67973456d47d046d3bab4316" &
        "bbfda30c4da95c1fbac93e9ccf3d1c5553f3edbf7e155b4ac16e534b000d7a0e4a95316e86dd6f7eb66d675079" &
        "480f2c901f0f022ef34f4664d2370681689ad7fcb07c0c4cf63e7e607b";

      NC_M_Leaf_BOX_NO : constant String :=
        "3082033030820218a00302010202145ee080bd510b879442bbdcc9ea2d470835c26e0f300d06092a864886f70d" &
        "01010b0500301a3118301606035504030c0f6e632d696e7465726d656469617465301e170d3236303732383232" &
        "303531305a170d3237303732383232303531305a300f310d300b06035504030c046d61696c30820122300d0609" &
        "2a864886f70d01010105000382010f003082010a02820101009d775b3a8f64c55dba751832c55e1b49cde8786a" &
        "e59f72bf0b4dc015b1fbc36dc7b3dd6707f4aa74c3c723df168cb7733dd0c4f7a89c292ab4bc81eeaa1a5ca18c" &
        "f0dd5cfb14447cc5c026530542f153b045a34e2859dd7038b077612aa2fe30ffeadc900c38daf61996eaccbfde" &
        "7650ddacc4b0f5ba7bc8d1865aa449ffd1e4a2dd68b7a483228373a720fb2f9d75c18f03a04bea8a8c1c376c32" &
        "40e74a1597e55d280500decbddabfafc20802f48b88ad96dce4d029a81018df9ded58c2e3a0f8f69dc17c6d8ec" &
        "d277a69676d1c8e9efd488581e29aa9fbb3707ef245d488c584c33590ee28f9bb7db01afdde31170cee50d9f7a" &
        "19d22e403e4039607a573f0203010001a379307730090603551d1304023000300e0603551d0f0101ff04040302" &
        "0780301a0603551d1104133011810f657665406578616d706c652e636f6d301d0603551d0e041604146b16cc51" &
        "72717de255e0a7e8cdb86df85b4fb4f4301f0603551d23041830168014a83004ae9ec44164bd55c5536ba175f1" &
        "afa07427300d06092a864886f70d01010b05000382010100c85bd1e90838cd2d941e010a89adf1ad9d90a51c60" &
        "f564266e527fc9667f64ca1033eb94510844f9f709ecac2a397eebfdedde63082dbc63c24001273770df1ef8b9" &
        "822772c504c260cdcb19e7c502c9a0c6d954dc7e1b042ecb4e37daf8136aea897e0bf761e0b7db77cd9626e48c" &
        "99275e9b9fe90156c9b64b424c34d61681f00bd42e728ab01824fc0293393d08cc6c97f7e48cf9111ae7c49096" &
        "fcad06760c09d0c0f7e52213f9082514a77244d485e89d374227c0557e455357b6b97b0a1e45e39a0fb986e68f" &
        "f01e5cfcfd2ef79435e7281d9796f46a9ca9f3bce3600f20269e0f6f62770933bac369be42f759420ee3ecb27f" &
        "da50614b263f0adcfd44";

      NC_M_Legacy_CA : constant String :=
        "3082033e30820226a0030201020214729dd4801a54586b73e69c048bc99eaeb8357e61300d06092a864886f70d" &
        "01010b050030123110300e06035504030c076e632d726f6f74301e170d3236303732383232303435315a170d33" &
        "36303732353232303435315a301a3118301606035504030c0f6e632d696e7465726d6564696174653082012230" &
        "0d06092a864886f70d01010105000382010f003082010a0282010100f25a28ff863d5122743363eb7b815d4b49" &
        "bbf25bf9d4c9a67acea1d03c869468645ebba4ce16de248dc0667fc5c3630187ff2ad73a0488f4728b3794d279" &
        "ede6e431f096a23ce4037621828b762db7e1d83649616e1753ddff36db01170dd53e86545cecb1b153fee190c2" &
        "3bfb4beb1a03629049d049b7013332fbf4effb038a6095800f20168feca771b27071c565acf9d426b4ac0ba414" &
        "3a25646d3f58c03b69e903a2a838dc56028e4bbd2e36eb573ba4b2d3409c89a0e77b3d9ecea3a86cdb86f80cf9" &
        "94bc6f504c30a27276815d5514bd6df3f6d5b71ed7acaa523a0924c9f87ab479838628c5012ed265e4ceee7968" &
        "169ec9595e8433f2b0f516f8b8ff0203010001a38183308180300f0603551d130101ff040530030101ff300e06" &
        "03551d0f0101ff040403020204301d0603551d1e0101ff04133011a00f300d810b6578616d706c652e636f6d30" &
        "1d0603551d0e04160414a83004ae9ec44164bd55c5536ba175f1afa07427301f0603551d2304183016801460fe" &
        "ba9da8bbc8d72217d5d3f13c65afc74d1198300d06092a864886f70d01010b0500038201010027d6f41f6fd1f4" &
        "a01d400a9d768de6afcc3a56ffb4a6a40045c1051b5917dfad0b0abee75e1e3beab650ba0553256e54cd62d78e" &
        "ab1b580be687ff7afd934466eb0affbf44776dc9736bb426159f67fe6560e46b93b2ae404ae2ce30086f292eb1" &
        "d774d338a68548b9e89140ba7020ff9b60fca4d0c122aad88b8836debac4b53d0bf2c0619d475b6e241ac0b850" &
        "de119230213668a2886fe4176311cb2cbe5da86520737e9e8763277a5a56c0d64d5e77d03d7211a14ebec64ba0" &
        "e2ffde1107abb1f5b035dd5ff8d91d43226ec21ce343acc184ec47e3d6358532a86ab8a6f5e9b8c2d935b098cb" &
        "9f71be92fd262701333ce6368502df40dba78e1117c427a2";

      NC_M_Legacy_Out : constant String :=
        "308203343082021ca00302010202145e75278a3262e7123824a92028992568a07271b1300d06092a864886f70d" &
        "01010b0500301a3118301606035504030c0f6e632d696e7465726d656469617465301e170d3236303732383232" &
        "303435325a170d3237303732383232303435325a302f310f300d06035504030c066c6567616379311c301a0609" &
        "2a864886f70d010901160d657665406576696c2e7465737430820122300d06092a864886f70d01010105000382" &
        "010f003082010a0282010100aac46bacdeda88781081471c9906add3fb9a497c0d4e3586168784fda6e206a34f" &
        "2fd3db1698376554ee8e25edaf85a6a3f99cfbf60aa8a2c9af62aa6b9167dbe25bad98c8b8aaed4210126cf67f" &
        "371c01cbfade0c740120f6c50c0bd513040b7833a197a748624beb04b12f479bfd2f0e0d6c7424c89a841bf02a" &
        "6abd5d740eb8e8e7c28343c3bc8fadeb0c9ba72fa67e81c03df0df3449920d97ced7d4bc738f4133b73e2abf61" &
        "00b7b7752be9f36a30f052bc1b26e9304a912662fd8b2c22d4d4e71341ae7088a50962958c2da5fd805cd124c8" &
        "c3fc2ba19eb24ae79b61e03da5335f965091c0e02e67b2aff3c314694a9719e32f7f93a4faab06a21d76c10203" &
        "010001a35d305b30090603551d1304023000300e0603551d0f0101ff040403020780301d0603551d0e04160414" &
        "5a8f487b700ff5867374f3b16f29f58b0ca35297301f0603551d23041830168014a83004ae9ec44164bd55c553" &
        "6ba175f1afa07427300d06092a864886f70d01010b05000382010100ab30c96056394da2085cb7501867953902" &
        "83e2d1fdc410feed7f3d1abc88cd01f5a8745bf6e3942caf8adb876a2ff5006f11b9395e5f707ad88fe0a3b3cc" &
        "7d88d95453a133c3bdfb78af2224e9a9705826cee9370749e3de88711b5bde2293e8041b8a05e8528bfe764b6b" &
        "7a6a28d277df0509ea1c7deb2ca525ac654734440a8dcfc2092826596a4d485e221efc2cfdbce3cd688b4efc59" &
        "ceca0aa68126033d7b51fc22804eabd19fa341df4d7a4ada5ba5eccf6f0201f998d99134e3180c79e474ef2b60" &
        "613204561e342232a5684eb76d44aaf25ad85efa3cc6aa3e1863ec9b53acde10ea640fd64aea64298f75a176bf" &
        "33f7b852da95747b4a5680ed04e9";

      NC_RID_CA : constant String :=
        "308203343082021ca0030201020214729dd4801a54586b73e69c048bc99eaeb8357e6b300d06092a864886f70d" &
        "01010b050030123110300e06035504030c076e632d726f6f74301e170d3236303732383232303632375a170d33" &
        "36303732353232303632375a301a3118301606035504030c0f6e632d696e7465726d6564696174653082012230" &
        "0d06092a864886f70d01010105000382010f003082010a0282010100f25a28ff863d5122743363eb7b815d4b49" &
        "bbf25bf9d4c9a67acea1d03c869468645ebba4ce16de248dc0667fc5c3630187ff2ad73a0488f4728b3794d279" &
        "ede6e431f096a23ce4037621828b762db7e1d83649616e1753ddff36db01170dd53e86545cecb1b153fee190c2" &
        "3bfb4beb1a03629049d049b7013332fbf4effb038a6095800f20168feca771b27071c565acf9d426b4ac0ba414" &
        "3a25646d3f58c03b69e903a2a838dc56028e4bbd2e36eb573ba4b2d3409c89a0e77b3d9ecea3a86cdb86f80cf9" &
        "94bc6f504c30a27276815d5514bd6df3f6d5b71ed7acaa523a0924c9f87ab479838628c5012ed265e4ceee7968" &
        "169ec9595e8433f2b0f516f8b8ff0203010001a37a3078300f0603551d130101ff040530030101ff300e060355" &
        "1d0f0101ff04040302020430150603551d1e0101ff040b3009a007300588032a0304301d0603551d0e04160414" &
        "a83004ae9ec44164bd55c5536ba175f1afa07427301f0603551d2304183016801460feba9da8bbc8d72217d5d3" &
        "f13c65afc74d1198300d06092a864886f70d01010b0500038201010083bb85963b575b423f597b77c9e329fcbd" &
        "ce752dac1300c79a1920fe861b3f87cda52ce49ef84e5b7c3b11b0857a9cd95510137bf9e42ad7a15238a14f98" &
        "4ec6cb4361939689c99964f8b96e3c80bb3321145432fc7595cb2abc1b8a00bc45677d1556f99e0edbe829f6ec" &
        "b288dae9d78cad5015bc1c27b827a22d6bb526eda5031aa17162b46bc351619dad423398da3f0f63515b9e525d" &
        "7c8201520920bcfbcb3aa1821a3ec20d9dd99a2c21e2314708c6c17a34cc4e5e60d34fd6d99fec5cd0fad6d938" &
        "6dfcd7a5bb4ca0c88179662398ee046ff2bc42e5e6848c1cb794577812decbbf520b33c70e3fb2724f7dfdab80" &
        "b7b23bd014d035bd3b43a10beff5";

      NC_RID_Leaf : constant String :=
        "3082033f30820227a0030201020214638327b11c564e421c607cdc6a3f500bd97a029c300d06092a864886f70d" &
        "01010b0500301a3118301606035504030c0f6e632d696e7465726d656469617465301e170d3236303732383232" &
        "303632375a170d3237303732383232303632375a301c311a301806035504030c116f7574736964652e6576696c" &
        "2e7465737430820122300d06092a864886f70d01010105000382010f003082010a0282010100adb37c5bc78aef" &
        "d46fe8d7fbbe12ff9c5735d959c24bf0676390c2ca2da45916a4bc0e5b325624b41eba751794529e8692f8d3bf" &
        "34ba3c16e80aa72d23fc7f8399b10dc9c85f27ebb61d771b17ccd4ca1bd526630c46f31719030ea108bc39ddc0" &
        "2dac063c38179871871fa3f1c8afb64cc368bf6ed8ab9357ae54a88c301965c05f51e2aedac6b4363240bdc304" &
        "f454cde3cc4d46109fd83f20b1cc450ddce3402dfcaff14391ffbca2f1e0aa1cc803fd715e097c19b97aa45b19" &
        "397857d15aeddd3784136bc1761aa32be7be94f4da92fa38418ba40e8e1287129ed73ca940f5dc8d7b67b212b3" &
        "f042fbdcd4deb9ff013dd8bab2b30bf0f8bc317005092b530203010001a37b307930090603551d130402300030" &
        "0e0603551d0f0101ff040403020780301c0603551d110415301382116f7574736964652e6576696c2e74657374" &
        "301d0603551d0e0416041400e5f0013eb285d0b44f0d7d6496e6f63050a32e301f0603551d23041830168014a8" &
        "3004ae9ec44164bd55c5536ba175f1afa07427300d06092a864886f70d01010b05000382010100907b98463c2e" &
        "4868ddb762ede59e3f4f8f826cbf956a19b31ff361b48ef693273c23a6cb56dd7f0f0f8064962cb7f3680e8700" &
        "2e1bc6668963477bdb0110c67738b4b0e1cab9a9614ac5b349a58afdebdd77a595f79c9ad867590a8d0b9ccbdc" &
        "7dda55e12a45d84065f72c2ef898588616f9812aeed84e36d30bcee1917da045f61fb26a1369fc51040e99db00" &
        "7626dc4232f33b3dc303b2af4bc0a7b6644d9b73fb444121ce5c9a18a543024e8cea0f95368dbc6b1e86f2c906" &
        "2c82c268690cc8d4b00f55493e3289087ec1c42b7615f8732d837762977a67b66541d8b13c22bccb8ce6115581" &
        "bf48a8cd6301f833323da6aec3c2c001c18c657fc1d029dc91";

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

      type Which is (Inside, Outside, Lookalike, CN_Outside, CN_Inside,
                     CN_Org, DN_Inside, DN_Outside, URI_Inside,
                     URI_Outside, URI_Userinfo, M_HOST_OK, M_HOST_NO, M_DOM_OK, M_DOM_NO, M_BOX_OK, M_BOX_NO, M_Legacy, Email);

      type Constrained_Path (Kind : Which) is limited new XV.Path_Source
        with null record;

      overriding function Length (Source : Constrained_Path) return Positive
      is (2);

      overriding function Certificate_At
        (Source : Constrained_Path; Index : Positive)
         return X509C.Certificate
      is (case Source.Kind is
             when Inside =>
               (if Index = 1
                then X509C.Decode_DER (From_Hex (NC_Inside),
                       CryptoLib.ASN1.Default_Limits, Status)
                else X509C.Decode_DER (From_Hex (NC_CA),
                       CryptoLib.ASN1.Default_Limits, Status)),
             when Outside =>
               (if Index = 1
                then X509C.Decode_DER (From_Hex (NC_Outside),
                       CryptoLib.ASN1.Default_Limits, Status)
                else X509C.Decode_DER (From_Hex (NC_CA),
                       CryptoLib.ASN1.Default_Limits, Status)),
             when Lookalike =>
               (if Index = 1
                then X509C.Decode_DER (From_Hex (NC_Lookalike),
                       CryptoLib.ASN1.Default_Limits, Status)
                else X509C.Decode_DER (From_Hex (NC_CA),
                       CryptoLib.ASN1.Default_Limits, Status)),
             when CN_Outside =>
               (if Index = 1
                then X509C.Decode_DER (From_Hex (NC_CN_Outside),
                       CryptoLib.ASN1.Default_Limits, Status)
                else X509C.Decode_DER (From_Hex (NC_CA),
                       CryptoLib.ASN1.Default_Limits, Status)),
             when CN_Inside =>
               (if Index = 1
                then X509C.Decode_DER (From_Hex (NC_CN_Inside),
                       CryptoLib.ASN1.Default_Limits, Status)
                else X509C.Decode_DER (From_Hex (NC_CA),
                       CryptoLib.ASN1.Default_Limits, Status)),
             when CN_Org =>
               (if Index = 1
                then X509C.Decode_DER (From_Hex (NC_CN_Org),
                       CryptoLib.ASN1.Default_Limits, Status)
                else X509C.Decode_DER (From_Hex (NC_CA),
                       CryptoLib.ASN1.Default_Limits, Status)),
             when DN_Inside =>
               (if Index = 1
                then X509C.Decode_DER (From_Hex (NC_DN_Inside),
                       CryptoLib.ASN1.Default_Limits, Status)
                else X509C.Decode_DER (From_Hex (NC_DN_CA),
                       CryptoLib.ASN1.Default_Limits, Status)),
             when DN_Outside =>
               (if Index = 1
                then X509C.Decode_DER (From_Hex (NC_DN_Outside),
                       CryptoLib.ASN1.Default_Limits, Status)
                else X509C.Decode_DER (From_Hex (NC_DN_CA),
                       CryptoLib.ASN1.Default_Limits, Status)),
             when URI_Inside =>
               (if Index = 1
                then X509C.Decode_DER (From_Hex (NC_URI_Inside),
                       CryptoLib.ASN1.Default_Limits, Status)
                else X509C.Decode_DER (From_Hex (NC_URI_CA),
                       CryptoLib.ASN1.Default_Limits, Status)),
             when URI_Outside =>
               (if Index = 1
                then X509C.Decode_DER (From_Hex (NC_URI_Outside),
                       CryptoLib.ASN1.Default_Limits, Status)
                else X509C.Decode_DER (From_Hex (NC_URI_CA),
                       CryptoLib.ASN1.Default_Limits, Status)),
             when URI_Userinfo =>
               (if Index = 1
                then X509C.Decode_DER (From_Hex (NC_URI_Userinfo),
                       CryptoLib.ASN1.Default_Limits, Status)
                else X509C.Decode_DER (From_Hex (NC_URI_CA),
                       CryptoLib.ASN1.Default_Limits, Status)),
             when M_HOST_OK =>
               (if Index = 1
                then X509C.Decode_DER (From_Hex (NC_M_Leaf_HOST_OK),
                       CryptoLib.ASN1.Default_Limits, Status)
                else X509C.Decode_DER (From_Hex (NC_M_CA_HOST_OK),
                       CryptoLib.ASN1.Default_Limits, Status)),
             when M_HOST_NO =>
               (if Index = 1
                then X509C.Decode_DER (From_Hex (NC_M_Leaf_HOST_NO),
                       CryptoLib.ASN1.Default_Limits, Status)
                else X509C.Decode_DER (From_Hex (NC_M_CA_HOST_NO),
                       CryptoLib.ASN1.Default_Limits, Status)),
             when M_DOM_OK =>
               (if Index = 1
                then X509C.Decode_DER (From_Hex (NC_M_Leaf_DOM_OK),
                       CryptoLib.ASN1.Default_Limits, Status)
                else X509C.Decode_DER (From_Hex (NC_M_CA_DOM_OK),
                       CryptoLib.ASN1.Default_Limits, Status)),
             when M_DOM_NO =>
               (if Index = 1
                then X509C.Decode_DER (From_Hex (NC_M_Leaf_DOM_NO),
                       CryptoLib.ASN1.Default_Limits, Status)
                else X509C.Decode_DER (From_Hex (NC_M_CA_DOM_NO),
                       CryptoLib.ASN1.Default_Limits, Status)),
             when M_BOX_OK =>
               (if Index = 1
                then X509C.Decode_DER (From_Hex (NC_M_Leaf_BOX_OK),
                       CryptoLib.ASN1.Default_Limits, Status)
                else X509C.Decode_DER (From_Hex (NC_M_CA_BOX_OK),
                       CryptoLib.ASN1.Default_Limits, Status)),
             when M_BOX_NO =>
               (if Index = 1
                then X509C.Decode_DER (From_Hex (NC_M_Leaf_BOX_NO),
                       CryptoLib.ASN1.Default_Limits, Status)
                else X509C.Decode_DER (From_Hex (NC_M_CA_BOX_NO),
                       CryptoLib.ASN1.Default_Limits, Status)),
             when M_Legacy =>
               (if Index = 1
                then X509C.Decode_DER (From_Hex (NC_M_Legacy_Out),
                       CryptoLib.ASN1.Default_Limits, Status)
                else X509C.Decode_DER (From_Hex (NC_M_Legacy_CA),
                       CryptoLib.ASN1.Default_Limits, Status)),
             when Email =>
               (if Index = 1
                then X509C.Decode_DER (From_Hex (NC_RID_Leaf),
                       CryptoLib.ASN1.Default_Limits, Status)
                else X509C.Decode_DER (From_Hex (NC_RID_CA),
                       CryptoLib.ASN1.Default_Limits, Status)));

      overriding function Is_Trust_Anchor
        (Source : Constrained_Path; Item : X509C.Certificate) return Boolean
      is (True);

      Now_Time : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2027, Month => 1, Day => 1,
         Hour => 0, Minute => 0, Second => 0);

      Result : XV.Validation_Result;
   begin
      --  A name inside the permitted subtree. Before the constraint was
      --  applied this failed as an unknown critical extension, so the chain
      --  could not be used at all.
      Result :=
        XV.Validate_Path (Constrained_Path'(Kind => Inside), Now_Time);
      Check (Result.Valid,
             "a name inside the permitted subtree validates, got "
             & XV.Failure_Image (Result.Failure));

      --  A name outside it. This is what the constraint exists to stop, and
      --  what a validator that merely recognised the extension would allow.
      Result :=
        XV.Validate_Path (Constrained_Path'(Kind => Outside), Now_Time);
      Check (not Result.Valid
             and then Result.Failure = XV.Name_Constraint_Violation,
             "a name outside the permitted subtree is refused, got "
             & XV.Failure_Image (Result.Failure));
      Check (Result.Index = 1,
             "and the failure names the certificate that broke it");

      --  "notexample.com" ends with "example.com" and is not inside it. A
      --  subtree is not a suffix, and this is the name that tells the two
      --  apart -- without it, matching on the ending alone passes every test
      --  here while admitting exactly the certificate the constraint forbids.
      Result :=
        XV.Validate_Path (Constrained_Path'(Kind => Lookalike), Now_Time);
      Check (not Result.Valid
             and then Result.Failure = XV.Name_Constraint_Violation,
             "a name that merely ends with the subtree is refused, got "
             & XV.Failure_Image (Result.Failure));

      --  A certificate with no alternative name at all, whose common name is
      --  outside the subtree. Constraining only the alternative names would
      --  let a constrained CA certify any host, so long as it named it in the
      --  field the constraint did not look at -- and
      --  CryptoLib.X509.Identity will read that field as a host when a caller
      --  asks for the old behaviour. The two have to cover the same ground.
      Result :=
        XV.Validate_Path (Constrained_Path'(Kind => CN_Outside), Now_Time);
      Check (not Result.Valid
             and then Result.Failure = XV.Name_Constraint_Violation,
             "a common name outside the subtree is refused when there is no "
             & "alternative name, got " & XV.Failure_Image (Result.Failure));

      Result :=
        XV.Validate_Path (Constrained_Path'(Kind => CN_Inside), Now_Time);
      Check (Result.Valid,
             "and one inside it is allowed, got "
             & XV.Failure_Image (Result.Failure));

      --  A common name that is not a host name is not judged as one. Refusing
      --  "Example Ltd Payments" against a domain subtree would reject chains
      --  nobody meant to forbid.
      Result :=
        XV.Validate_Path (Constrained_Path'(Kind => CN_Org), Now_Time);
      Check (Result.Valid,
             "a common name that is not a host name is left alone, got "
             & XV.Failure_Image (Result.Failure));

      --  A directory-name subtree constrains the certificate's own subject,
      --  which is how a CA is limited to an organisation rather than to a
      --  domain. It is a prefix of the name, not the whole of it: the base
      --  "C=DK, O=Example Ltd" covers every subject beginning with those two.
      Result :=
        XV.Validate_Path (Constrained_Path'(Kind => DN_Inside), Now_Time);
      Check (Result.Valid,
             "a subject beginning with the permitted name validates, got "
             & XV.Failure_Image (Result.Failure));

      Result :=
        XV.Validate_Path (Constrained_Path'(Kind => DN_Outside), Now_Time);
      Check (not Result.Valid
             and then Result.Failure = XV.Name_Constraint_Violation,
             "a subject in another organisation is refused, got "
             & XV.Failure_Image (Result.Failure));

      --  A URI subtree constrains the host the URI names and nothing else.
      Result :=
        XV.Validate_Path (Constrained_Path'(Kind => URI_Inside), Now_Time);
      Check (Result.Valid,
             "a URI whose host is inside the subtree validates, got "
             & XV.Failure_Image (Result.Failure));

      Result :=
        XV.Validate_Path (Constrained_Path'(Kind => URI_Outside), Now_Time);
      Check (not Result.Valid
             and then Result.Failure = XV.Name_Constraint_Violation,
             "a URI whose host is outside it is refused");

      --  Credentials and a port are not part of the host. Reading
      --  "user@srv.example.com:8443" as the host would put every URI outside
      --  every subtree, which fails safe and is still wrong.
      Result :=
        XV.Validate_Path (Constrained_Path'(Kind => URI_Userinfo), Now_Time);
      Check (Result.Valid,
             "a URI with credentials and a port is judged on its host, got "
             & XV.Failure_Image (Result.Failure));

      --  Mail subtrees, which RFC 5280 gives three readings told apart by the
      --  constraint's own shape. Collapsing them into a suffix test would let
      --  a constraint written for one mailbox cover a whole domain.
      Result := XV.Validate_Path (Constrained_Path'(Kind => M_HOST_OK), Now_Time);
      Check (Result.Valid,
             "a host constraint covers a mailbox on that host, got "
             & XV.Failure_Image (Result.Failure));

      Result := XV.Validate_Path (Constrained_Path'(Kind => M_HOST_NO), Now_Time);
      Check (not Result.Valid
             and then Result.Failure = XV.Name_Constraint_Violation,
             "and does not cover one on a host below it");

      Result := XV.Validate_Path (Constrained_Path'(Kind => M_DOM_OK), Now_Time);
      Check (Result.Valid,
             "a dotted constraint covers hosts under the domain, got "
             & XV.Failure_Image (Result.Failure));

      Result := XV.Validate_Path (Constrained_Path'(Kind => M_DOM_NO), Now_Time);
      Check (not Result.Valid
             and then Result.Failure = XV.Name_Constraint_Violation,
             "and does not cover the domain's own host");

      Result := XV.Validate_Path (Constrained_Path'(Kind => M_BOX_OK), Now_Time);
      Check (Result.Valid,
             "a mailbox constraint covers that mailbox, got "
             & XV.Failure_Image (Result.Failure));

      Result := XV.Validate_Path (Constrained_Path'(Kind => M_BOX_NO), Now_Time);
      Check (not Result.Valid
             and then Result.Failure = XV.Name_Constraint_Violation,
             "and does not cover another mailbox on the same host");

      --  The address in the subject rather than in an alternative name, which
      --  is where legacy certificates put it and where a reader will find it
      --  when there is nothing else. Same reasoning as the common name.
      Result := XV.Validate_Path (Constrained_Path'(Kind => M_Legacy), Now_Time);
      Check (not Result.Valid
             and then Result.Failure = XV.Name_Constraint_Violation,
             "an address in the subject is constrained too, got "
             & XV.Failure_Image (Result.Failure));

      --  A constraint on a form still not applied here -- a registered
      --  identifier, and nothing else permitted. It used to refuse the chain
      --  on sight, which was stricter than the constraint. A subtree
      --  restricts only names of its own type, so a permitted set naming
      --  none but registered identifiers says nothing at all about the DNS
      --  name this certificate carries, and RFC 5280 4.2.1.10 asks for the
      --  constraint to be processed or the certificate rejected only when an
      --  instance of that name form actually appears. None does here, and
      --  OpenSSL admits the same chain.
      --
      --  The certificate that does carry such a name is still refused --
      --  see Check_Unapplicable_Name_Constraint, which holds the two apart.
      Result :=
        XV.Validate_Path (Constrained_Path'(Kind => Email), Now_Time);
      Check (Result.Valid,
             "a constraint that reaches no name this certificate carries "
             & "does not refuse it, got " & XV.Failure_Image (Result.Failure));

      --  The subtree rule is not a suffix match. "example.com" covers
      --  "a.example.com" and must not cover "notexample.com", which is the
      --  difference between a constraint and a string comparison.
      declare
         package NC renames CryptoLib.X509.Name_Constraints;
         CA   : constant X509C.Certificate :=
           X509C.Decode_DER (From_Hex (NC_CA),
                             CryptoLib.ASN1.Default_Limits, Status);
         Leaf : constant X509C.Certificate :=
           X509C.Decode_DER (From_Hex (NC_Inside),
                             CryptoLib.ASN1.Default_Limits, Status);
         Where : constant Natural :=
           X509C.Find_Extension (CA, CryptoLib.ASN1.OIDs.Name_Constraints);
         use type NC.Verdict;
      begin
         Check (Where > 0, "fixture: the CA carries name constraints");
         Check (NC.Check (X509C.Extension_Value (CA, Where), Leaf)
                  = NC.Permitted,
                "the constrained CA permits its own subtree");
      end;
   end Check_Name_Constraints;


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
   Check_Policy_Processing;
   Check_Policy_Qualifiers;
   Check_Policy_Aware_Path_Building;
   Check_Self_Issued_Policy_Allowance;
   Check_Unsupported_Algorithm;
   Check_Verification_Failure_Kinds;
   Check_Policy_Tree_Bound;
   Check_Policy_Set_Is_A_Set;
   Check_Policy_Constraint_Skipcerts;
   Check_Name_Constraint_Depth_Fields;
   Check_Weak_RSA_Key;
   Check_Serial_Comparison;
   Check_Unapplicable_Name_Constraint;
   Check_Ed448;
   Check_Ed448_Certificate;
   Check_CSR_Signing;
   Check_Validity_Not_Past_Issuer;
   Check_Impossible_Dates;
   Check_Undated_Statement_Ages;
   Check_Bcrypt_PBKDF;
   Check_OpenSSH_Key_Unlock;
   Check_OpenSSH_Signature;
   Check_ECDSA_Raw_Entry_Points;
   Check_Constant_Time_Equal;
   Check_DH_Peer_Validation;
   Check_OpenSSH_Fingerprints;
   Check_DH_Group14;
   Check_DH_Group1;
   Check_X25519_Shared_Secret;
   Check_Chain_Constraint_Bypasses;
   Check_Signature_Algorithm_Agreement;
   Check_Random_Fails_Closed;
   Check_Off_Curve_Key;
   Check_Ed25519_Encoding;
   Check_Serial_Numbers;
   Check_Validity_Window;
   Check_Key_Identifiers;
   Check_PKCS12_Work_Factor;
   Check_PKCS12_Work_Ceiling;
   Check_Large_Certificate;
   Check_Oversized_Serial;
   Check_Decoder_Robustness;
   Check_Certificate_Ambiguity;
   Check_X509_Access_Locations;
   Check_RSA_Verify;
   Check_ECDSA_Curves;
   Check_X509_Validation;
   Check_X509_Identity;
   Check_X509_Purposes;
   Check_X509_Names;
   Check_Certificate_Armour;
   Check_X509_CRL;
   Check_Revocation_Details;
   Check_OCSP;
   Check_X509_Path_Building;
   Check_Name_Constraints;
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
