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
with Ada.Streams;
with CryptoLib.Blake2b;
with CryptoLib.Hashes;

package body Tests_Hashes is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Certificates.Certificate_Status;
   use type Interfaces.Unsigned_32;

   procedure Expect_MD5
     (Data     : Ada.Streams.Stream_Element_Array;
      Expected : CryptoLib.Hashes.MD5_Digest;
      Label    : String)
   is
      Actual : constant CryptoLib.Hashes.MD5_Digest := CryptoLib.Hashes.MD5 (Data);
   begin
      for Index in Actual'Range loop
         Check (Actual (Index) = Expected (Index), Label);
      end loop;
   end Expect_MD5;

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

   --  Hashing a message in pieces, for the two digests where nothing did.
   --
   --  The streaming tests cover MD5, SHA-1 and SHA-384. SHA-256 and SHA-512
   --  had none, and each digest buffers its own partial block -- 64 octets
   --  for SHA-256, 128 for SHA-512 -- so a sibling being right says nothing
   --  about them.
   --
   --  The one-shot SHA256 is Initialize, one Update, Finalize, so the NIST
   --  vectors never cross a chunk boundary. Production does: versionlib
   --  hashes a file in slices and shaping feeds a glyph at a time. A
   --  buffering fault there gives a wrong digest for exactly the inputs the
   --  vectors do not cover.
   procedure Check_Streaming_SHA256_SHA512 is
      function Sequence (Length : Natural)
        return Ada.Streams.Stream_Element_Array
      is
         Result : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Length));
      begin
         for I in Result'Range loop
            Result (I) :=
              Ada.Streams.Stream_Element (Natural (I) mod 251);
         end loop;
         return Result;
      end Sequence;
   begin
      --  Every length across the padding boundary, fed one octet at a time
      --  and split at a third, against the one-shot answer.
      for Length in 0 .. 200 loop
         declare
            Data  : constant Ada.Streams.Stream_Element_Array :=
              Sequence (Length);
            Split : constant Ada.Streams.Stream_Element_Offset :=
              Data'First + Ada.Streams.Stream_Element_Offset (Length / 3) - 1;

            Byte_256, Split_256 : CryptoLib.Hashes.SHA256_Context;
            Byte_512, Split_512 : CryptoLib.Hashes.SHA512_Context;
         begin
            CryptoLib.Hashes.Initialize_SHA256 (Byte_256);
            CryptoLib.Hashes.Initialize_SHA512 (Byte_512);
            for Index in Data'Range loop
               CryptoLib.Hashes.Update (Byte_256, Data (Index .. Index));
               CryptoLib.Hashes.Update (Byte_512, Data (Index .. Index));
            end loop;
            Check (Ada.Streams.Stream_Element_Array
                     (CryptoLib.Hashes.Finalize (Byte_256))
                   = Ada.Streams.Stream_Element_Array
                       (CryptoLib.Hashes.SHA256 (Data)),
                   "SHA-256 one octet at a time matches the one-shot at"
                   & Natural'Image (Length) & " octets");
            Check (Ada.Streams.Stream_Element_Array
                     (CryptoLib.Hashes.Finalize (Byte_512))
                   = Ada.Streams.Stream_Element_Array
                       (CryptoLib.Hashes.SHA512 (Data)),
                   "SHA-512 one octet at a time matches the one-shot at"
                   & Natural'Image (Length) & " octets");

            CryptoLib.Hashes.Initialize_SHA256 (Split_256);
            CryptoLib.Hashes.Update (Split_256, Data (Data'First .. Split));
            CryptoLib.Hashes.Update (Split_256, Data (Split + 1 .. Data'Last));
            Check (Ada.Streams.Stream_Element_Array
                     (CryptoLib.Hashes.Finalize (Split_256))
                   = Ada.Streams.Stream_Element_Array
                       (CryptoLib.Hashes.SHA256 (Data)),
                   "SHA-256 split update matches the one-shot at"
                   & Natural'Image (Length) & " octets");

            CryptoLib.Hashes.Initialize_SHA512 (Split_512);
            CryptoLib.Hashes.Update (Split_512, Data (Data'First .. Split));
            CryptoLib.Hashes.Update (Split_512, Data (Split + 1 .. Data'Last));
            Check (Ada.Streams.Stream_Element_Array
                     (CryptoLib.Hashes.Finalize (Split_512))
                   = Ada.Streams.Stream_Element_Array
                       (CryptoLib.Hashes.SHA512 (Data)),
                   "SHA-512 split update matches the one-shot at"
                   & Natural'Image (Length) & " octets");
         end;
      end loop;
   end Check_Streaming_SHA256_SHA512;

   --  The SHA-1 fingerprint, which is the one a Windows store answers to.
   --
   --  The SHA-256 fingerprint is tested. This one was not, and it is the
   --  one with a failure mode that says nothing: certutil matches
   --  "Cert Hash(sha1)", and handed a SHA-256 it exits zero having deleted
   --  nothing. devcert removes a development CA from the Windows store by
   --  this value, so a wrong one leaves that CA trusted and reports success.
   --
   --  Checked against what openssl prints for the same certificate, and
   --  checked not to be the other fingerprint -- the two are both lowercase
   --  hex over the same DER, and swapping them is precisely the mistake the
   --  spec warns about.
   procedure Check_SHA1_Fingerprint is
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

      Expected_SHA1 : constant String :=
        "ef2b656b25ce4502b72d46af56f68dad01d47f74";
      --  Colon-separated, which is what a person compares in a browser or
      --  a certificate manager. SHA1_Fingerprint deliberately is not: a
      --  store that wants the plain hex would not match this one either,
      --  which is the same mistake in the other direction.
      Expected_SHA256 : constant String :=
        "90:41:30:c5:10:0a:37:17:2c:e5:ef:b0:ee:da:e7:22"
        & ":9b:46:ed:9d:39:c7:35:e6:66:25:ee:14:17:21:a2:39";

      Got_SHA1 : constant String :=
        CryptoLib.Certificates.SHA1_Fingerprint (E448_Leaf_PEM);
      Got_SHA256 : constant String :=
        CryptoLib.Certificates.Fingerprint (E448_Leaf_PEM);
   begin
      Check (Got_SHA1 = Expected_SHA1,
             "the SHA-1 fingerprint is what openssl prints for the same "
             & "certificate, got " & Got_SHA1);
      Check (Got_SHA256 = Expected_SHA256,
             "and the SHA-256 one likewise");
      Check (Got_SHA1 /= Got_SHA256,
             "the two are different values, so a store told the wrong one "
             & "would not match by accident");
      Check ((for all C of Got_SHA1 => C /= ':'),
             "and the SHA-1 form carries no separators, certutil wanting "
             & "the digits unbroken");
      Check (Got_SHA1'Length = 40,
             "SHA-1 is forty hex digits, got"
             & Natural'Image (Got_SHA1'Length));

      Check (CryptoLib.Certificates.SHA1_Fingerprint ("") = "",
             "and text carrying no certificate has no fingerprint rather "
             & "than the hash of nothing");
   end Check_SHA1_Fingerprint;

   procedure Check_MD5_Vectors is
   begin
      Expect_MD5
        (Ada.Streams.Stream_Element_Array'(1 .. 0 => 0),
         [16#D4#, 16#1D#, 16#8C#, 16#D9#, 16#8F#, 16#00#, 16#B2#, 16#04#,
          16#E9#, 16#80#, 16#09#, 16#98#, 16#EC#, 16#F8#, 16#42#, 16#7E#],
         "MD5 empty vector");
      Expect_MD5
        (Bytes_From_String ("abc"),
         [16#90#, 16#01#, 16#50#, 16#98#, 16#3C#, 16#D2#, 16#4F#, 16#B0#,
          16#D6#, 16#96#, 16#3F#, 16#7D#, 16#28#, 16#E1#, 16#7F#, 16#72#],
         "MD5 abc vector");
      --  RFC 1321 vectors that exercise the padding paths the "abc" case cannot:
      --  62 bytes forces the extra-block pad (used > 56), 80 bytes spans two
      --  compression blocks.
      Expect_MD5
        (Bytes_From_String
           ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
         [16#D1#, 16#74#, 16#AB#, 16#98#, 16#D2#, 16#77#, 16#D9#, 16#F5#,
          16#A5#, 16#61#, 16#1C#, 16#2C#, 16#9F#, 16#41#, 16#9D#, 16#9F#],
         "MD5 alphanumeric vector");
      Expect_MD5
        (Bytes_From_String
           ("1234567890123456789012345678901234567890"
            & "1234567890123456789012345678901234567890"),
         [16#57#, 16#ED#, 16#F4#, 16#A2#, 16#2B#, 16#E3#, 16#C9#, 16#55#,
          16#AC#, 16#49#, 16#DA#, 16#2E#, 16#21#, 16#07#, 16#B6#, 16#7A#],
         "MD5 eighty-digit vector");
   end Check_MD5_Vectors;

   --  Streaming MD5: chunked updates reproduce the KAT, and byte-at-a-time
   --  updates match the one-shot digest across every padding boundary.
   procedure Check_Streaming_MD5 is
   begin
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
   end Check_Streaming_MD5;

   --  SHA-3 / SHAKE NIST known-answer vectors (previously only validated
   --  transitively via ML-KEM / sntrup761).
   procedure Check_SHA3_And_SHAKE_Vectors is
   begin
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
   end Check_SHA3_And_SHAKE_Vectors;

   --  Direct SHA-1/2 known-answer vectors ("abc"), previously only exercised
   --  transitively through PBKDF2 / ML-KEM.
   procedure Check_SHA1_Vector is
   begin
      Check
        (Ada.Streams.Stream_Element_Array
           (CryptoLib.Hashes.SHA1 (Bytes_From_String ("abc")))
         = Bytes_From_Hex ("a9993e364706816aba3e25717850c26c9cd0d89d"),
         "SHA-1 KAT (abc)");
   end Check_SHA1_Vector;

   --  Streaming SHA-1: chunked updates reproduce the KAT, and a byte-at-a-time
   --  multi-block (>64 byte) input matches the one-shot digest.
   procedure Check_Streaming_SHA1 is
   begin
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
   end Check_Streaming_SHA1;

   procedure Check_SHA256_SHA384_Vectors is
   begin
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
   end Check_SHA256_SHA384_Vectors;

   --  Streaming SHA-384: chunked updates reproduce the KAT, the 112-byte NIST
   --  vector exercises the extra-block pad (used > 112) across two blocks, and
   --  byte-at-a-time updates match the one-shot at every padding boundary.
   procedure Check_Streaming_SHA384 is
   begin
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
   end Check_Streaming_SHA384;

   procedure Check_SHA512_Vector is
   begin
      Check
        (Ada.Streams.Stream_Element_Array
           (CryptoLib.Hashes.SHA512 (Bytes_From_String ("abc")))
         = Bytes_From_Hex
             ("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
              & "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
         "SHA-512 KAT (abc)");
   end Check_SHA512_Vector;

   --  HMAC known-answer vectors (RFC 2202 / RFC 4231 test case 1:
   --  key = 0x0b x20, message = "Hi There").
   procedure Check_HMAC_Vectors is
   begin
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
   end Check_HMAC_Vectors;

   --  HMAC-SHA384 (RFC 4231 test case 1) plus the long-key path of all four
   --  variants (RFC 2202 / RFC 4231 test case 6): a key longer than the hash
   --  block is replaced by its own digest before the pads are derived.
   procedure Check_HMAC_SHA384_Long_Keys is
   begin
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
   end Check_HMAC_SHA384_Long_Keys;

   --  Streaming HMAC: split and byte-at-a-time updates reproduce the one-shot
   --  tag, with a short key and with a key longer than the hash block, and an
   --  Initialize/Finalize with no Update matches the empty message.
   procedure Check_Streaming_HMAC is
   begin
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
   end Check_Streaming_HMAC;

   --  BLAKE2b (RFC 7693) against hashlib, which is an independent
   --  implementation of the same specification. The cases are chosen for the
   --  places a transcription goes wrong: the empty message, a one-octet
   --  digest, a keyed hash, and the 128-octet block boundary in both
   --  directions -- Update must not compress a full buffer until something
   --  follows it, because the final block takes a different path.
   procedure Check_Blake2b is
      package B2 renames CryptoLib.Blake2b;
      Empty64 : constant String :=
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444"
        & "934eb04b903a685b1448b755d56f701afe9be2ce";
      Abc64 : constant String :=
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de"
        & "4533cc9518d38aa8dbf1925ab92386edd4009923";
      Abc32 : constant String :=
        "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319";
      Abc1 : constant String :=
        "6b";
      Long64 : constant String :=
        "195257374939c051a11c59d4c478b33e2be001f1fdfbea24d6036bf0bc4d0eb77f64d83243446d29103fe9e9"
        & "46707c9c6daffeb77eafcf0c856234af0527d456";
      Keyed64 : constant String :=
        "9f0b58e0218b30f17bd4857cedca136f64237362fdb79478916e54750aa29d87c4906ee41aeee3fec1627e89"
        & "e059eae4f2d435c16c0e122d6e2f9dd3abf8da1c";
      Block128 : constant String :=
        "2319e3789c47e2daa5fe807f61bec2a1a6537fa03f19ff32e87eecbfd64b7e0e8ccff439ac333b040f19b0c4"
        & "ddd11a61e24ac1fe0f10a039806c5dcc0da3d115";
      Block129 : constant String :=
        "9e0be1aaa2bd15ede5b418a67465bb7bb715e84c35181ca43da313d6eef77eff13b947f944bdd362bfd2be63"
        & "a216945b7bbc0697bb4ae8111328301d5be06770";
      Empty : constant Ada.Streams.Stream_Element_Array (1 .. 0) :=
        [others => 0];
      Abc   : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("abc");
      Key   : constant Ada.Streams.Stream_Element_Array :=
        [1, 2, 3, 4, 5, 6, 7, 8];
      Long  : Ada.Streams.Stream_Element_Array (1 .. 300);
      One_Block : Ada.Streams.Stream_Element_Array (1 .. 128);
      Over_Block : Ada.Streams.Stream_Element_Array (1 .. 129);
   begin
      for I in Long'Range loop
         Long (I) := Ada.Streams.Stream_Element (Natural (I) mod 251);
      end loop;
      for I in One_Block'Range loop
         One_Block (I) := Ada.Streams.Stream_Element (Natural (I) - 1);
      end loop;
      Over_Block (1 .. 128) := One_Block;
      Over_Block (129) := 0;

      Check (B2.Hash (Empty, 64) = Bytes_From_Hex (Empty64),
             "BLAKE2b of the empty message");
      Check (B2.Hash (Abc, 64) = Bytes_From_Hex (Abc64),
             "BLAKE2b of abc");
      Check (B2.Hash (Abc, 32) = Bytes_From_Hex (Abc32),
             "and at a 32-octet digest length, which is a different "
             & "parameter block and so a different hash");
      Check (B2.Hash (Abc, 1) = Bytes_From_Hex (Abc1),
             "and at one octet");
      Check (B2.Hash (Long, 64) = Bytes_From_Hex (Long64),
             "BLAKE2b over more than two blocks");
      Check (B2.Hash (Key, Abc, 64) = Bytes_From_Hex (Keyed64),
             "keyed BLAKE2b, whose key occupies a padded block of its own");
      Check (B2.Hash (One_Block, 64) = Bytes_From_Hex (Block128),
             "exactly one block");
      Check (B2.Hash (Over_Block, 64) = Bytes_From_Hex (Block129),
             "and one block plus an octet");

      --  Streaming must reach the same digest however the message is cut.
      declare
         Item   : B2.Context;
         Digest : Ada.Streams.Stream_Element_Array (1 .. 64);
      begin
         B2.Initialize (Item, 64);
         for I in Long'Range loop
            B2.Update (Item, Long (I .. I));
         end loop;
         B2.Finalize (Item, Digest);
         Check (Digest = Bytes_From_Hex (Long64),
                "a byte-at-a-time hash matches the one-shot digest");
      end;

      declare
         Item   : B2.Context;
         Digest : Ada.Streams.Stream_Element_Array (1 .. 64);
      begin
         B2.Initialize (Item, 64);
         B2.Update (Item, Long (1 .. 128));
         B2.Update (Item, Long (129 .. 300));
         B2.Finalize (Item, Digest);
         Check (Digest = Bytes_From_Hex (Long64),
                "and so does a split exactly on the block boundary");
      end;
   end Check_Blake2b;

   --  AUnit routine wrappers. Each check is a test of its own, so a
   --  failure reports the check that failed and the rest still run.
   procedure Run_Check_OpenSSH_Fingerprints (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Streaming_SHA256_SHA512 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_SHA1_Fingerprint (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_XXH3 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Adler32 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_CRC32 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Blake2b (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_MD5_Vectors (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Streaming_MD5 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_SHA3_And_SHAKE_Vectors (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_SHA1_Vector (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Streaming_SHA1 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_SHA256_SHA384_Vectors (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Streaming_SHA384 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_SHA512_Vector (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_HMAC_Vectors (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_HMAC_SHA384_Long_Keys (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Streaming_HMAC (Item : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Check_OpenSSH_Fingerprints (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_OpenSSH_Fingerprints;
   end Run_Check_OpenSSH_Fingerprints;

   procedure Run_Check_Streaming_SHA256_SHA512 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Streaming_SHA256_SHA512;
   end Run_Check_Streaming_SHA256_SHA512;

   procedure Run_Check_SHA1_Fingerprint (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_SHA1_Fingerprint;
   end Run_Check_SHA1_Fingerprint;

   procedure Run_Check_XXH3 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_XXH3;
   end Run_Check_XXH3;

   procedure Run_Check_Adler32 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Adler32;
   end Run_Check_Adler32;

   procedure Run_Check_CRC32 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_CRC32;
   end Run_Check_CRC32;

   procedure Run_Check_MD5_Vectors (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_MD5_Vectors;
   end Run_Check_MD5_Vectors;

   procedure Run_Check_Streaming_MD5 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Streaming_MD5;
   end Run_Check_Streaming_MD5;

   procedure Run_Check_SHA3_And_SHAKE_Vectors (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_SHA3_And_SHAKE_Vectors;
   end Run_Check_SHA3_And_SHAKE_Vectors;

   procedure Run_Check_SHA1_Vector (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_SHA1_Vector;
   end Run_Check_SHA1_Vector;

   procedure Run_Check_Streaming_SHA1 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Streaming_SHA1;
   end Run_Check_Streaming_SHA1;

   procedure Run_Check_SHA256_SHA384_Vectors (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_SHA256_SHA384_Vectors;
   end Run_Check_SHA256_SHA384_Vectors;

   procedure Run_Check_Streaming_SHA384 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Streaming_SHA384;
   end Run_Check_Streaming_SHA384;

   procedure Run_Check_SHA512_Vector (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_SHA512_Vector;
   end Run_Check_SHA512_Vector;

   procedure Run_Check_HMAC_Vectors (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_HMAC_Vectors;
   end Run_Check_HMAC_Vectors;

   procedure Run_Check_HMAC_SHA384_Long_Keys (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_HMAC_SHA384_Long_Keys;
   end Run_Check_HMAC_SHA384_Long_Keys;

   procedure Run_Check_Streaming_HMAC (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Streaming_HMAC;
   end Run_Check_Streaming_HMAC;

   procedure Run_Check_Blake2b (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Blake2b;
   end Run_Check_Blake2b;

   overriding procedure Register_Tests (Item : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (Item, Run_Check_OpenSSH_Fingerprints'Access, "openssh fingerprints");
      Register_Routine (Item, Run_Check_Streaming_SHA256_SHA512'Access, "streaming sha256 sha512");
      Register_Routine (Item, Run_Check_SHA1_Fingerprint'Access, "sha1 fingerprint");
      Register_Routine (Item, Run_Check_XXH3'Access, "xxh3");
      Register_Routine (Item, Run_Check_Adler32'Access, "adler32");
      Register_Routine (Item, Run_Check_CRC32'Access, "crc32");
      Register_Routine (Item, Run_Check_Blake2b'Access, "blake2b");
      Register_Routine (Item, Run_Check_MD5_Vectors'Access, "md5 vectors");
      Register_Routine (Item, Run_Check_Streaming_MD5'Access, "streaming md5");
      Register_Routine (Item, Run_Check_SHA3_And_SHAKE_Vectors'Access, "sha3 and shake vectors");
      Register_Routine (Item, Run_Check_SHA1_Vector'Access, "sha1 vector");
      Register_Routine (Item, Run_Check_Streaming_SHA1'Access, "streaming sha1");
      Register_Routine (Item, Run_Check_SHA256_SHA384_Vectors'Access, "sha256 sha384 vectors");
      Register_Routine (Item, Run_Check_Streaming_SHA384'Access, "streaming sha384");
      Register_Routine (Item, Run_Check_SHA512_Vector'Access, "sha512 vector");
      Register_Routine (Item, Run_Check_HMAC_Vectors'Access, "hmac vectors");
      Register_Routine (Item, Run_Check_HMAC_SHA384_Long_Keys'Access, "hmac sha384 long keys");
      Register_Routine (Item, Run_Check_Streaming_HMAC'Access, "streaming hmac");
   end Register_Tests;

   overriding function Name (Item : Test_Case) return AUnit.Message_String is
      pragma Unreferenced (Item);
   begin
      return AUnit.Format ("cryptolib hashes, checksums and fingerprints");
   end Name;

end Tests_Hashes;
