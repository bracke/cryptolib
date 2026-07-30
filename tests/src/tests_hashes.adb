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

package body Tests_Hashes is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Certificates.Certificate_Status;
   use type Interfaces.Unsigned_32;


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

end Tests_Hashes;
