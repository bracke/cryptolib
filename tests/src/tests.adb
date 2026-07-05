with Ada.Streams;
with Ada.Text_IO;
with Interfaces;
with System;

with CryptoLib.ChaCha20_Poly1305;
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

procedure Tests is
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.Errors.Status;

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
   Check_ECDSA_P384_P521_Signing;
   Check_XXH3;

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

   --  chacha20-poly1305@openssh.com known-answer vectors (generated by an
   --  independent reference cross-checked against OpenSSL's ChaCha20) and
   --  Seal/Open round-trip.
   declare
      use type Interfaces.Unsigned_32;

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

   Ada.Text_IO.Put_Line ("cryptolib tests passed");
end Tests;
