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

package body Tests_Ciphers is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Certificates.Certificate_Status;
   use type Interfaces.Unsigned_32;


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


   --  Every cipher name, against what OpenSSL makes of it.
   --
   --  Initialize dispatches on the name, and each name is its own branch
   --  fixing a mode and a key width. The suite reached four of them; the
   --  rest -- both 128-bit names, both 192-bit ones, and 3DES -- had no
   --  user here, so a name wired to the wrong width or the wrong mode would
   --  have encrypted happily and matched nothing anywhere else.
   --
   --  Same key, same IV, same plaintext as OpenSSL was given, so the
   --  ciphertext has to be identical byte for byte. That is what a mode or
   --  a width cannot be wrong in and still pass.
   procedure Check_Cipher_Names is
      Message : constant String :=
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

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

      procedure One_Name (Name, Key, IV, Expected : String) is
         Context : CryptoLib.Ciphers.Cipher_State;
         Plain   : constant Ada.Streams.Stream_Element_Array :=
           From_Hex (Message);
         Output  : Ada.Streams.Stream_Element_Array (Plain'Range);
         Status  : CryptoLib.Errors.Status;
      begin
         Status :=
           CryptoLib.Ciphers.Initialize
             (Context, Name, CryptoLib.Ciphers.Client_To_Server,
              From_Hex (Key), From_Hex (IV));
         Check (Status = CryptoLib.Errors.Ok,
                Name & " initialises with a key of its own width");
         Status := CryptoLib.Ciphers.Encrypt (Context, Plain, Output);
         Check (Status = CryptoLib.Errors.Ok, Name & " encrypts");
         Check (Output = From_Hex (Expected),
                Name & " produces what OpenSSL produces");
      end One_Name;
   begin
      One_Name ("aes128-ctr",
                "abababababababababababababababab",
                "000102030405060708090a0b0c0d0e0f",
                "10dec75cc1a7da62cdc982e6186e758908c140b5c5379873a710c0edcc85ca45"
                & "");
      One_Name ("aes192-ctr",
                "abababababababababababababababababababababababab",
                "000102030405060708090a0b0c0d0e0f",
                "74ca7eb72c325edb3f70dd4039febc906eb18324f9afac0f863fa647b83d2d59"
                & "");
      One_Name ("aes256-ctr",
                "abababababababababababababababababababababababababababababababab",
                "000102030405060708090a0b0c0d0e0f",
                "a66348b2729c70247ee550459837889edef0037d5f0d1293b392a6d2fd65ee3f"
                & "");
      One_Name ("aes128-cbc",
                "abababababababababababababababab",
                "000102030405060708090a0b0c0d0e0f",
                "3bf79ce0e6082a306a5e5b8392e28a3e78dd9a3c5ef8aee50ec762150ed621df"
                & "");
      One_Name ("aes192-cbc",
                "abababababababababababababababababababababababab",
                "000102030405060708090a0b0c0d0e0f",
                "2094ac9d7f1e93c6622a03db786f7316f5616711fec4d266a6e411c017822477"
                & "");
      One_Name ("aes256-cbc",
                "abababababababababababababababababababababababababababababababab",
                "000102030405060708090a0b0c0d0e0f",
                "76ed2071a4b20ae2dbe279d87c725b19891bd66749dfb5cfd82d8f9ff43e5be1"
                & "");
      One_Name ("3des-cbc",
                "abababababababababababababababababababababababab",
                "0001020304050607",
                "9943829c28b98324dbe5bb7132363aaa8b7e81a7db6fdfefd446f77c0d9626cd"
                & "");

      --  A key too short for the name it was given is refused rather than
      --  stretched. A longer one is accepted and cut to the width the name
      --  names, which is what SSH's key derivation produces when the two
      --  directions negotiate ciphers of different widths.
      declare
         Context : CryptoLib.Ciphers.Cipher_State;
      begin
         Check (CryptoLib.Ciphers.Initialize
                  (Context, "aes256-ctr", CryptoLib.Ciphers.Client_To_Server,
                   From_Hex ("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
                   From_Hex ("000102030405060708090a0b0c0d0e0f"))
                /= CryptoLib.Errors.Ok,
                "a 128-bit key under a 256-bit name is refused");

         Check (CryptoLib.Ciphers.Initialize
                  (Context, "aes128-ctr", CryptoLib.Ciphers.Client_To_Server,
                   From_Hex ("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
                             & "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
                   From_Hex ("000102030405060708090a0b0c0d0e0f"))
                = CryptoLib.Errors.Ok,
                "while a 256-bit key under a 128-bit name is taken as the "
                & "first sixteen bytes, which is how ssh_lib hands one "
                & "derivation to two ciphers of different widths");
      end;
   end Check_Cipher_Names;


   --  How a packet sequence number becomes a UMAC nonce.
   --
   --  The RFC 4418 vectors go through Generate_With_Nonce, which takes the
   --  nonce ready-made. Production goes through Generate, which builds one
   --  from the sequence number: eight bytes, big-endian, the high four zero
   --  because an SSH sequence is 32 bits. Nothing checked that conversion on
   --  either side of the interface -- the vectors never reach it, and
   --  ssh_lib round-trips its own packets, where both ends would agree on a
   --  wrong nonce just as readily as a right one.
   --
   --  Wrong here means every packet fails authentication against a real
   --  server while every test in both crates passes.
   procedure Check_UMAC_Sequence_Nonce is
      Key : constant CryptoLib.UMAC.UMAC_Key := [others => 16#3C#];
      Message : constant Ada.Streams.Stream_Element_Array (1 .. 5) :=
        [1, 2, 3, 4, 5];

      --  A sequence number whose four bytes all differ, so reversing them
      --  cannot land on the same value.
      Sequence : constant Interfaces.Unsigned_32 := 16#01020304#;

      Big_Endian : constant Ada.Streams.Stream_Element_Array (1 .. 8) :=
        [0, 0, 0, 0, 16#01#, 16#02#, 16#03#, 16#04#];
      Little_Endian : constant Ada.Streams.Stream_Element_Array (1 .. 8) :=
        [16#04#, 16#03#, 16#02#, 16#01#, 0, 0, 0, 0];

      From_Sequence : constant Ada.Streams.Stream_Element_Array :=
        CryptoLib.UMAC.Generate
          ("umac-64@openssh.com", Key, Sequence, Message);
   begin
      Check (From_Sequence'Length = 8,
             "a umac-64 tag is eight bytes, got"
             & Natural'Image (Natural (From_Sequence'Length)));

      Check (From_Sequence
             = CryptoLib.UMAC.Generate_With_Nonce
                 ("umac-64@openssh.com", Key, Big_Endian, Message),
             "the sequence number becomes the low four bytes of a big-endian "
             & "eight-byte nonce");

      --  The same four bytes the other way round must not produce the same
      --  tag, or the test above would hold whichever way it was built.
      Check (From_Sequence
             /= CryptoLib.UMAC.Generate_With_Nonce
                  ("umac-64@openssh.com", Key, Little_Endian, Message),
             "and not the same bytes reversed");

      --  Sequence numbers are per packet, so two of them must not agree.
      Check (From_Sequence
             /= CryptoLib.UMAC.Generate
                  ("umac-64@openssh.com", Key, Sequence + 1, Message),
             "consecutive sequence numbers give different tags");
   end Check_UMAC_Sequence_Nonce;


   --  Two ways of encrypting the same four bytes, made to agree.
   --
   --  chacha20-poly1305@openssh.com encrypts the packet length with K_1 --
   --  the second half of the 64-byte key -- at counter zero, separately from
   --  the body. Seal does that inline. Encrypt_Length does it again, for a
   --  caller that has to read a length off the wire before it knows how much
   --  more to read; ssh_lib calls it for exactly that.
   --
   --  They are two copies of one operation. Seal is covered by the
   --  cross-check against pyca; Encrypt_Length was covered by nothing, so a
   --  change to one that missed the other would leave this crate's tests
   --  passing while ssh_lib read a length no peer had written.
   procedure Check_Chacha_Length_Agreement is
      --  The two halves must differ, or reading the wrong one gives the same
      --  answer and this tests nothing. K_2 is the first thirty-two bytes and
      --  K_1 the second.
      Key : constant Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset
                (CryptoLib.ChaCha20_Poly1305.Key_Length)) :=
        [1 .. 32 => 16#7E#, 33 .. 64 => 16#B3#];

      --  A packet whose first four bytes are the length field.
      Plain : constant Ada.Streams.Stream_Element_Array (1 .. 20) :=
        [16#00#, 16#00#, 16#00#, 16#10#,
         others => 16#AA#];

      Sequence : constant Interfaces.Unsigned_32 := 16#0000_002A#;

      Wire : Ada.Streams.Stream_Element_Array
        (1 .. Plain'Length
              + Ada.Streams.Stream_Element_Offset
                  (CryptoLib.ChaCha20_Poly1305.Tag_Length));
      Sealed_Status : CryptoLib.Errors.Status;

      Separately : Ada.Streams.Stream_Element_Array (1 .. 4);
      Length_Status : CryptoLib.Errors.Status;
   begin
      Sealed_Status :=
        CryptoLib.ChaCha20_Poly1305.Seal (Key, Sequence, Plain, Wire);
      Check (Sealed_Status = CryptoLib.Errors.Ok, "a packet seals");

      Length_Status :=
        CryptoLib.ChaCha20_Poly1305.Encrypt_Length
          (Key, Sequence, Plain (1 .. 4), Separately);
      Check (Length_Status = CryptoLib.Errors.Ok,
             "and its length encrypts on its own");

      Check (Separately = Wire (1 .. 4),
             "the length encrypted on its own is the length Seal put on the "
             & "wire, so the two copies of that step agree");

      --  The sequence number is the nonce, so the same length under a
      --  different one must not come out the same.
      Check (CryptoLib.ChaCha20_Poly1305.Encrypt_Length
               (Key, Sequence + 1, Plain (1 .. 4), Separately)
             = CryptoLib.Errors.Ok
             and then Separately /= Wire (1 .. 4),
             "and a different sequence number encrypts it differently");
   end Check_Chacha_Length_Agreement;


   --  The one-shot CBC path, against the same authority as the streaming
   --  one.
   --
   --  CBC decryption is written twice here: Initialize with a CBC name and
   --  Decrypt for the transport, and Decrypt_CBC_Raw for a caller with the
   --  whole ciphertext in hand. ssh_lib uses both -- the first for packets,
   --  the second for an OpenSSH private key encrypted with a CBC cipher.
   --
   --  Only the decrypt side is written twice: Encrypt_CBC_Raw delegates to
   --  the streaming path, so the existing round trip does cross the two
   --  implementations rather than checking one against itself.
   --
   --  What it does not do is anchor either of them outside this crate. Until
   --  the cipher-name table went in, AES-CBC had no vector at all here --
   --  RC2 had one and AES did not -- so the pair agreed with each other and
   --  with nothing else. This decrypts what OpenSSL encrypted, which is a
   --  direct anchor rather than one reached through two other tests, and
   --  keeps the agreement assertion because it costs a line.
   procedure Check_CBC_Paths_Agree is
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

      Key        : constant String := "abababababababababababababababababababababababababababababababab";
      IV         : constant String := "000102030405060708090a0b0c0d0e0f";
      Plaintext  : constant String := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
      Ciphertext : constant String := "76ed2071a4b20ae2dbe279d87c725b19891bd66749dfb5cfd82d8f9ff43e5be1";

      Raw_Out    : Ada.Streams.Stream_Element_Array (1 .. 32);
      Stream_Out : Ada.Streams.Stream_Element_Array (1 .. 32);
      Context    : CryptoLib.Ciphers.Cipher_State;
      Status     : CryptoLib.Errors.Status;
   begin
      Status :=
        CryptoLib.Ciphers.Decrypt_CBC_Raw
          ("aes256-cbc", From_Hex (Key), From_Hex (IV),
           From_Hex (Ciphertext), Raw_Out);
      Check (Status = CryptoLib.Errors.Ok, "the one-shot path decrypts");
      Check (Raw_Out = From_Hex (Plaintext),
             "and gives back what OpenSSL encrypted, so its chaining is the "
             & "same chaining");

      Status :=
        CryptoLib.Ciphers.Initialize
          (Context, "aes256-cbc", CryptoLib.Ciphers.Client_To_Server,
           From_Hex (Key), From_Hex (IV));
      Check (Status = CryptoLib.Errors.Ok, "the streaming path initialises");
      Status :=
        CryptoLib.Ciphers.Decrypt (Context, From_Hex (Ciphertext), Stream_Out);
      Check (Status = CryptoLib.Errors.Ok, "and decrypts");

      Check (Raw_Out = Stream_Out,
             "the two CBC paths agree, so neither can drift from the other "
             & "unnoticed");
   end Check_CBC_Paths_Agree;


   --  The guard on a negotiated UMAC name.
   --
   --  ssh_lib asks Is_OpenSSH_UMAC_Name whether a selected MAC is one of
   --  these at all, Is_Implemented whether it can be performed, and
   --  Fail_Closed_Status for the answer to give when it cannot. None of the
   --  three was named by a test, and between them they decide whether a
   --  connection proceeds with a MAC this crate can actually compute.
   --
   --  The four names are also written down in ssh_lib, in Mac_Kind_For. Two
   --  lists that must not drift, so the same four are asserted here.
   procedure Check_UMAC_Negotiation_Guard is
      package U renames CryptoLib.UMAC;
   begin
      --  Exactly the four OpenSSH spellings, and the etm ones are among
      --  them: ssh_lib carries the same four and would offer a name this
      --  refused, or refuse one it offered, if either list moved.
      Check (U.Is_OpenSSH_UMAC_Name ("umac-64@openssh.com")
             and then U.Is_OpenSSH_UMAC_Name ("umac-128@openssh.com")
             and then U.Is_OpenSSH_UMAC_Name ("umac-64-etm@openssh.com")
             and then U.Is_OpenSSH_UMAC_Name ("umac-128-etm@openssh.com"),
             "the four OpenSSH UMAC names are recognised");
      Check (not U.Is_OpenSSH_UMAC_Name ("umac-64")
             and then not U.Is_OpenSSH_UMAC_Name ("hmac-sha2-256")
             and then not U.Is_OpenSSH_UMAC_Name (""),
             "and a name that is not one of them is not, including umac-64 "
             & "without the suffix that makes it OpenSSH's");

      --  Recognised and performable are separate questions, and the guard
      --  distinguishes three answers rather than two.
      Check (U.Is_Implemented ("umac-128-etm@openssh.com"),
             "a recognised name is one this crate can perform");
      Check (U.Fail_Closed_Status ("umac-128-etm@openssh.com")
             = CryptoLib.Errors.Ok,
             "so the guard admits it");
      Check (U.Fail_Closed_Status ("hmac-sha2-256")
             = CryptoLib.Errors.Handshake_Failed,
             "a MAC that is not UMAC at all is refused outright rather than "
             & "reported unsupported, which is a different thing");
      Check (U.Fail_Closed_Status ("umac-192@openssh.com")
             = CryptoLib.Errors.Handshake_Failed,
             "and so is a UMAC-shaped name this crate never agreed to");

      --  Tag width follows the name, and the etm spelling does not change
      --  it: a 128 name that produced a 64-bit tag would authenticate with
      --  half the bits the peer expects.
      Check (U.Tag_Length ("umac-64@openssh.com") = 8
             and then U.Tag_Length ("umac-64-etm@openssh.com") = 8,
             "a umac-64 name means an eight-byte tag either way");
      Check (U.Tag_Length ("umac-128@openssh.com") = 16
             and then U.Tag_Length ("umac-128-etm@openssh.com") = 16,
             "and a umac-128 name a sixteen-byte one");
      Check (U.Tag_Length ("hmac-sha2-256") = 0,
             "a name this does not know has no tag length to give");
   end Check_UMAC_Negotiation_Guard;


   --  RFC 8439 AEAD_CHACHA20_POLY1305 -- the construction TLS, IPsec and
   --  everything outside SSH mean by "ChaCha20-Poly1305", which is not the
   --  OpenSSH one this package also implements.
   procedure Check_ChaCha20_Poly1305_RFC8439 is
      package CP renames CryptoLib.ChaCha20_Poly1305;

      Key : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
        ("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
      Nonce : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex ("070000004041424344454647");
      Aad : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex ("50515253c0c1c2c3c4c5c6c7");
      Plain : constant Ada.Streams.Stream_Element_Array := Bytes_From_String
        ("Ladies and Gentlemen of the class of '99: If I could offer you "
         & "only one tip for the future, sunscreen would be it.");
      Want : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
        ("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63"
         & "dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b369"
         & "2ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3"
         & "ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600"
         & "691");
      Empty : constant Ada.Streams.Stream_Element_Array (1 .. 0) :=
        [others => 0];

      Wire : Ada.Streams.Stream_Element_Array (1 .. Plain'Length + 16);
      Back : Ada.Streams.Stream_Element_Array (1 .. Plain'Length);
      St   : CryptoLib.Errors.Status;
   begin
      St := CP.Seal_AEAD (Key, Nonce, Aad, Plain, Wire);
      Check (St = CryptoLib.Errors.Ok, "RFC 8439 seal status");
      Check (Wire = Want, "RFC 8439 2.8.2 ciphertext and tag");

      St := CP.Open_AEAD (Key, Nonce, Aad, Wire, Back);
      Check (St = CryptoLib.Errors.Ok and then Back = Plain,
             "RFC 8439 round-trips");

      --  A flipped tag, a flipped ciphertext bit and a changed AAD must each
      --  be refused, with nothing left in the output buffer.
      declare
         Bad : Ada.Streams.Stream_Element_Array := Wire;
      begin
         Bad (Bad'Last) := Bad (Bad'Last) xor 1;
         St := CP.Open_AEAD (Key, Nonce, Aad, Bad, Back);
         Check (St /= CryptoLib.Errors.Ok, "RFC 8439 refuses a flipped tag");
         Check (Back = [Back'Range => 0],
                "RFC 8439 zeroes the plaintext on a bad tag");

         Bad := Wire;
         Bad (Bad'First) := Bad (Bad'First) xor 16#80#;
         Check (CP.Open_AEAD (Key, Nonce, Aad, Bad, Back)
                  /= CryptoLib.Errors.Ok,
                "RFC 8439 refuses tampered ciphertext");
      end;
      Check (CP.Open_AEAD (Key, Nonce, Empty, Wire, Back)
               /= CryptoLib.Errors.Ok,
             "RFC 8439 refuses a changed AAD");

      --  Empty plaintext and empty AAD are both legal.
      declare
         W0 : Ada.Streams.Stream_Element_Array (1 .. 16);
         P0 : Ada.Streams.Stream_Element_Array (1 .. 0);
      begin
         Check (CP.Seal_AEAD (Key, Nonce, Empty, Empty, W0)
                  = CryptoLib.Errors.Ok
                and then CP.Open_AEAD (Key, Nonce, Empty, W0, P0)
                  = CryptoLib.Errors.Ok,
                "RFC 8439 seals and opens an empty plaintext");
      end;

      --  Wrong-width key and nonce are refused rather than padded.
      declare
         SSH_Key : constant Ada.Streams.Stream_Element_Array (1 .. 64) :=
           [others => 7];
         Short_N : constant Ada.Streams.Stream_Element_Array (1 .. 8) :=
           [others => 1];
      begin
         Check (CP.Seal_AEAD (SSH_Key, Nonce, Aad, Plain, Wire)
                  /= CryptoLib.Errors.Ok,
                "RFC 8439 refuses the SSH construction's 64-byte key");
         Check (CP.Seal_AEAD (Key, Short_N, Aad, Plain, Wire)
                  /= CryptoLib.Errors.Ok,
                "RFC 8439 refuses an 8-byte nonce");
      end;

      --  The two constructions in this package must not be confusable. They
      --  share ChaCha20 and Poly1305 and agree on nothing else, so sealing
      --  the same bytes each way must differ, and neither may open the
      --  other's output.
      declare
         SSH_Key  : constant Ada.Streams.Stream_Element_Array (1 .. 64) :=
           [others => 16#2B#];
         AEAD_Key : constant Ada.Streams.Stream_Element_Array (1 .. 32) :=
           SSH_Key (1 .. 32);
         Zero_N   : constant Ada.Streams.Stream_Element_Array (1 .. 12) :=
           [others => 0];
         Packet   : constant Ada.Streams.Stream_Element_Array (1 .. 20) :=
           [others => 16#41#];
         SSH_Wire  : Ada.Streams.Stream_Element_Array (1 .. 36);
         AEAD_Wire : Ada.Streams.Stream_Element_Array (1 .. 36);
         Out_Buf   : Ada.Streams.Stream_Element_Array (1 .. 20);
      begin
         Check (CP.Seal (SSH_Key, 0, Packet, SSH_Wire) = CryptoLib.Errors.Ok
                and then CP.Seal_AEAD (AEAD_Key, Zero_N, Empty, Packet,
                                       AEAD_Wire) = CryptoLib.Errors.Ok,
                "both constructions seal the same bytes");
         Check (SSH_Wire /= AEAD_Wire,
                "the SSH and RFC 8439 constructions produce different wire "
                & "bytes");
         Check (CP.Open_AEAD (AEAD_Key, Zero_N, Empty, SSH_Wire, Out_Buf)
                  /= CryptoLib.Errors.Ok,
                "RFC 8439 cannot open an OpenSSH packet");
         Check (CP.Open (SSH_Key, 0, AEAD_Wire, Out_Buf)
                  /= CryptoLib.Errors.Ok,
                "OpenSSH cannot open an RFC 8439 packet");
      end;
   end Check_ChaCha20_Poly1305_RFC8439;


   --  chacha20-poly1305@openssh.com known-answer vectors (generated by an
   --  independent reference cross-checked against OpenSSL's ChaCha20) and
   --  Seal/Open round-trip.
   procedure Check_OpenSSH_ChaCha20_Poly1305 is
   begin
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
   end Check_OpenSSH_ChaCha20_Poly1305;


   --  aes256-gcm@openssh.com known-answer (RFC 5647: 4-octet length is
   --  cleartext GCM AAD, only the body is encrypted) cross-checked against
   --  pyca/cryptography AESGCM, plus a Seal/Open round-trip. Sequence is unused
   --  (per-packet IV uniqueness is the caller's job), so a nonzero value here
   --  must not change the result.
   procedure Check_OpenSSH_AES_GCM is
   begin
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
   end Check_OpenSSH_AES_GCM;


   --  RFC 4418 UMAC known-answer tests. Key "abcdefghijklmnop", nonce
   --  "bcdefghi". The RFC publishes tags up to 96 bits, so umac-64 is checked
   --  in full and umac-128 against its 96-bit (12-byte) prefix (streams 0-2);
   --  the full 128-bit result additionally interoperates with live OpenSSH.
   procedure Check_UMAC_Vectors is
   begin
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
   end Check_UMAC_Vectors;


   procedure Check_ChaCha20_Poly1305_Tamper is
   begin
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
   end Check_ChaCha20_Poly1305_Tamper;


   --  Seal_AEAD / Open_AEAD: plain AES-256-GCM with no SSH framing, checked
   --  against the NIST GCM specification's AES-256 test vectors.
   procedure Check_AES_GCM_AEAD_Vectors is
   begin
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
   end Check_AES_GCM_AEAD_Vectors;

   --  AUnit routine wrappers. Each check is a test of its own, so a
   --  failure reports the check that failed and the rest still run.
   procedure Run_Check_ZIP_AES_CTR_Roundtrip (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_RC2_40_CBC_Decrypt (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_AES_256_CBC_Raw_Roundtrip (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_AES_CBC_Raw_Rejects_Bad_Sizes (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_UMAC_Sequence_Nonce (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Chacha_Length_Agreement (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_CBC_Paths_Agree (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_UMAC_Negotiation_Guard (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_ChaCha20_Poly1305_RFC8439 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Cipher_Names (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_OpenSSH_ChaCha20_Poly1305 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_OpenSSH_AES_GCM (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_UMAC_Vectors (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_ChaCha20_Poly1305_Tamper (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_AES_GCM_AEAD_Vectors (Item : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Check_ZIP_AES_CTR_Roundtrip (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_ZIP_AES_CTR_Roundtrip;
   end Run_Check_ZIP_AES_CTR_Roundtrip;

   procedure Run_Check_RC2_40_CBC_Decrypt (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_RC2_40_CBC_Decrypt;
   end Run_Check_RC2_40_CBC_Decrypt;

   procedure Run_Check_AES_256_CBC_Raw_Roundtrip (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_AES_256_CBC_Raw_Roundtrip;
   end Run_Check_AES_256_CBC_Raw_Roundtrip;

   procedure Run_Check_AES_CBC_Raw_Rejects_Bad_Sizes (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_AES_CBC_Raw_Rejects_Bad_Sizes;
   end Run_Check_AES_CBC_Raw_Rejects_Bad_Sizes;

   procedure Run_Check_UMAC_Sequence_Nonce (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_UMAC_Sequence_Nonce;
   end Run_Check_UMAC_Sequence_Nonce;

   procedure Run_Check_Chacha_Length_Agreement (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Chacha_Length_Agreement;
   end Run_Check_Chacha_Length_Agreement;

   procedure Run_Check_CBC_Paths_Agree (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_CBC_Paths_Agree;
   end Run_Check_CBC_Paths_Agree;

   procedure Run_Check_UMAC_Negotiation_Guard (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_UMAC_Negotiation_Guard;
   end Run_Check_UMAC_Negotiation_Guard;

   procedure Run_Check_ChaCha20_Poly1305_RFC8439 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_ChaCha20_Poly1305_RFC8439;
   end Run_Check_ChaCha20_Poly1305_RFC8439;

   procedure Run_Check_Cipher_Names (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Cipher_Names;
   end Run_Check_Cipher_Names;

   procedure Run_Check_OpenSSH_ChaCha20_Poly1305 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_OpenSSH_ChaCha20_Poly1305;
   end Run_Check_OpenSSH_ChaCha20_Poly1305;

   procedure Run_Check_OpenSSH_AES_GCM (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_OpenSSH_AES_GCM;
   end Run_Check_OpenSSH_AES_GCM;

   procedure Run_Check_UMAC_Vectors (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_UMAC_Vectors;
   end Run_Check_UMAC_Vectors;

   procedure Run_Check_ChaCha20_Poly1305_Tamper (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_ChaCha20_Poly1305_Tamper;
   end Run_Check_ChaCha20_Poly1305_Tamper;

   procedure Run_Check_AES_GCM_AEAD_Vectors (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_AES_GCM_AEAD_Vectors;
   end Run_Check_AES_GCM_AEAD_Vectors;

   overriding procedure Register_Tests (Item : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (Item, Run_Check_ZIP_AES_CTR_Roundtrip'Access, "zip aes ctr roundtrip");
      Register_Routine (Item, Run_Check_RC2_40_CBC_Decrypt'Access, "rc2 40 cbc decrypt");
      Register_Routine (Item, Run_Check_AES_256_CBC_Raw_Roundtrip'Access, "aes 256 cbc raw roundtrip");
      Register_Routine (Item, Run_Check_AES_CBC_Raw_Rejects_Bad_Sizes'Access, "aes cbc raw rejects bad sizes");
      Register_Routine (Item, Run_Check_UMAC_Sequence_Nonce'Access, "umac sequence nonce");
      Register_Routine (Item, Run_Check_Chacha_Length_Agreement'Access, "chacha length agreement");
      Register_Routine (Item, Run_Check_CBC_Paths_Agree'Access, "cbc paths agree");
      Register_Routine (Item, Run_Check_UMAC_Negotiation_Guard'Access, "umac negotiation guard");
      Register_Routine (Item, Run_Check_ChaCha20_Poly1305_RFC8439'Access, "chacha20 poly1305 rfc8439");
      Register_Routine (Item, Run_Check_Cipher_Names'Access, "cipher names");
      Register_Routine (Item, Run_Check_OpenSSH_ChaCha20_Poly1305'Access, "openssh chacha20 poly1305");
      Register_Routine (Item, Run_Check_OpenSSH_AES_GCM'Access, "openssh aes gcm");
      Register_Routine (Item, Run_Check_UMAC_Vectors'Access, "umac vectors");
      Register_Routine (Item, Run_Check_ChaCha20_Poly1305_Tamper'Access, "chacha20 poly1305 tamper");
      Register_Routine (Item, Run_Check_AES_GCM_AEAD_Vectors'Access, "aes gcm aead vectors");
   end Register_Tests;

   overriding function Name (Item : Test_Case) return AUnit.Message_String is
      pragma Unreferenced (Item);
   begin
      return AUnit.Format ("cryptolib ciphers and AEAD");
   end Name;

end Tests_Ciphers;
