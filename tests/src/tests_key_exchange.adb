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
with CryptoLib.MLDSA;
with CryptoLib.MLKEM768;
with CryptoLib.SNTRUP761;
with CryptoLib.Curve25519;
with CryptoLib.Ed25519;
with CryptoLib.Ed448;
with CryptoLib.SHA3;
with CryptoLib.Buffers;
with CryptoLib.Diffie_Hellman;
with CryptoLib.FFDHE;
with CryptoLib.Modexp;
with CryptoLib.Bignum;
with CryptoLib.Random;
with CryptoLib.RSA;
with Tests_Support; use Tests_Support;

package body Tests_Key_Exchange is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Certificates.Certificate_Status;
   use type Interfaces.Unsigned_32;

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
      Check (CryptoLib.Buffers.Is_Empty (Shared),
             "and leaves no shared secret behind");
      Check (CryptoLib.Diffie_Hellman.Compute_Group14_Shared_Secret
               (Fixed_Private, [1 => 1], Shared) /= CryptoLib.Errors.Ok,
             "and a peer value of one");
      Check (CryptoLib.Buffers.Is_Empty (Shared),
             "and leaves no shared secret behind");
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
      Check (CryptoLib.Buffers.Is_Empty (Shared),
             "and leaves no shared secret behind");
      Check (CryptoLib.Diffie_Hellman.Compute_Group1_Shared_Secret
               (Fixed_Private, [1 => 1], Shared) /= CryptoLib.Errors.Ok,
             "and a peer value of one");
      Check (CryptoLib.Buffers.Is_Empty (Shared),
             "and leaves no shared secret behind");
   end Check_DH_Group1;

   --  Each DH keypair generator, against the function that consumes what it
   --  produces.
   --
   --  Three of the four were called by nothing here. The shared-secret side
   --  is pinned by fixed-exponent vectors, but those say nothing about the
   --  generators: a generator using the wrong prime, or raising the wrong
   --  base, produces a public value nobody here would question.
   --
   --  No vector is needed to catch that. The public value a generator emits
   --  must be 2 raised to the private value it emitted alongside it, which
   --  is exactly what the shared-secret function computes when the peer
   --  sends 2. If the two halves disagree about the prime or the base they
   --  disagree here, and if they agree wrongly the vectors catch it -- so
   --  between them there is nowhere for a wrong constant to hide.
   procedure Check_DH_Generators is
      Rng : CryptoLib.Random.Random_Source;

      procedure One_Group (Label : String; Group : Natural) is
         Private_Value, Public_Value, Recomputed :
           CryptoLib.Buffers.Packet_Buffer;
         Status : CryptoLib.Errors.Status;
      begin
         case Group is
            when 1 =>
               Status := CryptoLib.Diffie_Hellman.Generate_Group1_Keypair
                           (Rng, Private_Value, Public_Value);
            when 14 =>
               Status := CryptoLib.Diffie_Hellman.Generate_Group14_Keypair
                           (Rng, Private_Value, Public_Value);
            when 16 =>
               Status := CryptoLib.Diffie_Hellman.Generate_Group16_Keypair
                           (Rng, Private_Value, Public_Value);
            when others =>
               Status := CryptoLib.Diffie_Hellman.Generate_Group18_Keypair
                           (Rng, Private_Value, Public_Value);
         end case;
         Check (Status = CryptoLib.Errors.Ok,
                Label & " generates a keypair");

         --  The peer sends 2, so the shared secret is 2^priv mod p: the
         --  public value again, by another route.
         case Group is
            when 1 =>
               Status := CryptoLib.Diffie_Hellman.Compute_Group1_Shared_Secret
                           (CryptoLib.Buffers.To_Array (Private_Value),
                            [1 => 2], Recomputed);
            when 14 =>
               Status := CryptoLib.Diffie_Hellman.Compute_Group14_Shared_Secret
                           (CryptoLib.Buffers.To_Array (Private_Value),
                            [1 => 2], Recomputed);
            when 16 =>
               Status := CryptoLib.Diffie_Hellman.Compute_Group16_Shared_Secret
                           (CryptoLib.Buffers.To_Array (Private_Value),
                            [1 => 2], Recomputed);
            when others =>
               Status := CryptoLib.Diffie_Hellman.Compute_Group18_Shared_Secret
                           (CryptoLib.Buffers.To_Array (Private_Value),
                            [1 => 2], Recomputed);
         end case;
         Check (Status = CryptoLib.Errors.Ok,
                Label & " recomputes from the private value it gave back");
         Check (CryptoLib.Buffers.To_Array (Public_Value)
                = CryptoLib.Buffers.To_Array (Recomputed),
                Label & " agrees with itself about the prime and the base");
      end One_Group;
   begin
      CryptoLib.Random.Initialize_Production (Rng);
      One_Group ("group1", 1);
      One_Group ("group14", 14);
      One_Group ("group16", 16);
      One_Group ("group18", 18);
   end Check_DH_Generators;

   --  Which group a server may talk this client into.
   --
   --  In group exchange the server proposes the prime and the generator, and
   --  this is the only thing that decides whether to accept them: it matches
   --  the proposal against the three RFC 3526 primes and names which one it
   --  is, or refuses. A match it should not have made is a key exchange
   --  carried out in a group the server chose, which is the whole reason the
   --  client is meant to check rather than take what it is handed.
   --
   --  ssh_lib calls it on the server's reply. Nothing here called it at all.
   procedure Check_Gex_Group_Selection is
      use type CryptoLib.Diffie_Hellman.Supported_Gex_Group;

      Gex_P14 : constant String :=
        "00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b2251" &
        "4a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42" &
        "e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a1" &
        "63bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed52907709696" &
        "6d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5" &
        "c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffff" &
        "ffffffffff";
      Gex_P16 : constant String :=
        "00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b2251" &
        "4a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42" &
        "e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a1" &
        "63bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed52907709696" &
        "6d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5" &
        "c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad3317" &
        "0d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb" &
        "0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b20" &
        "0cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a" &
        "723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2" &
        "db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970ce" &
        "e2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c9340631" &
        "99ffffffffffffffff";
      Gex_P18 : constant String :=
        "00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b2251" &
        "4a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42" &
        "e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a1" &
        "63bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed52907709696" &
        "6d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5" &
        "c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad3317" &
        "0d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb" &
        "0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b20" &
        "0cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a" &
        "723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2" &
        "db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970ce" &
        "e2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c9340284" &
        "9236c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001aeb0" &
        "6a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1bdb7f1447e6cc254b332051" &
        "512bd7af426fb8f401378cd2bf5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6d55e702f46" &
        "980c82b5a84031900b1c9e59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154" &
        "aacc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76f550aa3d8a1fbff0eb" &
        "19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee12bf2d5b0b7474d6e694f9" &
        "1e6dbe115974a3926f12fee5e438777cb6a932df8cd8bec4d073b931ba3bc832b68d9dd300741fa7bf8a" &
        "fc47ed2576f6936ba424663aab639c5ae4f5683423b4742bf1c978238f16cbe39d652de3fdb8befc848a" &
        "d922222e04a4037c0713eb57a81a23f0c73473fc646cea306b4bcbc8862f8385ddfa9d4b7fa2c087e879" &
        "683303ed5bdd3a062b3cf5b3a278a66d2a13f83f44f82ddf310ee074ab6a364597e899a0255dc164f31c" &
        "c50846851df9ab48195ded7ea1b1d510bd7ee74d73faf36bc31ecfa268359046f4eb879f924009438b48" &
        "1c6cd7889a002ed5ee382bc9190da6fc026e479558e4475677e9aa9e3050e2765694dfc81f56e880b96e" &
        "7160c980dd98edd3dfffffffffffffffff";
      Gex_P14_Altered : constant String :=
        "00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b2251" &
        "4a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42" &
        "e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a1" &
        "63bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed52907709696" &
        "6d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5" &
        "c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffff" &
        "fffffffffe";

      Generator_2 : constant String := "02";
      Generator_5 : constant String := "05";

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

      function Chosen (Prime, Generator : String)
        return CryptoLib.Diffie_Hellman.Supported_Gex_Group
      is (CryptoLib.Diffie_Hellman.Select_Group_Exchange_Group
            (From_Hex (Prime), From_Hex (Generator)));
   begin
      --  The three groups this crate knows, each recognised as itself.
      Check (Chosen (Gex_P14, Generator_2)
             = CryptoLib.Diffie_Hellman.Gex_Group14,
             "the group14 prime is recognised as group14");
      Check (Chosen (Gex_P16, Generator_2)
             = CryptoLib.Diffie_Hellman.Gex_Group16,
             "the group16 prime as group16");
      Check (Chosen (Gex_P18, Generator_2)
             = CryptoLib.Diffie_Hellman.Gex_Group18,
             "and the group18 prime as group18");

      --  One bit away from a group everybody agreed on is not that group.
      --  A server proposing it is proposing its own, and the client has no
      --  way to know what is wrong with it.
      Check (Chosen (Gex_P14_Altered, Generator_2)
             = CryptoLib.Diffie_Hellman.No_Supported_Gex_Group,
             "a prime one bit from group14 is refused rather than taken for "
             & "it");

      --  The generator is part of the agreement too.
      Check (Chosen (Gex_P14, Generator_5)
             = CryptoLib.Diffie_Hellman.No_Supported_Gex_Group,
             "the right prime under the wrong generator is refused");

      --  And nothing small or absent slips through.
      Check (Chosen ("fffffffb", Generator_2)
             = CryptoLib.Diffie_Hellman.No_Supported_Gex_Group,
             "a small prime nobody agreed to is refused");
      Check (Chosen (Gex_P14, "")
             = CryptoLib.Diffie_Hellman.No_Supported_Gex_Group,
             "and a proposal with no generator at all");
   end Check_Gex_Group_Selection;

   --  Which post-quantum method a name asks for.
   --
   --  ssh_lib does not carry a list of these names. It asks Is_Implemented
   --  and offers whatever this crate says it can do, so these predicates are
   --  the whole of the decision about what gets negotiated -- and then which
   --  KEM runs and which hash combines the two shared secrets.
   --
   --  A name classified into the wrong family runs the wrong KEM; one
   --  classified into the wrong combiner derives a different key from the
   --  same exchange. Both end the connection rather than weakening it, but
   --  neither is visible from inside either crate: the peer is the only
   --  thing that disagrees.
   procedure Check_Hybrid_PQ_Names is
      package HK renames CryptoLib.Hybrid_PQ_Kex;
      use type HK.Hybrid_PQ_Kind;

      ML_256 : constant String := "mlkem768x25519-sha256";
      ML_512 : constant String := "mlkem768x25519-sha512";
      NT_SSH : constant String := "sntrup761x25519-sha512@openssh.com";
      NT_Bare : constant String := "sntrup761x25519-sha512";
   begin
      --  All four are offered, and nothing else is.
      Check (HK.Is_Implemented (ML_256) and then HK.Is_Implemented (ML_512)
             and then HK.Is_Implemented (NT_SSH)
             and then HK.Is_Implemented (NT_Bare),
             "the four hybrid names are offered");
      Check (not HK.Is_Implemented ("curve25519-sha256")
             and then not HK.Is_Implemented ("sntrup761x25519-sha256")
             and then not HK.Is_Implemented (""),
             "and a name that is not one of them is not");

      --  The family decides which KEM runs.
      Check (HK.Is_MLKEM768_Hybrid_PQ_Kex_Name (ML_256)
             and then HK.Is_MLKEM768_Hybrid_PQ_Kex_Name (ML_512),
             "the ML-KEM names are recognised as ML-KEM");
      Check (not HK.Is_MLKEM768_Hybrid_PQ_Kex_Name (NT_SSH)
             and then not HK.Is_MLKEM768_Hybrid_PQ_Kex_Name (NT_Bare),
             "and the sntrup names are not");
      Check (HK.Is_SNTRUP761_Hybrid_PQ_Kex_Name (NT_SSH)
             and then HK.Is_SNTRUP761_Hybrid_PQ_Kex_Name (NT_Bare),
             "the sntrup names are recognised as sntrup");
      Check (not HK.Is_SNTRUP761_Hybrid_PQ_Kex_Name (ML_256)
             and then not HK.Is_SNTRUP761_Hybrid_PQ_Kex_Name (ML_512),
             "and the ML-KEM names are not");

      --  The suffix decides which hash combines the two secrets. This is the
      --  one where the name says the answer, so disagreeing with it is
      --  disagreeing with every peer that reads the same name.
      Check (not HK.Uses_SHA512_Combiner (ML_256),
             "the sha256 name combines with SHA-256");
      Check (HK.Uses_SHA512_Combiner (ML_512)
             and then HK.Uses_SHA512_Combiner (NT_SSH)
             and then HK.Uses_SHA512_Combiner (NT_Bare),
             "and every sha512 name with SHA-512");

      --  The two sntrup spellings are one method: OpenSSH used the suffixed
      --  name before the bare one was settled, and a peer may offer either.
      Check (HK.Kind_Of (NT_SSH) /= HK.Kind_Of (ML_256)
             and then HK.Uses_SHA512_Combiner (NT_SSH)
                      = HK.Uses_SHA512_Combiner (NT_Bare)
             and then HK.Is_SNTRUP761_Hybrid_PQ_Kex_Name (NT_SSH)
                      = HK.Is_SNTRUP761_Hybrid_PQ_Kex_Name (NT_Bare),
             "the suffixed and bare sntrup names agree about everything that "
             & "decides the exchange");
   end Check_Hybrid_PQ_Names;

   --  ML-KEM's algebraic core. These are the pieces MLKEM768 is built from;
   --  none was reachable from the suite, so a fault in one would have shown
   --  only as a KEM that stopped interoperating, with nothing to say where.
   --
   --  Checked by identity rather than by stored vectors: each routine is held
   --  against another routine that must agree with it, so neither can drift
   --  alone.
   procedure Check_MLKEM_Core_Algebra is
      package M renames CryptoLib.MLKEM768_Core;
      use type M.Polynomial;

      Q : constant Integer := M.Q_Value;
      A, B : M.Polynomial := [others => 0];

      function Congruent (Left, Right : M.Polynomial) return Boolean is
      begin
         for I in M.Polynomial'Range loop
            if (Left (I) - Right (I)) mod Q /= 0 then
               return False;
            end if;
         end loop;
         return True;
      end Congruent;

      --  Distance on the circle mod q, so a wrap counts as near not far.
      function Ring_Distance (Left, Right : Integer) return Integer is
         D : constant Integer := (Left - Right) mod Q;
      begin
         return Integer'Min (D, Q - D);
      end Ring_Distance;
   begin
      for I in M.Polynomial'Range loop
         A (I) := (I * 7 + 3) mod Q;
         B (I) := (I * 11 + 5) mod Q;
      end loop;

      Check (Congruent (M.Inverse_NTT (M.NTT (A)), A),
             "the inverse NTT undoes the NTT");

      --  The base everything else here rests on: the reference multiply,
      --  against a negacyclic convolution written out longhand in this test.
      --
      --  This is the only genuinely independent check in the group, and it
      --  has to be. Pointwise_Multiply is implemented as NTT (reference
      --  multiply (inverse NTT of each operand)) -- it is not a separate fast
      --  path -- so comparing the two would compare the reference multiply
      --  with itself and pass however wrong it was. Rq is Zq[x]/(x**256 + 1),
      --  so a product term that runs off the end comes back negated.
      declare
         Independent : M.Polynomial := [others => 0];
         N : constant Natural := M.N_Value;
      begin
         for I in 0 .. N - 1 loop
            for J in 0 .. N - 1 loop
               declare
                  K : constant Natural := (I + J) mod N;
                  P : constant Integer := (A (I) * B (J)) mod Q;
               begin
                  if I + J < N then
                     Independent (K) := (Independent (K) + P) mod Q;
                  else
                     Independent (K) := (Independent (K) - P) mod Q;
                  end if;
               end;
            end loop;
         end loop;
         Check (Congruent (M.Ring_Multiply_Reference (A, B), Independent),
                "the reference multiply is the negacyclic convolution");
      end;

      --  Given that, the NTT is a ring homomorphism over it.
      Check (Congruent
               (M.Inverse_NTT (M.Pointwise_Multiply (M.NTT (A), M.NTT (B))),
                M.Ring_Multiply_Reference (A, B)),
             "transforming, multiplying and transforming back is the product");

      --  Dot_Product sums the reference multiply over the components. It is
      --  not the pointwise product despite the vocabulary, and the two are
      --  checked to differ so nobody swaps one for the other.
      declare
         U, V : M.Polyvec;
         Sum_Reference, Sum_Pointwise : M.Polynomial := [others => 0];
      begin
         for K in M.Vector_Index loop
            for I in M.Polynomial'Range loop
               U (K)(I) := (I * (K + 2) + K) mod Q;
               V (K)(I) := (I * (K + 5) + 1) mod Q;
            end loop;
         end loop;
         for K in M.Vector_Index loop
            Sum_Reference :=
              M.Add (Sum_Reference, M.Ring_Multiply_Reference (U (K), V (K)));
            Sum_Pointwise :=
              M.Add (Sum_Pointwise, M.Pointwise_Multiply (U (K), V (K)));
         end loop;
         Check (Congruent (M.Dot_Product (U, V), Sum_Reference),
                "a dot product sums the reference multiply");
         Check (not Congruent (Sum_Reference, Sum_Pointwise),
                "and that is not the same as summing pointwise products");
      end;

      --  Twelve-bit encoding is exact: it is how a public key survives a wire.
      Check (M.Decode_12 (M.Encode_12 (A)) = A,
             "twelve-bit encode and decode round-trip exactly");

      --  A message survives the polynomial it is carried in.
      declare
         Message : M.MLKEM_Message := [others => 0];
      begin
         for I in Message'Range loop
            Message (I) :=
              Ada.Streams.Stream_Element ((Natural (I) * 37) mod 256);
         end loop;
         Check (M.Poly_To_Message (M.Message_To_Poly (Message)) = Message,
                "a message round-trips through its polynomial");
      end;

      --  The compressed encodings are lossy on purpose; what matters is that
      --  they lose no more than FIPS 203 allows, which is ceil (q / 2**(d+1)).
      declare
         R10 : constant M.Polynomial :=
           M.Decode_Decompress_10 (M.Compress_Encode_10 (A));
         R4  : constant M.Polynomial :=
           M.Decode_Decompress_4 (M.Compress_Encode_4 (A));
         Bound_10 : constant Integer := (Q + 2047) / 2048;
         Bound_4  : constant Integer := (Q + 31) / 32;
         Worst_10, Worst_4 : Integer := 0;
      begin
         for I in M.Polynomial'Range loop
            Worst_10 := Integer'Max (Worst_10, Ring_Distance (R10 (I), A (I)));
            Worst_4  := Integer'Max (Worst_4,  Ring_Distance (R4 (I), A (I)));
         end loop;
         Check (Worst_10 <= Bound_10,
                "ten-bit compression stays inside its error bound, worst"
                & Integer'Image (Worst_10) & " of" & Integer'Image (Bound_10));
         Check (Worst_4 <= Bound_4,
                "four-bit compression stays inside its error bound, worst"
                & Integer'Image (Worst_4) & " of" & Integer'Image (Bound_4));
         --  And they really are lossy: an exact round trip would mean the
         --  compression was not happening at all.
         Check (R4 /= A, "four-bit compression actually discards something");
      end;

      Check (M.Compress (0, 10) = 0 and then M.Decompress (0, 10) = 0,
             "zero compresses and decompresses to zero");

      --  Matrix sampling is a function of its seed and its indices.
      declare
         Rho : constant Ada.Streams.Stream_Element_Array (1 .. 32) :=
           [others => 7];
         P00 : constant M.Polynomial := M.Sample_NTT (Rho, 0, 0);
         P00_Again : constant M.Polynomial := M.Sample_NTT (Rho, 0, 0);
         P10 : constant M.Polynomial := M.Sample_NTT (Rho, 1, 0);
         P01 : constant M.Polynomial := M.Sample_NTT (Rho, 0, 1);
      begin
         Check (P00 = P00_Again, "sampling the matrix is deterministic");
         Check (P00 /= P10 and then P00 /= P01 and then P10 /= P01,
                "row and column both change what is sampled -- a matrix whose "
                & "entries collided would break the whole scheme");
         Check ((for all I in M.Polynomial'Range =>
                   P00 (I) >= 0 and then P00 (I) < Q),
                "every sampled coefficient is a residue mod q");
      end;

      --  Centred binomial noise is small, which is the entire point of it.
      declare
         Bytes : Ada.Streams.Stream_Element_Array (1 .. 128) := [others => 0];
         Noise : M.Polynomial;
         Lowest, Highest : Integer := 0;
      begin
         for I in Bytes'Range loop
            Bytes (I) :=
              Ada.Streams.Stream_Element ((Natural (I) * 53) mod 256);
         end loop;
         Noise := M.CBD_Eta2 (Bytes);
         for I in M.Polynomial'Range loop
            declare
               Centred : constant Integer :=
                 (if Noise (I) > Q / 2 then Noise (I) - Q else Noise (I));
            begin
               Lowest := Integer'Min (Lowest, Centred);
               Highest := Integer'Max (Highest, Centred);
            end;
         end loop;
         Check (Lowest >= -M.Eta_2 and then Highest <= M.Eta_2,
                "centred binomial noise stays within eta2, got"
                & Integer'Image (Lowest) & " .." & Integer'Image (Highest));
      end;
   end Check_MLKEM_Core_Algebra;

   --  FIPS 203 ML-KEM-768 known-answer test.  Deterministic keygen from d || z
   --  and encaps from m, checked against the pq-crystals final ML-KEM reference
   --  (byte-identical to OpenSSH).  The 1184/2400/1088-byte ek/dk/ct are
   --  compared via SHA-256; the 32-byte shared secret K is compared directly.
   procedure Check_MLKEM768_Vectors is
   begin
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
   end Check_MLKEM768_Vectors;

   procedure Check_SNTRUP761_Vectors is
   begin
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
   end Check_SNTRUP761_Vectors;

   procedure Check_Modexp_And_DH_Group18 is
   begin
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
   end Check_Modexp_And_DH_Group18;

   --  RFC 7919 finite-field groups. The primes were derived from the RFC's
   --  own construction and confirmed by handing p and g to OpenSSL as
   --  anonymous explicit parameters, which named each group back; the vector
   --  below was then computed independently in Python against that prime, so
   --  agreement here is agreement with a second implementation and not with
   --  this one's own arithmetic.
   procedure Check_FFDHE is
      package FF renames CryptoLib.FFDHE;
      use type FF.Group_Id;
   begin
      declare
         FF_XA : constant String :=
           "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
         FF_XB : constant String :=
           "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
         FF_YA : constant String :=
           "0eef0c0eae9c65a3332cdc742b58561d362c0af526f8ad528b19ff39c91434312f83302ed9dc6f2b84b25048"
           & "2dbd80962154f8a6d683741bf8bf4f3fdee22f80541a77553d1ae7a096c521f869987ae5eca1090d93e7bdea"
           & "0b4349f17fee34f4775bfb380f426dec937b25825680c6e2b8c4c9eede64b91f5cdc02ba78e75908d47cd27f"
           & "da4b5188c22baf2acd1e861ed0864e9eb9346640d354eada9f7156a601387ba5f1b8609733707803a5ac866f"
           & "c1bbe54b15a99934727bc5c157f893d867a89abf0ce3dd0cf3d7ce00073db8b3bbae1486faedc462f7edeb3d"
           & "c44ba30336de3d4dbfb4f14f143c46b0ba93f316f50c3377b9a38a27ae048f5605a4dcbf";
         FF_Z : constant String :=
           "5284cd3fd1f1074744f2f0e60003d25379171b45ef6f265606cb4065f9c390da0076da913ef1146829f6d333"
           & "e513169ba9d21861045a3e9c5c48a0d343052ba050777a94fb1baa149ce34397c7736d1a759cbc84dc0ed883"
           & "62e1465d0dd5f747d40744f4899ad4d37df814cd21a7e5dd6ee17cd05e70f75acf37bd30334525272b85daf6"
           & "d00d54de618f6bfbe06ef58723fbf38c30c2fee5989b65e93488f0825f1d5162104f1937ce96f7a9f671a42b"
           & "bfd5518302f83a37145be86edd1c988dab927c305914e8fd21489068da46c5a417e5fd7805e9bc64246b7196"
           & "0e62eb6f22a3d0b46186302e7fa537b77785f0a22e5a33101e08b1bd6e787127e07d6d96";
         XA : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex (FF_XA);
         XB : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex (FF_XB);
         Public_A : Ada.Streams.Stream_Element_Array (1 .. 256);
         Public_B : Ada.Streams.Stream_Element_Array (1 .. 256);
         Secret_A : Ada.Streams.Stream_Element_Array (1 .. 256);
         Secret_B : Ada.Streams.Stream_Element_Array (1 .. 256);
      begin
         Check (FF.Value_Length (FF.FFDHE2048) = 256
                and then FF.Value_Length (FF.FFDHE8192) = 1024,
                "the group widths are the prime widths");

         Check (FF.Public_Value (FF.FFDHE2048, XA, Public_A)
                  = CryptoLib.Errors.Ok,
                "ffdhe2048 derives a public value from a fixed exponent");
         Check (Public_A = Bytes_From_Hex (FF_YA),
                "and it is the value an independent modexp over the RFC 7919 "
                & "prime gives");

         Check (FF.Public_Value (FF.FFDHE2048, XB, Public_B)
                  = CryptoLib.Errors.Ok,
                "the second exponent derives too");
         Check (FF.Shared_Secret (FF.FFDHE2048, XA, Public_B, Secret_A)
                  = CryptoLib.Errors.Ok,
                "and the two sides agree a secret");
         Check (Secret_A = Bytes_From_Hex (FF_Z),
                "which is the published value for this pair");
         Check (FF.Shared_Secret (FF.FFDHE2048, XB, Public_A, Secret_B)
                  = CryptoLib.Errors.Ok,
                "the other direction agrees a secret too");
         Check (Secret_B = Secret_A, "and both directions reach the same one");
      end;

      --  Degenerate peer values. Each is what an attacker sends to force a
      --  shared secret it already knows.
      declare
         Secret : Ada.Streams.Stream_Element_Array (1 .. 256);
         X      : constant Ada.Streams.Stream_Element_Array (1 .. 32) :=
           [others => 7];
         Zero   : constant Ada.Streams.Stream_Element_Array (1 .. 256) :=
           [others => 0];
         One    : Ada.Streams.Stream_Element_Array (1 .. 256) := [others => 0];
         Narrow : constant Ada.Streams.Stream_Element_Array (1 .. 255) :=
           [others => 1];
      begin
         One (One'Last) := 1;
         Check (not FF.Valid_Peer_Value (FF.FFDHE2048, Zero),
                "a peer value of zero is refused");
         Check (not FF.Valid_Peer_Value (FF.FFDHE2048, One),
                "and a peer value of one");
         Check (not FF.Valid_Peer_Value (FF.FFDHE2048, Narrow),
                "and one of the wrong width");
         Check (FF.Shared_Secret (FF.FFDHE2048, X, Zero, Secret)
                  /= CryptoLib.Errors.Ok,
                "Shared_Secret refuses zero as well");
         Check (Secret = [Secret'Range => 0], "and leaves the secret zero");
         Check (FF.Shared_Secret (FF.FFDHE2048, X, One, Secret)
                  /= CryptoLib.Errors.Ok,
                "and refuses one");
         Check (Secret = [Secret'Range => 0], "and leaves the secret zero");

         --  A value at or above p. This is the case that pins the peer check
         --  specifically: zero and one are caught downstream anyway, because
         --  the secret they produce is itself refused, so a suite that tested
         --  only those would pass with the peer check deleted -- it did, until
         --  this was added. An unreduced base is also what CryptoLib.Modexp
         --  documents it does not accept.
         declare
            Too_Large : constant Ada.Streams.Stream_Element_Array (1 .. 256) :=
              [others => 16#FF#];
         begin
            Check (not FF.Valid_Peer_Value (FF.FFDHE2048, Too_Large),
                   "a peer value above the prime is refused");
            Check (FF.Shared_Secret (FF.FFDHE2048, X, Too_Large, Secret)
                     /= CryptoLib.Errors.Ok,
                   "and Shared_Secret refuses it rather than reducing it");
            Check (Secret = [Secret'Range => 0], "and leaves the secret zero");
         end;
      end;

      --  A generated pair must be usable by the side that consumes it.
      declare
         Rng      : CryptoLib.Random.Random_Source;
         Priv     : Ada.Streams.Stream_Element_Array (1 .. 32);
         Pub      : Ada.Streams.Stream_Element_Array (1 .. 256);
         Peer_X   : constant Ada.Streams.Stream_Element_Array (1 .. 32) :=
           [others => 3];
         Peer_Pub : Ada.Streams.Stream_Element_Array (1 .. 256);
         S1, S2   : Ada.Streams.Stream_Element_Array (1 .. 256);
      begin
         CryptoLib.Random.Initialize_Production (Rng);
         Check (FF.Generate_Keypair (FF.FFDHE2048, Rng, Priv, Pub)
                  = CryptoLib.Errors.Ok,
                "ffdhe2048 generates a keypair");
         Check (FF.Valid_Peer_Value (FF.FFDHE2048, Pub),
                "and the public value it emits is one it would accept");
         Check (FF.Public_Value (FF.FFDHE2048, Peer_X, Peer_Pub)
                  = CryptoLib.Errors.Ok,
                "the peer derives its own");
         Check (FF.Shared_Secret (FF.FFDHE2048, Priv, Peer_Pub, S1)
                  = CryptoLib.Errors.Ok
                and then FF.Shared_Secret (FF.FFDHE2048, Peer_X, Pub, S2)
                  = CryptoLib.Errors.Ok
                and then S1 = S2,
                "and a generated pair agrees with a fixed one");
      end;
   end Check_FFDHE;

   --  ML-DSA (FIPS 204) key generation against NIST's own ACVP vectors, taken
   --  from usnistgov/ACVP-Server. The keys are kilobytes, so what is pinned
   --  here is a SHA-256 of each; the seeds and the digests both come from
   --  NIST's published prompt and expected-result files.
   procedure Check_MLDSA is
      package M renames CryptoLib.MLDSA;

      function Digest_Hex
        (Data : Ada.Streams.Stream_Element_Array) return String
      is
         Digits_Set : constant String := "0123456789abcdef";
         Digest : constant CryptoLib.Hashes.SHA256_Digest :=
           CryptoLib.Hashes.SHA256 (Data);
         Result : String (1 .. 64);
         K      : Natural := 1;
      begin
         for B of Digest loop
            Result (K) := Digits_Set (Natural (B) / 16 + 1);
            Result (K + 1) := Digits_Set (Natural (B) mod 16 + 1);
            K := K + 2;
         end loop;
         return Result;
      end Digest_Hex;
   begin
      Check (M.Public_Key_Length (M.ML_DSA_44) = 1312
             and then M.Private_Key_Length (M.ML_DSA_44) = 2560
             and then M.Signature_Length (M.ML_DSA_44) = 2420,
             "the FIPS 204 lengths for ML-DSA-44");

      declare
         PK : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (M.Public_Key_Length (M.ML_DSA_44)));
         SK : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (M.Private_Key_Length (M.ML_DSA_44)));
      begin
         Check (M.Key_From_Seed (M.ML_DSA_44,
                                 Bytes_From_Hex
                                   ("7194b13c95231010afd2c909992bd2003ba6f437c3886bdbe3f6b867a14ba161"),
                                 PK, SK)
                  = CryptoLib.Errors.Ok,
                "ML-DSA-44 derives a key from ACVP seed 1");
         Check (Digest_Hex (PK) = "838b88b6ac41e2c60698173e08ca173d0b0d2839205806e56a8a3d53195f3a03",
                "and the public key is NIST's, vector 1");
         Check (Digest_Hex (SK) = "1c911d163cd0a5563e06f22403f7e16334fee17c2abb66f11ddf39ca6307ec58",
                "and so is the private key, vector 1");
      end;

      declare
         PK : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (M.Public_Key_Length (M.ML_DSA_44)));
         SK : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (M.Private_Key_Length (M.ML_DSA_44)));
      begin
         Check (M.Key_From_Seed (M.ML_DSA_44,
                                 Bytes_From_Hex
                                   ("2ebe5a4123398dfbcd5bdf0a42ebdd03112be3bc88a6e9b78d93120ab8d0120e"),
                                 PK, SK)
                  = CryptoLib.Errors.Ok,
                "ML-DSA-44 derives a key from ACVP seed 2");
         Check (Digest_Hex (PK) = "366cdfa62052438e03a4bb70e8aaa2c31c535584ef83a926b4efa1796605dacb",
                "and the public key is NIST's, vector 2");
         Check (Digest_Hex (SK) = "67c5410e10424bdb0a7a17755b9a08f86f52b3ebe372bb03caefd6bbfefd28a5",
                "and so is the private key, vector 2");
      end;

      declare
         PK : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (M.Public_Key_Length (M.ML_DSA_65)));
         SK : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (M.Private_Key_Length (M.ML_DSA_65)));
      begin
         Check (M.Key_From_Seed (M.ML_DSA_65,
                                 Bytes_From_Hex
                                   ("a991fd42b071d49c48ae3e75c647459e0daad1e1ba356a04801912d3294bcff8"),
                                 PK, SK)
                  = CryptoLib.Errors.Ok,
                "ML-DSA-65 derives a key from ACVP seed 3");
         Check (Digest_Hex (PK) = "b1a7d0d2f0d7a04b9d5ffccd9bd578864dab4a01cdd7f70a05cd1f4f0672e43a",
                "and the public key is NIST's, vector 3");
         Check (Digest_Hex (SK) = "56c53ac82fbff7d81b7a8cfbbc73011ceccad677e16dc53f2ece66d49aa11edd",
                "and so is the private key, vector 3");
      end;

      declare
         PK : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (M.Public_Key_Length (M.ML_DSA_65)));
         SK : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (M.Private_Key_Length (M.ML_DSA_65)));
      begin
         Check (M.Key_From_Seed (M.ML_DSA_65,
                                 Bytes_From_Hex
                                   ("494f29ad1c93abb2b9545bd14cc575a98ecd3062137b439b49eb1a8cc6652fc6"),
                                 PK, SK)
                  = CryptoLib.Errors.Ok,
                "ML-DSA-65 derives a key from ACVP seed 4");
         Check (Digest_Hex (PK) = "4f2a21f2bee92fc15c91ce7dc7d96f5dac1ee1f0f7eb7325823ea96dd12ecc84",
                "and the public key is NIST's, vector 4");
         Check (Digest_Hex (SK) = "bd37a2499543695d6d31afe6c5188fe18fa16f3980d2941edae7b5dbe5c71c14",
                "and so is the private key, vector 4");
      end;

      declare
         PK : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (M.Public_Key_Length (M.ML_DSA_87)));
         SK : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (M.Private_Key_Length (M.ML_DSA_87)));
      begin
         Check (M.Key_From_Seed (M.ML_DSA_87,
                                 Bytes_From_Hex
                                   ("a16f5b0796703e2d1a0140a35cbf36efabe70e752ba59b6a9a0e9c4b05302f73"),
                                 PK, SK)
                  = CryptoLib.Errors.Ok,
                "ML-DSA-87 derives a key from ACVP seed 5");
         Check (Digest_Hex (PK) = "33f49649f05ec2fc3b050007b18ade043bbc8d1c0ded03a269d540486daaa5f4",
                "and the public key is NIST's, vector 5");
         Check (Digest_Hex (SK) = "c64e15742f27d7d8e2832f7d55a5c014f2c9536082f3a3181cfc6246908dd649",
                "and so is the private key, vector 5");
      end;

      declare
         PK : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (M.Public_Key_Length (M.ML_DSA_87)));
         SK : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (M.Private_Key_Length (M.ML_DSA_87)));
      begin
         Check (M.Key_From_Seed (M.ML_DSA_87,
                                 Bytes_From_Hex
                                   ("e46d458a660285930d9656a88d14e751730cae7a4975b6e4fbe69e80e3f01e7f"),
                                 PK, SK)
                  = CryptoLib.Errors.Ok,
                "ML-DSA-87 derives a key from ACVP seed 6");
         Check (Digest_Hex (PK) = "f445cbb034fba125d17a8ac1be6ff617ddaca04a3e6b76ccf44e3dbc94cc7946",
                "and the public key is NIST's, vector 6");
         Check (Digest_Hex (SK) = "d679b094bb35dfba907e45fc449b5879353d7f32c65c6fe4430f55b2cef7a2f0",
                "and so is the private key, vector 6");
      end;

      --  A generated key must have the shape the parameter set promises.
      declare
         Rng : CryptoLib.Random.Random_Source;
         PK  : Ada.Streams.Stream_Element_Array (1 .. 1312);
         SK  : Ada.Streams.Stream_Element_Array (1 .. 2560);
      begin
         CryptoLib.Random.Initialize_Production (Rng);
         Check (M.Generate_Keypair (M.ML_DSA_44, Rng, PK, SK)
                  = CryptoLib.Errors.Ok,
                "ML-DSA-44 generates a keypair");
         Check (PK /= [PK'Range => 0] and then SK /= [SK'Range => 0],
                "and neither half is left empty");
      end;

      --  A wrong-length buffer is refused rather than truncated.
      declare
         Small : Ada.Streams.Stream_Element_Array (1 .. 16) := [others => 0];
         SK    : Ada.Streams.Stream_Element_Array (1 .. 2560);
      begin
         Check (M.Key_From_Seed (M.ML_DSA_44,
                                 Bytes_From_Hex ("00"), Small, SK)
                  /= CryptoLib.Errors.Ok,
                "a wrong-length seed is refused");
      end;
   end Check_MLDSA;

   --  ML-DSA signing and verification. The keys come from NIST ACVP seeds and
   --  are the ones the keygen test already pins; the expected signatures come
   --  from dilithium-py, which was checked against NIST's own sigGen vectors
   --  (deterministic, external, pure) before being used as a source here.
   procedure Check_MLDSA_Sign is
      package M renames CryptoLib.MLDSA;

      function Digest_Hex
        (Data : Ada.Streams.Stream_Element_Array) return String
      is
         Digits_Set : constant String := "0123456789abcdef";
         Digest : constant CryptoLib.Hashes.SHA256_Digest :=
           CryptoLib.Hashes.SHA256 (Data);
         Result : String (1 .. 64);
         K      : Natural := 1;
      begin
         for B of Digest loop
            Result (K) := Digits_Set (Natural (B) / 16 + 1);
            Result (K + 1) := Digits_Set (Natural (B) mod 16 + 1);
            K := K + 2;
         end loop;
         return Result;
      end Digest_Hex;

      Rng : CryptoLib.Random.Random_Source;
      Msg : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("cryptolib ml-dsa");
      Other_Msg : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("cryptolib ml-dsb");
      Empty_Ctx : constant Ada.Streams.Stream_Element_Array (1 .. 0) :=
        [others => 0];
      Ctx : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("ctx");
   begin
      CryptoLib.Random.Initialize_Production (Rng);

      declare
         PK : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (M.Public_Key_Length (M.ML_DSA_44)));
         SK : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (M.Private_Key_Length (M.ML_DSA_44)));
         Sig : Ada.Streams.Stream_Element_Array (1 .. 2420);
      begin
         Check (M.Key_From_Seed (M.ML_DSA_44, Bytes_From_Hex
                  ("7194b13c95231010afd2c909992bd2003ba6f437c3886bdbe3f6b867a14ba161"), PK, SK) = CryptoLib.Errors.Ok,
                "ML-DSA-44 key for the signing vector");
         Check (M.Sign (M.ML_DSA_44, SK, Msg, Empty_Ctx, Rng, True, Sig)
                  = CryptoLib.Errors.Ok,
                "ML-DSA-44 signs deterministically");
         Check (Digest_Hex (Sig)
                  = "26eb9f0e1f3d57a3d022cf2ee8c62fbaee2ebaed903ca1ea3be512ad718f9277",
                "and the signature is the expected one");
         Check (M.Verify (M.ML_DSA_44, PK, Msg, Empty_Ctx, Sig),
                "and it verifies under its own key");
         declare
            Bad : Ada.Streams.Stream_Element_Array := Sig;
         begin
            Bad (Bad'Last) := Bad (Bad'Last) xor 1;
            Check (not M.Verify (M.ML_DSA_44, PK, Msg, Empty_Ctx, Bad),
                   "a tampered signature does not verify");
         end;
         Check (not M.Verify (M.ML_DSA_44, PK, Other_Msg, Empty_Ctx, Sig),
                "nor does it over a different message");
         Check (not M.Verify (M.ML_DSA_44, PK, Msg, Ctx, Sig),
                "nor under a different context");
      end;

      declare
         PK : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (M.Public_Key_Length (M.ML_DSA_65)));
         SK : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (M.Private_Key_Length (M.ML_DSA_65)));
         Sig : Ada.Streams.Stream_Element_Array (1 .. 3309);
      begin
         Check (M.Key_From_Seed (M.ML_DSA_65, Bytes_From_Hex
                  ("a991fd42b071d49c48ae3e75c647459e0daad1e1ba356a04801912d3294bcff8"), PK, SK) = CryptoLib.Errors.Ok,
                "ML-DSA-65 key for the signing vector");
         Check (M.Sign (M.ML_DSA_65, SK, Msg, Empty_Ctx, Rng, True, Sig)
                  = CryptoLib.Errors.Ok,
                "ML-DSA-65 signs deterministically");
         Check (Digest_Hex (Sig)
                  = "5e6e8a286396650099ba687594c19f31c2a3d84393898b2e0b592aea15c20809",
                "and the signature is the expected one");
         Check (M.Verify (M.ML_DSA_65, PK, Msg, Empty_Ctx, Sig),
                "and it verifies under its own key");
         declare
            Bad : Ada.Streams.Stream_Element_Array := Sig;
         begin
            Bad (Bad'Last) := Bad (Bad'Last) xor 1;
            Check (not M.Verify (M.ML_DSA_65, PK, Msg, Empty_Ctx, Bad),
                   "a tampered signature does not verify");
         end;
         Check (not M.Verify (M.ML_DSA_65, PK, Other_Msg, Empty_Ctx, Sig),
                "nor does it over a different message");
         Check (not M.Verify (M.ML_DSA_65, PK, Msg, Ctx, Sig),
                "nor under a different context");
      end;

      declare
         PK : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (M.Public_Key_Length (M.ML_DSA_87)));
         SK : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (M.Private_Key_Length (M.ML_DSA_87)));
         Sig : Ada.Streams.Stream_Element_Array (1 .. 4627);
      begin
         Check (M.Key_From_Seed (M.ML_DSA_87, Bytes_From_Hex
                  ("a16f5b0796703e2d1a0140a35cbf36efabe70e752ba59b6a9a0e9c4b05302f73"), PK, SK) = CryptoLib.Errors.Ok,
                "ML-DSA-87 key for the signing vector");
         Check (M.Sign (M.ML_DSA_87, SK, Msg, Empty_Ctx, Rng, True, Sig)
                  = CryptoLib.Errors.Ok,
                "ML-DSA-87 signs deterministically");
         Check (Digest_Hex (Sig)
                  = "e1b932c2af1d3e983615cf36c3b87d943b3e7dbe969b4de8827865728c9d77f4",
                "and the signature is the expected one");
         Check (M.Verify (M.ML_DSA_87, PK, Msg, Empty_Ctx, Sig),
                "and it verifies under its own key");
         declare
            Bad : Ada.Streams.Stream_Element_Array := Sig;
         begin
            Bad (Bad'Last) := Bad (Bad'Last) xor 1;
            Check (not M.Verify (M.ML_DSA_87, PK, Msg, Empty_Ctx, Bad),
                   "a tampered signature does not verify");
         end;
         Check (not M.Verify (M.ML_DSA_87, PK, Other_Msg, Empty_Ctx, Sig),
                "nor does it over a different message");
         Check (not M.Verify (M.ML_DSA_87, PK, Msg, Ctx, Sig),
                "nor under a different context");
      end;
   end Check_MLDSA_Sign;

   --  AUnit routine wrappers. Each check is a test of its own, so a
   --  failure reports the check that failed and the rest still run.
   procedure Run_Check_DH_Peer_Validation (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_DH_Group14 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_DH_Group1 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_DH_Generators (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Gex_Group_Selection (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Hybrid_PQ_Names (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_MLKEM_Core_Algebra (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_FFDHE (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_MLDSA (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_MLDSA_Sign (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_MLKEM768_Vectors (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_SNTRUP761_Vectors (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Modexp_And_DH_Group18 (Item : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Check_DH_Peer_Validation (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_DH_Peer_Validation;
   end Run_Check_DH_Peer_Validation;

   procedure Run_Check_DH_Group14 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_DH_Group14;
   end Run_Check_DH_Group14;

   procedure Run_Check_DH_Group1 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_DH_Group1;
   end Run_Check_DH_Group1;

   procedure Run_Check_DH_Generators (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_DH_Generators;
   end Run_Check_DH_Generators;

   procedure Run_Check_Gex_Group_Selection (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Gex_Group_Selection;
   end Run_Check_Gex_Group_Selection;

   procedure Run_Check_Hybrid_PQ_Names (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Hybrid_PQ_Names;
   end Run_Check_Hybrid_PQ_Names;

   procedure Run_Check_MLKEM_Core_Algebra (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_MLKEM_Core_Algebra;
   end Run_Check_MLKEM_Core_Algebra;

   procedure Run_Check_MLKEM768_Vectors (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_MLKEM768_Vectors;
   end Run_Check_MLKEM768_Vectors;

   procedure Run_Check_SNTRUP761_Vectors (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_SNTRUP761_Vectors;
   end Run_Check_SNTRUP761_Vectors;

   procedure Run_Check_Modexp_And_DH_Group18 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Modexp_And_DH_Group18;
   end Run_Check_Modexp_And_DH_Group18;

   procedure Run_Check_FFDHE (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_FFDHE;
   end Run_Check_FFDHE;

   procedure Run_Check_MLDSA (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_MLDSA;
   end Run_Check_MLDSA;

   procedure Run_Check_MLDSA_Sign (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_MLDSA_Sign;
   end Run_Check_MLDSA_Sign;

   overriding procedure Register_Tests (Item : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (Item, Run_Check_DH_Peer_Validation'Access, "dh peer validation");
      Register_Routine (Item, Run_Check_DH_Group14'Access, "dh group14");
      Register_Routine (Item, Run_Check_DH_Group1'Access, "dh group1");
      Register_Routine (Item, Run_Check_DH_Generators'Access, "dh generators");
      Register_Routine (Item, Run_Check_Gex_Group_Selection'Access, "gex group selection");
      Register_Routine (Item, Run_Check_Hybrid_PQ_Names'Access, "hybrid pq names");
      Register_Routine (Item, Run_Check_MLKEM_Core_Algebra'Access, "mlkem core algebra");
      Register_Routine (Item, Run_Check_FFDHE'Access, "ffdhe groups");
      Register_Routine (Item, Run_Check_MLDSA'Access, "ml-dsa keygen");
      Register_Routine (Item, Run_Check_MLDSA_Sign'Access, "ml-dsa sign/verify");
      Register_Routine (Item, Run_Check_MLKEM768_Vectors'Access, "mlkem768 vectors");
      Register_Routine (Item, Run_Check_SNTRUP761_Vectors'Access, "sntrup761 vectors");
      Register_Routine (Item, Run_Check_Modexp_And_DH_Group18'Access, "modexp and dh group18");
   end Register_Tests;

   overriding function Name (Item : Test_Case) return AUnit.Message_String is
      pragma Unreferenced (Item);
   begin
      return AUnit.Format ("cryptolib key exchange and post-quantum KEMs");
   end Name;

end Tests_Key_Exchange;
