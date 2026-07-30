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

end Tests_Key_Exchange;
