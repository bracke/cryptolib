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

package body Tests_RSA is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Certificates.Certificate_Status;
   use type Interfaces.Unsigned_32;

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

   --  RSA signing: the private-key half of a package that was verification
   --  only. The key is one OpenSSL generated; the two deterministic vectors
   --  were produced by an independent Python implementation and confirmed by
   --  pyca before any of this existed.
   procedure Check_RSA_Signing is
      package R renames CryptoLib.RSA;

      Modulus : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
        ("bb574636d26885d938fac8887232f483126ae37d13ef89d515eed4db157b91"
         & "8cfb6dbadcdab75cda478ee60f2fa6080b76c19181442787ea3dde483842d6"
         & "9997ae414e1f41c60b6336dc1b63f69f54dfc91340928e0fd7b5b2d8a3a6e3"
         & "f4f103072cef9d7112b10e00a7ca52fceb243ff6c4f8a692c5c931fabb561c"
         & "c4c9017004b8d45a7c0b641922d31f7809c945a515430bb78ed7eeaa63be81"
         & "f5891411ed0aa34f8f3e460f110adbc0a2cd58b119d1a3d94991128b2f1463"
         & "e296638bb8c7ed64d6e1bb719b3f5beee1fa61917ac1ae4b16d8fbfa1d966e"
         & "c8ad42f7977d644436e6aa7eb1376441b80c1791e61b6bbae806f253a600ff"
         & "7ce9dda711370c13");
      Public_Exponent : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex ("010001");
      Private_Exponent : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
        ("1e6442fe9b75711ab37232670ef3b23eb3405b906129652db2e5b06aac4504"
         & "1b4accb08454b26b774e7ae1aff4006b8caf3829753ee114dd0cd560824961"
         & "8c15932382b0c7c300fa42f399394725ee51c6f529c41214d8348b58e17a59"
         & "152afb87f0a3c761b3c667bef679785611dad5ca4adbb5c0d8ccfcca856aab"
         & "b71c39705dd8fabf11bb8dee4de8d60b4aaa423e114132535ef2ce652554ea"
         & "2522ddf5638e2c7c375a31300bc853a7dfbb1b79dc1491ed3a5eeedd3ceb45"
         & "d3744e57c90887f26fecf2c9ed0db3d7e4660fc0fd22a841a2261926c9de76"
         & "869df98ec7e737c47fbd56e178f36af8c48bb3f0198dcd886008ff4688f538"
         & "d248167ef2e7ade1");
      Want_PSS_Salt0 : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
        ("90881c9ed0c0962243c7272f9383722e71c2c11ae4f61a6e942c0711dde337"
         & "8a302f1d6186543307210e33a7daaf56e52254eafb996a9375b5aaa491b4db"
         & "b86ae9d2287ab4fe7828a95b9470eb15c5d11021be4f13be351b0ab4bef06c"
         & "5180c306bc29722948b65f8821d1ea25d42efb285839aecfc0c409a09d9e36"
         & "f1a5317ea09322af6a95a74411d916558a6909d8726f746331bdf34a28338f"
         & "2177070958fb2d0411215dc679254455a2ff955fe31f2b7a2881508229565a"
         & "cd78b37545a5c532daafc72de962ab452f1ce22dbd6c3edcd474ef8d5f1cea"
         & "b94be7786dd997dfe5e739223f264e029b2bf2f3c5b1b2842b863c32826e3d"
         & "6d67ab599fcca2fb");
      Want_PKCS1 : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_Hex
        ("7e260df096f97246dbefbb6a219a36b913197f29f988e5930d4f0bf34043ee"
         & "cfb5a343fc9a3b186370ec7fe6c82aa09248ca5f32e818cfa8892b67f31b5a"
         & "b43a5fe5b20f7f08d2b6410995bf2fd4ec09d63a265af7b598f3a4ff636a53"
         & "d2919e72d568c1ec2a8ad6921553dd030558c91c594f9b3f54fc3b15c34119"
         & "ef35882854de82011dade262aee4ec10a3c22f2e3ca6a500cf8072d9fb7044"
         & "db016be52e3acf61ad29031bbc2f23faa6a9e0c0e3ac4218d500caeac0b741"
         & "562c66640aa181d636c27f8bd4d898afd6c79338dd578e6e13f6cbb9cd2cde"
         & "9545cb6be5aa291cdd62d97cb97ac41aea6f78f1d934a4b80c60c679236b25"
         & "be0d692436baaef9");

      Message : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("cryptolib rsa-pss signing");
      Signature : Ada.Streams.Stream_Element_Array (1 .. 256);
      Rng : CryptoLib.Random.Random_Source;
      St  : CryptoLib.Errors.Status;
   begin
      CryptoLib.Random.Initialize_Production (Rng);

      --  PKCS#1 v1.5 is deterministic, so it is pinned byte for byte.
      St := R.Sign_PKCS1_V1_5
        (Modulus, Public_Exponent, Private_Exponent, R.SHA256, Message, Rng,
         Signature);
      Check (St = CryptoLib.Errors.Ok, "RSA v1.5 signing succeeds");
      Check (Signature = Want_PKCS1, "RSA v1.5 signature is byte for byte");
      Check (R.Verify_PKCS1_V1_5
               (Modulus, Public_Exponent, R.SHA256, Message, Signature)
               = CryptoLib.Errors.Ok,
             "and this crate's own verifier accepts it");

      --  PSS with a zero-length salt is deterministic too, which is the only
      --  way to hold a randomised scheme to an exact answer.
      St := R.Sign_PSS
        (Modulus, Public_Exponent, Private_Exponent, R.SHA256, 0, Message,
         Rng, Signature);
      Check (St = CryptoLib.Errors.Ok, "RSA PSS signing succeeds at salt 0");
      Check (Signature = Want_PSS_Salt0,
             "RSA PSS salt-0 signature is byte for byte");
      Check (R.Verify_PSS
               (Modulus, Public_Exponent, R.SHA256, 0, Message, Signature)
               = CryptoLib.Errors.Ok,
             "and this crate's own verifier accepts it");

      --  With a real salt the scheme is randomised: two signatures over one
      --  message must differ and both must verify. A PSS implementation that
      --  forgot to draw a salt would still round-trip, and only this notices.
      declare
         First, Second : Ada.Streams.Stream_Element_Array (1 .. 256);
      begin
         Check (R.Sign_PSS (Modulus, Public_Exponent, Private_Exponent,
                            R.SHA256, 32, Message, Rng, First)
                  = CryptoLib.Errors.Ok
                and then R.Sign_PSS (Modulus, Public_Exponent,
                                     Private_Exponent, R.SHA256, 32, Message,
                                     Rng, Second) = CryptoLib.Errors.Ok,
                "RSA PSS signs twice at salt 32");
         Check (First /= Second,
                "two PSS signatures over one message differ");
         Check (R.Verify_PSS (Modulus, Public_Exponent, R.SHA256, 32,
                              Message, First) = CryptoLib.Errors.Ok
                and then R.Verify_PSS (Modulus, Public_Exponent, R.SHA256, 32,
                                       Message, Second)
                  = CryptoLib.Errors.Ok,
                "and both verify");
         --  A signature made with one salt length must not verify under
         --  another: the length is part of what was signed.
         Check (R.Verify_PSS (Modulus, Public_Exponent, R.SHA256, 0,
                              Message, First) /= CryptoLib.Errors.Ok,
                "a salt-32 signature does not verify as salt-0");
      end;

      --  SHA-384 and SHA-512 arms.
      for Hash in R.Hash_Algorithm loop
         declare
            Sig : Ada.Streams.Stream_Element_Array (1 .. 256);
         begin
            Check (R.Sign_PSS (Modulus, Public_Exponent, Private_Exponent,
                               Hash, 16, Message, Rng, Sig)
                     = CryptoLib.Errors.Ok
                   and then R.Verify_PSS (Modulus, Public_Exponent, Hash, 16,
                                          Message, Sig)
                     = CryptoLib.Errors.Ok,
                   "RSA PSS round-trips under " & Hash'Image);
            Check (R.Sign_PKCS1_V1_5 (Modulus, Public_Exponent,
                                      Private_Exponent, Hash, Message, Rng, Sig)
                     = CryptoLib.Errors.Ok
                   and then R.Verify_PKCS1_V1_5 (Modulus, Public_Exponent,
                                                 Hash, Message, Sig)
                     = CryptoLib.Errors.Ok,
                   "RSA v1.5 round-trips under " & Hash'Image);
         end;
      end loop;

      --  A signature must not verify over a message it does not cover.
      St := R.Sign_PKCS1_V1_5
        (Modulus, Public_Exponent, Private_Exponent, R.SHA256, Message, Rng,
         Signature);
      Check (R.Verify_PKCS1_V1_5
               (Modulus, Public_Exponent, R.SHA256,
                Bytes_From_String ("a different message"), Signature)
               /= CryptoLib.Errors.Ok,
             "a v1.5 signature does not verify over another message");

      --  A PKCS#8 RSA key, parsed and then used. The private exponent was not
      --  surfaced before signing existed, so a caller could read a key and
      --  still not sign with it. Checked end to end: what the parser hands
      --  back must be the exponent that makes a signature verify under the
      --  modulus beside it.
      declare
         package P8 renames CryptoLib.PKCS8;
         Key_DER : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
           ("30820278020100300d06092a864886f70d0101010500048202623082025e02"
         & "010002818100b8ffa2b48d2870fa4fe289746b0cc49dc4123f35cabbab2726"
         & "81c8fd3675588f43026d65d138a4c38c48feebf0076e1ebfac510093545086"
         & "3b8cdf4a2dc0258f7ab0ad8d7cc610904493cbb1c99e834b964270dedd0024"
         & "90d1015dd432befc865d188d7813b990431278e18e5873a49e0d1337d45653"
         & "abc4bab6ea06c977dbdf020301000102818100b3ab4ab8f193024e88812a20"
         & "0fcba1b4db752140bbf991daff11f342c0be2cd94e2a30573f6034dcda0516"
         & "d7cc115b48afbcca1ab5fba00d0e0eddd96c1f7e19764e4d9a97d3f81c1d94"
         & "ffefdcf5b0ead97009201743691c0eeec8d58c2dc15eb2ba88021d87f5f9eb"
         & "349e1a2e7038104726235ad91dc1e3ea1016d5f29429e9024100f501b54b53"
         & "2c04339e351ee73df1f873c7d210a4e16e24b368f8cac0e3dff34c4b3b9d39"
         & "814d1763ca6a448948cb6a231fe172a5524431b168c20f83ba7df583024100"
         & "c14ca38ad0b32eb0997a89a6a94524ce22cd56e8290fd1ed535524b46c74ce"
         & "a7e236797c8cba69e0e1ab5e29f1fe2b75b68d9679bd62ed2f1ff4476079a5"
         & "0d750241008ac56cea3d31b12f8b6c8b146f019eb7f57605f75db805119963"
         & "5173ef9de9304d6c76a11b9b8ea3f70239cf886baeb2365c7b932805782004"
         & "35e693b60da2010240237e7121524534b394db1d5f8f01754aacb54bda0180"
         & "3829fdfd4a6a1ee82bf243e580d54ffa02eb1a451f5b50663d90b5deb5dcd0"
         & "dbd375adc66b3cd9d966e9024100a432b9dc357fee7e0dacfa14059c627b94"
         & "b044240f2f8a5a58ba1f370a2040160077e07bc4e5d468dfdd9fa10009811e"
         & "65fb42c636339caf6cfcb11eaead89c4");
         Want_N : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
           ("b8ffa2b48d2870fa4fe289746b0cc49dc4123f35cabbab272681c8fd367558"
         & "8f43026d65d138a4c38c48feebf0076e1ebfac5100935450863b8cdf4a2dc0"
         & "258f7ab0ad8d7cc610904493cbb1c99e834b964270dedd002490d1015dd432"
         & "befc865d188d7813b990431278e18e5873a49e0d1337d45653abc4bab6ea06"
         & "c977dbdf");
         Want_D : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
           ("b3ab4ab8f193024e88812a200fcba1b4db752140bbf991daff11f342c0be2c"
         & "d94e2a30573f6034dcda0516d7cc115b48afbcca1ab5fba00d0e0eddd96c1f"
         & "7e19764e4d9a97d3f81c1d94ffefdcf5b0ead97009201743691c0eeec8d58c"
         & "2dc15eb2ba88021d87f5f9eb349e1a2e7038104726235ad91dc1e3ea1016d5"
         & "f29429e9");
         Key    : P8.Private_Key;
         Status : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         P8.Decode_DER (Key_DER, CryptoLib.ASN1.Default_Limits, Key, Status);
         Check (P8.Is_Present (Key), "the PKCS#8 RSA key decodes");
         --  DER INTEGERs may carry a leading zero, so compare numerically.
         Check (CryptoLib.Bignum.Compare (P8.RSA_Modulus (Key), Want_N) = 0,
                "and its modulus is the one OpenSSL wrote");
         Check (CryptoLib.Bignum.Compare
                  (P8.RSA_Private_Exponent (Key), Want_D) = 0,
                "and its private exponent too");

         --  The real test: sign with what came out of the parser.
         declare
            Sig : Ada.Streams.Stream_Element_Array (1 .. 128);
         begin
            Check (R.Sign_PKCS1_V1_5
                     (P8.RSA_Modulus (Key), P8.RSA_Exponent (Key),
                      P8.RSA_Private_Exponent (Key), R.SHA256, Message, Rng, Sig)
                     = CryptoLib.Errors.Ok
                   and then R.Verify_PKCS1_V1_5
                     (P8.RSA_Modulus (Key), P8.RSA_Exponent (Key),
                      R.SHA256, Message, Sig) = CryptoLib.Errors.Ok,
                   "a parsed PKCS#8 RSA key signs and verifies");
         end;
      end;

      --  The numeric primitives that only the library reached.
      --
      --  Mod_Reduce, Divide_Small and Bit_Length are hand-written arithmetic
      --  called from CryptoLib.RSA and from each other, which is exactly the
      --  shape the coverage audit excuses: named nowhere in this suite because
      --  something in the library names them. They are checked here against
      --  each other rather than against restated answers, because two
      --  algorithms agreeing is evidence and a repeated constant is not.
      declare
         package BN renames CryptoLib.Bignum;
         Rng2 : CryptoLib.Random.Random_Source;
      begin
         CryptoLib.Random.Initialize_Production (Rng2);

         --  Mod_Reduce is the shift-and-subtract remainder for a modulus as
         --  wide as the value; Mod_Small is Horner's for one that fits a
         --  machine integer. Where the two overlap -- a small modulus written
         --  wide -- they must agree, and they share no code at all.
         for Trial in 1 .. 40 loop
            declare
               Value : Ada.Streams.Stream_Element_Array (1 .. 33);
               Small : constant Positive := 65_537;
               Wide  : Ada.Streams.Stream_Element_Array (1 .. 33) :=
                 [others => 0];
               Got   : Ada.Streams.Stream_Element_Array (1 .. 33);
               Fine  : Boolean;
            begin
               Check (CryptoLib.Random.Fill (Rng2, Value)
                        = CryptoLib.Errors.Ok,
                      "a value to reduce");
               Wide (Wide'Last - 2) := 1;          --  65537 = 01 00 01
               Wide (Wide'Last) := 1;
               BN.Mod_Reduce (Value, Wide, Got, Fine);
               Check (Fine, "the reduction succeeds");
               Check (BN.Mod_Small (Got, Small) = BN.Mod_Small (Value, Small)
                      and then BN.Compare (Got, Wide) < 0,
                      "shift-and-subtract agrees with Horner on a small "
                      & "modulus, and lands below it");
            end;
         end loop;

         --  The edges, where an off-by-one lives.
         declare
            M    : constant Ada.Streams.Stream_Element_Array (1 .. 4) :=
              [0, 0, 1, 7];                        --  263
            Same : constant Ada.Streams.Stream_Element_Array := M;
            Less : constant Ada.Streams.Stream_Element_Array (1 .. 4) :=
              [0, 0, 0, 9];
            Zero : constant Ada.Streams.Stream_Element_Array (1 .. 4) :=
              [others => 0];
            Got  : Ada.Streams.Stream_Element_Array (1 .. 4);
            Fine : Boolean;
         begin
            BN.Mod_Reduce (Less, M, Got, Fine);
            Check (Fine and then Got = Less,
                   "a value below the modulus is returned unchanged");
            BN.Mod_Reduce (Same, M, Got, Fine);
            Check (Fine and then BN.Is_Zero (Got),
                   "a value equal to the modulus reduces to zero");
            BN.Mod_Reduce (Zero, M, Got, Fine);
            Check (Fine and then BN.Is_Zero (Got), "and zero stays zero");
            BN.Mod_Reduce (Less, Zero, Got, Fine);
            Check (not Fine, "a zero modulus is refused, not divided by");
         end;

         --  Divide_Small against the multiply that undoes it: quotient times
         --  divisor plus remainder is the value again.
         for Trial in 1 .. 20 loop
            declare
               Value : Ada.Streams.Stream_Element_Array (1 .. 24);
               Divisor  : constant Positive := 65_537;
               Quotient : Ada.Streams.Stream_Element_Array (1 .. 24);
               Remainder : Natural;
               Rebuilt   : Ada.Streams.Stream_Element_Array (1 .. 24);
               Fine      : Boolean;
            begin
               Check (CryptoLib.Random.Fill (Rng2, Value)
                        = CryptoLib.Errors.Ok, "a value to divide");
               BN.Divide_Small (Value, Divisor, Quotient, Remainder);
               declare
                  Product : constant Ada.Streams.Stream_Element_Array :=
                    BN.Multiply_Small (Quotient, Divisor);
                  Small   : Ada.Streams.Stream_Element_Array (1 .. 24) :=
                    [others => 0];
                  Work    : Natural := Remainder;
               begin
                  for I in reverse Small'Range loop
                     exit when Work = 0;
                     Small (I) := Ada.Streams.Stream_Element (Work mod 256);
                     Work := Work / 256;
                  end loop;
                  BN.Resize (BN.Add (Product, Small), Rebuilt'Length, Rebuilt,
                             Fine);
                  Check (Fine and then Rebuilt = Value,
                         "quotient times divisor plus remainder is the value");
                  Check (Remainder < Divisor,
                         "and the remainder is below the divisor");
               end;
            end;
         end loop;

         --  Bit_Length, which decides whether a private exponent is out of
         --  Wiener's reach during key generation.
         declare
            Zero  : constant Ada.Streams.Stream_Element_Array (1 .. 3) :=
              [others => 0];
            One   : constant Ada.Streams.Stream_Element_Array (1 .. 3) :=
              [0, 0, 1];
            Eight : constant Ada.Streams.Stream_Element_Array (1 .. 3) :=
              [0, 0, 16#FF#];
            Nine  : constant Ada.Streams.Stream_Element_Array (1 .. 3) :=
              [0, 1, 0];
            Padded : constant Ada.Streams.Stream_Element_Array (1 .. 8) :=
              [0, 0, 0, 0, 0, 0, 1, 0];
         begin
            Check (BN.Bit_Length (Zero) = 0, "zero has no bits");
            Check (BN.Bit_Length (One) = 1, "one has one");
            Check (BN.Bit_Length (Eight) = 8, "255 has eight");
            Check (BN.Bit_Length (Nine) = 9, "256 has nine");
            Check (BN.Bit_Length (Padded) = 9,
                   "and leading zero octets are not bits");
         end;
      end;

      --  Bignum's own operations, against answers this test computes a
      --  different way. Multiply_Small is the one key generation leans on for
      --  the large-by-small step in the inverse.
      declare
         package BN renames CryptoLib.Bignum;
         Value : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_Hex ("0123456789abcdef0123456789abcdef");
         Repeated : Ada.Streams.Stream_Element_Array (1 .. 20) :=
           [others => 0];
      begin
         --  Multiplying by n is adding n times, for a small n.
         for I in 1 .. 7 loop
            declare
               Sum : constant Ada.Streams.Stream_Element_Array :=
                 BN.Add (Repeated, Value);
               Fits : Boolean;
            begin
               BN.Resize (Sum, Repeated'Length, Repeated, Fits);
               Check (Fits, "the running sum still fits");
            end;
         end loop;
         declare
            Product : constant Ada.Streams.Stream_Element_Array :=
              BN.Multiply_Small (Value, 7);
            Sized   : Ada.Streams.Stream_Element_Array (1 .. 20);
            Fits    : Boolean;
         begin
            BN.Resize (Product, Sized'Length, Sized, Fits);
            Check (Fits and then Sized = Repeated,
                   "multiplying by a small number is repeated addition");
         end;
         --  And the general multiply agrees with the small one.
         declare
            Seven : constant Ada.Streams.Stream_Element_Array := [1 => 7];
            Wide  : constant Ada.Streams.Stream_Element_Array :=
              BN.Multiply (Value, Seven);
            Sized : Ada.Streams.Stream_Element_Array (1 .. 20);
            Fits  : Boolean;
         begin
            BN.Resize (Wide, Sized'Length, Sized, Fits);
            Check (Fits and then Sized = Repeated,
                   "the general multiply agrees with the small one");
         end;
      end;

      --  The modular inverse on its own, both ways round.
      --
      --  Key generation calls this to turn 65537 into the private exponent,
      --  but it cannot be tested through key generation: the sign-and-verify
      --  check inside Generate_Keypair discards a key built on a wrong
      --  inverse and draws another, so a half-broken inverse shows up as the
      --  generator being slower rather than as anything failing. Breaking the
      --  negative fold and running the suite proved exactly that -- nothing
      --  noticed. So it is checked here directly, on two moduli chosen to
      --  send it down each branch: one where the intermediate comes out
      --  positive, one where it comes out negative and has to be folded back
      --  into range. Both are about equally common in real use.
      declare
         Neg_Modulus : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_Hex
             ("8000000000000000000000000000000000000000000000000000000000000003");
         Neg_Inverse : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_Hex
             ("36db4924b6db4924b6db4924b6db4924b6db4924b6db4924b6db4924b6db4926");
         Pos_Modulus : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_Hex
             ("8000000000000000000000000000000000000000000000000000000000000005");
         Pos_Inverse : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_Hex
             ("68ba1745e8ba1745e8ba1745e8ba1745e8ba1745e8ba1745e8ba1745e8ba174a");
         Result : Ada.Streams.Stream_Element_Array (1 .. 32);
         Fine   : Boolean;
      begin
         CryptoLib.Bignum.Mod_Inverse_Small
           (65537, Neg_Modulus, Result, Fine);
         Check (Fine and then Result = Neg_Inverse,
                "the inverse of 65537 is right where the intermediate is "
                & "negative");
         CryptoLib.Bignum.Mod_Inverse_Small
           (65537, Pos_Modulus, Result, Fine);
         Check (Fine and then Result = Pos_Inverse,
                "and where it is positive");

         --  A modulus sharing a factor with the value has no inverse.
         declare
            Even : constant Ada.Streams.Stream_Element_Array :=
              Bytes_From_Hex ("0000000000000000000000000000000000000000000000000000000000020002");
            Small_Result : Ada.Streams.Stream_Element_Array (1 .. 32);
         begin
            CryptoLib.Bignum.Mod_Inverse_Small (2, Even, Small_Result, Fine);
            Check (not Fine, "a value sharing a factor with the modulus has "
                   & "no inverse");
            Check (Small_Result = [Small_Result'Range => 0],
                   "and the buffer is left zero");
         end;
      end;

      --  Key generation. Kept to 2048 bits: the larger sizes work but cost
      --  seconds each, and what is being checked here is the construction,
      --  not the width.
      declare
         N : Ada.Streams.Stream_Element_Array (1 .. 256);
         E : Ada.Streams.Stream_Element_Array (1 .. 3);
         D : Ada.Streams.Stream_Element_Array (1 .. 256);
         Sig : Ada.Streams.Stream_Element_Array (1 .. 256);
      begin
         Check (R.Modulus_Octets (R.RSA_2048) = 256
                and then R.Modulus_Octets (R.RSA_3072) = 384
                and then R.Modulus_Octets (R.RSA_4096) = 512,
                "each size names its own width in octets");
         Check (R.Generate_Keypair (R.RSA_2048, Rng, N, E, D)
                  = CryptoLib.Errors.Ok,
                "RSA generates a 2048-bit keypair");
         Check (E = [16#01#, 16#00#, 16#01#],
                "the generated public exponent is 65537");
         Check (N (N'First) >= 16#80#,
                "the modulus has exactly the requested width -- the top octet "
                & "is set, which is what drawing primes with their top two "
                & "bits set is for");
         Check ((N (N'Last) and 1) = 1, "the modulus is odd");

         --  d is the real private exponent, checked without knowing p or q:
         --  raising to d and then to e returns the input exactly when
         --  e*d = 1 mod lambda(n). A modulus or inverse that was subtly wrong
         --  fails here even though every length and shape looks right.
         declare
            Base : Ada.Streams.Stream_Element_Array (1 .. 256) :=
              [others => 0];
            Once, Twice : Ada.Streams.Stream_Element_Array (1 .. 256);
         begin
            Base (Base'Last) := 42;
            Once := CryptoLib.Modexp.Mod_Exp (Base, D, N);
            Twice := CryptoLib.Modexp.Mod_Exp (Once, E, N);
            Check (Twice = Base,
                   "raising to d and then to e is the identity mod n");
            Check (Once /= Base,
                   "and d is not doing nothing");
         end;

         --  The generated key must actually sign.
         Check (R.Sign_PSS (N, E, D, R.SHA256, 32, Message, Rng, Sig)
                  = CryptoLib.Errors.Ok
                and then R.Verify_PSS (N, E, R.SHA256, 32, Message, Sig)
                  = CryptoLib.Errors.Ok,
                "a generated key signs and verifies under PSS");
         Check (R.Sign_PKCS1_V1_5 (N, E, D, R.SHA256, Message, Rng, Sig)
                  = CryptoLib.Errors.Ok
                and then R.Verify_PKCS1_V1_5 (N, E, R.SHA256, Message, Sig)
                  = CryptoLib.Errors.Ok,
                "and under PKCS#1 v1.5");

         --  Two keys must not be the same key.
         declare
            N2 : Ada.Streams.Stream_Element_Array (1 .. 256);
            E2 : Ada.Streams.Stream_Element_Array (1 .. 3);
            D2 : Ada.Streams.Stream_Element_Array (1 .. 256);
         begin
            Check (R.Generate_Keypair (R.RSA_2048, Rng, N2, E2, D2)
                     = CryptoLib.Errors.Ok,
                   "a second keypair generates");
            Check (N2 /= N and then D2 /= D,
                   "and it is a different key");
         end;

         --  Wrong-width buffers are refused.
         declare
            Short_N : Ada.Streams.Stream_Element_Array (1 .. 128) :=
              [others => 16#A5#];
            Short_E : Ada.Streams.Stream_Element_Array (1 .. 2) :=
              [others => 16#A5#];
         begin
            Check (R.Generate_Keypair (R.RSA_2048, Rng, Short_N, E, D)
                     /= CryptoLib.Errors.Ok,
                   "a modulus buffer of the wrong width is refused");
            Check (Short_N = [Short_N'Range => 0], "and left zero");
            Check (R.Generate_Keypair (R.RSA_2048, Rng, N, Short_E, D)
                     /= CryptoLib.Errors.Ok,
                   "an exponent buffer of the wrong width is refused");
            Check (Short_E = [Short_E'Range => 0], "and left zero");
         end;
      end;

      --  The primes and CRT parameters, checked by using them rather than by
      --  restating how they were computed.
      --
      --  A CRT signature is reconstructed from dp, dq and the coefficient and
      --  required to equal the ordinary one. That exercises all three at once
      --  and cannot be satisfied by a wrong value the way "dp is the inverse
      --  of e mod p-1" could be -- that would just re-run the code that made
      --  it. This crate does not sign with CRT; the arithmetic is here only to
      --  hold the parameters it hands out to being the right ones.
      declare
         package BN renames CryptoLib.Bignum;
         Half : constant Ada.Streams.Stream_Element_Offset := 128;
         N  : Ada.Streams.Stream_Element_Array (1 .. 256);
         E  : Ada.Streams.Stream_Element_Array (1 .. 3);
         D  : Ada.Streams.Stream_Element_Array (1 .. 256);
         P, Q, DP, DQ, QI : Ada.Streams.Stream_Element_Array (1 .. Half);
      begin
         Check (R.Generate_Keypair_With_Primes
                  (R.RSA_2048, Rng, N, E, D, P, Q, DP, DQ, QI)
                  = CryptoLib.Errors.Ok,
                "RSA generates a keypair with its primes");

         --  p*q must be the modulus.
         declare
            Product : Ada.Streams.Stream_Element_Array (1 .. 256);
            Fits    : Boolean;
         begin
            BN.Resize (BN.Multiply (P, Q), Product'Length, Product, Fits);
            Check (Fits and then Product = N, "the primes multiply to n");
         end;

         --  q * qinv = 1 mod p. p is odd, so the modular multiply applies.
         declare
            One : Ada.Streams.Stream_Element_Array (1 .. Half) :=
              [others => 0];
         begin
            One (One'Last) := 1;
            Check (CryptoLib.Modexp.Mod_Mul (Q, QI, P) = One,
                   "the coefficient is q inverse modulo p");
         end;

         --  Reconstruct a signature through the CRT and compare.
         declare
            Base : Ada.Streams.Stream_Element_Array (1 .. 256) :=
              [others => 0];
            Small : Ada.Streams.Stream_Element_Array (1 .. Half) :=
              [others => 0];
            Plain : Ada.Streams.Stream_Element_Array (1 .. 256);
         begin
            Base (Base'Last) := 42;
            Small (Small'Last) := 42;         --  below both primes
            Plain := CryptoLib.Modexp.Mod_Exp (Base, D, N);

            declare
               S1 : constant Ada.Streams.Stream_Element_Array :=
                 CryptoLib.Modexp.Mod_Exp (Small, DP, P);
               S2_Raw : constant Ada.Streams.Stream_Element_Array :=
                 CryptoLib.Modexp.Mod_Exp (Small, DQ, Q);
               --  Two copies on purpose. Garner's formula needs s2 reduced
               --  mod p inside the difference, and the *unreduced* s2 in the
               --  final sum -- reducing it once and using it for both is
               --  wrong, which is how the first version of this test failed
               --  against parameters OpenSSL had already called correct.
               S2_Mod_P : Ada.Streams.Stream_Element_Array (1 .. Half) :=
                 S2_Raw;
               Diff : Ada.Streams.Stream_Element_Array (1 .. Half);
               Combined : Ada.Streams.Stream_Element_Array (1 .. 256);
               Fits : Boolean;
            begin
               --  q may exceed p, so bring the copy below p; one subtraction
               --  suffices because the primes are within a bit of each other.
               if BN.Compare (S2_Mod_P, P) >= 0 then
                  S2_Mod_P := BN.Subtract (S2_Mod_P, P);
               end if;
               if BN.Compare (S1, S2_Mod_P) >= 0 then
                  Diff := BN.Subtract (S1, S2_Mod_P);
               else
                  declare
                     Lifted : Ada.Streams.Stream_Element_Array (1 .. Half + 1);
                     Held   : Boolean;
                  begin
                     BN.Resize (BN.Add (S1, P), Lifted'Length, Lifted, Held);
                     Diff := BN.Subtract (Lifted, S2_Mod_P) (2 .. Half + 1);
                  end;
               end if;
               declare
                  H : constant Ada.Streams.Stream_Element_Array :=
                    CryptoLib.Modexp.Mod_Mul (QI, Diff, P);
                  HQ : constant Ada.Streams.Stream_Element_Array :=
                    BN.Multiply (H, Q);
               begin
                  BN.Resize (BN.Add (HQ, S2_Raw), Combined'Length,
                             Combined, Fits);
                  Check (Fits and then Combined = Plain,
                         "a CRT signature rebuilt from dp, dq and the "
                         & "coefficient equals the ordinary one");
               end;
            end;
         end;
      end;

      --  CRT signing. The point of it is speed, and the thing that must not
      --  change is the answer: a CRT signature is the same octets as the plain
      --  one, because both are m**d mod n by different routes. Held to the
      --  byte-exact vectors as well, which is the strongest form of that.
      declare
         N  : Ada.Streams.Stream_Element_Array (1 .. 256);
         Ex : Ada.Streams.Stream_Element_Array (1 .. 3);
         D  : Ada.Streams.Stream_Element_Array (1 .. 256);
         P, Q, DP, DQ, QI : Ada.Streams.Stream_Element_Array (1 .. 128);
         Plain, Via_CRT : Ada.Streams.Stream_Element_Array (1 .. 256);
      begin
         Check (R.Generate_Keypair_With_Primes
                  (R.RSA_2048, Rng, N, Ex, D, P, Q, DP, DQ, QI)
                  = CryptoLib.Errors.Ok,
                "a key with its CRT parameters");

         Check (R.Sign_PKCS1_V1_5 (N, Ex, D, R.SHA256, Message, Rng, Plain)
                  = CryptoLib.Errors.Ok,
                "v1.5 signs without CRT");
         Check (R.Sign_PKCS1_V1_5 (N, Ex, D, R.SHA256, Message, Rng, Via_CRT,
                                   P, Q, DP, DQ, QI)
                  = CryptoLib.Errors.Ok,
                "and with it");
         Check (Plain = Via_CRT,
                "the CRT signature is the same octets as the plain one");
         Check (R.Verify_PKCS1_V1_5 (N, Ex, R.SHA256, Message, Via_CRT)
                  = CryptoLib.Errors.Ok,
                "and it verifies");

         --  PSS is randomised, so the two cannot be compared directly; both
         --  must verify.
         declare
            PSS_Plain, PSS_CRT : Ada.Streams.Stream_Element_Array (1 .. 256);
         begin
            Check (R.Sign_PSS (N, Ex, D, R.SHA256, 0, Message, Rng, PSS_Plain)
                     = CryptoLib.Errors.Ok
                   and then R.Sign_PSS (N, Ex, D, R.SHA256, 0, Message, Rng,
                                        PSS_CRT, P, Q, DP, DQ, QI)
                     = CryptoLib.Errors.Ok,
                   "PSS signs both ways at salt length zero");
            Check (PSS_Plain = PSS_CRT,
                   "and at salt zero, where PSS is deterministic, they agree");
         end;

         --  A CRT parameter that belongs to the wrong prime produces a wrong
         --  signature, and the check against the public exponent refuses it
         --  rather than returning it. That refusal is the whole reason CRT is
         --  safe here: a released faulty CRT signature gives up the factors.
         Check (R.Sign_PKCS1_V1_5 (N, Ex, D, R.SHA256, Message, Rng, Via_CRT,
                                   P, Q, DQ, DP, QI)
                  /= CryptoLib.Errors.Ok,
                "swapped CRT exponents are caught before anything is returned");
         Check (Via_CRT = [Via_CRT'Range => 0],
                "and no signature is left behind");

         --  Both orderings of the primes. Swapping means exchanging p with q
         --  and dp with dq, and computing the coefficient again, since it is
         --  q inverse mod p and both have changed roles.
         --
         --  This improves the odds of exercising the branch that brings s2
         --  below p, and does not guarantee it. s2 is less than q, so the
         --  reduction only happens when q is the larger prime and s2 lands
         --  above p -- which depends on the message as well as on the primes.
         --  Measured by breaking that branch deliberately, this catches it
         --  about one run in three, and no arrangement of a generated key
         --  makes it certain.
         --
         --  What does make it safe is not this test. Every signature is
         --  raised to the public exponent and compared with the block that
         --  went in, so a wrong recombination returns an error rather than a
         --  signature. The branch is checked at run time on every use, which
         --  is a stronger guarantee than a test that fires sometimes.
         declare
            Swapped_QI : Ada.Streams.Stream_Element_Array (1 .. 128);
            Fine       : Boolean;
            Other_Way  : Ada.Streams.Stream_Element_Array (1 .. 256);
         begin
            CryptoLib.Bignum.Mod_Inverse (P, Q, Swapped_QI, Fine);
            Check (Fine, "the coefficient for the swapped ordering exists");
            Check (R.Sign_PKCS1_V1_5
                     (N, Ex, D, R.SHA256, Message, Rng, Other_Way,
                      Q, P, DQ, DP, Swapped_QI) = CryptoLib.Errors.Ok,
                   "CRT signs with the primes the other way round");
            Check (Other_Way = Plain,
                   "and reaches the same signature, whichever prime is larger");
         end;

         --  Four of the five is not CRT; it falls back rather than doing
         --  something halfway.
         Check (R.Sign_PKCS1_V1_5 (N, Ex, D, R.SHA256, Message, Rng, Via_CRT,
                                   P, Q, DP, DQ)
                  = CryptoLib.Errors.Ok
                and then Via_CRT = Plain,
                "an incomplete CRT set signs the plain way");
      end;

      --  Everything in the machine's own trust store still parses.
      --
      --  This crate's DER reader is deliberately strict -- it refuses
      --  indefinite lengths, non-minimal lengths, and now a BIT STRING whose
      --  padding bits are not zero. Every one of those rules is a chance to
      --  reject a certificate the world actually uses, and the crate's own
      --  corpus cannot show that has not happened: it holds what was written
      --  for it.
      --
      --  So the real store is read when there is one. The assertion is that
      --  nothing in it is refused, not that some particular number of roots
      --  is present -- the count changes as the machine's package updates,
      --  and pinning it would make this fail for a reason that is not about
      --  this crate. Absent a store, the check says so rather than passing
      --  quietly.
      declare
         Store_Path : constant String := "/etc/ssl/certs/ca-certificates.crt";
         Present    : Boolean;
      begin
         Present := Ada.Directories.Exists (Store_Path);
         if not Present then
            Ada.Text_IO.Put_Line
              ("  (no system trust store here; roots not re-checked)");
         else
            declare
               Size : constant Natural :=
                 Natural (Ada.Directories.Size (Store_Path));
               File : Ada.Streams.Stream_IO.File_Type;
               Raw  : Ada.Streams.Stream_Element_Array
                 (1 .. Ada.Streams.Stream_Element_Offset (Size));
               Last : Ada.Streams.Stream_Element_Offset;
               Text : String (1 .. Size);
               Seen, Refused : Natural := 0;
            begin
               Ada.Streams.Stream_IO.Open
                 (File, Ada.Streams.Stream_IO.In_File, Store_Path);
               Ada.Streams.Stream_IO.Read (File, Raw, Last);
               Ada.Streams.Stream_IO.Close (File);
               for I in Text'Range loop
                  Text (I) :=
                    Character'Val
                      (Raw (Ada.Streams.Stream_Element_Offset (I)));
               end loop;

               declare
                  use type CryptoLib.PEM.Decode_Status;
                  From   : Positive := Text'First;
                  Buffer : Ada.Streams.Stream_Element_Array
                    (1 .. Ada.Streams.Stream_Element_Offset
                            (CryptoLib.PEM.Maximum_Decoded_Length (Text)));
                  Wrote  : Ada.Streams.Stream_Element_Offset;
                  P_St   : CryptoLib.PEM.Decode_Status;
               begin
                  loop
                     CryptoLib.PEM.Decode_Block
                       (Text, "CERTIFICATE", From, Buffer, Wrote, P_St);
                     exit when Wrote < Buffer'First;
                     Seen := Seen + 1;
                     declare
                        D_St : CryptoLib.ASN1.Errors.Decode_Status;
                        Item : constant CryptoLib.X509.Certificates.Certificate
                          := CryptoLib.X509.Certificates.Decode_DER
                               (Buffer (Buffer'First .. Wrote),
                                CryptoLib.ASN1.Default_Limits, D_St);
                     begin
                        if P_St /= CryptoLib.PEM.Ok
                          or else not CryptoLib.X509.Certificates.Is_Present
                                        (Item)
                        then
                           Refused := Refused + 1;
                        end if;
                     end;
                  end loop;
                  Check (Seen > 0,
                         "the system trust store holds certificates to read");
                  Check (Refused = 0,
                         "every certificate in the system trust store parses,"
                         & Seen'Image & " of them, none refused");
               end;
            end;
         end if;
      end;

      --  A revocation entry naming a negative serial number.
      --
      --  Serials are compared as magnitudes with leading zeros stripped, which
      --  is right for the padded encodings a positive serial can have. It is
      --  wrong across the sign: DER writes -1 as content FF and 255 as content
      --  00 FF, and stripping leaves both as FF. A list naming -1 therefore
      --  reported the certificate whose serial is 255 as revoked. RFC 5280
      --  requires a serial to be positive; that requirement was read past.
      --
      --  Both lists below are the same bytes apart from the serial, so the
      --  positive one passing is what says the refusal is aimed at the sign
      --  and not at the hand-built list.
      declare
         package CRL renames CryptoLib.X509.CRLs;
         Serial_255 : constant Ada.Streams.Stream_Element_Array :=
           [16#00#, 16#FF#];
         Negative : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
           ("3081853051020101300d06092a864886f70d01010b05003018311630"
            & "140603550403130d6e65672d73657269616c2d6361170d3235303130"
            & "313030303030305a301430120201ff170d3235303130313030303030"
            & "305a300d06092a864886f70d01010b05000321000000000000000000"
            & "000000000000000000000000000000000000000000000000");
         Positive_One : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_Hex
           ("3081863052020101300d06092a864886f70d01010b05003018311630"
            & "140603550403130d6e65672d73657269616c2d6361170d3235303130"
            & "313030303030305a30153013020200ff170d32353031303130303030"
            & "30305a300d06092a864886f70d01010b050003210000000000000000"
            & "00000000000000000000000000000000000000000000000000");
         St : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         declare
            Good : constant CRL.Revocation_List :=
              CRL.Decode_DER (Positive_One, CryptoLib.ASN1.Default_Limits, St);
         begin
            Check (CRL.Is_Revoked (Good, Serial_255),
                   "a list naming serial 255 revokes serial 255");
         end;
         declare
            Bad : constant CRL.Revocation_List :=
              CRL.Decode_DER (Negative, CryptoLib.ASN1.Default_Limits, St);
         begin
            Check (not CRL.Is_Revoked (Bad, Serial_255),
                   "a list naming serial -1 does not revoke serial 255");
         end;
      end;

      --  An EC private key whose version is not the one RFC 5915 defines.
      --
      --  ECPrivateKey has exactly one version, ecPrivkeyVer1. This parser read
      --  it to step past it and never looked, which is the same shape as the
      --  RSA version that let a three-prime key through described as two of
      --  its primes. The two keys below differ in a single hex digit -- the
      --  version -- so the good one still parsing is what says the refusal is
      --  aimed at the version and not at the key.
      declare
         package P8 renames CryptoLib.PKCS8;
         use type CryptoLib.ASN1.Errors.Decode_Status;
         Good : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
           ("308187020100301306072a8648ce3d020106082a8648ce3d03010704"
            & "6d306b0201010420bb3914abe365433e40ba86663df5bf9b544d9bcb"
            & "55e21947a45eaf8ead169c7ba14403420004e88e9bd792561d0ac88b"
            & "cf58c0f8c91da493da9dbce2c528e87f79f0d3438804ec104757377c"
            & "900b1ad68f37cf7ae4196cc472d2b6dc2c34d2f8ba115d608bdc");
         Bad : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
           ("308187020100301306072a8648ce3d020106082a8648ce3d03010704"
            & "6d306b0201020420bb3914abe365433e40ba86663df5bf9b544d9bcb"
            & "55e21947a45eaf8ead169c7ba14403420004e88e9bd792561d0ac88b"
            & "cf58c0f8c91da493da9dbce2c528e87f79f0d3438804ec104757377c"
            & "900b1ad68f37cf7ae4196cc472d2b6dc2c34d2f8ba115d608bdc");
         Key : P8.Private_Key;
         St  : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         P8.Decode_DER (Good, CryptoLib.ASN1.Default_Limits, Key, St);
         Check (St = CryptoLib.ASN1.Errors.Ok and then P8.Is_Present (Key),
                "an EC private key with version 1 parses");
         declare
            Other : P8.Private_Key;
         begin
            P8.Decode_DER (Bad, CryptoLib.ASN1.Default_Limits, Other, St);
            Check (St /= CryptoLib.ASN1.Errors.Ok
                   and then not P8.Is_Present (Other),
                   "and one claiming version 2 is refused");
         end;
      end;

      --  A multi-prime RSA key is refused rather than read as two of its
      --  primes.
      --
      --  RFC 3447 marks these with version 1 and puts the extra primes after
      --  the five CRT fields. This reader takes exactly two, so such a key
      --  decoded happily and reported a p and a q that were two of three --
      --  86 octets each against a 257-octet modulus, whose product is not the
      --  modulus. Nothing said so; it would have surfaced later as a CRT
      --  signature the public-exponent check refused, with no hint why.
      declare
         package P8 renames CryptoLib.PKCS8;
         use type CryptoLib.ASN1.Errors.Decode_Status;
         Multi : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
           ("308204f3020100300d06092a864886f70d0101010500048204dd308204"
            & "d90201010282010100b1f79a0176297bbfe7d5115040b8211d31edbf3b"
            & "d6373f2b0c1eca199cf8f18534e94168553192c5018365bb250c25fa97"
            & "d501057f5c0a633141be9235c8645531027121d369b0d46e7057401308"
            & "08cd60b880f42d0b572ba99a92d1f3648512b1ae358fc8c0aac8620ac8"
            & "b95ede851c599bdbd4c33688f8d852adaf58122ec9359f9e8322be87e9"
            & "99c86bb687a9eeaa4ec6f56efe1f34e67a9ed1326944b733c4b84f1150"
            & "1c47990c26840b18f08ea8b9ece08220a984fa08fc6366e48aeef92148"
            & "83bd470c419f918505c6c8f722e2c0beb86f3212159423040fe8dca933"
            & "b6bd62063c3549af94ab90c82579ef78175b9ad797dce3e943ab4da787"
            & "930d733f02030100010282010022f8728cc2f957d5d7ea68628ab523dc"
            & "a6c8ff00f5111a1a8d6127796cfd060894e318f535786e4cc4055be230"
            & "5f78bf0b42d1d690b6375c527b86c518486e5ec728a1ae71ea9cd2c178"
            & "d5cc43711ab9b0bdd0a92a74cb62c5e7ee30bf307ea916395f57c40fcd"
            & "77fc91807e03cd4ac74007e26b37733ac95900f68fa0bbac213f2117b5"
            & "9201cfb12a71f103ffd391b88bfde0b3dedc742315194b986bd1f94eb6"
            & "50f4a46126f87788038dbeca6dc740294bd1e230b29d8959b60fb70142"
            & "15f2f4c1cd6ac9ffa1854aa2f57959bf21fb5b38657011075fd4f8c7f7"
            & "71eeeab402588445f414d0da16b6799eb6e9c1e354cc62b3519b642127"
            & "bea3216d3f08e50102560764eca45cf51928f53419257b08e8c2b33ac5"
            & "aad8b9c7c128b5457122a89244c234babb7e96ea45febab58aafb8b09e"
            & "d06f3925233554df6a5b5501a5036482a3e16b1360a2db90bdf3c2fc57"
            & "1b26303954e2d243830256071c3e751a1ac73830a854aa9d115add7412"
            & "1a8e157f9ff089a384aa1a6e295a9fbbe26f01d8c0c6c814f16fde8591"
            & "4e3d6455a54afaa4b375e1c0e833b967a63806a6c9a131928511582dff"
            & "5d26c7c66aad2215842502560407987faab95850ddf0da93768dd06beb"
            & "496858476c57d488dee14d5ada0b7cb56a0f2a073f2fc59da11b36cdb5"
            & "156c37a3a5bcfb87210df0e47d5b3c16b13c111bd442e73359fd73c7d8"
            & "c7b4a0f31aece3ba0965090256029cb8c172c6b5bc09fc3da6b4afa48f"
            & "494e415d43beb076c14a46b9eb9ddf2981179897a9b90511c27e17393f"
            & "2a18f9028af30017ecbf47831e5e2db09b03de4825016f7ffde35369cc"
            & "d891419ab6b84986b3c7edd5025601001f23c128dd3f40776a2e7c6778"
            & "2166729dea9744515fc3e3fc0f5b212f6b81770c3b2d87175f41b94cd7"
            & "7e93a1bd0de56dc594811ec50d29ccc5712fd83500d74a500a8cbb19bb"
            & "40e29d86386e3e967d26fdab423082010c30820108025603628e83649f"
            & "544b72e732db6dd827a1672c2cc166215f9b71d84c983e23726ebf0f4f"
            & "df727544529911339cb2d9ad9304b1123c80d784c75b429831bce4f6d3"
            & "5e5c615e406eb22c06ffc00712c13db0c393f4e47fb102560104e42934"
            & "db2f52c3d64d9e78b4b241cac126fc5716472592a1ef758a87bb85122a"
            & "b6fe6c04583c91eef6ddff8ebfce5a84411c4c2216ccba7213462e3bb5"
            & "0030119a12f94d1a815cde14df4c4b379a87577d4c6a1102560084129b"
            & "bf4dcc97fa65012c35858d74b6a70b786b74a7a63a313adac033cb2aef"
            & "07be8f6a5dbb541746a241891c08dcecb62828b61ce24d5b6501ab9ec2"
            & "fe686f64b2491d8513020d13ebfb452779a4ac8fc1c5d0bd");
         Key : P8.Private_Key;
         St  : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         P8.Decode_DER (Multi, CryptoLib.ASN1.Default_Limits, Key, St);
         Check (St /= CryptoLib.ASN1.Errors.Ok,
                "a three-prime RSA key is refused");
         Check (not P8.Is_Present (Key),
                "and nothing is handed back to read primes out of");
      end;

      --  A reused blinding pair. The pair changes what the exponentiation
      --  sees on every signature and must change nothing about the signature,
      --  so the test is that a run of them are all identical to one made
      --  without a pair at all.
      declare
         N  : Ada.Streams.Stream_Element_Array (1 .. 256);
         Ex : Ada.Streams.Stream_Element_Array (1 .. 3);
         D  : Ada.Streams.Stream_Element_Array (1 .. 256);
         P, Q, DP, DQ, QI : Ada.Streams.Stream_Element_Array (1 .. 128);
         Reference, With_Pair : Ada.Streams.Stream_Element_Array (1 .. 256);
         Pair : R.Blinding_Pair;
         All_Same : Boolean := True;
      begin
         Check (R.Generate_Keypair_With_Primes
                  (R.RSA_2048, Rng, N, Ex, D, P, Q, DP, DQ, QI)
                  = CryptoLib.Errors.Ok,
                "a key for the blinding-pair test");
         Check (R.Sign_PKCS1_V1_5 (N, Ex, D, R.SHA256, Message, Rng,
                                   Reference, P, Q, DP, DQ, QI)
                  = CryptoLib.Errors.Ok,
                "a reference signature without a pair");

         Check (R.Start_Blinding (N, Ex, Rng, Pair) = CryptoLib.Errors.Ok,
                "a blinding pair starts");
         --  Several signatures from one pair: it is squared after each, so a
         --  refresh that broke the inverse relation would show up on the
         --  second and not the first.
         for Round in 1 .. 4 loop
            if R.Sign_PKCS1_V1_5 (N, Ex, D, R.SHA256, Message, Rng, Pair,
                                  With_Pair, P, Q, DP, DQ, QI)
                 /= CryptoLib.Errors.Ok
              or else With_Pair /= Reference
            then
               All_Same := False;
            end if;
         end loop;
         Check (All_Same,
                "four signatures from one refreshed pair all equal the "
                & "reference");

         --  A pair belongs to the modulus it was started for.
         declare
            Other_N  : Ada.Streams.Stream_Element_Array (1 .. 256);
            Other_E  : Ada.Streams.Stream_Element_Array (1 .. 3);
            Other_D  : Ada.Streams.Stream_Element_Array (1 .. 256);
            O_P, O_Q, O_DP, O_DQ, O_QI :
              Ada.Streams.Stream_Element_Array (1 .. 128);
            Wrong    : Ada.Streams.Stream_Element_Array (1 .. 256) :=
              [others => 16#A5#];
            Narrow   : R.Blinding_Pair;
            Small_N  : Ada.Streams.Stream_Element_Array (1 .. 128) :=
              [others => 0];
         begin
            Check (R.Generate_Keypair_With_Primes
                     (R.RSA_2048, Rng, Other_N, Other_E, Other_D,
                      O_P, O_Q, O_DP, O_DQ, O_QI) = CryptoLib.Errors.Ok,
                   "a second key");
            --  Same width, different modulus: the pair is accepted by width
            --  and the signature simply will not verify, which the check
            --  against the public exponent turns into a refusal rather than a
            --  bad signature. That is the important half.
            Check (R.Sign_PKCS1_V1_5 (Other_N, Other_E, Other_D, R.SHA256,
                                      Message, Rng, Pair, Wrong,
                                      O_P, O_Q, O_DP, O_DQ, O_QI)
                     /= CryptoLib.Errors.Ok,
                   "a pair from another key of the same width is caught by "
                   & "the check against the public exponent");
            Check (Wrong = [Wrong'Range => 0], "and no signature is returned");

            --  A different width is refused outright, before any arithmetic.
            Small_N (Small_N'Last) := 3;
            Small_N (Small_N'First) := 16#80#;
            Check (R.Start_Blinding (Small_N, Ex, Rng, Narrow)
                     = CryptoLib.Errors.Ok,
                   "a pair for a narrower modulus starts");
            --  Named status, not merely "not Ok". Without the width guard the
            --  signature comes out wrong and the check against the public
            --  exponent refuses it anyway -- so a test that accepted any
            --  failure would pass with the guard deleted. What the guard buys
            --  is saying which thing went wrong, and that is what is asserted.
            Check (R.Sign_PKCS1_V1_5 (N, Ex, D, R.SHA256, Message, Rng,
                                      Narrow, Wrong, P, Q, DP, DQ, QI)
                     = CryptoLib.Errors.Handshake_Failed,
                   "and a wider modulus is refused as a mismatched pair, not "
                   & "as a bad signature");
            R.Wipe (Narrow);
         end;

         --  A pair does not square for ever. Past the refresh limit it is
         --  drawn again, so no run of signatures uses factors that are all
         --  powers of one initial value. Signing well past the limit must
         --  still produce the same signature every time, which is what shows
         --  the redraw keeps the pair consistent rather than merely different.
         declare
            Long_Run : Ada.Streams.Stream_Element_Array (1 .. 256);
            Steady   : Boolean := True;
         begin
            for Round in 1 .. R.Blinding_Refresh_Limit + 3 loop
               if R.Sign_PKCS1_V1_5 (N, Ex, D, R.SHA256, Message, Rng, Pair,
                                     Long_Run, P, Q, DP, DQ, QI)
                    /= CryptoLib.Errors.Ok
                 or else Long_Run /= Reference
               then
                  Steady := False;
               end if;
            end loop;
            Check (Steady,
                   "signing past the refresh limit keeps giving the reference "
                   & "signature, so the redrawn pair is still a pair");
         end;

         --  An unstarted pair is drawn rather than refused, so the pair-taking
         --  form is safe to call without Start_Blinding.
         declare
            Unstarted : R.Blinding_Pair;
            Fresh     : Ada.Streams.Stream_Element_Array (1 .. 256);
         begin
            Check (R.Sign_PKCS1_V1_5 (N, Ex, D, R.SHA256, Message, Rng,
                                      Unstarted, Fresh, P, Q, DP, DQ, QI)
                     = CryptoLib.Errors.Ok
                   and then Fresh = Reference,
                   "an unstarted pair is drawn on first use");
            R.Wipe (Unstarted);
         end;

         R.Wipe (Pair);
      end;

      --  Blinding cannot be seen in the output -- that is the point of it,
      --  the signature is identical either way, and the byte-exact vectors
      --  above would pass with it removed. What can be seen is that the
      --  private operation now needs randomness: with a source that refuses
      --  to yield bytes, signing must fail rather than quietly proceed
      --  unblinded. That is the only black-box evidence the blinding is
      --  actually being done, so it is what this checks.
      declare
         Dead : CryptoLib.Random.Random_Source;
         Sig  : Ada.Streams.Stream_Element_Array (1 .. 256) :=
           [others => 16#A5#];
      begin
         CryptoLib.Random.Initialize_Failing (Dead);
         Check (R.Sign_PKCS1_V1_5
                  (Modulus, Public_Exponent, Private_Exponent, R.SHA256,
                   Message, Dead, Sig) /= CryptoLib.Errors.Ok,
                "signing fails closed when no blinding factor can be drawn");
         Check (Sig = [Sig'Range => 0], "and leaves no signature behind");
         Check (R.Sign_PSS
                  (Modulus, Public_Exponent, Private_Exponent, R.SHA256, 0,
                   Message, Dead, Sig) /= CryptoLib.Errors.Ok,
                "and so does PSS, even at a salt length needing no randomness");
      end;

      --  Refusals, each leaving the buffer zero.
      declare
         Wrong_D : constant Ada.Streams.Stream_Element_Array (1 .. 256) :=
           [others => 3];
         Even_N  : Ada.Streams.Stream_Element_Array := Modulus;
         Short   : Ada.Streams.Stream_Element_Array (1 .. 128) :=
           [others => 16#A5#];
         Sig     : Ada.Streams.Stream_Element_Array (1 .. 256) :=
           [others => 16#A5#];
      begin
         --  The wrong private exponent produces a signature that does not
         --  verify, and the verify-after-sign check refuses to hand it back.
         Check (R.Sign_PKCS1_V1_5 (Modulus, Public_Exponent, Wrong_D,
                                   R.SHA256, Message, Rng, Sig)
                  /= CryptoLib.Errors.Ok,
                "a signature that does not verify is not returned");
         Check (Sig = [Sig'Range => 0], "and the buffer is left zero");

         Even_N (Even_N'Last) := Even_N (Even_N'Last) and 16#FE#;
         Check (R.Sign_PKCS1_V1_5 (Even_N, Public_Exponent, Private_Exponent,
                                   R.SHA256, Message, Rng, Sig)
                  /= CryptoLib.Errors.Ok,
                "an even modulus is not an RSA modulus");

         Check (R.Sign_PKCS1_V1_5 (Modulus, Public_Exponent, Private_Exponent,
                                   R.SHA256, Message, Rng, Short)
                  /= CryptoLib.Errors.Ok,
                "the output must be exactly as long as the modulus");
         Check (Short = [Short'Range => 0], "and it too is left zero");

         --  A salt too long for the modulus and digest is refused rather than
         --  quietly shortened.
         Check (R.Sign_PSS (Modulus, Public_Exponent, Private_Exponent,
                            R.SHA256, 256, Message, Rng, Sig)
                  /= CryptoLib.Errors.Ok,
                "a salt too long for the modulus is refused");
      end;
   end Check_RSA_Signing;

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

   --  AUnit routine wrappers. Each check is a test of its own, so a
   --  failure reports the check that failed and the rest still run.
   procedure Run_Check_Weak_RSA_Key (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_RSA_Signing (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_RSA_Verify (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_RSA_PSS (Item : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Check_Weak_RSA_Key (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Weak_RSA_Key;
   end Run_Check_Weak_RSA_Key;

   procedure Run_Check_RSA_Signing (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_RSA_Signing;
   end Run_Check_RSA_Signing;

   procedure Run_Check_RSA_Verify (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_RSA_Verify;
   end Run_Check_RSA_Verify;

   procedure Run_Check_RSA_PSS (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_RSA_PSS;
   end Run_Check_RSA_PSS;

   overriding procedure Register_Tests (Item : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (Item, Run_Check_Weak_RSA_Key'Access, "weak rsa key");
      Register_Routine (Item, Run_Check_RSA_Signing'Access, "rsa signing");
      Register_Routine (Item, Run_Check_RSA_Verify'Access, "rsa verify");
      Register_Routine (Item, Run_Check_RSA_PSS'Access, "rsa pss");
   end Register_Tests;

   overriding function Name (Item : Test_Case) return AUnit.Message_String is
      pragma Unreferenced (Item);
   begin
      return AUnit.Format ("cryptolib RSA");
   end Name;

end Tests_RSA;
