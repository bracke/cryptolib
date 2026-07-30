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

package body Tests_Curves is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Certificates.Certificate_Status;
   use type Interfaces.Unsigned_32;

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

   --  ECDH on the NIST prime curves. The agreement itself is checked against
   --  NIST CAVP and against secrets OpenSSL derived; the refusals are checked
   --  because an unvalidated peer point recovers the private key.
   procedure Check_ECDH is
      package E renames CryptoLib.ECDH;
      package C renames CryptoLib.EC_Curves;

      CAVP_D256 : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
        ("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");
      CAVP_Q256 : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
        ("04700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287"
         & "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac");
      CAVP_Z256 : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
        ("46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b");
      CAVP_P256 : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
        ("04ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230"
         & "28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141");

      CAVP_D384 : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
        ("3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b6818a661774a"
         & "d463b205da88cf699ab4d43c9cf98a1");
      CAVP_Q384 : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
        ("04a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272"
         & "734466b400091adbf2d68c58e0c50066ac68f19f2e1cb879aed43a9969b91a08"
         & "39c4c38a49749b661efedf243451915ed0905a32b060992b468c64766fc8437a");
      CAVP_Z384 : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
        ("5f9d29dc5e31a163060356213669c8ce132e22f57c9a04f40ba7fcead493b457"
         & "e5621e766c40a2e3d4d6a04b25e533f1");

      --  Keys OpenSSL generated; secret OpenSSL derived with pkeyutl.
      OSSL_D : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
        ("2f7724167279463ea243509514c2cd7e8aa6dde0daa21e42af431db0dac93233");
      OSSL_Q : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
        ("048ff6d1fc398a46324dccb4b26c10ee9502d024629aef8136492904642ba6c49d"
         & "15caecc8661fa6b11e952b04e4f27f0aaccbfb3daed51de2da41df2e9d3861ea");
      OSSL_Z : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
        ("e6c075c6e17fcae71aa984da3ac4bfb04fcd9f53ea0aeb87de510f09a5b759b0");

      Z32 : Ada.Streams.Stream_Element_Array (1 .. 32);
      Z48 : Ada.Streams.Stream_Element_Array (1 .. 48);
      Pub : Ada.Streams.Stream_Element_Array (1 .. 65);
      St  : CryptoLib.Errors.Status;
   begin
      St := E.Shared_Secret (C.Nistp256, CAVP_D256, CAVP_Q256, Z32);
      Check (St = CryptoLib.Errors.Ok and then Z32 = CAVP_Z256,
             "ECDH P-256 NIST CAVP shared secret");
      St := E.Public_Key (C.Nistp256, CAVP_D256, Pub);
      Check (St = CryptoLib.Errors.Ok and then Pub = CAVP_P256,
             "ECDH P-256 derives CAVP's own public point");
      St := E.Shared_Secret (C.Nistp384, CAVP_D384, CAVP_Q384, Z48);
      Check (St = CryptoLib.Errors.Ok and then Z48 = CAVP_Z384,
             "ECDH P-384 NIST CAVP shared secret");

      St := E.Shared_Secret (C.Nistp256, OSSL_D, OSSL_Q, Z32);
      Check (St = CryptoLib.Errors.Ok and then Z32 = OSSL_Z,
             "ECDH P-256 agrees with a secret OpenSSL derived");

      --  Every refusal a peer can provoke, with the secret left zero.
      declare
         Off_Curve : Ada.Streams.Stream_Element_Array := CAVP_Q256;
         Wrong_Tag : Ada.Streams.Stream_Element_Array := CAVP_Q256;
         Infinity  : constant Ada.Streams.Stream_Element_Array (1 .. 65) :=
           [others => 0];
         --  x set to p exactly: a value From_Bytes would carry unreduced.
         X_Is_P : constant Ada.Streams.Stream_Element_Array := Bytes_From_Hex
           ("04ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
            & "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac");
         Short_Q : constant Ada.Streams.Stream_Element_Array (1 .. 64) :=
           [others => 4];
      begin
         Off_Curve (Off_Curve'Last) := Off_Curve (Off_Curve'Last) + 1;
         Wrong_Tag (Wrong_Tag'First) := 16#02#;

         Check (E.Shared_Secret (C.Nistp256, CAVP_D256, Off_Curve, Z32)
                  /= CryptoLib.Errors.Ok,
                "ECDH refuses a point that is not on the curve");
         Check (Z32 = [Z32'Range => 0],
                "and leaves no shared secret behind");
         Check (not E.Valid_Peer_Point (C.Nistp256, Off_Curve),
                "Valid_Peer_Point refuses it too");

         Check (E.Shared_Secret (C.Nistp256, CAVP_D256, X_Is_P, Z32)
                  /= CryptoLib.Errors.Ok,
                "ECDH refuses a coordinate equal to p rather than reducing it");
         Check (E.Shared_Secret (C.Nistp256, CAVP_D256, Infinity, Z32)
                  /= CryptoLib.Errors.Ok,
                "ECDH refuses the all-zero point");
         Check (E.Shared_Secret (C.Nistp256, CAVP_D256, Wrong_Tag, Z32)
                  /= CryptoLib.Errors.Ok,
                "ECDH refuses a point that is not uncompressed");
         Check (E.Shared_Secret (C.Nistp256, CAVP_D256, Short_Q, Z32)
                  /= CryptoLib.Errors.Ok,
                "ECDH refuses a point of the wrong width");

         --  A scalar outside [1, n-1] is refused as well.
         declare
            Zero_D : constant Ada.Streams.Stream_Element_Array (1 .. 32) :=
              [others => 0];
            Order  : constant Ada.Streams.Stream_Element_Array :=
              Bytes_From_Hex
                ("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63"
                 & "2551");
         begin
            Check (E.Shared_Secret (C.Nistp256, Zero_D, CAVP_Q256, Z32)
                     /= CryptoLib.Errors.Ok,
                   "ECDH refuses a zero private scalar");
            Check (E.Shared_Secret (C.Nistp256, Order, CAVP_Q256, Z32)
                     /= CryptoLib.Errors.Ok,
                   "ECDH refuses a private scalar equal to the order");
         end;
      end;

      --  P-521 key generation, made to fail or succeed on purpose rather than
      --  by luck.
      --
      --  P-521's order is seven bits narrower than its octet width, so an
      --  unmasked draw lands below n about one time in 128 and the 64-attempt
      --  rejection loop usually gave up. "Usually" is not a test: with a live
      --  source this passes or fails at random, and deleting the masking
      --  showed up in only about half of runs.
      --
      --  The deterministic source fixes that. Its pattern repeats FF 00, and
      --  66 octets is an even number of them, so every one of the 64 attempts
      --  draws exactly the same value. Unmasked that value is above n and all
      --  64 attempts are refused -- Internal_Error, every time. Masked to 521
      --  bits its leading octet becomes 01, putting it at about half the
      --  order, and the first attempt succeeds. One run now decides it.
      declare
         Rng     : CryptoLib.Random.Random_Source;
         Pattern : constant Ada.Streams.Stream_Element_Array (1 .. 2) :=
           [16#FF#, 16#00#];
         D521    : Ada.Streams.Stream_Element_Array (1 .. 66);
         Q521    : Ada.Streams.Stream_Element_Array (1 .. 133);
      begin
         CryptoLib.Random.Initialize_Deterministic (Rng, Pattern);
         Check (E.Generate_Keypair (C.Nistp521, Rng, D521, Q521)
                  = CryptoLib.Errors.Ok,
                "P-521 keygen accepts a draw only its masking brings in range");
         Check (D521 (D521'First) <= 16#01#,
                "and the scalar it kept is masked to the order's bit length");
         Check (E.Valid_Peer_Point (C.Nistp521, Q521),
                "and the point that scalar implies is on the curve");
      end;

      --  Trim_To_Order's own contract, on each curve: P-256 and P-384 have no
      --  excess bits and must be left alone, P-521 has seven and must lose
      --  them. Checked directly so the rule is pinned even where no curve
      --  currently exercises it.
      declare
         All_Ones_32 : Ada.Streams.Stream_Element_Array (1 .. 32) :=
           [others => 16#FF#];
         All_Ones_48 : Ada.Streams.Stream_Element_Array (1 .. 48) :=
           [others => 16#FF#];
         All_Ones_66 : Ada.Streams.Stream_Element_Array (1 .. 66) :=
           [others => 16#FF#];
      begin
         C.Trim_To_Order (C.P256_Curve, All_Ones_32);
         C.Trim_To_Order (C.P384_Curve, All_Ones_48);
         C.Trim_To_Order (C.P521_Curve, All_Ones_66);
         Check (All_Ones_32 = [All_Ones_32'Range => 16#FF#],
                "Trim_To_Order leaves P-256 untouched");
         Check (All_Ones_48 = [All_Ones_48'Range => 16#FF#],
                "Trim_To_Order leaves P-384 untouched");
         Check (All_Ones_66 (All_Ones_66'First) = 16#01#
                and then All_Ones_66 (All_Ones_66'First + 1) = 16#FF#,
                "Trim_To_Order clears P-521's seven excess bits and no more");
      end;

      --  A fresh exchange on each curve must reach the same secret from both
      --  sides.
      for Curve in C.Curve_Kind loop
         declare
            Rng : CryptoLib.Random.Random_Source;
            W   : constant Ada.Streams.Stream_Element_Offset :=
              Ada.Streams.Stream_Element_Offset (E.Secret_Length (Curve));
            PW  : constant Ada.Streams.Stream_Element_Offset :=
              Ada.Streams.Stream_Element_Offset (E.Public_Key_Length (Curve));
            Da, Db, Za, Zb : Ada.Streams.Stream_Element_Array (1 .. W);
            Qa, Qb         : Ada.Streams.Stream_Element_Array (1 .. PW);
            Name : constant String := C.Curve_Kind'Image (Curve);
         begin
            CryptoLib.Random.Initialize_Production (Rng);
            Check (E.Generate_Keypair (Curve, Rng, Da, Qa)
                     = CryptoLib.Errors.Ok
                   and then E.Generate_Keypair (Curve, Rng, Db, Qb)
                     = CryptoLib.Errors.Ok,
                   "ECDH generates a keypair on " & Name);
            Check (E.Valid_Peer_Point (Curve, Qa)
                   and then E.Valid_Peer_Point (Curve, Qb),
                   "ECDH's own generated points pass its own validation on "
                   & Name);
            Check (E.Shared_Secret (Curve, Da, Qb, Za) = CryptoLib.Errors.Ok
                   and then E.Shared_Secret (Curve, Db, Qa, Zb)
                     = CryptoLib.Errors.Ok,
                   "both sides agree a secret on " & Name);
            Check (Za = Zb and then Za /= [Za'Range => 0],
                   "and it is the same non-zero secret on " & Name);
         end;
      end loop;
   end Check_ECDH;

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

   --  Ed25519 sign/verify (RFC 8032-style deterministic vector).
   procedure Check_Ed25519_Sign_Verify is
   begin
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
   end Check_Ed25519_Sign_Verify;

   --  X25519 RFC 7748 section 5.2 known-answer vectors.
   procedure Check_X25519_Vectors is
   begin
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
   end Check_X25519_Vectors;

   --  ECDSA deterministic (RFC 6979) signing.  P-384 is the authoritative
   --  RFC 6979 A.2.5 vector; P-521 is cross-verified with an external library.
   procedure Check_ECDSA_P384_Deterministic is
   begin
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
   end Check_ECDSA_P384_Deterministic;

   --  P-256 signing, against RFC 6979 A.2.5's own published r and s.
   --
   --  Two messages rather than one. The DRBG state width is the paired
   --  digest's, and the first version of this curve's wiring inherited a
   --  64-byte state meant for P-521 -- so a vector that only asked "did a
   --  signature come out" would have passed on a curve that could not sign
   --  at all. An exact r and s cannot.
   procedure Check_ECDSA_P256_Deterministic is
   begin
      declare
         D_256 : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_Hex
             ("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
         Pub_256 : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_Hex
             ("0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29f"
              & "b67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d446"
              & "2299");
         Sample_R : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_Hex
             ("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716");
         Sample_S : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_Hex
             ("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");
         Test_R : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_Hex
             ("f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367");
         Test_S : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_Hex
             ("019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083");
         Test_Msg : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String ("test");
         Sample_Msg : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String ("sample");
         R_256, S_256 : Ada.Streams.Stream_Element_Array (1 .. 32);
         Derived      : Ada.Streams.Stream_Element_Array (1 .. 65);
         St_256       : CryptoLib.Errors.Status;
      begin
         St_256 := CryptoLib.ECDSA.Public_Key_Raw
           (CryptoLib.ECDSA.Nistp256, D_256, Derived);
         Check (St_256 = CryptoLib.Errors.Ok and then Derived = Pub_256,
                "ECDSA P-256 derives RFC 6979 A.2.5's public key");

         St_256 := CryptoLib.ECDSA.Sign_Nistp256_Raw
           (D_256, Sample_Msg, R_256, S_256);
         Check (St_256 = CryptoLib.Errors.Ok, "ECDSA P-256 sign status");
         Check (R_256 = Sample_R and then S_256 = Sample_S,
                "ECDSA P-256 RFC 6979 A.2.5 KAT (sample)");
         Check (CryptoLib.ECDSA.Verify_Nistp256_Raw
                  (Pub_256, Sample_Msg, R_256, S_256) = CryptoLib.Errors.Ok,
                "ECDSA P-256 verifies what it signed");

         St_256 := CryptoLib.ECDSA.Sign_Nistp256_Raw
           (D_256, Test_Msg, R_256, S_256);
         Check (St_256 = CryptoLib.Errors.Ok and then R_256 = Test_R
                and then S_256 = Test_S,
                "ECDSA P-256 RFC 6979 A.2.5 KAT (test)");

         --  The signature must not verify over a message it does not cover.
         Check (CryptoLib.ECDSA.Verify_Nistp256_Raw
                  (Pub_256, Sample_Msg, R_256, S_256) /= CryptoLib.Errors.Ok,
                "ECDSA P-256 refuses a signature over another message");

         --  The generic entry point must agree with the fixed-curve one, and
         --  must not pair the curve with the wrong digest.
         Check (CryptoLib.ECDSA.Verify_Signature
                  (CryptoLib.ECDSA.Nistp256, CryptoLib.ECDSA.SHA256,
                   Pub_256, Test_Msg, R_256, S_256) = CryptoLib.Errors.Ok,
                "ECDSA P-256 verifies through Verify_Signature");
         Check (CryptoLib.ECDSA.Verify_Signature
                  (CryptoLib.ECDSA.Nistp256, CryptoLib.ECDSA.SHA384,
                   Pub_256, Test_Msg, R_256, S_256) /= CryptoLib.Errors.Ok,
                "ECDSA P-256 refuses the signature under the wrong digest");
      end;
   end Check_ECDSA_P256_Deterministic;

   --  P-256 key generation: the pair it returns must actually be a pair, and
   --  must be usable by the signer.
   procedure Check_ECDSA_P256_Keygen is
   begin
      declare
         Rng     : CryptoLib.Random.Random_Source;
         Scalar  : Ada.Streams.Stream_Element_Array (1 .. 32);
         Point   : Ada.Streams.Stream_Element_Array (1 .. 65);
         Derived : Ada.Streams.Stream_Element_Array (1 .. 65);
         R_G, S_G : Ada.Streams.Stream_Element_Array (1 .. 32);
         Msg_G   : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String ("cryptolib p-256 generated key");
         St_G    : CryptoLib.Errors.Status;
      begin
         CryptoLib.Random.Initialize_Production (Rng);
         St_G := CryptoLib.ECDSA.Generate_Nistp256_Keypair (Rng, Scalar, Point);
         Check (St_G = CryptoLib.Errors.Ok, "ECDSA P-256 keygen status");
         Check (Point (Point'First) = 16#04#,
                "ECDSA P-256 keygen emits an uncompressed point");

         --  The point must be the one the scalar implies, not merely a point.
         St_G := CryptoLib.ECDSA.Public_Key_Raw
           (CryptoLib.ECDSA.Nistp256, Scalar, Derived);
         Check (St_G = CryptoLib.Errors.Ok and then Derived = Point,
                "ECDSA P-256 keygen returns a matching pair");

         St_G := CryptoLib.ECDSA.Sign_Nistp256_Raw (Scalar, Msg_G, R_G, S_G);
         Check (St_G = CryptoLib.Errors.Ok, "ECDSA P-256 signs with a fresh key");
         Check (CryptoLib.ECDSA.Verify_Nistp256_Raw (Point, Msg_G, R_G, S_G)
                  = CryptoLib.Errors.Ok,
                "ECDSA P-256 fresh keypair round-trips");
      end;
   end Check_ECDSA_P256_Keygen;

   --  Negative / fail-closed tests: low-order X25519 point and AEAD tamper.
   procedure Check_Low_Order_X25519_Point is
   begin
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
   end Check_Low_Order_X25519_Point;

   --  AUnit routine wrappers. Each check is a test of its own, so a
   --  failure reports the check that failed and the rest still run.
   procedure Run_Check_ECDSA_P384_P521_Signing (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_ECDSA_P384_Public_Key (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Ed448 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_ECDSA_Raw_Entry_Points (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_ECDH (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_X25519_Shared_Secret (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Off_Curve_Key (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Ed25519_Encoding (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_ECDSA_Curves (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_ECDSA_Scalar_Encodings (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_ECDSA_P384_Verify (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Ed25519_Sign_Verify (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_X25519_Vectors (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_ECDSA_P384_Deterministic (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_ECDSA_P256_Deterministic (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_ECDSA_P256_Keygen (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Low_Order_X25519_Point (Item : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Check_ECDSA_P384_P521_Signing (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_ECDSA_P384_P521_Signing;
   end Run_Check_ECDSA_P384_P521_Signing;

   procedure Run_Check_ECDSA_P384_Public_Key (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_ECDSA_P384_Public_Key;
   end Run_Check_ECDSA_P384_Public_Key;

   procedure Run_Check_Ed448 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Ed448;
   end Run_Check_Ed448;

   procedure Run_Check_ECDSA_Raw_Entry_Points (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_ECDSA_Raw_Entry_Points;
   end Run_Check_ECDSA_Raw_Entry_Points;

   procedure Run_Check_ECDH (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_ECDH;
   end Run_Check_ECDH;

   procedure Run_Check_X25519_Shared_Secret (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_X25519_Shared_Secret;
   end Run_Check_X25519_Shared_Secret;

   procedure Run_Check_Off_Curve_Key (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Off_Curve_Key;
   end Run_Check_Off_Curve_Key;

   procedure Run_Check_Ed25519_Encoding (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Ed25519_Encoding;
   end Run_Check_Ed25519_Encoding;

   procedure Run_Check_ECDSA_Curves (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_ECDSA_Curves;
   end Run_Check_ECDSA_Curves;

   procedure Run_Check_ECDSA_Scalar_Encodings (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_ECDSA_Scalar_Encodings;
   end Run_Check_ECDSA_Scalar_Encodings;

   procedure Run_Check_ECDSA_P384_Verify (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_ECDSA_P384_Verify;
   end Run_Check_ECDSA_P384_Verify;

   procedure Run_Check_Ed25519_Sign_Verify (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Ed25519_Sign_Verify;
   end Run_Check_Ed25519_Sign_Verify;

   procedure Run_Check_X25519_Vectors (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_X25519_Vectors;
   end Run_Check_X25519_Vectors;

   procedure Run_Check_ECDSA_P384_Deterministic (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_ECDSA_P384_Deterministic;
   end Run_Check_ECDSA_P384_Deterministic;

   procedure Run_Check_ECDSA_P256_Deterministic (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_ECDSA_P256_Deterministic;
   end Run_Check_ECDSA_P256_Deterministic;

   procedure Run_Check_ECDSA_P256_Keygen (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_ECDSA_P256_Keygen;
   end Run_Check_ECDSA_P256_Keygen;

   procedure Run_Check_Low_Order_X25519_Point (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Low_Order_X25519_Point;
   end Run_Check_Low_Order_X25519_Point;

   overriding procedure Register_Tests (Item : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (Item, Run_Check_ECDSA_P384_P521_Signing'Access, "ecdsa p384 p521 signing");
      Register_Routine (Item, Run_Check_ECDSA_P384_Public_Key'Access, "ecdsa p384 public key");
      Register_Routine (Item, Run_Check_Ed448'Access, "ed448");
      Register_Routine (Item, Run_Check_ECDSA_Raw_Entry_Points'Access, "ecdsa raw entry points");
      Register_Routine (Item, Run_Check_ECDH'Access, "ecdh");
      Register_Routine (Item, Run_Check_X25519_Shared_Secret'Access, "x25519 shared secret");
      Register_Routine (Item, Run_Check_Off_Curve_Key'Access, "off curve key");
      Register_Routine (Item, Run_Check_Ed25519_Encoding'Access, "ed25519 encoding");
      Register_Routine (Item, Run_Check_ECDSA_Curves'Access, "ecdsa curves");
      Register_Routine (Item, Run_Check_ECDSA_Scalar_Encodings'Access, "ecdsa scalar encodings");
      Register_Routine (Item, Run_Check_ECDSA_P384_Verify'Access, "ecdsa p384 verify");
      Register_Routine (Item, Run_Check_Ed25519_Sign_Verify'Access, "ed25519 sign verify");
      Register_Routine (Item, Run_Check_X25519_Vectors'Access, "x25519 vectors");
      Register_Routine (Item, Run_Check_ECDSA_P384_Deterministic'Access, "ecdsa p384 deterministic");
      Register_Routine (Item, Run_Check_ECDSA_P256_Deterministic'Access, "ecdsa p256 deterministic");
      Register_Routine (Item, Run_Check_ECDSA_P256_Keygen'Access, "ecdsa p256 keygen");
      Register_Routine (Item, Run_Check_Low_Order_X25519_Point'Access, "low order x25519 point");
   end Register_Tests;

   overriding function Name (Item : Test_Case) return AUnit.Message_String is
      pragma Unreferenced (Item);
   begin
      return AUnit.Format ("cryptolib elliptic curves");
   end Name;

end Tests_Curves;
