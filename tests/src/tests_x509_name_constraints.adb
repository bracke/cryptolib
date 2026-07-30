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

package body Tests_X509_Name_Constraints is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Certificates.Certificate_Status;
   use type Interfaces.Unsigned_32;

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
                     URI_Outside, URI_Userinfo, M_HOST_OK, M_HOST_NO,
                     M_DOM_OK, M_DOM_NO, M_BOX_OK, M_BOX_NO, M_Legacy,
                     Email);

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
         Check (CryptoLib.ASN1.Errors."=" (Status, CryptoLib.ASN1.Errors.Ok),
                "fixture: the constrained certificates decode");
         Check (Where > 0, "fixture: the CA carries name constraints");
         Check (NC.Check (X509C.Extension_Value (CA, Where), Leaf)
                  = NC.Permitted,
                "the constrained CA permits its own subtree");
      end;
   end Check_Name_Constraints;

   --  AUnit routine wrappers. Each check is a test of its own, so a
   --  failure reports the check that failed and the rest still run.
   procedure Run_Check_Name_Constraint_Depth_Fields (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Unapplicable_Name_Constraint (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Name_Constraints (Item : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Check_Name_Constraint_Depth_Fields (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Name_Constraint_Depth_Fields;
   end Run_Check_Name_Constraint_Depth_Fields;

   procedure Run_Check_Unapplicable_Name_Constraint (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Unapplicable_Name_Constraint;
   end Run_Check_Unapplicable_Name_Constraint;

   procedure Run_Check_Name_Constraints (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Name_Constraints;
   end Run_Check_Name_Constraints;

   overriding procedure Register_Tests (Item : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (Item, Run_Check_Name_Constraint_Depth_Fields'Access, "name constraint depth fields");
      Register_Routine (Item, Run_Check_Unapplicable_Name_Constraint'Access, "unapplicable name constraint");
      Register_Routine (Item, Run_Check_Name_Constraints'Access, "name constraints");
   end Register_Tests;

   overriding function Name (Item : Test_Case) return AUnit.Message_String is
      pragma Unreferenced (Item);
   begin
      return AUnit.Format ("cryptolib X.509 name constraints");
   end Name;

end Tests_X509_Name_Constraints;
