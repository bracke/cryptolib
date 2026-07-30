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

package body Tests_X509_Validation is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Certificates.Certificate_Status;
   use type Interfaces.Unsigned_32;



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

   --  AUnit routine wrappers. Each check is a test of its own, so a
   --  failure reports the check that failed and the rest still run.
   procedure Run_Check_X509_Verify (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Unsupported_Algorithm (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Verification_Failure_Kinds (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Chain_Constraint_Bypasses (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Signature_Algorithm_Agreement (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_X509_Validation (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_X509_Identity (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_X509_Purposes (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_X509_Path_Building (Item : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Check_X509_Verify (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_X509_Verify;
   end Run_Check_X509_Verify;

   procedure Run_Check_Unsupported_Algorithm (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Unsupported_Algorithm;
   end Run_Check_Unsupported_Algorithm;

   procedure Run_Check_Verification_Failure_Kinds (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Verification_Failure_Kinds;
   end Run_Check_Verification_Failure_Kinds;

   procedure Run_Check_Chain_Constraint_Bypasses (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Chain_Constraint_Bypasses;
   end Run_Check_Chain_Constraint_Bypasses;

   procedure Run_Check_Signature_Algorithm_Agreement (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Signature_Algorithm_Agreement;
   end Run_Check_Signature_Algorithm_Agreement;

   procedure Run_Check_X509_Validation (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_X509_Validation;
   end Run_Check_X509_Validation;

   procedure Run_Check_X509_Identity (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_X509_Identity;
   end Run_Check_X509_Identity;

   procedure Run_Check_X509_Purposes (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_X509_Purposes;
   end Run_Check_X509_Purposes;

   procedure Run_Check_X509_Path_Building (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_X509_Path_Building;
   end Run_Check_X509_Path_Building;

   overriding procedure Register_Tests (Item : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (Item, Run_Check_X509_Verify'Access, "x509 verify");
      Register_Routine (Item, Run_Check_Unsupported_Algorithm'Access, "unsupported algorithm");
      Register_Routine (Item, Run_Check_Verification_Failure_Kinds'Access, "verification failure kinds");
      Register_Routine (Item, Run_Check_Chain_Constraint_Bypasses'Access, "chain constraint bypasses");
      Register_Routine (Item, Run_Check_Signature_Algorithm_Agreement'Access, "signature algorithm agreement");
      Register_Routine (Item, Run_Check_X509_Validation'Access, "x509 validation");
      Register_Routine (Item, Run_Check_X509_Identity'Access, "x509 identity");
      Register_Routine (Item, Run_Check_X509_Purposes'Access, "x509 purposes");
      Register_Routine (Item, Run_Check_X509_Path_Building'Access, "x509 path building");
   end Register_Tests;

   overriding function Name (Item : Test_Case) return AUnit.Message_String is
      pragma Unreferenced (Item);
   begin
      return AUnit.Format ("cryptolib X.509 validation");
   end Name;

end Tests_X509_Validation;
