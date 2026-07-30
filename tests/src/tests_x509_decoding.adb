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

package body Tests_X509_Decoding is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Certificates.Certificate_Status;
   use type Interfaces.Unsigned_32;



   --  Decoding a certificate this crate has just issued, end to end: PEM
   --  armour off, DER in, fields out. The CA is P-384 because that exercises
   --  the EC parameter path -- the curve is named beside the algorithm rather
   --  than implied by it, and getting that wrong yields a key of unknown type
   --  rather than a parse failure, which is the quieter mistake.
   procedure Check_X509_Decode is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.PEM.Decode_Status;
      use type CryptoLib.X509.Public_Key_Algorithm;
      use type CryptoLib.X509.Signature_Algorithm;

      package X509C renames CryptoLib.X509.Certificates;

      CA_PEM  : Unbounded_String;
      CA_Key  : Unbounded_String;
      Leaf    : Unbounded_String;
      Leaf_Key : Unbounded_String;
      Outcome : CryptoLib.Certificates.Certificate_Status;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          (Common_Name     => "asn1-decode-test-ca",
           Certificate_PEM => CA_PEM,
           Private_Key_PEM => CA_Key,
           Algorithm       => CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok,
             "fixture: the P-384 CA must be created");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (CA_Certificate_PEM => To_String (CA_PEM),
           CA_Private_Key_PEM => To_String (CA_Key),
           Common_Name        => "leaf.example",
           Names              =>
             [1 => To_Unbounded_String ("leaf.example")],
           Certificate_PEM    => Leaf,
           Private_Key_PEM    => Leaf_Key);
      Check (Outcome = CryptoLib.Certificates.Ok,
             "fixture: the leaf certificate must be issued");

      declare
         Text   : constant String := To_String (CA_PEM);
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Text)));
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Text'First;
         PEM_St : CryptoLib.PEM.Decode_Status;
         Parsed : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         Check (CryptoLib.PEM.Block_Count (Text, CryptoLib.PEM.Certificate_Label) = 1,
                "the CA text holds exactly one certificate block");

         CryptoLib.PEM.Decode_Block
           (Text, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, PEM_St);
         Check (PEM_St = CryptoLib.PEM.Ok,
                "the CA armour decodes: "
                & CryptoLib.PEM.Status_Image (PEM_St));

         declare
            CA : constant X509C.Certificate :=
              X509C.Decode_DER
                (Buffer (Buffer'First .. Last),
                 CryptoLib.ASN1.Default_Limits, Parsed);
         begin
            Check (Parsed = CryptoLib.ASN1.Errors.Ok,
                   "the CA certificate decodes: "
                   & CryptoLib.ASN1.Errors.Status_Image (Parsed));
            Check (X509C.Is_Present (CA), "the decoded CA is present");
            Check (X509C.Version (CA) = 3, "a CA issued here is v3");
            Check (X509C.Subject_Common_Name (CA) = "asn1-decode-test-ca",
                   "the subject common name is the one asked for, got "
                   & X509C.Subject_Common_Name (CA));
            Check (X509C.Is_Self_Issued (CA),
                   "a local CA names itself as issuer");
            Check (X509C.Public_Key_Algorithm_Of (CA)
                     = CryptoLib.X509.ECDSA_P384,
                   "the CA key is recognised as P-384");
            Check (X509C.Signature_Algorithm_Of (CA)
                     = CryptoLib.X509.ECDSA_With_SHA384,
                   "the CA signature algorithm is ecdsa-with-SHA384");
            Check (X509C.Serial_Number (CA)'Length > 0,
                   "the CA carries a serial number");
            Check (CryptoLib.X509.Is_Not_After
                     (X509C.Not_Before (CA), X509C.Not_After (CA)),
                   "the CA's validity window is not inverted");
            Check (X509C.Not_Before (CA).Year >= 2000,
                   "the notBefore year decodes into this century");

            --  basicConstraints is what makes a CA a CA, and it must be
            --  critical for anything to honour it.
            declare
               Index : constant Natural :=
                 X509C.Find_Extension
                   (CA, CryptoLib.ASN1.OIDs.Basic_Constraints);
            begin
               Check (Index > 0, "the CA carries basicConstraints");
               Check (X509C.Extension_Is_Critical (CA, Index),
                      "basicConstraints is critical on a CA");
            end;

            --  The signed bytes must be the ones that were signed: the TBS
            --  span has to sit inside the certificate and start with a
            --  SEQUENCE header.
            declare
               TBS : constant Ada.Streams.Stream_Element_Array :=
                 X509C.TBS_Bytes (CA);
               Whole : constant Ada.Streams.Stream_Element_Array :=
                 X509C.DER_Bytes (CA);
            begin
               Check (TBS'Length > 0 and then TBS'Length < Whole'Length,
                      "the signed bytes are a proper part of the certificate");
               Check (TBS (TBS'First) = 16#30#,
                      "the signed bytes begin at the TBSCertificate header");
               Check (Whole'Length = Last - Buffer'First + 1,
                      "the certificate kept the whole encoding it was given");
            end;
         end;
      end;

      --  The leaf, which must name the CA as issuer rather than itself.
      declare
         Text   : constant String := To_String (Leaf);
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Text)));
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Text'First;
         PEM_St : CryptoLib.PEM.Decode_Status;
         Parsed : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Text, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, PEM_St);
         Check (PEM_St = CryptoLib.PEM.Ok, "the leaf armour decodes");

         declare
            Cert : constant X509C.Certificate :=
              X509C.Decode_DER
                (Buffer (Buffer'First .. Last),
                 CryptoLib.ASN1.Default_Limits, Parsed);
         begin
            Check (Parsed = CryptoLib.ASN1.Errors.Ok,
                   "the leaf certificate decodes: "
                   & CryptoLib.ASN1.Errors.Status_Image (Parsed));
            Check (X509C.Subject_Common_Name (Cert) = "leaf.example",
                   "the leaf subject is the one asked for");
            Check (X509C.Issuer_Common_Name (Cert) = "asn1-decode-test-ca",
                   "the leaf names the CA as its issuer, got "
                   & X509C.Issuer_Common_Name (Cert));
            Check (not X509C.Is_Self_Issued (Cert),
                   "an issued leaf is not self-issued");
            Check (X509C.Find_Extension
                     (Cert, CryptoLib.ASN1.OIDs.Subject_Alternative_Name) > 0,
                   "the leaf carries a subject alternative name");
            Check (X509C.Extension_Count (Cert) > 0,
                   "the leaf carries extensions");
         end;
      end;

      --  PEM armour, refused where it should be.
      declare
         Buffer : Ada.Streams.Stream_Element_Array (1 .. 64);
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive;
         St     : CryptoLib.PEM.Decode_Status;

         Crossed : constant String :=
           "-----BEGIN CERTIFICATE-----" & ASCII.LF & "QUJD" & ASCII.LF
           & "-----END PRIVATE KEY-----" & ASCII.LF;
         Junk : constant String :=
           "-----BEGIN CERTIFICATE-----" & ASCII.LF & "QU!C" & ASCII.LF
           & "-----END CERTIFICATE-----" & ASCII.LF;
         Good : constant String :=
           "-----BEGIN CERTIFICATE-----" & ASCII.LF & "QUJD" & ASCII.LF
           & "-----END CERTIFICATE-----" & ASCII.LF;
         Preamble : constant String :=
           "Alias name: mykey" & ASCII.LF & "Entry type: PrivateKeyEntry"
           & ASCII.LF & Good;
      begin
         From := Crossed'First;
         CryptoLib.PEM.Decode_Block
           (Crossed, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, St);
         Check (St = CryptoLib.PEM.Malformed_Armour,
                "a block closed by a different label is refused");

         From := Junk'First;
         CryptoLib.PEM.Decode_Block
           (Junk, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, St);
         Check (St = CryptoLib.PEM.Invalid_Base64,
                "a character that is not base64 is refused, not skipped");

         From := Good'First;
         CryptoLib.PEM.Decode_Block
           (Good, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, St);
         Check (St = CryptoLib.PEM.Ok
                and then Last = Buffer'First + 2
                and then Buffer (Buffer'First) = Character'Pos ('A'),
                "a well-formed block decodes to its bytes");

         --  The preamble case that broke this once: text before the armour
         --  must not become part of the payload.
         From := Preamble'First;
         CryptoLib.PEM.Decode_Block
           (Preamble, CryptoLib.PEM.Certificate_Label, From, Buffer, Last,
            St);
         Check (St = CryptoLib.PEM.Ok
                and then Last = Buffer'First + 2
                and then Buffer (Buffer'First) = Character'Pos ('A'),
                "text before the armour is not swept into the payload");

         --  Walking a two-block chain.
         declare
            Chain : constant String := Good & Good;
         begin
            Check (CryptoLib.PEM.Block_Count
                     (Chain, CryptoLib.PEM.Certificate_Label) = 2,
                   "two blocks are counted");
            From := Chain'First;
            CryptoLib.PEM.Decode_Block
              (Chain, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, St);
            Check (St = CryptoLib.PEM.Ok, "the first block of a chain decodes");
            CryptoLib.PEM.Decode_Block
              (Chain, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, St);
            Check (St = CryptoLib.PEM.Ok,
                   "the walk reaches the second block");
            CryptoLib.PEM.Decode_Block
              (Chain, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, St);
            Check (St = CryptoLib.PEM.No_Block_Found,
                   "the walk ends after the last block");
         end;
      end;

      --  Trailing bytes after the certificate are not part of what was
      --  signed, so they must not be waved through.
      declare
         Text   : constant String := To_String (CA_PEM);
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Text)) + 1);
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Text'First;
         PEM_St : CryptoLib.PEM.Decode_Status;
         Parsed : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Text, CryptoLib.PEM.Certificate_Label, From,
            Buffer (Buffer'First .. Buffer'Last - 1), Last, PEM_St);
         Check (PEM_St = CryptoLib.PEM.Ok, "fixture: the CA decodes");
         Buffer (Last + 1) := 0;

         declare
            Cert : constant X509C.Certificate :=
              X509C.Decode_DER
                (Buffer (Buffer'First .. Last + 1),
                 CryptoLib.ASN1.Default_Limits, Parsed);
            pragma Unreferenced (Cert);
         begin
            Check (Parsed = CryptoLib.ASN1.Errors.Trailing_Data,
                   "a byte after the certificate is refused, got "
                   & CryptoLib.ASN1.Errors.Status_Image (Parsed));
         end;
      end;
   end Check_X509_Decode;



   --  The extensions that decide what a certificate is for. Every expected
   --  value here was read off "openssl x509 -text" for the same certificate
   --  before being written down.
   --  Where a certificate says to ask about it, and where to fetch its
   --  issuer. Reading these is what makes the revocation machinery reachable:
   --  a caller told that fetching is its own job still needs to be told the
   --  address.
   procedure Check_X509_Access_Locations is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.X509.Extensions.Access_Method;
      use type CryptoLib.X509.Extensions.General_Name_Kind;

      package X509C renames CryptoLib.X509.Certificates;
      package XE renames CryptoLib.X509.Extensions;

      Rich_Locations_DER : constant String :=
        "308202653082020ba003020102021442a799cc9ee44693e58977316c17422710dee46a300a06082a8648ce3d04" &
        "030230123110300e06035504030c077375626a656374301e170d3236303732383232323732345a170d32363038" &
        "32373232323732345a30123110300e06035504030c077375626a6563743059301306072a8648ce3d020106082a" &
        "8648ce3d0301070342000485a12a9ae8f287719fb228ab6c3e7382797ae9f619dd81191c057c95fe5657fed0e7" &
        "077ec57d20367034ca121396308c33f8f2caf86aa74d628dcfe8d675d097a382013d3082013930819906082b06" &
        "01050507010104818c308189302106082b060105050730018615687474703a2f2f6f6373702e6578616d706c65" &
        "2f61302306082b060105050730028617687474703a2f2f63612e6578616d706c652f692e637274301c06082b06" &
        "01050507300181106f637370406578616d706c652e636f6d302106082b060105050730018615687474703a2f2f" &
        "6f6373702e6578616d706c652f62307c0603551d1f047530733038a036a0348618687474703a2f2f63726c2e65" &
        "78616d706c652f312e63726c8618687474703a2f2f63726c2e6578616d706c652f322e63726c3037a035a033a4" &
        "1730153113301106035504030c0a63726c206973737565728618687474703a2f2f63726c2e6578616d706c652f" &
        "332e63726c301d0603551d0e04160414fd1d94e663fdd9c8c5cc77056ed51f11a34760fb300a06082a8648ce3d" &
        "0403020348003045022100a74db3351d4d7b5243fb3ee98f32c304e2103f79909ac3ae30db26bd9390c7480220" &
        "3094ade938c48216df9851f5ebe6c419a4004b02f85c5b1bec00c40bf61dc9aa";

      Relative_CRL_DER : constant String :=
        "3082016c30820113a00302010202141d7d7ae17d3708b8e11237cd63c957816560baa6300a06082a8648ce3d04" &
        "030230123110300e06035504030c077375626a656374301e170d3236303732383232323631335a170d32363038" &
        "32373232323631335a30123110300e06035504030c077375626a6563743059301306072a8648ce3d020106082a" &
        "8648ce3d0301070342000485a12a9ae8f287719fb228ab6c3e7382797ae9f619dd81191c057c95fe5657fed0e7" &
        "077ec57d20367034ca121396308c33f8f2caf86aa74d628dcfe8d675d097a347304530240603551d1f041d301b" &
        "3019a017a115301306035504030c0c72656c61746976652063726c301d0603551d0e04160414fd1d94e663fdd9" &
        "c8c5cc77056ed51f11a34760fb300a06082a8648ce3d0403020347003044022066e115503346fdced94320de48" &
        "193b36846f5be7bc4a42366ff1ada0c2324afe02205bf99505389f545214dca1452037398df88d4ce833fa7cbb" &
        "1ddd7fcea157428c";

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
      Rich   : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (Rich_Locations_DER), CryptoLib.ASN1.Default_Limits,
           Status);
   begin
      Check (Status = CryptoLib.ASN1.Errors.Ok,
             "a certificate naming responders and CRLs decodes");

      --  Four access descriptions, reported in the order the certificate
      --  gives them. Order is not decoration: it is the issuer's preference,
      --  and a caller working down the list is following it.
      Check (XE.Authority_Info_Count (Rich) = 4,
             "every access description is counted");
      Check (XE.Authority_Info_Method (Rich, 1) = XE.OCSP_Responder
             and then XE.Authority_Info_URI (Rich, 1)
                      = "http://ocsp.example/a",
             "the first entry is a responder");
      Check (XE.Authority_Info_Method (Rich, 2) = XE.CA_Issuers
             and then XE.Authority_Info_URI (Rich, 2)
                      = "http://ca.example/i.crt",
             "the second is where to fetch the issuer");
      Check (XE.Authority_Info_Method (Rich, 4) = XE.OCSP_Responder
             and then XE.Authority_Info_URI (Rich, 4)
                      = "http://ocsp.example/b",
             "the fourth is a second responder");

      --  The third entry names a responder by mail address rather than URI.
      --  It is still counted and its kind still reported: dropping it would
      --  renumber everything after it, and a caller indexing the list would
      --  quietly read the wrong entry.
      Check (XE.Authority_Info_Method (Rich, 3) = XE.OCSP_Responder,
             "a non-URI location keeps its place in the list");
      Check (XE.Authority_Info_Kind (Rich, 3) = XE.Email_Address,
             "and its kind is reported rather than guessed");
      Check (XE.Authority_Info_URI (Rich, 3) = "",
             "and it yields no URI, since it is not one");

      Check (XE.OCSP_Responder_URI (Rich) = "http://ocsp.example/a",
             "the first responder URI is the one to ask");
      Check (XE.CA_Issuers_URI (Rich) = "http://ca.example/i.crt",
             "and the issuer is fetched from the first caIssuers URI");

      --  Four names across two distribution points -- three URIs and a
      --  directory name -- flattened: a caller wants the places a CRL can be
      --  fetched from, and which distribution point each came from does not
      --  change where to go.
      Check (XE.CRL_Distribution_Point_Count (Rich) = 4,
             "names from every distribution point are counted");
      Check (XE.CRL_Distribution_Point_URI (Rich, 1)
             = "http://crl.example/1.crl"
             and then XE.CRL_Distribution_Point_URI (Rich, 2)
                      = "http://crl.example/2.crl",
             "both names of the first distribution point are reached");
      Check (XE.CRL_Distribution_Point_Kind (Rich, 3) = XE.Directory_Name,
             "a directory name is reported as one");
      Check (XE.CRL_Distribution_Point_URI (Rich, 4)
             = "http://crl.example/3.crl",
             "and the URI beside it is still reached");

      --  A distribution point named relative to the CRL issuer is a fragment
      --  of a name, not a place. Reporting it as a location would hand a
      --  caller something it cannot fetch from.
      declare
         Relative : constant X509C.Certificate :=
           X509C.Decode_DER
             (From_Hex (Relative_CRL_DER), CryptoLib.ASN1.Default_Limits,
              Status);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok,
                "a relative distribution point decodes");
         Check (XE.CRL_Distribution_Point_Count (Relative) = 0,
                "a distribution point relative to the CRL issuer names no "
                & "place to fetch from");

         --  Absent is not empty-and-present: a certificate naming nothing
         --  must not read as one naming something unreachable.
         Check (XE.Authority_Info_Count (Relative) = 0,
                "a certificate with no access descriptions reports none");
         Check (XE.OCSP_Responder_URI (Relative) = "",
                "and names no responder");
      end;
   end Check_X509_Access_Locations;


   --  An extension that appears twice, and extensions on a certificate whose
   --  version does not admit them. Both are ways of writing a certificate
   --  that means one thing to one reader and something else to another,
   --  which is worth refusing outright: whichever instance this happened to
   --  take, some other implementation takes the other, and the two disagree
   --  about what the issuer authorised.
   procedure Check_Certificate_Ambiguity is
      use type CryptoLib.ASN1.Errors.Decode_Status;

      package X509C renames CryptoLib.X509.Certificates;
      package XE renames CryptoLib.X509.Extensions;

      Honest_V3_DER : constant String :=
        "308203253082020da00302010202023000300d06092a864886f70d01010b050030163114301206035504030c0b" &
        "63726c2d746573742d6361301e170d3236303732393031313432365a170d3237303732393031313432365a301a" &
        "3118301606035504030c0f7265766f6b65642e6578616d706c6530820122300d06092a864886f70d0101010500" &
        "0382010f003082010a0282010100c0ed219d3150260bb4a5a976fd93941636a1dcdc8976321a5c82e468c74ff7" &
        "e755f29a6940524606cf7e70308e8c3ed01c6954e7e7a45fdedd1d914b6cf2459cbba0b0a2f3a248771f69301a" &
        "c2735a408af830e03b7c3941648de0810c102c79f17da1d486a3b676993fd30102ed86ee4d4cde770d3abf8dd4" &
        "b178885132f79e8799c63595af16af350d94207d96a5d830c19e2eff9edb43607e7c8e5ba3e737b82f71937a7c" &
        "a59ffcac9dfc633aa69ce1e08aabf84a068c4e1dfa9f7ca28f959062408140c1c8cf63d66761609bc2dff8b3d4" &
        "bd3250ee0a86b507023e9f9aee80b2184c01758ffaf3c280eeeff0fb0926de9c83cfc2f327c4dcd6254a044715" &
        "0203010001a3793077300c0603551d130101ff04023000300e0603551d0f0101ff0404030205a030170603551d" &
        "110410300e820c686f73742e6578616d706c65301d0603551d0e04160414b2300eeca1b7034732dc8f88bc8292" &
        "ab5ecbe8fe301f0603551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300d06092a8648" &
        "86f70d01010b0500038201010032fbc37897b1aded84fd07e03393dbd35ab45ba2149704757853447c7c82dc2f" &
        "1e5a5cf0fca4a9b513e7014f240a1acf63ec11514a61fa82d801339d754fcf60049cda3f618b215aa8c0bbd547" &
        "4fae1fcb1d7a60853962fc7a99af186be8f9eab7c4dfedac2824545d94eca8f716bb2e7a99145172c8f626b0d8" &
        "8e50bfa8083c833abe24a060379ae0bae5478e728d9bf302ff18540b24443ad055ce624d7c3de8526df13a6bc4" &
        "b727e57e0f2cb2ee3cafa62b177b7272e0b8bcc327441e5fc27acd6bf5a57df5ac9cb24025efb811d7520b94d2" &
        "0ecf1d6d96a26f7d1312e1c4e9389c35ff6bdce8ee602ed60cce5f9a7ddbb20fa4a1d073d217a282782a40de";

      Duplicate_Extension_DER : constant String :=
        "308203433082022ba00302010202023000300d06092a864886f70d01010b050030163114301206035504030c0b" &
        "63726c2d746573742d6361301e170d3236303732393031313432365a170d3237303732393031313432365a301a" &
        "3118301606035504030c0f7265766f6b65642e6578616d706c6530820122300d06092a864886f70d0101010500" &
        "0382010f003082010a0282010100c0ed219d3150260bb4a5a976fd93941636a1dcdc8976321a5c82e468c74ff7" &
        "e755f29a6940524606cf7e70308e8c3ed01c6954e7e7a45fdedd1d914b6cf2459cbba0b0a2f3a248771f69301a" &
        "c2735a408af830e03b7c3941648de0810c102c79f17da1d486a3b676993fd30102ed86ee4d4cde770d3abf8dd4" &
        "b178885132f79e8799c63595af16af350d94207d96a5d830c19e2eff9edb43607e7c8e5ba3e737b82f71937a7c" &
        "a59ffcac9dfc633aa69ce1e08aabf84a068c4e1dfa9f7ca28f959062408140c1c8cf63d66761609bc2dff8b3d4" &
        "bd3250ee0a86b507023e9f9aee80b2184c01758ffaf3c280eeeff0fb0926de9c83cfc2f327c4dcd6254a044715" &
        "0203010001a38196308193300f0603551d130101ff040530030101ff30090603551d1304023000300c0603551d" &
        "130101ff04023000300e0603551d0f0101ff0404030205a030170603551d110410300e820c686f73742e657861" &
        "6d706c65301d0603551d0e04160414b2300eeca1b7034732dc8f88bc8292ab5ecbe8fe301f0603551d23041830" &
        "168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300d06092a864886f70d01010b0500038201010007da" &
        "c8456835599f6b84eb8f88ad5eacc9bea0568a5f832288edab6454b5f06a5083f7bd83789d554dc33e44e9b8eb" &
        "f07d199b9e1a9980e900f490a1726e0cb6891e8413012e64193f90f1de7383e0442be007a0d38a8322701a5281" &
        "6abe62869d7d117b961b005a2752d592eeb4e0486ae4065038d05792501c3d1e24bf081522e0af4bf0986aac51" &
        "dc915ba204f188d4d5f124a32c5823bff6d671c07b2f2df9cd4728b136c11aed8a110d8ed37297d50fb4c13f8c" &
        "04625622168659e00a7b39ad192f4eccfe9c031dd1da51968543c6bce1d0d2850a40072f66040452bae65aa06b" &
        "d363111be7d43e77c292e762910985d6fc3bd65dba43bb5d54cfc38c81";

      V1_With_Extensions_DER : constant String :=
        "308203203082020802023000300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d74" &
        "6573742d6361301e170d3236303732393031313432365a170d3237303732393031313432365a301a3118301606" &
        "035504030c0f7265766f6b65642e6578616d706c6530820122300d06092a864886f70d01010105000382010f00" &
        "3082010a0282010100c0ed219d3150260bb4a5a976fd93941636a1dcdc8976321a5c82e468c74ff7e755f29a69" &
        "40524606cf7e70308e8c3ed01c6954e7e7a45fdedd1d914b6cf2459cbba0b0a2f3a248771f69301ac2735a408a" &
        "f830e03b7c3941648de0810c102c79f17da1d486a3b676993fd30102ed86ee4d4cde770d3abf8dd4b178885132" &
        "f79e8799c63595af16af350d94207d96a5d830c19e2eff9edb43607e7c8e5ba3e737b82f71937a7ca59ffcac9d" &
        "fc633aa69ce1e08aabf84a068c4e1dfa9f7ca28f959062408140c1c8cf63d66761609bc2dff8b3d4bd3250ee0a" &
        "86b507023e9f9aee80b2184c01758ffaf3c280eeeff0fb0926de9c83cfc2f327c4dcd6254a0447150203010001" &
        "a3793077300c0603551d130101ff04023000300e0603551d0f0101ff0404030205a030170603551d110410300e" &
        "820c686f73742e6578616d706c65301d0603551d0e04160414b2300eeca1b7034732dc8f88bc8292ab5ecbe8fe" &
        "301f0603551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300d06092a864886f70d0101" &
        "0b050003820101004a659bb771d37116b98b3991540d1a1bc392137fcfb077420fb43b414b0db9f3404a29d98c" &
        "94bc9b74c34f37b68486dcb533d263fe52b2129fc5874f2269f86b73b3deb0580aec94172626aad4a6906bca5d" &
        "5b28d350a62597ac9958dc34d0228800b4016423cabd05a264c5e2dd7601183daf8f4135cbfd01314579a3b6bc" &
        "5c1db235debec26f05edc536ca0aca626374ccd53b443ee9ab1e7e8ef627f59867c5d85533bd0a0e6958b61d02" &
        "3405f393c510ec66bb744f8b3a2f8db42b779b1f0c47fc9cbcf91b1f2392057848f152967817d96afc45d11a1d" &
        "1655f418563d3b91466b825335c56ac1b1d755240fe6b50a0eee3c28f0dc7f62aa548200ded705";

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
   begin
      --  The certificate the other two are built from: an ordinary v3 leaf
      --  that is not a CA. This must keep working, or the check below is
      --  refusing certificates rather than ambiguity.
      declare
         Honest : constant X509C.Certificate :=
           X509C.Decode_DER
             (From_Hex (Honest_V3_DER), CryptoLib.ASN1.Default_Limits,
              Status);
         Limits : constant XE.Basic_Constraints :=
           XE.Get_Basic_Constraints (Honest);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok
                and then X509C.Is_Present (Honest),
                "an ordinary v3 certificate decodes");
         Check (Limits.Present and then not Limits.Is_CA,
                "and is not a CA");
      end;

      --  The same certificate with basicConstraints CA:TRUE inserted before
      --  the CA:FALSE it already carried, and re-signed so the signature
      --  holds. Taking the first instance makes it a CA; taking the last
      --  makes it a leaf. OpenSSL refuses to load it at all.
      declare
         Doubled : constant X509C.Certificate :=
           X509C.Decode_DER
             (From_Hex (Duplicate_Extension_DER),
              CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (Status /= CryptoLib.ASN1.Errors.Ok,
                "a certificate carrying an extension twice is refused, got "
                & CryptoLib.ASN1.Errors.Status_Image (Status));
         Check (not X509C.Is_Present (Doubled),
                "and nothing is decoded from it");
      end;

      --  Extensions on a v1 certificate: some parsers read them, some
      --  ignore them, which is the same disagreement reached another way.
      declare
         Old : constant X509C.Certificate :=
           X509C.Decode_DER
             (From_Hex (V1_With_Extensions_DER),
              CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (Status /= CryptoLib.ASN1.Errors.Ok,
                "extensions on a v1 certificate are refused, got "
                & CryptoLib.ASN1.Errors.Status_Image (Status));
         Check (not X509C.Is_Present (Old),
                "and nothing is decoded from it either");
      end;
   end Check_Certificate_Ambiguity;


   --  A serial number names a certificate. A revocation names a certificate
   --  by issuer and serial and by nothing else, so two certificates from one
   --  CA sharing a serial cannot be revoked apart: revoking either revokes
   --  both, and there is no way to revoke just one. These used to be
   --  hardcoded, so every server certificate this crate issued carried the
   --  same one.
   procedure Check_Serial_Numbers is
      use type CryptoLib.ASN1.Errors.Decode_Status;

      package X509C renames CryptoLib.X509.Certificates;

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
         return X509C.Decode_DER
           (Buffer (Buffer'First .. Last), CryptoLib.ASN1.Default_Limits, D);
      end Decoded;

      CA_PEM, CA_Key   : Unbounded_String;
      A_PEM, A_Key     : Unbounded_String;
      B_PEM, B_Key     : Unbounded_String;
      Outcome          : CryptoLib.Certificates.Certificate_Status;

      --  Enough that a collision is not a thing that happens, and enough to
      --  put the value out of reach of anyone wanting to predict it.
      Minimum_Octets : constant := 8;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("serial-ca", CA_PEM, CA_Key, CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "alpha.example",
           [1 => To_Unbounded_String ("alpha.example")], A_PEM, A_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: alpha issued");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "beta.example",
           [1 => To_Unbounded_String ("beta.example")], B_PEM, B_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: beta issued");

      declare
         CA    : constant X509C.Certificate := Decoded (To_String (CA_PEM));
         Alpha : constant X509C.Certificate := Decoded (To_String (A_PEM));
         Beta  : constant X509C.Certificate := Decoded (To_String (B_PEM));

         SA : constant Ada.Streams.Stream_Element_Array :=
           X509C.Serial_Number (Alpha);
         SB : constant Ada.Streams.Stream_Element_Array :=
           X509C.Serial_Number (Beta);
         SC : constant Ada.Streams.Stream_Element_Array :=
           X509C.Serial_Number (CA);
      begin
         Check (X509C.Is_Present (Alpha) and then X509C.Is_Present (Beta),
                "fixture: both certificates decode");

         --  The property that matters.
         Check (SA /= SB,
                "two certificates from one CA get different serials");
         Check (SA /= SC and then SB /= SC,
                "and neither collides with the CA's own");

         Check (SA'Length >= Minimum_Octets and then SB'Length >= Minimum_Octets,
                "a serial carries real width, got"
                & Ada.Streams.Stream_Element_Offset'Image (SA'Length)
                & " octets");

         --  RFC 5280 requires a positive serial. The encoding is the content
         --  octets of an INTEGER, so a leading octet at or above 16#80#
         --  would make it negative, and a leading zero would mean the
         --  encoder padded one that was.
         Check (SA (SA'First) < 16#80# and then SB (SB'First) < 16#80#,
                "a serial is positive");
         Check (SA (SA'First) /= 0 and then SB (SB'First) /= 0,
                "and minimally encoded, with no padding octet");
      end;
   end Check_Serial_Numbers;


   --  A certificate is valid from when it was issued, for as long as the
   --  caller asked. The window used to be two literals in the source, so
   --  every certificate ever issued claimed the same decade and issuing
   --  would have started producing already-expired certificates once it ran
   --  out.
   procedure Check_Validity_Window is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.X509.Certificate_Time;

      package X509C renames CryptoLib.X509.Certificates;

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
         return X509C.Decode_DER
           (Buffer (Buffer'First .. Last), CryptoLib.ASN1.Default_Limits, D);
      end Decoded;

      CA_PEM, CA_Key, Short_PEM, Short_Key, Long_PEM, Long_Key :
        Unbounded_String;
      Outcome : CryptoLib.Certificates.Certificate_Status;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("validity-ca", CA_PEM, CA_Key, CryptoLib.Certificates.P384_Key,
           --  Longer than the certificates issued under it, because a leaf
           --  is now held to its issuer's expiry: a CA of the default life
           --  would clamp the long one below 2049 and this would be testing
           --  the clamp rather than the encoding.
           Valid_Days => 12_000);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "short.example",
           [1 => To_Unbounded_String ("short.example")], Short_PEM, Short_Key,
           Valid_Days => 1);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: short issued");

      --  Long enough that notAfter lands past 2049, where UTCTime stops
      --  being unambiguous and the encoding has to change.
      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "long.example",
           [1 => To_Unbounded_String ("long.example")], Long_PEM, Long_Key,
           Valid_Days => 10_000);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: long issued");

      declare
         Short : constant X509C.Certificate := Decoded (To_String (Short_PEM));
         Long  : constant X509C.Certificate := Decoded (To_String (Long_PEM));
      begin
         Check (X509C.Is_Present (Short) and then X509C.Is_Present (Long),
                "both certificates decode");

         --  The lifetime the caller asked for is the lifetime it got: a
         --  one-day certificate and a 10,000-day one cannot share a notAfter.
         Check (X509C.Not_After (Short) /= X509C.Not_After (Long),
                "the requested lifetime decides the expiry");
         Check (CryptoLib.X509.Is_Not_After
                  (X509C.Not_After (Short), X509C.Not_After (Long)),
                "and a shorter one expires first");

         --  Valid at the moment of issue, which a fixed window stops being.
         Check (CryptoLib.X509.Is_Not_After
                  (X509C.Not_Before (Short), X509C.Not_After (Short)),
                "the window is not inverted");
         Check (X509C.Not_Before (Short).Year >= 2026,
                "and starts no earlier than this crate was written, got"
                & Natural'Image (X509C.Not_Before (Short).Year));

         --  Past 2049 a two-digit year stops being unambiguous, so the
         --  encoding has to switch. Reading it back at all proves it did:
         --  a UTCTime carrying "53" would decode as 1953.
         Check (X509C.Not_After (Long).Year > 2049,
                "a long-lived certificate expires past 2049, got"
                & Natural'Image (X509C.Not_After (Long).Year));
         Check (CryptoLib.X509.Is_Not_After
                  (X509C.Not_Before (Long), X509C.Not_After (Long)),
                "and its window is still the right way round, which a "
                & "two-digit year would not have been");
      end;
   end Check_Validity_Window;


   --  A certificate says which key it belongs to and which key signed it.
   --
   --  RFC 5280 requires both -- subjectKeyIdentifier in every CA
   --  certificate, authorityKeyIdentifier in everything but a self-signed
   --  root -- because a name alone stops identifying a certificate as soon
   --  as a CA has more than one. After a re-key, or under a cross-signature,
   --  several certificates share a subject name and differ only by key. The
   --  crate issued neither.
   procedure Check_Key_Identifiers is
      use type CryptoLib.ASN1.Errors.Decode_Status;

      package X509C renames CryptoLib.X509.Certificates;
      package XE renames CryptoLib.X509.Extensions;

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
         return X509C.Decode_DER
           (Buffer (Buffer'First .. Last), CryptoLib.ASN1.Default_Limits, D);
      end Decoded;

      CA_PEM, CA_Key, Leaf_PEM, Leaf_Key : Unbounded_String;
      Outcome : CryptoLib.Certificates.Certificate_Status;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("identifier-ca", CA_PEM, CA_Key, CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "host.example",
           [1 => To_Unbounded_String ("host.example")], Leaf_PEM, Leaf_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: leaf issued");

      declare
         CA   : constant X509C.Certificate := Decoded (To_String (CA_PEM));
         Leaf : constant X509C.Certificate := Decoded (To_String (Leaf_PEM));

         CA_SKI   : constant CryptoLib.ASN1.Octets :=
           XE.Subject_Key_Identifier (CA);
         Leaf_SKI : constant CryptoLib.ASN1.Octets :=
           XE.Subject_Key_Identifier (Leaf);
         Leaf_AKI : constant CryptoLib.ASN1.Octets :=
           XE.Authority_Key_Identifier (Leaf);
         CA_AKI   : constant CryptoLib.ASN1.Octets :=
           XE.Authority_Key_Identifier (CA);
      begin
         Check (X509C.Is_Present (CA) and then X509C.Is_Present (Leaf),
                "both certificates decode");

         --  SHA-1 over the public key bits, which is the derivation 38 of
         --  the 40 system roots carrying one were measured to use.
         Check (CA_SKI'Length = 20 and then Leaf_SKI'Length = 20,
                "each certificate names its own key");
         Check (CA_SKI /= Leaf_SKI,
                "and two different keys get different identifiers");

         --  The link that makes the pair useful: the leaf points at the key
         --  that signed it, which is the CA's own.
         Check (Leaf_AKI = CA_SKI,
                "the leaf names the key that signed it");

         --  A self-signed CA signed itself, so it points at itself.
         Check (CA_AKI = CA_SKI,
                "and a self-signed CA points at its own key");
      end;
   end Check_Key_Identifiers;


   --  A certificate longer than 65_535 octets.
   --
   --  The DER length encoder stopped at a two-octet long form, and Byte
   --  truncates rather than complains, so anything larger was given a length
   --  with its high bits dropped. Issuance reported Ok and produced a
   --  certificate no parser could read -- OpenSSL refused it outright. A
   --  subject alternative name list is unbounded, so a caller with enough
   --  names reaches this with no indication that anything went wrong.
   --
   --  Decoding is the whole check: the reader refuses trailing data, so a
   --  certificate whose outer length is short by any amount cannot decode.
   procedure Check_Large_Certificate is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.PEM.Decode_Status;

      package X509C renames CryptoLib.X509.Certificates;

      --  Long names rather than many, because the reader bounds a sequence
      --  at 1024 items and the point here is the byte count, not the count.
      Count : constant := 1000;

      function Long_Name (Index : Positive) return Unbounded_String is
         Number : constant String := Positive'Image (Index);
      begin
         return To_Unbounded_String
           ("h" & Number (Number'First + 1 .. Number'Last) & "."
            & [1 .. 60 => 'a'] & ".example");
      end Long_Name;

      CA_PEM, CA_Key, Leaf_PEM, Leaf_Key : Unbounded_String;
      Names   : CryptoLib.Certificates.Subject_Alternative_Name_List
        (1 .. Count);
      Outcome : CryptoLib.Certificates.Certificate_Status;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("large-ca", CA_PEM, CA_Key, CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      for I in Names'Range loop
         Names (I) := Long_Name (I);
      end loop;

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "large.example", Names,
           Leaf_PEM, Leaf_Key);
      Check (Outcome = CryptoLib.Certificates.Ok,
             "a certificate with a great many names is issued");

      declare
         Text   : constant String := To_String (Leaf_PEM);
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Text)));
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Text'First;
         P      : CryptoLib.PEM.Decode_Status;
         Status : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Text, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, P);
         Check (P = CryptoLib.PEM.Ok, "its armour decodes");

         --  Past the two-octet long form, which is the case that was wrong.
         Check (Last > 65_535,
                "and it really is larger than a two-octet length can hold,"
                & Ada.Streams.Stream_Element_Offset'Image (Last)
                & " octets");

         --  Read back under limits that admit a certificate this size. The
         --  default caps a single string at 64 KB, which is a deliberate
         --  bound on what a caller is willing to decode rather than
         --  anything about the encoding -- and it is why the default limits
         --  will not read a certificate this crate can now write. What is
         --  under test is the length octets, so the bound is lifted here and
         --  left alone everywhere else.
         declare
            Roomy : constant CryptoLib.ASN1.Decode_Limits :=
              (Maximum_Input_Size     => 1024 * 1024,
               Maximum_Nesting_Depth  => 16,
               Maximum_Sequence_Items => 2048,
               Maximum_String_Length  => 1024 * 1024);
            Item  : constant X509C.Certificate :=
              X509C.Decode_DER
                (Buffer (Buffer'First .. Last), Roomy, Status);
         begin
            Check (Status = CryptoLib.ASN1.Errors.Ok
                   and then X509C.Is_Present (Item),
                   "and it decodes, got "
                   & CryptoLib.ASN1.Errors.Status_Image (Status));

            --  The reader refuses trailing data, so decoding at all proves
            --  the outer length octets named the whole certificate. Under
            --  the old encoder this came back short and the remainder read
            --  as trailing rubbish.
            Check (X509C.Extension_Count (Item) >= 4,
                   "with its extensions intact");
         end;
      end;
   end Check_Large_Certificate;


   --  A certificate whose serial number is absurd.
   --
   --  Nothing bounds a serial on the way in, and a CertID carries it, so the
   --  OCSP request builder is handed whatever the certificate says. Its
   --  length emitter stopped at a two-octet long form and converted the
   --  third octet to a Stream_Element rather than masking it, so a length
   --  past 65_535 raised CONSTRAINT_ERROR -- an exception escaping on input
   --  from whoever supplied the certificate.
   procedure Check_Oversized_Serial is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.PEM.Decode_Status;

      package X509C renames CryptoLib.X509.Certificates;
      package CO renames CryptoLib.OCSP;
      subtype Blob is Ada.Streams.Stream_Element_Array;
      subtype Spot is Ada.Streams.Stream_Element_Offset;

      --  Either side of every boundary where the DER length form changes:
      --  short form, one octet, two, three. Each fix in this area was found
      --  by tripping over one value; this walks all of them.
      type Size_List is array (Positive range <>) of Natural;
      Sizes : constant Size_List :=
        [126, 127, 128, 254, 255, 256, 65_534, 65_535, 65_536, 70_000];

      --  Minimal DER length octets, so the spliced certificate is one the
      --  reader will accept: it refuses a length written wider than it needs.
      function Length_Octets (Value : Natural) return Blob is
         Wide  : Blob (1 .. 4);
         First : Spot := 4;
         Rest  : Natural := Value;
      begin
         if Value < 128 then
            return [1 => Ada.Streams.Stream_Element (Value)];
         end if;
         Wide (First) := Ada.Streams.Stream_Element (Rest mod 256);
         Rest := Rest / 256;
         while Rest > 0 loop
            First := First - 1;
            Wide (First) := Ada.Streams.Stream_Element (Rest mod 256);
            Rest := Rest / 256;
         end loop;
         return [1 => Ada.Streams.Stream_Element (16#80# + (5 - First))]
                & Wide (First .. 4);
      end Length_Octets;

      function Wrap (Tag : Ada.Streams.Stream_Element; Content : Blob)
        return Blob
      is ([1 => Tag] & Length_Octets (Natural (Content'Length)) & Content);

      CA_PEM, CA_Key : Unbounded_String;
      Outcome : CryptoLib.Certificates.Certificate_Status;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("serial-size-ca", CA_PEM, CA_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      declare
         Text   : constant String := To_String (CA_PEM);
         Buffer : Blob
           (1 .. Spot (CryptoLib.PEM.Maximum_Decoded_Length (Text)));
         Last   : Spot;
         From   : Positive := Text'First;
         P      : CryptoLib.PEM.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Text, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, P);

         declare
            Real : constant Blob := Buffer (Buffer'First .. Last);

            --  Both headers are 30 82 LL LL at this size. Asserted rather
            --  than assumed: a splice onto a shape that moved would quietly
            --  produce something else and test nothing.
            Header_Ok : constant Boolean :=
              Real'Length > 8
              and then Real (Real'First) = 16#30#
              and then Real (Real'First + 1) = 16#82#
              and then Real (Real'First + 4) = 16#30#
              and then Real (Real'First + 5) = 16#82#;

            TBS_Body : constant Blob :=
              Real (Real'First + 8
                    .. Real'First + 7
                       + Spot (Natural (Real (Real'First + 6)) * 256
                               + Natural (Real (Real'First + 7))));
            Trailer  : constant Blob :=
              Real (TBS_Body'Last + 1 .. Real'Last);

            Version_Length : constant Spot :=
              2 + Spot (Real (Real'First + 9));
            Before_Serial : constant Blob :=
              TBS_Body (TBS_Body'First
                        .. TBS_Body'First + Version_Length - 1);
            After_Serial  : constant Blob :=
              TBS_Body (TBS_Body'First + Version_Length + 2
                        + Spot (Real (Real'First + 8 + Version_Length + 1))
                        .. TBS_Body'Last);

            Roomy : constant CryptoLib.ASN1.Decode_Limits :=
              (Maximum_Input_Size     => 1024 * 1024,
               Maximum_Nesting_Depth  => 16,
               Maximum_Sequence_Items => 2048,
               Maximum_String_Length  => 1024 * 1024);
         begin
            Check (P = CryptoLib.PEM.Ok and then Header_Ok,
                   "fixture: the certificate has the shape this splices");

            for Size of Sizes loop
               declare
                  Big_Serial : constant Blob :=
                    Wrap (16#02#,
                          [1 => 16#01#]
                          & [1 .. Spot (Size) => 16#42#]);
                  Spliced : constant Blob :=
                    Wrap (16#30#,
                          Wrap (16#30#,
                                Before_Serial & Big_Serial & After_Serial)
                          & Trailer);
                  Status : CryptoLib.ASN1.Errors.Decode_Status;
                  Item   : constant X509C.Certificate :=
                    X509C.Decode_DER (Spliced, Roomy, Status);

                  Out_Buffer : Blob (1 .. 128 * 1024);
                  Stop  : Spot;
                  Built : CryptoLib.ASN1.Errors.Decode_Status;
               begin
                  --  If this stopped decoding, the builder would never be
                  --  reached and everything below would pass while testing
                  --  nothing.
                  Check (Status = CryptoLib.ASN1.Errors.Ok
                         and then X509C.Is_Present (Item),
                         "a certificate with a" & Natural'Image (Size)
                         & "-octet serial decodes, got "
                         & CryptoLib.ASN1.Errors.Status_Image (Status));

                  CO.Build_Request
                    (Item, Item, Out_Buffer, Stop, Built);
                  Check (Built = CryptoLib.ASN1.Errors.Ok,
                         "and a request is built for it, got "
                         & CryptoLib.ASN1.Errors.Status_Image (Built));

                  --  The length octets have to name the rest of the request
                  --  exactly. This is what each of the three encoder faults
                  --  got wrong, in three different ways, at three different
                  --  sizes.
                  declare
                     Header : Natural := 2;
                     Stated : Natural := 0;
                     Count  : Natural;
                  begin
                     if Natural (Out_Buffer (2)) < 128 then
                        Stated := Natural (Out_Buffer (2));
                     else
                        Count := Natural (Out_Buffer (2)) - 128;
                        Header := 2 + Count;
                        for I in 1 .. Count loop
                           Stated :=
                             Stated * 256
                             + Natural (Out_Buffer (Spot (2 + I)));
                        end loop;
                     end if;

                     Check (Header + Stated = Natural (Stop),
                            "and its outer length names the whole request:"
                            & Natural'Image (Header + Stated) & " vs"
                            & Spot'Image (Stop));
                  end;
               end;
            end loop;
         end;
      end;
   end Check_Oversized_Serial;


   --  One comparison for a serial number, shared by both revocation paths.
   --
   --  A serial reaches a revocation check from two directions -- the
   --  certificate, and whatever a CA or a responder wrote about it -- and
   --  those are written by different implementations. The CRL path compared
   --  them as numbers and the OCSP path compared the octets, so the two
   --  could disagree about whether an answer was even about this
   --  certificate.
   --
   --  Leniency is the safe direction here, which is why the numeric reading
   --  is the one kept. A padded encoding read as a different certificate
   --  means an answer about this one is not found, and not finding a
   --  revocation looks exactly like not being revoked -- silently, and
   --  pointing the wrong way. Reading two different serials as the same
   --  number is not something this can do.
   procedure Check_Serial_Comparison is
      function S (Data : Ada.Streams.Stream_Element_Array)
        return Ada.Streams.Stream_Element_Array is (Data);

      Nothing : constant Ada.Streams.Stream_Element_Array (1 .. 0) :=
        [others => 0];
   begin
      Check (CryptoLib.X509.Same_Serial (S ([16#01#]), S ([16#00#, 16#01#])),
             "a padded serial is the same number as the bare one");
      Check (CryptoLib.X509.Same_Serial
               (S ([16#00#, 16#00#, 16#FF#]), S ([16#FF#])),
             "however many zeros it was padded with");
      Check (CryptoLib.X509.Same_Serial (S ([16#12#, 16#34#]),
                                         S ([16#12#, 16#34#])),
             "and an unpadded pair still matches itself");

      Check (not CryptoLib.X509.Same_Serial (S ([16#01#]), S ([16#02#])),
             "two different serials do not match");
      Check (not CryptoLib.X509.Same_Serial
                   (S ([16#01#]), S ([16#01#, 16#01#])),
             "nor do two whose values differ by a trailing octet");

      --  RFC 5280 requires a positive serial, so zero is not one. Matching
      --  it against another zero would make every unparsed serial agree
      --  with every other.
      Check (not CryptoLib.X509.Same_Serial (S ([16#00#]), S ([16#00#])),
             "a zero serial matches nothing, itself included");
      Check (not CryptoLib.X509.Same_Serial (Nothing, S ([16#01#])),
             "and an empty one is not a number at all");
   end Check_Serial_Comparison;


   --  A certificate must not outlive the one that signed it.
   --
   --  Issuing asked only how long the caller wanted, so a CA with two days
   --  left would happily sign a leaf claiming 397. The moment the CA
   --  expires the chain stops verifying, so the rest of that year is
   --  validity the certificate states and does not have -- and nothing said
   --  so, at issuing time or later. This crate already computes the window
   --  from the clock rather than writing a decade into the source for the
   --  same reason.
   --
   --  Clamped rather than refused: the caller asked for a certificate good
   --  for up to that long, and a shorter one that works beats a longer one
   --  that cannot.
   procedure Check_Validity_Not_Past_Issuer is
      package X509C renames CryptoLib.X509.Certificates;
      use type CryptoLib.PEM.Decode_Status;

      function Expiry (Certificate_PEM : String)
        return CryptoLib.X509.Certificate_Time
      is
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Certificate_PEM)));
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Certificate_PEM'First;
         Armour : CryptoLib.PEM.Decode_Status;
         Status : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Certificate_PEM, CryptoLib.PEM.Certificate_Label, From, Buffer,
            Last, Armour);
         if Armour /= CryptoLib.PEM.Ok then
            return (others => 0);
         end if;
         return X509C.Not_After
                  (X509C.Decode_DER
                     (Buffer (Buffer'First .. Last),
                      CryptoLib.ASN1.Default_Limits, Status));
      end Expiry;

      Forever_CA_PEM : constant String :=
        "-----BEGIN CERTIFICATE-----" & ASCII.LF &
        "MIIBEDCBw6ADAgECAhRIsMOpcUPLN2HirLi3TmMn5IgvSjAFBgMrZXAwFTETMBEG" & ASCII.LF &
        "A1UEAwwKRm9yZXZlciBDQTAgFw0yMDAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1" & ASCII.LF &
        "OVowFTETMBEGA1UEAwwKRm9yZXZlciBDQTAqMAUGAytlcAMhAILRKIiOp48mey16" & ASCII.LF &
        "LkTZ4/nE9oFe5nVvUUYXK+N7HEtIoyMwITAPBgNVHRMBAf8EBTADAQH/MA4GA1Ud" & ASCII.LF &
        "DwEB/wQEAwIBBjAFBgMrZXADQQAUFqdL6oObX9i0AkQhVS9lCf/jx/YB9bCGIJfc" & ASCII.LF &
        "30XoMCg4VUVbDPzhaGXvxJrXZIzBLxD20x8pGn/PRfX0vZMD" & ASCII.LF &
        "-----END CERTIFICATE-----";
      Forever_Key_PEM : constant String :=
        "-----BEGIN PRIVATE KEY-----" & ASCII.LF &
        "MC4CAQAwBQYDK2VwBCIEILZ+QZgzg6qYQGeXmkxYe16XLRdxIClgNw43MsJiuzHW" & ASCII.LF &
        "-----END PRIVATE KEY-----";
      Short_CA, Short_Key, Leaf, Leaf_Key : Unbounded_String;
      Long_CA, Long_Key, Long_Leaf, Long_Leaf_Key : Unbounded_String;
      Ever_Leaf, Ever_Key : Unbounded_String;
   begin
      --  A CA with two days left, asked for a leaf good for over a year.
      Check (CryptoLib.Certificates.Create_Local_CA
               ("short-lived-ca", Short_CA, Short_Key,
                CryptoLib.Certificates.Ed25519_Key, 2)
             = CryptoLib.Certificates.Ok,
             "a CA with two days left");
      Check (CryptoLib.Certificates.Issue_Server_Certificate
               (To_String (Short_CA), To_String (Short_Key), "brief.example",
                [1 => To_Unbounded_String ("brief.example")],
                Leaf, Leaf_Key, 397)
             = CryptoLib.Certificates.Ok,
             "still issues rather than refusing");
      Check (CryptoLib.X509.Is_Not_After
               (Expiry (To_String (Leaf)), Expiry (To_String (Short_CA))),
             "and the leaf does not outlast the CA that signed it");

      --  The ordinary case is untouched: a leaf under a long-lived CA gets
      --  the window it asked for, not the CA's.
      Check (CryptoLib.Certificates.Create_Local_CA
               ("long-lived-ca", Long_CA, Long_Key)
             = CryptoLib.Certificates.Ok,
             "a CA with ten years left");
      Check (CryptoLib.Certificates.Issue_Server_Certificate
               (To_String (Long_CA), To_String (Long_Key), "usual.example",
                [1 => To_Unbounded_String ("usual.example")],
                Long_Leaf, Long_Leaf_Key, 397)
             = CryptoLib.Certificates.Ok,
             "issues a leaf as usual");
      Check (not CryptoLib.X509.Is_Not_After
                   (Expiry (To_String (Long_CA)),
                    Expiry (To_String (Long_Leaf))),
             "whose window is its own and shorter than the CA's, not "
             & "clamped to it");

      --  A CA that says it never expires, which RFC 5280 spells 99991231.
      --  The ceiling is worked out as a clock time and no clock here reaches
      --  the year 9999, so this is the case where the bound cannot be
      --  computed -- and the right answer is to leave the certificate alone,
      --  because nothing issued today can run past a CA that never ends.
      --  Worth pinning because it arrives through an exception handler
      --  rather than a test on the year, and because the only other way in
      --  was a date like the 31st of February, which no longer parses.
      Check (CryptoLib.Certificates.Issue_Server_Certificate
               (Forever_CA_PEM, Forever_Key_PEM, "under.forever",
                [1 => To_Unbounded_String ("under.forever")],
                Ever_Leaf, Ever_Key, 397)
             = CryptoLib.Certificates.Ok,
             "a CA that never expires still issues");
      Check (Expiry (To_String (Ever_Leaf)).Year < 9999,
             "and the certificate gets a window of its own rather than the "
             & "CA's, got"
             & Natural'Image (Expiry (To_String (Ever_Leaf)).Year));

      --  The window it asked for, to the day: the same 397 days as the leaf
      --  issued above under an ordinary CA. Checking only that it is short
      --  of 9999 would pass just as well if the unreadable expiry had been
      --  read as "expires now", which is the other way this can go wrong.
      Check (Expiry (To_String (Ever_Leaf)).Year
             = Expiry (To_String (Long_Leaf)).Year
             and then Expiry (To_String (Ever_Leaf)).Month
                      = Expiry (To_String (Long_Leaf)).Month
             and then Expiry (To_String (Ever_Leaf)).Day
                      = Expiry (To_String (Long_Leaf)).Day,
             "and it is the same window a leaf gets under an ordinary CA, "
             & "not one cut back to the moment of issue");
   end Check_Validity_Not_Past_Issuer;


   --  A date that does not exist is not a time.
   --
   --  The day was checked against 31 and no further, so the 31st of
   --  February decoded happily. Nothing downstream notices: times are
   --  compared field by field, so a notAfter of 31 February keeps a
   --  certificate valid for the days after February has ended, and the
   --  number was chosen by whoever wrote the certificate. OpenSSL calls the
   --  same encoding a bad time value.
   --
   --  It also quietly disabled the issuer-expiry ceiling, which has to turn
   --  the CA's notAfter into a clock time and cannot turn that into one.
   procedure Check_Impossible_Dates is
      use type CryptoLib.ASN1.Errors.Decode_Status;

      --  A GeneralizedTime carrying exactly these characters.
      function Reads (Text : String) return Boolean is
         Data   : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Text'Length + 2));
         Cursor : Ada.Streams.Stream_Element_Offset := 1;
         Value  : CryptoLib.X509.Certificate_Time;
         Status : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         Data (1) := 16#18#;
         Data (2) := Ada.Streams.Stream_Element (Text'Length);
         for I in Text'Range loop
            Data (2 + Ada.Streams.Stream_Element_Offset (I - Text'First + 1)) :=
              Character'Pos (Text (I));
         end loop;
         CryptoLib.X509.Times.Read
           (Data, Cursor, Data'Last, 0, CryptoLib.ASN1.Default_Limits,
            Value, Status);
         return Status = CryptoLib.ASN1.Errors.Ok;
      end Reads;
   begin
      Check (not Reads ("20260231000000Z"),
             "the 31st of February is refused");
      Check (not Reads ("20260230000000Z"),
             "and the 30th");
      Check (not Reads ("20260431000000Z"),
             "and the 31st of a month with thirty days");
      Check (not Reads ("20260000000000Z"),
             "and a zeroth day");

      --  The leap year rule is the Gregorian one, not "divisible by four".
      Check (Reads ("20240229000000Z"),
             "the 29th of February stands in a leap year");
      Check (not Reads ("20250229000000Z"),
             "and not in an ordinary one");
      Check (not Reads ("21000229000000Z"),
             "not in 2100, which is divisible by four and not a leap year");
      Check (Reads ("20000229000000Z"),
             "and does stand in 2000, which is divisible by four hundred");

      --  Dates that do exist still decode, or this would be refusing real
      --  certificates rather than impossible ones.
      Check (Reads ("20260131000000Z"), "the 31st of January is a date");
      Check (Reads ("20260430000000Z"), "so is the 30th of April");
      Check (Reads ("20261231235959Z"), "and the last second of a year");
   end Check_Impossible_Dates;


   --  A statement that never says when it expires does not last for ever.
   --
   --  nextUpdate is optional in a CRL and in an OCSP response, and freshness
   --  was judged only against it: a list carrying one was refused once it
   --  passed, and a list carrying none had no window to be outside of. Two
   --  lists of the same age got opposite answers, the older-looking one
   --  being the one that admitted when it expired.
   --
   --  Nothing has to be forged to use this. The CRL below is genuine and
   --  correctly signed -- the issuer really did say "nothing revoked", in
   --  2016 -- and replaying it is how a certificate revoked since keeps
   --  working. Which is the sentence this package's own summary opens with.
   procedure Check_Undated_Statement_Ages is
      package X509C renames CryptoLib.X509.Certificates;
      package XC renames CryptoLib.X509.CRLs;
      package RV renames CryptoLib.X509.Revocation;
      use type RV.Revocation_Answer;

      Old_CRL_No_Next_DER : constant String :=
        "307c3030020101300506032b657030153113301106035504030c0a416e6369656e74204341170d3136303130" &
        "313030303030305a300506032b6570034100d42aad219f0f54efd41f288648bbabecc7d2b4433fbe33de7b7f" &
        "f9043bd6e2f4adf2fb9ee9fcdb37594779c7512c3d7d983c22692d253f62662260dc60710208";

      CRL_CA_DER : constant String :=
        "3082010e3081c1a0030201020214577aeb858a37d5fd81ef133d2f79f41b352b0865300506032b6570301531" &
        "13301106035504030c0a416e6369656e74204341301e170d3135303130313030303030305a170d3335303130" &
        "313030303030305a30153113301106035504030c0a416e6369656e74204341302a300506032b657003210066" &
        "cac3f61035489eb5047b43fe568288970990887c3b28dfe059572c9d7fc8b9a3233021300f0603551d130101" &
        "ff040530030101ff300e0603551d0f0101ff040403020106300506032b65700341006c648e89b0c39a67a31f" &
        "d67e7799560c095dd91d8625d0ec851229ac49a3ffe223a980f08e75f8903eff5e7bb2267bcb1a2b5661dd19" &
        "af7a9a5bfe53dea8df03";

      CRL_Leaf_DER : constant String :=
        "3081d930818ca00302010202021092300506032b657030153113301106035504030c0a416e6369656e742043" &
        "41301e170d3135303130313030303030305a170d3335303130313030303030305a3017311530130603550403" &
        "0c0c6c6561662e6578616d706c65302a300506032b657003210066cac3f61035489eb5047b43fe5682889709" &
        "90887c3b28dfe059572c9d7fc8b9300506032b65700341007c3a46fa18d9399201c207d4b39510689c321d00" &
        "e21238c63b6bf631429e79665f98463750a4792e8c4b887dcda8aaf423a7651b38e5b889186a829c34cf280c";

      OCSP_No_Next_DER : constant String :=
        "308202700a0100a08202693082026506092b06010505073001010482025630820252307fa118301631143012" &
        "06035504030c0b4f43535020416765204341180f32303236303732393131303935355a30523050303b300906" &
        "052b0e03021a050004148aa32804b8ef3e1a72a802fa517db805a64d6b860414cd92b608f1fd749014a411de" &
        "eaafcf1b3c5e589702021e618000180f32303236303732393131303935355a300a06082a8648ce3d04030203" &
        "4700304402206faf3ddabc08070db84eac39ad1a082a490917774f3f6c95edf7ea471823f6cc02205ab938e7" &
        "357de2d8b5a8aea5cdf2fd7ac00741f3e45ef854bf3fd984acfa99a1a0820178308201743082017030820116" &
        "a0030201020214727b3004679aafba2769bea705a91b243a8dba81300a06082a8648ce3d0403023016311430" &
        "1206035504030c0b4f43535020416765204341301e170d3236303732393131303935355a170d333431303135" &
        "3131303935355a30163114301206035504030c0b4f435350204167652043413059301306072a8648ce3d0201" &
        "06082a8648ce3d030107034200049dd9b1bdb250fafd0132582cc4ec06f590ef980cb19c5b94391cc539af61" &
        "a1ba333bc63a9dd6ac1fc8d721e114626be9cc45eb735e1029ede22b1811f760bc57a3423040300f0603551d" &
        "130101ff040530030101ff300e0603551d0f0101ff040403020106301d0603551d0e04160414cd92b608f1fd" &
        "749014a411deeaafcf1b3c5e5897300a06082a8648ce3d0403020348003045022067c206a7d209626c102be4" &
        "8f757a7a4afaf209562d73be0b43ba70bcbf4f5b8b0221008f76d1f212b8e471977a9f57aaf00673b53777bd" &
        "5fc36c3dfdb60f170726a0cc";

      OCSP_CA_DER : constant String :=
        "3082017030820116a0030201020214727b3004679aafba2769bea705a91b243a8dba81300a06082a8648ce3d" &
        "04030230163114301206035504030c0b4f43535020416765204341301e170d3236303732393131303935355a" &
        "170d3334313031353131303935355a30163114301206035504030c0b4f435350204167652043413059301306" &
        "072a8648ce3d020106082a8648ce3d030107034200049dd9b1bdb250fafd0132582cc4ec06f590ef980cb19c" &
        "5b94391cc539af61a1ba333bc63a9dd6ac1fc8d721e114626be9cc45eb735e1029ede22b1811f760bc57a342" &
        "3040300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301d0603551d0e0416" &
        "0414cd92b608f1fd749014a411deeaafcf1b3c5e5897300a06082a8648ce3d0403020348003045022067c206" &
        "a7d209626c102be48f757a7a4afaf209562d73be0b43ba70bcbf4f5b8b0221008f76d1f212b8e471977a9f57" &
        "aaf00673b53777bd5fc36c3dfdb60f170726a0cc";

      OCSP_Leaf_DER : constant String :=
        "3082016e30820113a00302010202021e61300a06082a8648ce3d04030230163114301206035504030c0b4f43" &
        "535020416765204341301e170d3236303732393131303935355a170d3332303131393131303935355a301731" &
        "15301306035504030c0c6c6561662e6578616d706c653059301306072a8648ce3d020106082a8648ce3d0301" &
        "07034200046d43ecd744c212d59a835dc92090d5431edd8c4085918fef3e90613dec37b48d3b7fc556b1beae" &
        "e9b13a66eb9dec3d9d16e37bbbb6c8161188a0e915504835ada350304e300c0603551d130101ff0402300030" &
        "1d0603551d0e04160414032c9886bbda604bc235e452d5697eabedc5e673301f0603551d23041830168014cd" &
        "92b608f1fd749014a411deeaafcf1b3c5e5897300a06082a8648ce3d04030203490030460221008ee8ca58a3" &
        "4bfaf8306e32e6eecf1a06b1464578a1a79a6cc42f43243387b17c022100c265d327bb504ff33138c5436790" &
        "3cc9297164c077c20ac285785052130cdba1";
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

      Leaf : constant X509C.Certificate :=
        X509C.Decode_DER (From_Hex (CRL_Leaf_DER),
                          CryptoLib.ASN1.Default_Limits, Status);
      CA   : constant X509C.Certificate :=
        X509C.Decode_DER (From_Hex (CRL_CA_DER),
                          CryptoLib.ASN1.Default_Limits, Status);
      List : constant XC.Revocation_List :=
        XC.Decode_DER (From_Hex (Old_CRL_No_Next_DER),
                       CryptoLib.ASN1.Default_Limits, Status);

      --  The list was issued on the first of January 2016.
      Ten_Years_On : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 1, Day => 2,
         Hour => 0, Minute => 0, Second => 0);
      Next_Day     : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2016, Month => 1, Day => 2,
         Hour => 0, Minute => 0, Second => 0);
   begin
      Check (XC.Is_Present (List) and then X509C.Is_Present (Leaf)
             and then X509C.Is_Present (CA),
             "fixture: the list, its issuer and a certificate all decode");
      Check (not XC.Has_Next_Update (List),
             "fixture: and the list never says when it expires");

      --  The day after it was issued it is worth believing.
      Check (RV.Check_Against_CRL (Leaf, CA, List, Next_Day) = RV.Not_Revoked,
             "a list without a nextUpdate is believed while it is fresh, got "
             & RV.Answer_Image
                 (RV.Check_Against_CRL (Leaf, CA, List, Next_Day)));

      --  Ten years later it is not, and it says so as staleness rather than
      --  as an answer about the certificate.
      Check (RV.Check_Against_CRL (Leaf, CA, List, Ten_Years_On) = RV.Stale,
             "and is stale ten years on rather than still saying nothing was "
             & "revoked, got "
             & RV.Answer_Image
                 (RV.Check_Against_CRL (Leaf, CA, List, Ten_Years_On)));

      --  The age is the only thing refusing it: the signature, the issuer
      --  and the scope are all fine, which is what makes replaying it work.
      Check (RV.Check_Against_CRL
               (Leaf, CA, List, Ten_Years_On,
                Maximum_Age_Days => 4_000) = RV.Not_Revoked,
             "and a caller who says it may be that old gets the answer, so "
             & "nothing else about the list is what was refused");

      --  The same for OCSP, where a response without a nextUpdate is not an
      --  oddity but what "openssl ocsp" produces unless told otherwise. RFC
      --  6960 reads the omission as newer information being available all
      --  the time, which is the opposite of what believing it for ever does.
      declare
         Reply : CryptoLib.OCSP.Response :=
           CryptoLib.OCSP.Decode_Response
             (From_Hex (OCSP_No_Next_DER), CryptoLib.ASN1.Default_Limits,
              Status);
         Resp_Leaf : constant X509C.Certificate :=
           X509C.Decode_DER (From_Hex (OCSP_Leaf_DER),
                             CryptoLib.ASN1.Default_Limits, Status);
         Resp_CA   : constant X509C.Certificate :=
           X509C.Decode_DER (From_Hex (OCSP_CA_DER),
                             CryptoLib.ASN1.Default_Limits, Status);
         Days_Later : constant CryptoLib.X509.Certificate_Time :=
           (Year => 2026, Month => 8, Day => 1,
            Hour => 12, Minute => 0, Second => 0);
         Years_Later : constant CryptoLib.X509.Certificate_Time :=
           (Year => 2036, Month => 8, Day => 1,
            Hour => 12, Minute => 0, Second => 0);
      begin
         Check (not CryptoLib.OCSP.Has_Next_Update (Reply),
                "fixture: the response names no nextUpdate");
         Check (RV.Check_Against_OCSP (Resp_Leaf, Resp_CA, Reply, Days_Later)
                = RV.Not_Revoked,
                "a response without a nextUpdate answers while it is fresh, "
                & "got "
                & RV.Answer_Image
                    (RV.Check_Against_OCSP
                       (Resp_Leaf, Resp_CA, Reply, Days_Later)));
         Check (RV.Check_Against_OCSP (Resp_Leaf, Resp_CA, Reply, Years_Later)
                = RV.Stale,
                "and is stale ten years on rather than still speaking for "
                & "the certificate, got "
                & RV.Answer_Image
                    (RV.Check_Against_OCSP
                       (Resp_Leaf, Resp_CA, Reply, Years_Later)));
      end;
   end Check_Undated_Statement_Ages;


   procedure Check_X509_Extensions is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.PEM.Decode_Status;
      use type CryptoLib.X509.Extensions.General_Name_Kind;

      package X509C renames CryptoLib.X509.Certificates;
      package XE renames CryptoLib.X509.Extensions;

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

      CA_PEM   : Unbounded_String;
      CA_Key   : Unbounded_String;
      Leaf_PEM : Unbounded_String;
      Leaf_Key : Unbounded_String;
      Outcome  : CryptoLib.Certificates.Certificate_Status;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("extensions-ca", CA_PEM, CA_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "host.example",
           [1 => To_Unbounded_String ("host.example"),
            2 => To_Unbounded_String ("alt.example"),
            3 => To_Unbounded_String ("127.0.0.1")],
           Leaf_PEM, Leaf_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: leaf issued");

      declare
         CA : constant X509C.Certificate := Decoded (To_String (CA_PEM));
         BC : constant XE.Basic_Constraints := XE.Get_Basic_Constraints (CA);
         KU : constant XE.Key_Usage := XE.Get_Key_Usage (CA);
         EK : constant XE.Extended_Key_Usage := XE.Get_Extended_Key_Usage (CA);
      begin
         Check (BC.Present and then BC.Well_Formed and then BC.Is_CA,
                "the CA's basic constraints say CA:TRUE");
         Check (not BC.Has_Path_Length,
                "the CA states no path length constraint");
         Check (KU.Present and then KU.Well_Formed,
                "the CA carries a well-formed key usage");
         Check (KU.Certificate_Sign and then KU.CRL_Sign,
                "the CA may sign certificates and CRLs");
         Check (not KU.Digital_Signature,
                "the CA's key usage is only what it needs");

         --  Absent is not the same as empty, and the type says which.
         Check (not EK.Present,
                "the CA has no extended key usage, which is not an empty one");
         Check (not XE.Has_Unsupported_Critical_Extension (CA),
                "every critical extension on the CA is one we understand");
      end;

      declare
         Leaf : constant X509C.Certificate := Decoded (To_String (Leaf_PEM));
         BC   : constant XE.Basic_Constraints :=
           XE.Get_Basic_Constraints (Leaf);
         KU   : constant XE.Key_Usage := XE.Get_Key_Usage (Leaf);
         EK   : constant XE.Extended_Key_Usage :=
           XE.Get_Extended_Key_Usage (Leaf);
      begin
         Check (BC.Present and then not BC.Is_CA,
                "the leaf's basic constraints say CA:FALSE");
         Check (KU.Present and then KU.Digital_Signature
                and then not KU.Certificate_Sign,
                "the leaf may sign but may not issue certificates");
         Check (EK.Present and then EK.Well_Formed and then EK.Server_Auth,
                "the leaf is issued for TLS server authentication");
         Check (not EK.Client_Auth,
                "a server certificate is not also a client one");
         Check (not EK.Any_Purpose and then not EK.Has_Unrecognised,
                "the leaf's purposes are exactly the ones recognised");

         --  Subject alternative names, in the order they were asked for.
         Check (XE.Subject_Alternative_Name_Count (Leaf) = 3,
                "the leaf carries three alternative names");
         Check (XE.Subject_Alternative_Name_Kind (Leaf, 1) = XE.DNS_Name
                and then XE.Subject_Alternative_Name_Text (Leaf, 1)
                           = "host.example",
                "the first alternative name is the DNS name asked for");
         Check (XE.Subject_Alternative_Name_Kind (Leaf, 2) = XE.DNS_Name
                and then XE.Subject_Alternative_Name_Text (Leaf, 2)
                           = "alt.example",
                "the second alternative name is the other DNS name");

         --  An address is bytes. Rendering it would invite comparing
         --  addresses as text, where 10.0.0.1 and 10.000.000.001 differ and
         --  the addresses do not.
         Check (XE.Subject_Alternative_Name_Kind (Leaf, 3) = XE.IP_Address,
                "the third alternative name is an address");
         Check (XE.Subject_Alternative_Name_Text (Leaf, 3) = "",
                "an address is not offered as text");
         declare
            Address : constant Ada.Streams.Stream_Element_Array :=
              XE.Subject_Alternative_Name_Bytes (Leaf, 3);
         begin
            Check (Address'Length = 4,
                   "an IPv4 address is four octets");
            Check (Address (Address'First) = 127
                   and then Address (Address'First + 1) = 0
                   and then Address (Address'First + 2) = 0
                   and then Address (Address'First + 3) = 1,
                   "the address octets are 127.0.0.1");
         end;

         Check (not XE.Has_Unsupported_Critical_Extension (Leaf),
                "every critical extension on the leaf is one we understand");

         --  Asking past the end must not invent a name.
         Check (XE.Subject_Alternative_Name_Text (Leaf, 9) = "",
                "a name past the end is empty");
         Check (XE.Subject_Alternative_Name_Bytes (Leaf, 9)'Length = 0,
                "a name past the end has no octets");
      end;
   end Check_X509_Extensions;



   --  Distinguished names taken apart rather than flattened.
   --
   --  The certificate is one OpenSSL issued with every common attribute, so
   --  the ordering and the labels can be checked against what "openssl x509
   --  -nameopt rfc2253" prints for the same bytes.
   procedure Check_X509_Names is
      use type CryptoLib.X509.Attribute_Kind;
      use type CryptoLib.X509.Names.Directory_String_Kind;

      package X509C renames CryptoLib.X509.Certificates;
      package XN renames CryptoLib.X509.Names;

      Multi_Certificate : constant String :=
        "308203403082022802140a69642915b0555887f43cad736f58c003e69ded300d06092a864886f70d01010b0500" &
        "30163114301206035504030c0b7273612d746573742d6361301e170d3236303732383139333135365a170d3237" &
        "303732383139333135365a3081a2310b300906035504061302444b3114301206035504080c0b486f7665647374" &
        "6164656e3113301106035504070c0a436f70656e686167656e31143012060355040a0c0b4578616d706c65204c" &
        "746431143012060355040b0c0b456e67696e656572696e67311a301806035504030c116d756c74692e6578616d" &
        "706c652e636f6d3120301e06092a864886f70d010901161161646d696e406578616d706c652e636f6d30820122" &
        "300d06092a864886f70d01010105000382010f003082010a0282010100c62626cc40706f4eec4a2098b1dc8694" &
        "a5a20d0896371462df1bc05898b1ca553793bdc8a7f22e5318d4bd6057d203e61f6565a1c02cebff0652fd1522" &
        "54992da0b4148071de75e897baeede1201d65086c860bb0f096719360fc373b333de8eff20179775ca8bee5c89" &
        "9930dee779e02ba0cde4f7a58b12abca10e6a2f0624ae9f8cc3d7da1fbafd8139d265b2c48ab6e36660921f5b1" &
        "ae05c3fbe7630d7fc7a138b1f2eba7b9ed5d303a4276161595bf6234746974c68b2da2c2a45a6550955cd179cb" &
        "003f432b99ae9260fd32adddf394796660f19809d79b3778419d23365d91b105212a94fb814583eb2e90ceb48f" &
        "552b888442c732288e4b4137fff0d10203010001300d06092a864886f70d01010b050003820101002632f88d68" &
        "f7c8bd35178730a33cbc9b20c8b5e8b5c756be3c4872636470ccf2e2f6f19bd26ef01d9b365c38307e384591e6" &
        "e90745014af092fc62c4a41bcac2cf37f92038c5dfca9355e6ea9590eb23031cc7af80f46effde8ec1fab977b7" &
        "1089990e5f7355c3819762fc131572e8e358c389dd79993c4022cf8d3796516ad46af2209720aaa332bfee7bb2" &
        "424c5881863874f9db30742009310858f5a63a5a8454a183aa41c0a02feb2d7fdeb0e81ba59af4fa7e124e6d62" &
        "1a8a2e0fecd6ecfeeae65066de8140c5f71bbff3e8d67c305b5c8aa34f1080ef83fb658782d6fd7255c93f664b" &
        "fb0de858da0800ac25c9edba5d7866b1db86116fc5d307652791";

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

      Raw    : constant Ada.Streams.Stream_Element_Array :=
        From_Hex (Multi_Certificate);
      Status : CryptoLib.ASN1.Errors.Decode_Status;
      Item   : constant X509C.Certificate :=
        X509C.Decode_DER (Raw, CryptoLib.ASN1.Default_Limits, Status);
   begin
      Check (X509C.Is_Present (Item), "fixture: the certificate decodes");

      --  Seven attributes, in the order DER holds them.
      Check (XN.Attribute_Count (Item, XN.Subject_Name) = 7,
             "the subject carries seven attributes, got"
             & Natural'Image (XN.Attribute_Count (Item, XN.Subject_Name)));

      Check (XN.Attribute_Kind_At (Item, XN.Subject_Name, 1)
               = CryptoLib.X509.Country
             and then XN.Attribute_Text (Item, XN.Subject_Name, 1) = "DK",
             "the first attribute is the country");

      --  The same attribute, read as its raw parts rather than as text. A
      --  caller that needs an attribute this crate has no Kind for has only
      --  these two, so they are checked against the kind and text that are
      --  derived from them: the identifier must be the countryName OID, and
      --  the bytes must be the text those bytes encode.
      Check (XN.Attribute_Identifier (Item, XN.Subject_Name, 1)
               = CryptoLib.ASN1.Octets'[16#55#, 16#04#, 16#06#],
             "the first attribute's identifier is the countryName OID "
             & "2.5.4.6");
      Check (XN.Attribute_Bytes (Item, XN.Subject_Name, 1)
               = Bytes_From_String ("DK"),
             "and its raw value is the text it decodes to");
      Check (XN.Attribute_Identifier (Item, XN.Subject_Name, 4)
               /= XN.Attribute_Identifier (Item, XN.Subject_Name, 1),
             "a different attribute kind has a different identifier");
      Check (XN.Attribute_Bytes (Item, XN.Subject_Name, 4)
               = Bytes_From_String ("Example Ltd"),
             "the organization's raw value is its text too");

      Check (XN.Attribute_Kind_At (Item, XN.Subject_Name, 4)
               = CryptoLib.X509.Organization
             and then XN.Attribute_Text (Item, XN.Subject_Name, 4)
                        = "Example Ltd",
             "the fourth is the organization");
      Check (XN.Attribute_Kind_At (Item, XN.Subject_Name, 6)
               = CryptoLib.X509.Common_Name
             and then XN.Attribute_Text (Item, XN.Subject_Name, 6)
                        = "multi.example.com",
             "the sixth is the common name");
      Check (XN.Attribute_Kind_At (Item, XN.Subject_Name, 7)
               = CryptoLib.X509.Email_Address,
             "the seventh is the email address");

      --  Found by kind rather than by counting.
      Check (XN.Find_Attribute
               (Item, XN.Subject_Name, CryptoLib.X509.Organizational_Unit) = 5,
             "the organizational unit is found by kind");
      Check (XN.Find_Attribute
               (Item, XN.Subject_Name, CryptoLib.X509.Domain_Component) = 0,
             "an attribute the name does not carry is not found");
      Check (XN.Find_Attribute
               (Item, XN.Subject_Name, CryptoLib.X509.Unknown_Attribute) = 0,
             "searching for the unknown kind finds nothing, since every "
             & "unrecognised attribute would answer to it");

      --  The encodings are reported, not guessed at.
      Check (XN.Attribute_String_Kind (Item, XN.Subject_Name, 1)
               = XN.Printable_String,
             "a country is a PrintableString");
      Check (XN.Attribute_String_Kind (Item, XN.Subject_Name, 7)
               = XN.IA5_String,
             "an email address is an IA5String");

      --  Formatting is RFC 4514 order: most specific first, which is the
      --  reverse of how DER holds it. This is the same string openssl prints
      --  with -nameopt rfc2253, except for the label it gives the email
      --  attribute.
      Check (XN.Format (Item, XN.Subject_Name)
               = "EMAIL=admin@example.com,CN=multi.example.com,"
               & "OU=Engineering,O=Example Ltd,L=Copenhagen,"
               & "ST=Hovedstaden,C=DK",
             "the formatted subject is in RFC 4514 order, got "
             & XN.Format (Item, XN.Subject_Name));

      --  The issuer of this certificate is the RSA test CA, one attribute.
      Check (XN.Attribute_Count (Item, XN.Issuer_Name) = 1
             and then XN.Attribute_Text (Item, XN.Issuer_Name, 1)
                        = "rsa-test-ca",
             "the issuer name is read the same way");

      --  Formatting is for reading, not for comparing: the encoded name is
      --  what an issuer signed and what tells two subjects apart.
      Check (X509C.Subject_Bytes (Item)'Length > 0
             and then X509C.Subject_Bytes (Item) /= X509C.Issuer_Bytes (Item),
             "the encoded subject and issuer differ, which is the comparison "
             & "that counts");
   end Check_X509_Names;



   --  The armour handling behind the issuance API, now that it goes through
   --  the strict decoder.
   --
   --  What this pins is not that good input works -- the certificate tests
   --  already cover that -- but that damaged input is refused rather than
   --  decoded into something else. A decoder that skips what it does not
   --  recognise turns one stray character into a different certificate, and
   --  the fingerprint of that certificate is a number nobody can match.
   procedure Check_Certificate_Armour is
      CA_PEM  : Unbounded_String;
      CA_Key  : Unbounded_String;
      Outcome : CryptoLib.Certificates.Certificate_Status;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("armour-ca", CA_PEM, CA_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      declare
         Good        : constant String := To_String (CA_PEM);
         Fingerprint : constant String :=
           CryptoLib.Certificates.Fingerprint (Good);
      begin
         Check (Fingerprint'Length > 0,
                "a well-formed certificate has a fingerprint");

         --  A stray character inside the base64. Skipping it would shift
         --  every following bit and yield a different certificate with a
         --  perfectly plausible fingerprint.
         declare
            Body_Start : constant Natural :=
              Ada.Strings.Fixed.Index (Good, "-----" & ASCII.LF) + 6;
            Damaged    : String := Good;
         begin
            Check (Body_Start in Good'Range,
                   "fixture: the armour body was found");
            Damaged (Body_Start + 4) := '!';
            Check (CryptoLib.Certificates.Fingerprint (Damaged) = "",
                   "a certificate with a stray character in its armour has "
                   & "no fingerprint, rather than a different one");
            Check (not CryptoLib.Certificates.Same_Certificate
                         (Good, Damaged),
                   "damaged armour does not compare equal to the original");
         end;

         --  Armour that opens as one thing and closes as another.
         declare
            Crossed : constant String :=
              "-----BEGIN CERTIFICATE-----" & ASCII.LF & "QUJD" & ASCII.LF
              & "-----END PRIVATE KEY-----" & ASCII.LF;
         begin
            Check (CryptoLib.Certificates.Fingerprint (Crossed) = "",
                   "a block closed by a different label is refused");
         end;

         --  Text before the armour must not become part of the payload. This
         --  is the shape that failed here once: keytool names the alias
         --  first, and openssl -text prints the whole certificate.
         declare
            With_Preamble : constant String :=
              "Alias name: mykey" & ASCII.LF
              & "Entry type: PrivateKeyEntry" & ASCII.LF & Good;
         begin
            Check (CryptoLib.Certificates.Fingerprint (With_Preamble)
                     = Fingerprint,
                   "a preamble before the armour does not change the "
                   & "certificate");
         end;
      end;
   end Check_Certificate_Armour;

   --  AUnit routine wrappers. Each check is a test of its own, so a
   --  failure reports the check that failed and the rest still run.
   procedure Run_Check_X509_Decode (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_X509_Extensions (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Serial_Comparison (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Validity_Not_Past_Issuer (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Impossible_Dates (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Undated_Statement_Ages (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Serial_Numbers (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Validity_Window (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Key_Identifiers (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Large_Certificate (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Oversized_Serial (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Certificate_Ambiguity (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_X509_Access_Locations (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_X509_Names (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Certificate_Armour (Item : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Check_X509_Decode (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_X509_Decode;
   end Run_Check_X509_Decode;

   procedure Run_Check_X509_Extensions (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_X509_Extensions;
   end Run_Check_X509_Extensions;

   procedure Run_Check_Serial_Comparison (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Serial_Comparison;
   end Run_Check_Serial_Comparison;

   procedure Run_Check_Validity_Not_Past_Issuer (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Validity_Not_Past_Issuer;
   end Run_Check_Validity_Not_Past_Issuer;

   procedure Run_Check_Impossible_Dates (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Impossible_Dates;
   end Run_Check_Impossible_Dates;

   procedure Run_Check_Undated_Statement_Ages (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Undated_Statement_Ages;
   end Run_Check_Undated_Statement_Ages;

   procedure Run_Check_Serial_Numbers (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Serial_Numbers;
   end Run_Check_Serial_Numbers;

   procedure Run_Check_Validity_Window (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Validity_Window;
   end Run_Check_Validity_Window;

   procedure Run_Check_Key_Identifiers (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Key_Identifiers;
   end Run_Check_Key_Identifiers;

   procedure Run_Check_Large_Certificate (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Large_Certificate;
   end Run_Check_Large_Certificate;

   procedure Run_Check_Oversized_Serial (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Oversized_Serial;
   end Run_Check_Oversized_Serial;

   procedure Run_Check_Certificate_Ambiguity (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Certificate_Ambiguity;
   end Run_Check_Certificate_Ambiguity;

   procedure Run_Check_X509_Access_Locations (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_X509_Access_Locations;
   end Run_Check_X509_Access_Locations;

   procedure Run_Check_X509_Names (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_X509_Names;
   end Run_Check_X509_Names;

   procedure Run_Check_Certificate_Armour (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Certificate_Armour;
   end Run_Check_Certificate_Armour;

   overriding procedure Register_Tests (Item : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (Item, Run_Check_X509_Decode'Access, "x509 decode");
      Register_Routine (Item, Run_Check_X509_Extensions'Access, "x509 extensions");
      Register_Routine (Item, Run_Check_Serial_Comparison'Access, "serial comparison");
      Register_Routine (Item, Run_Check_Validity_Not_Past_Issuer'Access, "validity not past issuer");
      Register_Routine (Item, Run_Check_Impossible_Dates'Access, "impossible dates");
      Register_Routine (Item, Run_Check_Undated_Statement_Ages'Access, "undated statement ages");
      Register_Routine (Item, Run_Check_Serial_Numbers'Access, "serial numbers");
      Register_Routine (Item, Run_Check_Validity_Window'Access, "validity window");
      Register_Routine (Item, Run_Check_Key_Identifiers'Access, "key identifiers");
      Register_Routine (Item, Run_Check_Large_Certificate'Access, "large certificate");
      Register_Routine (Item, Run_Check_Oversized_Serial'Access, "oversized serial");
      Register_Routine (Item, Run_Check_Certificate_Ambiguity'Access, "certificate ambiguity");
      Register_Routine (Item, Run_Check_X509_Access_Locations'Access, "x509 access locations");
      Register_Routine (Item, Run_Check_X509_Names'Access, "x509 names");
      Register_Routine (Item, Run_Check_Certificate_Armour'Access, "certificate armour");
   end Register_Tests;

   overriding function Name (Item : Test_Case) return AUnit.Message_String is
      pragma Unreferenced (Item);
   begin
      return AUnit.Format ("cryptolib X.509 decoding");
   end Name;

end Tests_X509_Decoding;
