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

package body Tests_Encodings is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Certificates.Certificate_Status;
   use type Interfaces.Unsigned_32;

   procedure Check_Identity_Predicates is
      Cert, Key, Other_Cert, Other_Key : Ada.Strings.Unbounded.Unbounded_String;
      Status : CryptoLib.Certificates.Certificate_Status;
   begin
      Check (CryptoLib.Certificates.Valid_DNS_Name ("localhost"), "plain host");
      Check (CryptoLib.Certificates.Valid_DNS_Name ("a.b.example"), "dotted name");
      Check
        (CryptoLib.Certificates.Valid_DNS_Name ("x-1.example"),
         "a hyphen inside a label");
      Check
        (not CryptoLib.Certificates.Valid_DNS_Name ("-bad.example"),
         "a label may not begin with a hyphen");
      Check
        (not CryptoLib.Certificates.Valid_DNS_Name ("bad-.example"),
         "a label may not end with a hyphen");
      Check
        (not CryptoLib.Certificates.Valid_DNS_Name ("trailing.dot."),
         "a trailing dot is not a label");
      Check (not CryptoLib.Certificates.Valid_DNS_Name (""), "an empty name");
      Check
        (not CryptoLib.Certificates.Valid_DNS_Name ("under_score.example"),
         "an underscore is not a DNS character");

      Check
        (CryptoLib.Certificates.Valid_DNS_Name ("*.example.test"),
         "a wildcard qualifying a domain");
      Check
        (not CryptoLib.Certificates.Valid_DNS_Name ("*"),
         "a wildcard alone names everything");
      Check
        (not CryptoLib.Certificates.Valid_DNS_Name ("*.test"),
         "a wildcard needs more than a single label under it");
      Check
        (not CryptoLib.Certificates.Valid_DNS_Name ("a*b.example.test"),
         "a star inside a label is not a wildcard");

      Check (CryptoLib.Certificates.Valid_IP_Address ("127.0.0.1"), "IPv4");
      Check (CryptoLib.Certificates.Valid_IP_Address ("::1"), "IPv6");
      Check
        (not CryptoLib.Certificates.Valid_IP_Address ("256.0.0.1"),
         "an octet above 255 is not an address");
      Check
        (CryptoLib.Certificates.Valid_Email_Address ("someone@example.test"),
         "an email address");
      Check
        (not CryptoLib.Certificates.Valid_Email_Address ("no-at-sign"),
         "an address needs an at sign");

      --  Same certificate, different armour width: the text differs, the
      --  certificate does not.
      Status :=
        CryptoLib.Certificates.Create_Local_CA ("compare-ca", Cert, Key);
      Check (Status = CryptoLib.Certificates.Ok, "comparison CA");
      Status :=
        CryptoLib.Certificates.Create_Local_CA
          ("compare-other", Other_Cert, Other_Key);
      Check (Status = CryptoLib.Certificates.Ok, "second comparison CA");

      declare
         Text : constant String := Ada.Strings.Unbounded.To_String (Cert);
         --  The same bytes, armoured with different line endings.
         Rewrapped : constant String := Text & ASCII.LF & ASCII.LF;
      begin
         Check
           (CryptoLib.Certificates.Same_Certificate (Text, Rewrapped),
            "the same certificate compares equal through its armour");
         Check
           (not CryptoLib.Certificates.Same_Certificate
              (Text, Ada.Strings.Unbounded.To_String (Other_Cert)),
            "a different certificate does not");
         Check
           (not CryptoLib.Certificates.Same_Certificate
              (Text, Ada.Strings.Unbounded.To_String (Key)),
            "a private key is not that certificate");

         --  Readers put things in front of the armour: keytool -rfc names the
         --  alias and the entry type first, openssl -text prints the whole
         --  certificate. Every letter of that used to be swept into the base64,
         --  so a certificate a keystore really held compared as a different one
         --  -- and devcert refused to remove its own anchor on the strength of
         --  it.
         declare
            Preamble : constant String :=
              "Alias name: devcert-ca" & ASCII.LF
              & "Creation date: Jul 28, 2026" & ASCII.LF
              & "Entry type: trustedCertEntry" & ASCII.LF & ASCII.LF & Text;
         begin
            Check
              (CryptoLib.Certificates.Same_Certificate (Text, Preamble),
               "a certificate is itself with a reader's preamble in front");
            Check
              (CryptoLib.Certificates.Fingerprint (Preamble)
               = CryptoLib.Certificates.Fingerprint (Text),
               "and fingerprints the same either way");
            Check
              (not CryptoLib.Certificates.Same_Certificate
                 (Preamble, Ada.Strings.Unbounded.To_String (Other_Cert)),
               "while a different certificate still differs");
         end;
         Check
           (CryptoLib.Certificates.Contains_Certificate (Text),
            "a certificate is recognised by its armour");
         Check
           (not CryptoLib.Certificates.Contains_Private_Key (Text),
            "and is not mistaken for a key");
         Check
           (CryptoLib.Certificates.Contains_Private_Key
              (Ada.Strings.Unbounded.To_String (Key)),
            "a private key is recognised by its armour");
      end;
   end Check_Identity_Predicates;

   --  The DER reader is the floor everything X.509 stands on, so these check
   --  the refusals as closely as the acceptances. Each malformed case is a
   --  shape that is legal BER, or nearly legal DER, and would be accepted by a
   --  reader that only looked at tags and lengths.
   procedure Check_ASN1_DER is
      use CryptoLib.ASN1;
      use type CryptoLib.ASN1.Errors.Decode_Status;

      subtype ASN1_Element is CryptoLib.ASN1.Element;

      package DER renames CryptoLib.ASN1.DER;
      package Err renames CryptoLib.ASN1.Errors;

      Limits : constant Decode_Limits := Default_Limits;

      procedure Expect
        (Data    : Ada.Streams.Stream_Element_Array;
         Wanted  : Err.Decode_Status;
         Message : String)
      is
         Pos    : Ada.Streams.Stream_Element_Offset := Data'First;
         Item   : ASN1_Element;
         Status : Err.Decode_Status;
      begin
         DER.Read (Data, Pos, Data'Last, 0, Limits, Item, Status);
         Check (Status = Wanted,
                Message & ": expected " & Err.Status_Image (Wanted)
                & ", got " & Err.Status_Image (Status));
      end Expect;
   begin
      --  A SEQUENCE holding INTEGER 5, read through and then into.
      declare
         Data : constant Ada.Streams.Stream_Element_Array :=
           [16#30#, 16#03#, 16#02#, 16#01#, 16#05#];
         Pos    : Ada.Streams.Stream_Element_Offset := Data'First;
         Seq    : ASN1_Element;
         Status : Err.Decode_Status;
         Value  : Natural;
      begin
         DER.Read_Sequence (Data, Pos, Data'Last, 0, Limits, Seq, Status);
         Check (Status = Err.Ok, "DER reads a SEQUENCE header");
         Check (Seq.Constructed, "a SEQUENCE is constructed");
         Check (Content_Length (Seq) = 3, "SEQUENCE content is three octets");
         Check (Encoded_First (Seq) = Data'First
                and then Encoded_Last (Seq) = Data'Last,
                "the encoded range covers the whole TLV, header included");
         Check (DER.At_End (Pos, Data'Last),
                "reading an element advances past it");

         Pos := Seq.First;
         DER.Read_Small_Integer
           (Data, Pos, Seq.Last, 1, Limits, Value, Status);
         Check (Status = Err.Ok and then Value = 5,
                "DER reads a nested INTEGER");
         Check (DER.At_End (Pos, Seq.Last), "the SEQUENCE is consumed");
      end;

      --  Indefinite length is BER. Refusing it is the point.
      Expect ([16#30#, 16#80#, 16#00#, 16#00#], Err.Unsupported_Encoding,
              "indefinite length is refused");

      --  A BIT STRING's padding bits must be zero (X.690 11.2.1). This is not
      --  pedantry: the key-usage reader indexes bits straight out of the
      --  octets, so a certificate that set a bit inside the padding would
      --  claim a usage its own encoding does not grant. 03 02 04 18 says four
      --  unused bits over 0001_1000, whose lowest four are not all zero.
      --
      --  Read rather than Expect, because Expect drives the generic TLV
      --  reader, which does not look inside a BIT STRING -- the first version
      --  of this test used it and reported the rule missing when it was the
      --  test aimed at the wrong door.
      declare
         procedure Expect_Bits
           (Data    : Ada.Streams.Stream_Element_Array;
            Wanted  : Err.Decode_Status;
            Message : String)
         is
            Pos    : Ada.Streams.Stream_Element_Offset := Data'First;
            Item   : ASN1_Element;
            Unused : Natural;
            Status : Err.Decode_Status;
         begin
            DER.Read_Bit_String
              (Data, Pos, Data'Last, 0, Limits, Item, Unused, Status);
            Check (Status = Wanted,
                   Message & ": expected " & Err.Status_Image (Wanted)
                   & ", got " & Err.Status_Image (Status));
         end Expect_Bits;
      begin
         Expect_Bits ([16#03#, 16#02#, 16#04#, 16#18#], Err.Non_Canonical_DER,
                      "a BIT STRING with a bit set in its padding is refused");
         --  The same shape with the padding clear is accepted, so the refusal
         --  is aimed at the padding and not the encoding around it.
         Expect_Bits ([16#03#, 16#02#, 16#04#, 16#10#], Err.Ok,
                      "and the same string with clear padding is accepted");
         --  And a count above seven was already refused; kept beside its
         --  neighbour so the two rules are read together.
         Expect_Bits ([16#03#, 16#02#, 16#08#, 16#00#], Err.Invalid_Value,
                      "more than seven unused bits is refused");
      end;

      --  Long form where the short form would do.
      Expect ([16#04#, 16#81#, 16#01#, 16#41#], Err.Non_Canonical_DER,
              "a length in long form that fits the short form is refused");
      Expect ([16#04#, 16#82#, 16#00#, 16#81#], Err.Non_Canonical_DER,
              "a length with a leading zero octet is refused");
      Expect ([16#04#, 16#FF#, 16#01#], Err.Invalid_Length,
              "the reserved length octet is refused");

      --  A length the buffer cannot satisfy.
      Expect ([16#04#, 16#05#, 16#01#, 16#02#], Err.Truncated_Input,
              "a length past the end of the buffer is refused");
      Expect ([16#04#], Err.Truncated_Input, "a header with no length is refused");

      --  High-tag-number form used for a tag that fits the identifier octet.
      Expect ([16#1F#, 16#01#, 16#00#], Err.Non_Canonical_DER,
              "a high-tag form for a low tag number is refused");
      Expect ([16#1F#, 16#80#, 16#01#, 16#00#], Err.Non_Canonical_DER,
              "a high tag padded with a leading zero group is refused");

      --  Nesting, against a deliberately shallow limit.
      declare
         Shallow : constant Decode_Limits :=
           (Maximum_Input_Size     => 1024,
            Maximum_Nesting_Depth  => 2,
            Maximum_Sequence_Items => 16,
            Maximum_String_Length  => 256);
         Data : constant Ada.Streams.Stream_Element_Array :=
           [16#30#, 16#02#, 16#05#, 16#00#];
         Pos    : Ada.Streams.Stream_Element_Offset := Data'First;
         Item   : ASN1_Element;
         Status : Err.Decode_Status;
      begin
         DER.Read (Data, Pos, Data'Last, 3, Shallow, Item, Status);
         Check (Status = Err.Excessive_Nesting,
                "a read below the depth limit is refused");
      end;

      --  A length larger than the caller will decode.
      declare
         Tight : constant Decode_Limits :=
           (Maximum_Input_Size     => 100,
            Maximum_Nesting_Depth  => 8,
            Maximum_Sequence_Items => 16,
            Maximum_String_Length  => 100);
         Data : constant Ada.Streams.Stream_Element_Array :=
           [16#04#, 16#82#, 16#01#, 16#00#];
         Pos    : Ada.Streams.Stream_Element_Offset := Data'First;
         Item   : ASN1_Element;
         Status : Err.Decode_Status;
      begin
         DER.Read (Data, Pos, Data'Last, 0, Tight, Item, Status);
         Check (Status = Err.Size_Limit_Exceeded,
                "a length beyond the caller's limit is refused");
      end;

      --  INTEGER: shortest form, and the sign rules that go with it.
      declare
         Pos      : Ada.Streams.Stream_Element_Offset;
         Item     : ASN1_Element;
         Negative : Boolean;
         Status   : Err.Decode_Status;

         Padded   : constant Ada.Streams.Stream_Element_Array :=
           [16#02#, 16#02#, 16#00#, 16#01#];
         Legal    : constant Ada.Streams.Stream_Element_Array :=
           [16#02#, 16#02#, 16#00#, 16#80#];
         Signed   : constant Ada.Streams.Stream_Element_Array :=
           [16#02#, 16#01#, 16#FF#];
         Empty    : constant Ada.Streams.Stream_Element_Array :=
           [16#02#, 16#00#];
      begin
         Pos := Padded'First;
         DER.Read_Integer
           (Padded, Pos, Padded'Last, 0, Limits, Item, Negative, Status);
         Check (Status = Err.Non_Canonical_DER,
                "an INTEGER with a redundant leading zero is refused");

         --  The same leading zero is required here: without it the value
         --  would read as negative.
         Pos := Legal'First;
         DER.Read_Integer
           (Legal, Pos, Legal'Last, 0, Limits, Item, Negative, Status);
         Check (Status = Err.Ok and then not Negative,
                "an INTEGER whose leading zero carries the sign is accepted");

         Pos := Signed'First;
         DER.Read_Integer
           (Signed, Pos, Signed'Last, 0, Limits, Item, Negative, Status);
         Check (Status = Err.Ok and then Negative,
                "a negative INTEGER is reported as negative");

         Pos := Signed'First;
         declare
            Value : Natural;
         begin
            DER.Read_Small_Integer
              (Signed, Pos, Signed'Last, 0, Limits, Value, Status);
            Check (Status = Err.Invalid_Value,
                   "a negative INTEGER is not a small non-negative one");
         end;

         Pos := Empty'First;
         DER.Read_Integer
           (Empty, Pos, Empty'Last, 0, Limits, Item, Negative, Status);
         Check (Status = Err.Invalid_Value,
                "an INTEGER with no content octets is refused");
      end;

      --  BOOLEAN: DER fixes true at all bits set.
      declare
         Pos    : Ada.Streams.Stream_Element_Offset;
         Value  : Boolean;
         Status : Err.Decode_Status;

         Yes  : constant Ada.Streams.Stream_Element_Array :=
           [16#01#, 16#01#, 16#FF#];
         No   : constant Ada.Streams.Stream_Element_Array :=
           [16#01#, 16#01#, 16#00#];
         Odd  : constant Ada.Streams.Stream_Element_Array :=
           [16#01#, 16#01#, 16#01#];
      begin
         Pos := Yes'First;
         DER.Read_Boolean (Yes, Pos, Yes'Last, 0, Limits, Value, Status);
         Check (Status = Err.Ok and then Value, "BOOLEAN 16#FF# is true");

         Pos := No'First;
         DER.Read_Boolean (No, Pos, No'Last, 0, Limits, Value, Status);
         Check (Status = Err.Ok and then not Value, "BOOLEAN 16#00# is false");

         Pos := Odd'First;
         DER.Read_Boolean (Odd, Pos, Odd'Last, 0, Limits, Value, Status);
         Check (Status = Err.Invalid_Value,
                "any other BOOLEAN octet is refused, however BER reads it");
      end;

      --  BIT STRING: the unused-bit count is consumed, not handed back as
      --  part of the value.
      declare
         Pos     : Ada.Streams.Stream_Element_Offset;
         Item    : ASN1_Element;
         Unused  : Natural;
         Status  : Err.Decode_Status;

         Key   : constant Ada.Streams.Stream_Element_Array :=
           [16#03#, 16#03#, 16#00#, 16#AB#, 16#CD#];
         Wide  : constant Ada.Streams.Stream_Element_Array :=
           [16#03#, 16#02#, 16#08#, 16#00#];
         Bare  : constant Ada.Streams.Stream_Element_Array :=
           [16#03#, 16#01#, 16#03#];
         None  : constant Ada.Streams.Stream_Element_Array :=
           [16#03#, 16#00#];
      begin
         Pos := Key'First;
         DER.Read_Bit_String
           (Key, Pos, Key'Last, 0, Limits, Item, Unused, Status);
         Check (Status = Err.Ok and then Unused = 0
                and then Content_Length (Item) = 2
                and then Key (Item.First) = 16#AB#,
                "a BIT STRING yields its value without the unused-bit octet");

         Pos := Wide'First;
         DER.Read_Bit_String
           (Wide, Pos, Wide'Last, 0, Limits, Item, Unused, Status);
         Check (Status = Err.Invalid_Value,
                "more than seven unused bits is refused");

         Pos := Bare'First;
         DER.Read_Bit_String
           (Bare, Pos, Bare'Last, 0, Limits, Item, Unused, Status);
         Check (Status = Err.Invalid_Value,
                "unused bits with no value octets is refused");

         Pos := None'First;
         DER.Read_Bit_String
           (None, Pos, None'Last, 0, Limits, Item, Unused, Status);
         Check (Status = Err.Invalid_Value,
                "a BIT STRING without its unused-bit octet is refused");
      end;

      --  NULL carries nothing.
      declare
         Pos    : Ada.Streams.Stream_Element_Offset;
         Status : Err.Decode_Status;

         Good : constant Ada.Streams.Stream_Element_Array := [16#05#, 16#00#];
         Bad  : constant Ada.Streams.Stream_Element_Array :=
           [16#05#, 16#01#, 16#00#];
      begin
         Pos := Good'First;
         DER.Read_Null (Good, Pos, Good'Last, 0, Limits, Status);
         Check (Status = Err.Ok, "an empty NULL is accepted");

         Pos := Bad'First;
         DER.Read_Null (Bad, Pos, Bad'Last, 0, Limits, Status);
         Check (Status = Err.Invalid_Value, "a NULL with content is refused");
      end;

      --  OBJECT IDENTIFIER: encoding rules, then a match against the table.
      declare
         Pos    : Ada.Streams.Stream_Element_Offset;
         Item   : ASN1_Element;
         Status : Err.Decode_Status;

         --  ecdsa-with-SHA384, as it appears in a certificate this crate
         --  issues under a P-384 CA.
         Sig : constant Ada.Streams.Stream_Element_Array :=
           [16#06#, 16#08#, 16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#04#,
            16#03#, 16#03#];
         CN  : constant Ada.Streams.Stream_Element_Array :=
           [16#06#, 16#03#, 16#55#, 16#04#, 16#03#];
         Pad : constant Ada.Streams.Stream_Element_Array :=
           [16#06#, 16#02#, 16#80#, 16#01#];
         Cut : constant Ada.Streams.Stream_Element_Array :=
           [16#06#, 16#02#, 16#55#, 16#81#];
      begin
         Pos := Sig'First;
         DER.Read_Object_Identifier
           (Sig, Pos, Sig'Last, 0, Limits, Item, Status);
         Check (Status = Err.Ok, "a well-formed OID is accepted");
         Check (CryptoLib.ASN1.OIDs.Matches
                  (Sig, Item, CryptoLib.ASN1.OIDs.ECDSA_With_SHA384),
                "the OID table recognises ecdsa-with-SHA384");
         Check (not CryptoLib.ASN1.OIDs.Matches
                  (Sig, Item, CryptoLib.ASN1.OIDs.ECDSA_With_SHA256),
                "a different signature OID does not match");

         Pos := CN'First;
         DER.Read_Object_Identifier
           (CN, Pos, CN'Last, 0, Limits, Item, Status);
         Check (Status = Err.Ok
                and then CryptoLib.ASN1.OIDs.Matches
                           (CN, Item, CryptoLib.ASN1.OIDs.Common_Name),
                "the OID table recognises id-at-commonName");
         Check (not CryptoLib.ASN1.OIDs.Matches
                  (CN, Item, CryptoLib.ASN1.OIDs.Organization),
                "a shorter arc list does not match a longer identifier");

         Pos := Pad'First;
         DER.Read_Object_Identifier
           (Pad, Pos, Pad'Last, 0, Limits, Item, Status);
         Check (Status = Err.Non_Canonical_DER,
                "an OID arc padded with a leading zero group is refused");

         Pos := Cut'First;
         DER.Read_Object_Identifier
           (Cut, Pos, Cut'Last, 0, Limits, Item, Status);
         Check (Status = Err.Invalid_Value,
                "an OID ending mid-arc is refused");
      end;

      --  A tag that is not the one required.
      declare
         Data : constant Ada.Streams.Stream_Element_Array :=
           [16#02#, 16#01#, 16#05#];
         Pos    : Ada.Streams.Stream_Element_Offset := Data'First;
         Item   : ASN1_Element;
         Status : Err.Decode_Status;
      begin
         DER.Read_Sequence (Data, Pos, Data'Last, 0, Limits, Item, Status);
         Check (Status = Err.Invalid_Tag,
                "an INTEGER read as a SEQUENCE is refused");
         Check (Pos = Data'First,
                "a refused read leaves the position where it was");
      end;
   end Check_ASN1_DER;

   --  Malformed input must come back as a status, never as an exception.
   --
   --  A library that parses what an attacker sends and lets an exception out
   --  has turned a malformed message into a denial of service, which is a
   --  vulnerability in a component whose whole contract is to fail closed.
   --  The seed is a real certificate; the mutations are deterministic, so a
   --  failure here reproduces exactly rather than once in a while.
   procedure Check_Decoder_Robustness is
      use type CryptoLib.ASN1.Errors.Decode_Status;

      package X509C renames CryptoLib.X509.Certificates;
      package XC renames CryptoLib.X509.CRLs;
      package CO renames CryptoLib.OCSP;

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

      function Decoded_Bytes (Text : String)
        return Ada.Streams.Stream_Element_Array
      is
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Text)));
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Text'First;
         P      : CryptoLib.PEM.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Text, CryptoLib.PEM.Certificate_Label, From, Buffer, Last, P);
         return Buffer (Buffer'First .. Last);
      end Decoded_Bytes;

      CA_PEM   : Unbounded_String;
      CA_Key   : Unbounded_String;
      Leaf_PEM : Unbounded_String;
      Leaf_Key : Unbounded_String;
      Outcome  : CryptoLib.Certificates.Certificate_Status;

      --  A deterministic generator: the suite must fail the same way twice.
      State : Interfaces.Unsigned_64 := 16#2545F4914F6CDD1D#;
      function Next return Natural is
         use type Interfaces.Unsigned_64;
      begin
         State := State xor Interfaces.Shift_Left (State, 13);
         State := State xor Interfaces.Shift_Right (State, 7);
         State := State xor Interfaces.Shift_Left (State, 17);
         return Natural (State mod 65_536);
      end Next;

      Raised  : Natural := 0;
      Decoded : Natural := 0;
      Rounds  : constant := 3_000;

      --  A second seed, carrying every policy extension and both qualifier
      --  kinds. The issued certificate above carries none, so without this
      --  the policy parsers never see a mutated byte -- and they are five
      --  readers of attacker-supplied extension values.
      Policy_Seed_DER : constant String :=
        "30820249308201cea003020102021457dc68c06a8727f75fca6853854da359d207b6fc300a06082a8648ce3d04" &
        "030230163114301206035504030c0b706f6c6963792d726f6f74301e170d3236303732393037343631385a170d" &
        "3237303532353037343631385a30163114301206035504030c0b706f6c6963792d726f6f743076301006072a86" &
        "48ce3d020106052b8104002203620004fab57ef5a1788133397062176d5925a43cd8595df917f6743c6323355d" &
        "2658e3173fce28a87905f80b9ba83ee1aab697a7bb599368c751864a56fbaa711e5b2726530bc20c83714e3ce3" &
        "718536a74005d731b1489eb8e166434548c44d69b0cfa381dc3081d9300f0603551d130101ff040530030101ff" &
        "300e0603551d0f0101ff0404030201063081960603551d2004818e30818b30818806092b06010401868d1f0130" &
        "7b302906082b06010505070201161d68747470733a2f2f6578616d706c652e746573742f6370732e68746d6c30" &
        "4e06082b060105050702023042301a1a104578616d706c652054657374204f726730060201010201021a244973" &
        "7375656420756e64657220746865206578616d706c65207465737420706f6c696379301d0603551d0e04160414" &
        "208a7da7f801c4b3c24c5dea13986578cbec0ed6300a06082a8648ce3d0403020369003066023100d3a5eb9ed0" &
        "6bc532ebf2da5d489183d0d4f082690d1e888f8ea954e0594b77d2a9d2494c620bc7665fec33b9f48809510231" &
        "00e86ff2b3713b9ba9a632c6a0fa424829c0548fee20becea5932b0f3e759885375e1feb99b0a882cd62789cfe" &
        "ea02f666";
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("robustness-ca", CA_PEM, CA_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "host.example",
           [1 => To_Unbounded_String ("host.example")],
           Leaf_PEM, Leaf_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: leaf issued");

      declare
         Issued : constant Ada.Streams.Stream_Element_Array :=
           Decoded_Bytes (To_String (Leaf_PEM));
         With_Policies : constant Ada.Streams.Stream_Element_Array :=
           From_Hex (Policy_Seed_DER);
      begin
         Check (Issued'Length > 64, "fixture: the seed certificate decoded");
         Check (With_Policies'Length > 64,
                "fixture: the policy-carrying seed decoded");

         for Round in 1 .. Rounds loop
            declare
               --  Alternating, so both shapes are mutated equally.
               Seed : constant Ada.Streams.Stream_Element_Array :=
                 (if Round mod 2 = 0 then Issued else With_Policies);
               Work : Ada.Streams.Stream_Element_Array := Seed;
               Cuts : constant Natural := 1 + Next mod 6;
               Last : Ada.Streams.Stream_Element_Offset := Work'Last;
            begin
               for Edit in 1 .. Cuts loop
                  declare
                     Where : constant Ada.Streams.Stream_Element_Offset :=
                       Work'First
                       + Ada.Streams.Stream_Element_Offset
                           (Next mod Natural (Work'Length));
                  begin
                     case Next mod 3 is
                        when 0 =>
                           --  A byte anywhere.
                           Work (Where) :=
                             Ada.Streams.Stream_Element (Next mod 256);
                        when 1 =>
                           --  Something that looks like a length, which is
                           --  where a reader is most likely to be led astray.
                           Work (Where) :=
                             (case Next mod 6 is
                                 when 0 => 16#80#,
                                 when 1 => 16#81#,
                                 when 2 => 16#82#,
                                 when 3 => 16#84#,
                                 when 4 => 16#FF#,
                                 when others => 16#00#);
                        when others =>
                           --  Truncation.
                           if Where > Work'First then
                              Last :=
                                Ada.Streams.Stream_Element_Offset'Min
                                  (Last, Where);
                           end if;
                     end case;
                  end;
               end loop;

               --  Every decoder sees every input. A mutated certificate is
               --  not a CRL, but the CRL reader still walks into it, and
               --  walking into the wrong thing is exactly the case that has
               --  to stay safe.
               declare
                  Input  : Ada.Streams.Stream_Element_Array
                    renames Work (Work'First .. Last);
                  Status : CryptoLib.ASN1.Errors.Decode_Status;
               begin
                  declare
                     C : constant X509C.Certificate :=
                       X509C.Decode_DER
                         (Input, CryptoLib.ASN1.Default_Limits, Status);
                  begin
                     if X509C.Is_Present (C) then
                        Decoded := Decoded + 1;

                        --  Read every policy extension and the qualifier
                        --  text: a parser that returns a status and then
                        --  hands back a span that blows up on use has not
                        --  failed safely.
                        declare
                           package PP renames CryptoLib.X509.Policies;
                           Named : constant PP.Policy_Set :=
                             PP.Policies_Of (C);
                           Maps  : constant PP.Mapping_Set :=
                             PP.Mappings_Of (C);
                           Cons  : constant PP.Policy_Constraints :=
                             PP.Constraints_Of (C);
                           Inh   : constant PP.Inhibit_Any_Policy :=
                             PP.Inhibit_Of (C);
                        begin
                           for P in 1 .. Named.Count loop
                              for Q in 1 ..
                                Named.Entries (P).Qualifier_Count
                              loop
                                 declare
                                    Text : constant String :=
                                      Named.Entries (P).Qualifiers (Q).Text
                                        (1 .. Named.Entries (P).Qualifiers (Q)
                                                .Length);
                                 begin
                                    pragma Unreferenced (Text);
                                 end;
                              end loop;
                           end loop;
                           pragma Unreferenced (Maps, Cons, Inh);
                        end;

                        for I in 1 .. X509C.Extension_Count (C) loop
                           declare
                              Ignore : constant CryptoLib.ASN1.Octets :=
                                X509C.Extension_Value (C, I);
                           begin
                              pragma Unreferenced (Ignore);
                           end;
                        end loop;
                     end if;
                  end;

                  declare
                     L : constant XC.Revocation_List :=
                       XC.Decode_DER
                         (Input, CryptoLib.ASN1.Default_Limits, Status);
                     N : constant Natural := XC.Entry_Count (L);
                     B : constant Boolean :=
                       XC.Has_Unsupported_Critical_Extension (L);
                  begin
                     pragma Unreferenced (N, B);
                  end;

                  declare
                     R : constant CO.Response :=
                       CO.Decode_Response
                         (Input, CryptoLib.ASN1.Default_Limits, Status);
                     B : constant Boolean :=
                       CO.Has_Unsupported_Critical_Extension (R);
                  begin
                     pragma Unreferenced (B);
                  end;
               end;
            exception
               when others =>
                  Raised := Raised + 1;
            end;
         end loop;

         Check (Raised = 0,
                "no malformed input escaped as an exception, got"
                & Natural'Image (Raised) & " of" & Natural'Image (Rounds));

         --  Without this the check above passes trivially on input that
         --  never reaches the decoder at all.
         Check (Decoded > Rounds / 100,
                "and enough mutations still decoded to reach real code, got"
                & Natural'Image (Decoded));
      end;
   end Check_Decoder_Robustness;

   --  Signing a request somebody else wrote.
   --
   --  Only the refusal of a malformed request was pinned before, so the
   --  whole working path was untested: which key shape a request carries is
   --  discovered by trying each width in turn, and nothing checked that a
   --  request came back out as a certificate for the key it asked about.
   --  Getting that wrong issues a certificate for the wrong key, which is
   --  the one mistake a CA must not make.
   --
   --  Ed448 is here because it did not work. The width was never tried, so
   --  an Ed448 request was refused whatever the CA was -- and it could not
   --  have worked earlier anyway, since the proof of possession below is an
   --  Ed448 signature and this crate could not check one until recently.
   procedure Check_CSR_Signing is
      package X509C renames CryptoLib.X509.Certificates;
      use type CryptoLib.X509.Public_Key_Algorithm;
      use type CryptoLib.PEM.Decode_Status;

      CSR_Ed25519_PEM : constant String :=
        "-----BEGIN CERTIFICATE REQUEST-----" & ASCII.LF &
        "MIGVMEkCAQAwFjEUMBIGA1UEAwwLY3NyLmV4YW1wbGUwKjAFBgMrZXADIQBBJpvj" & ASCII.LF &
        "aZxK7SwC8CaIrLz4i3VkyTsS5Ye0XbklAWR4xaAAMAUGAytlcANBAD7itkSYJMpQ" & ASCII.LF &
        "1mMRDkJDhzFhJLlfw/wlENMXrdpzof7u/CKUOau7MH3hvXAClMOOG2bZGA9XhN83" & ASCII.LF &
        "uTKPDkS8Fw8=" & ASCII.LF &
        "-----END CERTIFICATE REQUEST-----";
      CSR_P384_PEM : constant String :=
        "-----BEGIN CERTIFICATE REQUEST-----" & ASCII.LF &
        "MIIBDTCBlQIBADAWMRQwEgYDVQQDDAtjc3IuZXhhbXBsZTB2MBAGByqGSM49AgEG" & ASCII.LF &
        "BSuBBAAiA2IABFi3dHDRyk+Dz18vqqw9bsGzjLJtbFBfcBV0mVLbpId0fu2kEriP" & ASCII.LF &
        "1strUf45B1XBcWJ+C2TSJp33iMQC4tutrr2rJDXzHm4Uv1I20NJFWI8pafnkXK7K" & ASCII.LF &
        "HnLtP8yccD8eg6AAMAoGCCqGSM49BAMCA2cAMGQCMG8MmYT9rRbmR02tbgqG8t9s" & ASCII.LF &
        "rc6Pw4tiwIKA7IgI6n0GST6UbigyR6vTEwjKkaOBVQIwNm8h1jfbSAAnyIXfWzHM" & ASCII.LF &
        "yU2TZ0M9TknrtxSFba6jEgMA1cj4t8kfPN+X9sFChPPd" & ASCII.LF &
        "-----END CERTIFICATE REQUEST-----";
      CSR_Ed448_PEM : constant String :=
        "-----BEGIN CERTIFICATE REQUEST-----" & ASCII.LF &
        "MIHgMGICAQAwFjEUMBIGA1UEAwwLY3NyLmV4YW1wbGUwQzAFBgMrZXEDOgANH4DL" & ASCII.LF &
        "Cg5y24zB0yCYnWMlf6CVxn2+dh9q/uDI8pi6uwTgXc24ANumjZSyuSScgvBSwKxM" & ASCII.LF &
        "BgOMgQCgADAFBgMrZXEDcwCiHVlUdTjRU8vk0KbthD7WYlBi4u9mTp7GQEHIjR0R" & ASCII.LF &
        "9NlFfTxY/3vY3VLRcZOkeBIkuvr5iJ6EeoD53Wi6dd02QG+K9BMGLQ2URuJWpzaF" & ASCII.LF &
        "YAWCJiwoap6pUSg3bUe6wUOkMnPzurMPfMLXo439xNeDGQA=" & ASCII.LF &
        "-----END CERTIFICATE REQUEST-----";
      CSR_Ed448_Tampered_PEM : constant String :=
        "-----BEGIN CERTIFICATE REQUEST-----" & ASCII.LF &
        "MIHgMGICAQAwFjEUMBIGA1UEAwwLY3NyLmV4YW1wbGUwQzAFBgMrZXEDOgANH4DL" & ASCII.LF &
        "Cg5y24zB0yCYnWMlf6CVxn2+dh9q/uDI8pi6uwTgXc24ANumjZSyuSScgvBSwKxM" & ASCII.LF &
        "BgOMgQCgADAFBgMrZXEDcwCiHVlUdTjRU8vk0KbthD7WYlBi4u9mTp7GQEHIjR0R" & ASCII.LF &
        "9NlFfTxY/3vY3VLRcZOkeBIkuvr5iJ6EeoD53Wi6dd02QG+K9BMGLQ2URuJWpzaF" & ASCII.LF &
        "YAWCJiwoap6pUSg3bUe6wUOkMnPzurMPfMLXo439xNeDGQE=" & ASCII.LF &
        "-----END CERTIFICATE REQUEST-----";

      CSR_RSA_PEM : constant String :=
        "-----BEGIN CERTIFICATE REQUEST-----" & ASCII.LF &
        "MIICYzCCAUsCAQAwHjEcMBoGA1UEAwwTcnNhLnJlcXVlc3QuZXhhbXBsZTCCASIw" & ASCII.LF &
        "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMHCQpPTVm3pD0d9FUhUKBFZ+rPq" & ASCII.LF &
        "u5LusbTg+eAHU6j4m3yqjeTdRfLdwBPLDssTcFB7m26r3v9RiJvEbpgnAlA1n8L6" & ASCII.LF &
        "7xP8lfJeCOqCsGD4AVdE+WWUtUakOu5zuxGxbIy1/xY6Q64KFSbul2gT3nmnPBtx" & ASCII.LF &
        "ECpi44QVvr4SfAhmdNe8U6zvAnuA8D8ooFsIY/lT7tiKHnutkpnKfM+2CuHR3vcK" & ASCII.LF &
        "x/KMUEdY5segc44Cr2+BjvUyFEGYvh6teBoccOMMtr4C+wvmpsy0TszZDsl4L176" & ASCII.LF &
        "2XWcvfUKqEYEm3vpcgrWDONH+kKE4T/wiJFL7PtafRWpGvL5/M5dCTaVwFECAwEA" & ASCII.LF &
        "AaAAMA0GCSqGSIb3DQEBCwUAA4IBAQBPwYA3lAy0jS4hqUPnRz4xkMhPwer0LUaS" & ASCII.LF &
        "fEvOpbjqulmZfDBUQkfIFlve/JqRINCFUCH8gMR8/cFcL0eOhKIuax85tC75lgnP" & ASCII.LF &
        "Z+5bb/JN39u+JfTR5ouKwd+w9YFnslLr6a0X9OVu3Ids1bzZ15w+E30n/oy9YJHB" & ASCII.LF &
        "3nOPO2ZudZSxhi9+Y7jHSHHKMmAnzfShC+m909cuJCY2h1T9AD4d8ATghwGudXz2" & ASCII.LF &
        "ZrB+acI/Gw1Fdkxlx0F5WLvbQ1kfo1yqViQn2LChsB5Pmr0mVWRRnouVVTN8kx+x" & ASCII.LF &
        "LwEiIpsn8CcZ3Mipis3VpJ680SQybRVZXHuTs8SH7amS2CCUPc8f" & ASCII.LF &
        "-----END CERTIFICATE REQUEST-----";
      CSR_Spaced_Name_PEM : constant String :=
        "-----BEGIN CERTIFICATE REQUEST-----" & ASCII.LF &
        "MIICYjCCAUoCAQAwHTEbMBkGA1UEAwwSZXZpbC50ZXN0IGF0dGFja2VyMIIBIjAN" & ASCII.LF &
        "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwcJCk9NWbekPR30VSFQoEVn6s+q7" & ASCII.LF &
        "ku6xtOD54AdTqPibfKqN5N1F8t3AE8sOyxNwUHubbqve/1GIm8RumCcCUDWfwvrv" & ASCII.LF &
        "E/yV8l4I6oKwYPgBV0T5ZZS1RqQ67nO7EbFsjLX/FjpDrgoVJu6XaBPeeac8G3EQ" & ASCII.LF &
        "KmLjhBW+vhJ8CGZ017xTrO8Ce4DwPyigWwhj+VPu2Ioee62Smcp8z7YK4dHe9wrH" & ASCII.LF &
        "8oxQR1jmx6BzjgKvb4GO9TIUQZi+Hq14Ghxw4wy2vgL7C+amzLROzNkOyXgvXvrZ" & ASCII.LF &
        "dZy99QqoRgSbe+lyCtYM40f6QoThP/CIkUvs+1p9Faka8vn8zl0JNpXAUQIDAQAB" & ASCII.LF &
        "oAAwDQYJKoZIhvcNAQELBQADggEBADfiNY+VdyXZIGnRbzjjktEeUCq0lUdwwVbV" & ASCII.LF &
        "ybkl6IMMNw1BULUP1URRUwryWCwaRUyK+q36U4PeE+CI9TmtKErAVoXeNu8q/zox" & ASCII.LF &
        "DLQCwipPpeMuxM515axvMNMzwykPSl/QP6sfxBjuRcjy2jneslQsnOswBYJLh5tj" & ASCII.LF &
        "jJ8yo1k7rzux1RY6664BSEoQP3DnZpKiorni1sUJVjJRgViQ6iRG2mRrvAj7QOoB" & ASCII.LF &
        "l0I+uRR80TllKTruvHL3SnSiEqMe+cKJjHyrMiGTDZ3or8yYwcbeBYV5lOmCAPhK" & ASCII.LF &
        "FBabLd9d9PsQKF71JI0X8KzIGU0M+6XtKQasiqDpBJsr5BTnmdE=" & ASCII.LF &
        "-----END CERTIFICATE REQUEST-----";
      CA_Cert, CA_Key : Unbounded_String;

      --  The issued certificate's own subject key algorithm, read back from
      --  the DER rather than assumed from what went in.
      function Issued_Key_Kind (Certificate_PEM : String)
        return CryptoLib.X509.Public_Key_Algorithm
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
            return CryptoLib.X509.Unknown_Public_Key_Algorithm;
         end if;
         return X509C.Public_Key_Algorithm_Of
                  (X509C.Decode_DER
                     (Buffer (Buffer'First .. Last),
                      CryptoLib.ASN1.Default_Limits, Status));
      end Issued_Key_Kind;

      procedure One_Request
        (Label    : String;
         Request  : String;
         Expected : CryptoLib.X509.Public_Key_Algorithm)
      is
         Issued : Unbounded_String;
      begin
         Check (CryptoLib.Certificates.Sign_CSR
                  (To_String (CA_Cert), To_String (CA_Key), Request, Issued)
                = CryptoLib.Certificates.Ok,
                Label & " request is signed");
         Check (Issued_Key_Kind (To_String (Issued)) = Expected,
                Label & " certificate carries the key the request asked "
                & "about, not the CA's");
         Check (OpenSSL_Interop.Chain_Verifies
                  (To_String (CA_Cert), To_String (Issued)),
                Label & " certificate verifies against its CA in OpenSSL");
      end One_Request;
   begin
      Check (CryptoLib.Certificates.Create_Local_CA ("csr-signing-ca",
                                                     CA_Cert, CA_Key)
             = CryptoLib.Certificates.Ok,
             "a CA to sign requests with");

      One_Request ("an Ed25519", CSR_Ed25519_PEM, CryptoLib.X509.Ed25519);
      One_Request ("a P-384", CSR_P384_PEM, CryptoLib.X509.ECDSA_P384);
      One_Request ("an Ed448", CSR_Ed448_PEM, CryptoLib.X509.Ed448);

      --  RSA, which this crate can verify but cannot generate. Signing a
      --  request needs neither: the CA signs with its own key and the
      --  subject's goes in as the request encoded it. Refused outright until
      --  the widths stopped being tried one at a time.
      One_Request ("an RSA", CSR_RSA_PEM, CryptoLib.X509.RSA);

      --  The name in the request becomes the name in the certificate, so a
      --  request cannot ask for one that is not a name. "evil.test
      --  attacker" is a dNSName no resolver will ever answer for and two
      --  parsers may disagree about -- the same hazard as a NUL in a name,
      --  which this crate refuses elsewhere. The profile paths have always
      --  checked the names they are given; this one signed whatever the
      --  request put in its common name.
      declare
         Issued : Unbounded_String;
      begin
         Check (CryptoLib.Certificates.Sign_CSR
                  (To_String (CA_Cert), To_String (CA_Key),
                   CSR_Spaced_Name_PEM, Issued)
                /= CryptoLib.Certificates.Ok,
                "a request whose common name is not a name is refused");
         Check (Length (Issued) = 0,
                "and nothing is issued carrying it");
      end;

      --  A request is a claim to hold a key, and its signature is the only
      --  thing behind that claim. Signing one that does not check would
      --  certify a key to whoever asked rather than to whoever holds it.
      declare
         Issued : Unbounded_String;
      begin
         Check (CryptoLib.Certificates.Sign_CSR
                  (To_String (CA_Cert), To_String (CA_Key),
                   CSR_Ed448_Tampered_PEM, Issued)
                /= CryptoLib.Certificates.Ok,
                "a request whose own signature does not check is refused");
         Check (Length (Issued) = 0,
                "and no certificate comes out of it");
      end;
   end Check_CSR_Signing;

   --  A real OpenSSH private key, opened with nothing but this crate.
   --
   --  SECURITY.md used to claim bcrypt was "proven by decrypting a real
   --  OpenSSH key". That proof lived somewhere else, and when the KAT was
   --  added a few commits ago the claim was narrowed to match what is
   --  actually here. This puts the original claim back, earned: the key
   --  below came out of ssh-keygen, and what opens it is bcrypt_pbkdf for
   --  the key material and AES-256-CTR for the blob, both from this crate.
   --
   --  Two primitives against a third party's artifact catches what neither
   --  KAT can. A vector proves each one computes what its own specification
   --  says; this proves they agree with what OpenSSH actually wrote, in the
   --  order and the widths it wrote it -- 32 bytes of key and 16 of IV cut
   --  from one 48-byte derivation.
   procedure Check_OpenSSH_Key_Unlock is
      OpenSSH_Salt : constant String :=
        "2a44a1b83faf7d1cac356a66592e5cca";
      OpenSSH_Blob : constant String :=
        "bbe192ee2b44570b362c32d3bedb15f91cdc535243911677e733050c34c02d6f698ff951949d4e5587c8" &
        "23f77312e30943e8abcc2c2dedb45eb45d65f5336fb34df2c484559b53b24cbc71fc5e70404c8c2cda85" &
        "a6bf7b22e6186804a6a4101a5dfb2111a38898a7e1714fbbefc96c4d1e883a11340f03ed5a2ef5f8b762" &
        "ff300d194299eb451ab501170e1edb0bd4bb19e8ba5a5654e33ec1ce9d3f7c9ebe5f";
      OpenSSH_Rounds : constant := 24;

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

      --  The passphrase given to ssh-keygen.
      Passphrase : constant String := "correct horse";

      procedure Open_With (Pass : String; Ok : out Boolean;
                           Names_The_Key : out Boolean)
      is
         Material : Ada.Streams.Stream_Element_Array (1 .. 48);
         Blob     : constant Ada.Streams.Stream_Element_Array :=
           From_Hex (OpenSSH_Blob);
         Plain    : Ada.Streams.Stream_Element_Array (Blob'Range);
         Context  : CryptoLib.Ciphers.Cipher_State;
         Status   : CryptoLib.Errors.Status;
      begin
         Ok := False;
         Names_The_Key := False;

         Status :=
           CryptoLib.BCrypt_PBKDF.Derive
             (Pass, From_Hex (OpenSSH_Salt),
              Interfaces.Unsigned_32 (OpenSSH_Rounds), Material);
         if Status /= CryptoLib.Errors.Ok then
            return;
         end if;

         --  OpenSSH cuts one derivation into the key and the IV.
         Status :=
           CryptoLib.Ciphers.Initialize
             (Context, "aes256-ctr", CryptoLib.Ciphers.Client_To_Server,
              Material (1 .. 32), Material (33 .. 48));
         if Status /= CryptoLib.Errors.Ok then
            return;
         end if;

         Status := CryptoLib.Ciphers.Decrypt (Context, Blob, Plain);
         if Status /= CryptoLib.Errors.Ok then
            return;
         end if;

         --  The two check words OpenSSH writes at the head of the private
         --  section, equal only when the passphrase was right.
         Ok := Plain (Plain'First .. Plain'First + 3)
               = Plain (Plain'First + 4 .. Plain'First + 7);

         --  And past them, the key type as a length-prefixed string.
         declare
            Kind : constant Ada.Streams.Stream_Element_Array :=
              Plain (Plain'First + 8 .. Plain'First + 22);
         begin
            Names_The_Key :=
              Kind = From_Hex ("0000000b7373682d65643235353139");
         end;
      end Open_With;

      Unlocked, Named : Boolean;
   begin
      Open_With (Passphrase, Unlocked, Named);
      Check (Unlocked,
             "a key written by ssh-keygen opens with bcrypt_pbkdf and "
             & "AES-256-CTR from this crate");
      Check (Named,
             "and what comes out names itself ssh-ed25519, so the plaintext "
             & "is the key and not merely self-consistent");

      Open_With ("wrong horse", Unlocked, Named);
      Check (not Unlocked,
             "the wrong passphrase does not open it");
   end Check_OpenSSH_Key_Unlock;

   --  A signature OpenSSH made, checked here.
   --
   --  The Ed25519 vectors prove this computes what RFC 8032 says. They do
   --  not prove it agrees with what another implementation actually emits
   --  over bytes that implementation chose to frame its own way. This is
   --  ssh-keygen -Y sign: the signature is over the SSHSIG structure --
   --  a magic string, the namespace, the hash name and the SHA-512 of the
   --  file -- none of which this crate assembled.
   procedure Check_OpenSSH_Signature is
      SSHSIG_Public : constant String :=
        "b91b800e2174fc90ce2ef7f072a481cde08ef64e57a829ad260f9afd19f9199c";
      SSHSIG_Signature : constant String :=
        "6d79e9ebdc4545ab74b5070c58e910d0f39d0b66deac7415f8adb55e6fd77a718ffcf1ee5b1f56a2097e" &
        "57a347521d03af7a1e93e8414dae6682571f86f45108";
      SSHSIG_Signed : constant String :=
        "5353485349470000000963727970746f6c6962000000000000000673686135313200000040c91009ba89" &
        "2e18933ebd13f0d3228cde25b72da75dae9195ab38b62e46f6290f157b8f0dd6fa25e0fe25499b55f6b5" &
        "02158d23818827c7652194a69fe938d1c6";

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

      Signature : Ada.Streams.Stream_Element_Array (1 .. 64) :=
        From_Hex (SSHSIG_Signature);
      Signed    : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (SSHSIG_Signed'Length / 2)) :=
        From_Hex (SSHSIG_Signed);
   begin
      Check (CryptoLib.Ed25519.Verify
               (From_Hex (SSHSIG_Public), Signature, Signed)
             = CryptoLib.Errors.Ok,
             "a signature written by ssh-keygen verifies here");

      Signature (11) := Signature (11) xor 1;
      Check (CryptoLib.Ed25519.Verify
               (From_Hex (SSHSIG_Public), Signature, Signed)
             /= CryptoLib.Errors.Ok,
             "and one bit of it is enough to break it");
      Signature (11) := Signature (11) xor 1;

      Signed (Signed'Last) := Signed (Signed'Last) xor 1;
      Check (CryptoLib.Ed25519.Verify
               (From_Hex (SSHSIG_Public), Signature, Signed)
             /= CryptoLib.Errors.Ok,
             "as is one bit of what was signed");
   end Check_OpenSSH_Signature;

   --  Certification requests, against ones OpenSSL made and calls
   --  "self-signature verify OK".
   --
   --  The RSA request is the interesting one: the hand-written reader this
   --  replaced knew two algorithms, so an RSA request was simply unreadable.
   procedure Check_PKCS10 is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.X509.Public_Key_Algorithm;
      use type CryptoLib.X509.Signature_Algorithm;
      use type CryptoLib.X509.Signatures.Verification_Result;

      package P10 renames CryptoLib.PKCS10;

      CSR_RSA : constant String :=
        "308202633082014b020100301e311c301a06035504030c137273612e726571756573742e6578616d706c653082" &
        "0122300d06092a864886f70d01010105000382010f003082010a0282010100c1c24293d3566de90f477d154854" &
        "281159fab3eabb92eeb1b4e0f9e00753a8f89b7caa8de4dd45f2ddc013cb0ecb1370507b9b6eabdeff51889bc4" &
        "6e98270250359fc2faef13fc95f25e08ea82b060f8015744f96594b546a43aee73bb11b16c8cb5ff163a43ae0a" &
        "1526ee976813de79a73c1b71102a62e38415bebe127c086674d7bc53acef027b80f03f28a05b0863f953eed88a" &
        "1e7bad9299ca7ccfb60ae1d1def70ac7f28c504758e6c7a0738e02af6f818ef532144198be1ead781a1c70e30c" &
        "b6be02fb0be6a6ccb44eccd90ec9782f5efad9759cbdf50aa846049b7be9720ad60ce347fa4284e13ff088914b" &
        "ecfb5a7d15a91af2f9fcce5d093695c0510203010001a000300d06092a864886f70d01010b050003820101004f" &
        "c18037940cb48d2e21a943e7473e3190c84fc1eaf42d46927c4bcea5b8eaba59997c30544247c8165bdefc9a91" &
        "20d0855021fc80c47cfdc15c2f478e84a22e6b1f39b42ef99609cf67ee5b6ff24ddfdbbe25f4d1e68b8ac1dfb0" &
        "f58167b252ebe9ad17f4e56edc876cd5bcd9d79c3e137d27fe8cbd6091c1de738f3b666e7594b1862f7e63b8c7" &
        "4871ca326027cdf4a10be9bdd3d72e2426368754fd003e1df004e08701ae757cf666b07e69c23f1b0d45764c65" &
        "c7417958bbdb43591fa35caa562427d8b0a1b01e4f9abd265564519e8b9555337c931fb12f0122229b27f02719" &
        "dcc8a98acdd5a49ebcd124326d15595c7b93b3c487eda992d820943dcf1f";

      CSR_EC : constant String :=
        "3081d6307f020100301d311b301906035504030c1265632e726571756573742e6578616d706c65305930130607" &
        "2a8648ce3d020106082a8648ce3d030107034200048065edef6450ae2dd122ee3be6dd3e788e005e20718fd4ca" &
        "9ddcb1932f0abb8de8342e09ed93f3843807090c731e5aa1956f658349545f742a53e0008d0e970aa000300a06" &
        "082a8648ce3d0403020347003044022032a17de60ae9eeaca6e34dc95d4a28a7d6d4546a3fa85051460d510f84" &
        "fc122902204cfa118746d6f0419d522722f0a1a5d6ab34fe24109e33714197275afce901c7";

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
      declare
         Item : constant P10.Request :=
           P10.Decode_DER
             (From_Hex (CSR_RSA), CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok and then P10.Is_Present (Item),
                "an RSA request decodes: "
                & CryptoLib.ASN1.Errors.Status_Image (Status));
         Check (P10.Subject_Common_Name (Item) = "rsa.request.example",
                "its subject is read, got " & P10.Subject_Common_Name (Item));
         Check (P10.Public_Key_Algorithm_Of (Item) = CryptoLib.X509.RSA,
                "its key is recognised as RSA");
         Check (P10.Signature_Algorithm_Of (Item)
                  = CryptoLib.X509.SHA256_With_RSA,
                "its signature algorithm is read");
         Check (P10.Verify_Signature (Item)
                  = CryptoLib.X509.Signatures.Valid,
                "the requester proves possession of the key, got "
                & CryptoLib.X509.Signatures.Result_Image
                    (P10.Verify_Signature (Item)));
      end;

      declare
         Item : constant P10.Request :=
           P10.Decode_DER
             (From_Hex (CSR_EC), CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok, "an EC request decodes");
         Check (P10.Public_Key_Algorithm_Of (Item)
                  = CryptoLib.X509.ECDSA_P256,
                "its key is recognised as P-256");
         Check (P10.Verify_Signature (Item)
                  = CryptoLib.X509.Signatures.Valid,
                "and it too proves possession");
      end;

      --  A request altered after signing. The signature covers the name and
      --  the key, so changing either has to break it -- otherwise a request
      --  could be edited in flight to ask for a different name, which is the
      --  attack a CA reads this signature to prevent.
      declare
         Damaged : Ada.Streams.Stream_Element_Array := From_Hex (CSR_EC);
         Broken  : CryptoLib.ASN1.Errors.Decode_Status;
         Where   : Ada.Streams.Stream_Element_Offset := 0;
      begin
         --  Inside the subject's text rather than at an arbitrary offset: a
         --  character changes and every tag and length stays as it was, so
         --  the encoding still parses and only the signature can object.
         for I in Damaged'Range loop
            if I + 2 <= Damaged'Last
              and then Damaged (I) = Character'Pos ('r')
              and then Damaged (I + 1) = Character'Pos ('e')
              and then Damaged (I + 2) = Character'Pos ('q')
            then
               Where := I;
               exit;
            end if;
         end loop;
         Check (Where /= 0, "fixture: the subject text was found");
         Damaged (Where) := Character'Pos ('R');
         declare
            Item : constant P10.Request :=
              P10.Decode_DER
                (Damaged, CryptoLib.ASN1.Default_Limits, Broken);
         begin
            --  Asserted rather than guarded: a tamper that stopped being a
            --  tamper would otherwise skip the check it exists for.
            Check (Broken = CryptoLib.ASN1.Errors.Ok,
                   "the altered request still parses, so the signature is "
                   & "what has to reject it");
            Check (P10.Verify_Signature (Item)
                     /= CryptoLib.X509.Signatures.Valid,
                   "an altered request does not verify");
         end;
      end;

      --  Trailing bytes are refused, as on a certificate.
      declare
         Padded : constant Ada.Streams.Stream_Element_Array :=
           From_Hex (CSR_EC) & [0];
         Item   : constant P10.Request :=
           P10.Decode_DER (Padded, CryptoLib.ASN1.Default_Limits, Status);
         pragma Unreferenced (Item);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Trailing_Data,
                "a byte after the request is refused, got "
                & CryptoLib.ASN1.Errors.Status_Image (Status));
      end;
   end Check_PKCS10;

   --  PKCS#8 private keys, decoded from the structure rather than found by
   --  looking for bytes that resemble a key.
   procedure Check_PKCS8 is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.X509.Public_Key_Algorithm;

      package P8 renames CryptoLib.PKCS8;

      P8_EC : constant String :=
        "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b02010104300dbe7e740d398458dc39" &
        "a3f0d7e71e7132b65e26af9a13766441d3b1c79a30f141700119bb0be582c54a8f09fad2815ba16403620004d8" &
        "e1d6e84534ed29f11bc644c46499728c15b025b8bfbaa8238d053946fed7f22fced5751f61c20208bf534ec12e" &
        "1a8abf3ed710988a642539fd5e33f5da33755b63aad074d171ba133c82b99bfca240d3fd6e5408e0f2ca6b82d5" &
        "c721f9e7d8";

      P8_ED : constant String :=
        "302e020100300506032b65700422042080ab3b0dfee005444ee6adfa364f304e2ae937d00c1d30ce92cfeb3697" &
        "165818";

      P8_ENCRYPTED : constant String :=
        "3082011c305706092a864886f70d01050d304a302906092a864886f70d01050c301c0408284f2424c1ce1bd702" &
        "020800300c06082a864886f70d02090500301d060960864801650304012a04106fb723fb9ef3b3abd27e95015b" &
        "9e9bd40481c05a630d1d00b1af14808281d59b93505214f7d933ee5bf2a6d1d993b50beadc93404590b57d9f2e" &
        "543acae2938d951742ad0f56338ea5f27ae865c8f51cf900aae0c2ccd3bde779e0fe9dde9d8e9fe779c1e34602" &
        "976f3cd7b4320e251fdab8f79b02ac2d1e3093feba822275034d86bff7eaaa46aa7694705b98120138ff47dc89" &
        "68febec15edf5ccbf1749d626c53bca650c92de959bc6425624c83d6ab1e8922191a7e69713e9c4106140c8b98" &
        "91606bda2f21cc102304985001e9ca7e8f07";

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
      --  A P-384 key made by OpenSSL. The scalar is the octet string inside
      --  the ECPrivateKey, reached by walking there.
      declare
         Item : P8.Private_Key;
      begin
         P8.Decode_DER
           (From_Hex (P8_EC), CryptoLib.ASN1.Default_Limits, Item, Status);
         Check (Status = CryptoLib.ASN1.Errors.Ok and then P8.Is_Present (Item),
                "an EC private key decodes: "
                & CryptoLib.ASN1.Errors.Status_Image (Status));
         Check (P8.Algorithm_Of (Item) = CryptoLib.X509.ECDSA_P384,
                "its curve is read from the algorithm parameters");
         Check (P8.Private_Value (Item)'Length = 48,
                "a P-384 scalar is 48 octets, got"
                & Natural'Image (Natural (P8.Private_Value (Item)'Length)));

         --  Wiping is not only a matter of scope: it can be asked for.
         P8.Wipe (Item);
         Check (not P8.Is_Present (Item),
                "a wiped key is no longer present");
         Check (P8.Private_Value (Item)'Length = 0,
                "and holds nothing");
      end;

      declare
         Item : P8.Private_Key;
      begin
         P8.Decode_DER
           (From_Hex (P8_ED), CryptoLib.ASN1.Default_Limits, Item, Status);
         Check (Status = CryptoLib.ASN1.Errors.Ok,
                "an Ed25519 private key decodes");
         Check (P8.Algorithm_Of (Item) = CryptoLib.X509.Ed25519,
                "its algorithm is read");
         Check (P8.Private_Value (Item)'Length = 32,
                "the seed is 32 octets, unwrapped from the octet string that "
                & "this one encoding doubles up");
      end;

      --  An encrypted key needs a password, and there is nowhere here to put
      --  one. Refused as unsupported rather than read as if it were plain,
      --  which would yield ciphertext presented as a key.
      declare
         Item : P8.Private_Key;
      begin
         P8.Decode_DER
           (From_Hex (P8_ENCRYPTED), CryptoLib.ASN1.Default_Limits, Item,
            Status);
         Check (Status = CryptoLib.ASN1.Errors.Unsupported_Encoding,
                "an encrypted key is refused as unsupported, got "
                & CryptoLib.ASN1.Errors.Status_Image (Status));
         Check (not P8.Is_Present (Item),
                "and nothing is left behind from the attempt");
      end;

      --  Trailing data, as everywhere else.
      declare
         Item   : P8.Private_Key;
         Padded : constant Ada.Streams.Stream_Element_Array :=
           From_Hex (P8_ED) & [0];
      begin
         P8.Decode_DER
           (Padded, CryptoLib.ASN1.Default_Limits, Item, Status);
         Check (Status = CryptoLib.ASN1.Errors.Trailing_Data,
                "a byte after the key is refused");
      end;
   end Check_PKCS8;

   --  A configured identity: a chain and the key that goes with it, checked
   --  before anything tries to use them.
   --
   --  The two failures worth catching are a key that does not belong to the
   --  certificate and a chain assembled the wrong way round. Both are
   --  ordinary configuration mistakes that otherwise surface as a handshake
   --  failing somewhere far from the cause.
   procedure Check_Identities is
      use type CryptoLib.Identities.Identity_Status;
      use type CryptoLib.X509.Public_Key_Algorithm;

      package ID renames CryptoLib.Identities;

      CA_PEM    : Unbounded_String;
      CA_Key    : Unbounded_String;
      Leaf_PEM  : Unbounded_String;
      Leaf_Key  : Unbounded_String;
      Other_PEM : Unbounded_String;
      Other_Key : Unbounded_String;
      Outcome   : CryptoLib.Certificates.Certificate_Status;
   begin
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("identity-chain-ca", CA_PEM, CA_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "host.example",
           [1 => To_Unbounded_String ("host.example")],
           Leaf_PEM, Leaf_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: leaf issued");

      Outcome :=
        CryptoLib.Certificates.Issue_Server_Certificate
          (To_String (CA_PEM), To_String (CA_Key), "other.example",
           [1 => To_Unbounded_String ("other.example")],
           Other_PEM, Other_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: other leaf");

      --  Leaf then issuer, which is the order a PEM file and a TLS handshake
      --  both use.
      declare
         Item : ID.Local_Identity;
         St   : ID.Identity_Status;
      begin
         ID.Decode
           (To_String (Leaf_PEM) & To_String (CA_PEM),
            To_String (Leaf_Key), Item, St);
         Check (St = ID.Ok,
                "a chain and its own key check out, got "
                & ID.Status_Image (St));
         Check (ID.Is_Present (Item), "and the identity is present");
         Check (ID.Chain_Length (Item) = 2,
                "both certificates are held, got"
                & Natural'Image (ID.Chain_Length (Item)));
         Check (ID.Key_Algorithm_Of (Item) = CryptoLib.X509.ECDSA_P384,
                "the key algorithm is reported");
         Check (ID.Certificate_Bytes (Item, 1)'Length > 0
                and then ID.Certificate_Bytes (Item, 3)'Length = 0,
                "certificates are addressable and asking past the end is "
                & "empty");

         --  Wiping is not only end of scope.
         ID.Wipe (Item);
         Check (not ID.Is_Present (Item), "a wiped identity is not present");
         Check (ID.Chain_Length (Item) = 0, "and holds no chain");
      end;

      --  A leaf alone is a chain of one, which is ordinary.
      declare
         Item : ID.Local_Identity;
         St   : ID.Identity_Status;
      begin
         ID.Decode (To_String (Leaf_PEM), To_String (Leaf_Key), Item, St);
         Check (St = ID.Ok and then ID.Chain_Length (Item) = 1,
                "a single certificate and its key check out");
      end;

      --  The mistake this exists for: the wrong key.
      declare
         Item : ID.Local_Identity;
         St   : ID.Identity_Status;
      begin
         ID.Decode (To_String (Leaf_PEM), To_String (Other_Key), Item, St);
         Check (St = ID.Key_Mismatch,
                "a key from another certificate is refused, got "
                & ID.Status_Image (St));
         Check (not ID.Is_Present (Item),
                "and nothing is left usable behind it");
      end;

      --  And the other one: the chain upside down.
      declare
         Item : ID.Local_Identity;
         St   : ID.Identity_Status;
      begin
         ID.Decode
           (To_String (CA_PEM) & To_String (Leaf_PEM),
            To_String (Leaf_Key), Item, St);
         Check (St = ID.Chain_Out_Of_Order,
                "a chain in the wrong order is refused, got "
                & ID.Status_Image (St));
      end;

      --  An RSA identity, which is what most servers are configured with.
      --  Matching one needs no derivation: an RSA private key carries its own
      --  modulus and exponent, so the question is a comparison against the
      --  two integers in the certificate.
      declare
         RSA_Leaf_PEM : constant String :=
           "-----BEGIN CERTIFICATE-----" & ASCII.LF &
           "MIICuDCCAaACFAppZCkVsFVYh/Q8rXNvWMAD5p3rMA0GCSqGSIb3DQEBDAUAMBYx" & ASCII.LF &
           "FDASBgNVBAMMC3JzYS10ZXN0LWNhMB4XDTI2MDcyODE5MDMyNFoXDTI3MDcyODE5" & ASCII.LF &
           "MDMyNFowGzEZMBcGA1UEAwwQbGVhZi5yc2EuZXhhbXBsZTCCASIwDQYJKoZIhvcN" & ASCII.LF &
           "AQEBBQADggEPADCCAQoCggEBAL0PmgpIoMyy+119Tl2IuJmaZBQosmMiazvJqC+A" & ASCII.LF &
           "w1Q/35AsX4a+lnnloFwXtCFvvfRhFXxOLSgHuXLfQFa1cu4UWCpQQL+NLcp7ymXu" & ASCII.LF &
           "6XR89USlUNtR1sz2NXaM+g4ufTZ6fN7HBaCrCMv9dUrD6LtXUhL37zDecH//mkrA" & ASCII.LF &
           "PWtpm6FwRJv/KJgHODwv/kSLRG6UEtFik1Phro/L/9+HF3EULATMzrJUqdovR8HT" & ASCII.LF &
           "1KYDgU4CldGjOjZkw6ZoxmV+3L2d+pNT1F7kP4I98UPdALnr8qfWnLZBh76DoDWc" & ASCII.LF &
           "Czdvm4NfrunInxLrVqNB81lcYJIgpzs1AqpyPz83GUxlWLsCAwEAATANBgkqhkiG" & ASCII.LF &
           "9w0BAQwFAAOCAQEARn/i3pR71kW0nZ1kCb46LS1WiELjUdofM2XcU6/31LHTDsh7" & ASCII.LF &
           "Lc2QuuZuFLk03b5OFEUvawoaMKybtJpPQOJvSuJGvKyfFRNIgnRneWJmpPfM09za" & ASCII.LF &
           "Ubf/AnjZmyZMxJHthFm+4ap3/BEFoPRpVC38c7TwUS3LYl+P3Yp2Ihh5DXpPUiCU" & ASCII.LF &
           "A4yX4mbW3k8iRgcETeyLHtORF2x0fzrulKjD8zdxFFFwsehba9JbMU8w6DhpXLX0" & ASCII.LF &
           "QYt6k0zCkr0tqwxnSjA97/uXvtptXb/K5V/WRK+mbbfUxbz8PKwan6zkWBjwT9Hu" & ASCII.LF &
           "/RjLDgPBgAA6BeNlZY3XkYFFz3w4MSz1sdeVew==" & ASCII.LF &
           "-----END CERTIFICATE-----";

         RSA_Leaf_Key : constant String :=
           "-----BEGIN PRIVATE KEY-----" & ASCII.LF &
           "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC9D5oKSKDMsvtd" & ASCII.LF &
           "fU5diLiZmmQUKLJjIms7yagvgMNUP9+QLF+GvpZ55aBcF7Qhb730YRV8Ti0oB7ly" & ASCII.LF &
           "30BWtXLuFFgqUEC/jS3Ke8pl7ul0fPVEpVDbUdbM9jV2jPoOLn02enzexwWgqwjL" & ASCII.LF &
           "/XVKw+i7V1IS9+8w3nB//5pKwD1raZuhcESb/yiYBzg8L/5Ei0RulBLRYpNT4a6P" & ASCII.LF &
           "y//fhxdxFCwEzM6yVKnaL0fB09SmA4FOApXRozo2ZMOmaMZlfty9nfqTU9Re5D+C" & ASCII.LF &
           "PfFD3QC56/Kn1py2QYe+g6A1nAs3b5uDX67pyJ8S61ajQfNZXGCSIKc7NQKqcj8/" & ASCII.LF &
           "NxlMZVi7AgMBAAECggEASWRiFvXkvjII1F0Na8/kYXSGvzChN0yoNhhtWqtwqCb3" & ASCII.LF &
           "gX9IQgWAYqeaXcWx3n0DT3fUoGG0s+Jzwj0aO87KY9Ov+hUXXYTPrtfpVTKum9La" & ASCII.LF &
           "X6CRR+J4MS6uyGunspOndduM1+qIq7tZed7VhoWQthEKwmRPDTh8kaPG4JfKAATe" & ASCII.LF &
           "yXaIJYxuwc1UvAyL23hlw2yLRtAzbpGC6W4MlK82JPMYRMhm8vauFktU3gigKBjc" & ASCII.LF &
           "9n10vwsMd5H8qU8jFS6knhiboQS2tnsrp0vyNDmILWxywtkm3nDK1xYDfzfP2Efb" & ASCII.LF &
           "QuM5SPXz0p0Nr7f487gdv63nF84oB82/EejrmQlGeQKBgQDvBtpMjhOSMhoIvtQJ" & ASCII.LF &
           "/QHcyEJUif2ybR/A1oAu0//qWGlYoY6liLBHsphffcfw0dXS71I/bAOxehtqjSN6" & ASCII.LF &
           "rbtfYw4Mg/GCDkiyHfM54Rn2nS3JKFgAvG6LQDBw/WbucKocGhlLA7Z20+ORCkgA" & ASCII.LF &
           "JMGPn2Kr/6IQ+vZSEhBBpCT3RQKBgQDKfHIHlw5j/iQZ6XAKNywsad7sUj8m2R+Y" & ASCII.LF &
           "dwE7tc7FxeQJ9TPhLpOUGuqlUPta+Lmo8VC4pGUleQjGUGe3M8Q8fleaUuE+FljR" & ASCII.LF &
           "BGFSXd01QCqk3w8Zerz8orPMdsC6mxVHHTe8zIzPqQzR+grrMFPXOB3RoyUQMgRd" & ASCII.LF &
           "ejC3+x4P/wKBgDYVmd2KpFkHJyblbvsXmY1IbuHMG3B9CptKrdRqudRfzu50F9/S" & ASCII.LF &
           "zvhaK+onfs8526UP689X9Hn7BCsW5nlCyEvsEOi6DjJ8YuySpE9rZMGNjSegDlGU" & ASCII.LF &
           "UXsGui9G1zyKl6MmMKTtoSLADRTre6E0r+t8iAodHKG093lYhv8jUg31AoGAMcCo" & ASCII.LF &
           "KBNGtu0QI8nG/MuXsAYHf1uqJrp81/KNvAUtHE1Gfefg6niOTHrcougmCrFItSku" & ASCII.LF &
           "I2BJdg6qSEgjY9F1a0PD9KherenBwwHng9yKaPYuRDqGtEUDQLQdp6SaMH/Al6un" & ASCII.LF &
           "MV21T6UDAGkG28kRILWqJgOHLNaNWgaXB+3M8jMCgYAleeSjeMEtygS6DnysgsDy" & ASCII.LF &
           "oXP1zYgSmCnpSiK/DkiL+yaoTQf+KxFdxxAZPEmeWD+VW4p2vzOvhWhJq6f87EoF" & ASCII.LF &
           "ArUwd/weVJXE9H+qGuqoIpJ/CnvIPRkzPGm9DxsY95w7DkLgn6tvz8OWfNU1+Sg4" & ASCII.LF &
           "K7QNFJW77PZJbezJ2ZRh6g==" & ASCII.LF &
           "-----END PRIVATE KEY-----";

         RSA_Other_Key : constant String :=
           "-----BEGIN PRIVATE KEY-----" & ASCII.LF &
           "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCnqIxwFIbJAdX0" & ASCII.LF &
           "kudx7n6KPClXjH89E0vsXbw0EhUksfU9B2UNOk75v1omI3FgfTk8pKLvS9LxkZPR" & ASCII.LF &
           "gIDJctkHfRNhJvvqD9psM8It9JIWtBW8fCgh072IFEQIjlA8+Af99PG5O4OEHlzm" & ASCII.LF &
           "dJT1dkP7Do838wt36s/TWLGOiBxm2J98omFWCOiWPhvpxVHpXXSxKXgVX2edtpa1" & ASCII.LF &
           "OHpoTLrBcgNYYDUMeldkgEIKqEQ9s4G5jgkyoPpP/7GWDx+WsGuRFD/zN+Q9aCbC" & ASCII.LF &
           "KIYVdqLHpUkbDS/EyMMEUiguhDzQ/EpahN9/XhMmTe66bC1sS3kux6CgD2N3DV4a" & ASCII.LF &
           "xjnR2hKfAgMBAAECggEABe1JCa1JsB46GHgZA0erF+siJJyS4u9yGUKdcWz/BY0R" & ASCII.LF &
           "xLzxYl/tUTOyiPNrAdfR1JL9YsULb/7CR8wcwWjBKcKbxmBA1F8H5n6HhTH5xO1M" & ASCII.LF &
           "Cp2/ZwxVM7pQejAnWTOerk7UCZHqoRqk4U2KkCLeKsHlzjrvuacgMbIXYZjuNOex" & ASCII.LF &
           "nkAz0OFf4ogHiplsSBsA7oeL34ZDlg/QFHlss531Mo5WESJEwVhe1kW4vhW9NyOI" & ASCII.LF &
           "lFpBAfs8Xr7PEL8XEoIagTNi3h3SR8QtReSfflWrSuUPCHQ4GpFs2EnUb/7OGrAH" & ASCII.LF &
           "RynjnZ0yNEtcYwrei0wPjdizlGpTvIAHIlsOuzaaAQKBgQDj+p1vdDML8v1o8SyF" & ASCII.LF &
           "+0P7d4cTwNaWoZQD95oaaO4Rj2GTvxJLoVF0/LnyEtuyFLQsKccP+4/mfYuV6n4E" & ASCII.LF &
           "Q9qkQdgXnHRhr1tArLQ9b7s9UCsE2ShxbQlgestNM06oW+keE3nvGCUX6xEP1KhI" & ASCII.LF &
           "yrHIWzRau4UN32LgGAxxue26wwKBgQC8Q/CP0VmqtA7KXwgf6nc8xLg50zzN2uAg" & ASCII.LF &
           "aR7zxZ4KYFkHs5wcpMJSpMu5n+w0zbApMtLBw4D+kILY4/3bJZ9NTx1Ml7+TnfSm" & ASCII.LF &
           "vTNVwc1tLvPdoyAV0FR9C0OuZ2dK7BZ93pq4afYsN0ODfmwG9JVPM4wLKV5LpQpE" & ASCII.LF &
           "dysqDW7y9QKBgETiQpOcjpf7san1xTgudZoTwZKsX6pf4/NW6w8zyUsxAZC82PBV" & ASCII.LF &
           "K+GnQx/rpsomC1KUxPsFTbOdF4ISukTbo8KhyoNH2LpzW6UtCcDOc8rQ4E60ts2e" & ASCII.LF &
           "3ohyUd9fs1KXgtZ9mAgwSXTyp9MatEZaSGF7fVQ0+Lz6VEvVuFzciwI1AoGBAJLu" & ASCII.LF &
           "QzU7IkwDsvdmK6UdDGo07cLThcTzabBh2nJObQWUJGfKWbBRNgfh7c21blfXoADH" & ASCII.LF &
           "VY0709TZXAWCCoGaXzWq5Sb919qRkHsBdqsbUgRAfLshsMzVhtsAi5X1xbvHfdZG" & ASCII.LF &
           "gWIj8KiZiOt7Izxabp0dkdK0Oo+3AshkaR+s1EZxAoGBAKqCwAIH+HU0YF7MmjK0" & ASCII.LF &
           "lJKGNKoy7WhxA4RESQkWv5Zet9i0sqPlz5ajKDZRcJBWBaxLIZo9oolXUlJltdfN" & ASCII.LF &
           "5kgKVRcPV00ThGuuZKUHpSURmZS+iP0i6Rrx51ZKdb/T+Jf0CU2vPauaxcZ17ekc" & ASCII.LF &
           "k3VQLvwKPdHckJ89GRA83oLh" & ASCII.LF &
           "-----END PRIVATE KEY-----";
         Item : ID.Local_Identity;
         St   : ID.Identity_Status;
      begin
         ID.Decode (RSA_Leaf_PEM, RSA_Leaf_Key, Item, St);
         Check (St = ID.Ok,
                "an RSA certificate and its own key check out, got "
                & ID.Status_Image (St));
         Check (ID.Key_Algorithm_Of (Item) = CryptoLib.X509.RSA,
                "and the key is reported as RSA");

         --  A different RSA key of the same size. The failure has to be a
         --  mismatch rather than an inability to tell, or a caller cannot
         --  distinguish "wrong key" from "not checked".
         ID.Decode (RSA_Leaf_PEM, RSA_Other_Key, Item, St);
         Check (St = ID.Key_Mismatch,
                "another RSA key of the same size is a mismatch, not an "
                & "unchecked identity, got " & ID.Status_Image (St));
      end;

      --  The other two curves. Matching these needs the public point
      --  derived from the scalar, which is the same arithmetic on all three
      --  and was only ever offered for one of them.
      declare
         P256_Leaf : constant String :=
           "-----BEGIN CERTIFICATE-----" & ASCII.LF &
           "MIIBKDCBzwIUDNb25fQiF6PjOrD6qfSpFj2KY5EwCgYIKoZIzj0EAwIwEjEQMA4G" & ASCII.LF &
           "A1UEAwwHcDI1Ni1jYTAeFw0yNjA3MjgxOTExMzFaFw0yNzA3MjgxOTExMzFaMBwx" & ASCII.LF &
           "GjAYBgNVBAMMEWxlYWYucDI1Ni5leGFtcGxlMFkwEwYHKoZIzj0CAQYIKoZIzj0D" & ASCII.LF &
           "AQcDQgAEjQ6HgkMnOkYjt9ywJo2fiNj4nvi+jFMmxbbWvAVuYcWfaCXlXIMKEkwz" & ASCII.LF &
           "LUIDfkxvRTO4aP8CoDpkCpA6Vzc6TDAKBggqhkjOPQQDAgNIADBFAiEAkXYM7UH4" & ASCII.LF &
           "P7G31aw72aKYI9Phky02Lx1WmDcfIrvz1pICIEtkjpugplNQ62ZgEfUl4k+00f1s" & ASCII.LF &
           "p71JQPavUV5SbzxV" & ASCII.LF &
           "-----END CERTIFICATE-----";

         P256_Key : constant String :=
           "-----BEGIN PRIVATE KEY-----" & ASCII.LF &
           "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgyfvjdmW+qhTmVjFM" & ASCII.LF &
           "vLt3ubIrMpcVGK7QvaHIqobtI4ihRANCAASNDoeCQyc6RiO33LAmjZ+I2Pie+L6M" & ASCII.LF &
           "UybFtta8BW5hxZ9oJeVcgwoSTDMtQgN+TG9FM7ho/wKgOmQKkDpXNzpM" & ASCII.LF &
           "-----END PRIVATE KEY-----";

         P256_Alt : constant String :=
           "-----BEGIN PRIVATE KEY-----" & ASCII.LF &
           "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZ1wL8wt312RjJ85J" & ASCII.LF &
           "skUbZx0VurwfmgPMLk32oYqWeu+hRANCAATYB8yQPFjLsmtkyPJTkNw4inikSlxR" & ASCII.LF &
           "ICjnFj/zr+knrgoWNbHCtEcNHKkl08X0RLqOQ1Jt10iN3XcMlDQhJqjY" & ASCII.LF &
           "-----END PRIVATE KEY-----";

         P521_Leaf : constant String :=
           "-----BEGIN CERTIFICATE-----" & ASCII.LF &
           "MIIBsTCCARICFB0q89Xz7gyESR358e7GIzg9InzhMAoGCCqGSM49BAMCMBIxEDAO" & ASCII.LF &
           "BgNVBAMMB3A1MjEtY2EwHhcNMjYwNzI4MTkxMTMxWhcNMjcwNzI4MTkxMTMxWjAc" & ASCII.LF &
           "MRowGAYDVQQDDBFsZWFmLnA1MjEuZXhhbXBsZTCBmzAQBgcqhkjOPQIBBgUrgQQA" & ASCII.LF &
           "IwOBhgAEAWeV2y073JLStpmKqOgllO86I0HGwH1rufdQgsEpCmnQ96hipf/+jdqi" & ASCII.LF &
           "DUvSoS6vDKIxrN7+icu/TPKxAIF482OfAAmK76cP29aM0LUHbuX6yC6oya4GfaRg" & ASCII.LF &
           "m3VmkUszvKW1Hdkf4D+WEde13jgxn2/fWc0dHLMlEC1WLLEpQvSa0g8MMAoGCCqG" & ASCII.LF &
           "SM49BAMCA4GMADCBiAJCAIowN9YZvYhNDpT1czUiM++cbk8KGHXAvFYnN6C3ErnT" & ASCII.LF &
           "TrAgX9ZBBhcnPIIhiEc7R+ARydGZrwSHWL1WNEMy0YL6AkIAqL87ZPB5Qk6QUML9" & ASCII.LF &
           "yj2fVE7rOSzy1WyjlLFCdWlv+97luri69Fc+4XqRFhC2GFz7IwNF9eeMbeEvGeU/" & ASCII.LF &
           "70Nhi3Y=" & ASCII.LF &
           "-----END CERTIFICATE-----";

         P521_Key : constant String :=
           "-----BEGIN PRIVATE KEY-----" & ASCII.LF &
           "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAIgx2sfzzwK3Wolda" & ASCII.LF &
           "+75K1hINe6fq3ZD6xKeEZCR2kaH9AJ0h8JrV1elkLILJWLBawH1UcvMaUp/rTpSZ" & ASCII.LF &
           "MRjU2aWhgYkDgYYABAFnldstO9yS0raZiqjoJZTvOiNBxsB9a7n3UILBKQpp0Peo" & ASCII.LF &
           "YqX//o3aog1L0qEurwyiMaze/onLv0zysQCBePNjnwAJiu+nD9vWjNC1B27l+sgu" & ASCII.LF &
           "qMmuBn2kYJt1ZpFLM7yltR3ZH+A/lhHXtd44MZ9v31nNHRyzJRAtViyxKUL0mtIP" & ASCII.LF &
           "DA==" & ASCII.LF &
           "-----END PRIVATE KEY-----";
         Item : ID.Local_Identity;
         St   : ID.Identity_Status;
      begin
         ID.Decode (P256_Leaf, P256_Key, Item, St);
         Check (St = ID.Ok,
                "a P-256 certificate and its own key check out, got "
                & ID.Status_Image (St));
         Check (ID.Key_Algorithm_Of (Item) = CryptoLib.X509.ECDSA_P256,
                "and the curve is reported");

         ID.Decode (P521_Leaf, P521_Key, Item, St);
         Check (St = ID.Ok,
                "a P-521 certificate and its own key check out, got "
                & ID.Status_Image (St));

         --  A different key on the same curve, which is the case that needs
         --  the derivation rather than a look at the algorithm.
         ID.Decode (P256_Leaf, P256_Alt, Item, St);
         Check (St = ID.Key_Mismatch,
                "another P-256 key is a mismatch, not an unchecked identity, "
                & "got " & ID.Status_Image (St));

         --  A key from a different curve fails earlier, on the algorithm.
         ID.Decode (P256_Leaf, P521_Key, Item, St);
         Check (St = ID.Key_Mismatch,
                "a key from another curve does not match either");
      end;

      --  Material that is not there, or not a key.
      declare
         Item : ID.Local_Identity;
         St   : ID.Identity_Status;
      begin
         ID.Decode ("", To_String (Leaf_Key), Item, St);
         Check (St = ID.Empty_Chain, "no certificate is an empty chain");

         ID.Decode (To_String (Leaf_PEM), "", Item, St);
         Check (St = ID.Malformed_Private_Key,
                "no key is a malformed key, got " & ID.Status_Image (St));

         ID.Decode (To_String (Leaf_PEM), To_String (Leaf_PEM), Item, St);
         Check (St = ID.Malformed_Private_Key,
                "a certificate offered as a key is refused");
      end;
   end Check_Identities;

   --  Encrypted PKCS#8, which is how a private key is usually stored when it
   --  is stored at all.
   procedure Check_PKCS8_Encrypted is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.PKCS8.Unlock_Status;
      use type CryptoLib.X509.Public_Key_Algorithm;

      package P8 renames CryptoLib.PKCS8;

      Enc_AES256_SHA256 : constant String :=
        "3082011c305706092a864886f70d01050d304a302906092a864886f70d01050c301c0408df34818c3c3c80a202" &
        "020800300c06082a864886f70d02090500301d060960864801650304012a041006fdcf33c7464bdca2fa561a76" &
        "a00ef70481c00128f1659941272ed217c3593b453df712ac47e26e769eba6219b81be2c99312221bac341c46bb" &
        "d4ce9679b6709504ab612214d770f8851d4acab66a78860b54ec047a5f2918be4cac36033411285de399123f34" &
        "9a35ed38497670f0cc9b18311cf771e3df5a5c9af377d7b62dbbd83c16bc4444d14102424b8c9d6e9895987cb6" &
        "5c1a27a6add7f081ff703de76aacc7dfa40852ee6dd6110ddb32e5dc91346c1ff29d8b0285647c14357de6972e" &
        "59437e826e896351c0430a25151763d60a41";

      Enc_AES128_SHA256 : constant String :=
        "3082011c305706092a864886f70d01050d304a302906092a864886f70d01050c301c040857868de5f9d6e0c102" &
        "020800300c06082a864886f70d02090500301d06096086480165030401020410247e74d67631454ced2016b9b4" &
        "65b8380481c0992e4ccba11bb6d3c02440b5b71aef8528f7cd55fb1294aee05f338b05eea055112bdb5b312053" &
        "5ac985bcdd51a0a7fafafac751766e6c5e636818a5ab3ef1fa0b557f90fcf90d2565d50263bedd270bd0af4dbb" &
        "76150606db97ad3486e0509a20f75a8015e6cde6aad9ea451e13be85f66159a0f66899c1b345f15199e50d98e9" &
        "3230073ee61c4826680cb09dd94f088d0e411487ad611d1179afe4d928befa8f2000e20b39e2acaedf1a86a4e2" &
        "8385bdde0e38a759d3bbf49f291453aa319a";

      Enc_AES256_SHA1 : constant String :=
        "3082011c305706092a864886f70d01050d304a302906092a864886f70d01050c301c04088effc7d368f0ae4202" &
        "020800300c06082a864886f70d02090500301d060960864801650304012a0410adbe6acbca7a9cd8c22c289b3c" &
        "5a14750481c0e2c9a9c43c182a05c1613d30c9127642b2a65aebdb9b53a45cb3aa9aeb9d85747664d70aa8125a" &
        "b29562acf5e96cdbfd904c445c23725b9fe42ab9e092dcdca993a70c73150a6c220fae6858905bc804df74f605" &
        "43236a390b5707858caf30d8489ac4cd0643841ce658f997fd483b359a59b9047c775f242752b05d59be6318ec" &
        "62b44723e089039e77340800cc7f1b7d44c2bc9e535bbff3aa0f327e5c7024b6c997472faf6839daa7a92ca09d" &
        "7e6823d3f34e04b2dc0bac4c946dfce8c062";

      Enc_Ed25519 : constant String :=
        "30819b305706092a864886f70d01050d304a302906092a864886f70d01050c301c040806b7d23f573e40950202" &
        "0800300c06082a864886f70d020b0500301d060960864801650304012a041033efd4612f61a77cf17e2a339875" &
        "bc800440ef28f1ea1c4b1dbfc9d4e6eb9eaa0e629d4ca045484862db42fcfa101bf3ced85fd0ae9862399c8716" &
        "4bda482f82cb02b73538967572ac02ec051ada2d0a9aee";

      Expected_Scalar : constant String :=
        "0dbe7e740d398458dc39a3f0d7e71e7132b65e26af9a13766441d3b1c79a30f141700119bb0be582c54a8f09fad2815b";

      P8_EC : constant String :=
        "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b02010104300dbe7e740d398458dc39" &
        "a3f0d7e71e7132b65e26af9a13766441d3b1c79a30f141700119bb0be582c54a8f09fad2815ba16403620004d8" &
        "e1d6e84534ed29f11bc644c46499728c15b025b8bfbaa8238d053946fed7f22fced5751f61c20208bf534ec12e" &
        "1a8abf3ed710988a642539fd5e33f5da33755b63aad074d171ba133c82b99bfca240d3fd6e5408e0f2ca6b82d5" &
        "c721f9e7d8";

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

      procedure Check_Scheme (Encoded : String; Label : String) is
         Item : P8.Private_Key;
         St   : P8.Unlock_Status;
      begin
         P8.Decode_Encrypted_DER
           (From_Hex (Encoded), "secret", CryptoLib.ASN1.Default_Limits,
            Item, St);
         Check (St = P8.Ok,
                Label & " opens with the right password, got "
                & P8.Unlock_Image (St));

         --  The right key, not merely something that parses. A wrong key that
         --  happened to decode would pass every test but this one.
         Check (P8.Private_Value (Item) = From_Hex (Expected_Scalar),
                Label & " recovers the scalar OpenSSL holds");

         P8.Decode_Encrypted_DER
           (From_Hex (Encoded), "wrong", CryptoLib.ASN1.Default_Limits,
            Item, St);
         Check (St = P8.Wrong_Password_Or_Corrupt,
                Label & " refuses a wrong password, got "
                & P8.Unlock_Image (St));
         Check (not P8.Is_Present (Item),
                Label & " leaves nothing behind after refusing");
      end Check_Scheme;
   begin
      --  The combinations OpenSSL writes: two key sizes, and the PRF both
      --  named and defaulted.
      Check_Scheme (Enc_AES256_SHA256, "AES-256 with HMAC-SHA256");
      Check_Scheme (Enc_AES128_SHA256, "AES-128 with HMAC-SHA256");
      Check_Scheme (Enc_AES256_SHA1, "AES-256 with the default PRF");

      declare
         Item : P8.Private_Key;
         St   : P8.Unlock_Status;
      begin
         P8.Decode_Encrypted_DER
           (From_Hex (Enc_Ed25519), "secret", CryptoLib.ASN1.Default_Limits,
            Item, St);
         Check (St = P8.Ok
                and then P8.Algorithm_Of (Item) = CryptoLib.X509.Ed25519
                and then P8.Private_Value (Item)'Length = 32,
                "an encrypted Ed25519 key opens to its seed, got "
                & P8.Unlock_Image (St));
      end;

      --  An iteration count is a number in a file somebody else wrote.
      --  Honouring an enormous one is doing what that file says.
      declare
         Item : P8.Private_Key;
         St   : P8.Unlock_Status;
      begin
         P8.Decode_Encrypted_DER
           (From_Hex (Enc_AES256_SHA256), "secret",
            CryptoLib.ASN1.Default_Limits, Item, St,
            Maximum_Iterations => 1);
         Check (St = P8.Excessive_Iterations,
                "work beyond the caller's limit is refused before it is "
                & "done, got " & P8.Unlock_Image (St));
      end;

      --  A plain key handed to the encrypted reader, and an encrypted one
      --  handed to the plain reader. Neither should be mistaken for the
      --  other.
      declare
         Item   : P8.Private_Key;
         St     : P8.Unlock_Status;
         Parse  : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         P8.Decode_Encrypted_DER
           (From_Hex (P8_EC), "secret", CryptoLib.ASN1.Default_Limits,
            Item, St);
         Check (St /= P8.Ok,
                "a plain key is not opened as an encrypted one");

         P8.Decode_DER
           (From_Hex (Enc_AES256_SHA256), CryptoLib.ASN1.Default_Limits,
            Item, Parse);
         Check (Parse = CryptoLib.ASN1.Errors.Unsupported_Encoding,
                "an encrypted key is refused by the plain reader rather "
                & "than read as though it were plain");
      end;
   end Check_PKCS8_Encrypted;

   --  Reading a PKCS#12 bundle, which this crate could write and not read --
   --  the kind of asymmetry that leaves a caller unable to check what it just
   --  produced.
   procedure Check_PKCS12 is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.PKCS12.Open_Status;
      use type CryptoLib.X509.Public_Key_Algorithm;

      package X509C renames CryptoLib.X509.Certificates;
      package P12 renames CryptoLib.PKCS12;

      OpenSSL_Bundle : constant String :=
        "30820cbf02010330820c8506092a864886f70d010701a0820c7604820c7230820c6e308206e206092a864886f7" &
        "0d010706a08206d3308206cf020100308206c806092a864886f70d010701305706092a864886f70d01050d304a" &
        "302906092a864886f70d01050c301c040839469ec75087e37902020800300c06082a864886f70d02090500301d" &
        "060960864801650304012a0410132fc7eb0141c3dfbdb906a4d869655b8082066057c51abbe81587124880906d" &
        "d798e12b0fef0e98140c64ad59d75e522cd9888486d43f2dcb0ae36d084726f495dd8f817dd9b21d04cd22c250" &
        "d64f0a97519736da96e088683cfe740698356b6a548a11a3fc24002fd121883e8c9bc26833b487bcb7ef64a749" &
        "22c344ae61dff8359bb0ca2285503697cf333e58553819ededb581dbb285514d88f3e246f67b261aabd19af46f" &
        "b65920c433cf9a76d7d3436cd54a1f0ddda79e90bd296f7269b9e400db185a67bdfcaed8776ee08a94daf1df6e" &
        "bf654d051a0ff956559d04b6649b2941214e1c00a0bedbf279e9cd1867f013688f8842e13523b0e11560af8648" &
        "34d99c5fce339d91c9873fc3dd0d4b48c7bc149f58a13e36afb3985cf088edb91c5499c05b3c6a22089071d7e0" &
        "35fd7943015a9c7e27fea13830549359a285e888eeb1517dfa8e22059606adc4bb4ded95a6b44939cc2aa104cc" &
        "ac77daebbee2627137511cc110864b1c8ce105006f2174ce303fa0816cf49bfee33d6b9c908b81ef553339f865" &
        "dff5f007828c7b89bb1425aa6e3a79b2f003b8c43221e7b2d6d8495da987d8a76f1913e18b758507121234d06a" &
        "f7ad89ac7ff85d75480c590fcb633116e4201325fa29124217c8a54615f47e6b21a7c7b779d8810c90f3a20f56" &
        "28e0bb6b0af29e96a7e513a0ec354cd8cea9e54855d8c7539aa5dac38af055573043544f94739d062785320597" &
        "6978009a879ba6895eb566ac974ec84ca7754e5c70e025022017fb2773b5b2ad9ccafd567ef80d95c9d6f8e633" &
        "81a1281550f09d5b9568411dc8f048db50c857c262ee94b4b97ba31d4dbe32435e4bc288d0df425487d970835c" &
        "95a425275479d88c33ea7eea47c7ee6b8d2a424152a4982f5e84c18120803c2ee66eff1586cf6092278e94c4a9" &
        "64740a98b3783ab6be86d7df8d94e3fe76f628a2879a9b5c851c248712605bba34c2c45dc63d1a00df8cde827c" &
        "2d04c6f263280628c05bbef6d351f852cadc19e25c81afaef51545c884b177769ae46eee02ffc9108a8b9f5233" &
        "6ffc104a7514f47ae60621ce1f1f8eec4e38c8a698e293aa8a4c70ee988b3a4d29608852d0ebd53f773045fc36" &
        "cb4c5f54f4b7409acd479714894ad4b774718489c4c60953b621d3516daa7b05eb0d6c7638c06768bab563e78c" &
        "142d99031be6ac8e8c6a34ede011e7f2fd2fcdfe59f1b6bbd39933c6554dc2c06031ef6404ef526ea7e0370791" &
        "cf96d25a9f91ac0d0cd7e819d094a3ade7c71222e13954187493f3e25468d5747278b7e4bc1a31e464b58627fd" &
        "b13dbf86fc770a6dd91f48ba974a54285d8b4a08ca5ae43d83c13bdbba7c0f974565e87b139bd1c16438384169" &
        "f89e51c93949c36d757c15264dc2a7f0380c7c3001ff42398cb6131bf99d6a05cd4e222ae05b843d43dc6ca444" &
        "41613f0ea55e96c8506ffd9ddc3de069a560e84667d621082237c569130eb12a6099aaf4820405751a466824a7" &
        "50fae6301bb274951c09c035301a68e4a81cf5ff86c69a550b39782e7dbf5490dc7c147cd5b71901e12efa740b" &
        "92ada61c27495cc05ed6a598e00458384b3069d56b8a7f84edb7a2785bf9f1907657172396d78311761334f22e" &
        "45735f8724693be80017c76bf3612fd24afc1e55283ba84051fc9b20fdcd9542621af55ceb837bf2da5c581b62" &
        "610f454f7a4f28870ddc26bb4e7a7a7ddbd7ab17437c49191c9c05e1aab948788865369e883d30c747686519ce" &
        "27f301d060a5192d1a204a6ffcd9f9f157c2f85dd90d00446f94014c9d19b2c6cf11bad958e966ba799cf4cf46" &
        "91ead8cccb4eab9f28808f5a1230e6efe91357a7333e7d05c3ed5ca3eadf396ba9c08f9b123e8adb1e29193ada" &
        "be2b18cc46a5eec5dd25f07882eebcd6eb4382110d08ea6d1b862f241a0f8b91e986a79187a6a50a00d45fb200" &
        "20c17b117c4ccc11a9fac2736157cf13b417a8561aad359fef693ed574c453c3c1f127332b20fab318ea06d74c" &
        "c4e22674bf3796ed619dd2d0a52aaff9a14ba01e923566fdc338951799b31aaf63182bfde8b9111e6ea2a8a1d0" &
        "8d6604e328b010bd18dff25164691c8f6ad29066540d648595445a84322f1329918fcdc913b230fde3ab6b5de0" &
        "2460a8b560d7063fab107ab0b1e281f30a99cbd966f256ef101e81f65ef8b3dbd3c9e5f018f6080a03d9288c42" &
        "a731553ee47083e35fd1a43aa8ef90b39447766dacdf5792b59c76a16c7a95e9361017f2b72ecc25bef66b9ca6" &
        "c8d450eaf8520b827742b3912bbf1b552f84101b26ffaf34fe6170e79f803eefefc036867eb285c8c86d746f7d" &
        "3082058406092a864886f70d010701a0820575048205713082056d30820569060b2a864886f70d010c0a0102a0" &
        "8205313082052d305706092a864886f70d01050d304a302906092a864886f70d01050c301c04085f6ef3c0caaf" &
        "fb8e02020800300c06082a864886f70d02090500301d060960864801650304012a04107c38d110d01fb5c9d68c" &
        "561dee0f4252048204d02570beeac202309e79155bb893405dc3c9877e80684cb5be23815713c58b40e2ac286c" &
        "b06a7e646a2fe125a73335700dd4d1eed1e5d3cc4839267a9504984d953bcf13f3f9ff373adc11cff7659dd22d" &
        "5b5e063d676353a121365192b358859c50b299b5f6a0fe893e60dbfe3af81b600e3d69acae1585e56e8008352e" &
        "ed116a8a7c5ae739860e5f45fce0b22d39809ceb62d9cb88f0d4303cd9005c142ee01690a81dbd0fd10a989d22" &
        "dd9ba695c66069821eab3c987a5904a6f51fd6493cdc5e3c98f690bbfbcaf83f53b1eef64bebc9f2bda4165066" &
        "7e5a2d892e1d9ddbab7fe58c39ac40670e97dce8d64c541ad8813cd89aebc37e665a0310b772b4b4e4043c0069" &
        "c94644c00a05456816e8fcdb10cdd647413dc5c266817b8ed651c477acf36030b45372a50ad125a4e24dc2d326" &
        "4373c263075ea01bd438921f2798bd504d043c4d52a577caaf5ecb386e83b61616051329b4741a4a82d0e44e54" &
        "1d7d05a0cb4aab5c29a5405cf7afd668867aedec13c991b238496bc1439a1ff8b559fa7cd26d9387e921ad6b8c" &
        "77b44e9dad9d3b4e573ffd4f1fce1bd4aca1ae8b4b95f95da8082bc2db0e8f4c53446ca7f59473680cfe43e0e6" &
        "e21a405e1dbb4f85205c6226535f8c0518013d98e3f623f6da68dbceffed1c19c1a69173baff3c352d3b527654" &
        "9b02e300bd786ad068453fa0072baafbfa42acd40ba3cdf746740f229e320dd5612eb0af2fcee57944e0be44bb" &
        "67d0c2356a7a4a57bb9a014cd469f6f1d8a5122478fe835421c111e93b9476028cc55039220aee8f2bdabf4549" &
        "ead539582145723ba108916f359ba330907d12d725828b1767636f9f71c9a55ddb55263995cbcb09b5d9ade403" &
        "f2831edced726db547162693cdfba523807c19dc86d2ee12edf55278b14dd5528b6bff297e31913da9e4822977" &
        "60ceb2e1ceee7f0098e74168ee649f9d978698637c1bdb0f42075ae468682eead73c7661b35c83787dcbb773ed" &
        "13205d51feda27a55e2834db39c3a181c4a2cb6a8a32176105f3d7792d797f692e75b1492f02fb8bc6102c4add" &
        "0ddad1f73e09c6019a13ede66ddc70052bad93d0a1ce02a729096abcee9ab477df4d95add82fdda21512b9d296" &
        "80d24863f5add6c937d5d77abf05c89fa6d45ee43c45d3ae94daacfe14d78edb6d90e12e80f2b395c8de5f5f8a" &
        "cc620c0a252a92208efb9e52c24985e9e6087587ea486e518c7d84281a9e8bd4b0261b52ecc2ef76000be6ba2b" &
        "21f843804aab5cd3198668b09e45e99e1bc31392052d2d010b000de1653a1c435604656c66000b3b0ee7e4a82b" &
        "adc924f2a47aadce070265bde6422ef50ddc111857a7db39f9bc49f30fa0e6ead6028b4e83fb6eb397569d45f2" &
        "0b1759033a4f75d222b4650d9ce0355ff9e8743a1e6b508c815dbfc3e692680f075f2b6f341bf6d2289fbd7e6c" &
        "a54fb93f1f6f3870f55c632af30cb7b17ca2ec7ba81c170d46bb173b838ea7be35ac077d577b641e13c7e0dbe5" &
        "227f4d90e65d04952ba62cbfa6d88cb911e14cf9da2e569fbdc30510ff1277be8c4829b88b86c14cabd327b443" &
        "7d405cf75efbd44032c1944a42010ad046abedea8f82b67563cd26f0420ea5ac9129a661dc29e115121698dbf7" &
        "f3105760168aeb4a199438dd58436ce3e008febb3c67b8a1a6278c84ca862ed4ed372a26d2f4dde637cab2b069" &
        "a70fa82a3277362f7177aa73f73808d1400ad7aac95c00f85aced73125302306092a864886f70d010915311604" &
        "140f8b7a610f5ad04c532f9f02fc593c808a3a2bdd30313021300906052b0e03021a0500041417b42fdeeddc75" &
        "cad52c98532b3e92b52a334c4e04088b98cc91beff977802020800";

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

      CA_PEM  : Unbounded_String;
      CA_Key  : Unbounded_String;
      Bundle  : Unbounded_String;
      Outcome : CryptoLib.Certificates.Certificate_Status;
   begin
      --  A bundle this crate wrote, read back. The round trip is the point:
      --  generating one nobody can open is a failure that only shows up in
      --  somebody else's tool.
      Outcome :=
        CryptoLib.Certificates.Create_Local_CA
          ("p12-roundtrip-ca", CA_PEM, CA_Key,
           CryptoLib.Certificates.P384_Key);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: CA created");

      Outcome :=
        CryptoLib.Certificates.Generate_PKCS12
          (To_String (CA_PEM), To_String (CA_Key), "friendly", "secret",
           Bundle, Iterations => 4_096);
      Check (Outcome = CryptoLib.Certificates.Ok, "fixture: bundle written");

      declare
         Text : constant String := To_String (Bundle);
         Raw  : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Text'Length));
         Item : P12.Bundle;
         St   : P12.Open_Status;
      begin
         for I in Text'Range loop
            Raw (Ada.Streams.Stream_Element_Offset (I - Text'First + 1)) :=
              Character'Pos (Text (I));
         end loop;

         P12.Open (Raw, "secret", CryptoLib.ASN1.Default_Limits, Item, St);
         Check (St = P12.Ok,
                "a bundle this crate wrote opens here, got "
                & P12.Status_Image (St));
         Check (P12.Certificate_Count (Item) = 1,
                "it carries its one certificate");
         Check (P12.Has_Private_Key (Item)
                and then P12.Key_Algorithm_Of (Item)
                           = CryptoLib.X509.ECDSA_P384
                and then P12.Private_Value (Item)'Length = 48,
                "and the P-384 key that goes with it");

         --  The certificate really is the CA's, not merely certificate-shaped.
         declare
            Parsed : CryptoLib.ASN1.Errors.Decode_Status;
            Cert   : constant X509C.Certificate :=
              X509C.Decode_DER
                (P12.Certificate_Bytes (Item, 1),
                 CryptoLib.ASN1.Default_Limits, Parsed);
         begin
            Check (Parsed = CryptoLib.ASN1.Errors.Ok
                   and then X509C.Subject_Common_Name (Cert)
                              = "p12-roundtrip-ca",
                   "the certificate inside is the one that went in");
         end;

         --  Nothing is believed before the MAC is checked, so a wrong
         --  password yields nothing rather than a hopeful parse.
         P12.Open (Raw, "wrong", CryptoLib.ASN1.Default_Limits, Item, St);
         Check (St = P12.Wrong_Password_Or_Corrupt,
                "a wrong password is refused, got " & P12.Status_Image (St));
         Check (not P12.Is_Present (Item)
                and then P12.Certificate_Count (Item) = 0,
                "and nothing is left readable behind it");
      end;

      --  A bundle OpenSSL wrote with its own defaults, where the certificates
      --  sit in PKCS#7 encrypted content rather than in the clear. This is
      --  the common shape; a reader that skipped it would report a bundle
      --  full of certificates as having none.
      declare
         Item : P12.Bundle;
         St   : P12.Open_Status;
      begin
         P12.Open (From_Hex (OpenSSL_Bundle), "secret",
                   CryptoLib.ASN1.Default_Limits, Item, St);
         Check (St = P12.Ok,
                "an OpenSSL bundle opens, got " & P12.Status_Image (St));
         Check (P12.Certificate_Count (Item) = 2,
                "both its certificates are found, got"
                & Natural'Image (P12.Certificate_Count (Item)));
         Check (P12.Has_Private_Key (Item)
                and then P12.Key_Algorithm_Of (Item) = CryptoLib.X509.RSA,
                "and its RSA key");

         declare
            Leaf_Parsed   : CryptoLib.ASN1.Errors.Decode_Status;
            Issuer_Parsed : CryptoLib.ASN1.Errors.Decode_Status;
            Leaf   : constant X509C.Certificate :=
              X509C.Decode_DER
                (P12.Certificate_Bytes (Item, 1),
                 CryptoLib.ASN1.Default_Limits, Leaf_Parsed);
            Issuer : constant X509C.Certificate :=
              X509C.Decode_DER
                (P12.Certificate_Bytes (Item, 2),
                 CryptoLib.ASN1.Default_Limits, Issuer_Parsed);
         begin
            Check (Leaf_Parsed = CryptoLib.ASN1.Errors.Ok
                   and then Issuer_Parsed = CryptoLib.ASN1.Errors.Ok,
                   "both extracted certificates decode");
            Check (X509C.Subject_Common_Name (Leaf) = "leaf.rsa.example",
                   "the leaf comes out of the encrypted bag intact, got "
                   & X509C.Subject_Common_Name (Leaf));
            Check (X509C.Subject_Common_Name (Issuer) = "rsa-test-ca",
                   "and so does its issuer");
         end;
      end;
   end Check_PKCS12;

   --  AUnit routine wrappers. Each check is a test of its own, so a
   --  failure reports the check that failed and the rest still run.
   procedure Run_Check_ASN1_DER (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_CSR_Signing (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_OpenSSH_Key_Unlock (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_OpenSSH_Signature (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Decoder_Robustness (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_PKCS10 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_PKCS8 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Identities (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_PKCS8_Encrypted (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_PKCS12 (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Identity_Predicates (Item : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Check_ASN1_DER (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_ASN1_DER;
   end Run_Check_ASN1_DER;

   procedure Run_Check_CSR_Signing (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_CSR_Signing;
   end Run_Check_CSR_Signing;

   procedure Run_Check_OpenSSH_Key_Unlock (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_OpenSSH_Key_Unlock;
   end Run_Check_OpenSSH_Key_Unlock;

   procedure Run_Check_OpenSSH_Signature (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_OpenSSH_Signature;
   end Run_Check_OpenSSH_Signature;

   procedure Run_Check_Decoder_Robustness (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Decoder_Robustness;
   end Run_Check_Decoder_Robustness;

   procedure Run_Check_PKCS10 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_PKCS10;
   end Run_Check_PKCS10;

   procedure Run_Check_PKCS8 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_PKCS8;
   end Run_Check_PKCS8;

   procedure Run_Check_Identities (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Identities;
   end Run_Check_Identities;

   procedure Run_Check_PKCS8_Encrypted (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_PKCS8_Encrypted;
   end Run_Check_PKCS8_Encrypted;

   procedure Run_Check_PKCS12 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_PKCS12;
   end Run_Check_PKCS12;

   procedure Run_Check_Identity_Predicates (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Identity_Predicates;
   end Run_Check_Identity_Predicates;

   overriding procedure Register_Tests (Item : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (Item, Run_Check_ASN1_DER'Access, "asn1 der");
      Register_Routine (Item, Run_Check_CSR_Signing'Access, "csr signing");
      Register_Routine (Item, Run_Check_OpenSSH_Key_Unlock'Access, "openssh key unlock");
      Register_Routine (Item, Run_Check_OpenSSH_Signature'Access, "openssh signature");
      Register_Routine (Item, Run_Check_Decoder_Robustness'Access, "decoder robustness");
      Register_Routine (Item, Run_Check_PKCS10'Access, "pkcs10");
      Register_Routine (Item, Run_Check_PKCS8'Access, "pkcs8");
      Register_Routine (Item, Run_Check_Identities'Access, "identities");
      Register_Routine (Item, Run_Check_PKCS8_Encrypted'Access, "pkcs8 encrypted");
      Register_Routine (Item, Run_Check_PKCS12'Access, "pkcs12");
      Register_Routine (Item, Run_Check_Identity_Predicates'Access, "identity predicates");
   end Register_Tests;

   overriding function Name (Item : Test_Case) return AUnit.Message_String is
      pragma Unreferenced (Item);
   begin
      return AUnit.Format ("cryptolib ASN.1, PEM, PKCS and OpenSSH encodings");
   end Name;

end Tests_Encodings;
