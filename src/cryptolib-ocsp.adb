with Ada.Streams;

with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.OIDs;
with CryptoLib.Hashes;
with CryptoLib.X509.Extensions;
with CryptoLib.X509.Signatures;
with CryptoLib.X509.Times;

package body CryptoLib.OCSP is

   use CryptoLib.ASN1;
   use CryptoLib.ASN1.Errors;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.X509.Signature_Algorithm;
   use type CryptoLib.X509.Signatures.Verification_Result;

   package DER_Reader renames CryptoLib.ASN1.DER;
   package OID_Table renames CryptoLib.ASN1.OIDs;
   package X509C renames CryptoLib.X509.Certificates;
   package XE renames CryptoLib.X509.Extensions;
   package XS renames CryptoLib.X509.Signatures;

   Empty_Octets : constant Octets (1 .. 0) := [others => 0];

   function Slice (Item : Response; Where : Span) return Octets
   is (if Where.Last < Where.First
       then Empty_Octets
       else Item.DER (Where.First .. Where.Last));

   function Result_Image (Result : Verification_Result) return String is
   begin
      case Result is
         when Accepted                => return "accepted";
         when Not_Successful          => return "not successful";
         when Malformed_Response      => return "malformed response";
         when Wrong_Certificate       => return "wrong certificate";
         when Unsupported_Extension   => return "unsupported extension";
         when Nonce_Missing           => return "nonce missing";
         when Nonce_Mismatch          => return "nonce mismatch";
         when Unknown_Responder       => return "unknown responder";
         when Delegate_Not_Authorized => return "delegate not authorized";
         when Invalid_Signature       => return "invalid signature";
         when Unsupported_Algorithm   => return "unsupported algorithm";
         when Missing_Input           => return "missing input";
      end case;
   end Result_Image;

   -----------------------------------------------------------------------
   --  Request building
   -----------------------------------------------------------------------

   --  Emit a DER length, in the shortest form that holds it.
   --
   --  The long form used to stop at two octets, and the third octet was a
   --  conversion to Stream_Element rather than a masked byte, so a length
   --  past 65_535 raised instead of writing. A certificate's serial number
   --  is not bounded by its decoder, so a certificate carrying an absurd one
   --  turned an OCSP request into a crash -- on input from whoever supplied
   --  the certificate.
   procedure Put_Length
     (Output : in out Octets;
      Cursor : in out Offset;
      Value  : Natural)
   is
   begin
      if Value < 128 then
         Output (Cursor) := Ada.Streams.Stream_Element (Value);
         Cursor := Cursor + 1;
         return;
      end if;

      declare
         Octets_Out : array (1 .. 4) of Ada.Streams.Stream_Element;
         First      : Natural := Octets_Out'Last;
         Rest       : Natural := Value;
      begin
         Octets_Out (First) := Ada.Streams.Stream_Element (Rest mod 256);
         Rest := Rest / 256;
         while Rest > 0 loop
            First := First - 1;
            Octets_Out (First) := Ada.Streams.Stream_Element (Rest mod 256);
            Rest := Rest / 256;
         end loop;

         Output (Cursor) :=
           Ada.Streams.Stream_Element
             (16#80# + (Octets_Out'Last - First + 1));
         Cursor := Cursor + 1;
         for I in First .. Octets_Out'Last loop
            Output (Cursor) := Octets_Out (I);
            Cursor := Cursor + 1;
         end loop;
      end;
   end Put_Length;

   procedure Put_TLV
     (Output  : in out Octets;
      Cursor  : in out Offset;
      Tag     : Ada.Streams.Stream_Element;
      Content : Octets)
   is
   begin
      Output (Cursor) := Tag;
      Cursor := Cursor + 1;
      Put_Length (Output, Cursor, Natural (Content'Length));
      for B of Content loop
         Output (Cursor) := B;
         Cursor := Cursor + 1;
      end loop;
   end Put_TLV;

   --  How many octets a TLV with this much content occupies. Has to agree
   --  with Put_Length exactly: the sizes are computed up front and the
   --  buffer check depends on them, so a disagreement writes past what was
   --  reserved.
   function TLV_Length (Content : Natural) return Natural
   is (1
       + (if Content < 128 then 1
          elsif Content < 16#100# then 2
          elsif Content < 16#10000# then 3
          elsif Content < 16#1000000# then 4
          else 5)
       + Content);

   procedure Build_Request
     (Item   : Certificate;
      Issuer : Certificate;
      Output : out Octets;
      Last   : out Offset;
      Status : out Decode_Status;
      Nonce  : Octets := No_Nonce)
   is
      Cursor : Offset := Output'First;

      Send_Nonce : constant Boolean := Nonce'Length > 0;

      --  extnValue is an OCTET STRING whose content is itself a DER OCTET
      --  STRING holding the nonce -- two layers, as RFC 6960 requires and as
      --  OpenSSL writes it.
      Nonce_Inner : constant Natural :=
        (if Send_Nonce then TLV_Length (Natural (Nonce'Length)) else 0);
      Nonce_Ext   : constant Natural :=
        (if Send_Nonce
         then TLV_Length (Natural (OID_Table.OCSP_Nonce'Length))
              + TLV_Length (Nonce_Inner)
         else 0);
      Nonce_List  : constant Natural :=
        (if Send_Nonce then TLV_Length (Nonce_Ext) else 0);
      Nonce_Block : constant Natural :=
        (if Send_Nonce then TLV_Length (TLV_Length (Nonce_List)) else 0);
   begin
      Last := Output'First - 1;
      Status := Ok;
      Output := [others => 0];

      if not X509C.Is_Present (Item) or else not X509C.Is_Present (Issuer)
      then
         Status := Invalid_Value;
         return;
      end if;

      declare
         --  The issuer's name as encoded, hashed whole: the responder
         --  computed it over the same bytes it signed, not over a rendering.
         Name_Hash : constant Octets :=
           Octets (CryptoLib.Hashes.SHA1 (X509C.Subject_Bytes (Issuer)));
         --  The key, not the SubjectPublicKeyInfo around it.
         Key_Hash  : constant Octets :=
           Octets (CryptoLib.Hashes.SHA1 (X509C.Public_Key (Issuer)));
         Serial    : constant Octets := X509C.Serial_Number (Item);

         --  Nested innermost first, each level's content being the level
         --  below it as a whole TLV:
         --    OCSPRequest > TBSRequest > requestList > Request > CertID
         --  and CertID holding the algorithm and the three values.
         Alg_Content : constant Natural :=
           TLV_Length (Natural (OID_Table.SHA1_Digest_Algorithm'Length))
           + TLV_Length (0);
         Cert_ID_Content : constant Natural :=
           TLV_Length (Alg_Content)
           + TLV_Length (Natural (Name_Hash'Length))
           + TLV_Length (Natural (Key_Hash'Length))
           + TLV_Length (Natural (Serial'Length));
         Request_Content : constant Natural := TLV_Length (Cert_ID_Content);
         List_Content    : constant Natural := TLV_Length (Request_Content);
         TBS_Content     : constant Natural :=
           TLV_Length (List_Content) + Nonce_Block;
         Outer_Content   : constant Natural := TLV_Length (TBS_Content);
         Total           : constant Natural := TLV_Length (Outer_Content);
      begin
         if Serial'Length = 0
           or else Natural (Nonce'Length) > Maximum_Nonce_Length
         then
            Status := Invalid_Value;
            return;
         end if;

         if Natural (Output'Length) < Total then
            Status := Size_Limit_Exceeded;
            return;
         end if;

         --  OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest }
         Output (Cursor) := 16#30#;
         Cursor := Cursor + 1;
         Put_Length (Output, Cursor, Outer_Content);

         --  TBSRequest ::= SEQUENCE { requestList SEQUENCE OF Request }
         Output (Cursor) := 16#30#;
         Cursor := Cursor + 1;
         Put_Length (Output, Cursor, TBS_Content);

         --  requestList
         Output (Cursor) := 16#30#;
         Cursor := Cursor + 1;
         Put_Length (Output, Cursor, List_Content);

         --  Request ::= SEQUENCE { reqCert CertID }
         Output (Cursor) := 16#30#;
         Cursor := Cursor + 1;
         Put_Length (Output, Cursor, Request_Content);

         --  CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash,
         --                        issuerKeyHash, serialNumber }
         Output (Cursor) := 16#30#;
         Cursor := Cursor + 1;
         Put_Length (Output, Cursor, Cert_ID_Content);

         --  AlgorithmIdentifier ::= SEQUENCE { algorithm, parameters }
         Output (Cursor) := 16#30#;
         Cursor := Cursor + 1;
         Put_Length (Output, Cursor, Alg_Content);
         Put_TLV (Output, Cursor, 16#06#, OID_Table.SHA1_Digest_Algorithm);
         Put_TLV (Output, Cursor, 16#05#, Empty_Octets);

         Put_TLV (Output, Cursor, 16#04#, Name_Hash);
         Put_TLV (Output, Cursor, 16#04#, Key_Hash);
         Put_TLV (Output, Cursor, 16#02#, Serial);

         --  requestExtensions [2] EXPLICIT Extensions, after the request
         --  list rather than inside it: the nonce is about the question, not
         --  about the certificate being asked after.
         if Send_Nonce then
            Output (Cursor) := 16#A2#;
            Cursor := Cursor + 1;
            Put_Length (Output, Cursor, TLV_Length (Nonce_List));

            Output (Cursor) := 16#30#;
            Cursor := Cursor + 1;
            Put_Length (Output, Cursor, Nonce_List);

            Output (Cursor) := 16#30#;
            Cursor := Cursor + 1;
            Put_Length (Output, Cursor, Nonce_Ext);

            Put_TLV (Output, Cursor, 16#06#, OID_Table.OCSP_Nonce);

            --  The outer OCTET STRING, then the inner one it wraps.
            Output (Cursor) := 16#04#;
            Cursor := Cursor + 1;
            Put_Length (Output, Cursor, Nonce_Inner);
            Put_TLV (Output, Cursor, 16#04#, Nonce);
         end if;

         Last := Cursor - 1;
      end;
   end Build_Request;

   -----------------------------------------------------------------------
   --  Response decoding
   -----------------------------------------------------------------------

   function Signature_Algorithm_For
     (Data : Octets; OID : Element) return CryptoLib.X509.Signature_Algorithm
   is
      use CryptoLib.X509;
   begin
      if OID_Table.Matches (Data, OID, OID_Table.ECDSA_With_SHA384) then
         return ECDSA_With_SHA384;
      elsif OID_Table.Matches (Data, OID, OID_Table.ECDSA_With_SHA256) then
         return ECDSA_With_SHA256;
      elsif OID_Table.Matches (Data, OID, OID_Table.ECDSA_With_SHA512) then
         return ECDSA_With_SHA512;
      elsif OID_Table.Matches (Data, OID, OID_Table.SHA256_With_RSA) then
         return SHA256_With_RSA;
      elsif OID_Table.Matches (Data, OID, OID_Table.SHA384_With_RSA) then
         return SHA384_With_RSA;
      elsif OID_Table.Matches (Data, OID, OID_Table.SHA512_With_RSA) then
         return SHA512_With_RSA;
      elsif OID_Table.Matches (Data, OID, OID_Table.Ed25519) then
         return Ed25519_Signature;
      else
         return Unknown_Signature_Algorithm;
      end if;
   end Signature_Algorithm_For;

   procedure Read_Algorithm
     (Data       : Octets;
      Position   : in out Offset;
      Last       : Offset;
      Depth      : Natural;
      Limits     : Decode_Limits;
      Identifier : out Element;
      Status     : out Decode_Status)
   is
      Cursor : Offset := Position;
      Alg    : Element;
      Inner  : Offset;
      Ignore : Element;
   begin
      Identifier := (others => <>);
      DER_Reader.Read_Sequence
        (Data, Cursor, Last, Depth, Limits, Alg, Status);
      if Status /= Ok then
         return;
      end if;

      Inner := Alg.First;
      DER_Reader.Read_Object_Identifier
        (Data, Inner, Alg.Last, Depth + 1, Limits, Identifier, Status);
      if Status /= Ok then
         return;
      end if;

      if not DER_Reader.At_End (Inner, Alg.Last) then
         DER_Reader.Read
           (Data, Inner, Alg.Last, Depth + 1, Limits, Ignore, Status);
         if Status /= Ok then
            return;
         end if;
      end if;

      Position := Cursor;
   end Read_Algorithm;

   --  Read one SingleResponse: which certificate it is about, what it says,
   --  and for how long. One reader, used to validate the list at decode and
   --  Walk a [Number] EXPLICIT Extensions wrapper, reporting the nonce and
   --  whether anything critical in it is unrecognised.
   --
   --  Both answers come from one walk. Asking them separately would mean two
   --  passes that could disagree about which extension is which -- and the
   --  one that decides whether the response may be read at all is the one
   --  that must not be wrong.
   --
   --  Absent is not an error: these blocks are optional and most responses
   --  carry none. A critical extension this cannot interpret is a different
   --  matter, because marking it critical is the responder saying that
   --  ignoring it changes what the response means.
   procedure Scan_Extensions
     (Data     : Octets;
      Position : Offset;
      Last     : Offset;
      Depth    : Natural;
      Number   : Tag_Number;
      Limits   : Decode_Limits;
      Where    : out Span;
      Found    : out Boolean;
      Unknown  : out Boolean)
   is
      Cursor : Offset := Position;
      Wrap   : Element;
      Seq    : Element;
      Status : Decode_Status;
   begin
      Where := (First => 1, Last => 0);
      Found := False;
      Unknown := False;

      if DER_Reader.At_End (Cursor, Last) then
         return;
      end if;

      DER_Reader.Read (Data, Cursor, Last, Depth, Limits, Wrap, Status);
      if Status /= Ok
        or else Wrap.Class /= Context_Specific
        or else Wrap.Number /= Number
        or else not Wrap.Constructed
      then
         return;
      end if;

      Cursor := Wrap.First;
      DER_Reader.Read_Sequence
        (Data, Cursor, Wrap.Last, Depth + 1, Limits, Seq, Status);
      if Status /= Ok then
         --  A block that will not parse is not evidence that nothing
         --  critical is in it.
         Unknown := True;
         return;
      end if;

      Cursor := Seq.First;
      while not DER_Reader.At_End (Cursor, Seq.Last) loop
         declare
            Ext   : Element;
            Part  : Offset;
            OID   : Element;
            Value : Element;
            Inner : Element;
            Look  : Offset;
            Peek  : Element;
            Flag  : Boolean := False;
            Try   : Decode_Status;
         begin
            DER_Reader.Read_Sequence
              (Data, Cursor, Seq.Last, Depth + 2, Limits, Ext, Status);
            exit when Status /= Ok;

            Part := Ext.First;
            DER_Reader.Read_Object_Identifier
              (Data, Part, Ext.Last, Depth + 3, Limits, OID, Status);
            exit when Status /= Ok;

            Look := Part;
            DER_Reader.Read
              (Data, Look, Ext.Last, Depth + 3, Limits, Peek, Try);
            if Try = Ok
              and then Peek.Class = Universal
              and then Peek.Number = Tag_Boolean
            then
               DER_Reader.Read_Boolean
                 (Data, Part, Ext.Last, Depth + 3, Limits, Flag, Status);
               exit when Status /= Ok;
            end if;

            DER_Reader.Read_Octet_String
              (Data, Part, Ext.Last, Depth + 3, Limits, Value, Status);
            exit when Status /= Ok;

            --  The nonce is the only extension this acts on, so it is the
            --  only one whose criticality it can honour.
            if Flag
              and then not OID_Table.Matches
                             (Data, OID, OID_Table.OCSP_Nonce)
            then
               Unknown := True;
            end if;

            if OID_Table.Matches (Data, OID, OID_Table.OCSP_Nonce) then
               --  extnValue wraps a DER OCTET STRING; the nonce is its
               --  content, not the wrapper's.
               Part := Value.First;
               DER_Reader.Read_Octet_String
                 (Data, Part, Value.Last, Depth + 4, Limits, Inner, Status);
               if Status = Ok and then not Is_Empty (Inner) then
                  Where := (First => Inner.First, Last => Inner.Last);
                  Found := True;
               end if;
               Status := Ok;
            end if;
         end;
      end loop;

      --  Fell out of the loop on a parse failure rather than the end.
      if Status /= Ok then
         Unknown := True;
      end if;
   end Scan_Extensions;

   --  to pick from it at verify, so the two cannot disagree about what an
   --  entry means.
   procedure Read_Single_Response
     (Data      : Octets;
      Position  : in out Offset;
      Last      : Offset;
      Limits    : Decode_Limits;
      Name_Hash : out Span;
      Key_Hash  : out Span;
      Serial    : out Span;
      State     : out Certificate_Status;
      Issued    : out Certificate_Time;
      Due       : out Certificate_Time;
      Due_Given : out Boolean;
      Revoked_At    : out Certificate_Time;
      Revoked_Given : out Boolean;
      Reason        : out CryptoLib.X509.Revocation_Reason;
      Reason_Given  : out Boolean;
      Unknown_Critical : out Boolean;
      Status    : out Decode_Status)
   is
      Single  : Element;
      Cert_ID : Element;
      Field   : Element;
      Inner   : Offset;
      Value   : Element;
   begin
      Name_Hash := (First => 1, Last => 0);
      Key_Hash := (First => 1, Last => 0);
      Serial := (First => 1, Last => 0);
      State := Unknown;
      Issued := (others => 0);
      Due := (others => 0);
      Due_Given := False;
      Revoked_At := (others => 0);
      Revoked_Given := False;
      Reason := CryptoLib.X509.Unspecified;
      Reason_Given := False;
      Unknown_Critical := False;

      DER_Reader.Read_Sequence
        (Data, Position, Last, 7, Limits, Single, Status);
      if Status /= Ok then
         return;
      end if;

      Inner := Single.First;
      DER_Reader.Read_Sequence
        (Data, Inner, Single.Last, 8, Limits, Cert_ID, Status);
      if Status /= Ok then
         return;
      end if;

      declare
         Part  : Offset := Cert_ID.First;
         Alg   : Element;
         Minus : Boolean;
      begin
         Read_Algorithm (Data, Part, Cert_ID.Last, 9, Limits, Alg, Status);
         if Status /= Ok then
            return;
         end if;

         DER_Reader.Read_Octet_String
           (Data, Part, Cert_ID.Last, 9, Limits, Field, Status);
         if Status /= Ok then
            return;
         end if;
         Name_Hash := (First => Field.First, Last => Field.Last);

         DER_Reader.Read_Octet_String
           (Data, Part, Cert_ID.Last, 9, Limits, Field, Status);
         if Status /= Ok then
            return;
         end if;
         Key_Hash := (First => Field.First, Last => Field.Last);

         DER_Reader.Read_Integer
           (Data, Part, Cert_ID.Last, 9, Limits, Field, Minus, Status);
         --  Positive, for the same reason as in a CRL: serials are compared as
         --  magnitudes, so a response about -1 would answer for the
         --  certificate whose serial is 255.
         if Status /= Ok or else Minus then
            Status := Invalid_Value;
            return;
         end if;
         Serial := (First => Field.First, Last => Field.Last);
      end;

      --  certStatus is a CHOICE of context tags: [0] good, [1] revoked,
      --  [2] unknown.
      DER_Reader.Read (Data, Inner, Single.Last, 8, Limits, Value, Status);
      if Status /= Ok then
         return;
      end if;

      if Value.Class /= Context_Specific then
         Status := Invalid_Tag;
         return;
      end if;

      case Value.Number is
         when 0      => State := Good;
         when 1      => State := Revoked;
         when others => State := Unknown;
      end case;

      --  revoked is [1] IMPLICIT RevokedInfo, so the context tag stands in
      --  for the SEQUENCE and its content is revocationTime followed by an
      --  optional [0] EXPLICIT reason. Stepping past it, as this used to,
      --  loses when the revocation took effect -- which is the difference
      --  between a signature made before it and one made after.
      if State = Revoked and then not Is_Empty (Value) then
         declare
            Within : Offset := Value.First;
            When_T : Certificate_Time;
            Try    : Decode_Status;
         begin
            CryptoLib.X509.Times.Read
              (Data, Within, Value.Last, 9, Limits, When_T, Try);
            if Try = Ok then
               Revoked_At := When_T;
               Revoked_Given := True;

               if not DER_Reader.At_End (Within, Value.Last) then
                  declare
                     Tag  : Element;
                     Code : Element;
                     Deep : Offset;
                  begin
                     DER_Reader.Read
                       (Data, Within, Value.Last, 9, Limits, Tag, Try);
                     if Try = Ok
                       and then Tag.Class = Context_Specific
                       and then Tag.Number = 0
                       and then Tag.Constructed
                     then
                        Deep := Tag.First;
                        DER_Reader.Read
                          (Data, Deep, Tag.Last, 10, Limits, Code, Try);
                        if Try = Ok
                          and then Code.Class = Universal
                          and then Code.Number = Tag_Enumerated
                        then
                           --  The responder said something; whether this
                           --  crate names the code is a separate matter.
                           Reason_Given := True;
                           Reason := CryptoLib.X509.Unknown_Reason;
                           if Content_Length (Code) = 1
                             and then Data (Code.First) < 16#80#
                           then
                              Reason :=
                                CryptoLib.X509.Reason_Of
                                  (Natural (Data (Code.First)));
                           end if;
                        end if;
                     end if;
                  end;
               end if;
            end if;
         end;
      end if;

      CryptoLib.X509.Times.Read
        (Data, Inner, Single.Last, 8, Limits, Issued, Status);
      if Status /= Ok then
         return;
      end if;

      --  What is left is nextUpdate [0] and singleExtensions [1], both
      --  optional. The cursor has to advance past whichever is present:
      --  peeking at the first without stepping over it leaves the second
      --  unreachable, which is how the per-entry extensions went unread.
      while not DER_Reader.At_End (Inner, Single.Last) loop
         declare
            Look : Offset := Inner;
            Tag  : Element;
            Try  : Decode_Status;
         begin
            DER_Reader.Read (Data, Look, Single.Last, 8, Limits, Tag, Try);
            exit when Try /= Ok
              or else Tag.Class /= Context_Specific
              or else not Tag.Constructed;

            case Tag.Number is
               when 0 =>
                  declare
                     Within : Offset := Tag.First;
                  begin
                     CryptoLib.X509.Times.Read
                       (Data, Within, Tag.Last, 9, Limits, Due, Status);
                     if Status = Ok then
                        Due_Given := True;
                     else
                        Status := Ok;
                     end if;
                  end;

               when 1 =>
                  --  singleExtensions. The nonce does not belong here, so
                  --  only the criticality answer is taken.
                  declare
                     At_Nonce : Span;
                     Carried  : Boolean;
                     Odd      : Boolean;
                  begin
                     Scan_Extensions
                       (Data, Inner, Single.Last, 8, 1, Limits,
                        At_Nonce, Carried, Odd);
                     Unknown_Critical := Unknown_Critical or else Odd;
                  end;

               when others =>
                  null;
            end case;

            Inner := Look;
         end;
      end loop;
   end Read_Single_Response;

   function Decode_Response
     (Data   : Octets;
      Limits : Decode_Limits;
      Status : out Decode_Status) return Response
   is
      Result : Response (Data'Length);
      Shift  : constant Offset := 1 - Data'First;
      Work   : Octets renames Result.DER;

      Cursor : Offset;
      Outer  : Element;
      Field  : Element;
   begin
      Status := Ok;

      if Data'Length = 0 then
         Status := Truncated_Input;
         return Result;
      end if;

      if Natural (Data'Length) > Limits.Maximum_Input_Size then
         Status := Size_Limit_Exceeded;
         return Result;
      end if;

      for I in Data'Range loop
         Work (I + Shift) := Data (I);
      end loop;

      Cursor := Work'First;
      DER_Reader.Read_Sequence
        (Work, Cursor, Work'Last, 0, Limits, Outer, Status);
      if Status /= Ok then
         return Result;
      end if;

      --  responseStatus ENUMERATED
      Cursor := Outer.First;
      DER_Reader.Read_Expected
        (Work, Cursor, Outer.Last, 1, Limits, Universal, 10, False,
         Field, Status);
      if Status /= Ok then
         return Result;
      end if;

      if Content_Length (Field) /= 1 then
         Status := Invalid_Value;
         return Result;
      end if;

      case Natural (Work (Field.First)) is
         when 0      => Result.Outcome := Successful;
         when 1      => Result.Outcome := Malformed_Request;
         when 2      => Result.Outcome := Internal_Error;
         when 3      => Result.Outcome := Try_Later;
         when 5      => Result.Outcome := Signature_Required;
         when 6      => Result.Outcome := Unauthorized;
         when others => Result.Outcome := Unknown_Response_Status;
      end case;

      if Result.Outcome /= Successful then
         --  A refusal carries no responseBytes, and there is nothing further
         --  to read. It decoded; it just does not answer.
         Result.Present := True;
         return Result;
      end if;

      --  responseBytes [0] EXPLICIT SEQUENCE { responseType, response }
      declare
         Wrapper : Element;
         Bytes   : Element;
         Inner   : Offset;
         Kind    : Element;
         Body_S  : Element;
      begin
         DER_Reader.Read_Expected
           (Work, Cursor, Outer.Last, 1, Limits, Context_Specific, 0, True,
            Wrapper, Status);
         if Status /= Ok then
            return Result;
         end if;

         Inner := Wrapper.First;
         DER_Reader.Read_Sequence
           (Work, Inner, Wrapper.Last, 2, Limits, Bytes, Status);
         if Status /= Ok then
            return Result;
         end if;

         Inner := Bytes.First;
         DER_Reader.Read_Object_Identifier
           (Work, Inner, Bytes.Last, 3, Limits, Kind, Status);
         if Status /= Ok then
            return Result;
         end if;

         if not OID_Table.Matches (Work, Kind, OID_Table.OCSP_Basic_Response)
         then
            --  The only response type defined. Anything else is not one this
            --  can read, which is not the same as malformed.
            Status := Unsupported_Encoding;
            return Result;
         end if;

         DER_Reader.Read_Octet_String
           (Work, Inner, Bytes.Last, 3, Limits, Body_S, Status);
         if Status /= Ok then
            return Result;
         end if;

         --  BasicOCSPResponse ::= SEQUENCE { tbsResponseData,
         --      signatureAlgorithm, signature, certs [0] EXPLICIT OPTIONAL }
         declare
            Basic  : Element;
            Walk   : Offset := Body_S.First;
            TBS    : Element;
            Alg_ID : Element;
            Unused : Natural;
         begin
            DER_Reader.Read_Sequence
              (Work, Walk, Body_S.Last, 4, Limits, Basic, Status);
            if Status /= Ok then
               return Result;
            end if;

            Walk := Basic.First;
            DER_Reader.Read_Sequence
              (Work, Walk, Basic.Last, 5, Limits, TBS, Status);
            if Status /= Ok then
               return Result;
            end if;
            Result.TBS :=
              (First => Encoded_First (TBS), Last => Encoded_Last (TBS));

            Read_Algorithm
              (Work, Walk, Basic.Last, 5, Limits, Alg_ID, Status);
            if Status /= Ok then
               return Result;
            end if;
            Result.Algorithm := Signature_Algorithm_For (Work, Alg_ID);

            DER_Reader.Read_Bit_String
              (Work, Walk, Basic.Last, 5, Limits, Field, Unused, Status);
            if Status /= Ok then
               return Result;
            end if;
            Result.Signature := (First => Field.First, Last => Field.Last);

            --  certs [0], holding the delegated responder when there is one.
            if not DER_Reader.At_End (Walk, Basic.Last) then
               declare
                  Certs : Element;
                  List  : Element;
                  Each  : Offset;
                  One   : Element;
               begin
                  DER_Reader.Read_Expected
                    (Work, Walk, Basic.Last, 5, Limits,
                     Context_Specific, 0, True, Certs, Status);
                  if Status /= Ok then
                     return Result;
                  end if;

                  Each := Certs.First;
                  DER_Reader.Read_Sequence
                    (Work, Each, Certs.Last, 6, Limits, List, Status);
                  if Status /= Ok then
                     return Result;
                  end if;

                  Each := List.First;
                  if not DER_Reader.At_End (Each, List.Last) then
                     DER_Reader.Read_Sequence
                       (Work, Each, List.Last, 7, Limits, One, Status);
                     if Status /= Ok then
                        return Result;
                     end if;
                     Result.Signer_Cert :=
                       (First => Encoded_First (One),
                        Last  => Encoded_Last (One));
                     Result.Has_Signer := True;
                  end if;
               end;
            end if;

            --  ResponseData ::= SEQUENCE { version [0] DEFAULT v1,
            --      responderID, producedAt, responses, extensions [1] }
            declare
               Part : Offset := TBS.First;
               Skip : Element;
               Look : Offset;
               Peek : Element;
               Try  : Decode_Status;
               Made : Certificate_Time;
            begin
               --  version [0], responderID [1] or [2]: neither is needed to
               --  decide anything here, and the responder's identity is
               --  settled by the signature rather than by what it calls
               --  itself.
               loop
                  Look := Part;
                  DER_Reader.Read
                    (Work, Look, TBS.Last, 6, Limits, Peek, Try);
                  exit when Try /= Ok;
                  exit when Peek.Class = Universal
                    and then Peek.Number in Tag_UTC_Time
                                          | Tag_Generalized_Time;
                  Part := Look;
               end loop;

               CryptoLib.X509.Times.Read
                 (Work, Part, TBS.Last, 6, Limits, Made, Status);
               if Status /= Ok then
                  return Result;
               end if;

               --  responses SEQUENCE OF SingleResponse. A responder may
               --  answer about several certificates in one response, so
               --  which one applies is not knowable here -- it depends on
               --  the certificate the caller asks about. The list is kept
               --  and Verify picks from it. Reading only the first would
               --  answer about somebody else's certificate whenever a
               --  responder bundled its replies.
               DER_Reader.Read_Sequence
                 (Work, Part, TBS.Last, 6, Limits, Skip, Status);
               if Status /= Ok then
                  return Result;
               end if;
               Result.Responses := (First => Skip.First, Last => Skip.Last);

               --  Walked once here so that a malformed entry anywhere in the
               --  list is refused at decode rather than found later by a
               --  caller who happened to ask about that certificate.
               declare
                  Row   : Offset := Skip.First;
                  Row_ID : Span;
                  Row_State : Certificate_Status;
                  Row_From  : Certificate_Time;
                  Row_To    : Certificate_Time;
                  Row_Due   : Boolean;
                  Row_Rev   : Certificate_Time;
                  Row_Rev_Given : Boolean;
                  Row_Reason    : CryptoLib.X509.Revocation_Reason;
                  Row_Reason_Given : Boolean;
                  Row_Odd   : Boolean;
                  Name_H, Key_H, Serial_S : Span;
                  Seen  : Natural := 0;
               begin
                  while not DER_Reader.At_End (Row, Skip.Last) loop
                     Read_Single_Response
                       (Work, Row, Skip.Last, Limits, Name_H, Key_H,
                        Serial_S, Row_State, Row_From, Row_To, Row_Due,
                        Row_Rev, Row_Rev_Given, Row_Reason, Row_Reason_Given,
                        Row_Odd, Status);
                     exit when Status /= Ok;
                     Result.Odd_Critical :=
                       Result.Odd_Critical or else Row_Odd;
                     Seen := Seen + 1;
                  end loop;

                  if Status /= Ok or else Seen = 0 then
                     if Status = Ok then
                        Status := Invalid_Value;
                     end if;
                     return Result;
                  end if;

                  pragma Unreferenced (Row_ID);
               end;

               --  responseExtensions [1] EXPLICIT Extensions OPTIONAL.
               declare
                  At_Nonce : Span;
                  Carried  : Boolean;
                  Odd      : Boolean;
               begin
                  Scan_Extensions
                    (Work, Part, TBS.Last, 6, 1, Limits, At_Nonce, Carried,
                     Odd);
                  Result.Nonce_At := At_Nonce;
                  Result.Has_Nonce_Ext := Carried;
                  Result.Odd_Critical := Result.Odd_Critical or else Odd;
               end;
            end;
         end;
      end;

      Result.Present := True;
      return Result;
   end Decode_Response;

   function Is_Present (Item : Response) return Boolean
   is (Item.Present);

   function Status_Of (Item : Response) return Response_Status
   is (Item.Outcome);

   function Certificate_Status_Of (Item : Response) return Certificate_Status
   is (Item.Cert_State);

   function This_Update (Item : Response) return Certificate_Time
   is (Item.Issued);

   function Has_Next_Update (Item : Response) return Boolean
   is (Item.Due_Present);

   function Next_Update (Item : Response) return Certificate_Time
   is (Item.Due);

   function Has_Unsupported_Critical_Extension
     (Item : Response) return Boolean
   is (Item.Odd_Critical);

   function Has_Nonce (Item : Response) return Boolean
   is (Item.Has_Nonce_Ext);

   function Nonce (Item : Response) return Octets
   is (Slice (Item, Item.Nonce_At));

   function Revocation_Of (Item : Response) return Revocation_Details
   is (Item.Revocation);

   function Responder (Item : Response) return Responder_Kind
   is (Item.Signed_By);

   function Same_Bytes (Left : Octets; Right : Octets) return Boolean is
   begin
      if Left'Length /= Right'Length or else Left'Length = 0 then
         return False;
      end if;
      for I in 0 .. Left'Length - 1 loop
         if Left (Left'First + Offset (I)) /= Right (Right'First + Offset (I))
         then
            return False;
         end if;
      end loop;
      return True;
   end Same_Bytes;

   function Verify
     (Item           : in out Response;
      Subject        : Certificate;
      Issuer         : Certificate;
      Expected_Nonce : Octets := No_Nonce) return Verification_Result
   is
   begin
      Item.Signed_By := Not_Established;

      if not Item.Present
        or else not X509C.Is_Present (Subject)
        or else not X509C.Is_Present (Issuer)
      then
         return Missing_Input;
      end if;

      if Item.Outcome /= Successful then
         return Not_Successful;
      end if;

      --  Which of the responses is about this certificate. A responder may
      --  answer about several at once, so the list is searched rather than
      --  its first entry assumed: taking the first would answer about
      --  somebody else's certificate whenever a responder bundled its
      --  replies, and answer confidently.
      declare
         Name_Hash : constant Octets :=
           Octets (CryptoLib.Hashes.SHA1 (X509C.Subject_Bytes (Issuer)));
         Key_Hash  : constant Octets :=
           Octets (CryptoLib.Hashes.SHA1 (X509C.Public_Key (Issuer)));
         Serial    : constant Octets := X509C.Serial_Number (Subject);

         Row    : Offset := Item.Responses.First;
         Parse  : Decode_Status;
         Found  : Boolean := False;

         Row_Name, Row_Key, Row_Serial : Span;
         Row_State : Certificate_Status;
         Row_From, Row_To : Certificate_Time;
         Row_Due   : Boolean;
         Row_Rev   : Certificate_Time;
         Row_Rev_Given : Boolean;
         Row_Reason    : CryptoLib.X509.Revocation_Reason;
         Row_Reason_Given : Boolean;
         Row_Odd   : Boolean;
      begin
         if Item.Responses.Last < Item.Responses.First then
            return Malformed_Response;
         end if;

         while not DER_Reader.At_End (Row, Item.Responses.Last) loop
            Read_Single_Response
              (Item.DER, Row, Item.Responses.Last, Default_Limits,
               Row_Name, Row_Key, Row_Serial, Row_State, Row_From, Row_To,
               Row_Due, Row_Rev, Row_Rev_Given, Row_Reason, Row_Reason_Given,
               Row_Odd, Parse);
            exit when Parse /= Ok;

            if Same_Bytes (Slice (Item, Row_Name), Name_Hash)
              and then Same_Bytes (Slice (Item, Row_Key), Key_Hash)
              and then CryptoLib.X509.Same_Serial
                         (Slice (Item, Row_Serial), Serial)
            then
               --  This is the answer that was asked for; the rest are about
               --  other certificates and say nothing about this one.
               Item.Name_Hash := Row_Name;
               Item.Key_Hash := Row_Key;
               Item.Serial := Row_Serial;
               Item.Cert_State := Row_State;
               Item.Issued := Row_From;
               Item.Due := Row_To;
               Item.Due_Present := Row_Due;
               Item.Revocation :=
                 (Present    => Row_State = Revoked and then Row_Rev_Given,
                  Revoked_At => Row_Rev,
                  Has_Reason => Row_Reason_Given,
                  Reason     => Row_Reason);
               Found := True;
               exit;
            end if;
         end loop;

         if not Found then
            return Wrong_Certificate;
         end if;
      end;

      --  Before anything is read out of the response. A critical extension
      --  this cannot interpret means the response does not say what this
      --  reads it as saying, whoever signed it.
      if Item.Odd_Critical then
         return Unsupported_Extension;
      end if;

      --  Checked before the signature, because a nonce that does not match
      --  means this is not the answer to the question asked, however well
      --  signed it is. Only checked when the caller sent one: a response
      --  fetched without a nonce has nothing to compare against, and
      --  demanding one anyway would refuse every stapled response.
      if Expected_Nonce'Length > 0 then
         if not Item.Has_Nonce_Ext then
            return Nonce_Missing;
         end if;
         if not Same_Bytes (Slice (Item, Item.Nonce_At), Expected_Nonce) then
            return Nonce_Mismatch;
         end if;
      end if;

      if not XS.Is_Supported (Item.Algorithm) then
         return Unsupported_Algorithm;
      end if;

      --  The issuer may answer for its own certificates.
      if XS.Verify_Signed_Data
           (Signed    => Slice (Item, Item.TBS),
            Signature => Slice (Item, Item.Signature),
            Algorithm => Item.Algorithm,
            Issuer    => Issuer) = XS.Valid
      then
         Item.Signed_By := Issuer_Signed;
         return Accepted;
      end if;

      --  Otherwise a responder the issuer delegated to, which has to be in
      --  the response and has to have been issued by that issuer.
      if not Item.Has_Signer then
         return Unknown_Responder;
      end if;

      declare
         Parsed : Decode_Status;
         Signer : constant Certificate :=
           X509C.Decode_DER
             (Slice (Item, Item.Signer_Cert), Default_Limits, Parsed);
      begin
         if Parsed /= Ok or else not X509C.Is_Present (Signer) then
            return Malformed_Response;
         end if;

         if XS.Verify_Certificate_Signature (Signer, Issuer) /= XS.Valid then
            --  Signed by something the issuer did not vouch for. Without this
            --  check, anyone holding any certificate could answer for
            --  anybody's.
            return Unknown_Responder;
         end if;

         declare
            Usage : constant XE.Extended_Key_Usage :=
              XE.Get_Extended_Key_Usage (Signer);
         begin
            --  The delegation has to be explicit. An ordinary certificate the
            --  issuer signed -- a web server's, say -- must not be able to
            --  speak for the issuer's revocation state, so an absent extended
            --  key usage is not permission here.
            if not (Usage.Present and then Usage.OCSP_Signing) then
               return Delegate_Not_Authorized;
            end if;
         end;

         if XS.Verify_Signed_Data
              (Signed    => Slice (Item, Item.TBS),
               Signature => Slice (Item, Item.Signature),
               Algorithm => Item.Algorithm,
               Issuer    => Signer) /= XS.Valid
         then
            return Invalid_Signature;
         end if;

         Item.Signed_By := Delegate_Signed;
         return Accepted;
      end;
   end Verify;

end CryptoLib.OCSP;
