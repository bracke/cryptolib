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

   --  Emit a DER length.
   procedure Put_Length
     (Output : in out Octets;
      Cursor : in out Offset;
      Value  : Natural)
   is
   begin
      if Value < 128 then
         Output (Cursor) := Ada.Streams.Stream_Element (Value);
         Cursor := Cursor + 1;
      elsif Value < 256 then
         Output (Cursor) := 16#81#;
         Output (Cursor + 1) := Ada.Streams.Stream_Element (Value);
         Cursor := Cursor + 2;
      else
         Output (Cursor) := 16#82#;
         Output (Cursor + 1) := Ada.Streams.Stream_Element (Value / 256);
         Output (Cursor + 2) :=
           Ada.Streams.Stream_Element (Value mod 256);
         Cursor := Cursor + 3;
      end if;
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

   --  How many octets a TLV with this much content occupies.
   function TLV_Length (Content : Natural) return Natural
   is (1 + (if Content < 128 then 1 elsif Content < 256 then 2 else 3)
       + Content);

   procedure Build_Request
     (Item   : Certificate;
      Issuer : Certificate;
      Output : out Octets;
      Last   : out Offset;
      Status : out Decode_Status)
   is
      Cursor : Offset := Output'First;
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
         TBS_Content     : constant Natural := TLV_Length (List_Content);
         Outer_Content   : constant Natural := TLV_Length (TBS_Content);
         Total           : constant Natural := TLV_Length (Outer_Content);
      begin
         if Serial'Length = 0 then
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

               --  responses SEQUENCE OF SingleResponse; the first is the one
               --  asked about, and a response bundling others is not
               --  interpreted here.
               DER_Reader.Read_Sequence
                 (Work, Part, TBS.Last, 6, Limits, Skip, Status);
               if Status /= Ok then
                  return Result;
               end if;

               declare
                  Single : Element;
                  Row    : Offset := Skip.First;
                  Cert_ID : Element;
                  Field2 : Element;
                  Inner2 : Offset;
                  State  : Element;
               begin
                  DER_Reader.Read_Sequence
                    (Work, Row, Skip.Last, 7, Limits, Single, Status);
                  if Status /= Ok then
                     return Result;
                  end if;

                  Inner2 := Single.First;
                  DER_Reader.Read_Sequence
                    (Work, Inner2, Single.Last, 8, Limits, Cert_ID, Status);
                  if Status /= Ok then
                     return Result;
                  end if;

                  declare
                     Part2 : Offset := Cert_ID.First;
                     Alg2  : Element;
                     Minus : Boolean;
                  begin
                     Read_Algorithm
                       (Work, Part2, Cert_ID.Last, 9, Limits, Alg2, Status);
                     if Status /= Ok then
                        return Result;
                     end if;

                     DER_Reader.Read_Octet_String
                       (Work, Part2, Cert_ID.Last, 9, Limits, Field2, Status);
                     if Status /= Ok then
                        return Result;
                     end if;
                     Result.Name_Hash :=
                       (First => Field2.First, Last => Field2.Last);

                     DER_Reader.Read_Octet_String
                       (Work, Part2, Cert_ID.Last, 9, Limits, Field2, Status);
                     if Status /= Ok then
                        return Result;
                     end if;
                     Result.Key_Hash :=
                       (First => Field2.First, Last => Field2.Last);

                     DER_Reader.Read_Integer
                       (Work, Part2, Cert_ID.Last, 9, Limits, Field2, Minus,
                        Status);
                     if Status /= Ok then
                        return Result;
                     end if;
                     Result.Serial :=
                       (First => Field2.First, Last => Field2.Last);
                  end;

                  --  certStatus is a CHOICE of context tags: [0] good,
                  --  [1] revoked, [2] unknown.
                  DER_Reader.Read
                    (Work, Inner2, Single.Last, 8, Limits, State, Status);
                  if Status /= Ok then
                     return Result;
                  end if;

                  if State.Class /= Context_Specific then
                     Status := Invalid_Tag;
                     return Result;
                  end if;

                  case State.Number is
                     when 0      => Result.Cert_State := Good;
                     when 1      => Result.Cert_State := Revoked;
                     when others => Result.Cert_State := Unknown;
                  end case;

                  CryptoLib.X509.Times.Read
                    (Work, Inner2, Single.Last, 8, Limits, Result.Issued,
                     Status);
                  if Status /= Ok then
                     return Result;
                  end if;

                  --  nextUpdate is [0] EXPLICIT and optional.
                  if not DER_Reader.At_End (Inner2, Single.Last) then
                     declare
                        Look2 : Offset := Inner2;
                        Tag2  : Element;
                        Try2  : Decode_Status;
                     begin
                        DER_Reader.Read
                          (Work, Look2, Single.Last, 8, Limits, Tag2, Try2);
                        if Try2 = Ok
                          and then Tag2.Class = Context_Specific
                          and then Tag2.Number = 0
                          and then Tag2.Constructed
                        then
                           declare
                              Within : Offset := Tag2.First;
                           begin
                              CryptoLib.X509.Times.Read
                                (Work, Within, Tag2.Last, 9, Limits,
                                 Result.Due, Status);
                              if Status = Ok then
                                 Result.Due_Present := True;
                              else
                                 Status := Ok;
                              end if;
                           end;
                        end if;
                     end;
                  end if;
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
     (Item    : in out Response;
      Subject : Certificate;
      Issuer  : Certificate) return Verification_Result
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

      --  The response has to be about this certificate, under this issuer.
      --  A response that verifies beautifully and concerns somebody else is
      --  the failure this catches.
      declare
         Name_Hash : constant Octets :=
           Octets (CryptoLib.Hashes.SHA1 (X509C.Subject_Bytes (Issuer)));
         Key_Hash  : constant Octets :=
           Octets (CryptoLib.Hashes.SHA1 (X509C.Public_Key (Issuer)));
      begin
         if not Same_Bytes (Slice (Item, Item.Name_Hash), Name_Hash)
           or else not Same_Bytes (Slice (Item, Item.Key_Hash), Key_Hash)
           or else not Same_Bytes
                         (Slice (Item, Item.Serial),
                          X509C.Serial_Number (Subject))
         then
            return Wrong_Certificate;
         end if;
      end;

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
