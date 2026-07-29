with Ada.Streams;

with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.OIDs;
with CryptoLib.X509.Times;

package body CryptoLib.X509.Certificates is

   use CryptoLib.ASN1;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use CryptoLib.ASN1.Errors;

   package DER_Reader renames CryptoLib.ASN1.DER;
   package OID_Table renames CryptoLib.ASN1.OIDs;

   Empty_Octets : constant Octets (1 .. 0) := [others => 0];

   function Slice (Item : Certificate; Where : Span) return Octets
   is (if Where.Last < Where.First
       then Empty_Octets
       else Item.DER (Where.First .. Where.Last));

   function To_Span (Value : Element) return Span
   is (First => Value.First, Last => Value.Last);

   function Encoded_Span (Value : Element) return Span
   is (First => Encoded_First (Value), Last => Encoded_Last (Value));

   --  Which signature algorithm does this AlgorithmIdentifier name?
   --  Do two parsed extensions name the same identifier?
   function Same_Identifier
     (Data : Octets; Left : Extension_Record; Right : Extension_Record)
      return Boolean
   is
      L : constant Octets := Data (Left.OID_First .. Left.OID_Last);
      R : constant Octets := Data (Right.OID_First .. Right.OID_Last);
   begin
      if L'Length /= R'Length then
         return False;
      end if;
      for I in 0 .. L'Length - 1 loop
         if L (L'First + Offset (I)) /= R (R'First + Offset (I)) then
            return False;
         end if;
      end loop;
      return True;
   end Same_Identifier;

   function Signature_Algorithm_For
     (Data : Octets; OID : Element) return Signature_Algorithm
   is
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
      elsif OID_Table.Matches (Data, OID, OID_Table.RSASSA_PSS) then
         return RSASSA_PSS;
      elsif OID_Table.Matches (Data, OID, OID_Table.Ed25519) then
         return Ed25519_Signature;
      elsif OID_Table.Matches (Data, OID, OID_Table.Ed448) then
         return Ed448_Signature;
      else
         return Unknown_Signature_Algorithm;
      end if;
   end Signature_Algorithm_For;

   --  Read an AlgorithmIdentifier, reporting its OID and, for EC keys, the
   --  named curve that follows it.
   procedure Read_Algorithm
     (Data       : Octets;
      Position   : in out Offset;
      Last       : Offset;
      Depth      : Natural;
      Limits     : Decode_Limits;
      Identifier : out Element;
      Parameter  : out Element;
      Has_Param  : out Boolean;
      Status     : out Decode_Status)
   is
      Cursor : Offset := Position;
      Alg    : Element;
      Inner  : Offset;
   begin
      Identifier := (others => <>);
      Parameter := (others => <>);
      Has_Param := False;

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

      --  Parameters are optional and their shape depends on the algorithm:
      --  a named curve for EC, NULL for the RSA family, absent for Ed25519.
      --  Read whatever is there without interpreting it here.
      if not DER_Reader.At_End (Inner, Alg.Last) then
         DER_Reader.Read
           (Data, Inner, Alg.Last, Depth + 1, Limits, Parameter, Status);
         if Status /= Ok then
            return;
         end if;
         Has_Param := True;
      end if;

      Position := Cursor;
   end Read_Algorithm;

   --  See CryptoLib.X509.Times: certificates and revocation lists share one
   --  reader for these, so a validity window and a nextUpdate cannot be read
   --  differently.
   procedure Read_Time
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Value    : out Certificate_Time;
      Status   : out Decode_Status)
   is
   begin
      CryptoLib.X509.Times.Read
        (Data, Position, Last, Depth, Limits, Value, Status);
   end Read_Time;

   function Decode_DER
     (Data   : Octets;
      Limits : Decode_Limits;
      Status : out Decode_Status) return Certificate
   is
      Result : Certificate (Data'Length);

      --  Offsets are rebased onto the copy the certificate keeps, so that
      --  every span stays meaningful once the caller's buffer is gone.
      Shift  : constant Offset := 1 - Data'First;

      Work   : Octets renames Result.DER;
      Cursor : Offset;
      Outer  : Element;
      TBS    : Element;
      Field  : Element;
      Alg_ID : Element;
      Param  : Element;
      Has_P  : Boolean;
      Inner  : Offset;
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

      if not DER_Reader.At_End (Cursor, Work'Last) then
         --  A certificate is one SEQUENCE. Anything after it was not part of
         --  what was signed and must not be quietly ignored.
         Status := Trailing_Data;
         return Result;
      end if;

      Cursor := Outer.First;
      DER_Reader.Read_Sequence
        (Work, Cursor, Outer.Last, 1, Limits, TBS, Status);
      if Status /= Ok then
         return Result;
      end if;
      Result.TBS := Encoded_Span (TBS);

      --  signatureAlgorithm, the outer one. It must agree with the copy
      --  inside the TBS, which is checked below.
      Read_Algorithm
        (Work, Cursor, Outer.Last, 1, Limits, Alg_ID, Param, Has_P, Status);
      if Status /= Ok then
         return Result;
      end if;
      Result.Sig_Algorithm := Signature_Algorithm_For (Work, Alg_ID);
      if Has_P then
         Result.Sig_Parameters :=
           (First => Encoded_First (Param), Last => Encoded_Last (Param));
      end if;

      declare
         Unused : Natural;
      begin
         DER_Reader.Read_Bit_String
           (Work, Cursor, Outer.Last, 1, Limits, Field, Unused, Status);
         if Status /= Ok then
            return Result;
         end if;
         if Unused /= 0 then
            Status := Invalid_Value;
            return Result;
         end if;
         Result.Signature := To_Span (Field);
      end;

      if not DER_Reader.At_End (Cursor, Outer.Last) then
         Status := Trailing_Data;
         return Result;
      end if;

      --  Now the TBS itself.
      Inner := TBS.First;

      --  version [0] EXPLICIT, absent meaning v1.
      declare
         Look : Offset := Inner;
         Tag  : Element;
         Peek : Decode_Status;
      begin
         DER_Reader.Read (Work, Look, TBS.Last, 2, Limits, Tag, Peek);
         if Peek = Ok
           and then Tag.Class = Context_Specific
           and then Tag.Number = 0
           and then Tag.Constructed
         then
            declare
               Version_Cursor : Offset := Tag.First;
               Raw            : Natural;
            begin
               DER_Reader.Read_Small_Integer
                 (Work, Version_Cursor, Tag.Last, 3, Limits, Raw, Status);
               if Status /= Ok then
                  return Result;
               end if;
               if Raw > 2 then
                  --  v1 is encoded 0, v3 is 2. Anything higher is a version
                  --  whose rules are not known here.
                  Status := Unsupported_Encoding;
                  return Result;
               end if;
               Result.Version_Number := Raw + 1;
               Inner := Look;
            end;
         end if;
      end;

      declare
         Negative : Boolean;
      begin
         DER_Reader.Read_Integer
           (Work, Inner, TBS.Last, 2, Limits, Field, Negative, Status);
         if Status /= Ok then
            return Result;
         end if;
         if Negative then
            --  RFC 5280 requires a positive serial number.
            Status := Invalid_Value;
            return Result;
         end if;
         Result.Serial := To_Span (Field);
      end;

      --  The inner signature algorithm must match the outer one. A
      --  certificate that names one algorithm where it is signed and another
      --  where it is verified is one an attacker has had a hand in.
      Read_Algorithm
        (Work, Inner, TBS.Last, 2, Limits, Alg_ID, Param, Has_P, Status);
      if Status /= Ok then
         return Result;
      end if;
      if Signature_Algorithm_For (Work, Alg_ID) /= Result.Sig_Algorithm then
         Status := Invalid_Value;
         return Result;
      end if;

      DER_Reader.Read_Sequence
        (Work, Inner, TBS.Last, 2, Limits, Field, Status);
      if Status /= Ok then
         return Result;
      end if;
      Result.Issuer := Encoded_Span (Field);

      --  validity
      declare
         Validity : Element;
         Times    : Offset;
      begin
         DER_Reader.Read_Sequence
           (Work, Inner, TBS.Last, 2, Limits, Validity, Status);
         if Status /= Ok then
            return Result;
         end if;

         Times := Validity.First;
         Read_Time
           (Work, Times, Validity.Last, 3, Limits, Result.Valid_From, Status);
         if Status /= Ok then
            return Result;
         end if;
         Read_Time
           (Work, Times, Validity.Last, 3, Limits, Result.Valid_To, Status);
         if Status /= Ok then
            return Result;
         end if;
         if not DER_Reader.At_End (Times, Validity.Last) then
            Status := Trailing_Data;
            return Result;
         end if;
      end;

      DER_Reader.Read_Sequence
        (Work, Inner, TBS.Last, 2, Limits, Field, Status);
      if Status /= Ok then
         return Result;
      end if;
      Result.Subject := Encoded_Span (Field);

      --  subjectPublicKeyInfo
      declare
         SPKI   : Element;
         Within : Offset;
         Bits   : Element;
         Unused : Natural;
      begin
         DER_Reader.Read_Sequence
           (Work, Inner, TBS.Last, 2, Limits, SPKI, Status);
         if Status /= Ok then
            return Result;
         end if;
         Result.SPKI := Encoded_Span (SPKI);

         Within := SPKI.First;
         Read_Algorithm
           (Work, Within, SPKI.Last, 3, Limits, Alg_ID, Param, Has_P, Status);
         if Status /= Ok then
            return Result;
         end if;

         if OID_Table.Matches (Work, Alg_ID, OID_Table.Ed25519) then
            Result.Key_Algorithm := Ed25519;
         elsif OID_Table.Matches (Work, Alg_ID, OID_Table.Ed448) then
            Result.Key_Algorithm := Ed448;
         elsif OID_Table.Matches (Work, Alg_ID, OID_Table.RSA_Encryption) then
            Result.Key_Algorithm := RSA;
         elsif OID_Table.Matches (Work, Alg_ID, OID_Table.EC_Public_Key) then
            --  Which curve is in the parameters, and an EC key without them
            --  does not say what it is.
            if not Has_P then
               Result.Key_Algorithm := Unknown_Public_Key_Algorithm;
            elsif OID_Table.Matches (Work, Param, OID_Table.Prime256v1) then
               Result.Key_Algorithm := ECDSA_P256;
            elsif OID_Table.Matches (Work, Param, OID_Table.Secp384r1) then
               Result.Key_Algorithm := ECDSA_P384;
            elsif OID_Table.Matches (Work, Param, OID_Table.Secp521r1) then
               Result.Key_Algorithm := ECDSA_P521;
            else
               Result.Key_Algorithm := Unknown_Public_Key_Algorithm;
            end if;
         else
            Result.Key_Algorithm := Unknown_Public_Key_Algorithm;
         end if;

         DER_Reader.Read_Bit_String
           (Work, Within, SPKI.Last, 3, Limits, Bits, Unused, Status);
         if Status /= Ok then
            return Result;
         end if;
         if Unused /= 0 then
            Status := Invalid_Value;
            return Result;
         end if;
         Result.SPKI_Key := To_Span (Bits);

         if not DER_Reader.At_End (Within, SPKI.Last) then
            Status := Trailing_Data;
            return Result;
         end if;
      end;

      --  The optional trailing fields. The unique identifiers are implicit
      --  [1] and [2]; extensions are explicit [3].
      while not DER_Reader.At_End (Inner, TBS.Last) loop
         declare
            Look : Offset := Inner;
            Tag  : Element;
         begin
            DER_Reader.Read (Work, Look, TBS.Last, 2, Limits, Tag, Status);
            if Status /= Ok then
               return Result;
            end if;

            if Tag.Class /= Context_Specific then
               Status := Invalid_Tag;
               return Result;
            end if;

            case Tag.Number is
               when 1 | 2 =>
                  --  Present only in v2 and v3, and of no interest here; kept
                  --  unread rather than rejected.
                  Inner := Look;

               when 3 =>
                  declare
                     List   : Element;
                     Walk   : Offset := Tag.First;
                     Each   : Offset;
                     Ext    : Element;
                     Seen   : Natural := 0;
                  begin
                     DER_Reader.Read_Sequence
                       (Work, Walk, Tag.Last, 3, Limits, List, Status);
                     if Status /= Ok then
                        return Result;
                     end if;

                     Each := List.First;
                     while not DER_Reader.At_End (Each, List.Last) loop
                        DER_Reader.Read_Sequence
                          (Work, Each, List.Last, 4, Limits, Ext, Status);
                        if Status /= Ok then
                           return Result;
                        end if;

                        if Seen = Maximum_Extensions
                          or else Seen = Limits.Maximum_Sequence_Items
                        then
                           Status := Size_Limit_Exceeded;
                           return Result;
                        end if;
                        Seen := Seen + 1;

                        declare
                           Part     : Offset := Ext.First;
                           OID      : Element;
                           Critical : Boolean := False;
                           Value    : Element;
                        begin
                           DER_Reader.Read_Object_Identifier
                             (Work, Part, Ext.Last, 5, Limits, OID, Status);
                           if Status /= Ok then
                              return Result;
                           end if;

                           --  critical DEFAULT FALSE. DER omits a default, so
                           --  an explicit FALSE here is itself non-canonical.
                           declare
                              Peek : Offset := Part;
                              Try  : Element;
                              Look2 : Decode_Status;
                           begin
                              DER_Reader.Read
                                (Work, Peek, Ext.Last, 5, Limits, Try, Look2);
                              if Look2 = Ok
                                and then Try.Class = Universal
                                and then Try.Number = Tag_Boolean
                              then
                                 DER_Reader.Read_Boolean
                                   (Work, Part, Ext.Last, 5, Limits,
                                    Critical, Status);
                                 if Status /= Ok then
                                    return Result;
                                 end if;
                                 if not Critical then
                                    Status := Non_Canonical_DER;
                                    return Result;
                                 end if;
                              end if;
                           end;

                           DER_Reader.Read_Octet_String
                             (Work, Part, Ext.Last, 5, Limits, Value, Status);
                           if Status /= Ok then
                              return Result;
                           end if;

                           if not DER_Reader.At_End (Part, Ext.Last) then
                              Status := Trailing_Data;
                              return Result;
                           end if;

                           Result.Extensions (Seen) :=
                             (OID_First   => OID.First,
                              OID_Last    => OID.Last,
                              Critical    => Critical,
                              Value_First => Value.First,
                              Value_Last  => Value.Last);
                        end;
                     end loop;

                     if not DER_Reader.At_End (Walk, Tag.Last) then
                        Status := Trailing_Data;
                        return Result;
                     end if;

                     --  RFC 5280: a certificate MUST NOT carry two
                     --  instances of the same extension. Refused rather than
                     --  resolved, because there is no right way to resolve
                     --  it: readers that take the first and readers that
                     --  take the last both look correct, and a certificate
                     --  carrying basicConstraints twice is a CA to one of
                     --  them and not to the other. OpenSSL refuses to load
                     --  such a certificate at all.
                     for A in 1 .. Seen loop
                        for B in A + 1 .. Seen loop
                           if Same_Identifier
                                (Work, Result.Extensions (A),
                                 Result.Extensions (B))
                           then
                              Status := Invalid_Value;
                              return Result;
                           end if;
                        end loop;
                     end loop;

                     --  Extensions belong to v3 only. A v1 or v2 certificate
                     --  carrying them is read by some parsers and ignored by
                     --  others, which is the same disagreement by another
                     --  route.
                     if Result.Version_Number /= 3 then
                        Status := Invalid_Value;
                        return Result;
                     end if;

                     Result.Extension_Total := Seen;
                     Inner := Look;
                  end;

               when others =>
                  Status := Invalid_Tag;
                  return Result;
            end case;
         end;
      end loop;

      Result.Present := True;
      return Result;
   end Decode_DER;

   function Is_Present (Item : Certificate) return Boolean
   is (Item.Present);

   function Version (Item : Certificate) return Natural
   is (Item.Version_Number);

   function Serial_Number (Item : Certificate) return Octets
   is (Slice (Item, Item.Serial));

   function Issuer_Bytes (Item : Certificate) return Octets
   is (Slice (Item, Item.Issuer));

   function Subject_Bytes (Item : Certificate) return Octets
   is (Slice (Item, Item.Subject));

   function Not_Before (Item : Certificate) return Certificate_Time
   is (Item.Valid_From);

   function Not_After (Item : Certificate) return Certificate_Time
   is (Item.Valid_To);

   function Signature_Algorithm_Of
     (Item : Certificate) return Signature_Algorithm
   is (Item.Sig_Algorithm);

   function Public_Key_Algorithm_Of
     (Item : Certificate) return Public_Key_Algorithm
   is (Item.Key_Algorithm);

   function Public_Key (Item : Certificate) return Octets
   is (Slice (Item, Item.SPKI_Key));

   function Public_Key_Info_Bytes (Item : Certificate) return Octets
   is (Slice (Item, Item.SPKI));

   function TBS_Bytes (Item : Certificate) return Octets
   is (Slice (Item, Item.TBS));

   function Signature_Bytes (Item : Certificate) return Octets
   is (Slice (Item, Item.Signature));

   function Signature_Parameters (Item : Certificate) return Octets
   is (Slice (Item, Item.Sig_Parameters));

   function DER_Bytes (Item : Certificate) return Octets
   is (if Item.Present then Item.DER else Empty_Octets);

   function Extension_Count (Item : Certificate) return Natural
   is (Item.Extension_Total);

   function Extension_Identifier
     (Item : Certificate; Index : Positive) return Octets
   is (if Index > Item.Extension_Total
       then Empty_Octets
       else Slice (Item,
                   (First => Item.Extensions (Index).OID_First,
                    Last  => Item.Extensions (Index).OID_Last)));

   function Extension_Is_Critical
     (Item : Certificate; Index : Positive) return Boolean
   is (Index <= Item.Extension_Total
       and then Item.Extensions (Index).Critical);

   function Extension_Value
     (Item : Certificate; Index : Positive) return Octets
   is (if Index > Item.Extension_Total
       then Empty_Octets
       else Slice (Item,
                   (First => Item.Extensions (Index).Value_First,
                    Last  => Item.Extensions (Index).Value_Last)));

   function Find_Extension
     (Item : Certificate; Identifier : Octets) return Natural
   is
   begin
      for I in 1 .. Item.Extension_Total loop
         declare
            Candidate : constant Octets := Extension_Identifier (Item, I);
         begin
            if Candidate'Length = Identifier'Length then
               declare
                  Same : Boolean := True;
               begin
                  for J in 0 .. Identifier'Length - 1 loop
                     if Candidate (Candidate'First + Offset (J))
                       /= Identifier (Identifier'First + Offset (J))
                     then
                        Same := False;
                        exit;
                     end if;
                  end loop;
                  if Same then
                     return I;
                  end if;
               end;
            end if;
         end;
      end loop;
      return 0;
   end Find_Extension;

   function Is_Self_Issued (Item : Certificate) return Boolean is
      Left  : constant Octets := Issuer_Bytes (Item);
      Right : constant Octets := Subject_Bytes (Item);
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
   end Is_Self_Issued;

   --  The first common name within an encoded Name.
   --
   --  A Name is a sequence of relative names, each a set of attribute/value
   --  pairs. Only the value's octets are returned: turning a
   --  DirectoryString's several encodings into text is a display concern and
   --  belongs above this.
   function First_Common_Name (Item : Certificate; Where : Span) return String
   is
      Limits : constant Decode_Limits := CryptoLib.ASN1.Default_Limits;
      Work   : Octets renames Item.DER;
      Cursor : Offset;
      Name   : Element;
      Status : Decode_Status;
   begin
      if Where.Last < Where.First then
         return "";
      end if;

      Cursor := Where.First;
      DER_Reader.Read_Sequence
        (Work, Cursor, Where.Last, 0, Limits, Name, Status);
      if Status /= Ok then
         return "";
      end if;

      declare
         RDN_Cursor : Offset := Name.First;
      begin
         while not DER_Reader.At_End (RDN_Cursor, Name.Last) loop
            declare
               RDN : Element;
            begin
               DER_Reader.Read_Set
                 (Work, RDN_Cursor, Name.Last, 1, Limits, RDN, Status);
               exit when Status /= Ok;

               declare
                  Pair_Cursor : Offset := RDN.First;
               begin
                  while not DER_Reader.At_End (Pair_Cursor, RDN.Last) loop
                     declare
                        Pair  : Element;
                        Inner : Offset;
                        OID   : Element;
                        Value : Element;
                     begin
                        DER_Reader.Read_Sequence
                          (Work, Pair_Cursor, RDN.Last, 2, Limits, Pair,
                           Status);
                        exit when Status /= Ok;

                        Inner := Pair.First;
                        DER_Reader.Read_Object_Identifier
                          (Work, Inner, Pair.Last, 3, Limits, OID, Status);
                        exit when Status /= Ok;

                        DER_Reader.Read
                          (Work, Inner, Pair.Last, 3, Limits, Value, Status);
                        exit when Status /= Ok;

                        if OID_Table.Matches
                             (Work, OID, OID_Table.Common_Name)
                        then
                           declare
                              Text : String (1 .. Content_Length (Value));
                           begin
                              for I in Text'Range loop
                                 Text (I) :=
                                   Character'Val
                                     (Work (Value.First + Offset (I - 1)));
                              end loop;
                              return Text;
                           end;
                        end if;
                     end;
                  end loop;
               end;
            end;
         end loop;
      end;

      return "";
   end First_Common_Name;

   function Subject_Common_Name (Item : Certificate) return String
   is (First_Common_Name (Item, Item.Subject));

   function Issuer_Common_Name (Item : Certificate) return String
   is (First_Common_Name (Item, Item.Issuer));

end CryptoLib.X509.Certificates;
