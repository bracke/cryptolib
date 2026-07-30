with Ada.Streams;

with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.OIDs;
with CryptoLib.X509.Times;

package body CryptoLib.X509.CRLs is

   use CryptoLib.ASN1;
   use CryptoLib.ASN1.Errors;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;

   package DER_Reader renames CryptoLib.ASN1.DER;
   package OID_Table renames CryptoLib.ASN1.OIDs;

   Empty_Octets : constant Octets (1 .. 0) := [others => 0];

   function Slice (Item : Revocation_List; Where : Span) return Octets
   is (if Where.Last < Where.First
       then Empty_Octets
       else Item.DER (Where.First .. Where.Last));

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

   function Decode_DER
     (Data   : Octets;
      Limits : Decode_Limits;
      Status : out Decode_Status) return Revocation_List
   is
      Result : Revocation_List (Data'Length);
      Shift  : constant Offset := 1 - Data'First;
      Work   : Octets renames Result.DER;

      Cursor : Offset;
      Outer  : Element;
      TBS    : Element;
      Field  : Element;
      Alg_ID : Element;
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
         Status := Trailing_Data;
         return Result;
      end if;

      Cursor := Outer.First;
      DER_Reader.Read_Sequence
        (Work, Cursor, Outer.Last, 1, Limits, TBS, Status);
      if Status /= Ok then
         return Result;
      end if;
      Result.TBS := (First => Encoded_First (TBS), Last => Encoded_Last (TBS));

      Read_Algorithm
        (Work, Cursor, Outer.Last, 1, Limits, Alg_ID, Status);
      if Status /= Ok then
         return Result;
      end if;
      Result.Algorithm := Signature_Algorithm_For (Work, Alg_ID);

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
         Result.Signature := (First => Field.First, Last => Field.Last);
      end;

      if not DER_Reader.At_End (Cursor, Outer.Last) then
         Status := Trailing_Data;
         return Result;
      end if;

      --  Now the TBSCertList.
      Inner := TBS.First;

      --  version is OPTIONAL and, when present, an INTEGER before the
      --  algorithm. A v1 CRL simply starts with the algorithm.
      declare
         Look : Offset := Inner;
         Peek : Element;
         Try  : Decode_Status;
      begin
         DER_Reader.Read (Work, Look, TBS.Last, 2, Limits, Peek, Try);
         if Try = Ok
           and then Peek.Class = Universal
           and then Peek.Number = Tag_Integer
         then
            declare
               Raw : Natural;
            begin
               DER_Reader.Read_Small_Integer
                 (Work, Inner, TBS.Last, 2, Limits, Raw, Status);
               if Status /= Ok then
                  return Result;
               end if;
               if Raw > 1 then
                  Status := Unsupported_Encoding;
                  return Result;
               end if;
               Result.Version := Raw + 1;
            end;
         end if;
      end;

      --  The inner algorithm must agree with the outer one, for the same
      --  reason it must on a certificate.
      Read_Algorithm (Work, Inner, TBS.Last, 2, Limits, Alg_ID, Status);
      if Status /= Ok then
         return Result;
      end if;
      if Signature_Algorithm_For (Work, Alg_ID) /= Result.Algorithm then
         Status := Invalid_Value;
         return Result;
      end if;

      DER_Reader.Read_Sequence
        (Work, Inner, TBS.Last, 2, Limits, Field, Status);
      if Status /= Ok then
         return Result;
      end if;
      Result.Issuer :=
        (First => Encoded_First (Field), Last => Encoded_Last (Field));

      CryptoLib.X509.Times.Read
        (Work, Inner, TBS.Last, 2, Limits, Result.Issued, Status);
      if Status /= Ok then
         return Result;
      end if;

      --  nextUpdate is optional, and so is the revoked list, so what comes
      --  next has to be looked at rather than assumed.
      if not DER_Reader.At_End (Inner, TBS.Last) then
         declare
            Look : Offset := Inner;
            Peek : Element;
            Try  : Decode_Status;
         begin
            DER_Reader.Read (Work, Look, TBS.Last, 2, Limits, Peek, Try);
            if Try = Ok
              and then Peek.Class = Universal
              and then Peek.Number in Tag_UTC_Time | Tag_Generalized_Time
            then
               CryptoLib.X509.Times.Read
                 (Work, Inner, TBS.Last, 2, Limits, Result.Due, Status);
               if Status /= Ok then
                  return Result;
               end if;
               Result.Due_Present := True;
            end if;
         end;
      end if;

      if not DER_Reader.At_End (Inner, TBS.Last) then
         declare
            Look : Offset := Inner;
            Peek : Element;
            Try  : Decode_Status;
         begin
            DER_Reader.Read (Work, Look, TBS.Last, 2, Limits, Peek, Try);
            if Try = Ok
              and then Peek.Class = Universal
              and then Peek.Number = Tag_Sequence
            then
               DER_Reader.Read_Sequence
                 (Work, Inner, TBS.Last, 2, Limits, Field, Status);
               if Status /= Ok then
                  return Result;
               end if;
               Result.Revoked := (First => Field.First, Last => Field.Last);
               Result.Has_Revoked := True;
            end if;
         end;
      end if;

      --  crlExtensions [0] EXPLICIT Extensions OPTIONAL. Kept rather than
      --  interpreted: what matters here is whether any of them is critical
      --  and unrecognised, which is asked separately.
      if not DER_Reader.At_End (Inner, TBS.Last) then
         declare
            Wrap : Element;
            Seq  : Element;
            Walk : Offset := Inner;
         begin
            DER_Reader.Read (Work, Walk, TBS.Last, 2, Limits, Wrap, Status);
            if Status = Ok
              and then Wrap.Class = Context_Specific
              and then Wrap.Number = 0
              and then Wrap.Constructed
            then
               Walk := Wrap.First;
               DER_Reader.Read_Sequence
                 (Work, Walk, Wrap.Last, 3, Limits, Seq, Status);
               if Status /= Ok then
                  return Result;
               end if;
               Result.Extensions := (First => Seq.First, Last => Seq.Last);
               Result.Has_Ext := True;
            else
               --  Something is there that is not the extensions block. A CRL
               --  this reader cannot account for is refused rather than
               --  read up to the part it understood.
               Status := Invalid_Tag;
               return Result;
            end if;
         end;
      end if;

      Status := Ok;
      Result.Present := True;
      return Result;
   end Decode_DER;

   function Is_Present (Item : Revocation_List) return Boolean
   is (Item.Present);

   function Has_Unsupported_Critical_Extension
     (Item : Revocation_List) return Boolean
   is
      Limits : constant Decode_Limits := Default_Limits;
      Cursor : Offset;
      Status : Decode_Status;
   begin
      if not Item.Present or else not Item.Has_Ext then
         return False;
      end if;

      Cursor := Item.Extensions.First;
      while not DER_Reader.At_End (Cursor, Item.Extensions.Last) loop
         declare
            Ext      : Element;
            Part     : Offset;
            OID      : Element;
            Value    : Element;
            Critical : Boolean := False;
            Look     : Offset;
            Peek     : Element;
            Try      : Decode_Status;

            --  Recognised means "does not change what this list says".
            --  cRLNumber orders lists, the identifiers name the issuer's
            --  key, freshestCRL points at a delta without making this one
            --  partial. None of them narrows what the list covers, so none
            --  of them can turn an absent serial into a wrong answer.
            function Known return Boolean
            is (OID_Table.Matches (Item.DER, OID, OID_Table.CRL_Number)
                or else OID_Table.Matches
                          (Item.DER, OID, OID_Table.Authority_Key_Identifier)
                or else OID_Table.Matches
                          (Item.DER, OID, OID_Table.Issuer_Alternative_Name)
                or else OID_Table.Matches
                          (Item.DER, OID, OID_Table.Freshest_CRL));
         begin
            DER_Reader.Read_Sequence
              (Item.DER, Cursor, Item.Extensions.Last, 4, Limits, Ext,
               Status);
            --  An extensions block that does not parse is not evidence that
            --  nothing critical is in it.
            exit when Status /= Ok;

            Part := Ext.First;
            DER_Reader.Read_Object_Identifier
              (Item.DER, Part, Ext.Last, 5, Limits, OID, Status);
            exit when Status /= Ok;

            Look := Part;
            DER_Reader.Read
              (Item.DER, Look, Ext.Last, 5, Limits, Peek, Try);
            if Try = Ok
              and then Peek.Class = Universal
              and then Peek.Number = Tag_Boolean
            then
               DER_Reader.Read_Boolean
                 (Item.DER, Part, Ext.Last, 5, Limits, Critical, Status);
               exit when Status /= Ok;
            end if;

            DER_Reader.Read_Octet_String
              (Item.DER, Part, Ext.Last, 5, Limits, Value, Status);
            exit when Status /= Ok;

            if Critical and then not Known then
               return True;
            end if;
         end;
      end loop;

      --  Reached only by falling out of the loop on a parse failure; the
      --  list could not be accounted for, so it is not vouched for either.
      return Status /= Ok;
   end Has_Unsupported_Critical_Extension;

   function Issuer_Bytes (Item : Revocation_List) return Octets
   is (Slice (Item, Item.Issuer));

   function This_Update (Item : Revocation_List) return Certificate_Time
   is (Item.Issued);

   function Has_Next_Update (Item : Revocation_List) return Boolean
   is (Item.Due_Present);

   function Next_Update (Item : Revocation_List) return Certificate_Time
   is (Item.Due);

   function TBS_Bytes (Item : Revocation_List) return Octets
   is (Slice (Item, Item.TBS));

   --  Read the reasonCode out of an entry's extensions, if it carries one.
   --
   --  crlEntryExtensions is the third and last field of an entry, present
   --  only when the issuer had something to add. An extension this does not
   --  recognise is passed over rather than refused: an entry saying why in a
   --  way this cannot read still says that the certificate is revoked, and
   --  that is the part a caller must not lose.
   procedure Read_Entry_Reason
     (Data   : Octets;
      From   : Offset;
      Last   : Offset;
      Limits : Decode_Limits;
      Found  : out Boolean;
      Reason : out CryptoLib.X509.Revocation_Reason)
   is
      Cursor : Offset := From;
      Outer  : Element;
      Status : Decode_Status;
   begin
      Found := False;
      Reason := CryptoLib.X509.Unspecified;

      if DER_Reader.At_End (Cursor, Last) then
         return;
      end if;

      DER_Reader.Read_Sequence (Data, Cursor, Last, 4, Limits, Outer, Status);
      if Status /= Ok then
         return;
      end if;

      Cursor := Outer.First;
      while not DER_Reader.At_End (Cursor, Outer.Last) loop
         declare
            Ext   : Element;
            Part  : Offset;
            OID   : Element;
            Value : Element;
            Flag  : Boolean;
            Look  : Offset;
            Peek  : Element;
            Try   : Decode_Status;
            Code  : Natural;
         begin
            DER_Reader.Read_Sequence
              (Data, Cursor, Outer.Last, 5, Limits, Ext, Status);
            exit when Status /= Ok;

            Part := Ext.First;
            DER_Reader.Read_Object_Identifier
              (Data, Part, Ext.Last, 6, Limits, OID, Status);
            exit when Status /= Ok;

            --  critical DEFAULT FALSE sits between the identifier and the
            --  value, so it has to be stepped over when present.
            Look := Part;
            DER_Reader.Read (Data, Look, Ext.Last, 6, Limits, Peek, Try);
            if Try = Ok
              and then Peek.Class = Universal
              and then Peek.Number = Tag_Boolean
            then
               DER_Reader.Read_Boolean
                 (Data, Part, Ext.Last, 6, Limits, Flag, Status);
               exit when Status /= Ok;
            end if;

            DER_Reader.Read_Octet_String
              (Data, Part, Ext.Last, 6, Limits, Value, Status);
            exit when Status /= Ok;

            if OID_Table.Matches (Data, OID, OID_Table.CRL_Reason_Code) then
               --  CRLReason is an ENUMERATED, tag 10, not an INTEGER, so it
               --  is read as an element and its content decoded here. The
               --  issuer having said something is recorded even when what it
               --  said is not a code this crate names: Found and Reason
               --  answer different questions.
               Part := Value.First;
               DER_Reader.Read
                 (Data, Part, Value.Last, 7, Limits, Peek, Status);
               if Status /= Ok
                 or else Peek.Class /= Universal
                 or else Peek.Number /= Tag_Enumerated
               then
                  return;
               end if;

               Found := True;
               Reason := CryptoLib.X509.Unknown_Reason;
               if Content_Length (Peek) = 1
                 and then Data (Peek.First) < 16#80#
               then
                  Code := Natural (Data (Peek.First));
                  Reason := CryptoLib.X509.Reason_Of (Code);
               end if;
               return;
            end if;
         end;
      end loop;
   end Read_Entry_Reason;

   --  Walk the revoked entries, reporting each to the caller.
   --
   --  One reader for every question asked of the list -- whether a serial is
   --  on it, how many entries it has, and what an entry says -- so that the
   --  answers cannot disagree about where an entry starts or what it holds.
   generic
      with procedure Visit
        (Serial     : Octets;
         Revoked_At : Certificate_Time;
         Has_Reason : Boolean;
         Reason     : CryptoLib.X509.Revocation_Reason;
         Stop       : out Boolean);
   procedure Walk_Entries (Item : Revocation_List);

   procedure Walk_Entries (Item : Revocation_List) is
      Limits : constant Decode_Limits := Default_Limits;
      Cursor : Offset;
      Status : Decode_Status;
      Halt   : Boolean := False;
   begin
      if not Item.Present or else not Item.Has_Revoked then
         return;
      end if;

      Cursor := Item.Revoked.First;
      while not DER_Reader.At_End (Cursor, Item.Revoked.Last) loop
         declare
            Row    : Element;
            Field  : Element;
            Part   : Offset;
            Minus  : Boolean;
            When_T : Certificate_Time;
            Has_R  : Boolean;
            Why    : CryptoLib.X509.Revocation_Reason;
         begin
            DER_Reader.Read_Sequence
              (Item.DER, Cursor, Item.Revoked.Last, 3, Limits, Row, Status);
            exit when Status /= Ok;

            Part := Row.First;
            DER_Reader.Read_Integer
              (Item.DER, Part, Row.Last, 4, Limits, Field, Minus, Status);
            --  A serial number must be positive (RFC 5280 4.1.2.2), and a
            --  negative one is not merely irregular here: serials are compared
            --  as magnitudes with leading zeros stripped, so an entry naming
            --  -1 -- content FF -- matches a certificate whose serial is 255,
            --  whose content is 00 FF. That reported the wrong certificate
            --  revoked. The entry is not skipped but the walk stops, because a
            --  list with a malformed entry is not a list whose silence about
            --  anything else can be trusted.
            exit when Status /= Ok or else Minus;

            --  revocationDate is not optional: an entry that does not say
            --  when is malformed, and reading past it would put the
            --  extensions walk on the wrong bytes.
            CryptoLib.X509.Times.Read
              (Item.DER, Part, Row.Last, 4, Limits, When_T, Status);
            exit when Status /= Ok;

            Read_Entry_Reason
              (Item.DER, Part, Row.Last, Limits, Has_R, Why);

            Visit
              (Item.DER (Field.First .. Field.Last), When_T, Has_R, Why,
               Halt);
            exit when Halt;
         end;
      end loop;
   end Walk_Entries;

   --  Compare serial numbers as numbers, not as octets.
   --
   --  A DER INTEGER carries a leading zero when its top bit would otherwise
   --  make it negative, so the same serial can be written with or without
   --  one depending on where it came from. Comparing raw octets would miss a
   --  revocation on that account, and a missed revocation is a revoked
   --  certificate treated as good.
   function Same_Number (Left : Octets; Right : Octets) return Boolean
   is (CryptoLib.X509.Same_Serial (Left, Right));

   function Is_Revoked
     (Item : Revocation_List; Serial : Octets) return Boolean
   is
      Found : Boolean := False;

      procedure Consider
        (Candidate  : Octets;
         Revoked_At : Certificate_Time;
         Has_Reason : Boolean;
         Reason     : CryptoLib.X509.Revocation_Reason;
         Stop       : out Boolean)
      is
         pragma Unreferenced (Revoked_At, Has_Reason, Reason);
      begin
         Stop := False;
         if Same_Number (Candidate, Serial) then
            Found := True;
            Stop := True;
         end if;
      end Consider;

      procedure Run is new Walk_Entries (Consider);
   begin
      if Serial'Length = 0 then
         return False;
      end if;

      Run (Item);
      return Found;
   end Is_Revoked;

   function Find_Revocation
     (Item : Revocation_List; Serial : Octets) return Revocation_Details
   is
      Result : Revocation_Details;

      procedure Consider
        (Candidate  : Octets;
         Revoked_At : Certificate_Time;
         Has_Reason : Boolean;
         Reason     : CryptoLib.X509.Revocation_Reason;
         Stop       : out Boolean)
      is
      begin
         Stop := False;
         if Same_Number (Candidate, Serial) then
            Result :=
              (Present    => True,
               Revoked_At => Revoked_At,
               Has_Reason => Has_Reason,
               Reason     => Reason);
            Stop := True;
         end if;
      end Consider;

      procedure Run is new Walk_Entries (Consider);
   begin
      if Serial'Length = 0 then
         return Result;
      end if;

      Run (Item);
      return Result;
   end Find_Revocation;

   function Entry_Count (Item : Revocation_List) return Natural is
      Total : Natural := 0;

      procedure Count
        (Candidate  : Octets;
         Revoked_At : Certificate_Time;
         Has_Reason : Boolean;
         Reason     : CryptoLib.X509.Revocation_Reason;
         Stop       : out Boolean)
      is
         pragma Unreferenced (Candidate, Revoked_At, Has_Reason, Reason);
      begin
         Stop := False;
         Total := Total + 1;
      end Count;

      procedure Run is new Walk_Entries (Count);
   begin
      Run (Item);
      return Total;
   end Entry_Count;

   function Verify_Signature
     (Item   : Revocation_List;
      Issuer : Certificate)
      return CryptoLib.X509.Signatures.Verification_Result
   is
   begin
      if not Item.Present then
         return CryptoLib.X509.Signatures.Missing_Input;
      end if;

      return CryptoLib.X509.Signatures.Verify_Signed_Data
        (Signed    => TBS_Bytes (Item),
         Signature => Slice (Item, Item.Signature),
         Algorithm => Item.Algorithm,
         Issuer    => Issuer);
   end Verify_Signature;

end CryptoLib.X509.CRLs;
