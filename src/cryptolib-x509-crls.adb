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

      --  Anything left is crlExtensions, which are not interpreted here.
      Result.Present := True;
      return Result;
   end Decode_DER;

   function Is_Present (Item : Revocation_List) return Boolean
   is (Item.Present);

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

   --  Walk the revoked entries, reporting each serial to the caller.
   generic
      with procedure Visit (Serial : Octets; Stop : out Boolean);
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
            Row   : Element;
            Field : Element;
            Part  : Offset;
            Minus : Boolean;
         begin
            DER_Reader.Read_Sequence
              (Item.DER, Cursor, Item.Revoked.Last, 3, Limits, Row, Status);
            exit when Status /= Ok;

            Part := Row.First;
            DER_Reader.Read_Integer
              (Item.DER, Part, Row.Last, 4, Limits, Field, Minus, Status);
            exit when Status /= Ok;

            Visit (Item.DER (Field.First .. Field.Last), Halt);
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
   function Same_Number (Left : Octets; Right : Octets) return Boolean is
      L : Offset := Left'First;
      R : Offset := Right'First;
   begin
      while L <= Left'Last and then Left (L) = 0 loop
         L := L + 1;
      end loop;
      while R <= Right'Last and then Right (R) = 0 loop
         R := R + 1;
      end loop;

      if Left'Last - L /= Right'Last - R then
         return False;
      end if;

      while L <= Left'Last loop
         if Left (L) /= Right (R) then
            return False;
         end if;
         L := L + 1;
         R := R + 1;
      end loop;

      return True;
   end Same_Number;

   function Is_Revoked
     (Item : Revocation_List; Serial : Octets) return Boolean
   is
      Found : Boolean := False;

      procedure Consider (Candidate : Octets; Stop : out Boolean) is
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

   function Entry_Count (Item : Revocation_List) return Natural is
      Total : Natural := 0;

      procedure Count (Candidate : Octets; Stop : out Boolean) is
         pragma Unreferenced (Candidate);
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
