with Ada.Streams;

with CryptoLib.ASN1;
with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.Errors;
with CryptoLib.ASN1.OIDs;

package body CryptoLib.X509.Extensions is

   use CryptoLib.ASN1;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.ASN1.Errors.Decode_Status;

   package X509C renames CryptoLib.X509.Certificates;
   package DER_Reader renames CryptoLib.ASN1.DER;
   package OID_Table renames CryptoLib.ASN1.OIDs;

   Empty_Octets : constant Octets (1 .. 0) := [others => 0];

   Limits : constant Decode_Limits := Default_Limits;

   --  Fetch one extension's value by identifier.
   function Value_Of
     (Item       : Certificate;
      Identifier : Octets;
      Found      : out Boolean) return Octets
   is
      Index : constant Natural := X509C.Find_Extension (Item, Identifier);
   begin
      Found := Index > 0;
      if not Found then
         return Empty_Octets;
      end if;
      return X509C.Extension_Value (Item, Index);
   end Value_Of;

   function Get_Basic_Constraints (Item : Certificate) return Basic_Constraints
   is
      Found  : Boolean;
      Data   : constant Octets :=
        Value_Of (Item, OID_Table.Basic_Constraints, Found);
      Result : Basic_Constraints;
      Cursor : Offset;
      Seq    : Element;
      Status : Errors.Decode_Status;
   begin
      if not Found then
         return Result;
      end if;

      Result.Present := True;

      Cursor := Data'First;
      DER_Reader.Read_Sequence
        (Data, Cursor, Data'Last, 0, Limits, Seq, Status);
      if Status /= Errors.Ok
        or else not DER_Reader.At_End (Cursor, Data'Last)
      then
         return Result;
      end if;

      Cursor := Seq.First;

      --  cA DEFAULT FALSE, so an absent boolean means not a CA.
      if not DER_Reader.At_End (Cursor, Seq.Last) then
         declare
            Look : Offset := Cursor;
            Peek : Element;
            Try  : Errors.Decode_Status;
         begin
            DER_Reader.Read (Data, Look, Seq.Last, 1, Limits, Peek, Try);
            if Try = Errors.Ok
              and then Peek.Class = Universal
              and then Peek.Number = Tag_Boolean
            then
               DER_Reader.Read_Boolean
                 (Data, Cursor, Seq.Last, 1, Limits, Result.Is_CA, Status);
               if Status /= Errors.Ok then
                  return Result;
               end if;
            end if;
         end;
      end if;

      if not DER_Reader.At_End (Cursor, Seq.Last) then
         declare
            Length : Natural;
         begin
            DER_Reader.Read_Small_Integer
              (Data, Cursor, Seq.Last, 1, Limits, Length, Status);
            if Status /= Errors.Ok then
               return Result;
            end if;
            Result.Has_Path_Length := True;
            Result.Path_Length := Length;
         end;
      end if;

      Result.Well_Formed := DER_Reader.At_End (Cursor, Seq.Last);
      return Result;
   end Get_Basic_Constraints;

   function Get_Key_Usage (Item : Certificate) return Key_Usage is
      Found  : Boolean;
      Data   : constant Octets :=
        Value_Of (Item, OID_Table.Key_Usage, Found);
      Result : Key_Usage;
      Cursor : Offset;
      Bits   : Element;
      Unused : Natural;
      Status : Errors.Decode_Status;

      --  Bit 0 is the most significant bit of the first octet, which is not
      --  the numbering an array index would give.
      function Bit (Index : Natural) return Boolean is
         Position : constant Offset := Bits.First + Offset (Index / 8);
         Mask     : constant Natural := 2 ** (7 - (Index mod 8));
      begin
         if Position > Bits.Last then
            return False;
         end if;
         return (Natural (Data (Position)) / Mask) mod 2 = 1;
      end Bit;
   begin
      if not Found then
         return Result;
      end if;

      Result.Present := True;

      Cursor := Data'First;
      DER_Reader.Read_Bit_String
        (Data, Cursor, Data'Last, 0, Limits, Bits, Unused, Status);
      if Status /= Errors.Ok
        or else not DER_Reader.At_End (Cursor, Data'Last)
      then
         return Result;
      end if;

      Result.Well_Formed := True;
      Result.Digital_Signature := Bit (0);
      Result.Non_Repudiation   := Bit (1);
      Result.Key_Encipherment  := Bit (2);
      Result.Data_Encipherment := Bit (3);
      Result.Key_Agreement     := Bit (4);
      Result.Certificate_Sign  := Bit (5);
      Result.CRL_Sign          := Bit (6);
      Result.Encipher_Only     := Bit (7);
      Result.Decipher_Only     := Bit (8);
      return Result;
   end Get_Key_Usage;

   function Get_Extended_Key_Usage
     (Item : Certificate) return Extended_Key_Usage
   is
      Found  : Boolean;
      Data   : constant Octets :=
        Value_Of (Item, OID_Table.Extended_Key_Usage, Found);
      Result : Extended_Key_Usage;
      Cursor : Offset;
      Seq    : Element;
      Status : Errors.Decode_Status;
   begin
      if not Found then
         return Result;
      end if;

      Result.Present := True;

      Cursor := Data'First;
      DER_Reader.Read_Sequence
        (Data, Cursor, Data'Last, 0, Limits, Seq, Status);
      if Status /= Errors.Ok
        or else not DER_Reader.At_End (Cursor, Data'Last)
      then
         return Result;
      end if;

      Cursor := Seq.First;
      while not DER_Reader.At_End (Cursor, Seq.Last) loop
         declare
            Purpose : Element;
         begin
            DER_Reader.Read_Object_Identifier
              (Data, Cursor, Seq.Last, 1, Limits, Purpose, Status);
            if Status /= Errors.Ok then
               return Result;
            end if;

            if OID_Table.Matches (Data, Purpose, OID_Table.EKU_Server_Auth) then
               Result.Server_Auth := True;
            elsif OID_Table.Matches
                    (Data, Purpose, OID_Table.EKU_Client_Auth)
            then
               Result.Client_Auth := True;
            elsif OID_Table.Matches
                    (Data, Purpose, OID_Table.EKU_Code_Signing)
            then
               Result.Code_Signing := True;
            elsif OID_Table.Matches
                    (Data, Purpose, OID_Table.EKU_Email_Protection)
            then
               Result.Email_Protection := True;
            elsif OID_Table.Matches
                    (Data, Purpose, OID_Table.EKU_OCSP_Signing)
            then
               Result.OCSP_Signing := True;
            elsif OID_Table.Matches (Data, Purpose, OID_Table.EKU_Any) then
               Result.Any_Purpose := True;
            else
               Result.Has_Unrecognised := True;
            end if;
         end;
      end loop;

      Result.Well_Formed := True;
      return Result;
   end Get_Extended_Key_Usage;

   --  Walk the GeneralNames sequence, stopping at Wanted.
   --
   --  Re-walked on each call rather than held in the certificate. A
   --  certificate carries an unbounded list and the walk is cheap; storing it
   --  would mean a bound, and a bound would mean deciding what to do with the
   --  names past it.
   procedure Locate_Name
     (Item   : Certificate;
      Wanted : Natural;
      Total  : out Natural;
      Found  : out Boolean;
      Value  : out Element;
      Data   : out Boolean)
   is
      Present : Boolean;
      Bytes   : constant Octets :=
        Value_Of (Item, OID_Table.Subject_Alternative_Name, Present);
      Cursor  : Offset;
      Seq     : Element;
      Status  : Errors.Decode_Status;
      Seen    : Natural := 0;
   begin
      Total := 0;
      Found := False;
      Value := (others => <>);
      Data := Present;

      if not Present or else Bytes'Length = 0 then
         return;
      end if;

      Cursor := Bytes'First;
      DER_Reader.Read_Sequence
        (Bytes, Cursor, Bytes'Last, 0, Limits, Seq, Status);
      if Status /= Errors.Ok then
         return;
      end if;

      Cursor := Seq.First;
      while not DER_Reader.At_End (Cursor, Seq.Last) loop
         declare
            Name : Element;
         begin
            DER_Reader.Read (Bytes, Cursor, Seq.Last, 1, Limits, Name, Status);
            exit when Status /= Errors.Ok;
            Seen := Seen + 1;
            if Seen = Wanted then
               Value := Name;
               Found := True;
            end if;
         end;
      end loop;

      Total := Seen;
   end Locate_Name;

   --  The extension's value octets, re-fetched for slicing a located name.
   function SAN_Bytes (Item : Certificate) return Octets is
      Present : Boolean;
   begin
      return Value_Of (Item, OID_Table.Subject_Alternative_Name, Present);
   end SAN_Bytes;

   function Subject_Alternative_Name_Count (Item : Certificate) return Natural
   is
      Total : Natural;
      Found : Boolean;
      Value : Element;
      Data  : Boolean;
   begin
      Locate_Name (Item, 0, Total, Found, Value, Data);
      return Total;
   end Subject_Alternative_Name_Count;

   function Subject_Alternative_Name_Kind
     (Item : Certificate; Index : Positive) return General_Name_Kind
   is
      Total : Natural;
      Found : Boolean;
      Value : Element;
      Data  : Boolean;
   begin
      Locate_Name (Item, Index, Total, Found, Value, Data);
      if not Found then
         return Other_Name;
      end if;

      --  GeneralName is a CHOICE, so the context tag is the kind.
      case Value.Number is
         when 1      => return Email_Address;
         when 2      => return DNS_Name;
         when 6      => return URI;
         when 7      => return IP_Address;
         when 4      => return Directory_Name;
         when others => return Other_Name;
      end case;
   end Subject_Alternative_Name_Kind;

   function Subject_Alternative_Name_Text
     (Item : Certificate; Index : Positive) return String
   is
      Total : Natural;
      Found : Boolean;
      Value : Element;
      Data  : Boolean;
      Kind  : constant General_Name_Kind :=
        Subject_Alternative_Name_Kind (Item, Index);
   begin
      if Kind not in DNS_Name | Email_Address | URI then
         return "";
      end if;

      Locate_Name (Item, Index, Total, Found, Value, Data);
      if not Found then
         return "";
      end if;

      declare
         Bytes : constant Octets := SAN_Bytes (Item);
         Text  : String (1 .. Content_Length (Value));
      begin
         for I in Text'Range loop
            Text (I) :=
              Character'Val (Bytes (Value.First + Offset (I - 1)));
         end loop;
         return Text;
      end;
   end Subject_Alternative_Name_Text;

   function Subject_Alternative_Name_Bytes
     (Item : Certificate; Index : Positive) return Octets
   is
      Total : Natural;
      Found : Boolean;
      Value : Element;
      Data  : Boolean;
   begin
      Locate_Name (Item, Index, Total, Found, Value, Data);
      if not Found or else Is_Empty (Value) then
         return Empty_Octets;
      end if;

      declare
         Bytes : constant Octets := SAN_Bytes (Item);
      begin
         return Bytes (Value.First .. Value.Last);
      end;
   end Subject_Alternative_Name_Bytes;

   function Subject_Key_Identifier (Item : Certificate) return Octets is
      Found  : Boolean;
      Data   : constant Octets :=
        Value_Of (Item, OID_Table.Subject_Key_Identifier, Found);
      Cursor : Offset;
      Item_E : Element;
      Status : Errors.Decode_Status;
   begin
      if not Found or else Data'Length = 0 then
         return Empty_Octets;
      end if;

      Cursor := Data'First;
      DER_Reader.Read_Octet_String
        (Data, Cursor, Data'Last, 0, Limits, Item_E, Status);
      if Status /= Errors.Ok or else Is_Empty (Item_E) then
         return Empty_Octets;
      end if;

      return Data (Item_E.First .. Item_E.Last);
   end Subject_Key_Identifier;

   function Authority_Key_Identifier (Item : Certificate) return Octets is
      Found  : Boolean;
      Data   : constant Octets :=
        Value_Of (Item, OID_Table.Authority_Key_Identifier, Found);
      Cursor : Offset;
      Seq    : Element;
      Status : Errors.Decode_Status;
   begin
      if not Found or else Data'Length = 0 then
         return Empty_Octets;
      end if;

      Cursor := Data'First;
      DER_Reader.Read_Sequence
        (Data, Cursor, Data'Last, 0, Limits, Seq, Status);
      if Status /= Errors.Ok then
         return Empty_Octets;
      end if;

      --  keyIdentifier is [0] IMPLICIT, so it is a primitive context tag
      --  rather than an OCTET STRING tag. The other fields are optional and
      --  of no interest here.
      Cursor := Seq.First;
      while not DER_Reader.At_End (Cursor, Seq.Last) loop
         declare
            Field : Element;
         begin
            DER_Reader.Read (Data, Cursor, Seq.Last, 1, Limits, Field, Status);
            exit when Status /= Errors.Ok;

            if Field.Class = Context_Specific
              and then Field.Number = 0
              and then not Field.Constructed
              and then not Is_Empty (Field)
            then
               return Data (Field.First .. Field.Last);
            end if;
         end;
      end loop;

      return Empty_Octets;
   end Authority_Key_Identifier;

   function Has_Unsupported_Critical_Extension
     (Item : Certificate) return Boolean
   is
      function Understood (Identifier : Octets) return Boolean is
         Known : Boolean := False;

         procedure Consider (Candidate : Octets) is
         begin
            if Known or else Candidate'Length /= Identifier'Length then
               return;
            end if;
            for I in 0 .. Identifier'Length - 1 loop
               if Candidate (Candidate'First + Offset (I))
                 /= Identifier (Identifier'First + Offset (I))
               then
                  return;
               end if;
            end loop;
            Known := True;
         end Consider;
      begin
         Consider (OID_Table.Basic_Constraints);
         Consider (OID_Table.Key_Usage);
         Consider (OID_Table.Extended_Key_Usage);
         Consider (OID_Table.Subject_Alternative_Name);
         Consider (OID_Table.Subject_Key_Identifier);
         Consider (OID_Table.Authority_Key_Identifier);

         --  Name constraints are here because CryptoLib.X509.Validation
         --  applies them. Certificate policies are here because they impose
         --  nothing by themselves: they say under which policies a
         --  certificate was issued, and it takes a caller asking for a
         --  particular policy to make that restrict anything. Policy
         --  constraints and inhibitAnyPolicy are deliberately absent -- they
         --  demand policy processing this crate does not do, so a chain
         --  carrying them critically is refused rather than accepted with the
         --  demand ignored.
         Consider (OID_Table.Name_Constraints);
         Consider (OID_Table.Certificate_Policies);
         return Known;
      end Understood;
   begin
      for I in 1 .. X509C.Extension_Count (Item) loop
         if X509C.Extension_Is_Critical (Item, I)
           and then not Understood (X509C.Extension_Identifier (Item, I))
         then
            return True;
         end if;
      end loop;

      return False;
   end Has_Unsupported_Critical_Extension;

end CryptoLib.X509.Extensions;
