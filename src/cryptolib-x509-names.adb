with Ada.Streams;

with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.Errors;
with CryptoLib.ASN1.OIDs;

package body CryptoLib.X509.Names is

   use CryptoLib.ASN1;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.ASN1.Errors.Decode_Status;

   package X509C renames CryptoLib.X509.Certificates;
   package DER_Reader renames CryptoLib.ASN1.DER;
   package OID_Table renames CryptoLib.ASN1.OIDs;

   Empty_Octets : constant Octets (1 .. 0) := [others => 0];

   Limits : constant Decode_Limits := Default_Limits;

   function Name_Bytes
     (Item : Certificate; Which : Name_Selector) return Octets
   is (case Which is
          when Subject_Name => X509C.Subject_Bytes (Item),
          when Issuer_Name  => X509C.Issuer_Bytes (Item));

   --  Walk the name, stopping at the attribute wanted.
   --
   --  Re-walked per call rather than held: a name is small, and storing it
   --  would mean a bound on how many attributes a certificate may have, which
   --  is a decision this package has no business making.
   procedure Locate
     (Data   : Octets;
      Wanted : Natural;
      Total  : out Natural;
      Found  : out Boolean;
      OID    : out Element;
      Value  : out Element)
   is
      Cursor : Offset;
      Name   : Element;
      Status : Errors.Decode_Status;
      Seen   : Natural := 0;
   begin
      Total := 0;
      Found := False;
      OID := (others => <>);
      Value := (others => <>);

      if Data'Length = 0 then
         return;
      end if;

      Cursor := Data'First;
      DER_Reader.Read_Sequence
        (Data, Cursor, Data'Last, 0, Limits, Name, Status);
      if Status /= Errors.Ok then
         return;
      end if;

      Cursor := Name.First;
      while not DER_Reader.At_End (Cursor, Name.Last) loop
         declare
            RDN : Element;
         begin
            DER_Reader.Read_Set
              (Data, Cursor, Name.Last, 1, Limits, RDN, Status);
            exit when Status /= Errors.Ok;

            declare
               Inner : Offset := RDN.First;
            begin
               while not DER_Reader.At_End (Inner, RDN.Last) loop
                  declare
                     Pair      : Element;
                     Part      : Offset;
                     Pair_OID  : Element;
                     Pair_Text : Element;
                  begin
                     DER_Reader.Read_Sequence
                       (Data, Inner, RDN.Last, 2, Limits, Pair, Status);
                     exit when Status /= Errors.Ok;

                     Part := Pair.First;
                     DER_Reader.Read_Object_Identifier
                       (Data, Part, Pair.Last, 3, Limits, Pair_OID, Status);
                     exit when Status /= Errors.Ok;

                     DER_Reader.Read
                       (Data, Part, Pair.Last, 3, Limits, Pair_Text, Status);
                     exit when Status /= Errors.Ok;

                     Seen := Seen + 1;
                     if Seen = Wanted then
                        OID := Pair_OID;
                        Value := Pair_Text;
                        Found := True;
                     end if;
                  end;
               end loop;
            end;
         end;
      end loop;

      Total := Seen;
   end Locate;

   function Attribute_Count
     (Item : Certificate; Which : Name_Selector) return Natural
   is
      Data  : constant Octets := Name_Bytes (Item, Which);
      Total : Natural;
      Found : Boolean;
      OID   : Element;
      Value : Element;
   begin
      Locate (Data, 0, Total, Found, OID, Value);
      return Total;
   end Attribute_Count;

   function Kind_For (Data : Octets; OID : Element) return Attribute_Kind is
   begin
      if OID_Table.Matches (Data, OID, OID_Table.Common_Name) then
         return Common_Name;
      elsif OID_Table.Matches (Data, OID, OID_Table.Organization) then
         return Organization;
      elsif OID_Table.Matches (Data, OID, OID_Table.Organizational_Unit) then
         return Organizational_Unit;
      elsif OID_Table.Matches (Data, OID, OID_Table.Country) then
         return Country;
      elsif OID_Table.Matches (Data, OID, OID_Table.Locality) then
         return Locality;
      elsif OID_Table.Matches (Data, OID, OID_Table.State_Or_Province) then
         return State_Or_Province;
      elsif OID_Table.Matches (Data, OID, OID_Table.Serial_Number) then
         return Serial_Number_Attribute;
      elsif OID_Table.Matches (Data, OID, OID_Table.Domain_Component) then
         return Domain_Component;
      elsif OID_Table.Matches (Data, OID, OID_Table.Email_Address) then
         return Email_Address;
      else
         return Unknown_Attribute;
      end if;
   end Kind_For;

   function Common_Name_Of (Name_DER : Octets) return String is
      Total : Natural;
      Found : Boolean;
      OID   : Element;
      Value : Element;
   begin
      for I in 1 .. Natural'Last loop
         Locate (Name_DER, I, Total, Found, OID, Value);
         exit when not Found;

         if Kind_For (Name_DER, OID) = Common_Name then
            declare
               Text : String (1 .. Content_Length (Value));
            begin
               for J in Text'Range loop
                  Text (J) :=
                    Character'Val (Name_DER (Value.First + Offset (J - 1)));
               end loop;
               return Text;
            end;
         end if;

         exit when I >= Total;
      end loop;

      return "";
   end Common_Name_Of;

   function Attribute_Kind_At
     (Item  : Certificate;
      Which : Name_Selector;
      Index : Positive) return Attribute_Kind
   is
      Data  : constant Octets := Name_Bytes (Item, Which);
      Total : Natural;
      Found : Boolean;
      OID   : Element;
      Value : Element;
   begin
      Locate (Data, Index, Total, Found, OID, Value);
      if not Found then
         return Unknown_Attribute;
      end if;
      return Kind_For (Data, OID);
   end Attribute_Kind_At;

   function Attribute_Identifier
     (Item  : Certificate;
      Which : Name_Selector;
      Index : Positive) return Octets
   is
      Data  : constant Octets := Name_Bytes (Item, Which);
      Total : Natural;
      Found : Boolean;
      OID   : Element;
      Value : Element;
   begin
      Locate (Data, Index, Total, Found, OID, Value);
      if not Found or else Is_Empty (OID) then
         return Empty_Octets;
      end if;
      return Data (OID.First .. OID.Last);
   end Attribute_Identifier;

   function Attribute_String_Kind
     (Item  : Certificate;
      Which : Name_Selector;
      Index : Positive) return Directory_String_Kind
   is
      Data  : constant Octets := Name_Bytes (Item, Which);
      Total : Natural;
      Found : Boolean;
      OID   : Element;
      Value : Element;
   begin
      Locate (Data, Index, Total, Found, OID, Value);
      if not Found then
         return Other_String;
      end if;

      if Value.Class /= Universal then
         return Other_String;
      end if;

      case Value.Number is
         when Tag_Printable_String => return Printable_String;
         when Tag_UTF8_String      => return UTF8_String;
         when Tag_IA5_String       => return IA5_String;
         when Tag_T61_String       => return Teletex_String;
         when Tag_BMP_String       => return BMP_String;
         when 28                   => return Universal_String;
         when others               => return Other_String;
      end case;
   end Attribute_String_Kind;

   function Attribute_Bytes
     (Item  : Certificate;
      Which : Name_Selector;
      Index : Positive) return Octets
   is
      Data  : constant Octets := Name_Bytes (Item, Which);
      Total : Natural;
      Found : Boolean;
      OID   : Element;
      Value : Element;
   begin
      Locate (Data, Index, Total, Found, OID, Value);
      if not Found or else Is_Empty (Value) then
         return Empty_Octets;
      end if;
      return Data (Value.First .. Value.Last);
   end Attribute_Bytes;

   function Attribute_Text
     (Item  : Certificate;
      Which : Name_Selector;
      Index : Positive) return String
   is
      Kind : constant Directory_String_Kind :=
        Attribute_String_Kind (Item, Which, Index);
   begin
      if Kind in BMP_String | Universal_String | Other_String then
         return "";
      end if;

      declare
         Value : constant Octets := Attribute_Bytes (Item, Which, Index);
         Text  : String (1 .. Natural (Value'Length));
      begin
         for I in Text'Range loop
            Text (I) :=
              Character'Val (Value (Value'First + Offset (I - 1)));
         end loop;
         return Text;
      end;
   end Attribute_Text;

   function Find_Attribute
     (Item  : Certificate;
      Which : Name_Selector;
      Kind  : Attribute_Kind) return Natural
   is
   begin
      if Kind = Unknown_Attribute then
         --  Every unrecognised attribute answers to this, so a search for it
         --  would return whichever came first and mean nothing.
         return 0;
      end if;

      for I in 1 .. Attribute_Count (Item, Which) loop
         if Attribute_Kind_At (Item, Which, I) = Kind then
            return I;
         end if;
      end loop;

      return 0;
   end Find_Attribute;

   --  The short label RFC 4514 gives an attribute, or "" for one it does not.
   function Label_For (Kind : Attribute_Kind) return String
   is (case Kind is
          when Common_Name             => "CN",
          when Organization            => "O",
          when Organizational_Unit     => "OU",
          when Country                 => "C",
          when Locality                => "L",
          when State_Or_Province       => "ST",
          when Serial_Number_Attribute => "SERIALNUMBER",
          when Domain_Component        => "DC",
          when Email_Address           => "EMAIL",
          when Unknown_Attribute       => "");

   function Format
     (Item : Certificate; Which : Name_Selector) return String
   is
      Total : constant Natural := Attribute_Count (Item, Which);

      --  Escaped per RFC 4514: the characters that would otherwise change how
      --  the rendering parses. Without this a value containing a comma reads
      --  back as two attributes, which is the reason formatted names must not
      --  be compared.
      function Escaped (Value : String) return String is
         Result : String (1 .. 2 * Value'Length);
         Last   : Natural := 0;
      begin
         for I in Value'Range loop
            declare
               C : constant Character := Value (I);
            begin
               if C = ',' or else C = '+' or else C = '"' or else C = '\'
                 or else C = '<' or else C = '>' or else C = ';'
                 or else C = '='
                 or else (I = Value'First and then (C = ' ' or else C = '#'))
                 or else (I = Value'Last and then C = ' ')
               then
                  Last := Last + 1;
                  Result (Last) := '\';
               end if;
               Last := Last + 1;
               Result (Last) := C;
            end;
         end loop;
         return Result (1 .. Last);
      end Escaped;

      --  Built by walking backwards: RFC 4514 renders the most specific
      --  attribute first, and DER holds the least specific first.
      function Render (Index : Natural) return String is
      begin
         if Index = 0 then
            return "";
         end if;

         declare
            Kind  : constant Attribute_Kind :=
              Attribute_Kind_At (Item, Which, Index);
            Label : constant String := Label_For (Kind);
            Text  : constant String := Attribute_Text (Item, Which, Index);
            One   : constant String :=
              (if Label'Length = 0 or else Text'Length = 0
               then ""
               else Label & "=" & Escaped (Text));
            Rest  : constant String := Render (Index - 1);
         begin
            if One'Length = 0 then
               return Rest;
            elsif Rest'Length = 0 then
               return One;
            else
               return One & "," & Rest;
            end if;
         end;
      end Render;
   begin
      return Render (Total);
   end Format;

end CryptoLib.X509.Names;
