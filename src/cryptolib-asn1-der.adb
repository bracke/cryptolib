package body CryptoLib.ASN1.DER is

   use CryptoLib.ASN1.Errors;

   --  Identifier octet fields. Written as arithmetic on Natural rather than
   --  as bit operations on Stream_Element so that the shapes being tested are
   --  legible against the encoding rules they come from.
   function Class_Of (B : Octet) return Tag_Class
   is (case Natural (B) / 64 is
          when 0      => Universal,
          when 1      => Application,
          when 2      => Context_Specific,
          when others => Private_Class);

   function Constructed_Of (B : Octet) return Boolean
   is ((Natural (B) / 32) mod 2 = 1);

   function Low_Tag_Of (B : Octet) return Natural
   is (Natural (B) mod 32);

   High_Tag_Form : constant Natural := 31;

   --  Read the tag number when it did not fit in the identifier octet.
   --
   --  Each octet carries seven bits, high bit set on all but the last. The
   --  first must not be 16#80#: that would be a leading zero group, which is
   --  the high-tag equivalent of a non-minimal length and is refused for the
   --  same reason.
   procedure Read_High_Tag
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Number   : out Tag_Number;
      Status   : out Decode_Status)
   is
      Accumulated : Natural := 0;
      Seen        : Natural := 0;
      B           : Octet;
   begin
      Number := 0;
      Status := Ok;

      loop
         if Position > Last then
            Status := Truncated_Input;
            return;
         end if;

         B := Data (Position);
         Seen := Seen + 1;

         if Seen = 1 and then B = 16#80# then
            Status := Non_Canonical_DER;
            return;
         end if;

         --  Refuse before the shift rather than after, so nothing overflows
         --  on the way to being rejected.
         if Accumulated > (Tag_Number'Last - Natural (B) mod 128) / 128 then
            Status := Size_Limit_Exceeded;
            return;
         end if;

         Accumulated := Accumulated * 128 + Natural (B) mod 128;
         Position := Position + 1;
         exit when Natural (B) / 128 = 0;
      end loop;

      Number := Accumulated;
   end Read_High_Tag;

   --  Read the length octets.
   procedure Read_Length
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Limits   : Decode_Limits;
      Length   : out Natural;
      Status   : out Decode_Status)
   is
      First_Octet : Octet;
      Count       : Natural;
      Accumulated : Natural := 0;
   begin
      Length := 0;
      Status := Ok;

      if Position > Last then
         Status := Truncated_Input;
         return;
      end if;

      First_Octet := Data (Position);
      Position := Position + 1;

      if Natural (First_Octet) < 128 then
         Length := Natural (First_Octet);
         return;
      end if;

      if First_Octet = 16#80# then
         --  Indefinite length: legal BER, and a constructed encoding whose
         --  end is announced rather than declared. DER does not have it.
         Status := Unsupported_Encoding;
         return;
      end if;

      if First_Octet = 16#FF# then
         Status := Invalid_Length;
         return;
      end if;

      Count := Natural (First_Octet) - 128;

      if Position + Offset (Count) - 1 > Last then
         Status := Truncated_Input;
         return;
      end if;

      if Data (Position) = 0 then
         --  A leading zero octet in the length.
         Status := Non_Canonical_DER;
         return;
      end if;

      for I in 0 .. Count - 1 loop
         if Accumulated > (Natural'Last - Natural (Data (Position + Offset (I)))) / 256 then
            Status := Size_Limit_Exceeded;
            return;
         end if;
         Accumulated := Accumulated * 256 + Natural (Data (Position + Offset (I)));
      end loop;

      if Accumulated < 128 then
         --  Expressible in the short form, so the long form is not minimal.
         Status := Non_Canonical_DER;
         return;
      end if;

      if Accumulated > Limits.Maximum_Input_Size then
         Status := Size_Limit_Exceeded;
         return;
      end if;

      Position := Position + Offset (Count);
      Length := Accumulated;
   end Read_Length;

   procedure Read
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Item     : out Element;
      Status   : out Decode_Status)
   is
      Cursor : Offset := Position;
      Header : constant Offset := Position;
      Ident  : Octet;
      Number : Tag_Number;
      Length : Natural;
   begin
      Item := (others => <>);
      Status := Ok;

      if Depth > Limits.Maximum_Nesting_Depth then
         Status := Excessive_Nesting;
         return;
      end if;

      if Last > Data'Last or else Cursor < Data'First then
         Status := Truncated_Input;
         return;
      end if;

      if Cursor > Last then
         Status := Truncated_Input;
         return;
      end if;

      Ident := Data (Cursor);
      Cursor := Cursor + 1;

      if Low_Tag_Of (Ident) = High_Tag_Form then
         Read_High_Tag (Data, Cursor, Last, Number, Status);
         if Status /= Ok then
            return;
         end if;

         if Number < High_Tag_Form then
            --  Encodable in the identifier octet, so the long form is not
            --  minimal.
            Status := Non_Canonical_DER;
            return;
         end if;
      else
         Number := Low_Tag_Of (Ident);
      end if;

      Read_Length (Data, Cursor, Last, Limits, Length, Status);
      if Status /= Ok then
         return;
      end if;

      if Length > Natural (Last - Cursor + 1) then
         Status := Truncated_Input;
         return;
      end if;

      Item :=
        (Class        => Class_Of (Ident),
         Constructed  => Constructed_Of (Ident),
         Number       => Number,
         Header_First => Header,
         First        => Cursor,
         Last         => Cursor + Offset (Length) - 1);

      Position := Cursor + Offset (Length);
   end Read;

   procedure Read_Expected
     (Data        : Octets;
      Position    : in out Offset;
      Last        : Offset;
      Depth       : Natural;
      Limits      : Decode_Limits;
      Class       : Tag_Class;
      Number      : Tag_Number;
      Constructed : Boolean;
      Item        : out Element;
      Status      : out Decode_Status)
   is
      Cursor : Offset := Position;
   begin
      Read (Data, Cursor, Last, Depth, Limits, Item, Status);
      if Status /= Ok then
         return;
      end if;

      if Item.Class /= Class
        or else Item.Number /= Number
        or else Item.Constructed /= Constructed
      then
         Item := (others => <>);
         Status := Invalid_Tag;
         return;
      end if;

      Position := Cursor;
   end Read_Expected;

   procedure Read_Sequence
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Item     : out Element;
      Status   : out Decode_Status)
   is
   begin
      Read_Expected
        (Data, Position, Last, Depth, Limits,
         Universal, Tag_Sequence, True, Item, Status);
   end Read_Sequence;

   procedure Read_Set
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Item     : out Element;
      Status   : out Decode_Status)
   is
   begin
      Read_Expected
        (Data, Position, Last, Depth, Limits,
         Universal, Tag_Set, True, Item, Status);
   end Read_Set;

   procedure Read_Integer
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Item     : out Element;
      Negative : out Boolean;
      Status   : out Decode_Status)
   is
      Cursor : Offset := Position;
   begin
      Negative := False;
      Read_Expected
        (Data, Cursor, Last, Depth, Limits,
         Universal, Tag_Integer, False, Item, Status);
      if Status /= Ok then
         return;
      end if;

      if Is_Empty (Item) then
         --  An INTEGER always has at least one content octet.
         Item := (others => <>);
         Status := Invalid_Value;
         return;
      end if;

      if Content_Length (Item) >= 2 then
         declare
            B0 : constant Natural := Natural (Data (Item.First));
            B1 : constant Natural := Natural (Data (Item.First + 1));
         begin
            --  Two's complement in shortest form: the leading nine bits may
            --  not be all zeros or all ones, or the first octet is redundant.
            if (B0 = 16#00# and then B1 < 16#80#)
              or else (B0 = 16#FF# and then B1 >= 16#80#)
            then
               Item := (others => <>);
               Status := Non_Canonical_DER;
               return;
            end if;
         end;
      end if;

      Negative := Natural (Data (Item.First)) >= 16#80#;
      Position := Cursor;
   end Read_Integer;

   procedure Read_Small_Integer
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Value    : out Natural;
      Status   : out Decode_Status)
   is
      Cursor      : Offset := Position;
      Item        : Element;
      Negative    : Boolean;
      Accumulated : Natural := 0;
   begin
      Value := 0;
      Read_Integer (Data, Cursor, Last, Depth, Limits, Item, Negative, Status);
      if Status /= Ok then
         return;
      end if;

      if Negative then
         Status := Invalid_Value;
         return;
      end if;

      for I in Item.First .. Item.Last loop
         if Accumulated > (Natural'Last - Natural (Data (I))) / 256 then
            Status := Invalid_Value;
            return;
         end if;
         Accumulated := Accumulated * 256 + Natural (Data (I));
      end loop;

      Value := Accumulated;
      Position := Cursor;
   end Read_Small_Integer;

   procedure Read_Boolean
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Value    : out Boolean;
      Status   : out Decode_Status)
   is
      Cursor : Offset := Position;
      Item   : Element;
   begin
      Value := False;
      Read_Expected
        (Data, Cursor, Last, Depth, Limits,
         Universal, Tag_Boolean, False, Item, Status);
      if Status /= Ok then
         return;
      end if;

      if Content_Length (Item) /= 1 then
         Status := Invalid_Value;
         return;
      end if;

      --  DER fixes true as all bits set. BER's "any non-zero" would let one
      --  value be written 254 ways.
      case Natural (Data (Item.First)) is
         when 16#00# => Value := False;
         when 16#FF# => Value := True;
         when others =>
            Status := Invalid_Value;
            return;
      end case;

      Position := Cursor;
   end Read_Boolean;

   procedure Read_Object_Identifier
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Item     : out Element;
      Status   : out Decode_Status)
   is
      Cursor     : Offset := Position;
      Arc_Start  : Boolean := True;
   begin
      Read_Expected
        (Data, Cursor, Last, Depth, Limits,
         Universal, Tag_Object_Identifier, False, Item, Status);
      if Status /= Ok then
         return;
      end if;

      if Is_Empty (Item) then
         Item := (others => <>);
         Status := Invalid_Value;
         return;
      end if;

      for I in Item.First .. Item.Last loop
         if Arc_Start and then Data (I) = 16#80# then
            --  A leading continuation octet with no bits in it: a padded arc.
            Item := (others => <>);
            Status := Non_Canonical_DER;
            return;
         end if;
         Arc_Start := Natural (Data (I)) / 128 = 0;
      end loop;

      if not Arc_Start then
         --  The last octet asked for a continuation that never came.
         Item := (others => <>);
         Status := Invalid_Value;
         return;
      end if;

      Position := Cursor;
   end Read_Object_Identifier;

   procedure Read_Bit_String
     (Data        : Octets;
      Position    : in out Offset;
      Last        : Offset;
      Depth       : Natural;
      Limits      : Decode_Limits;
      Item        : out Element;
      Unused_Bits : out Natural;
      Status      : out Decode_Status)
   is
      Cursor : Offset := Position;
      Raw    : Element;
   begin
      Unused_Bits := 0;
      Item := (others => <>);

      Read_Expected
        (Data, Cursor, Last, Depth, Limits,
         Universal, Tag_Bit_String, False, Raw, Status);
      if Status /= Ok then
         return;
      end if;

      if Is_Empty (Raw) then
         --  The unused-bit octet is mandatory even when there are no bits.
         Status := Invalid_Value;
         return;
      end if;

      Unused_Bits := Natural (Data (Raw.First));
      if Unused_Bits > 7 then
         Unused_Bits := 0;
         Status := Invalid_Value;
         return;
      end if;

      if Content_Length (Raw) = 1 and then Unused_Bits /= 0 then
         --  No value octets, so no bits can be unused.
         Unused_Bits := 0;
         Status := Invalid_Value;
         return;
      end if;

      if Content_Length (Raw) - 1 > Limits.Maximum_String_Length then
         Unused_Bits := 0;
         Status := Size_Limit_Exceeded;
         return;
      end if;

      --  X.690 11.2.1: the bits after the last one shall be zero. Checked
      --  here rather than left to each caller, because a caller that indexes
      --  bits -- as the key-usage reader does -- otherwise reads padding as
      --  value, and a certificate setting a bit in the padding would claim a
      --  usage its own encoding does not grant. It also means the unused count
      --  can be ignored by callers that only want the octets, which is why
      --  several do.
      if Unused_Bits > 0 then
         declare
            Final : constant Ada.Streams.Stream_Element := Data (Raw.Last);
            Mask  : constant Ada.Streams.Stream_Element :=
              Ada.Streams.Stream_Element (2 ** Unused_Bits - 1);
         begin
            if (Final and Mask) /= 0 then
               Unused_Bits := 0;
               Status := Non_Canonical_DER;
               return;
            end if;
         end;
      end if;

      Item := Raw;
      Item.First := Raw.First + 1;
      Position := Cursor;
   end Read_Bit_String;

   procedure Read_Octet_String
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Item     : out Element;
      Status   : out Decode_Status)
   is
      Cursor : Offset := Position;
   begin
      Read_Expected
        (Data, Cursor, Last, Depth, Limits,
         Universal, Tag_Octet_String, False, Item, Status);
      if Status /= Ok then
         return;
      end if;

      if Content_Length (Item) > Limits.Maximum_String_Length then
         Item := (others => <>);
         Status := Size_Limit_Exceeded;
         return;
      end if;

      Position := Cursor;
   end Read_Octet_String;

   procedure Read_Null
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Status   : out Decode_Status)
   is
      Cursor : Offset := Position;
      Item   : Element;
   begin
      Read_Expected
        (Data, Cursor, Last, Depth, Limits,
         Universal, Tag_Null, False, Item, Status);
      if Status /= Ok then
         return;
      end if;

      if not Is_Empty (Item) then
         Status := Invalid_Value;
         return;
      end if;

      Position := Cursor;
   end Read_Null;

end CryptoLib.ASN1.DER;
