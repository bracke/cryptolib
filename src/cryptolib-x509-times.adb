with Ada.Streams;

with CryptoLib.ASN1.DER;

package body CryptoLib.X509.Times is

   use CryptoLib.ASN1;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use CryptoLib.ASN1.Errors;

   package DER_Reader renames CryptoLib.ASN1.DER;

   procedure Read
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Value    : out Certificate_Time;
      Status   : out Decode_Status)
   is
      Cursor : Offset := Position;
      Item   : Element;
      Wide   : Boolean;

      function Digits_At (From : Offset; Count : Natural) return Integer is
         Total : Integer := 0;
      begin
         for I in 0 .. Count - 1 loop
            declare
               C : constant Natural := Natural (Data (From + Offset (I)));
            begin
               if C < Character'Pos ('0') or else C > Character'Pos ('9') then
                  return -1;
               end if;
               Total := Total * 10 + (C - Character'Pos ('0'));
            end;
         end loop;
         return Total;
      end Digits_At;

      Base   : Offset;
      Year   : Integer;
      Fields : array (1 .. 5) of Integer;
   begin
      Value := (others => 0);

      DER_Reader.Read (Data, Cursor, Last, Depth, Limits, Item, Status);
      if Status /= Ok then
         return;
      end if;

      if Item.Class /= Universal or else Item.Constructed then
         Status := Invalid_Tag;
         return;
      end if;

      if Item.Number = Tag_UTC_Time then
         Wide := False;
      elsif Item.Number = Tag_Generalized_Time then
         Wide := True;
      else
         Status := Invalid_Tag;
         return;
      end if;

      --  "YYMMDDHHMMSSZ" or "YYYYMMDDHHMMSSZ", and nothing else.
      if Content_Length (Item) /= (if Wide then 15 else 13) then
         Status := Invalid_Value;
         return;
      end if;

      if Data (Item.Last) /= Character'Pos ('Z') then
         Status := Invalid_Value;
         return;
      end if;

      if Wide then
         Year := Digits_At (Item.First, 4);
         Base := Item.First + 4;
      else
         Year := Digits_At (Item.First, 2);
         Base := Item.First + 2;
         if Year >= 0 then
            --  RFC 5280: 50 and above is the twentieth century.
            Year := (if Year >= 50 then 1900 + Year else 2000 + Year);
         end if;
      end if;

      if Year < 0 then
         Status := Invalid_Value;
         return;
      end if;

      for I in Fields'Range loop
         Fields (I) := Digits_At (Base + Offset ((I - 1) * 2), 2);
         if Fields (I) < 0 then
            Status := Invalid_Value;
            return;
         end if;
      end loop;

      if Fields (1) not in 1 .. 12
        or else Fields (2) not in 1 .. 31
        or else Fields (3) > 23
        or else Fields (4) > 59
        or else Fields (5) > 60
      then
         Status := Invalid_Value;
         return;
      end if;

      Value :=
        (Year   => Year,
         Month  => Fields (1),
         Day    => Fields (2),
         Hour   => Fields (3),
         Minute => Fields (4),
         Second => Fields (5));
      Position := Cursor;
   end Read;

end CryptoLib.X509.Times;
