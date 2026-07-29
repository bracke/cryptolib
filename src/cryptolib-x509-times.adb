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
        or else Fields (2) < 1
        or else Fields (3) > 23
        or else Fields (4) > 59
        or else Fields (5) > 60
      then
         Status := Invalid_Value;
         return;
      end if;

      --  The day has to exist in the month it names. Checking it against 31
      --  and no further accepts the 31st of February, which is not a date:
      --  a certificate expiring on it is compared field by field like any
      --  other and so stays valid for the days after the month has ended.
      --  Whoever wrote the certificate chose that number.
      declare
         Leap : constant Boolean :=
           (Year mod 4 = 0 and then Year mod 100 /= 0)
           or else Year mod 400 = 0;
         Days_In_Month : constant array (1 .. 12) of Natural :=
           [1  => 31, 2 => (if Leap then 29 else 28), 3  => 31, 4  => 30,
            5  => 31, 6 => 30, 7  => 31, 8  => 31, 9  => 30, 10 => 31,
            11 => 30, 12 => 31];
      begin
         if Fields (2) > Days_In_Month (Fields (1)) then
            Status := Invalid_Value;
            return;
         end if;
      end;

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
