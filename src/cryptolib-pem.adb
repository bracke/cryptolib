package body CryptoLib.PEM is

   use type Ada.Streams.Stream_Element_Offset;

   Begin_Prefix : constant String := "-----BEGIN ";
   End_Prefix   : constant String := "-----END ";
   Armour_Tail  : constant String := "-----";

   function Status_Image (Status : Decode_Status) return String is
   begin
      case Status is
         when Ok               => return "ok";
         when No_Block_Found   => return "no block found";
         when Malformed_Armour => return "malformed armour";
         when Invalid_Base64   => return "invalid base64";
         when Buffer_Too_Small => return "buffer too small";
         when Empty_Block      => return "empty block";
      end case;
   end Status_Image;

   function Is_Whitespace (C : Character) return Boolean
   is (C = ' ' or else C = ASCII.HT or else C = ASCII.CR or else C = ASCII.LF);

   --  Base64 alphabet value, or -1. Padding is not a value and is handled by
   --  the decoder, which is the only place that knows whether padding is
   --  allowed at the position it appears.
   function Base64_Value (C : Character) return Integer is
   begin
      case C is
         when 'A' .. 'Z' => return Character'Pos (C) - Character'Pos ('A');
         when 'a' .. 'z' => return Character'Pos (C) - Character'Pos ('a') + 26;
         when '0' .. '9' => return Character'Pos (C) - Character'Pos ('0') + 52;
         when '+'        => return 62;
         when '/'        => return 63;
         when others     => return -1;
      end case;
   end Base64_Value;

   --  Does Text hold Pattern at Position?
   function Matches_At
     (Text     : String;
      Position : Integer;
      Pattern  : String) return Boolean
   is
   begin
      if Pattern'Length = 0 then
         return True;
      end if;
      if Position < Text'First
        or else Position + Pattern'Length - 1 > Text'Last
      then
         return False;
      end if;
      return Text (Position .. Position + Pattern'Length - 1) = Pattern;
   end Matches_At;

   --  Find the next occurrence of Pattern at or after From.
   function Index_From
     (Text    : String;
      From    : Integer;
      Pattern : String) return Natural
   is
   begin
      if Pattern'Length = 0 or else Pattern'Length > Text'Length then
         return 0;
      end if;

      for I in Integer'Max (From, Text'First)
             .. Text'Last - Pattern'Length + 1
      loop
         if Text (I .. I + Pattern'Length - 1) = Pattern then
            return I;
         end if;
      end loop;

      return 0;
   end Index_From;

   --  Locate one labelled block's armour.
   --
   --  Body_First .. Body_Last is what lies between the two armour lines, and
   --  After is the first index past the END line.
   procedure Find_Block
     (Text       : String;
      Label      : String;
      From       : Positive;
      Body_First : out Natural;
      Body_Last  : out Natural;
      After      : out Natural;
      Status     : out Decode_Status)
   is
      Opening    : constant String := Begin_Prefix & Label & Armour_Tail;
      Closing    : constant String := End_Prefix & Label & Armour_Tail;
      Head       : Natural;
      Tail       : Natural;
      Other_End  : Natural;
   begin
      Body_First := 0;
      Body_Last  := 0;
      After      := 0;

      Head := Index_From (Text, From, Opening);
      if Head = 0 then
         Status := No_Block_Found;
         return;
      end if;

      Body_First := Head + Opening'Length;

      --  A block must be closed by its own label. An END naming something
      --  else means the armour is crossed, not that this block runs on to the
      --  next matching END -- which is what searching only for Closing would
      --  quietly do.
      Other_End := Index_From (Text, Body_First, End_Prefix);
      Tail := Index_From (Text, Body_First, Closing);

      if Tail = 0 or else (Other_End /= 0 and then Other_End < Tail) then
         Status := Malformed_Armour;
         Body_First := 0;
         return;
      end if;

      Body_Last := Tail - 1;
      After := Tail + Closing'Length;
      Status := Ok;
   end Find_Block;

   procedure Decode_Block
     (Text   : String;
      Label  : String;
      From   : in out Positive;
      Output : out Octets;
      Last   : out Offset;
      Status : out Decode_Status)
   is
      Body_First : Natural;
      Body_Last  : Natural;
      After      : Natural;
      Quantum    : array (0 .. 3) of Integer := [others => 0];
      Filled     : Natural := 0;
      Padding    : Natural := 0;
      Cursor     : Offset;
      Finished   : Boolean := False;
   begin
      Last := Output'First - 1;
      Cursor := Output'First;

      Find_Block (Text, Label, From, Body_First, Body_Last, After, Status);
      if Status /= Ok then
         return;
      end if;

      if Body_Last < Body_First then
         Status := Empty_Block;
         return;
      end if;

      for I in Body_First .. Body_Last loop
         declare
            C     : constant Character := Text (I);
            Value : Integer;
         begin
            if Is_Whitespace (C) then
               goto Continue;
            end if;

            --  Anything after the padding has ended the encoding.
            if Finished then
               Status := Invalid_Base64;
               Last := Output'First - 1;
               return;
            end if;

            if C = '=' then
               --  Padding only completes a quantum, and only the last two
               --  positions of one.
               if Filled < 2 then
                  Status := Invalid_Base64;
                  Last := Output'First - 1;
                  return;
               end if;
               Padding := Padding + 1;
               Quantum (Filled) := 0;
               Filled := Filled + 1;
            else
               if Padding > 0 then
                  --  Base64 after padding.
                  Status := Invalid_Base64;
                  Last := Output'First - 1;
                  return;
               end if;

               Value := Base64_Value (C);
               if Value < 0 then
                  Status := Invalid_Base64;
                  Last := Output'First - 1;
                  return;
               end if;
               Quantum (Filled) := Value;
               Filled := Filled + 1;
            end if;

            if Filled = 4 then
               declare
                  Produced : constant Natural := 3 - Padding;
                  Packed   : constant Integer :=
                    Quantum (0) * 262_144 + Quantum (1) * 4_096
                    + Quantum (2) * 64 + Quantum (3);
               begin
                  if Cursor + Offset (Produced) - 1 > Output'Last then
                     Status := Buffer_Too_Small;
                     Last := Output'First - 1;
                     return;
                  end if;

                  if Produced >= 1 then
                     Output (Cursor) :=
                       Ada.Streams.Stream_Element (Packed / 65_536);
                     Cursor := Cursor + 1;
                  end if;
                  if Produced >= 2 then
                     Output (Cursor) :=
                       Ada.Streams.Stream_Element ((Packed / 256) mod 256);
                     Cursor := Cursor + 1;
                  end if;
                  if Produced >= 3 then
                     Output (Cursor) :=
                       Ada.Streams.Stream_Element (Packed mod 256);
                     Cursor := Cursor + 1;
                  end if;
               end;

               Filled := 0;
               Finished := Padding > 0;
            end if;
         end;
         <<Continue>>
      end loop;

      if Filled /= 0 then
         --  A quantum left unfinished: the encoding is truncated.
         Status := Invalid_Base64;
         Last := Output'First - 1;
         return;
      end if;

      if Cursor = Output'First then
         Status := Empty_Block;
         return;
      end if;

      Last := Cursor - 1;
      From := After;
      Status := Ok;
   end Decode_Block;

   function Block_Count (Text : String; Label : String) return Natural is
      Opening : constant String := Begin_Prefix & Label & Armour_Tail;
      Cursor  : Natural := Text'First;
      Found   : Natural := 0;
      Head    : Natural;
   begin
      loop
         Head := Index_From (Text, Cursor, Opening);
         exit when Head = 0;
         Found := Found + 1;
         Cursor := Head + Opening'Length;
      end loop;
      return Found;
   end Block_Count;

end CryptoLib.PEM;
