with Ada.Streams; use Ada.Streams;

package body CryptoLib.Base64 is

   Alphabet : constant String :=
     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

   function Encoded_Length (Count : Natural) return Natural is
     ((Count / 3) * 4 + (case Count mod 3 is
                            when 0 => 0,
                            when 1 => 2,
                            when others => 3));

   function Decoded_Length (Length : Natural) return Natural is
     (case Length mod 4 is
         when 0 => (Length / 4) * 3,
         when 2 => (Length / 4) * 3 + 1,
         when 3 => (Length / 4) * 3 + 2,
         --  One character over a group boundary encodes nothing.
         when others => 0);

   procedure Encode
     (Data : Ada.Streams.Stream_Element_Array;
      Into : out String;
      Last : out Natural)
   is
      Cursor : Stream_Element_Offset := Data'First;
      Out_At : Natural := Into'First;

      procedure Put (Value : Natural) is
      begin
         Into (Out_At) := Alphabet (Value + 1);
         Out_At := Out_At + 1;
      end Put;
   begin
      Last := Into'First - 1;
      if Into'Length < Encoded_Length (Natural (Data'Length)) then
         return;
      end if;

      while Cursor <= Data'Last loop
         declare
            Remaining : constant Stream_Element_Offset := Data'Last - Cursor + 1;
            B0 : constant Natural := Natural (Data (Cursor));
            B1 : constant Natural :=
              (if Remaining > 1 then Natural (Data (Cursor + 1)) else 0);
            B2 : constant Natural :=
              (if Remaining > 2 then Natural (Data (Cursor + 2)) else 0);
            Trio : constant Natural := B0 * 65536 + B1 * 256 + B2;
         begin
            Put (Trio / 262144);
            Put ((Trio / 4096) mod 64);
            if Remaining > 1 then
               Put ((Trio / 64) mod 64);
            end if;
            if Remaining > 2 then
               Put (Trio mod 64);
            end if;
            Cursor := Cursor + 3;
         end;
      end loop;
      Last := Out_At - 1;
   end Encode;

   procedure Decode
     (Text  : String;
      Into  : out Ada.Streams.Stream_Element_Array;
      Last  : out Ada.Streams.Stream_Element_Offset;
      Valid : out Boolean)
   is
      --  -1 for anything outside the alphabet, including padding and space.
      function Value_Of (Item : Character) return Integer is
      begin
         for I in Alphabet'Range loop
            if Alphabet (I) = Item then
               return I - Alphabet'First;
            end if;
         end loop;
         return -1;
      end Value_Of;

      Produced : constant Natural := Decoded_Length (Text'Length);
      Cursor   : Natural := Text'First;
      Out_At   : Stream_Element_Offset := Into'First;
   begin
      Into := [others => 0];
      Last := Into'First - 1;
      Valid := False;

      if Text'Length = 0 then
         Valid := True;
         return;
      end if;
      if Produced = 0 or else Natural (Into'Length) < Produced then
         return;
      end if;

      while Cursor <= Text'Last loop
         declare
            Group : constant Natural :=
              Natural'Min (4, Text'Last - Cursor + 1);
            V : array (0 .. 3) of Integer := [others => 0];
            Accum : Natural := 0;
         begin
            for I in 0 .. Group - 1 loop
               V (I) := Value_Of (Text (Cursor + I));
               if V (I) < 0 then
                  return;
               end if;
            end loop;

            for I in 0 .. 3 loop
               Accum := Accum * 64 + (if I < Group then V (I) else 0);
            end loop;

            --  A short final group carries bits that encode nothing; DER-like
            --  strictness, and what keeps the encoding one-to-one.
            case Group is
               when 2 =>
                  if Accum mod 65536 /= 0 then
                     return;
                  end if;
               when 3 =>
                  if Accum mod 256 /= 0 then
                     return;
                  end if;
               when others => null;
            end case;

            Into (Out_At) := Stream_Element (Accum / 65536);
            Out_At := Out_At + 1;
            if Group > 2 then
               Into (Out_At) := Stream_Element ((Accum / 256) mod 256);
               Out_At := Out_At + 1;
            end if;
            if Group > 3 then
               Into (Out_At) := Stream_Element (Accum mod 256);
               Out_At := Out_At + 1;
            end if;
            Cursor := Cursor + Group;
         end;
      end loop;

      Last := Out_At - 1;
      Valid := True;
   end Decode;

end CryptoLib.Base64;
