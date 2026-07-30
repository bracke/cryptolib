with Ada.Streams; use Ada.Streams;
with Interfaces;
with System;

with CryptoLib.Secure_Wipe;

package body CryptoLib.Blake2b is

   --  RFC 7693 section 2.6: the same initialisation vector SHA-512 uses.
   IV : constant Word_Array (0 .. 7) :=
     [16#6A09E667F3BCC908#,
      16#BB67AE8584CAA73B#,
      16#3C6EF372FE94F82B#,
      16#A54FF53A5F1D36F1#,
      16#510E527FADE682D1#,
      16#9B05688C2B3E6C1F#,
      16#1F83D9ABFB41BD6B#,
      16#5BE0CD19137E2179#];

   --  The twelve message permutations of RFC 7693 section 2.7; the last
   --  two repeat the first two.
   Sigma : constant array (0 .. 11, 0 .. 15) of Natural :=
     [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
      [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
      [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
      [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
      [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
      [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
      [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
      [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
      [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
      [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
      [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
      [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]];

   function Rotate_Right (Value : Word_64; Amount : Natural) return Word_64 is
     (Word_64 (Interfaces.Rotate_Right (Interfaces.Unsigned_64 (Value),
                                        Amount)));

   --  The G mixing function, RFC 7693 section 3.1. The rotation amounts 32,
   --  24, 16 and 63 are what distinguish BLAKE2b from BLAKE2s.
   procedure Mix
     (V          : in out Word_Array;
      A, B, C, D : Natural;
      X, Y       : Word_64) is
   begin
      V (A) := V (A) + V (B) + X;
      V (D) := Rotate_Right (V (D) xor V (A), 32);
      V (C) := V (C) + V (D);
      V (B) := Rotate_Right (V (B) xor V (C), 24);
      V (A) := V (A) + V (B) + Y;
      V (D) := Rotate_Right (V (D) xor V (A), 16);
      V (C) := V (C) + V (D);
      V (B) := Rotate_Right (V (B) xor V (C), 63);
   end Mix;

   --  Compress one 128-octet block. Last says whether this is the final
   --  block, which is what the inversion of V (14) marks.
   procedure Compress
     (H          : in out Word_Array;
      Block      : Stream_Element_Array;
      Counter    : Word_64;
      Counter_Hi : Word_64;
      Last       : Boolean)
   is
      V : Word_Array (0 .. 15);
      M : Word_Array (0 .. 15);
   begin
      for I in M'Range loop
         declare
            Base : constant Stream_Element_Offset :=
              Block'First + Stream_Element_Offset (I) * 8;
            Word : Word_64 := 0;
         begin
            --  Little-endian, which is BLAKE2's byte order throughout.
            for J in reverse 0 .. 7 loop
               Word := Word * 256
                 + Word_64 (Block (Base + Stream_Element_Offset (J)));
            end loop;
            M (I) := Word;
         end;
      end loop;

      V (0 .. 7) := H;
      V (8 .. 15) := IV;
      V (12) := V (12) xor Counter;
      V (13) := V (13) xor Counter_Hi;
      if Last then
         V (14) := not V (14);
      end if;

      for Round in 0 .. 11 loop
         Mix (V, 0, 4,  8, 12, M (Sigma (Round, 0)),  M (Sigma (Round, 1)));
         Mix (V, 1, 5,  9, 13, M (Sigma (Round, 2)),  M (Sigma (Round, 3)));
         Mix (V, 2, 6, 10, 14, M (Sigma (Round, 4)),  M (Sigma (Round, 5)));
         Mix (V, 3, 7, 11, 15, M (Sigma (Round, 6)),  M (Sigma (Round, 7)));
         Mix (V, 0, 5, 10, 15, M (Sigma (Round, 8)),  M (Sigma (Round, 9)));
         Mix (V, 1, 6, 11, 12, M (Sigma (Round, 10)), M (Sigma (Round, 11)));
         Mix (V, 2, 7,  8, 13, M (Sigma (Round, 12)), M (Sigma (Round, 13)));
         Mix (V, 3, 4,  9, 14, M (Sigma (Round, 14)), M (Sigma (Round, 15)));
      end loop;

      for I in H'Range loop
         H (I) := H (I) xor V (I) xor V (I + 8);
      end loop;
   end Compress;

   --  The parameter block, RFC 7693 section 2.5, folded into H (0) as the
   --  spec's "IV XOR ParamBlock" for the simple case: digest length, key
   --  length, fanout 1 and depth 1, everything else zero.
   procedure Start
     (Item : out Context; Key_Bytes : Natural; Length : Digest_Length) is
   begin
      Item.H := IV;
      Item.H (0) := Item.H (0)
        xor Word_64 (Length)
        xor Word_64 (Key_Bytes) * 2 ** 8
        xor 16#01_01_00_00#;
      Item.Buffer := [others => 0];
      Item.Buffered := 0;
      Item.Counter := 0;
      Item.Counter_Hi := 0;
      Item.Out_Length := Length;
      Item.Started := True;
   end Start;

   procedure Initialize (Item : out Context; Length : Digest_Length := 64) is
   begin
      Start (Item, 0, Length);
   end Initialize;

   procedure Initialize
     (Item   : out Context;
      Key    : Ada.Streams.Stream_Element_Array;
      Length : Digest_Length := 64) is
   begin
      if Key'Length > 64 then
         raise Constraint_Error with "BLAKE2b key longer than 64 octets";
      end if;
      Start (Item, Natural (Key'Length), Length);
      if Key'Length > 0 then
         --  A keyed hash begins with the key in a block of its own, zero
         --  padded to the full 128 octets.
         declare
            Padded : Stream_Element_Array (Block_Index) := [others => 0];
         begin
            Padded (0 .. Key'Length - 1) := Key;
            Update (Item, Padded);
            CryptoLib.Secure_Wipe.Wipe (Padded'Address, Padded'Length);
         end;
      end if;
   end Initialize;

   procedure Update
     (Item : in out Context; Data : Ada.Streams.Stream_Element_Array)
   is
      Cursor : Stream_Element_Offset := Data'First;
   begin
      while Cursor <= Data'Last loop
         if Item.Buffered = 128 then
            --  A full buffer is only compressed once something follows it:
            --  the final block takes a different path, so it must not be
            --  consumed here.
            Item.Counter := Item.Counter + 128;
            if Item.Counter < 128 then
               Item.Counter_Hi := Item.Counter_Hi + 1;
            end if;
            Compress (Item.H, Item.Buffer, Item.Counter, Item.Counter_Hi,
                      False);
            Item.Buffered := 0;
         end if;
         declare
            Room : constant Stream_Element_Offset := 128 - Item.Buffered;
            Take : constant Stream_Element_Offset :=
              Stream_Element_Offset'Min (Room, Data'Last - Cursor + 1);
         begin
            Item.Buffer (Item.Buffered .. Item.Buffered + Take - 1) :=
              Data (Cursor .. Cursor + Take - 1);
            Item.Buffered := Item.Buffered + Take;
            Cursor := Cursor + Take;
         end;
      end loop;
   end Update;

   procedure Finalize
     (Item : in out Context; Digest : out Ada.Streams.Stream_Element_Array)
   is
      use System;
   begin
      if Digest'Length /= Stream_Element_Offset (Item.Out_Length) then
         raise Constraint_Error with "BLAKE2b digest buffer is the wrong size";
      end if;

      Item.Counter := Item.Counter + Word_64 (Item.Buffered);
      if Item.Counter < Word_64 (Item.Buffered) then
         Item.Counter_Hi := Item.Counter_Hi + 1;
      end if;
      Item.Buffer (Item.Buffered .. 127) := [others => 0];
      Compress (Item.H, Item.Buffer, Item.Counter, Item.Counter_Hi, True);

      for I in Digest'Range loop
         declare
            Offset : constant Natural := Natural (I - Digest'First);
            Word   : constant Word_64 := Item.H (Offset / 8);
         begin
            Digest (I) :=
              Stream_Element ((Word / (2 ** (8 * (Offset mod 8)))) mod 256);
         end;
      end loop;

      CryptoLib.Secure_Wipe.Wipe (Item'Address, Item'Size / Storage_Unit);
   end Finalize;

   function Hash
     (Data   : Ada.Streams.Stream_Element_Array;
      Length : Digest_Length := 64) return Ada.Streams.Stream_Element_Array
   is
      Item   : Context;
      Result : Stream_Element_Array (1 .. Stream_Element_Offset (Length));
   begin
      Initialize (Item, Length);
      Update (Item, Data);
      Finalize (Item, Result);
      return Result;
   end Hash;

   function Hash
     (Key    : Ada.Streams.Stream_Element_Array;
      Data   : Ada.Streams.Stream_Element_Array;
      Length : Digest_Length := 64) return Ada.Streams.Stream_Element_Array
   is
      Item   : Context;
      Result : Stream_Element_Array (1 .. Stream_Element_Offset (Length));
   begin
      Initialize (Item, Key, Length);
      Update (Item, Data);
      Finalize (Item, Result);
      return Result;
   end Hash;

end CryptoLib.Blake2b;
