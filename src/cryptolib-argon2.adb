with Ada.Streams; use Ada.Streams;
with Ada.Unchecked_Deallocation;
with Interfaces;

with CryptoLib.Blake2b;
with CryptoLib.Constant_Time;
with CryptoLib.Secure_Wipe;

package body CryptoLib.Argon2 is

   use CryptoLib.Errors;

   type Word_64 is mod 2 ** 64;
   type Word_32 is mod 2 ** 32;

   Block_Words : constant := 128;                 --  1024 octets
   subtype Word_Index is Natural range 0 .. Block_Words - 1;
   type Block is array (Word_Index) of Word_64;
   type Block_Array is array (Natural range <>) of Block;
   type Block_Array_Access is access Block_Array;

   procedure Free is
     new Ada.Unchecked_Deallocation (Block_Array, Block_Array_Access);

   Sync_Points : constant := 4;                   --  slices per pass

   function Rotate_Right (Value : Word_64; Amount : Natural) return Word_64 is
     (Word_64 (Interfaces.Rotate_Right (Interfaces.Unsigned_64 (Value),
                                        Amount)));

   --  Little-endian 32- and 64-bit encodings, which is Argon2's byte order.
   function LE32 (Value : Natural) return Stream_Element_Array is
      Word : constant Word_32 := Word_32 (Value);
   begin
      return [Stream_Element (Word mod 256),
              Stream_Element ((Word / 2 ** 8) mod 256),
              Stream_Element ((Word / 2 ** 16) mod 256),
              Stream_Element ((Word / 2 ** 24) mod 256)];
   end LE32;

   function To_Octets (Item : Block) return Stream_Element_Array is
      Result : Stream_Element_Array (0 .. 1023);
   begin
      for I in Item'Range loop
         for J in 0 .. 7 loop
            Result (Stream_Element_Offset (I * 8 + J)) :=
              Stream_Element ((Item (I) / (2 ** (8 * J))) mod 256);
         end loop;
      end loop;
      return Result;
   end To_Octets;

   procedure From_Octets (Data : Stream_Element_Array; Item : out Block) is
   begin
      for I in Item'Range loop
         declare
            Word : Word_64 := 0;
         begin
            for J in reverse 0 .. 7 loop
               Word := Word * 256
                 + Word_64 (Data (Data'First
                                  + Stream_Element_Offset (I * 8 + J)));
            end loop;
            Item (I) := Word;
         end;
      end loop;
   end From_Octets;

   --  H', RFC 9106 section 3.3: BLAKE2b when the output fits in 64 octets,
   --  and a chain of 64-octet hashes contributing 32 octets each when it does
   --  not. The tag length is prefixed to the message in both cases, so a
   --  different length is a different hash rather than a truncation.
   function Variable_Hash
     (Data : Stream_Element_Array; Length : Positive)
      return Stream_Element_Array
   is
      Result : Stream_Element_Array (1 .. Stream_Element_Offset (Length));
   begin
      if Length <= 64 then
         declare
            Item   : CryptoLib.Blake2b.Context;
            Digest : Stream_Element_Array (1 .. Stream_Element_Offset (Length));
         begin
            CryptoLib.Blake2b.Initialize (Item, Length);
            CryptoLib.Blake2b.Update (Item, LE32 (Length));
            CryptoLib.Blake2b.Update (Item, Data);
            CryptoLib.Blake2b.Finalize (Item, Digest);
            return Digest;
         end;
      end if;

      declare
         V      : Stream_Element_Array (1 .. 64);
         Cursor : Stream_Element_Offset := Result'First;
         Item   : CryptoLib.Blake2b.Context;
         Left   : Stream_Element_Offset := Stream_Element_Offset (Length);
      begin
         CryptoLib.Blake2b.Initialize (Item, 64);
         CryptoLib.Blake2b.Update (Item, LE32 (Length));
         CryptoLib.Blake2b.Update (Item, Data);
         CryptoLib.Blake2b.Finalize (Item, V);

         --  Each link contributes its first 32 octets until 64 or fewer
         --  remain, and the last link contributes all of what is left.
         while Left > 64 loop
            Result (Cursor .. Cursor + 31) := V (1 .. 32);
            Cursor := Cursor + 32;
            Left := Left - 32;
            V := CryptoLib.Blake2b.Hash (V, 64);
         end loop;
         Result (Cursor .. Result'Last) := V (1 .. Left);
         CryptoLib.Secure_Wipe.Wipe (V'Address, V'Length);
      end;
      return Result;
   end Variable_Hash;

   --  The BlaMka mixing function, RFC 9106 section 3.5. It is BLAKE2b's GB
   --  with the extra 2*a*b term, which is what makes each step depend on a
   --  multiplication and so on latency an adversary cannot shorten.
   procedure Mix (A, B, C, D : in out Word_64) is
      function Mul (X, Y : Word_64) return Word_64 is
        (2 * Word_64 (Word_32 (X and 16#FFFF_FFFF#))
           * Word_64 (Word_32 (Y and 16#FFFF_FFFF#)));
   begin
      A := A + B + Mul (A, B);
      D := Rotate_Right (D xor A, 32);
      C := C + D + Mul (C, D);
      B := Rotate_Right (B xor C, 24);
      A := A + B + Mul (A, B);
      D := Rotate_Right (D xor A, 16);
      C := C + D + Mul (C, D);
      B := Rotate_Right (B xor C, 63);
   end Mix;

   type Word_Index_Array is array (Positive range 1 .. 16) of Word_Index;

   --  P, the permutation over sixteen words: BLAKE2b's round shape.
   procedure Permute (V : in out Block; I : Word_Index_Array) is
   begin
      Mix (V (I (1)), V (I (5)), V (I (9)),  V (I (13)));
      Mix (V (I (2)), V (I (6)), V (I (10)), V (I (14)));
      Mix (V (I (3)), V (I (7)), V (I (11)), V (I (15)));
      Mix (V (I (4)), V (I (8)), V (I (12)), V (I (16)));
      Mix (V (I (1)), V (I (6)), V (I (11)), V (I (16)));
      Mix (V (I (2)), V (I (7)), V (I (12)), V (I (13)));
      Mix (V (I (3)), V (I (8)), V (I (9)),  V (I (14)));
      Mix (V (I (4)), V (I (5)), V (I (10)), V (I (15)));
   end Permute;

   --  G, RFC 9106 section 3.4: R = X xor Y, P over rows, P over columns, then
   --  xor R back in. With_Xor adds the previous contents of the destination,
   --  which is what the second and later passes do.
   procedure Compress
     (Dest : in out Block; X, Y : Block; With_Xor : Boolean)
   is
      R : Block;
      Z : Block;
   begin
      for K in R'Range loop
         R (K) := X (K) xor Y (K);
      end loop;
      Z := R;

      --  Rows: sixteen consecutive words, eight of them.
      for Row in 0 .. 7 loop
         declare
            Index : Word_Index_Array;
         begin
            for K in Index'Range loop
               Index (K) := Row * 16 + (K - 1);
            end loop;
            Permute (Z, Index);
         end;
      end loop;

      --  Columns: two words from each row, striding by sixteen.
      for Col in 0 .. 7 loop
         declare
            Index : Word_Index_Array;
         begin
            for K in 0 .. 7 loop
               Index (2 * K + 1) := 2 * Col + 16 * K;
               Index (2 * K + 2) := 2 * Col + 16 * K + 1;
            end loop;
            Permute (Z, Index);
         end;
      end loop;

      for K in Dest'Range loop
         if With_Xor then
            Dest (K) := Dest (K) xor Z (K) xor R (K);
         else
            Dest (K) := Z (K) xor R (K);
         end if;
      end loop;
   end Compress;

   function Derive
     (Kind       : Variant;
      Password   : Ada.Streams.Stream_Element_Array;
      Salt       : Ada.Streams.Stream_Element_Array;
      Secret     : Ada.Streams.Stream_Element_Array;
      Associated : Ada.Streams.Stream_Element_Array;
      Iterations : Positive;
      Memory_KiB : Positive;
      Lanes      : Positive;
      Tag        : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      Memory : Block_Array_Access;
      Blocks : Natural;
      Lane_Length : Natural;
      Segment     : Natural;
      Kind_Code   : constant Natural := Variant'Pos (Kind);
   begin
      Tag := [others => 0];

      if Tag'Length < 4
        or else Salt'Length < 8
        or else Secret'Length > 64
        or else Memory_KiB < 8 * Lanes
        or else Lanes > 16#FF_FFFF#
      then
         return Handshake_Failed;
      end if;

      --  m' = 4*p*floor(m/4p): the memory rounded down to a whole number of
      --  segments in every lane.
      Blocks := (Memory_KiB / (Sync_Points * Lanes)) * Sync_Points * Lanes;
      Lane_Length := Blocks / Lanes;
      Segment := Lane_Length / Sync_Points;

      begin
         Memory := new Block_Array (0 .. Blocks - 1);
      exception
         when others =>
            return Internal_Error;
      end;

      declare
         H0 : Stream_Element_Array (1 .. 64);

         procedure Initial_Hash is
            Item : CryptoLib.Blake2b.Context;
         begin
            CryptoLib.Blake2b.Initialize (Item, 64);
            CryptoLib.Blake2b.Update (Item, LE32 (Lanes));
            CryptoLib.Blake2b.Update (Item, LE32 (Natural (Tag'Length)));
            CryptoLib.Blake2b.Update (Item, LE32 (Memory_KiB));
            CryptoLib.Blake2b.Update (Item, LE32 (Iterations));
            CryptoLib.Blake2b.Update (Item, LE32 (16#13#));   --  version
            CryptoLib.Blake2b.Update (Item, LE32 (Kind_Code));
            CryptoLib.Blake2b.Update (Item, LE32 (Natural (Password'Length)));
            CryptoLib.Blake2b.Update (Item, Password);
            CryptoLib.Blake2b.Update (Item, LE32 (Natural (Salt'Length)));
            CryptoLib.Blake2b.Update (Item, Salt);
            CryptoLib.Blake2b.Update (Item, LE32 (Natural (Secret'Length)));
            CryptoLib.Blake2b.Update (Item, Secret);
            CryptoLib.Blake2b.Update (Item, LE32 (Natural (Associated'Length)));
            CryptoLib.Blake2b.Update (Item, Associated);
            CryptoLib.Blake2b.Finalize (Item, H0);
         end Initial_Hash;

         --  Argon2i and the independent half of Argon2id draw their indices
         --  from a block generated by compressing a counter, rather than from
         --  the data. Address_Block holds that stream.
         Address_Block : Block := [others => 0];
         Input_Block   : Block := [others => 0];
         Zero_Block    : constant Block := [others => 0];

         --  The second compression takes the first's output as its own
         --  input. Through a copy, so that the destination and the operand
         --  are not the same object: Compress reads both operands before it
         --  writes, so aliasing them would work, but working by accident is
         --  not a property to rely on and GNAT is right to say so.
         procedure Next_Addresses is
            Source : Block;
         begin
            Input_Block (6) := Input_Block (6) + 1;
            Compress (Address_Block, Zero_Block, Input_Block, False);
            Source := Address_Block;
            Compress (Address_Block, Zero_Block, Source, False);
         end Next_Addresses;

         function Independent_Indexing
           (Pass : Natural; Slice : Natural) return Boolean
         is (Kind = Argon2i
             or else (Kind = Argon2id and then Pass = 0 and then Slice < 2));

      begin
         Initial_Hash;

         --  The first two columns of every lane come straight from H0.
         for Lane in 0 .. Lanes - 1 loop
            for Column in 0 .. 1 loop
               declare
                  Seed : constant Stream_Element_Array :=
                    H0 & LE32 (Column) & LE32 (Lane);
                  Bytes : constant Stream_Element_Array :=
                    Variable_Hash (Seed, 1024);
               begin
                  From_Octets (Bytes, Memory (Lane * Lane_Length + Column));
               end;
            end loop;
         end loop;

         for Pass in 0 .. Iterations - 1 loop
            for Slice in 0 .. Sync_Points - 1 loop
               for Lane in 0 .. Lanes - 1 loop
                  declare
                     Start : Natural;
                  begin
                     if Pass = 0 and then Slice = 0 then
                        Start := 2;
                     else
                        Start := 0;
                     end if;

                     if Independent_Indexing (Pass, Slice) then
                        Input_Block := [others => 0];
                        Input_Block (0) := Word_64 (Pass);
                        Input_Block (1) := Word_64 (Lane);
                        Input_Block (2) := Word_64 (Slice);
                        Input_Block (3) := Word_64 (Blocks);
                        Input_Block (4) := Word_64 (Iterations);
                        Input_Block (5) := Word_64 (Kind_Code);
                        --  The slot is the segment index itself, not a
                        --  counter of blocks produced, so the first segment
                        --  -- which starts at 2 rather than 0 -- needs its
                        --  address block generated before the loop and then
                        --  reads slots 2 upward. A separate counter agrees
                        --  with this only while a segment is shorter than
                        --  128 blocks, which is why small parameters hid it.
                        if Pass = 0 and then Slice = 0 then
                           Next_Addresses;
                        end if;
                     end if;

                     for Index in Start .. Segment - 1 loop
                        declare
                           Current : constant Natural :=
                             Lane * Lane_Length + Slice * Segment + Index;
                           Previous : Natural;
                           J1, J2   : Word_64;
                           Ref_Lane : Natural;
                           Ref_Index : Natural;
                           Window   : Natural;
                           Position : Natural;
                        begin
                           if Current mod Lane_Length = 0 then
                              Previous := Current + Lane_Length - 1;
                           else
                              Previous := Current - 1;
                           end if;

                           if Independent_Indexing (Pass, Slice) then
                              if Index mod 128 = 0 then
                                 Next_Addresses;
                              end if;
                              J1 := Address_Block (Index mod 128)
                                      and 16#FFFF_FFFF#;
                              J2 := Address_Block (Index mod 128) / 2 ** 32;
                           else
                              J1 := Memory (Previous) (0) and 16#FFFF_FFFF#;
                              J2 := Memory (Previous) (0) / 2 ** 32;
                           end if;

                           if Pass = 0 and then Slice = 0 then
                              Ref_Lane := Lane;
                           else
                              Ref_Lane := Natural (J2 mod Word_64 (Lanes));
                           end if;

                           --  How much of the reference lane is already
                           --  filled and therefore quotable.
                           --  The block immediately before this one is
                           --  already the other operand, so it is excluded
                           --  from the reference area: that is the -1 on
                           --  every same-lane case, and getting it wrong
                           --  produces a tag that is wrong everywhere.
                           if Pass = 0 then
                              if Slice = 0 then
                                 Window := Index - 1;
                              elsif Ref_Lane = Lane then
                                 Window := Slice * Segment + Index - 1;
                              elsif Index = 0 then
                                 Window := Slice * Segment - 1;
                              else
                                 Window := Slice * Segment;
                              end if;
                           else
                              if Ref_Lane = Lane then
                                 Window := Lane_Length - Segment + Index - 1;
                              elsif Index = 0 then
                                 Window := Lane_Length - Segment - 1;
                              else
                                 Window := Lane_Length - Segment;
                              end if;
                           end if;

                           --  RFC 9106 section 3.4.1.2's mapping, which
                           --  weights the choice toward recent blocks.
                           declare
                              X : constant Word_64 :=
                                (J1 * J1) / 2 ** 32;
                              Y : constant Word_64 :=
                                (Word_64 (Window) * X) / 2 ** 32;
                              Z : constant Natural :=
                                Window - 1 - Natural (Y);
                           begin
                              if Pass = 0 then
                                 Position := 0;
                              else
                                 if Slice = Sync_Points - 1 then
                                    Position := 0;
                                 else
                                    Position := (Slice + 1) * Segment;
                                 end if;
                              end if;
                              Ref_Index :=
                                (Position + Z) mod Lane_Length;
                           end;

                           Compress
                             (Memory (Current),
                              Memory (Previous),
                              Memory (Ref_Lane * Lane_Length + Ref_Index),
                              With_Xor => Pass > 0);
                        end;
                     end loop;
                  end;
               end loop;
            end loop;
         end loop;

         --  The final block is the xor of the last column of every lane.
         declare
            Final : Block := Memory (Lane_Length - 1);
         begin
            for Lane in 1 .. Lanes - 1 loop
               for K in Final'Range loop
                  Final (K) :=
                    Final (K) xor Memory (Lane * Lane_Length + Lane_Length - 1) (K);
               end loop;
            end loop;
            Tag := Variable_Hash (To_Octets (Final), Natural (Tag'Length));
            CryptoLib.Secure_Wipe.Wipe (Final'Address, 1024);
         end;

         CryptoLib.Secure_Wipe.Wipe (H0'Address, H0'Length);
      end;

      for I in Memory'Range loop
         CryptoLib.Secure_Wipe.Wipe (Memory (I)'Address, 1024);
      end loop;
      Free (Memory);
      return Ok;
   exception
      when others =>
         if Memory /= null then
            Free (Memory);
         end if;
         Tag := [others => 0];
         return Internal_Error;
   end Derive;

   function Derive
     (Kind       : Variant;
      Password   : Ada.Streams.Stream_Element_Array;
      Salt       : Ada.Streams.Stream_Element_Array;
      Iterations : Positive;
      Memory_KiB : Positive;
      Lanes      : Positive;
      Tag        : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      None : constant Stream_Element_Array (1 .. 0) := [others => 0];
   begin
      return Derive (Kind, Password, Salt, None, None,
                     Iterations, Memory_KiB, Lanes, Tag);
   end Derive;

   function Verify
     (Kind       : Variant;
      Password   : Ada.Streams.Stream_Element_Array;
      Salt       : Ada.Streams.Stream_Element_Array;
      Secret     : Ada.Streams.Stream_Element_Array;
      Associated : Ada.Streams.Stream_Element_Array;
      Iterations : Positive;
      Memory_KiB : Positive;
      Lanes      : Positive;
      Tag        : Ada.Streams.Stream_Element_Array) return Boolean
   is
      Computed : Ada.Streams.Stream_Element_Array (Tag'Range);
      Status   : CryptoLib.Errors.Status;
   begin
      if Tag'Length = 0 then
         return False;
      end if;
      Status := Derive (Kind, Password, Salt, Secret, Associated,
                        Iterations, Memory_KiB, Lanes, Computed);
      if Status /= CryptoLib.Errors.Ok then
         --  Derive zeroes Computed on failure; say no without comparing, so
         --  a refused parameter cannot be mistaken for a matching all-zero
         --  tag.
         return False;
      end if;
      return Result : constant Boolean :=
        CryptoLib.Constant_Time.Equal (Computed, Tag)
      do
         CryptoLib.Secure_Wipe.Wipe
           (Computed'Address, Computed'Length);
      end return;
   end Verify;

   function Verify
     (Kind       : Variant;
      Password   : Ada.Streams.Stream_Element_Array;
      Salt       : Ada.Streams.Stream_Element_Array;
      Iterations : Positive;
      Memory_KiB : Positive;
      Lanes      : Positive;
      Tag        : Ada.Streams.Stream_Element_Array) return Boolean
   is
      None : constant Ada.Streams.Stream_Element_Array (1 .. 0) :=
        [others => 0];
   begin
      return Verify (Kind, Password, Salt, None, None,
                     Iterations, Memory_KiB, Lanes, Tag);
   end Verify;

end CryptoLib.Argon2;
