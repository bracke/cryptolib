with Interfaces;

package body CryptoLib.SHA3 is
   use type Ada.Streams.Stream_Element_Offset;
   use type Interfaces.Unsigned_64;

   subtype Word64 is Interfaces.Unsigned_64;
   subtype Byte is Interfaces.Unsigned_8;

   type Lane_Index is range 0 .. 24;
   type Keccak_State is array (Lane_Index) of Word64;
   type Round_Index is range 0 .. 23;
   type Round_Constants is array (Round_Index) of Word64;
   type Rotation_Offsets is array (Lane_Index) of Natural;

   RC : constant Round_Constants :=
     [16#0000_0000_0000_0001#,
      16#0000_0000_0000_8082#,
      16#8000_0000_0000_808A#,
      16#8000_0000_8000_8000#,
      16#0000_0000_0000_808B#,
      16#0000_0000_8000_0001#,
      16#8000_0000_8000_8081#,
      16#8000_0000_0000_8009#,
      16#0000_0000_0000_008A#,
      16#0000_0000_0000_0088#,
      16#0000_0000_8000_8009#,
      16#0000_0000_8000_000A#,
      16#0000_0000_8000_808B#,
      16#8000_0000_0000_008B#,
      16#8000_0000_0000_8089#,
      16#8000_0000_0000_8003#,
      16#8000_0000_0000_8002#,
      16#8000_0000_0000_0080#,
      16#0000_0000_0000_800A#,
      16#8000_0000_8000_000A#,
      16#8000_0000_8000_8081#,
      16#8000_0000_0000_8080#,
      16#0000_0000_8000_0001#,
      16#8000_0000_8000_8008#];

   Rho : constant Rotation_Offsets :=
     [0,  1, 62, 28, 27,
      36, 44,  6, 55, 20,
       3, 10, 43, 25, 39,
      41, 45, 15, 21,  8,
      18,  2, 61, 56, 14];

   function Index_Of
     (X_Value : Natural;
      Y_Value : Natural)
      return Lane_Index
     with SPARK_Mode => On,
          Pre => X_Value <= 4 and then Y_Value <= 4
   is
   begin
      return Lane_Index (X_Value + 5 * Y_Value);
   end Index_Of;

   function Rotate_Left_64
     (Value  : Word64;
      Amount : Natural)
      return Word64
     with SPARK_Mode => On,
          Pre => Amount <= 64
   is
   begin
      if Amount = 0 then
         return Value;
      else
         return Interfaces.Shift_Left (Value, Amount)
           or Interfaces.Shift_Right (Value, 64 - Amount);
      end if;
   end Rotate_Left_64;

   --  Keccak-f[1600], each round written out: every lane index and rotation
   --  a literal, so nothing is looked up or reduced modulo five at run time.
   --  Generated from the definition: theta, rho and pi, chi, iota.
   procedure Permute (State_Item : in out Keccak_State) is
      function Rot (Value : Word64; Amount : Natural) return Word64 is
        (Interfaces.Rotate_Left (Value, Amount))
        with Inline;
      A : Keccak_State := State_Item;
      B : Keccak_State;
      C0, C1, C2, C3, C4, D0, D1, D2, D3, D4 : Word64;
   begin
      for Round_Value in Round_Index loop
         C0 := A (0) xor A (5) xor A (10) xor A (15) xor A (20);
         C1 := A (1) xor A (6) xor A (11) xor A (16) xor A (21);
         C2 := A (2) xor A (7) xor A (12) xor A (17) xor A (22);
         C3 := A (3) xor A (8) xor A (13) xor A (18) xor A (23);
         C4 := A (4) xor A (9) xor A (14) xor A (19) xor A (24);
         D0 := C4 xor Rot (C1, 1);
         D1 := C0 xor Rot (C2, 1);
         D2 := C1 xor Rot (C3, 1);
         D3 := C2 xor Rot (C4, 1);
         D4 := C3 xor Rot (C0, 1);
         B (0) := (A (0) xor D0);
         B (16) := Rot (A (5) xor D0, 36);
         B (7) := Rot (A (10) xor D0, 3);
         B (23) := Rot (A (15) xor D0, 41);
         B (14) := Rot (A (20) xor D0, 18);
         B (10) := Rot (A (1) xor D1, 1);
         B (1) := Rot (A (6) xor D1, 44);
         B (17) := Rot (A (11) xor D1, 10);
         B (8) := Rot (A (16) xor D1, 45);
         B (24) := Rot (A (21) xor D1, 2);
         B (20) := Rot (A (2) xor D2, 62);
         B (11) := Rot (A (7) xor D2, 6);
         B (2) := Rot (A (12) xor D2, 43);
         B (18) := Rot (A (17) xor D2, 15);
         B (9) := Rot (A (22) xor D2, 61);
         B (5) := Rot (A (3) xor D3, 28);
         B (21) := Rot (A (8) xor D3, 55);
         B (12) := Rot (A (13) xor D3, 25);
         B (3) := Rot (A (18) xor D3, 21);
         B (19) := Rot (A (23) xor D3, 56);
         B (15) := Rot (A (4) xor D4, 27);
         B (6) := Rot (A (9) xor D4, 20);
         B (22) := Rot (A (14) xor D4, 39);
         B (13) := Rot (A (19) xor D4, 8);
         B (4) := Rot (A (24) xor D4, 14);
         A (0) := B (0) xor ((not B (1)) and B (2));
         A (1) := B (1) xor ((not B (2)) and B (3));
         A (2) := B (2) xor ((not B (3)) and B (4));
         A (3) := B (3) xor ((not B (4)) and B (0));
         A (4) := B (4) xor ((not B (0)) and B (1));
         A (5) := B (5) xor ((not B (6)) and B (7));
         A (6) := B (6) xor ((not B (7)) and B (8));
         A (7) := B (7) xor ((not B (8)) and B (9));
         A (8) := B (8) xor ((not B (9)) and B (5));
         A (9) := B (9) xor ((not B (5)) and B (6));
         A (10) := B (10) xor ((not B (11)) and B (12));
         A (11) := B (11) xor ((not B (12)) and B (13));
         A (12) := B (12) xor ((not B (13)) and B (14));
         A (13) := B (13) xor ((not B (14)) and B (10));
         A (14) := B (14) xor ((not B (10)) and B (11));
         A (15) := B (15) xor ((not B (16)) and B (17));
         A (16) := B (16) xor ((not B (17)) and B (18));
         A (17) := B (17) xor ((not B (18)) and B (19));
         A (18) := B (18) xor ((not B (19)) and B (15));
         A (19) := B (19) xor ((not B (15)) and B (16));
         A (20) := B (20) xor ((not B (21)) and B (22));
         A (21) := B (21) xor ((not B (22)) and B (23));
         A (22) := B (22) xor ((not B (23)) and B (24));
         A (23) := B (23) xor ((not B (24)) and B (20));
         A (24) := B (24) xor ((not B (20)) and B (21));
         A (0) := A (0) xor RC (Round_Value);
      end loop;
      State_Item := A;
   end Permute;

   procedure Xor_Rate_Byte
     (State_Item : in out Keccak_State;
      Offset     : Natural;
      Value      : Byte)
     with SPARK_Mode => On,
          Pre => Offset <= 199
   is
      Lane_Value : constant Lane_Index := Lane_Index (Offset / 8);
      Shift_Bits : constant Natural := (Offset mod 8) * 8;
   begin
      State_Item (Lane_Value) := State_Item (Lane_Value)
        xor Interfaces.Shift_Left (Word64 (Value), Shift_Bits);
   end Xor_Rate_Byte;

   function Read_Rate_Byte
     (State_Item : Keccak_State;
      Offset     : Natural)
      return Ada.Streams.Stream_Element
     with SPARK_Mode => On,
          Pre => Offset <= 199
   is
      Lane_Value : constant Lane_Index := Lane_Index (Offset / 8);
      Shift_Bits : constant Natural := (Offset mod 8) * 8;
   begin
      return Ada.Streams.Stream_Element
        (Interfaces.Shift_Right (State_Item (Lane_Value), Shift_Bits) and 16#FF#);
   end Read_Rate_Byte;

   function Sponge
     (Data          : Ada.Streams.Stream_Element_Array;
      Rate_Bytes    : Positive;
      Domain_Suffix : Byte;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array
   is
      State_Item : Keccak_State := [others => 0];
      Position   : Natural := 0;
      Result     : Ada.Streams.Stream_Element_Array
        (Ada.Streams.Stream_Element_Offset (1) .. Ada.Streams.Stream_Element_Offset (Output_Length)) :=
        [others => 0];
      Out_Index  : Ada.Streams.Stream_Element_Offset := Result'First;
   begin
      --  Whole lanes at a time where they line up -- the rates are
      --  multiples of eight -- and the rest a byte at a time.
      declare
         Data_Index : Ada.Streams.Stream_Element_Offset := Data'First;
      begin
         while Data_Index <= Data'Last loop
            if Position mod 8 = 0 and then Data'Last - Data_Index + 1 >= 8 then
               declare
                  Lane_Value : Word64 := 0;
               begin
                  for K in reverse 0 .. 7 loop
                     Lane_Value := Interfaces.Shift_Left (Lane_Value, 8)
                       or Word64 (Data (Data_Index + Ada.Streams.Stream_Element_Offset (K)));
                  end loop;
                  State_Item (Lane_Index (Position / 8)) := State_Item (Lane_Index (Position / 8)) xor Lane_Value;
               end;
               Position := Position + 8;
               Data_Index := Data_Index + 8;
            else
               Xor_Rate_Byte (State_Item, Position, Byte (Data (Data_Index)));
               Position := Position + 1;
               Data_Index := Data_Index + 1;
            end if;
            if Position = Rate_Bytes then
               Permute (State_Item);
               Position := 0;
            end if;
         end loop;
      end;

      Xor_Rate_Byte (State_Item, Position, Domain_Suffix);
      Xor_Rate_Byte (State_Item, Rate_Bytes - 1, 16#80#);
      Permute (State_Item);

      while Out_Index <= Result'Last loop
         for Rate_Index in 0 .. Rate_Bytes - 1 loop
            exit when Out_Index > Result'Last;
            Result (Out_Index) := Read_Rate_Byte (State_Item, Rate_Index);
            Out_Index := Out_Index + 1;
         end loop;
         if Out_Index <= Result'Last then
            Permute (State_Item);
         end if;
      end loop;

      return Result;
   end Sponge;

   function SHA3_256
     (Data : Ada.Streams.Stream_Element_Array)
      return SHA3_256_Digest
   is
      Bytes_Value : constant Ada.Streams.Stream_Element_Array :=
        Sponge (Data, 136, 16#06#, 32);
      Result      : SHA3_256_Digest := [others => 0];
   begin
      for Index_Value in Result'Range loop
         Result (Index_Value) := Bytes_Value
           (Ada.Streams.Stream_Element_Offset (Index_Value));
      end loop;
      return Result;
   end SHA3_256;

   function SHA3_512
     (Data : Ada.Streams.Stream_Element_Array)
      return SHA3_512_Digest
   is
      Bytes_Value : constant Ada.Streams.Stream_Element_Array :=
        Sponge (Data, 72, 16#06#, 64);
      Result      : SHA3_512_Digest := [others => 0];
   begin
      for Index_Value in Result'Range loop
         Result (Index_Value) := Bytes_Value
           (Ada.Streams.Stream_Element_Offset (Index_Value));
      end loop;
      return Result;
   end SHA3_512;

   function SHAKE128
     (Data          : Ada.Streams.Stream_Element_Array;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      return Sponge (Data, 168, 16#1F#, Output_Length);
   end SHAKE128;

   function SHAKE256
     (Data          : Ada.Streams.Stream_Element_Array;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      return Sponge (Data, 136, 16#1F#, Output_Length);
   end SHAKE256;

end CryptoLib.SHA3;
