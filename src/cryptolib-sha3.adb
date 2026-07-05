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

   procedure Permute (State_Item : in out Keccak_State) is
      C_Data : array (Natural range 0 .. 4) of Word64 := [others => 0];
      D_Data : array (Natural range 0 .. 4) of Word64 := [others => 0];
      B_Data : Keccak_State := [others => 0];
   begin
      for Round_Value in Round_Index loop
         for X_Value in 0 .. 4 loop
            C_Data (X_Value) := State_Item (Index_Of (X_Value, 0))
              xor State_Item (Index_Of (X_Value, 1))
              xor State_Item (Index_Of (X_Value, 2))
              xor State_Item (Index_Of (X_Value, 3))
              xor State_Item (Index_Of (X_Value, 4));
         end loop;

         for X_Value in 0 .. 4 loop
            D_Data (X_Value) := C_Data ((X_Value + 4) mod 5)
              xor Rotate_Left_64 (C_Data ((X_Value + 1) mod 5), 1);
         end loop;

         for X_Value in 0 .. 4 loop
            for Y_Value in 0 .. 4 loop
               State_Item (Index_Of (X_Value, Y_Value)) :=
                 State_Item (Index_Of (X_Value, Y_Value)) xor D_Data (X_Value);
            end loop;
         end loop;

         for X_Value in 0 .. 4 loop
            for Y_Value in 0 .. 4 loop
               B_Data (Index_Of (Y_Value, (2 * X_Value + 3 * Y_Value) mod 5)) :=
                 Rotate_Left_64
                   (State_Item (Index_Of (X_Value, Y_Value)),
                    Rho (Index_Of (X_Value, Y_Value)));
            end loop;
         end loop;

         for X_Value in 0 .. 4 loop
            for Y_Value in 0 .. 4 loop
               State_Item (Index_Of (X_Value, Y_Value)) :=
                 B_Data (Index_Of (X_Value, Y_Value)) xor
                 ((not B_Data (Index_Of ((X_Value + 1) mod 5, Y_Value)))
                  and B_Data (Index_Of ((X_Value + 2) mod 5, Y_Value)));
            end loop;
         end loop;

         State_Item (0) := State_Item (0) xor RC (Round_Value);
      end loop;
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
      for Data_Index in Data'Range loop
         Xor_Rate_Byte (State_Item, Position, Byte (Data (Data_Index)));
         Position := Position + 1;
         if Position = Rate_Bytes then
            Permute (State_Item);
            Position := 0;
         end if;
      end loop;

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
