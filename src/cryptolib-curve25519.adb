with Interfaces;
with CryptoLib.Secure_Wipe;
with System;

package body CryptoLib.Curve25519 is
   use Ada.Streams;
   use CryptoLib.Errors;
   use type Interfaces.Unsigned_64;

   subtype Limb_Index is Natural range 0 .. 15;
   type Field_Element is array (Limb_Index) of Long_Long_Integer;

   Base_Value : constant Long_Long_Integer := 65_536;

   P_Limbs : constant Field_Element :=
     [0 => 16#FFED#, 1 .. 14 => 16#FFFF#, 15 => 16#7FFF#];

   A24_Value : constant Field_Element := [0 => 121_665, others => 0];

   Base_Point : constant Public_Key := [1 => 9, others => 0];

   procedure Carry25519 (Item : in out Field_Element) is
      Carry_Value : Long_Long_Integer;
   begin
      for Pass_Value in 1 .. 2 loop
         for Index_Value in Limb_Index loop
            Item (Index_Value) := Item (Index_Value) + Base_Value;
            Carry_Value := Item (Index_Value) / Base_Value;
            if Index_Value < 15 then
               Item (Index_Value + 1) :=
                 Item (Index_Value + 1) + Carry_Value - 1;
            else
               Item (0) := Item (0) + 38 * (Carry_Value - 1);
            end if;
            Item (Index_Value) :=
              Item (Index_Value) - Carry_Value * Base_Value;
         end loop;
      end loop;
   end Carry25519;

   function Subtract_P_Borrow
     (Item : Field_Element; Result_Item : out Field_Element) return Natural
   is
      Borrow_Value : Long_Long_Integer := 0;
      Temp_Value   : Long_Long_Integer;
   begin
      --  Fixed-limb subtraction of p from Item.  Each limb is first lifted by
      --  the radix, so the output limb and next borrow are derived with
      --  division/modulo instead of a data-dependent repair branch.
      for Index_Value in Limb_Index loop
         Temp_Value :=
           Item (Index_Value)
           + Base_Value
           - P_Limbs (Index_Value)
           - Borrow_Value;
         Result_Item (Index_Value) := Temp_Value mod Base_Value;
         Borrow_Value := 1 - (Temp_Value / Base_Value);
      end loop;
      return Natural (Borrow_Value);
   end Subtract_P_Borrow;

   function Is_Zero_Field (Item : Field_Element) return Boolean is
      Work_Item        : Field_Element := Item;
      Accumulator_Item : Interfaces.Unsigned_64 := 0;
   begin
      Carry25519 (Work_Item);
      for Index_Value in Limb_Index loop
         Accumulator_Item :=
           Accumulator_Item
           or Interfaces.Unsigned_64 (Work_Item (Index_Value));
      end loop;
      return Accumulator_Item = 0;
   end Is_Zero_Field;

   procedure Select_Field
     (Result_Item : out Field_Element;
      False_Item  : Field_Element;
      True_Item   : Field_Element;
      Select_Bit  : Natural)
   is
      Select_Mask : constant Interfaces.Unsigned_64 :=
        Interfaces.Unsigned_64 (0) - Interfaces.Unsigned_64 (Select_Bit mod 2);
      False_Value : Interfaces.Unsigned_64;
      True_Value  : Interfaces.Unsigned_64;
   begin
      for Index_Value in Limb_Index loop
         False_Value := Interfaces.Unsigned_64 (False_Item (Index_Value));
         True_Value := Interfaces.Unsigned_64 (True_Item (Index_Value));
         Result_Item (Index_Value) :=
           Long_Long_Integer
             ((False_Value and not Select_Mask)
              or (True_Value and Select_Mask));
      end loop;
   end Select_Field;

   procedure Normalize_Final (Item : in out Field_Element) is
      Candidate_Item : Field_Element;
      Selected_Item  : Field_Element;
      Borrow_Value   : Natural;
      Select_Bit     : Natural;
   begin
      Carry25519 (Item);
      Carry25519 (Item);

      for Pass_Value in 1 .. 2 loop
         Borrow_Value := Subtract_P_Borrow (Item, Candidate_Item);
         Select_Bit := 1 - Borrow_Value;
         Select_Field (Selected_Item, Item, Candidate_Item, Select_Bit);
         Item := Selected_Item;
      end loop;

      Carry25519 (Item);
   end Normalize_Final;

   procedure Add_Field
     (Result_Item : out Field_Element;
      Left_Item   : Field_Element;
      Right_Item  : Field_Element) is
   begin
      for Index_Value in Limb_Index loop
         Result_Item (Index_Value) :=
           Left_Item (Index_Value) + Right_Item (Index_Value);
      end loop;
   end Add_Field;

   procedure Sub_Field
     (Result_Item : out Field_Element;
      Left_Item   : Field_Element;
      Right_Item  : Field_Element) is
   begin
      --  Keep subtraction non-negative by adding 4p before subtracting.
      --  This avoids data-dependent repair branches in the ladder body.
      for Index_Value in Limb_Index loop
         Result_Item (Index_Value) :=
           Left_Item (Index_Value)
           + 4 * P_Limbs (Index_Value)
           - Right_Item (Index_Value);
      end loop;
   end Sub_Field;

   procedure Square_Field
     (Result_Item : out Field_Element; Item : Field_Element);

   procedure Multiply_Field
     (Result_Item : out Field_Element;
      Left_Item   : Field_Element;
      Right_Item  : Field_Element)
   is
      Work_Product : array (Natural range 0 .. 30) of Long_Long_Integer :=
        [others => 0];
      Reduced_Item : Field_Element := [others => 0];
   begin
      for Left_Index in Limb_Index loop
         for Right_Index in Limb_Index loop
            Work_Product (Left_Index + Right_Index) :=
              Work_Product (Left_Index + Right_Index)
              + Left_Item (Left_Index) * Right_Item (Right_Index);
         end loop;
      end loop;

      for Index_Value in 0 .. 14 loop
         Work_Product (Index_Value) :=
           Work_Product (Index_Value) + 38 * Work_Product (Index_Value + 16);
      end loop;

      for Index_Value in Limb_Index loop
         Reduced_Item (Index_Value) := Work_Product (Index_Value);
      end loop;

      Carry25519 (Reduced_Item);
      Carry25519 (Reduced_Item);
      Result_Item := Reduced_Item;
   end Multiply_Field;

   procedure Square_Field
     (Result_Item : out Field_Element; Item : Field_Element) is
   begin
      Multiply_Field (Result_Item, Item, Item);
   end Square_Field;

   procedure Conditional_Swap
     (Left_Item  : in out Field_Element;
      Right_Item : in out Field_Element;
      Swap_Bit   : Natural)
   is
      Swap_Mask       : constant Interfaces.Unsigned_64 :=
        Interfaces.Unsigned_64 (0) - Interfaces.Unsigned_64 (Swap_Bit mod 2);
      Temporary_Value : Interfaces.Unsigned_64;
      Left_Value      : Interfaces.Unsigned_64;
      Right_Value     : Interfaces.Unsigned_64;
   begin
      for Index_Value in Limb_Index loop
         Left_Value := Interfaces.Unsigned_64 (Left_Item (Index_Value));
         Right_Value := Interfaces.Unsigned_64 (Right_Item (Index_Value));
         Temporary_Value := (Left_Value xor Right_Value) and Swap_Mask;
         Left_Item (Index_Value) :=
           Long_Long_Integer (Left_Value xor Temporary_Value);
         Right_Item (Index_Value) :=
           Long_Long_Integer (Right_Value xor Temporary_Value);
      end loop;
   end Conditional_Swap;

   procedure Unpack_Field (Result_Item : out Field_Element; Value : Public_Key)
     with SPARK_Mode => On
   is
   begin
      for Index_Value in Limb_Index loop
         Result_Item (Index_Value) :=
           Long_Long_Integer (Value (Public_Key_Index (2 * Index_Value + 1)))
           + 256
             * Long_Long_Integer
                 (Value (Public_Key_Index (2 * Index_Value + 2)));
      end loop;
      Result_Item (15) := Result_Item (15) mod 32_768;
   end Unpack_Field;

   procedure Pack_Field (Result_Item : out Public_Key; Item : Field_Element) is
      Work_Item : Field_Element := Item;
   begin
      Normalize_Final (Work_Item);
      for Index_Value in Limb_Index loop
         Result_Item (Public_Key_Index (2 * Index_Value + 1)) :=
           Stream_Element (Work_Item (Index_Value) mod 256);
         Result_Item (Public_Key_Index (2 * Index_Value + 2)) :=
           Stream_Element ((Work_Item (Index_Value) / 256) mod 256);
      end loop;
   end Pack_Field;

   function Scalar_Bit
     (Scalar_Item : Public_Key; Bit_Index : Natural) return Natural
     with SPARK_Mode => On,
          Pre => Bit_Index <= 255
   is
      Byte_Index : constant Public_Key_Index :=
        Public_Key_Index (Bit_Index / 8 + 1);
      Bit_Offset : constant Natural := Bit_Index mod 8;
      Byte_Value : constant Natural := Natural (Scalar_Item (Byte_Index));
   begin
      return (Byte_Value / (2 ** Bit_Offset)) mod 2;
   end Scalar_Bit;

   procedure Invert_Field
     (Result_Item : out Field_Element; Item : Field_Element)
   is
      Work_Item : Field_Element := Item;
   begin
      --  Fermat inversion: z^(p - 2), with p - 2 = 2^255 - 21.
      --  This is the fixed-iteration exponentiation used by small
      --  Curve25519 implementations; the skipped multiplications encode
      --  the zero bits of the public exponent and are not secret-dependent.
      for Bit_Index in reverse 0 .. 253 loop
         declare
            Squared_Item : Field_Element;
            Product_Item : Field_Element;
         begin
            Square_Field (Squared_Item, Work_Item);
            Work_Item := Squared_Item;
            if Bit_Index /= 2 and then Bit_Index /= 4 then
               Multiply_Field (Product_Item, Work_Item, Item);
               Work_Item := Product_Item;
            end if;
         end;
      end loop;
      Result_Item := Work_Item;
   end Invert_Field;

   function X25519
     (Scalar_Item : Public_Key;
      U_Item      : Public_Key;
      Result_Item : out Public_Key) return Status
   is
      Clamped_Scalar : Public_Key := Scalar_Item;
      Received_U     : Public_Key := U_Item;
      X1_Value       : Field_Element := [others => 0];
      X2_Value       : Field_Element := [0 => 1, others => 0];
      Z2_Value       : Field_Element := [others => 0];
      X3_Value       : Field_Element := [others => 0];
      Z3_Value       : Field_Element := [0 => 1, others => 0];
      Swap_Value     : Natural := 0;
      A_Value        : Field_Element := [others => 0];
      AA_Value       : Field_Element := [others => 0];
      B_Value        : Field_Element := [others => 0];
      BB_Value       : Field_Element := [others => 0];
      E_Value        : Field_Element := [others => 0];
      C_Value        : Field_Element := [others => 0];
      D_Value        : Field_Element := [others => 0];
      DA_Value       : Field_Element := [others => 0];
      CB_Value       : Field_Element := [others => 0];
      Temporary_1    : Field_Element := [others => 0];
      Temporary_2    : Field_Element := [others => 0];
      Inverse_Value  : Field_Element := [others => 0];
      Bit_Value      : Natural;
      Any_Nonzero    : Boolean := False;

      --  Scrub the private scalar and all Montgomery-ladder state (secret,
      --  scalar-dependent).  Wipe via each object's own 'Address so the store
      --  can't be elided.  The shared secret leaves only via Result_Item.
      procedure Scrub_Secrets is
         use System;
      begin
         Secure_Wipe.Wipe (Clamped_Scalar'Address, Clamped_Scalar'Size / Storage_Unit);
         Secure_Wipe.Wipe (Received_U'Address, Received_U'Size / Storage_Unit);
         Secure_Wipe.Wipe (X1_Value'Address, X1_Value'Size / Storage_Unit);
         Secure_Wipe.Wipe (X2_Value'Address, X2_Value'Size / Storage_Unit);
         Secure_Wipe.Wipe (Z2_Value'Address, Z2_Value'Size / Storage_Unit);
         Secure_Wipe.Wipe (X3_Value'Address, X3_Value'Size / Storage_Unit);
         Secure_Wipe.Wipe (Z3_Value'Address, Z3_Value'Size / Storage_Unit);
         Secure_Wipe.Wipe (A_Value'Address, A_Value'Size / Storage_Unit);
         Secure_Wipe.Wipe (AA_Value'Address, AA_Value'Size / Storage_Unit);
         Secure_Wipe.Wipe (B_Value'Address, B_Value'Size / Storage_Unit);
         Secure_Wipe.Wipe (BB_Value'Address, BB_Value'Size / Storage_Unit);
         Secure_Wipe.Wipe (E_Value'Address, E_Value'Size / Storage_Unit);
         Secure_Wipe.Wipe (C_Value'Address, C_Value'Size / Storage_Unit);
         Secure_Wipe.Wipe (D_Value'Address, D_Value'Size / Storage_Unit);
         Secure_Wipe.Wipe (DA_Value'Address, DA_Value'Size / Storage_Unit);
         Secure_Wipe.Wipe (CB_Value'Address, CB_Value'Size / Storage_Unit);
         Secure_Wipe.Wipe (Temporary_1'Address, Temporary_1'Size / Storage_Unit);
         Secure_Wipe.Wipe (Temporary_2'Address, Temporary_2'Size / Storage_Unit);
         Secure_Wipe.Wipe (Inverse_Value'Address, Inverse_Value'Size / Storage_Unit);
      end Scrub_Secrets;
   begin
      Result_Item := [others => 0];

      --  RFC 7748 scalar clamping for X25519.
      Clamped_Scalar (1) := Clamped_Scalar (1) and Stream_Element'(16#F8#);
      Clamped_Scalar (32) :=
        (Clamped_Scalar (32) and Stream_Element'(16#7F#))
        or Stream_Element'(16#40#);

      --  RFC 7748 section 5 requires X25519 scalar multiplication to mask
      --  the most-significant bit of the received u-coordinate.  This is
      --  deliberately local to arithmetic: SSH exchange hashing still uses
      --  the exact Q_C/Q_S bytes received on the wire.
      Received_U (32) := Received_U (32) and Stream_Element'(16#7F#);
      Unpack_Field (X1_Value, Received_U);
      X3_Value := X1_Value;

      for Bit_Index in reverse 0 .. 254 loop
         Bit_Value := Scalar_Bit (Clamped_Scalar, Bit_Index);
         Swap_Value := (Swap_Value + Bit_Value) mod 2;
         Conditional_Swap (X2_Value, X3_Value, Swap_Value);
         Conditional_Swap (Z2_Value, Z3_Value, Swap_Value);
         Swap_Value := Bit_Value;

         Add_Field (A_Value, X2_Value, Z2_Value);
         Square_Field (AA_Value, A_Value);
         Sub_Field (B_Value, X2_Value, Z2_Value);
         Square_Field (BB_Value, B_Value);
         Sub_Field (E_Value, AA_Value, BB_Value);
         Add_Field (C_Value, X3_Value, Z3_Value);
         Sub_Field (D_Value, X3_Value, Z3_Value);
         Multiply_Field (DA_Value, D_Value, A_Value);
         Multiply_Field (CB_Value, C_Value, B_Value);

         Add_Field (Temporary_1, DA_Value, CB_Value);
         Square_Field (X3_Value, Temporary_1);
         Sub_Field (Temporary_1, DA_Value, CB_Value);
         Square_Field (Temporary_2, Temporary_1);
         Multiply_Field (Z3_Value, X1_Value, Temporary_2);
         Multiply_Field (X2_Value, AA_Value, BB_Value);
         Multiply_Field (Temporary_1, A24_Value, E_Value);
         Add_Field (Temporary_2, AA_Value, Temporary_1);
         Multiply_Field (Z2_Value, E_Value, Temporary_2);
      end loop;

      Conditional_Swap (X2_Value, X3_Value, Swap_Value);
      Conditional_Swap (Z2_Value, Z3_Value, Swap_Value);

      Normalize_Final (Z2_Value);
      if Is_Zero_Field (Z2_Value) then
         Result_Item := [others => 0];
         Scrub_Secrets;
         return Handshake_Failed;
      end if;

      Invert_Field (Inverse_Value, Z2_Value);
      Multiply_Field (Temporary_1, X2_Value, Inverse_Value);
      Pack_Field (Result_Item, Temporary_1);

      declare
         Nonzero_Accumulator : Interfaces.Unsigned_64 := 0;
      begin
         for Byte_Value of Result_Item loop
            Nonzero_Accumulator :=
              Nonzero_Accumulator or Interfaces.Unsigned_64 (Byte_Value);
         end loop;
         Any_Nonzero := Nonzero_Accumulator /= 0;
      end;

      if not Any_Nonzero then
         Result_Item := [others => 0];
         Scrub_Secrets;
         return Handshake_Failed;
      end if;

      Scrub_Secrets;
      return Ok;
   exception
      when others =>
         Result_Item := [others => 0];
         Scrub_Secrets;
         return Internal_Error;
   end X25519;

   procedure Clear (Private_Item : out Private_Key) is
   begin
      Private_Item.Data := [others => 0];
      Private_Item.Valid := False;
   exception
      when others =>
         null;
   end Clear;

   procedure Clear_Stream_Array (Item : out Stream_Element_Array)
     with SPARK_Mode => On
   is
   begin
      for Index_Value in Item'Range loop
         Item (Index_Value) := 0;
      end loop;
   end Clear_Stream_Array;

   procedure Clear (Public_Item : out Public_Key) is
   begin
      Public_Item := [others => 0];
   exception
      when others =>
         null;
   end Clear;

   function Generate_Keypair
     (Source_Item  : in out CryptoLib.Random.Random_Source;
      Private_Item : out Private_Key;
      Public_Item  : out Public_Key) return CryptoLib.Errors.Status
   is
      Status_Value : Status;
   begin
      Clear (Private_Item);
      Clear (Public_Item);

      declare
         Random_Data : Stream_Element_Array (1 .. 32);
      begin
         Status_Value := CryptoLib.Random.Fill (Source_Item, Random_Data);
         if Status_Value /= Ok then
            Clear (Private_Item);
            return Status_Value;
         end if;

         for Offset_Value in 0 .. 31 loop
            Private_Item.Data (Public_Key_Index (Offset_Value + 1)) :=
              Random_Data
                (Random_Data'First + Stream_Element_Offset (Offset_Value));
         end loop;

         Clear_Stream_Array (Random_Data);
      end;

      Status_Value := X25519 (Private_Item.Data, Base_Point, Public_Item);
      if Status_Value /= Ok then
         Clear (Private_Item);
         Clear (Public_Item);
         return Status_Value;
      end if;

      Private_Item.Valid := True;
      return Ok;
   exception
      when others =>
         Clear (Private_Item);
         Clear (Public_Item);
         return Internal_Error;
   end Generate_Keypair;

   function Shared_Secret
     (Private_Item : Private_Key;
      Peer_Public  : Public_Key;
      Secret_Item  : out Public_Key) return CryptoLib.Errors.Status is
   begin
      Clear (Secret_Item);
      if not Private_Item.Valid then
         return Handshake_Failed;
      end if;

      return X25519 (Private_Item.Data, Peer_Public, Secret_Item);
   exception
      when others =>
         Clear (Secret_Item);
         return Internal_Error;
   end Shared_Secret;

   function Compute_Raw
     (Scalar_Item : Public_Key;
      Peer_Public : Public_Key;
      Secret_Item : out Public_Key) return CryptoLib.Errors.Status is
   begin
      return X25519 (Scalar_Item, Peer_Public, Secret_Item);
   exception
      when others =>
         Clear (Secret_Item);
         return Internal_Error;
   end Compute_Raw;
end CryptoLib.Curve25519;
