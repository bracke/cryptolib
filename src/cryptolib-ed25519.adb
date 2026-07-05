with CryptoLib.Hashes;
with CryptoLib.Secure_Wipe;
with System;

package body CryptoLib.Ed25519 is
   use Ada.Streams;
   use CryptoLib.Errors;

   subtype Byte_Value is Natural range 0 .. 255;
   subtype Fe_Index is Natural range 0 .. 31;
   type Field_Element is array (Fe_Index) of Byte_Value;

   type Point is record
      X : Field_Element := [others => 0];
      Y : Field_Element := [0 => 1, others => 0];
   end record;

   type Extended_Point is record
      X : Field_Element := [others => 0];
      Y : Field_Element := [0 => 1, others => 0];
      Z : Field_Element := [0 => 1, others => 0];
      T : Field_Element := [others => 0];
   end record;

   P_Value : constant Field_Element :=
     [0 => 16#ED#, 1 .. 30 => 16#FF#, 31 => 16#7F#];

   P_Minus_2 : constant Field_Element :=
     [0 => 16#EB#, 1 .. 30 => 16#FF#, 31 => 16#7F#];

   Sqrt_Exponent : constant Field_Element :=
     [0 => 16#FE#, 1 .. 30 => 16#FF#, 31 => 16#0F#];

   D_Value : constant Field_Element :=
     [16#A3#,
      16#78#,
      16#59#,
      16#13#,
      16#CA#,
      16#4D#,
      16#EB#,
      16#75#,
      16#AB#,
      16#D8#,
      16#41#,
      16#41#,
      16#4D#,
      16#0A#,
      16#70#,
      16#00#,
      16#98#,
      16#E8#,
      16#79#,
      16#77#,
      16#79#,
      16#40#,
      16#C7#,
      16#8C#,
      16#73#,
      16#FE#,
      16#6F#,
      16#2B#,
      16#EE#,
      16#6C#,
      16#03#,
      16#52#];

   Sqrt_Minus_One : constant Field_Element :=
     [16#B0#,
      16#A0#,
      16#0E#,
      16#4A#,
      16#27#,
      16#1B#,
      16#EE#,
      16#C4#,
      16#78#,
      16#E4#,
      16#2F#,
      16#AD#,
      16#06#,
      16#18#,
      16#43#,
      16#2F#,
      16#A7#,
      16#D7#,
      16#FB#,
      16#3D#,
      16#99#,
      16#00#,
      16#4D#,
      16#2B#,
      16#0B#,
      16#DF#,
      16#C1#,
      16#4F#,
      16#80#,
      16#24#,
      16#83#,
      16#2B#];

   L_Value : constant Field_Element :=
     [16#ED#,
      16#D3#,
      16#F5#,
      16#5C#,
      16#1A#,
      16#63#,
      16#12#,
      16#58#,
      16#D6#,
      16#9C#,
      16#F7#,
      16#A2#,
      16#DE#,
      16#F9#,
      16#DE#,
      16#14#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#10#];

   function Compare
     (Left_Item : Field_Element; Right_Item : Field_Element) return Integer
     with SPARK_Mode => On
   is
   begin
      for Index_Value in reverse Fe_Index loop
         if Left_Item (Index_Value) < Right_Item (Index_Value) then
            return -1;
         elsif Left_Item (Index_Value) > Right_Item (Index_Value) then
            return 1;
         end if;
      end loop;
      return 0;
   end Compare;

   function Equal
     (Left_Item : Field_Element; Right_Item : Field_Element) return Boolean
     with SPARK_Mode => On
   is
   begin
      return Compare (Left_Item, Right_Item) = 0;
   end Equal;

   function Select_Field
     (False_Item : Field_Element; True_Item : Field_Element; Choice : Natural)
      return Field_Element
     with SPARK_Mode => On;

   procedure Subtract_In_Place
     (Left_Item : in out Field_Element; Right_Item : Field_Element)
   is
      Borrow_Value : Integer := 0;
      Work_Value   : Integer;
   begin
      for Index_Value in Fe_Index loop
         --  Left-Right-Borrow lies in [-256,255]; +256 maps it to [0,511], so
         --  the byte result and next borrow come out without a branch.
         Work_Value :=
           Integer (Left_Item (Index_Value))
           - Integer (Right_Item (Index_Value))
           - Borrow_Value + 256;
         Borrow_Value := 1 - Work_Value / 256;
         Left_Item (Index_Value) := Byte_Value (Work_Value mod 256);
      end loop;
   end Subtract_In_Place;

   function Subtract_With_Borrow
     (Left_Item   : Field_Element;
      Right_Item  : Field_Element;
      Result_Item : out Field_Element) return Natural
   is
      Borrow_Value : Integer := 0;
      Work_Value   : Integer;
   begin
      for Index_Value in Fe_Index loop
         Work_Value :=
           Integer (Left_Item (Index_Value))
           - Integer (Right_Item (Index_Value))
           - Borrow_Value + 256;
         Borrow_Value := 1 - Work_Value / 256;
         Result_Item (Index_Value) := Byte_Value (Work_Value mod 256);
      end loop;
      return Natural (Borrow_Value);
   end Subtract_With_Borrow;

   procedure Normalize (Item : in out Field_Element) is
      Candidate_Value : Field_Element := [others => 0];
      Borrow_Value    : Natural;
      Use_Candidate   : Natural;
   begin
      --  Ed25519 field values are kept close to canonical by Add_Mod and
      --  Mul_Mod.  Use fixed candidate-and-select reductions instead of a
      --  data-dependent while loop so private field values do not control
      --  the number of final-reduction iterations.
      for Pass_Index in 1 .. 2 loop
         Borrow_Value := Subtract_With_Borrow (Item, P_Value, Candidate_Value);
         Use_Candidate := 1 - Borrow_Value;
         Item := Select_Field (Item, Candidate_Value, Use_Candidate);
      end loop;
   end Normalize;

   function Add_Mod
     (Left_Item : Field_Element; Right_Item : Field_Element)
      return Field_Element
   is
      Result_Value : Field_Element;
      Carry_Value  : Natural := 0;
      Work_Value   : Natural;
   begin
      for Index_Value in Fe_Index loop
         Work_Value :=
           Left_Item (Index_Value) + Right_Item (Index_Value) + Carry_Value;
         Result_Value (Index_Value) := Work_Value mod 256;
         Carry_Value := Work_Value / 256;
      end loop;
      --  The field modulus is 2**255 - 19.  A carry from bit 256 is 38 mod p,
      --  and bit 255 in the top byte is 19 mod p.  Fold both unconditionally
      --  (each contributes 0 when absent), then let the constant-time Normalize
      --  do the final reduction -- no data-dependent branch or recursion.
      declare
         Top_Bit : constant Natural := Result_Value (31) / 128;
      begin
         Result_Value (31) := Result_Value (31) mod 128;
         Carry_Value := 38 * Carry_Value + 19 * Top_Bit;
      end;
      for Index_Value in Fe_Index loop
         Work_Value := Natural (Result_Value (Index_Value)) + Carry_Value;
         Result_Value (Index_Value) := Work_Value mod 256;
         Carry_Value := Work_Value / 256;
      end loop;
      Normalize (Result_Value);
      return Result_Value;
   end Add_Mod;

   function Sub_Mod
     (Left_Item : Field_Element; Right_Item : Field_Element)
      return Field_Element
   is
      Result_Value : Field_Element;
      Diff_Value   : Field_Element;
      Plus_P_Value : Field_Element;
      Borrow_Value : Natural;
      Carry_Value  : Natural := 0;
      Work_Value   : Natural;
   begin
      --  Diff = Left - Right (mod 2**256); Borrow = 1 exactly when Left < Right.
      Borrow_Value := Subtract_With_Borrow (Left_Item, Right_Item, Diff_Value);
      --  Plus_P = (Diff + p) mod 2**256, which equals Left - Right + p when a
      --  borrow occurred.  Selecting on the borrow avoids the Compare branch.
      for Index_Value in Fe_Index loop
         Work_Value :=
           Natural (Diff_Value (Index_Value)) + Natural (P_Value (Index_Value))
           + Carry_Value;
         Plus_P_Value (Index_Value) := Byte_Value (Work_Value mod 256);
         Carry_Value := Work_Value / 256;
      end loop;
      Result_Value := Select_Field (Diff_Value, Plus_P_Value, Borrow_Value);
      Normalize (Result_Value);
      return Result_Value;
   end Sub_Mod;

   function Get_Bit_Value
     (Item : Field_Element; Bit_Index : Natural) return Natural
     with SPARK_Mode => On
   is
      Byte_Index : constant Natural := Bit_Index / 8;
      Bit_Offset : constant Natural := Bit_Index mod 8;
   begin
      if Byte_Index > 31 then
         return 0;
      end if;
      return (Item (Byte_Index) / (2 ** Bit_Offset)) mod 2;
   end Get_Bit_Value;

   function Select_Field
     (False_Item : Field_Element; True_Item : Field_Element; Choice : Natural)
      return Field_Element
     with SPARK_Mode => On
   is
      Choice_Value : constant Natural := Choice mod 2;
      Other_Value  : constant Natural := 1 - Choice_Value;
      Result_Value : Field_Element;
   begin
      for Index_Value in Fe_Index loop
         Result_Value (Index_Value) :=
           Byte_Value
             (Natural (False_Item (Index_Value)) * Other_Value
              + Natural (True_Item (Index_Value)) * Choice_Value);
      end loop;
      return Result_Value;
   end Select_Field;

   function Double_Mod (Item : Field_Element) return Field_Element is
   begin
      return Add_Mod (Item, Item);
   end Double_Mod;

   function Mul_Mod
     (Left_Item : Field_Element; Right_Item : Field_Element)
      return Field_Element
   is
      type Wide_Array is array (Natural range 0 .. 63) of Long_Long_Integer;
      Work_Value   : Wide_Array := [others => 0];
      Carry_Value  : Long_Long_Integer;
      Fold_Value   : Long_Long_Integer;
      Result_Value : Field_Element := [others => 0];
   begin
      for Left_Index in Fe_Index loop
         for Right_Index in Fe_Index loop
            Work_Value (Left_Index + Right_Index) :=
              Work_Value (Left_Index + Right_Index)
              + Long_Long_Integer (Left_Item (Left_Index))
                * Long_Long_Integer (Right_Item (Right_Index));
         end loop;
      end loop;

      for Index_Value in 32 .. 63 loop
         Work_Value (Index_Value - 32) :=
           Work_Value (Index_Value - 32) + 38 * Work_Value (Index_Value);
         Work_Value (Index_Value) := 0;
      end loop;

      for Pass_Index in 1 .. 3 loop
         Carry_Value := 0;
         for Index_Value in 0 .. 31 loop
            Work_Value (Index_Value) := Work_Value (Index_Value) + Carry_Value;
            Carry_Value := Work_Value (Index_Value) / 256;
            Work_Value (Index_Value) := Work_Value (Index_Value) mod 256;
         end loop;

         if Carry_Value /= 0 then
            Work_Value (0) := Work_Value (0) + 38 * Carry_Value;
         end if;

         Fold_Value := Work_Value (31) / 128;
         if Fold_Value /= 0 then
            Work_Value (31) := Work_Value (31) mod 128;
            Work_Value (0) := Work_Value (0) + 19 * Fold_Value;
         end if;
      end loop;

      for Index_Value in Fe_Index loop
         Result_Value (Index_Value) := Byte_Value (Work_Value (Index_Value));
      end loop;
      Normalize (Result_Value);
      return Result_Value;
   end Mul_Mod;

   function Square_Mod (Item : Field_Element) return Field_Element is
   begin
      return Mul_Mod (Item, Item);
   end Square_Mod;

   function Pow_Mod
     (Base_Item : Field_Element; Exponent_Item : Field_Element)
      return Field_Element
   is
      Result_Value : Field_Element := [0 => 1, others => 0];
      Current_Base : Field_Element := Base_Item;
   begin
      for Bit_Index in 0 .. 254 loop
         declare
            Product_Value : constant Field_Element :=
              Mul_Mod (Result_Value, Current_Base);
            Bit_Value     : constant Natural :=
              Get_Bit_Value (Exponent_Item, Bit_Index);
         begin
            Result_Value :=
              Select_Field (Result_Value, Product_Value, Bit_Value);
            Current_Base := Square_Mod (Current_Base);
         end;
      end loop;
      return Result_Value;
   end Pow_Mod;

   function Inv_Mod (Item : Field_Element) return Field_Element is
   begin
      return Pow_Mod (Item, P_Minus_2);
   end Inv_Mod;

   function From_Stream
     (Data : Stream_Element_Array; Offset : Stream_Element_Offset)
      return Field_Element
   is
      Result_Value : Field_Element := [others => 0];
   begin
      for Index_Value in Fe_Index loop
         Result_Value (Index_Value) :=
           Natural (Data (Offset + Stream_Element_Offset (Index_Value)));
      end loop;
      return Result_Value;
   end From_Stream;

   function Scalar_Less_Than_L (Scalar_Bytes : Field_Element) return Boolean
     with SPARK_Mode => On
   is
   begin
      return Compare (Scalar_Bytes, L_Value) < 0;
   end Scalar_Less_Than_L;

   function Decode_Point
     (Encoded_Data : Stream_Element_Array; Item : out Point) return Status;

   function Point_Equal (Left_Item : Point; Right_Item : Point) return Boolean
   is
      Left_X  : Field_Element := Left_Item.X;
      Left_Y  : Field_Element := Left_Item.Y;
      Right_X : Field_Element := Right_Item.X;
      Right_Y : Field_Element := Right_Item.Y;
   begin
      Normalize (Left_X);
      Normalize (Left_Y);
      Normalize (Right_X);
      Normalize (Right_Y);
      return Equal (Left_X, Right_X) and then Equal (Left_Y, Right_Y);
   end Point_Equal;

   function To_Extended (Item : Point) return Extended_Point is
   begin
      return
        (X => Item.X,
         Y => Item.Y,
         Z => [0 => 1, others => 0],
         T => Mul_Mod (Item.X, Item.Y));
   end To_Extended;

   function To_Affine (Item : Extended_Point) return Point is
      Z_Inv       : constant Field_Element := Inv_Mod (Item.Z);
      Result_Item : Point;
   begin
      Result_Item.X := Mul_Mod (Item.X, Z_Inv);
      Result_Item.Y := Mul_Mod (Item.Y, Z_Inv);
      return Result_Item;
   end To_Affine;

   function Add_Extended
     (Left_Item : Extended_Point; Right_Item : Extended_Point)
      return Extended_Point
   is
      A_Value  : constant Field_Element :=
        Mul_Mod
          (Sub_Mod (Left_Item.Y, Left_Item.X),
           Sub_Mod (Right_Item.Y, Right_Item.X));
      B_Value  : constant Field_Element :=
        Mul_Mod
          (Add_Mod (Left_Item.Y, Left_Item.X),
           Add_Mod (Right_Item.Y, Right_Item.X));
      C_Value  : constant Field_Element :=
        Double_Mod (Mul_Mod (D_Value, Mul_Mod (Left_Item.T, Right_Item.T)));
      D2_Value : constant Field_Element :=
        Double_Mod (Mul_Mod (Left_Item.Z, Right_Item.Z));
      E_Value  : constant Field_Element := Sub_Mod (B_Value, A_Value);
      F_Value  : constant Field_Element := Sub_Mod (D2_Value, C_Value);
      G_Value  : constant Field_Element := Add_Mod (D2_Value, C_Value);
      H_Value  : constant Field_Element := Add_Mod (B_Value, A_Value);
   begin
      return
        (X => Mul_Mod (E_Value, F_Value),
         Y => Mul_Mod (G_Value, H_Value),
         Z => Mul_Mod (F_Value, G_Value),
         T => Mul_Mod (E_Value, H_Value));
   end Add_Extended;

   function Add_Point (Left_Item : Point; Right_Item : Point) return Point is
   begin
      return
        To_Affine
          (Add_Extended (To_Extended (Left_Item), To_Extended (Right_Item)));
   end Add_Point;

   --  Branchless per-coordinate select of one Extended_Point.
   function Select_Extended
     (False_Item : Extended_Point; True_Item : Extended_Point; Choice : Natural)
      return Extended_Point
   is
   begin
      return
        (X => Select_Field (False_Item.X, True_Item.X, Choice),
         Y => Select_Field (False_Item.Y, True_Item.Y, Choice),
         Z => Select_Field (False_Item.Z, True_Item.Z, Choice),
         T => Select_Field (False_Item.T, True_Item.T, Choice));
   end Select_Extended;

   function Scalar_Multiply
     (Scalar_Bytes : Field_Element; Point_Item : Point) return Point
   is
      Result_Value : Extended_Point;
      Addend_Value : Extended_Point := To_Extended (Point_Item);
      Sum_Value    : Extended_Point;
   begin
      --  Constant-time double-and-add-ALWAYS: the add is unconditional and the
      --  secret scalar bit only selects (branchlessly) whether to keep it, so
      --  the point-add pattern no longer leaks the scalar.
      for Bit_Index in 0 .. 255 loop
         Sum_Value := Add_Extended (Result_Value, Addend_Value);
         Result_Value :=
           Select_Extended
             (Result_Value, Sum_Value,
              Get_Bit_Value (Scalar_Bytes, Bit_Index));
         Addend_Value := Add_Extended (Addend_Value, Addend_Value);
      end loop;
      return To_Affine (Result_Value);
   end Scalar_Multiply;

   function Add_Scalar_Mod_L
     (Left_Item : Field_Element; Right_Item : Field_Element)
      return Field_Element
   is
      Result_Value : Field_Element := [others => 0];
      Carry_Value  : Natural := 0;
      Work_Value   : Natural;
   begin
      for Index_Value in Fe_Index loop
         Work_Value :=
           Left_Item (Index_Value) + Right_Item (Index_Value) + Carry_Value;
         Result_Value (Index_Value) := Work_Value mod 256;
         Carry_Value := Work_Value / 256;
      end loop;

      --  Branchless conditional subtract of the group order L: subtract when
      --  Result >= L (Subtract_With_Borrow reports no borrow) or the addition
      --  overflowed 2**256 (Carry_Value = 1).
      declare
         Reduced_Value : Field_Element;
         Borrow_Value  : constant Natural :=
           Subtract_With_Borrow (Result_Value, L_Value, Reduced_Value);
         Use_Reduced   : constant Natural :=
           1 - (1 - Carry_Value) * Borrow_Value;
      begin
         Result_Value :=
           Select_Field (Result_Value, Reduced_Value, Use_Reduced);
      end;
      return Result_Value;
   end Add_Scalar_Mod_L;

   function Double_Scalar_Mod_L (Item : Field_Element) return Field_Element is
   begin
      return Add_Scalar_Mod_L (Item, Item);
   end Double_Scalar_Mod_L;

   function Mul_Scalar_Mod_L
     (Left_Item : Field_Element; Right_Item : Field_Element)
      return Field_Element
   is
      Result_Value : Field_Element := [others => 0];
      Addend_Value : Field_Element := Left_Item;
   begin
      for Bit_Index in 0 .. 255 loop
         Result_Value :=
           Select_Field
             (Result_Value,
              Add_Scalar_Mod_L (Result_Value, Addend_Value),
              Get_Bit_Value (Right_Item, Bit_Index));
         Addend_Value := Double_Scalar_Mod_L (Addend_Value);
      end loop;
      return Result_Value;
   end Mul_Scalar_Mod_L;

   function Reduce_SHA512_Digest_Mod_L
     (Digest_Value : CryptoLib.Hashes.SHA512_Digest) return Field_Element
   is
      Result_Value : Field_Element := [others => 0];
      One_Value    : constant Field_Element := [0 => 1, others => 0];
      Byte_Index   : Natural;
      Bit_Offset   : Natural;
      Bit_Value    : Natural;
   begin
      for Bit_Index_Value in reverse 0 .. 511 loop
         Result_Value := Double_Scalar_Mod_L (Result_Value);
         Byte_Index := Bit_Index_Value / 8 + 1;
         Bit_Offset := Bit_Index_Value mod 8;
         Bit_Value :=
           Natural (Digest_Value (Byte_Index)) / (2 ** Bit_Offset) mod 2;
         Result_Value :=
           Select_Field
             (Result_Value,
              Add_Scalar_Mod_L (Result_Value, One_Value),
              Bit_Value);
      end loop;

      return Result_Value;
   end Reduce_SHA512_Digest_Mod_L;

   function Hash_Reduce_Mod_L
     (R_Bytes          : Stream_Element_Array;
      Public_Key_Bytes : Stream_Element_Array;
      Message_Bytes    : Stream_Element_Array) return Field_Element
   is
      Context_Item : CryptoLib.Hashes.SHA512_Context;
      Digest_Value : CryptoLib.Hashes.SHA512_Digest;
   begin
      CryptoLib.Hashes.Initialize_SHA512 (Context_Item);
      CryptoLib.Hashes.Update (Context_Item, R_Bytes);
      CryptoLib.Hashes.Update (Context_Item, Public_Key_Bytes);
      CryptoLib.Hashes.Update (Context_Item, Message_Bytes);
      Digest_Value := CryptoLib.Hashes.Finalize (Context_Item);

      return Reduce_SHA512_Digest_Mod_L (Digest_Value);
   end Hash_Reduce_Mod_L;

   function Decode_Base_Point return Point is
      Encoded_Base : constant Stream_Element_Array (1 .. 32) :=
        [1 => 16#58#, 2 .. 32 => 16#66#];
      Base_Point   : Point;
      Status_Value : Status;
   begin
      Status_Value := Decode_Point (Encoded_Base, Base_Point);
      if Status_Value /= Ok then
         return (X => [others => 0], Y => [0 => 1, others => 0]);
      end if;
      return Base_Point;
   end Decode_Base_Point;

   function Decode_Point
     (Encoded_Data : Stream_Element_Array; Item : out Point) return Status
   is
      Y_Value     : Field_Element :=
        From_Stream (Encoded_Data, Encoded_Data'First);
      Sign_Bit    : constant Natural := Y_Value (31) / 128;
      Y_Squared   : Field_Element;
      U_Value     : Field_Element;
      V_Value     : Field_Element;
      Candidate   : Field_Element;
      X_Value     : Field_Element;
      Check_Value : Field_Element;
   begin
      if Encoded_Data'Length /= 32 then
         return Handshake_Failed;
      end if;

      Y_Value (31) := Y_Value (31) mod 128;
      if Compare (Y_Value, P_Value) >= 0 then
         return Handshake_Failed;
      end if;

      Y_Squared := Square_Mod (Y_Value);
      U_Value := Sub_Mod (Y_Squared, [0 => 1, others => 0]);
      V_Value := Add_Mod (Mul_Mod (D_Value, Y_Squared), [0 => 1, others => 0]);
      Candidate := Mul_Mod (U_Value, Inv_Mod (V_Value));
      X_Value := Pow_Mod (Candidate, Sqrt_Exponent);
      Check_Value := Square_Mod (X_Value);

      if not Equal (Check_Value, Candidate) then
         X_Value := Mul_Mod (X_Value, Sqrt_Minus_One);
         Check_Value := Square_Mod (X_Value);
         if not Equal (Check_Value, Candidate) then
            return Handshake_Failed;
         end if;
      end if;

      if X_Value (0) mod 2 /= Sign_Bit then
         X_Value := Sub_Mod ([others => 0], X_Value);
      end if;

      Item.X := X_Value;
      Item.Y := Y_Value;
      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Decode_Point;

   function Encode_Point (Item : Point) return Stream_Element_Array is
      X_Value      : Field_Element := Item.X;
      Y_Value      : Field_Element := Item.Y;
      Result_Value : Stream_Element_Array (1 .. 32);
   begin
      Normalize (X_Value);
      Normalize (Y_Value);
      for Index_Value in Fe_Index loop
         Result_Value
           (Result_Value'First + Stream_Element_Offset (Index_Value)) :=
           Stream_Element (Y_Value (Index_Value));
      end loop;
      if X_Value (0) mod 2 /= 0 then
         Result_Value (Result_Value'Last) :=
           Result_Value (Result_Value'Last) or 16#80#;
      end if;
      return Result_Value;
   end Encode_Point;

   function Secret_Scalar_From_Seed
     (Seed_Bytes : Stream_Element_Array; Prefix : out Stream_Element_Array)
      return Field_Element
   is
      Digest_Value : constant CryptoLib.Hashes.SHA512_Digest :=
        CryptoLib.Hashes.SHA512 (Seed_Bytes);
      Result_Value : Field_Element := [others => 0];
   begin
      for Index_Value in Fe_Index loop
         Result_Value (Index_Value) :=
           Natural (Digest_Value (Index_Value + 1));
         Prefix (Prefix'First + Stream_Element_Offset (Index_Value)) :=
           Digest_Value (Index_Value + 33);
      end loop;
      Result_Value (0) := Result_Value (0) - Result_Value (0) mod 8;
      Result_Value (31) := Result_Value (31) mod 64 + 64;
      return Result_Value;
   end Secret_Scalar_From_Seed;

   function Sign
     (Seed_Bytes       : Stream_Element_Array;
      Public_Key_Bytes : Stream_Element_Array;
      Message_Bytes    : Stream_Element_Array;
      Signature_Bytes  : out Stream_Element_Array) return Status
   is
      Prefix_Bytes : Stream_Element_Array (1 .. 32);
      A_Scalar     : Field_Element;
      R_Scalar     : Field_Element;
      H_Scalar     : Field_Element;
      S_Scalar     : Field_Element;
      Base_Point   : Point;
      R_Encoded    : Stream_Element_Array (1 .. 32);
      Context_Item : CryptoLib.Hashes.SHA512_Context;
      Digest_Value : CryptoLib.Hashes.SHA512_Digest;

      procedure Scrub_Secrets is
         use System;
      begin
         Secure_Wipe.Wipe (Prefix_Bytes'Address, Prefix_Bytes'Length);
         Secure_Wipe.Wipe (A_Scalar'Address, A_Scalar'Size / Storage_Unit);
         Secure_Wipe.Wipe (R_Scalar'Address, R_Scalar'Size / Storage_Unit);
         Secure_Wipe.Wipe (H_Scalar'Address, H_Scalar'Size / Storage_Unit);
         Secure_Wipe.Wipe (S_Scalar'Address, S_Scalar'Size / Storage_Unit);
         Secure_Wipe.Wipe
           (Digest_Value'Address, Digest_Value'Size / Storage_Unit);
         Secure_Wipe.Wipe
           (Context_Item'Address, Context_Item'Size / Storage_Unit);
      end Scrub_Secrets;
   begin
      if Seed_Bytes'Length /= 32
        or else Public_Key_Bytes'Length /= Public_Key_Length
        or else Signature_Bytes'Length /= Signature_Length
      then
         Signature_Bytes := [others => 0];
         return Handshake_Failed;
      end if;

      A_Scalar := Secret_Scalar_From_Seed (Seed_Bytes, Prefix_Bytes);
      Base_Point := Decode_Base_Point;

      CryptoLib.Hashes.Initialize_SHA512 (Context_Item);
      CryptoLib.Hashes.Update (Context_Item, Prefix_Bytes);
      CryptoLib.Hashes.Update (Context_Item, Message_Bytes);
      Digest_Value := CryptoLib.Hashes.Finalize (Context_Item);
      R_Scalar := Reduce_SHA512_Digest_Mod_L (Digest_Value);
      R_Encoded := Encode_Point (Scalar_Multiply (R_Scalar, Base_Point));

      H_Scalar :=
        Hash_Reduce_Mod_L (R_Encoded, Public_Key_Bytes, Message_Bytes);
      S_Scalar :=
        Add_Scalar_Mod_L (R_Scalar, Mul_Scalar_Mod_L (H_Scalar, A_Scalar));

      for Index_Value in 0 .. 31 loop
         Signature_Bytes
           (Signature_Bytes'First + Stream_Element_Offset (Index_Value)) :=
           R_Encoded (R_Encoded'First + Stream_Element_Offset (Index_Value));
         Signature_Bytes
           (Signature_Bytes'First
            + 32
            + Stream_Element_Offset (Index_Value)) :=
           Stream_Element (S_Scalar (Index_Value));
      end loop;

      --  Scrub secret material.  Plain "X := [others => 0]" is eliminated as a
      --  dead store at -O3; Secure_Wipe uses volatile stores that survive.
      Scrub_Secrets;
      return Ok;
   exception
      when others =>
         Signature_Bytes := [others => 0];
         Scrub_Secrets;
         return Internal_Error;
   end Sign;

   function Verify
     (Public_Key_Bytes : Stream_Element_Array;
      Signature_Bytes  : Stream_Element_Array;
      Message_Bytes    : Stream_Element_Array) return Status
   is
      Public_Point : Point;
      R_Point      : Point;
      Base_Point   : Point;
      Left_Point   : Point;
      Right_Point  : Point;
      H_Scalar     : Field_Element;
      S_Field      : Field_Element;
      Status_Value : Status;
   begin

      if Public_Key_Bytes'Length /= Public_Key_Length
        or else Signature_Bytes'Length /= Signature_Length
      then
         return Handshake_Failed;
      end if;

      S_Field := From_Stream (Signature_Bytes, Signature_Bytes'First + 32);
      if not Scalar_Less_Than_L (S_Field) then
         return Handshake_Failed;
      end if;

      Status_Value := Decode_Point (Public_Key_Bytes, Public_Point);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Decode_Point
          (Signature_Bytes
             (Signature_Bytes'First .. Signature_Bytes'First + 31),
           R_Point);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      H_Scalar :=
        Hash_Reduce_Mod_L
          (Signature_Bytes
             (Signature_Bytes'First .. Signature_Bytes'First + 31),
           Public_Key_Bytes,
           Message_Bytes);
      Base_Point := Decode_Base_Point;
      Left_Point := Scalar_Multiply (S_Field, Base_Point);
      Right_Point :=
        Add_Point (R_Point, Scalar_Multiply (H_Scalar, Public_Point));

      if Point_Equal (Left_Point, Right_Point) then
         return Ok;
      else
         return Handshake_Failed;
      end if;
   exception
      when others =>
         return Internal_Error;
   end Verify;
end CryptoLib.Ed25519;
