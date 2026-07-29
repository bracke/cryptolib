with Ada.Streams; use Ada.Streams;
with System;

with CryptoLib.SHA3;
with CryptoLib.Secure_Wipe;

package body CryptoLib.Ed448 is

   use CryptoLib.Errors;

   subtype Byte_Value is Natural range 0 .. 255;
   subtype Fe_Index is Natural range 0 .. 55;
   type Field_Element is array (Fe_Index) of Byte_Value;

   --  edwards448: x^2 + y^2 = 1 + d*x^2*y^2 over p = 2^448 - 2^224 - 1, with
   --  d = -39081 and a base point of order L. Every one of these was derived
   --  and checked rather than transcribed -- see the commit message.
   Prime_Value : constant Field_Element :=
     [16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FE#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#];

   Order_Value : constant Field_Element :=
     [16#F3#, 16#44#, 16#58#, 16#AB#, 16#92#, 16#C2#, 16#78#,
      16#23#, 16#55#, 16#8F#, 16#C5#, 16#8D#, 16#72#, 16#C2#,
      16#6C#, 16#21#, 16#90#, 16#36#, 16#D6#, 16#AE#, 16#49#,
      16#DB#, 16#4E#, 16#C4#, 16#E9#, 16#23#, 16#CA#, 16#7C#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#3F#];

   D_Value : constant Field_Element :=
     [16#56#, 16#67#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FE#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#];

   Base_X_Value : constant Field_Element :=
     [16#5E#, 16#C0#, 16#0C#, 16#C7#, 16#2B#, 16#A8#, 16#26#,
      16#26#, 16#8E#, 16#93#, 16#00#, 16#8B#, 16#E1#, 16#80#,
      16#3B#, 16#43#, 16#11#, 16#65#, 16#B6#, 16#2A#, 16#F7#,
      16#1A#, 16#AE#, 16#12#, 16#64#, 16#A4#, 16#D3#, 16#A3#,
      16#24#, 16#E3#, 16#6D#, 16#EA#, 16#67#, 16#17#, 16#0F#,
      16#47#, 16#70#, 16#65#, 16#14#, 16#9E#, 16#DA#, 16#36#,
      16#BF#, 16#22#, 16#A6#, 16#15#, 16#1D#, 16#22#, 16#ED#,
      16#0D#, 16#ED#, 16#6B#, 16#C6#, 16#70#, 16#19#, 16#4F#];

   Base_Y_Value : constant Field_Element :=
     [16#14#, 16#FA#, 16#30#, 16#F2#, 16#5B#, 16#79#, 16#08#,
      16#98#, 16#AD#, 16#C8#, 16#D7#, 16#4E#, 16#2C#, 16#13#,
      16#BD#, 16#FD#, 16#C4#, 16#39#, 16#7C#, 16#E6#, 16#1C#,
      16#FF#, 16#D3#, 16#3A#, 16#D7#, 16#C2#, 16#A0#, 16#05#,
      16#1E#, 16#9C#, 16#78#, 16#87#, 16#40#, 16#98#, 16#A3#,
      16#6C#, 16#73#, 16#73#, 16#EA#, 16#4B#, 16#62#, 16#C7#,
      16#C9#, 16#56#, 16#37#, 16#20#, 16#76#, 16#88#, 16#24#,
      16#BC#, 16#B6#, 16#6E#, 16#71#, 16#46#, 16#3F#, 16#69#];

   --  Projective (X : Y : Z), the coordinates RFC 8032 5.2.4 gives complete
   --  formulas for. Complete means no exceptional cases, so the ladder below
   --  needs no test for the neutral element and takes no branch on a secret.
   type Point is record
      X : Field_Element;
      Y : Field_Element;
      Z : Field_Element;
   end record;

   type Affine_Point is record
      X : Field_Element;
      Y : Field_Element;
   end record;

   Zero_Element : constant Field_Element := [others => 0];
   One_Element  : constant Field_Element := [1, others => 0];

   ---------------------------------------------------------------------
   --  Field arithmetic mod p
   ---------------------------------------------------------------------

   --  Is Left >= Right? Whole-width compare, no early exit.
   --  The borrow out of Left - Right, as 0 or 1.
   --
   --  Biased by 256 so the quotient carries the sign: the value is never
   --  negative, so the division is a shift and nothing tests a sign bit.
   --  Writing this as "if Diff < 0" reads better and compiles to a jns on
   --  data that, during signing, is derived from the private scalar.
   function Borrow_Of (Left : Field_Element; Right : Field_Element)
     return Natural
   is
      Borrow : Natural := 0;
   begin
      for I in Fe_Index loop
         declare
            Biased : constant Natural := Left (I) - Right (I) - Borrow + 256;
         begin
            Borrow := 1 - Biased / 256;
         end;
      end loop;
      return Borrow;
   end Borrow_Of;

   function Not_Less (Left : Field_Element; Right : Field_Element)
     return Boolean
   is (Borrow_Of (Left, Right) = 0);

   --  Left - Right when Take is 1, Left unchanged when it is 0.
   procedure Conditional_Subtract
     (Item : in out Field_Element; Amount : Field_Element; Take : Natural)
   is
      Borrow : Natural := 0;
      Keep   : constant Natural := Take mod 2;
   begin
      for I in Fe_Index loop
         declare
            Sub    : constant Natural := Amount (I) * Keep;
            Biased : constant Natural := Item (I) - Sub - Borrow + 256;
         begin
            Item (I) := Biased mod 256;
            Borrow := 1 - Biased / 256;
         end;
      end loop;
   end Conditional_Subtract;

   --  Bring a value in [0, 2p) down to [0, p). Twice, because a folded
   --  product can land above 2p.
   procedure Normalize (Item : in out Field_Element) is
   begin
      for Pass in 1 .. 2 loop
         Conditional_Subtract
           (Item, Prime_Value, 1 - Borrow_Of (Item, Prime_Value));
      end loop;
   end Normalize;

   function Add_Mod (Left : Field_Element; Right : Field_Element)
     return Field_Element
   is
      Result : Field_Element;
      Carry  : Natural := 0;
   begin
      for I in Fe_Index loop
         declare
            Sum : constant Natural := Left (I) + Right (I) + Carry;
         begin
            Result (I) := Sum mod 256;
            Carry := Sum / 256;
         end;
      end loop;

      --  A carry out is 2^448, which is 2^224 + 1 here.
      declare
         Fold : Field_Element := [others => 0];
         C    : Natural := 0;
      begin
         Fold (0) := Carry;
         Fold (28) := Carry;
         for I in Fe_Index loop
            declare
               Sum : constant Natural := Result (I) + Fold (I) + C;
            begin
               Result (I) := Sum mod 256;
               C := Sum / 256;
            end;
         end loop;
      end;

      Normalize (Result);
      return Result;
   end Add_Mod;

   function Sub_Mod (Left : Field_Element; Right : Field_Element)
     return Field_Element
   is
      Result : Field_Element := Left;
      Borrow : Natural := 0;
   begin
      for I in Fe_Index loop
         declare
            Biased : constant Natural := Left (I) - Right (I) - Borrow + 256;
         begin
            Result (I) := Biased mod 256;
            Borrow := 1 - Biased / 256;
         end;
      end loop;

      --  Borrowing out means the true value was negative, so p goes back on.
      --  Always added, masked by the borrow, rather than added under an if:
      --  the borrow is derived from the operands and those are secret here.
      declare
         C : Natural := 0;
      begin
         for I in Fe_Index loop
            declare
               Sum : constant Natural :=
                 Result (I) + Prime_Value (I) * Borrow + C;
            begin
               Result (I) := Sum mod 256;
               C := Sum / 256;
            end;
         end loop;
      end;

      Normalize (Result);
      return Result;
   end Sub_Mod;

   function Mul_Mod (Left : Field_Element; Right : Field_Element)
     return Field_Element
   is
      type Wide_Array is array (Natural range 0 .. 127) of Long_Long_Integer;
      Work   : Wide_Array := [others => 0];
      Result : Field_Element := [others => 0];
      Carry  : Long_Long_Integer;
   begin
      for I in Fe_Index loop
         for J in Fe_Index loop
            Work (I + J) :=
              Work (I + J)
              + Long_Long_Integer (Left (I)) * Long_Long_Integer (Right (J));
         end loop;
      end loop;

      --  2^448 = 2^224 + 1 mod p, so a word at index I >= 56 lands at both
      --  I - 56 and I - 28. Descending, because I - 28 may itself be one of
      --  the indices still to be folded.
      for I in reverse 56 .. 127 loop
         Work (I - 56) := Work (I - 56) + Work (I);
         Work (I - 28) := Work (I - 28) + Work (I);
         Work (I) := 0;
      end loop;

      for Pass in 1 .. 3 loop
         Carry := 0;
         for I in Fe_Index loop
            Work (I) := Work (I) + Carry;
            Carry := Work (I) / 256;
            Work (I) := Work (I) mod 256;
         end loop;

         --  Unconditionally, adding nothing when there is no carry: the
         --  carry out of a product of secret values is secret.
         Work (0) := Work (0) + Carry;
         Work (28) := Work (28) + Carry;
      end loop;

      for I in Fe_Index loop
         Result (I) := Byte_Value (Work (I));
      end loop;
      Normalize (Result);
      return Result;
   end Mul_Mod;

   function Square_Mod (Item : Field_Element) return Field_Element
   is (Mul_Mod (Item, Item));

   --  Item raised to an exponent given as bytes, square-and-multiply-always
   --  over a fixed count. The exponents here are public (p - 2, (p + 1) / 4),
   --  but the base is not, so the shape stays uniform.
   function Pow_Mod (Base : Field_Element; Exponent : Field_Element)
     return Field_Element
   is
      Result : Field_Element := One_Element;
   begin
      for I in reverse Fe_Index loop
         for Bit in reverse 0 .. 7 loop
            Result := Square_Mod (Result);
            if (Exponent (I) / (2 ** Bit)) mod 2 = 1 then
               Result := Mul_Mod (Result, Base);
            end if;
         end loop;
      end loop;
      return Result;
   end Pow_Mod;

   function Inv_Mod (Item : Field_Element) return Field_Element is
      Exponent : Field_Element := Prime_Value;
   begin
      --  p - 2.
      Exponent (0) := Exponent (0) - 2;
      return Pow_Mod (Item, Exponent);
   end Inv_Mod;

   --  Item^((p + 1) / 4), the square root when one exists. p is 3 mod 4.
   function Sqrt_Mod (Item : Field_Element) return Field_Element is
      Exponent : Field_Element := [others => 0];
      Carry    : Natural := 1;
   begin
      --  (p + 1) / 4, computed rather than written out.
      for I in Fe_Index loop
         declare
            Sum : constant Natural := Prime_Value (I) + Carry;
         begin
            Exponent (I) := Sum mod 256;
            Carry := Sum / 256;
         end;
      end loop;

      for Shift in 1 .. 2 loop
         declare
            Above : Natural := 0;
         begin
            for I in reverse Fe_Index loop
               declare
                  Current : constant Natural := Exponent (I);
               begin
                  Exponent (I) := Current / 2 + Above * 128;
                  Above := Current mod 2;
               end;
            end loop;
         end;
      end loop;

      return Pow_Mod (Item, Exponent);
   end Sqrt_Mod;

   function Equal_Field (Left : Field_Element; Right : Field_Element)
     return Boolean
   is
      Differs : Natural := 0;
   begin
      for I in Fe_Index loop
         Differs := Differs + abs (Left (I) - Right (I));
      end loop;
      return Differs = 0;
   end Equal_Field;

   --  Right when Take is 1, Left when it is 0, without branching on Take.
   function Select_Field
     (Left : Field_Element; Right : Field_Element; Take : Natural)
      return Field_Element
   is
      Chosen : constant Natural := Take mod 2;
      Other  : constant Natural := 1 - Chosen;
      Result : Field_Element;
   begin
      for I in Fe_Index loop
         Result (I) := Byte_Value (Left (I) * Other + Right (I) * Chosen);
      end loop;
      return Result;
   end Select_Field;

   ---------------------------------------------------------------------
   --  Point arithmetic
   ---------------------------------------------------------------------

   Neutral_Point : constant Point :=
     (X => Zero_Element, Y => One_Element, Z => One_Element);

   --  RFC 8032 5.2.4 projective addition. Complete on this curve, so it is
   --  also what doubling could use; the dedicated doubling below is the same
   --  formulas specialised, kept because the ladder runs it 448 times.
   function Add_Point (Left : Point; Right : Point) return Point is
      A : constant Field_Element := Mul_Mod (Left.Z, Right.Z);
      B : constant Field_Element := Square_Mod (A);
      C : constant Field_Element := Mul_Mod (Left.X, Right.X);
      D : constant Field_Element := Mul_Mod (Left.Y, Right.Y);
      E : constant Field_Element := Mul_Mod (D_Value, Mul_Mod (C, D));
      F : constant Field_Element := Sub_Mod (B, E);
      G : constant Field_Element := Add_Mod (B, E);
      H : constant Field_Element :=
        Mul_Mod (Add_Mod (Left.X, Left.Y), Add_Mod (Right.X, Right.Y));
   begin
      return
        (X => Mul_Mod (Mul_Mod (A, F), Sub_Mod (Sub_Mod (H, C), D)),
         Y => Mul_Mod (Mul_Mod (A, G), Sub_Mod (D, C)),
         Z => Mul_Mod (F, G));
   end Add_Point;

   function Double_Point (Item : Point) return Point is
      B : constant Field_Element := Square_Mod (Add_Mod (Item.X, Item.Y));
      C : constant Field_Element := Square_Mod (Item.X);
      D : constant Field_Element := Square_Mod (Item.Y);
      E : constant Field_Element := Add_Mod (C, D);
      H : constant Field_Element := Square_Mod (Item.Z);
      J : constant Field_Element := Sub_Mod (E, Add_Mod (H, H));
   begin
      return
        (X => Mul_Mod (Sub_Mod (B, E), J),
         Y => Mul_Mod (E, Sub_Mod (C, D)),
         Z => Mul_Mod (E, J));
   end Double_Point;

   function Select_Point (Left : Point; Right : Point; Take : Natural)
     return Point
   is (X => Select_Field (Left.X, Right.X, Take),
       Y => Select_Field (Left.Y, Right.Y, Take),
       Z => Select_Field (Left.Z, Right.Z, Take));

   --  Double-and-add-always: the addition happens on every bit and only the
   --  select depends on the bit, so the scalar leaves no trace in the shape
   --  of the work.
   function Scalar_Multiply (Item : Point; Scalar : Field_Element)
     return Point
   is
      Result : Point := Neutral_Point;
      Sum    : Point;
      Bit    : Natural;
   begin
      for I in reverse Fe_Index loop
         for Index in reverse 0 .. 7 loop
            Result := Double_Point (Result);
            Sum := Add_Point (Result, Item);
            Bit := (Scalar (I) / (2 ** Index)) mod 2;
            Result := Select_Point (Result, Sum, Bit);
         end loop;
      end loop;
      return Result;
   end Scalar_Multiply;

   function To_Affine (Item : Point) return Affine_Point is
      Inverse : constant Field_Element := Inv_Mod (Item.Z);
   begin
      return (X => Mul_Mod (Item.X, Inverse), Y => Mul_Mod (Item.Y, Inverse));
   end To_Affine;

   function Same_Point (Left : Point; Right : Point) return Boolean is
      L : constant Affine_Point := To_Affine (Left);
      R : constant Affine_Point := To_Affine (Right);
   begin
      return Equal_Field (L.X, R.X) and then Equal_Field (L.Y, R.Y);
   end Same_Point;

   Base_Point : constant Point :=
     (X => Base_X_Value, Y => Base_Y_Value, Z => One_Element);

   function Encode_Point (Item : Point) return Stream_Element_Array is
      A      : constant Affine_Point := To_Affine (Item);
      Result : Stream_Element_Array (1 .. 57) := [others => 0];
   begin
      for I in Fe_Index loop
         Result (Stream_Element_Offset (I + 1)) := Stream_Element (A.Y (I));
      end loop;
      declare
         Sign_Bit : constant Natural := A.X (0) mod 2;
      begin
         Result (57) := Stream_Element (Sign_Bit * 128);
      end;
      return Result;
   end Encode_Point;

   --  Recover x from y and the sign bit. Fails when the encoding names no
   --  point, which is something an attacker can hand over.
   procedure Decode_Point
     (Data : Stream_Element_Array; Item : out Point; Ok : out Boolean)
   is
      Y    : Field_Element := [others => 0];
      Sign : Natural;
   begin
      Item := Neutral_Point;
      Ok := False;

      if Data'Length /= 57 then
         return;
      end if;

      for I in Fe_Index loop
         Y (I) := Byte_Value (Data (Data'First + Stream_Element_Offset (I)));
      end loop;
      Sign := Natural (Data (Data'First + 56)) / 128;

      --  The unused bits of the final octet are not free space: a second
      --  encoding of one key is a second name for it.
      if Natural (Data (Data'First + 56)) mod 128 /= 0 then
         return;
      end if;

      if Not_Less (Y, Prime_Value) then
         return;
      end if;

      declare
         Y2  : constant Field_Element := Square_Mod (Y);
         U   : constant Field_Element := Sub_Mod (Y2, One_Element);
         V   : constant Field_Element :=
           Sub_Mod (Mul_Mod (D_Value, Y2), One_Element);
         Ratio : Field_Element;
         X     : Field_Element;
      begin
         if Equal_Field (V, Zero_Element) then
            return;
         end if;

         Ratio := Mul_Mod (U, Inv_Mod (V));
         X := Sqrt_Mod (Ratio);

         --  Ratio may be a non-residue, in which case the exponentiation
         --  returns something that is not its root and the encoding names
         --  no point at all.
         if not Equal_Field (Square_Mod (X), Ratio) then
            return;
         end if;

         if Equal_Field (X, Zero_Element) and then Sign = 1 then
            return;
         end if;

         if X (0) mod 2 /= Sign then
            X := Sub_Mod (Prime_Value, X);
         end if;

         Item := (X => X, Y => Y, Z => One_Element);
         Ok := True;
      end;
   end Decode_Point;

   ---------------------------------------------------------------------
   --  Scalars mod L
   ---------------------------------------------------------------------

   --  Reduce an arbitrary-width little-endian value mod L, most significant
   --  bit first. One conditional subtraction per bit, taken branchlessly, so
   --  the work does not depend on the value.
   function Reduce_Mod_L (Data : Stream_Element_Array) return Field_Element is
      Acc  : Field_Element := [others => 0];
      Bit  : Natural;
      Take : Natural;
   begin
      for I in reverse Data'Range loop
         for Index in reverse 0 .. 7 loop
            --  Acc := Acc * 2 + bit.
            declare
               Carry : Natural := (Natural (Data (I)) / (2 ** Index)) mod 2;
            begin
               for J in Fe_Index loop
                  Bit := Acc (J) / 128;
                  Acc (J) := (Acc (J) mod 128) * 2 + Carry;
                  Carry := Bit;
               end loop;
            end;

            Take := (if Not_Less (Acc, Order_Value) then 1 else 0);
            Conditional_Subtract (Acc, Order_Value, Take);
         end loop;
      end loop;
      return Acc;
   end Reduce_Mod_L;

   function Mul_Mod_L (Left : Field_Element; Right : Field_Element)
     return Field_Element
   is
      Work    : array (Natural range 0 .. 111) of Long_Long_Integer :=
        [others => 0];
      Product : Stream_Element_Array (1 .. 112);
      Carry   : Long_Long_Integer := 0;
   begin
      for I in Fe_Index loop
         for J in Fe_Index loop
            Work (I + J) :=
              Work (I + J)
              + Long_Long_Integer (Left (I)) * Long_Long_Integer (Right (J));
         end loop;
      end loop;

      for I in Work'Range loop
         Work (I) := Work (I) + Carry;
         Carry := Work (I) / 256;
         Work (I) := Work (I) mod 256;
         Product (Stream_Element_Offset (I + 1)) :=
           Stream_Element (Work (I));
      end loop;

      return Reduce_Mod_L (Product);
   end Mul_Mod_L;

   function Add_Mod_L (Left : Field_Element; Right : Field_Element)
     return Field_Element
   is
      Result : Field_Element;
      Carry  : Natural := 0;
      Take   : Natural;
   begin
      for I in Fe_Index loop
         declare
            Sum : constant Natural := Left (I) + Right (I) + Carry;
         begin
            Result (I) := Sum mod 256;
            Carry := Sum / 256;
         end;
      end loop;

      --  Both operands are already below L, so one subtraction is enough.
      Take := (if Carry /= 0 or else Not_Less (Result, Order_Value)
               then 1 else 0);
      Conditional_Subtract (Result, Order_Value, Take);
      return Result;
   end Add_Mod_L;

   ---------------------------------------------------------------------
   --  EdDSA
   ---------------------------------------------------------------------

   --  RFC 8032 5.2: dom4(0, "") for pure Ed448 with an empty context.
   Domain_Prefix : constant Stream_Element_Array :=
     [Character'Pos ('S'), Character'Pos ('i'), Character'Pos ('g'),
      Character'Pos ('E'), Character'Pos ('d'), Character'Pos ('4'),
      Character'Pos ('4'), Character'Pos ('8'), 0, 0];

   --  The secret scalar and the prefix that seeds r, from the seed.
   procedure Expand_Seed
     (Seed_Bytes : Stream_Element_Array;
      Scalar     : out Field_Element;
      Prefix     : out Stream_Element_Array)
   is
      Digest : constant Stream_Element_Array :=
        CryptoLib.SHA3.SHAKE256 (Seed_Bytes, 114);
      Pruned : Stream_Element_Array (1 .. 57) := Digest (1 .. 57);
   begin
      --  RFC 8032 5.2.5: clear the two low bits, clear the last octet, set
      --  the top bit of the one before it.
      Pruned (1) := Pruned (1) and 16#FC#;
      Pruned (57) := 0;
      Pruned (56) := Pruned (56) or 16#80#;

      Scalar := [others => 0];
      for I in Fe_Index loop
         Scalar (I) := Byte_Value (Pruned (Stream_Element_Offset (I + 1)));
      end loop;

      Prefix := Digest (58 .. 114);
      CryptoLib.Secure_Wipe.Wipe
        (Pruned'Address, Pruned'Length);
   end Expand_Seed;

   function Public_Key_From_Seed
     (Seed_Bytes       : Ada.Streams.Stream_Element_Array;
      Public_Key_Bytes : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      Scalar : Field_Element;
      Prefix : Stream_Element_Array (1 .. 57);
   begin
      Public_Key_Bytes := [others => 0];

      if Seed_Bytes'Length /= Stream_Element_Offset (Seed_Length)
        or else Public_Key_Bytes'Length
                /= Stream_Element_Offset (Public_Key_Length)
      then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      Expand_Seed (Seed_Bytes, Scalar, Prefix);
      Public_Key_Bytes := Encode_Point (Scalar_Multiply (Base_Point, Scalar));

      CryptoLib.Secure_Wipe.Wipe (Scalar'Address, Scalar'Size / 8);
      CryptoLib.Secure_Wipe.Wipe (Prefix'Address, Prefix'Length);
      return CryptoLib.Errors.Ok;
   end Public_Key_From_Seed;

   function Generate_Keypair
     (Rng              : in out CryptoLib.Random.Random_Source;
      Seed_Bytes       : out Ada.Streams.Stream_Element_Array;
      Public_Key_Bytes : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      Status : CryptoLib.Errors.Status;
   begin
      Seed_Bytes := [others => 0];
      Public_Key_Bytes := [others => 0];

      if Seed_Bytes'Length /= Stream_Element_Offset (Seed_Length)
        or else Public_Key_Bytes'Length
                /= Stream_Element_Offset (Public_Key_Length)
      then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      Status := CryptoLib.Random.Fill (Rng, Seed_Bytes);
      if Status /= CryptoLib.Errors.Ok then
         Seed_Bytes := [others => 0];
         return CryptoLib.Errors.Internal_Error;
      end if;

      Status := Public_Key_From_Seed (Seed_Bytes, Public_Key_Bytes);
      if Status /= CryptoLib.Errors.Ok then
         Seed_Bytes := [others => 0];
         Public_Key_Bytes := [others => 0];
         return CryptoLib.Errors.Internal_Error;
      end if;

      return CryptoLib.Errors.Ok;
   end Generate_Keypair;

   function Sign
     (Seed_Bytes       : Ada.Streams.Stream_Element_Array;
      Public_Key_Bytes : Ada.Streams.Stream_Element_Array;
      Message_Bytes    : Ada.Streams.Stream_Element_Array;
      Signature_Bytes  : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      Scalar : Field_Element;
      Prefix : Stream_Element_Array (1 .. 57);
   begin
      Signature_Bytes := [others => 0];

      if Seed_Bytes'Length /= Stream_Element_Offset (Seed_Length)
        or else Public_Key_Bytes'Length
                /= Stream_Element_Offset (Public_Key_Length)
        or else Signature_Bytes'Length
                /= Stream_Element_Offset (Signature_Length)
      then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      Expand_Seed (Seed_Bytes, Scalar, Prefix);

      declare
         R_Scalar : constant Field_Element :=
           Reduce_Mod_L
             (CryptoLib.SHA3.SHAKE256
                (Domain_Prefix & Prefix & Message_Bytes, 114));
         R_Point  : constant Stream_Element_Array :=
           Encode_Point (Scalar_Multiply (Base_Point, R_Scalar));
         K_Scalar : constant Field_Element :=
           Reduce_Mod_L
             (CryptoLib.SHA3.SHAKE256
                (Domain_Prefix & R_Point & Public_Key_Bytes & Message_Bytes,
                 114));
         S_Scalar : constant Field_Element :=
           Add_Mod_L (R_Scalar, Mul_Mod_L (K_Scalar, Scalar));
      begin
         Signature_Bytes (Signature_Bytes'First
                          .. Signature_Bytes'First + 56) := R_Point;
         for I in Fe_Index loop
            Signature_Bytes
              (Signature_Bytes'First + 57 + Stream_Element_Offset (I)) :=
              Stream_Element (S_Scalar (I));
         end loop;
         Signature_Bytes (Signature_Bytes'First + 113) := 0;
      end;

      CryptoLib.Secure_Wipe.Wipe (Scalar'Address, Scalar'Size / 8);
      CryptoLib.Secure_Wipe.Wipe (Prefix'Address, Prefix'Length);
      return CryptoLib.Errors.Ok;
   end Sign;

   function Verify
     (Public_Key_Bytes : Ada.Streams.Stream_Element_Array;
      Signature_Bytes  : Ada.Streams.Stream_Element_Array;
      Message_Bytes    : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      A_Point : Point;
      R_Point : Point;
      Ok      : Boolean;
      S_Value : Field_Element := [others => 0];
   begin
      if Public_Key_Bytes'Length /= Stream_Element_Offset (Public_Key_Length)
        or else Signature_Bytes'Length
                /= Stream_Element_Offset (Signature_Length)
      then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      Decode_Point (Public_Key_Bytes, A_Point, Ok);
      if not Ok then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      Decode_Point
        (Signature_Bytes (Signature_Bytes'First
                          .. Signature_Bytes'First + 56), R_Point, Ok);
      if not Ok then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      --  S is a scalar, and one at or above L is a second encoding of a
      --  signature that already has one.
      for I in Fe_Index loop
         S_Value (I) :=
           Byte_Value
             (Signature_Bytes
                (Signature_Bytes'First + 57 + Stream_Element_Offset (I)));
      end loop;
      if Signature_Bytes (Signature_Bytes'First + 113) /= 0
        or else Not_Less (S_Value, Order_Value)
      then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      declare
         K_Scalar : constant Field_Element :=
           Reduce_Mod_L
             (CryptoLib.SHA3.SHAKE256
                (Domain_Prefix
                 & Signature_Bytes (Signature_Bytes'First
                                    .. Signature_Bytes'First + 56)
                 & Public_Key_Bytes & Message_Bytes, 114));
         Left  : Point := Scalar_Multiply (Base_Point, S_Value);
         Right : Point :=
           Add_Point (R_Point, Scalar_Multiply (A_Point, K_Scalar));
      begin
         --  Multiply both sides by the cofactor, which is 4 here, so that a
         --  small-order component cannot decide the answer.
         for Pass in 1 .. 2 loop
            Left := Double_Point (Left);
            Right := Double_Point (Right);
         end loop;

         if Same_Point (Left, Right) then
            return CryptoLib.Errors.Ok;
         else
            return CryptoLib.Errors.Handshake_Failed;
         end if;
      end;
   end Verify;

end CryptoLib.Ed448;
