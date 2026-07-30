package body CryptoLib.Field448 is

   One_Element : constant Field_Element := [1, others => 0];

   Prime_Value : constant Field_Element :=
     [16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FE#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#];

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
   function Prime return Field_Element is (Prime_Value);

end CryptoLib.Field448;
