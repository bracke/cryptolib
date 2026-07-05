with Interfaces; use Interfaces;

package body CryptoLib.EC_Arith is

   use Ada.Streams;

   Low_Mask : constant Unsigned_64 := 16#FFFF_FFFF#;

   --  Raw N-word borrow subtract over the whole element (high words are zero,
   --  so operating over Max_Words is correct and constant-time).
   function Raw_Sub (A, B : Element) return Element is
      R      : Element;
      Borrow : Unsigned_64 := 0;
   begin
      for J in Element'Range loop
         declare
            D : constant Unsigned_64 :=
              Unsigned_64 (A (J)) - Unsigned_64 (B (J)) - Borrow;
         begin
            R (J) := Word (D and Low_Mask);
            Borrow := Shift_Right (D, 63) and 1;
         end;
      end loop;
      return R;
   end Raw_Sub;

   function Geq_Mask (A, M : Element) return Word is
      Borrow : Unsigned_64 := 0;
   begin
      for J in Element'Range loop                  --  LSB .. MSB
         Borrow :=
           Shift_Right
             (Unsigned_64 (A (J)) - Unsigned_64 (M (J)) - Borrow, 63) and 1;
      end loop;
      return Word (Borrow) - 1;                     --  Borrow = 0 -> all-ones
   end Geq_Mask;

   function CT_Select (Mask : Word; A, B : Element) return Element is
      R : Element;
   begin
      for J in Element'Range loop
         R (J) := (A (J) and Mask) or (B (J) and not Mask);
      end loop;
      return R;
   end CT_Select;

   function Is_Zero_Mask (A : Element) return Word is
      Acc : Word := 0;
   begin
      for J in Element'Range loop
         Acc := Acc or A (J);
      end loop;
      --  Acc = 0 -> all-ones, else zero.
      return Word (Shift_Right (Unsigned_64 (Acc) or (0 - Unsigned_64 (Acc)), 63)) - 1;
   end Is_Zero_Mask;

   function Equal_Mask (A, B : Element) return Word is
      Acc : Word := 0;
   begin
      for J in Element'Range loop
         Acc := Acc or (A (J) xor B (J));
      end loop;
      return Word (Shift_Right (Unsigned_64 (Acc) or (0 - Unsigned_64 (Acc)), 63)) - 1;
   end Equal_Mask;

   --  X := (X * 2) mod M for X < M, using modulus M with N significant words.
   function Double_Mod (X, M : Element; N : Natural) return Element is
      R     : Element := [others => 0];
      Carry : Word := 0;
   begin
      for J in 0 .. N - 1 loop
         declare
            Next : constant Word := Shift_Right (X (J), 31);
         begin
            R (J) := Shift_Left (X (J), 1) or Carry;
            Carry := Next;
         end;
      end loop;
      if Carry /= 0 or else (Geq_Mask (R, M) and 1) /= 0 then
         R := Raw_Sub (R, M);
      end if;
      return R;
   end Double_Mod;

   function N0_Inverse (M0 : Word) return Word is
      X : Word := 1;
   begin
      for Iteration in 1 .. 5 loop
         X := X * (2 - M0 * X);
      end loop;
      return (not X) + 1;
   end N0_Inverse;

   function Make_Context
     (Modulus_BE : Ada.Streams.Stream_Element_Array) return Context
   is
      Ctx   : Context;
      First : Stream_Element_Offset := Modulus_BE'First;
   begin
      while First <= Modulus_BE'Last and then Modulus_BE (First) = 0 loop
         First := First + 1;
      end loop;
      Ctx.Byte_Len := Natural (Modulus_BE'Last - First + 1);
      Ctx.N_Words := (Ctx.Byte_Len + 3) / 4;

      --  Little-endian words from big-endian bytes.
      declare
         Idx : Natural := 0;
      begin
         for I in reverse First .. Modulus_BE'Last loop
            Ctx.M (Idx / 4) :=
              Ctx.M (Idx / 4)
              or Shift_Left (Word (Modulus_BE (I)), (Idx mod 4) * 8);
            Idx := Idx + 1;
         end loop;
      end;

      Ctx.N0 := N0_Inverse (Ctx.M (0));

      --  R**2 mod M = 2**(64*N) mod M, by repeated doubling from 1.
      Ctx.R2 := [others => 0];
      Ctx.R2 (0) := 1;
      for Count in 1 .. 64 * Ctx.N_Words loop
         Ctx.R2 := Double_Mod (Ctx.R2, Ctx.M, Ctx.N_Words);
      end loop;
      return Ctx;
   end Make_Context;

   function Byte_Length (Ctx : Context) return Natural is (Ctx.Byte_Len);
   function Modulus (Ctx : Context) return Element is (Ctx.M);

   function From_Bytes
     (Ctx : Context; Data_BE : Ada.Streams.Stream_Element_Array) return Element
   is
      pragma Unreferenced (Ctx);
      R   : Element := [others => 0];
      Idx : Natural := 0;
   begin
      for I in reverse Data_BE'Range loop
         exit when Idx / 4 > Max_Words - 1;
         R (Idx / 4) := R (Idx / 4)
           or Shift_Left (Word (Data_BE (I)), (Idx mod 4) * 8);
         Idx := Idx + 1;
      end loop;
      return R;
   end From_Bytes;

   function To_Bytes
     (Ctx : Context; A : Element) return Ada.Streams.Stream_Element_Array
   is
      R : Stream_Element_Array (1 .. Stream_Element_Offset (Ctx.Byte_Len)) :=
        [others => 0];
   begin
      for I in 0 .. Ctx.Byte_Len - 1 loop
         R (R'Last - Stream_Element_Offset (I)) :=
           Stream_Element (Shift_Right (A (I / 4), (I mod 4) * 8) and 16#FF#);
      end loop;
      return R;
   end To_Bytes;

   function Add (Ctx : Context; A, B : Element) return Element is
      N     : constant Natural := Ctx.N_Words;
      R     : Element := [others => 0];
      Carry : Unsigned_64 := 0;
   begin
      for J in 0 .. N - 1 loop
         Carry := Carry + Unsigned_64 (A (J)) + Unsigned_64 (B (J));
         R (J) := Word (Carry and Low_Mask);
         Carry := Shift_Right (Carry, 32);
      end loop;
      return CT_Select
        ((Word (0) - Word (Carry)) or Geq_Mask (R, Ctx.M), Raw_Sub (R, Ctx.M), R);
   end Add;

   function Sub (Ctx : Context; A, B : Element) return Element is
      N      : constant Natural := Ctx.N_Words;
      R      : Element := [others => 0];
      Borrow : Unsigned_64 := 0;
      Added  : Element := [others => 0];
      Carry  : Unsigned_64 := 0;
   begin
      for J in 0 .. N - 1 loop
         declare
            D : constant Unsigned_64 :=
              Unsigned_64 (A (J)) - Unsigned_64 (B (J)) - Borrow;
         begin
            R (J) := Word (D and Low_Mask);
            Borrow := Shift_Right (D, 63) and 1;
         end;
      end loop;
      --  If a borrow escaped (A < B), add M back.
      for J in 0 .. N - 1 loop
         Carry := Carry + Unsigned_64 (R (J)) + Unsigned_64 (Ctx.M (J));
         Added (J) := Word (Carry and Low_Mask);
         Carry := Shift_Right (Carry, 32);
      end loop;
      return CT_Select (Word (0) - Word (Borrow), Added, R);
   end Sub;

   function Mont_Mul (Ctx : Context; A, B : Element) return Element is
      N : constant Natural := Ctx.N_Words;
      T : array (0 .. Max_Words + 1) of Word := [others => 0];
      R : Element := [others => 0];
   begin
      for I in 0 .. N - 1 loop
         declare
            Carry : Unsigned_64 := 0;
         begin
            for J in 0 .. N - 1 loop
               declare
                  Sum : constant Unsigned_64 :=
                    Unsigned_64 (T (J))
                    + Unsigned_64 (A (J)) * Unsigned_64 (B (I)) + Carry;
               begin
                  T (J) := Word (Sum and Low_Mask);
                  Carry := Shift_Right (Sum, 32);
               end;
            end loop;
            declare
               Sum : constant Unsigned_64 := Unsigned_64 (T (N)) + Carry;
            begin
               T (N) := Word (Sum and Low_Mask);
               T (N + 1) := T (N + 1) + Word (Shift_Right (Sum, 32));
            end;
         end;

         declare
            M_Word : constant Word :=
              Word ((Unsigned_64 (T (0)) * Unsigned_64 (Ctx.N0)) and Low_Mask);
            Carry  : Unsigned_64 :=
              Shift_Right
                (Unsigned_64 (T (0)) + Unsigned_64 (M_Word) * Unsigned_64 (Ctx.M (0)),
                 32);
         begin
            for J in 1 .. N - 1 loop
               declare
                  Sum : constant Unsigned_64 :=
                    Unsigned_64 (T (J))
                    + Unsigned_64 (M_Word) * Unsigned_64 (Ctx.M (J)) + Carry;
               begin
                  T (J - 1) := Word (Sum and Low_Mask);
                  Carry := Shift_Right (Sum, 32);
               end;
            end loop;
            declare
               Sum : constant Unsigned_64 := Unsigned_64 (T (N)) + Carry;
            begin
               T (N - 1) := Word (Sum and Low_Mask);
               T (N) := T (N + 1) + Word (Shift_Right (Sum, 32));
               T (N + 1) := 0;
            end;
         end;
      end loop;

      for J in 0 .. N - 1 loop
         R (J) := T (J);
      end loop;
      return CT_Select
        ((Word (0) - T (N)) or Geq_Mask (R, Ctx.M), Raw_Sub (R, Ctx.M), R);
   end Mont_Mul;

   function To_Mont (Ctx : Context; A : Element) return Element is
     (Mont_Mul (Ctx, A, Ctx.R2));

   function One_Element return Element is
      R : Element := [others => 0];
   begin
      R (0) := 1;
      return R;
   end One_Element;

   function From_Mont (Ctx : Context; A : Element) return Element is
     (Mont_Mul (Ctx, A, One_Element));

   function One_Mont (Ctx : Context) return Element is
     (Mont_Mul (Ctx, One_Element, Ctx.R2));

end CryptoLib.EC_Arith;
