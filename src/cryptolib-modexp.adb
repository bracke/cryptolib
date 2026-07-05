with Interfaces; use Interfaces;

package body CryptoLib.Modexp is

   use Ada.Streams;

   subtype Word is Unsigned_32;
   subtype DWord is Unsigned_64;
   type Word_Array is array (Natural range <>) of Word;

   Low_Mask : constant DWord := 16#FFFF_FFFF#;

   --  Number of significant 32-bit words needed to hold a big-endian value.
   function Word_Count (B : Stream_Element_Array) return Natural is
      First : Stream_Element_Offset := B'First;
   begin
      while First <= B'Last and then B (First) = 0 loop
         First := First + 1;
      end loop;
      if First > B'Last then
         return 1;                                    --  value is zero
      end if;
      return Natural (B'Last - First) / 4 + 1;
   end Word_Count;

   --  Big-endian bytes -> little-endian word array of exactly N words.
   function To_Words (B : Stream_Element_Array; N : Natural) return Word_Array is
      Result : Word_Array (0 .. N - 1) := [others => 0];
      Idx    : Natural := 0;                          --  byte index from LSB
   begin
      for I in reverse B'Range loop
         declare
            W_Index : constant Natural := Idx / 4;
            Shift   : constant Natural := (Idx mod 4) * 8;
         begin
            exit when W_Index > N - 1;
            Result (W_Index) :=
              Result (W_Index) or Shift_Left (Word (B (I)), Shift);
         end;
         Idx := Idx + 1;
      end loop;
      return Result;
   end To_Words;

   --  Little-endian words -> big-endian bytes of the requested length.
   function To_Bytes
     (W : Word_Array; Length : Stream_Element_Count) return Stream_Element_Array
   is
      Result : Stream_Element_Array (1 .. Length) := [others => 0];
   begin
      for Idx in 0 .. Natural (Length) - 1 loop
         declare
            W_Index : constant Natural := Idx / 4;
            Shift   : constant Natural := (Idx mod 4) * 8;
         begin
            if W_Index <= W'Last then
               Result (Result'Last - Stream_Element_Offset (Idx)) :=
                 Stream_Element (Shift_Right (W (W_Index), Shift) and 16#FF#);
            end if;
         end;
      end loop;
      return Result;
   end To_Bytes;

   --  True when X (N words) >= M (N words).
   function Geq (X, M : Word_Array) return Boolean is
   begin
      for J in reverse X'Range loop
         if X (J) > M (J) then
            return True;
         elsif X (J) < M (J) then
            return False;
         end if;
      end loop;
      return True;                                    --  equal
   end Geq;

   --  X - M mod 2**(32*N) (used when X >= M so no true borrow escapes).
   function Sub (X, M : Word_Array) return Word_Array is
      Result : Word_Array (X'Range);
      Borrow : DWord := 0;
   begin
      for J in X'Range loop
         declare
            D : constant DWord := DWord (X (J)) - DWord (M (J)) - Borrow;
         begin
            Result (J) := Word (D and Low_Mask);
            Borrow := Shift_Right (D, 63);            --  1 if underflow
         end;
      end loop;
      return Result;
   end Sub;

   --  X := (X * 2) mod M, for X < M.
   function Double_Mod (X, M : Word_Array) return Word_Array is
      Result : Word_Array (X'Range);
      Carry  : Word := 0;
   begin
      for J in X'Range loop
         declare
            Next_Carry : constant Word := Shift_Right (X (J), 31);
         begin
            Result (J) := Shift_Left (X (J), 1) or Carry;
            Carry := Next_Carry;
         end;
      end loop;
      if Carry /= 0 or else Geq (Result, M) then
         Result := Sub (Result, M);
      end if;
      return Result;
   end Double_Mod;

   --  -M(0)**(-1) mod 2**32, the CIOS per-word constant.  M(0) is odd.
   function N0_Inverse (M0 : Word) return Word is
      X : Word := 1;
   begin
      for Iteration in 1 .. 5 loop                    --  Newton: 2,4,8,16,32 bits
         X := X * (2 - M0 * X);
      end loop;
      return (not X) + 1;                             --  negate mod 2**32
   end N0_Inverse;

   --  Branchless select: returns A where Mask is all-ones, B where all-zero.
   function CT_Select (Mask : Word; A, B : Word_Array) return Word_Array is
      Result : Word_Array (A'Range);
   begin
      for J in A'Range loop
         Result (J) := (A (J) and Mask) or (B (J) and not Mask);
      end loop;
      return Result;
   end CT_Select;

   --  All-ones when X >= M, zero otherwise, with no data-dependent branch.
   function CT_Geq_Mask (X, M : Word_Array) return Word is
      Borrow : DWord := 0;
   begin
      for J in X'Range loop                            --  LSB .. MSB
         Borrow :=
           Shift_Right (DWord (X (J)) - DWord (M (J)) - Borrow, 63) and 1;
      end loop;
      return Word (Borrow) - 1;                         --  Borrow = 0 -> all-ones
   end CT_Geq_Mask;

   --  Montgomery product: A * B * R**(-1) mod M, with R = 2**(32*N).
   function Mont_Mul (A, B, M : Word_Array; N0 : Word) return Word_Array is
      N : constant Natural := M'Length;
      T : Word_Array (0 .. N + 1) := [others => 0];
   begin
      for I in 0 .. N - 1 loop
         declare
            Carry : DWord := 0;
         begin
            for J in 0 .. N - 1 loop
               declare
                  Sum : constant DWord :=
                    DWord (T (J)) + DWord (A (J)) * DWord (B (I)) + Carry;
               begin
                  T (J) := Word (Sum and Low_Mask);
                  Carry := Shift_Right (Sum, 32);
               end;
            end loop;
            declare
               Sum : constant DWord := DWord (T (N)) + Carry;
            begin
               T (N) := Word (Sum and Low_Mask);
               T (N + 1) := T (N + 1) + Word (Shift_Right (Sum, 32));
            end;
         end;

         declare
            M_Word : constant Word :=
              Word ((DWord (T (0)) * DWord (N0)) and Low_Mask);
            Carry  : DWord :=
              Shift_Right (DWord (T (0)) + DWord (M_Word) * DWord (M (0)), 32);
         begin
            for J in 1 .. N - 1 loop
               declare
                  Sum : constant DWord :=
                    DWord (T (J)) + DWord (M_Word) * DWord (M (J)) + Carry;
               begin
                  T (J - 1) := Word (Sum and Low_Mask);
                  Carry := Shift_Right (Sum, 32);
               end;
            end loop;
            declare
               Sum : constant DWord := DWord (T (N)) + Carry;
            begin
               T (N - 1) := Word (Sum and Low_Mask);
               T (N) := T (N + 1) + Word (Shift_Right (Sum, 32));
               T (N + 1) := 0;
            end;
         end;
      end loop;

      declare
         Result    : Word_Array (0 .. N - 1);
         Subtracted : Word_Array (0 .. N - 1);
         Do_Sub    : Word;
      begin
         for J in 0 .. N - 1 loop
            Result (J) := T (J);
         end loop;
         Subtracted := Sub (Result, M);
         --  Subtract M iff the CIOS overflow word is set or Result >= M.  T (N)
         --  is 0 or 1 (result < 2M), so (0 - T (N)) is the overflow mask.
         Do_Sub := (Word (0) - T (N)) or CT_Geq_Mask (Result, M);
         return CT_Select (Do_Sub, Subtracted, Result);
      end;
   end Mont_Mul;

   function Mod_Exp
     (Base     : Stream_Element_Array;
      Exponent : Stream_Element_Array;
      Modulus  : Stream_Element_Array)
      return Stream_Element_Array
   is
      N        : constant Natural := Word_Count (Modulus);
      M        : constant Word_Array := To_Words (Modulus, N);
      N0       : constant Word := N0_Inverse (M (0));
      Base_W    : Word_Array := To_Words (Base, N);
      Exp_Bytes : constant Natural := Natural (Exponent'Length);
      Exp_W     : constant Word_Array :=
        To_Words (Exponent, Natural'Max ((Exp_Bytes + 3) / 4, 1));
      One       : Word_Array (0 .. N - 1) := [others => 0];
      R2        : Word_Array (0 .. N - 1) := [others => 0];
      Result_M  : Word_Array (0 .. N - 1);
      Base_M    : Word_Array (0 .. N - 1);
   begin
      One (0) := 1;

      --  R**2 mod M = 2**(64*N) mod M, by repeated doubling from 1.
      R2 (0) := 1;
      for Count in 1 .. 64 * N loop
         R2 := Double_Mod (R2, M);
      end loop;

      --  Ensure Base < M (callers guarantee it, but stay safe).
      if Geq (Base_W, M) then
         Base_W := Sub (Base_W, M);
      end if;

      Base_M := Mont_Mul (Base_W, R2, M, N0);         --  Base * R mod M
      Result_M := Mont_Mul (One, R2, M, N0);          --  Montgomery form of 1

      --  Fixed-count square-and-multiply-ALWAYS over the full exponent width
      --  (the byte length is public); the multiply result is chosen by a
      --  branchless select, so timing is independent of the secret exponent.
      for Bit in reverse 0 .. 8 * Exp_Bytes - 1 loop
         Result_M := Mont_Mul (Result_M, Result_M, M, N0);
         declare
            Bit_Val : constant Word :=
              Shift_Right (Exp_W (Bit / 32), Bit mod 32) and 1;
            Product : constant Word_Array :=
              Mont_Mul (Result_M, Base_M, M, N0);
         begin
            Result_M := CT_Select (Word (0) - Bit_Val, Product, Result_M);
         end;
      end loop;

      return To_Bytes (Mont_Mul (Result_M, One, M, N0), Modulus'Length);
   end Mod_Exp;

end CryptoLib.Modexp;
