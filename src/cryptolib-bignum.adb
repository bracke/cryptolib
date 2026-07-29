with Interfaces; use Interfaces;

package body CryptoLib.Bignum is

   use Ada.Streams;

   subtype Offset is Stream_Element_Offset;

   --  The first octet that is not a leading zero, or one past the end for a
   --  number that is zero.
   function Value_First (Value : Octets) return Offset is
   begin
      for I in Value'Range loop
         if Value (I) /= 0 then
            return I;
         end if;
      end loop;
      return Value'Last + 1;
   end Value_First;

   function Is_Zero (Value : Octets) return Boolean
   is (Value_First (Value) > Value'Last);

   function Compare (Left, Right : Octets) return Integer is
      L_First : constant Offset := Value_First (Left);
      R_First : constant Offset := Value_First (Right);
      L_Len   : constant Offset := Left'Last - L_First + 1;
      R_Len   : constant Offset := Right'Last - R_First + 1;
   begin
      if L_Len /= R_Len then
         return (if L_Len < R_Len then -1 else 1);
      end if;
      for I in 0 .. L_Len - 1 loop
         if Left (L_First + I) /= Right (R_First + I) then
            return (if Left (L_First + I) < Right (R_First + I) then -1 else 1);
         end if;
      end loop;
      return 0;
   end Compare;

   function Add (Left, Right : Octets) return Octets is
      Width  : constant Offset :=
        Offset'Max (Left'Length, Right'Length) + 1;
      Result : Octets (1 .. Width) := [others => 0];
      Carry  : Unsigned_16 := 0;
      L_I    : Offset := Left'Last;
      R_I    : Offset := Right'Last;
   begin
      for I in reverse Result'Range loop
         declare
            Sum : Unsigned_16 := Carry;
         begin
            if L_I >= Left'First then
               Sum := Sum + Unsigned_16 (Left (L_I));
               L_I := L_I - 1;
            end if;
            if R_I >= Right'First then
               Sum := Sum + Unsigned_16 (Right (R_I));
               R_I := R_I - 1;
            end if;
            Result (I) := Stream_Element (Sum and 16#FF#);
            Carry := Shift_Right (Sum, 8);
         end;
      end loop;
      return Result;
   end Add;

   function Subtract (Left, Right : Octets) return Octets is
      Result : Octets (1 .. Left'Length) := [others => 0];
      Borrow : Integer := 0;
      R_I    : Offset := Right'Last;
      Out_I  : Offset := Result'Last;
   begin
      for I in reverse Left'Range loop
         declare
            Sub : Integer := Integer (Left (I)) - Borrow;
         begin
            if R_I >= Right'First then
               Sub := Sub - Integer (Right (R_I));
               R_I := R_I - 1;
            end if;
            if Sub < 0 then
               Sub := Sub + 256;
               Borrow := 1;
            else
               Borrow := 0;
            end if;
            Result (Out_I) := Stream_Element (Sub);
            Out_I := Out_I - 1;
         end;
      end loop;
      return Result;
   end Subtract;

   function Multiply (Left, Right : Octets) return Octets is
      Result : Octets (1 .. Left'Length + Right'Length) := [others => 0];
   begin
      if Left'Length = 0 or else Right'Length = 0 then
         return Result;
      end if;
      for I in reverse Left'Range loop
         declare
            Carry : Unsigned_32 := 0;
            Out_I : Offset :=
              Result'Last - (Left'Last - I);
         begin
            for J in reverse Right'Range loop
               declare
                  Cur : constant Unsigned_32 :=
                    Unsigned_32 (Left (I)) * Unsigned_32 (Right (J))
                    + Unsigned_32 (Result (Out_I)) + Carry;
               begin
                  Result (Out_I) := Stream_Element (Cur and 16#FF#);
                  Carry := Shift_Right (Cur, 8);
                  Out_I := Out_I - 1;
               end;
            end loop;
            while Carry /= 0 loop
               declare
                  Cur : constant Unsigned_32 :=
                    Unsigned_32 (Result (Out_I)) + Carry;
               begin
                  Result (Out_I) := Stream_Element (Cur and 16#FF#);
                  Carry := Shift_Right (Cur, 8);
                  Out_I := Out_I - 1;
               end;
            end loop;
         end;
      end loop;
      return Result;
   end Multiply;

   function Multiply_Small (Value : Octets; Factor : Natural) return Octets is
      Result : Octets (1 .. Value'Length + 4) := [others => 0];
      Carry  : Unsigned_64 := 0;
      Out_I  : Offset := Result'Last;
   begin
      for I in reverse Value'Range loop
         declare
            Cur : constant Unsigned_64 :=
              Unsigned_64 (Value (I)) * Unsigned_64 (Factor) + Carry;
         begin
            Result (Out_I) := Stream_Element (Cur and 16#FF#);
            Carry := Shift_Right (Cur, 8);
            Out_I := Out_I - 1;
         end;
      end loop;
      while Carry /= 0 and then Out_I >= Result'First loop
         Result (Out_I) := Stream_Element (Carry and 16#FF#);
         Carry := Shift_Right (Carry, 8);
         Out_I := Out_I - 1;
      end loop;
      return Result;
   end Multiply_Small;

   procedure Divide_Small
     (Value     : Octets;
      Divisor   : Positive;
      Quotient  : out Octets;
      Remainder : out Natural)
   is
      Running : Unsigned_64 := 0;
      Out_I   : Offset := Quotient'First;
   begin
      Quotient := [others => 0];
      Remainder := 0;
      if Quotient'Length /= Value'Length then
         return;
      end if;
      for I in Value'Range loop
         Running := Shift_Left (Running, 8) or Unsigned_64 (Value (I));
         Quotient (Out_I) :=
           Stream_Element (Running / Unsigned_64 (Divisor));
         Running := Running mod Unsigned_64 (Divisor);
         Out_I := Out_I + 1;
      end loop;
      Remainder := Natural (Running);
   end Divide_Small;

   function Mod_Small (Value : Octets; Divisor : Positive) return Natural is
      Running : Unsigned_64 := 0;
   begin
      for I in Value'Range loop
         Running :=
           (Shift_Left (Running, 8) or Unsigned_64 (Value (I)))
           mod Unsigned_64 (Divisor);
      end loop;
      return Natural (Running);
   end Mod_Small;

   function Subtract_Small (Value : Octets; Amount : Natural) return Octets is
      Small : Octets (1 .. 8) := [others => 0];
      Work  : Unsigned_64 := Unsigned_64 (Amount);
   begin
      for I in reverse Small'Range loop
         Small (I) := Stream_Element (Work and 16#FF#);
         Work := Shift_Right (Work, 8);
      end loop;
      return Subtract (Value, Small);
   end Subtract_Small;

   procedure Resize
     (Value  : Octets;
      Width  : Stream_Element_Offset;
      Result : out Octets;
      Fits   : out Boolean)
   is
      First : constant Offset := Value_First (Value);
      Len   : constant Offset := Value'Last - First + 1;
   begin
      Result := [others => 0];
      Fits := False;
      if Result'Length /= Width then
         return;
      end if;
      if First > Value'Last then
         Fits := True;                       --  zero fits any width
         return;
      end if;
      if Len > Width then
         return;
      end if;
      Result (Result'Last - Len + 1 .. Result'Last) :=
        Value (First .. Value'Last);
      Fits := True;
   end Resize;

   --  The inverse of a small value modulo a large one; see the spec for why
   --  this needs no general division. Modulus = q*Value + r makes r smaller
   --  than Value, so the extended Euclid below is Integer arithmetic, and
   --  substituting r = Modulus - q*Value back turns
   --  x*Value + y*r = 1 into (x - y*q)*Value + y*Modulus = 1: the inverse is
   --  x - y*q, and y is small.
   procedure Mod_Inverse_Small
     (Value   : Positive;
      Modulus : Octets;
      Inverse : out Octets;
      Ok      : out Boolean)
   is
      Q : Octets (Modulus'Range);
      R : Natural;

      G, X, Y : Integer;
      A, B    : Integer;
      X0, X1  : Integer := 0;
      Y0, Y1  : Integer := 0;
      Quot    : Integer;
      Temp    : Integer;
   begin
      Inverse := [others => 0];
      Ok := False;
      Divide_Small (Modulus, Value, Q, R);

      --  Extended Euclid on (e, r), iteratively.
      A := Value;
      B := R;
      X0 := 1; X1 := 0;
      Y0 := 0; Y1 := 1;
      while B /= 0 loop
         Quot := A / B;
         Temp := A - Quot * B; A := B; B := Temp;
         Temp := X0 - Quot * X1; X0 := X1; X1 := Temp;
         Temp := Y0 - Quot * Y1; Y0 := Y1; Y1 := Temp;
      end loop;
      G := A; X := X0; Y := Y0;
      if G /= 1 then
         return;
      end if;

      declare
         --  value = x - y*q, held as a sign and a magnitude so the octet
         --  arithmetic never has to represent a negative number. |y| < e and
         --  q is about Modulus/e, so the magnitude stays near Modulus and the
         --  reduction below takes a step or two at most.
         Width : constant Offset := Modulus'Length + 8;

         function Small (Amount : Natural) return Octets is
            Result : Octets (1 .. Width) := [others => 0];
            Work   : Natural := Amount;
         begin
            for I in reverse Result'Range loop
               exit when Work = 0;
               Result (I) := Stream_Element (Work mod 256);
               Work := Work / 256;
            end loop;
            return Result;
         end Small;

         Mag_YQ : Octets (1 .. Width) := [others => 0];
         Mag_X  : constant Octets := Small (abs X);
         Work   : Octets (1 .. Width) := [others => 0];
         Neg    : Boolean;
         Fits   : Boolean;
      begin
         Resize (Multiply_Small (Q, abs Y), Width, Mag_YQ, Fits);
         if not Fits then
            return;
         end if;

         if Y >= 0 then
            --  value = x - |y|*q
            if X >= 0 then
               if Compare (Mag_X, Mag_YQ) >= 0 then
                  Neg := False; Work := Subtract (Mag_X, Mag_YQ);
               else
                  Neg := True;  Work := Subtract (Mag_YQ, Mag_X);
               end if;
            else
               Neg := True;
               Resize (Add (Mag_YQ, Mag_X), Width, Work, Fits);
               if not Fits then
                  return;
               end if;
            end if;
         else
            --  value = x + |y|*q
            if X >= 0 then
               Neg := False;
               Resize (Add (Mag_YQ, Mag_X), Width, Work, Fits);
               if not Fits then
                  return;
               end if;
            elsif Compare (Mag_YQ, Mag_X) >= 0 then
               Neg := False; Work := Subtract (Mag_YQ, Mag_X);
            else
               Neg := True;  Work := Subtract (Mag_X, Mag_YQ);
            end if;
         end if;

         while Compare (Work, Modulus) >= 0 loop
            Work := Subtract (Work, Modulus);
         end loop;

         if Neg and then not Is_Zero (Work) then
            declare
               Folded : constant Octets := Subtract (Modulus, Work);
            begin
               Resize (Folded, Width, Work, Fits);
               if not Fits then
                  return;
               end if;
            end;
         end if;

         Resize (Work, Inverse'Length, Inverse, Fits);
         Ok := Fits;
      end;
   end Mod_Inverse_Small;

   procedure Mod_Inverse
     (Value   : Octets;
      Modulus : Octets;
      Inverse : out Octets;
      Ok      : out Boolean)
   is
      Width : constant Offset := Modulus'Length + 1;

      --  Everything is carried at one octet more than the modulus, so an
      --  intermediate (X + M) can be formed before it is halved.
      subtype Work_Value is Octets (1 .. Width);

      M    : Work_Value := [others => 0];
      U, V : Work_Value := [others => 0];
      X1, X2 : Work_Value := [others => 0];
      One  : Work_Value := [others => 0];
      Fits : Boolean;

      function Is_Even (Item : Work_Value) return Boolean
      is ((Item (Item'Last) and 1) = 0);

      --  Halve, and where the value is odd add the modulus first so the
      --  result stays the right residue. This is the whole trick that lets
      --  the algorithm work with shifts instead of divisions.
      procedure Halve_Mod (Item : in out Work_Value) is
         Remainder : Natural;
         Halved    : Work_Value;
      begin
         if not Is_Even (Item) then
            declare
               Summed : constant Octets := Add (Item, M);
               Sized  : Work_Value;
               Held   : Boolean;
            begin
               Resize (Summed, Width, Sized, Held);
               if not Held then
                  return;
               end if;
               Item := Sized;
            end;
         end if;
         Divide_Small (Item, 2, Halved, Remainder);
         Item := Halved;
      end Halve_Mod;

      --  Left := Left - Right, wrapped into [0, M).
      procedure Subtract_Mod (Left : in out Work_Value; Right : Work_Value) is
      begin
         if Compare (Left, Right) >= 0 then
            Left := Subtract (Left, Right);
         else
            declare
               Lifted : constant Octets := Add (Left, M);
               Sized  : Work_Value;
               Held   : Boolean;
            begin
               Resize (Lifted, Width, Sized, Held);
               if not Held then
                  return;
               end if;
               Left := Subtract (Sized, Right);
            end;
         end if;
      end Subtract_Mod;

      --  A bound on the iterations. The algorithm halves one side or reduces
      --  a difference every pass, so it finishes in a few times the bit
      --  length; the cap is a backstop against a malformed input spinning
      --  rather than a real limit.
      Rounds : constant Natural := 32 * Natural (Width) + 64;
   begin
      Inverse := [others => 0];
      Ok := False;

      if Is_Zero (Modulus) or else (Modulus (Modulus'Last) and 1) = 0 then
         return;                    --  Montgomery and this algorithm want odd
      end if;
      Resize (Modulus, Width, M, Fits);
      if not Fits then
         return;
      end if;
      One (One'Last) := 1;

      --  U starts at Value reduced below the modulus.
      Resize (Value, Width, U, Fits);
      if not Fits then
         return;
      end if;
      while Compare (U, M) >= 0 loop
         U := Subtract (U, M);
      end loop;
      if Is_Zero (U) then
         return;
      end if;
      V := M;
      X1 (X1'Last) := 1;            --  x1 = 1, x2 = 0

      for Round in 1 .. Rounds loop
         exit when Compare (U, One) = 0 or else Compare (V, One) = 0;
         --  Either side reaching zero means they shared a factor, and there
         --  is no inverse. Without this the halving loop below spins forever
         --  on a zero, which is exactly what it did.
         if Is_Zero (U) or else Is_Zero (V) then
            return;
         end if;
         while Is_Even (U) loop
            declare
               Halved : Work_Value;
               Rest   : Natural;
            begin
               Divide_Small (U, 2, Halved, Rest);
               U := Halved;
            end;
            Halve_Mod (X1);
         end loop;
         while Is_Even (V) loop
            declare
               Halved : Work_Value;
               Rest   : Natural;
            begin
               Divide_Small (V, 2, Halved, Rest);
               V := Halved;
            end;
            Halve_Mod (X2);
         end loop;
         if Compare (U, V) >= 0 then
            U := Subtract (U, V);
            Subtract_Mod (X1, X2);
         else
            V := Subtract (V, U);
            Subtract_Mod (X2, X1);
         end if;
      end loop;

      declare
         Answer : Work_Value :=
           (if Compare (U, One) = 0 then X1 else X2);
      begin
         if Compare (U, One) /= 0 and then Compare (V, One) /= 0 then
            return;                 --  no inverse: they share a factor
         end if;
         while Compare (Answer, M) >= 0 loop
            Answer := Subtract (Answer, M);
         end loop;
         Resize (Answer, Inverse'Length, Inverse, Fits);
         Ok := Fits and then not Is_Zero (Inverse);
         if not Ok then
            Inverse := [others => 0];
         end if;
      end;
   end Mod_Inverse;

   function Bit_Length (Value : Octets) return Natural is
      First : constant Offset := Value_First (Value);
      Top   : Stream_Element;
      Bits  : Natural;
   begin
      if First > Value'Last then
         return 0;
      end if;
      Top := Value (First);
      Bits := 0;
      while Top /= 0 loop
         Bits := Bits + 1;
         Top := Top / 2;
      end loop;
      return Bits + 8 * Natural (Value'Last - First);
   end Bit_Length;

end CryptoLib.Bignum;
