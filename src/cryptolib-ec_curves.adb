with Interfaces; use Interfaces;
with CryptoLib.Modexp;

package body CryptoLib.EC_Curves is

   use Ada.Streams;
   use CryptoLib.Errors;

   function Nib (Ch : Character) return Stream_Element is
     (case Ch is
         when '0' .. '9' => Character'Pos (Ch) - Character'Pos ('0'),
         when 'a' .. 'f' => Character'Pos (Ch) - Character'Pos ('a') + 10,
         when 'A' .. 'F' => Character'Pos (Ch) - Character'Pos ('A') + 10,
         when others => 0);

   function From_Hex (Text : String) return Stream_Element_Array is
      R : Stream_Element_Array (1 .. Stream_Element_Offset (Text'Length / 2));
   begin
      for I in R'Range loop
         R (I) :=
           Nib (Text (Text'First + Natural (I - 1) * 2)) * 16
           + Nib (Text (Text'First + Natural (I - 1) * 2 + 1));
      end loop;
      return R;
   end From_Hex;

   --  Copy a modulus into the fixed 66-byte slot (right-aligned) and derive
   --  modulus - 2 (all these moduli end in an odd byte >= 3, so no borrow).
   procedure Fill_Modulus
     (Hex   : String;
      Slot  : out Stream_Element_Array;
      Minus : out Stream_Element_Array)
   is
      Bytes : constant Stream_Element_Array := From_Hex (Hex);
   begin
      Slot := [others => 0];
      Slot (Slot'Last - Bytes'Length + 1 .. Slot'Last) := Bytes;
      Minus := Slot;
      Minus (Minus'Last) := Minus (Minus'Last) - 2;
   end Fill_Modulus;

   --  P-256, taken from the curve OpenSSL prints for prime256v1 rather than
   --  from memory. a is p - 3, which is what the shared point arithmetic
   --  assumes; a curve where it were not could not use A3_Mont.
   function P256_Curve return Curve_Data is
      Cv : Curve_Data;
      P_Hex : constant String :=
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
      N_Hex : constant String :=
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
      Gx : constant Stream_Element_Array := From_Hex
        ("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
      Gy : constant Stream_Element_Array := From_Hex
        ("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
      B_Bytes : constant Stream_Element_Array := From_Hex
        ("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
   begin
      Cv.Kind := Nistp256;
      Cv.Byte_Length := 32;
      Cv.Q_Bits := 256;
      Cv.Nonce_Shift := 0;
      Cv.P_Len := 32;
      Fill_Modulus (P_Hex, Cv.P_Bytes, Cv.P_Minus_2);
      Fill_Modulus (N_Hex, Cv.N_Bytes, Cv.N_Minus_2);
      Cv.Field := Make_Context (From_Hex (P_Hex));
      Cv.Order := Make_Context (From_Hex (N_Hex));
      Cv.Base :=
        (X => To_Mont (Cv.Field, From_Bytes (Cv.Field, Gx)),
         Y => To_Mont (Cv.Field, From_Bytes (Cv.Field, Gy)),
         Z => One_Mont (Cv.Field));
      declare
         B_El  : constant Element := From_Bytes (Cv.Field, B_Bytes);
         B3_El : constant Element :=
           Add (Cv.Field, B_El, Add (Cv.Field, B_El, B_El));
         Three : constant Element :=
           From_Bytes (Cv.Field, Stream_Element_Array'(1 => 3));
      begin
         Cv.B3_Mont := To_Mont (Cv.Field, B3_El);
         Cv.A3_Mont := To_Mont (Cv.Field, Sub (Cv.Field, Zero, Three));
      end;
      return Cv;
   end P256_Curve;

   function P384_Curve return Curve_Data is
      Cv : Curve_Data;
      P_Hex : constant String :=
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
        & "ffffffff0000000000000000ffffffff";
      N_Hex : constant String :=
        "ffffffffffffffffffffffffffffffffffffffffffffffff"
        & "c7634d81f4372ddf581a0db248b0a77aecec196accc52973";
      Gx : constant Stream_Element_Array := From_Hex
        ("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b98"
         & "59f741e082542a385502f25dbf55296c3a545e3872760ab7");
      Gy : constant Stream_Element_Array := From_Hex
        ("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147c"
         & "e9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f");
      B_Bytes : constant Stream_Element_Array := From_Hex
        ("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe814112"
         & "0314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef");
   begin
      Cv.Kind := Nistp384;
      Cv.Byte_Length := 48;
      Cv.Q_Bits := 384;
      Cv.Nonce_Shift := 0;
      Cv.P_Len := 48;
      Fill_Modulus (P_Hex, Cv.P_Bytes, Cv.P_Minus_2);
      Fill_Modulus (N_Hex, Cv.N_Bytes, Cv.N_Minus_2);
      Cv.Field := Make_Context (From_Hex (P_Hex));
      Cv.Order := Make_Context (From_Hex (N_Hex));
      Cv.Base :=
        (X => To_Mont (Cv.Field, From_Bytes (Cv.Field, Gx)),
         Y => To_Mont (Cv.Field, From_Bytes (Cv.Field, Gy)),
         Z => One_Mont (Cv.Field));
      declare
         B_El  : constant Element := From_Bytes (Cv.Field, B_Bytes);
         B3_El : constant Element :=
           Add (Cv.Field, B_El, Add (Cv.Field, B_El, B_El));
         Three : constant Element :=
           From_Bytes (Cv.Field, Stream_Element_Array'(1 => 3));
      begin
         Cv.B3_Mont := To_Mont (Cv.Field, B3_El);
         Cv.A3_Mont := To_Mont (Cv.Field, Sub (Cv.Field, Zero, Three));
      end;
      return Cv;
   end P384_Curve;

   function P521_Curve return Curve_Data is
      Cv : Curve_Data;
      P_Hex : constant String :=
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        & "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        & "ffff";
      N_Hex : constant String :=
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        & "fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138"
        & "6409";
      Gx : constant Stream_Element_Array := From_Hex
        ("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d"
         & "3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e"
         & "5bd66");
      Gy : constant Stream_Element_Array := From_Hex
        ("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e"
         & "662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd"
         & "16650");
      B_Bytes : constant Stream_Element_Array := From_Hex
        ("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1"
         & "09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b5"
         & "03f00");
   begin
      Cv.Kind := Nistp521;
      Cv.Byte_Length := 66;
      Cv.Q_Bits := 521;
      Cv.Nonce_Shift := 528 - 521;              --  66 bytes = 528 bits
      Cv.P_Len := 66;
      Fill_Modulus (P_Hex, Cv.P_Bytes, Cv.P_Minus_2);
      Fill_Modulus (N_Hex, Cv.N_Bytes, Cv.N_Minus_2);
      Cv.Field := Make_Context (From_Hex (P_Hex));
      Cv.Order := Make_Context (From_Hex (N_Hex));
      Cv.Base :=
        (X => To_Mont (Cv.Field, From_Bytes (Cv.Field, Gx)),
         Y => To_Mont (Cv.Field, From_Bytes (Cv.Field, Gy)),
         Z => One_Mont (Cv.Field));
      declare
         B_El  : constant Element := From_Bytes (Cv.Field, B_Bytes);
         B3_El : constant Element :=
           Add (Cv.Field, B_El, Add (Cv.Field, B_El, B_El));
         Three : constant Element :=
           From_Bytes (Cv.Field, Stream_Element_Array'(1 => 3));
      begin
         Cv.B3_Mont := To_Mont (Cv.Field, B3_El);
         Cv.A3_Mont := To_Mont (Cv.Field, Sub (Cv.Field, Zero, Three));
      end;
      return Cv;
   end P521_Curve;

   --  a*b mod modulus in the normal domain.
   function Mul_Mod (Ctx : Context; A, B : Element) return Element is
     (Mont_Mul (Ctx, To_Mont (Ctx, A), B));

   --  Renes-Costello-Batina complete addition (Algorithm 1, general a),
   --  projective, no exceptional cases: it doubles when P = Q and absorbs the
   --  identity (0:1:0).  A3 = a (= -3 mod p) and B3 = 3*b, both Montgomery-p.
   function Point_Add
     (F : Context; A3, B3 : Element; P, Q : Point) return Point
   is
      T0, T1, T2, T3, T4, T5, X3, Y3, Z3 : Element;
   begin
      T0 := Mont_Mul (F, P.X, Q.X);
      T1 := Mont_Mul (F, P.Y, Q.Y);
      T2 := Mont_Mul (F, P.Z, Q.Z);
      T3 := Add (F, P.X, P.Y);
      T4 := Add (F, Q.X, Q.Y);
      T3 := Mont_Mul (F, T3, T4);
      T4 := Add (F, T0, T1);
      T3 := Sub (F, T3, T4);
      T4 := Add (F, P.X, P.Z);
      T5 := Add (F, Q.X, Q.Z);
      T4 := Mont_Mul (F, T4, T5);
      T5 := Add (F, T0, T2);
      T4 := Sub (F, T4, T5);
      T5 := Add (F, P.Y, P.Z);
      X3 := Add (F, Q.Y, Q.Z);
      T5 := Mont_Mul (F, T5, X3);
      X3 := Add (F, T1, T2);
      T5 := Sub (F, T5, X3);
      Z3 := Mont_Mul (F, A3, T4);
      X3 := Mont_Mul (F, B3, T2);
      Z3 := Add (F, X3, Z3);
      X3 := Sub (F, T1, Z3);
      Z3 := Add (F, T1, Z3);
      Y3 := Mont_Mul (F, X3, Z3);
      T1 := Add (F, T0, T0);
      T1 := Add (F, T1, T0);
      T2 := Mont_Mul (F, A3, T2);
      T4 := Mont_Mul (F, B3, T4);
      T1 := Add (F, T1, T2);
      T2 := Sub (F, T0, T2);
      T2 := Mont_Mul (F, A3, T2);
      T4 := Add (F, T4, T2);
      T0 := Mont_Mul (F, T1, T4);
      Y3 := Add (F, Y3, T0);
      T0 := Mont_Mul (F, T5, T4);
      X3 := Mont_Mul (F, T3, X3);
      X3 := Sub (F, X3, T0);
      T0 := Mont_Mul (F, T3, T1);
      Z3 := Mont_Mul (F, T5, Z3);
      Z3 := Add (F, Z3, T0);
      return (X => X3, Y => Y3, Z => Z3);
   end Point_Add;

   --  Fixed-length double-and-add-always ladder with branchless point select.
   --  The ladder over any base, not only the generator: verification needs
   --  u1*G + u2*Q, and Q is whatever public key is being checked.
   function Scalar_Mult_Base
     (Cv : Curve_Data; K : Element; Base : Point) return Point
   is
      R : Point := (X => Zero, Y => One_Mont (Cv.Field), Z => Zero);
   begin
      for Bit in reverse 0 .. Cv.Q_Bits - 1 loop
         R := Point_Add (Cv.Field, Cv.A3_Mont, Cv.B3_Mont, R, R);
         declare
            Sum  : constant Point :=
              Point_Add (Cv.Field, Cv.A3_Mont, Cv.B3_Mont, R, Base);
            Bit_Val : constant Word :=
              Shift_Right (K (Bit / 32), Bit mod 32) and 1;
            Mask : constant Word := Word (0) - Bit_Val;
         begin
            R := (X => CT_Select (Mask, Sum.X, R.X),
                  Y => CT_Select (Mask, Sum.Y, R.Y),
                  Z => CT_Select (Mask, Sum.Z, R.Z));
         end;
      end loop;
      return R;
   end Scalar_Mult_Base;

   function Scalar_Mult (Cv : Curve_Data; K : Element) return Point is
     (Scalar_Mult_Base (Cv, K, Cv.Base));

   --  The low L bytes of a right-aligned modulus slot.
   function Low (S : Stream_Element_Array; L : Natural) return Stream_Element_Array
   is (S (S'Last - Stream_Element_Offset (L) + 1 .. S'Last));

   --  Modular inverse via the constant-time Modexp (Fermat).
   function Inv_Mod
     (Value : Element; Exp_BE, Mod_BE : Stream_Element_Array; Ctx : Context)
      return Element
   is
      V_Bytes : constant Stream_Element_Array := To_Bytes (Ctx, Value);
   begin
      return
        From_Bytes (Ctx, CryptoLib.Modexp.Mod_Exp (V_Bytes, Exp_BE, Mod_BE));
   end Inv_Mod;

   function Parse_Private
     (Data : Stream_Element_Array; Cv : Curve_Data; Value : out Element)
      return Boolean
   is
      First : Stream_Element_Offset := Data'First;
   begin
      Value := Zero;
      if Data'Length = 0 then
         return False;
      end if;

      while First <= Data'Last
        and then Natural (Data'Last - First + 1) > Cv.Byte_Length
        and then Data (First) = 0
      loop
         First := First + 1;
      end loop;

      if First > Data'Last
        or else Natural (Data'Last - First + 1) > Cv.Byte_Length
      then
         return False;
      end if;

      Value := From_Bytes (Cv.Order, Data (First .. Data'Last));
      return Geq_Mask (Value, Modulus (Cv.Order)) = 0
        and then Is_Zero_Mask (Value) = 0;
   end Parse_Private;

   function Affine_Point
     (Cv           : Curve_Data;
      D            : Element;
      Public_Point : out Stream_Element_Array) return Status
   is
      Pt : constant Point := Scalar_Mult (Cv, D);
      Zn : constant Element := From_Mont (Cv.Field, Pt.Z);
      Zi : Element;
   begin
      --  Zeroed here rather than left to the callers. Both of them happen to
      --  zero Public_Point before calling, so this changes nothing today --
      --  but the package promises a zeroed buffer on failure, and a helper
      --  that only keeps that promise when its caller already did is one
      --  edit away from breaking it silently.
      Public_Point := [others => 0];
      if Is_Zero_Mask (Zn) /= 0 then
         return CryptoLib.Errors.Authentication_Failed;
      end if;

      Zi := Inv_Mod (Zn, Low (Cv.P_Minus_2, Cv.P_Len),
                     Low (Cv.P_Bytes, Cv.P_Len), Cv.Field);

      declare
         X_Aff : constant Element := Mont_Mul (Cv.Field, Pt.X, Zi);
         Y_Aff : constant Element := Mont_Mul (Cv.Field, Pt.Y, Zi);
         X_By  : constant Stream_Element_Array := To_Bytes (Cv.Field, X_Aff);
         Y_By  : constant Stream_Element_Array := To_Bytes (Cv.Field, Y_Aff);
      begin
         Public_Point (Public_Point'First) := 16#04#;
         Public_Point
           (Public_Point'First + 1
            .. Public_Point'First + Stream_Element_Offset (Cv.P_Len)) := X_By;
         Public_Point
           (Public_Point'First + Stream_Element_Offset (Cv.P_Len) + 1
            .. Public_Point'Last) := Y_By;
      end;
      return CryptoLib.Errors.Ok;
   end Affine_Point;

   procedure Trim_To_Order
     (Cv : Curve_Data; Draw : in out Stream_Element_Array)
   is
      Excess : constant Natural := 8 * Cv.Byte_Length - Cv.Q_Bits;
   begin
      if Draw'Length = 0 or else Excess = 0 then
         return;
      end if;
      Draw (Draw'First) :=
        Draw (Draw'First) and Stream_Element (2 ** (8 - Excess) - 1);
   end Trim_To_Order;

   function Curve_Of (Kind : Curve_Kind) return Curve_Data
   is (case Kind is
          when Nistp256 => P256_Curve,
          when Nistp384 => P384_Curve,
          when Nistp521 => P521_Curve);

   --  The curve equation, multiplied through by 3:
   --
   --     y**2 = x**3 + ax + b   <=>   3y**2 = 3x**3 + 3ax + 3b
   --
   --  because 3 is invertible mod p. Written that way so the check can use
   --  B3_Mont, the 3*b the addition formula already needs, instead of
   --  recovering b from it. Recovering b would mean a modular inversion --
   --  slow, and the first version of this got its Montgomery domain wrong
   --  and rejected every valid point. Tripling is three additions, which
   --  are linear and so keep Montgomery form.
   --
   --  The point arrives with Z = 1, so the stored coordinates are the affine
   --  ones and nothing has to be normalized first.
   function On_Curve (Cv : Curve_Data; P : Point) return Boolean is
      function Triple (V : Element) return Element
      is (Add (Cv.Field, V, Add (Cv.Field, V, V)));

      X2  : constant Element := Mont_Mul (Cv.Field, P.X, P.X);
      X3  : constant Element := Mont_Mul (Cv.Field, X2, P.X);
      Y2  : constant Element := Mont_Mul (Cv.Field, P.Y, P.Y);
      A_X : constant Element := Mont_Mul (Cv.Field, Cv.A3_Mont, P.X);
      LHS : constant Element := Triple (Y2);
      RHS : constant Element :=
        Add (Cv.Field,
             Add (Cv.Field, Triple (X3), Triple (A_X)),
             Cv.B3_Mont);
   begin
      --  Z is zero only at infinity, which is never a valid peer key and
      --  must not reach a scalar multiplication.
      if Is_Zero_Mask (From_Mont (Cv.Field, P.Z)) /= 0 then
         return False;
      end if;
      return Equal_Mask (LHS, RHS) = All_Ones;
   end On_Curve;

   function Parse_Point
     (Cv      : Curve_Data;
      Encoded : Stream_Element_Array;
      P       : out Point) return Boolean
   is
      Width : constant Stream_Element_Offset :=
        Stream_Element_Offset (Cv.P_Len);
   begin
      P := (X => Zero, Y => Zero, Z => Zero);
      if Encoded'Length /= 2 * Width + 1
        or else Encoded (Encoded'First) /= 16#04#
      then
         return False;
      end if;
      declare
         X_Raw : constant Element :=
           From_Bytes (Cv.Field,
                       Encoded (Encoded'First + 1 .. Encoded'First + Width));
         Y_Raw : constant Element :=
           From_Bytes (Cv.Field,
                       Encoded (Encoded'First + Width + 1 .. Encoded'Last));
      begin
         --  From_Bytes packs octets and does not reduce, so a coordinate at
         --  or above p would be carried into the field arithmetic as itself
         --  and violate what every operation here assumes. It is also not a
         --  canonical encoding of anything: refused rather than reduced,
         --  since reducing would silently accept a second spelling of a
         --  point.
         if Geq_Mask (X_Raw, Modulus (Cv.Field)) /= 0
           or else Geq_Mask (Y_Raw, Modulus (Cv.Field)) /= 0
         then
            return False;
         end if;
         P := (X => To_Mont (Cv.Field, X_Raw),
               Y => To_Mont (Cv.Field, Y_Raw),
               Z => One_Mont (Cv.Field));
      end;
      return True;
   end Parse_Point;

   function Affine_X
     (Cv      : Curve_Data;
      P       : Point;
      X_Bytes : out Stream_Element_Array) return Boolean
   is
      Zn : constant Element := From_Mont (Cv.Field, P.Z);
      Zi : Element;
   begin
      X_Bytes := [others => 0];
      if X_Bytes'Length /= Stream_Element_Offset (Cv.P_Len) then
         return False;
      end if;
      if Is_Zero_Mask (Zn) /= 0 then
         return False;
      end if;
      Zi := Inv_Mod (Zn, Low (Cv.P_Minus_2, Cv.P_Len),
                     Low (Cv.P_Bytes, Cv.P_Len), Cv.Field);
      X_Bytes := To_Bytes (Cv.Field, Mont_Mul (Cv.Field, P.X, Zi));
      return True;
   end Affine_X;

end CryptoLib.EC_Curves;
