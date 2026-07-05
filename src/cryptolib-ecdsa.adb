with Interfaces; use Interfaces;
with CryptoLib.Hashes;
with CryptoLib.Macs;
with CryptoLib.EC_Arith; use CryptoLib.EC_Arith;
with CryptoLib.Modexp;
with CryptoLib.Secure_Wipe;
with System;

--  Constant-time ECDSA signer for NIST P-384 / P-521.  All arithmetic is
--  fixed-width and branchless (CryptoLib.EC_Arith Montgomery field/order
--  arithmetic; Renes-Costello-Batina complete projective point addition, which
--  has no exceptional cases; a fixed-length double-and-add-always ladder with
--  branchless point select).  The two modular inverses (Z**-1 mod p and
--  k**-1 mod n) go through the constant-time CryptoLib.Modexp (Fermat).  RFC
--  6979 deterministic nonces are unchanged apart from constant-time candidate
--  reduction/validation.
package body CryptoLib.ECDSA is

   use Ada.Streams;
   use CryptoLib.Errors;

   type Curve_Kind is (Nistp384, Nistp521);

   type Point is record
      X, Y, Z : Element;                       --  projective, Montgomery-p form
   end record;

   type Curve_Data is record
      Kind        : Curve_Kind;
      Byte_Length : Natural;
      Q_Bits      : Natural;
      Nonce_Shift : Natural;                    --  bits to drop from the nonce
      Field       : Context;                    --  mod p
      Order       : Context;                    --  mod n
      P_Bytes     : Stream_Element_Array (1 .. 66);
      N_Bytes     : Stream_Element_Array (1 .. 66);
      P_Minus_2   : Stream_Element_Array (1 .. 66);
      N_Minus_2   : Stream_Element_Array (1 .. 66);
      P_Len       : Natural;
      Base        : Point;
      B3_Mont     : Element;                    --  3*b in Montgomery-p form
      A3_Mont     : Element;                    --  a = -3 mod p, Montgomery-p
   end record;

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
   function Scalar_Mult (Cv : Curve_Data; K : Element) return Point is
      R : Point := (X => Zero, Y => One_Mont (Cv.Field), Z => Zero);
   begin
      for Bit in reverse 0 .. Cv.Q_Bits - 1 loop
         R := Point_Add (Cv.Field, Cv.A3_Mont, Cv.B3_Mont, R, R);
         declare
            Sum  : constant Point :=
              Point_Add (Cv.Field, Cv.A3_Mont, Cv.B3_Mont, R, Cv.Base);
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
   end Scalar_Mult;

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

   --  Right-shift an element by a fixed bit count (< 32); constant-time.
   function Shift_Bits (A : Element; N : Natural) return Element is
      R : Element := [others => 0];
   begin
      if N = 0 then
         return A;
      end if;
      for J in Element'Range loop
         R (J) := Shift_Right (A (J), N);
         if J < Element'Last then
            R (J) := R (J) or Shift_Left (A (J + 1), 32 - N);
         end if;
      end loop;
      return R;
   end Shift_Bits;

   function Digest_Array
     (Digest_Value : CryptoLib.Hashes.SHA384_Digest) return Stream_Element_Array
   is
      R : Stream_Element_Array (1 .. Digest_Value'Length);
      C : Stream_Element_Offset := R'First;
   begin
      for B of Digest_Value loop
         R (C) := B; C := C + 1;
      end loop;
      return R;
   end Digest_Array;

   function Digest_Array
     (Digest_Value : CryptoLib.Hashes.SHA512_Digest) return Stream_Element_Array
   is
      R : Stream_Element_Array (1 .. Digest_Value'Length);
      C : Stream_Element_Offset := R'First;
   begin
      for B of Digest_Value loop
         R (C) := B; C := C + 1;
      end loop;
      return R;
   end Digest_Array;

   function Hash_Data
     (Cv : Curve_Data; Message_Bytes : Stream_Element_Array)
      return Stream_Element_Array
   is
   begin
      case Cv.Kind is
         when Nistp384 =>
            return Digest_Array (CryptoLib.Hashes.SHA384 (Message_Bytes));
         when Nistp521 =>
            return Digest_Array (CryptoLib.Hashes.SHA512 (Message_Bytes));
      end case;
   end Hash_Data;

   function HMAC_Data
     (Cv : Curve_Data; Key_Data, Message_Data : Stream_Element_Array)
      return Stream_Element_Array
   is
   begin
      case Cv.Kind is
         when Nistp384 =>
            return Digest_Array
              (CryptoLib.Macs.HMAC_SHA384 (Key_Data, Message_Data));
         when Nistp521 =>
            return Digest_Array
              (CryptoLib.Macs.HMAC_SHA512 (Key_Data, Message_Data));
      end case;
   end HMAC_Data;

   --  Order-field octets of a value in [0, n).
   function Order_Octets (Cv : Curve_Data; V : Element) return Stream_Element_Array
   is
   begin
      return To_Bytes (Cv.Order, V);
   end Order_Octets;

   --  Deterministic RFC 6979 nonce: return the Counter-th accepted candidate
   --  in [1, n-1] as an order element.  HMAC-DRBG is unchanged; only the
   --  candidate reduction/validation is constant-time.
   function Nonce_For
     (Cv            : Curve_Data;
      Private_Octets : Stream_Element_Array;
      H_Octets       : Stream_Element_Array;
      Counter_Value  : Natural;
      Found          : out Boolean) return Element
   is
      DL : constant Natural := (if Cv.Kind = Nistp384 then 48 else 64);
      V_Data : Stream_Element_Array (1 .. Stream_Element_Offset (DL)) :=
        [others => 1];
      K_Data : Stream_Element_Array (1 .. Stream_Element_Offset (DL)) :=
        [others => 0];
      Seed : Stream_Element_Array
        (1 .. Stream_Element_Offset (DL + 1 + 2 * Cv.Byte_Length));
      Tail : Stream_Element_Array (1 .. Stream_Element_Offset (DL + 1));
      T_Data : Stream_Element_Array (1 .. Stream_Element_Offset (Cv.Byte_Length));
      Accepted : Natural := 0;
      Cursor : Stream_Element_Offset;
      T_Cursor : Stream_Element_Offset;
      Candidate : Element;
      Result : Element := Zero;

      procedure Build_Seed (Sep : Stream_Element) is
      begin
         Cursor := Seed'First;
         for B of V_Data loop
            Seed (Cursor) := B; Cursor := Cursor + 1;
         end loop;
         Seed (Cursor) := Sep; Cursor := Cursor + 1;
         for B of Private_Octets loop
            Seed (Cursor) := B; Cursor := Cursor + 1;
         end loop;
         for B of H_Octets loop
            Seed (Cursor) := B; Cursor := Cursor + 1;
         end loop;
      end Build_Seed;

      --  Scrub the HMAC-DRBG state and nonce copies (all derived from the
      --  private key) before returning; the accepted nonce leaves only via
      --  Result.  Closes over the locals so the real objects are wiped.
      procedure Scrub_State is
         use System;
      begin
         Secure_Wipe.Wipe (V_Data'Address, V_Data'Length);
         Secure_Wipe.Wipe (K_Data'Address, K_Data'Length);
         Secure_Wipe.Wipe (T_Data'Address, T_Data'Length);
         Secure_Wipe.Wipe (Seed'Address, Seed'Length);
         Secure_Wipe.Wipe (Tail'Address, Tail'Length);
         Secure_Wipe.Wipe (Candidate'Address, Candidate'Size / Storage_Unit);
      end Scrub_State;
   begin
      Found := False;
      Build_Seed (0);
      K_Data := HMAC_Data (Cv, K_Data, Seed);
      V_Data := HMAC_Data (Cv, K_Data, V_Data);
      Build_Seed (1);
      K_Data := HMAC_Data (Cv, K_Data, Seed);
      V_Data := HMAC_Data (Cv, K_Data, V_Data);

      for Attempt in 0 .. 511 loop
         T_Data := [others => 0];
         T_Cursor := T_Data'First;
         while T_Cursor <= T_Data'Last loop
            V_Data := HMAC_Data (Cv, K_Data, V_Data);
            for B of V_Data loop
               exit when T_Cursor > T_Data'Last;
               T_Data (T_Cursor) := B; T_Cursor := T_Cursor + 1;
            end loop;
         end loop;

         Candidate := Shift_Bits (From_Bytes (Cv.Order, T_Data), Cv.Nonce_Shift);
         if (Geq_Mask (Candidate, Modulus (Cv.Order)) = 0)
           and then (Is_Zero_Mask (Candidate) = 0)
         then
            if Accepted = Counter_Value then
               Result := Candidate;
               Found := True;
               Scrub_State;
               return Result;
            end if;
            Accepted := Accepted + 1;
         end if;

         Cursor := Tail'First;
         for B of V_Data loop
            Tail (Cursor) := B; Cursor := Cursor + 1;
         end loop;
         Tail (Cursor) := 0;
         K_Data := HMAC_Data (Cv, K_Data, Tail);
         V_Data := HMAC_Data (Cv, K_Data, V_Data);
      end loop;
      Scrub_State;
      return Result;
   end Nonce_For;

   --  Parse an mpint private scalar and validate it is in [1, n-1].
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
      if Data (First) = 0 then
         if Data'Length = 1 or else Data (First + 1) < 16#80# then
            return False;
         end if;
         First := First + 1;
      elsif Data (First) >= 16#80# then
         return False;
      end if;
      if Natural (Data'Last - First + 1) > Cv.Byte_Length then
         return False;
      end if;
      Value := From_Bytes (Cv.Order, Data (First .. Data'Last));
      return Geq_Mask (Value, Modulus (Cv.Order)) = 0
        and then Is_Zero_Mask (Value) = 0;
   end Parse_Private;

   function Sign_Raw
     (Cv                   : Curve_Data;
      Private_Scalar_Mpint : Stream_Element_Array;
      Message_Bytes        : Stream_Element_Array;
      R_Bytes              : out Stream_Element_Array;
      S_Bytes              : out Stream_Element_Array) return Status
   is
      D_Value : Element;
      Hash    : constant Stream_Element_Array := Hash_Data (Cv, Message_Bytes);
      H_Value : constant Element :=
        Add (Cv.Order, From_Bytes (Cv.Order, Hash), Zero);   --  h mod n
      H_Octets : constant Stream_Element_Array := Order_Octets (Cv, H_Value);
   begin
      R_Bytes := [others => 0];
      S_Bytes := [others => 0];
      if Natural (R_Bytes'Length) /= Cv.Byte_Length
        or else Natural (S_Bytes'Length) /= Cv.Byte_Length
      then
         return Handshake_Failed;
      end if;
      if not Parse_Private (Private_Scalar_Mpint, Cv, D_Value) then
         return Authentication_Failed;
      end if;

      for Counter in 0 .. 255 loop
         declare
            Found  : Boolean;
            K      : Element :=
              Nonce_For (Cv, Order_Octets (Cv, D_Value), H_Octets, Counter,
                         Found);
            R_Pt   : Point;
            Zn, Zi : Element;
            X_Aff  : Element;
            R_Val  : Element;
            K_Inv  : Element;
            S_Val  : Element;
         begin
            exit when not Found;
            R_Pt := Scalar_Mult (Cv, K);
            Zn := From_Mont (Cv.Field, R_Pt.Z);
            if Is_Zero_Mask (Zn) /= 0 then          --  point at infinity (never)
               goto Continue;
            end if;
            Zi := Inv_Mod (Zn, Low (Cv.P_Minus_2, Cv.P_Len),
                           Low (Cv.P_Bytes, Cv.P_Len), Cv.Field);
            --  affine x = X * Z**-1 (R_Pt.X Montgomery, Zi normal -> normal).
            X_Aff := Mont_Mul (Cv.Field, R_Pt.X, Zi);
            R_Val := Add (Cv.Order, From_Bytes (Cv.Order, To_Bytes (Cv.Field, X_Aff)), Zero);
            if Is_Zero_Mask (R_Val) /= 0 then
               goto Continue;
            end if;
            --  s = k**-1 (h + r*d) mod n
            K_Inv := Inv_Mod (K, Low (Cv.N_Minus_2, Cv.Byte_Length),
                              Low (Cv.N_Bytes, Cv.Byte_Length), Cv.Order);
            S_Val :=
              Mul_Mod (Cv.Order, K_Inv,
                       Add (Cv.Order, H_Value, Mul_Mod (Cv.Order, R_Val, D_Value)));
            if Is_Zero_Mask (S_Val) /= 0 then
               goto Continue;
            end if;
            R_Bytes := To_Bytes (Cv.Order, R_Val);
            S_Bytes := To_Bytes (Cv.Order, S_Val);
            --  Scrub the secret nonce, its inverse, and the private scalar.
            Secure_Wipe.Wipe (K'Address, K'Size / System.Storage_Unit);
            Secure_Wipe.Wipe (K_Inv'Address, K_Inv'Size / System.Storage_Unit);
            Secure_Wipe.Wipe (D_Value'Address, D_Value'Size / System.Storage_Unit);
            return Ok;
         end;
         <<Continue>>
      end loop;
      Secure_Wipe.Wipe (D_Value'Address, D_Value'Size / System.Storage_Unit);
      return Authentication_Failed;
   exception
      when others =>
         R_Bytes := [others => 0];
         S_Bytes := [others => 0];
         Secure_Wipe.Wipe (D_Value'Address, D_Value'Size / System.Storage_Unit);
         return Internal_Error;
   end Sign_Raw;

   function Sign_Nistp384_Raw
     (Private_Scalar_Mpint : Stream_Element_Array;
      Message_Bytes        : Stream_Element_Array;
      R_Bytes              : out Stream_Element_Array;
      S_Bytes              : out Stream_Element_Array) return Status is
   begin
      return Sign_Raw
        (P384_Curve, Private_Scalar_Mpint, Message_Bytes, R_Bytes, S_Bytes);
   end Sign_Nistp384_Raw;

   function Sign_Nistp521_Raw
     (Private_Scalar_Mpint : Stream_Element_Array;
      Message_Bytes        : Stream_Element_Array;
      R_Bytes              : out Stream_Element_Array;
      S_Bytes              : out Stream_Element_Array) return Status is
   begin
      return Sign_Raw
        (P521_Curve, Private_Scalar_Mpint, Message_Bytes, R_Bytes, S_Bytes);
   end Sign_Nistp521_Raw;

end CryptoLib.ECDSA;
