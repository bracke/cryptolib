with Interfaces; use Interfaces;
with CryptoLib.Hashes;
with CryptoLib.Macs;
with CryptoLib.EC_Arith; use CryptoLib.EC_Arith;
with CryptoLib.EC_Curves; use CryptoLib.EC_Curves;
with CryptoLib.Modexp;
with CryptoLib.Secure_Wipe;
with System;

--  Constant-time ECDSA signer for NIST P-256 / P-384 / P-521.  All arithmetic is
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
     (Digest_Value : CryptoLib.Hashes.SHA256_Digest) return Stream_Element_Array
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

   function Hash_For
     (Digest : Digest_Id; Message_Bytes : Stream_Element_Array)
      return Stream_Element_Array
   is
   begin
      case Digest is
         when SHA256 =>
            return Digest_Array (CryptoLib.Hashes.SHA256 (Message_Bytes));
         when SHA384 =>
            return Digest_Array (CryptoLib.Hashes.SHA384 (Message_Bytes));
         when SHA512 =>
            return Digest_Array (CryptoLib.Hashes.SHA512 (Message_Bytes));
      end case;
   end Hash_For;

   --  The digest a curve's own algorithms pair with, for the signing paths
   --  and for the fixed-curve verify entry points.
   function Matching_Digest (Cv : Curve_Data) return Digest_Id
   is (case Cv.Kind is
          when Nistp256 => SHA256,
          when Nistp384 => SHA384,
          when Nistp521 => SHA512);

   --  ECDSA uses the leftmost bits of the digest, so a hash wider than the
   --  order is cut rather than reduced. Every curve here has an order whose
   --  width in octets is at least that of the digests it is used with, save
   --  where this cuts.
   function Hash_Data
     (Cv : Curve_Data; Message_Bytes : Stream_Element_Array)
      return Stream_Element_Array
   is
   begin
      return Hash_For (Matching_Digest (Cv), Message_Bytes);
   end Hash_Data;

   function Hash_Data
     (Cv            : Curve_Data;
      Digest        : Digest_Id;
      Message_Bytes : Stream_Element_Array) return Stream_Element_Array
   is
      Full : constant Stream_Element_Array :=
        Hash_For (Digest, Message_Bytes);
      Wide : constant Stream_Element_Offset :=
        Stream_Element_Offset (Cv.Byte_Length);
   begin
      if Full'Length <= Wide then
         return Full;
      end if;
      return Full (Full'First .. Full'First + Wide - 1);
   end Hash_Data;

   function HMAC_Data
     (Cv : Curve_Data; Key_Data, Message_Data : Stream_Element_Array)
      return Stream_Element_Array
   is
   begin
      case Cv.Kind is
         when Nistp256 =>
            return Digest_Array
              (CryptoLib.Macs.HMAC_SHA256 (Key_Data, Message_Data));
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
      --  The DRBG runs under the digest the curve pairs with, so its state is
      --  exactly that digest's width. Spelled as a case over the digest rather
      --  than as a two-way test on the curve: the earlier "P-384 or else 64"
      --  read correctly while P-384 and P-521 were the only curves, and gave
      --  P-256 a 64-byte state the moment it was added -- HMAC-SHA-256 returns
      --  32, and every P-256 signature died in the size check and came back
      --  Internal_Error. A case over Digest_Id cannot acquire a wrong default,
      --  because a new digest fails to compile until it is answered for.
      DL : constant Natural :=
        (case Matching_Digest (Cv) is
            when SHA256 => 32,
            when SHA384 => 48,
            when SHA512 => 64);
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
   --  Read a private scalar, however it was written.
   --
   --  Two encodings arrive here and both are legitimate. An SSH mpint pads a
   --  value whose top bit is set with a leading zero octet, so it is one
   --  wider than the curve; a raw scalar is exactly the curve's width
   --  whatever its top byte happens to be. They are told apart by length,
   --  which is the only thing that distinguishes them.
   --
   --  Reading the first byte instead is what this did before, and it refused
   --  any raw scalar of 16#80# or above -- about half of every P-384 key
   --  generated anywhere else. This crate did not notice because its own
   --  generation only produced scalars the old reading accepted, so keys made
   --  here worked and keys made by OpenSSL failed on a coin toss.
   --
   --  Leading zeros are stripped only while the value is too wide to be the
   --  scalar, so a raw scalar that genuinely begins with a zero octet keeps
   --  it. Non-minimal padding is accepted rather than refused: unlike a
   --  signature, a private scalar has no canonical encoding whose violation
   --  means anything, and the value is the same either way.
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

   function Sign_Nistp256_Raw
     (Private_Scalar_Mpint : Stream_Element_Array;
      Message_Bytes        : Stream_Element_Array;
      R_Bytes              : out Stream_Element_Array;
      S_Bytes              : out Stream_Element_Array) return Status is
   begin
      return Sign_Raw
        (P256_Curve, Private_Scalar_Mpint, Message_Bytes, R_Bytes, S_Bytes);
   end Sign_Nistp256_Raw;

   function Sign_Nistp521_Raw
     (Private_Scalar_Mpint : Stream_Element_Array;
      Message_Bytes        : Stream_Element_Array;
      R_Bytes              : out Stream_Element_Array;
      S_Bytes              : out Stream_Element_Array) return Status is
   begin
      return Sign_Raw
        (P521_Curve, Private_Scalar_Mpint, Message_Bytes, R_Bytes, S_Bytes);
   end Sign_Nistp521_Raw;

   --  Projective (X/Z, Y/Z), so one inversion gives both affine coordinates.
   --  One body for every curve, so a fix to it cannot reach one and miss
   --  another.
   function Public_Key_Raw
     (Curve                : Curve_Id;
      Private_Scalar_Mpint : Stream_Element_Array;
      Public_Point         : out Stream_Element_Array)
      return Status
   is
      Cv : constant Curve_Data :=
        (case Curve is
            when Nistp256 => P256_Curve,
            when Nistp384 => P384_Curve,
            when Nistp521 => P521_Curve);
      D  : Element;
   begin
      Public_Point := [others => 0];
      if Public_Point'Length /= 2 * Stream_Element_Offset (Cv.P_Len) + 1 then
         return CryptoLib.Errors.Handshake_Failed;
      end if;
      if not Parse_Private (Private_Scalar_Mpint, Cv, D) then
         return CryptoLib.Errors.Authentication_Failed;
      end if;
      return Affine_Point (Cv, D, Public_Point);
   end Public_Key_Raw;

   function Public_Nistp384_Raw
     (Private_Scalar_Mpint : Stream_Element_Array;
      Public_Point         : out Stream_Element_Array)
      return Status
   is
   begin
      return Public_Key_Raw (Nistp384, Private_Scalar_Mpint, Public_Point);
   end Public_Nistp384_Raw;

   --  One body for both curves, so the rejection-sampling argument below
   --  cannot be right for one and quietly wrong for the other.
   function Generate_Keypair
     (Cv             : Curve_Data;
      Rng            : in out CryptoLib.Random.Random_Source;
      Private_Scalar : out Stream_Element_Array;
      Public_Point   : out Stream_Element_Array)
      return Status
   is
      Attempts : constant := 64;
      D        : Element;
   begin
      Private_Scalar := [others => 0];
      Public_Point := [others => 0];
      if Private_Scalar'Length /= Stream_Element_Offset (Cv.Byte_Length)
        or else Public_Point'Length /= 2 * Stream_Element_Offset (Cv.P_Len) + 1
      then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      --  A uniform draw is only a valid scalar when it lands in [1, n-1].
      --  Rejecting and redrawing keeps the distribution honest, where reducing
      --  mod n would bias it.
      for Attempt in 1 .. Attempts loop
         if CryptoLib.Random.Fill (Rng, Private_Scalar) /= CryptoLib.Errors.Ok
         then
            return CryptoLib.Errors.Internal_Error;
         end if;
         Trim_To_Order (Cv, Private_Scalar);
         if Parse_Private (Private_Scalar, Cv, D) then
            return Affine_Point (Cv, D, Public_Point);
         end if;
      end loop;

      Private_Scalar := [others => 0];
      return CryptoLib.Errors.Internal_Error;
   end Generate_Keypair;

   function Generate_Nistp384_Keypair
     (Rng            : in out CryptoLib.Random.Random_Source;
      Private_Scalar : out Stream_Element_Array;
      Public_Point   : out Stream_Element_Array)
      return Status
   is
   begin
      return Generate_Keypair (P384_Curve, Rng, Private_Scalar, Public_Point);
   end Generate_Nistp384_Keypair;

   function Generate_Nistp256_Keypair
     (Rng            : in out CryptoLib.Random.Random_Source;
      Private_Scalar : out Stream_Element_Array;
      Public_Point   : out Stream_Element_Array)
      return Status
   is
   begin
      return Generate_Keypair (P256_Curve, Rng, Private_Scalar, Public_Point);
   end Generate_Nistp256_Keypair;

   --  Verification is public arithmetic: r and s are on the wire and the key is
   --  published, so nothing here is secret and the constant-time discipline the
   --  signer needs does not apply. It reuses the same primitives regardless.
   --  The verification is the same on every curve; only the parameters
   --  differ. Kept as one body so that a fix to it cannot reach one curve and
   --  miss another.
   function Verify_Raw
     (Cv            : Curve_Data;
      Digest        : Digest_Id;
      Public_Point  : Stream_Element_Array;
      Message_Bytes : Stream_Element_Array;
      R_Bytes       : Stream_Element_Array;
      S_Bytes       : Stream_Element_Array) return Status
   is
      Length : constant Stream_Element_Offset :=
        Stream_Element_Offset (Cv.Byte_Length);
      P_Len  : constant Stream_Element_Offset :=
        Stream_Element_Offset (Cv.P_Len);

      function In_Range (Value : Element) return Boolean is
        (Is_Zero_Mask (Value) = 0
         and then Geq_Mask (Value, Modulus (Cv.Order)) = 0);

      R_Value, S_Value : Element;
      Q                : Point;
   begin
      if Public_Point'Length /= 2 * P_Len + 1
        or else R_Bytes'Length /= Length
        or else S_Bytes'Length /= Length
      then
         return Handshake_Failed;
      end if;

      --  Only the uncompressed form; a compressed point would have to be
      --  decompressed, and nothing here emits one.
      if Public_Point (Public_Point'First) /= 16#04# then
         return Authentication_Failed;
      end if;

      R_Value := From_Bytes (Cv.Order, R_Bytes);
      S_Value := From_Bytes (Cv.Order, S_Bytes);
      if not In_Range (R_Value) or else not In_Range (S_Value) then
         return Authentication_Failed;
      end if;

      --  The public point has to be on the curve, and nothing above
      --  establishes that: the coordinates arrive as bytes and were turned
      --  into field elements without anything checking they satisfy the
      --  curve equation.
      --
      --  It matters wherever the key is the attacker's to choose rather than
      --  something a CA already vouched for -- a self-signed certificate, or
      --  a certificate request, where the signature is the only evidence the
      --  requester holds the key. Verifying against a point off the curve is
      --  arithmetic in a group nobody chose, and the guarantee that only the
      --  private key could have produced the signature does not survive it.
      declare
         X_Raw : constant Element :=
           From_Bytes
             (Cv.Field,
              Public_Point (Public_Point'First + 1
                            .. Public_Point'First + P_Len));
         Y_Raw : constant Element :=
           From_Bytes
             (Cv.Field,
              Public_Point (Public_Point'First + P_Len + 1
                            .. Public_Point'Last));
         P_Mod : constant Element := Modulus (Cv.Field);

         X_M : constant Element := To_Mont (Cv.Field, X_Raw);
         Y_M : constant Element := To_Mont (Cv.Field, Y_Raw);

         --  a is -3 on all three curves, so 3 is its negation, and only 3*b
         --  is carried. Checking 3*y^2 = 3*x^3 + 3*a*x + 3*b keeps to what
         --  the curve data holds.
         Three_M : constant Element := Sub (Cv.Field, Zero, Cv.A3_Mont);
         Left    : constant Element :=
           Mont_Mul (Cv.Field, Three_M, Mont_Mul (Cv.Field, Y_M, Y_M));
         X_Cubed : constant Element :=
           Mont_Mul (Cv.Field, Mont_Mul (Cv.Field, X_M, X_M), X_M);
         Right   : constant Element :=
           Add (Cv.Field,
                Add (Cv.Field,
                     Mont_Mul (Cv.Field, Three_M, X_Cubed),
                     Mont_Mul (Cv.Field, Three_M,
                               Mont_Mul (Cv.Field, Cv.A3_Mont, X_M))),
                Cv.B3_Mont);
      begin
         --  Coordinates outside the field are not coordinates.
         if Geq_Mask (X_Raw, P_Mod) /= 0
           or else Geq_Mask (Y_Raw, P_Mod) /= 0
         then
            return Authentication_Failed;
         end if;

         --  Compared after Add (.., Zero) on both sides, which is how the
         --  rest of this file normalises before Equal_Mask: a Montgomery
         --  result is not necessarily the least residue, so two equal field
         --  elements can hold different representations and compare unequal.
         --  Without it this rejected perfectly good keys, and which ones
         --  depended on the values.
         if Equal_Mask
              (Add (Cv.Field, Left, Zero), Add (Cv.Field, Right, Zero))
            /= All_Ones
         then
            return Authentication_Failed;
         end if;
      end;

      Q :=
        (X => To_Mont
                (Cv.Field,
                 From_Bytes
                   (Cv.Field,
                    Public_Point (Public_Point'First + 1
                                  .. Public_Point'First + P_Len))),
         Y => To_Mont
                (Cv.Field,
                 From_Bytes
                   (Cv.Field,
                    Public_Point (Public_Point'First + P_Len + 1
                                  .. Public_Point'Last))),
         Z => One_Mont (Cv.Field));

      declare
         Hash    : constant Stream_Element_Array :=
           Hash_Data (Cv, Digest, Message_Bytes);
         H_Value : constant Element :=
           Add (Cv.Order, From_Bytes (Cv.Order, Hash), Zero);
         S_Inv   : constant Element :=
           Inv_Mod (S_Value, Low (Cv.N_Minus_2, Cv.Byte_Length),
                    Low (Cv.N_Bytes, Cv.Byte_Length), Cv.Order);
         U1      : constant Element := Mul_Mod (Cv.Order, H_Value, S_Inv);
         U2      : constant Element := Mul_Mod (Cv.Order, R_Value, S_Inv);
         Sum     : constant Point :=
           Point_Add
             (Cv.Field, Cv.A3_Mont, Cv.B3_Mont,
              Scalar_Mult (Cv, U1),
              Scalar_Mult_Base (Cv, U2, Q));
         Zn      : constant Element := From_Mont (Cv.Field, Sum.Z);
         Zi      : Element;
         X_Aff   : Element;
      begin
         if Is_Zero_Mask (Zn) /= 0 then
            return Authentication_Failed;      --  the point at infinity
         end if;

         Zi := Inv_Mod (Zn, Low (Cv.P_Minus_2, Cv.P_Len),
                        Low (Cv.P_Bytes, Cv.P_Len), Cv.Field);
         X_Aff := Mont_Mul (Cv.Field, Sum.X, Zi);

         if Equal_Mask
              (Add (Cv.Order,
                    From_Bytes (Cv.Order, To_Bytes (Cv.Field, X_Aff)), Zero),
               R_Value) = All_Ones
         then
            return CryptoLib.Errors.Ok;
         end if;
         return Authentication_Failed;
      end;
   end Verify_Raw;

   function Verify_Signature
     (Curve         : Curve_Id;
      Digest        : Digest_Id;
      Public_Point  : Stream_Element_Array;
      Message_Bytes : Stream_Element_Array;
      R_Bytes       : Stream_Element_Array;
      S_Bytes       : Stream_Element_Array) return Status
   is
      Cv : constant Curve_Data :=
        (case Curve is
            when Nistp256 => P256_Curve,
            when Nistp384 => P384_Curve,
            when Nistp521 => P521_Curve);
   begin
      return Verify_Raw
        (Cv, Digest, Public_Point, Message_Bytes, R_Bytes, S_Bytes);
   end Verify_Signature;

   function Verify_Nistp256_Raw
     (Public_Point  : Stream_Element_Array;
      Message_Bytes : Stream_Element_Array;
      R_Bytes       : Stream_Element_Array;
      S_Bytes       : Stream_Element_Array) return Status
   is
   begin
      return Verify_Raw
        (P256_Curve, Matching_Digest (P256_Curve),
         Public_Point, Message_Bytes, R_Bytes, S_Bytes);
   end Verify_Nistp256_Raw;

   function Verify_Nistp384_Raw
     (Public_Point  : Stream_Element_Array;
      Message_Bytes : Stream_Element_Array;
      R_Bytes       : Stream_Element_Array;
      S_Bytes       : Stream_Element_Array) return Status
   is
   begin
      return Verify_Raw
        (P384_Curve, Matching_Digest (P384_Curve),
         Public_Point, Message_Bytes, R_Bytes, S_Bytes);
   end Verify_Nistp384_Raw;

   function Verify_Nistp521_Raw
     (Public_Point  : Stream_Element_Array;
      Message_Bytes : Stream_Element_Array;
      R_Bytes       : Stream_Element_Array;
      S_Bytes       : Stream_Element_Array) return Status
   is
   begin
      return Verify_Raw
        (P521_Curve, Matching_Digest (P521_Curve),
         Public_Point, Message_Bytes, R_Bytes, S_Bytes);
   end Verify_Nistp521_Raw;

end CryptoLib.ECDSA;
