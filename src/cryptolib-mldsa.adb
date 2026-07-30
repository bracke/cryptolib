with Ada.Streams; use Ada.Streams;
with CryptoLib.SHA3;

package body CryptoLib.MLDSA is

   use CryptoLib.Errors;

   Q : constant := 8380417;          --  2**23 - 2**13 + 1
   N : constant := 256;              --  polynomial degree
   D : constant := 13;               --  dropped bits in Power2Round

   subtype Coefficient is Integer range -(Q - 1) .. Q - 1;
   subtype Poly_Index is Natural range 0 .. N - 1;
   type Poly is array (Poly_Index) of Coefficient;
   type Poly_Vector is array (Natural range <>) of Poly;

   --  Everything the three parameter sets differ in.
   type Parameters is record
      K, L    : Positive;            --  matrix dimensions
      Eta     : Positive;            --  secret coefficient bound
      Tau     : Positive;            --  non-zero coefficients in the challenge
      Beta    : Positive;            --  Tau * Eta
      Gamma1  : Positive;            --  mask range
      Gamma2  : Positive;            --  decomposition modulus
      Omega   : Positive;            --  hint weight ceiling
      C_Bytes : Positive;            --  challenge digest length
      PK_Len  : Positive;
      SK_Len  : Positive;
      Sig_Len : Positive;
   end record;

   function Params (Set : Parameter_Set) return Parameters is
     (case Set is
         when ML_DSA_44 =>
           (K => 4, L => 4, Eta => 2, Tau => 39, Beta => 78,
            Gamma1 => 2 ** 17, Gamma2 => (Q - 1) / 88, Omega => 80,
            C_Bytes => 32,
            PK_Len => 1312, SK_Len => 2560, Sig_Len => 2420),
         when ML_DSA_65 =>
           (K => 6, L => 5, Eta => 4, Tau => 49, Beta => 196,
            Gamma1 => 2 ** 19, Gamma2 => (Q - 1) / 32, Omega => 55,
            C_Bytes => 48,
            PK_Len => 1952, SK_Len => 4032, Sig_Len => 3309),
         when ML_DSA_87 =>
           (K => 8, L => 7, Eta => 2, Tau => 60, Beta => 120,
            Gamma1 => 2 ** 19, Gamma2 => (Q - 1) / 32, Omega => 75,
            C_Bytes => 64,
            PK_Len => 2592, SK_Len => 4896, Sig_Len => 4627));

   function Public_Key_Length (Set : Parameter_Set) return Positive is
     (Params (Set).PK_Len);
   function Private_Key_Length (Set : Parameter_Set) return Positive is
     (Params (Set).SK_Len);
   function Signature_Length (Set : Parameter_Set) return Positive is
     (Params (Set).Sig_Len);

   --  The NTT constants: zeta**bit_reverse_8(i) mod q, with zeta = 1753 a
   --  primitive 512th root of unity. Generated from that definition and
   --  checked (zeta**512 = 1, zeta**256 /= 1) rather than transcribed.
   Zetas : constant array (0 .. 255) of Coefficient :=
     [1, 4808194, 3765607, 3761513, 5178923, 5496691,
      5234739, 5178987, 7778734, 3542485, 2682288, 2129892,
      3764867, 7375178, 557458, 7159240, 5010068, 4317364,
      2663378, 6705802, 4855975, 7946292, 676590, 7044481,
      5152541, 1714295, 2453983, 1460718, 7737789, 4795319,
      2815639, 2283733, 3602218, 3182878, 2740543, 4793971,
      5269599, 2101410, 3704823, 1159875, 394148, 928749,
      1095468, 4874037, 2071829, 4361428, 3241972, 2156050,
      3415069, 1759347, 7562881, 4805951, 3756790, 6444618,
      6663429, 4430364, 5483103, 3192354, 556856, 3870317,
      2917338, 1853806, 3345963, 1858416, 3073009, 1277625,
      5744944, 3852015, 4183372, 5157610, 5258977, 8106357,
      2508980, 2028118, 1937570, 4564692, 2811291, 5396636,
      7270901, 4158088, 1528066, 482649, 1148858, 5418153,
      7814814, 169688, 2462444, 5046034, 4213992, 4892034,
      1987814, 5183169, 1736313, 235407, 5130263, 3258457,
      5801164, 1787943, 5989328, 6125690, 3482206, 4197502,
      7080401, 6018354, 7062739, 2461387, 3035980, 621164,
      3901472, 7153756, 2925816, 3374250, 1356448, 5604662,
      2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
      348812, 8052569, 1011223, 6026202, 4561790, 6458164,
      6143691, 1744507, 1753, 6444997, 5720892, 6924527,
      2660408, 6600190, 8321269, 2772600, 1182243, 87208,
      636927, 4415111, 4423672, 6084020, 5095502, 4663471,
      8352605, 822541, 1009365, 5926272, 6400920, 1596822,
      4423473, 4620952, 6695264, 4969849, 2678278, 4611469,
      4829411, 635956, 8129971, 5925040, 4234153, 6607829,
      2192938, 6653329, 2387513, 4768667, 8111961, 5199961,
      3747250, 2296099, 1239911, 4541938, 3195676, 2642980,
      1254190, 8368000, 2998219, 141835, 8291116, 2513018,
      7025525, 613238, 7070156, 6161950, 7921677, 6458423,
      4040196, 4908348, 2039144, 6500539, 7561656, 6201452,
      6757063, 2105286, 6006015, 6346610, 586241, 7200804,
      527981, 5637006, 6903432, 1994046, 2491325, 6987258,
      507927, 7192532, 7655613, 6545891, 5346675, 8041997,
      2647994, 3009748, 5767564, 4148469, 749577, 4357667,
      3980599, 2569011, 6764887, 1723229, 1665318, 2028038,
      1163598, 5011144, 3994671, 8368538, 7009900, 3020393,
      3363542, 214880, 545376, 7609976, 3105558, 7277073,
      508145, 7826699, 860144, 3430436, 140244, 6866265,
      6195333, 3123762, 2358373, 6187330, 5365997, 6663603,
      2926054, 7987710, 8077412, 3531229, 4405932, 4606686,
      1900052, 7598542, 1054478, 7648983];

   --  Reduce into 0 .. Q-1.
   function Mod_Q (Value : Integer) return Coefficient is
      R : Integer := Value mod Q;
   begin
      if R < 0 then
         R := R + Q;
      end if;
      return R;
   end Mod_Q;

   --  The representative in (-q/2, q/2], which is what the signature encoding
   --  and the norm checks are stated in terms of. Reduced form is 0 .. q-1,
   --  and packing that directly underflows the field width.
   function Centred (Value : Coefficient) return Integer is
      R : constant Integer := Mod_Q (Value);
   begin
      return (if R > (Q - 1) / 2 then R - Q else R);
   end Centred;

   function Mul_Mod_Q (Left, Right : Coefficient) return Coefficient is
     (Coefficient (Long_Long_Integer (Left) * Long_Long_Integer (Right)
                   mod Long_Long_Integer (Q)));

   --  The forward NTT of FIPS 204 algorithm 41: Cooley-Tukey, in place, with
   --  the zetas in bit-reversed order.
   procedure NTT (Item : in out Poly) is
      K_Index : Natural := 0;
      Len     : Natural := 128;
   begin
      while Len >= 1 loop
         declare
            Start : Natural := 0;
         begin
            while Start < N loop
               K_Index := K_Index + 1;
               declare
                  Zeta : constant Coefficient := Zetas (K_Index);
               begin
                  for J in Start .. Start + Len - 1 loop
                     declare
                        T : constant Coefficient :=
                          Mul_Mod_Q (Zeta, Item (J + Len));
                     begin
                        Item (J + Len) := Mod_Q (Item (J) - T);
                        Item (J) := Mod_Q (Item (J) + T);
                     end;
                  end loop;
               end;
               Start := Start + 2 * Len;
            end loop;
         end;
         Len := Len / 2;
      end loop;
   end NTT;

   --  The inverse, algorithm 42, including the final scaling by 256**-1.
   procedure Inverse_NTT (Item : in out Poly) is
      K_Index : Integer := 256;
      Len     : Natural := 1;
      F       : constant Coefficient := 8347681;   --  256**-1 mod q
   begin
      while Len <= 128 loop
         declare
            Start : Natural := 0;
         begin
            while Start < N loop
               K_Index := K_Index - 1;
               declare
                  Zeta : constant Coefficient := Mod_Q (-Zetas (K_Index));
               begin
                  for J in Start .. Start + Len - 1 loop
                     declare
                        T : constant Coefficient := Item (J);
                     begin
                        Item (J) := Mod_Q (T + Item (J + Len));
                        Item (J + Len) := Mod_Q (T - Item (J + Len));
                        Item (J + Len) := Mul_Mod_Q (Zeta, Item (J + Len));
                     end;
                  end loop;
               end;
               Start := Start + 2 * Len;
            end loop;
         end;
         Len := Len * 2;
      end loop;
      for I in Poly_Index loop
         Item (I) := Mul_Mod_Q (F, Item (I));
      end loop;
   end Inverse_NTT;

   function Pointwise (Left, Right : Poly) return Poly is
      Result : Poly;
   begin
      for I in Poly_Index loop
         Result (I) := Mul_Mod_Q (Left (I), Right (I));
      end loop;
      return Result;
   end Pointwise;

   --  RejNTTPoly, algorithm 30: three octets at a time, keep what lands below
   --  q. The stream is SHAKE128 over rho and the two indices.
   function Rej_NTT_Poly (Seed : Stream_Element_Array) return Poly is
      Result : Poly := [others => 0];
      Filled : Natural := 0;
      Want   : Natural := 1344;      --  eight SHAKE128 blocks to start
   begin
      loop
         declare
            Stream : constant Stream_Element_Array :=
              CryptoLib.SHA3.SHAKE128 (Seed, Want);
            Cursor : Stream_Element_Offset := Stream'First;
         begin
            Filled := 0;
            while Filled < N and then Cursor + 2 <= Stream'Last loop
               declare
                  B0 : constant Integer := Integer (Stream (Cursor));
                  B1 : constant Integer := Integer (Stream (Cursor + 1));
                  B2 : constant Integer :=
                    Integer (Stream (Cursor + 2)) mod 128;
                  Z  : constant Integer := B2 * 65536 + B1 * 256 + B0;
               begin
                  if Z < Q then
                     Result (Filled) := Z;
                     Filled := Filled + 1;
                  end if;
                  Cursor := Cursor + 3;
               end;
            end loop;
         end;
         exit when Filled = N;
         Want := Want * 2;           --  vanishingly unlikely; bounded anyway
         exit when Want > 200_000;
      end loop;
      return Result;
   end Rej_NTT_Poly;

   --  RejBoundedPoly, algorithm 31: half an octet at a time, mapped into
   --  -eta .. eta.
   function Rej_Bounded_Poly
     (Seed : Stream_Element_Array; Eta : Positive) return Poly
   is
      Result : Poly := [others => 0];
      Filled : Natural := 0;
      Want   : Natural := 1088;
   begin
      loop
         declare
            Stream : constant Stream_Element_Array :=
              CryptoLib.SHA3.SHAKE256 (Seed, Want);
            Cursor : Stream_Element_Offset := Stream'First;

            procedure Take (Nibble : Integer) is
            begin
               if Filled >= N then
                  return;
               end if;
               if Eta = 2 then
                  if Nibble < 15 then
                     Result (Filled) := 2 - (Nibble mod 5);
                     Filled := Filled + 1;
                  end if;
               else
                  if Nibble < 9 then
                     Result (Filled) := 4 - Nibble;
                     Filled := Filled + 1;
                  end if;
               end if;
            end Take;
         begin
            Filled := 0;
            while Filled < N and then Cursor <= Stream'Last loop
               Take (Integer (Stream (Cursor)) mod 16);
               Take (Integer (Stream (Cursor)) / 16);
               Cursor := Cursor + 1;
            end loop;
         end;
         exit when Filled = N;
         Want := Want * 2;
         exit when Want > 200_000;
      end loop;
      return Result;
   end Rej_Bounded_Poly;

   --  Power2Round, algorithm 35: split each coefficient into high and low
   --  halves about 2**d.
   procedure Power2Round (Item : Poly; High : out Poly; Low : out Poly) is
      Half : constant Integer := 2 ** (D - 1);
   begin
      for I in Poly_Index loop
         declare
            R  : constant Integer := Mod_Q (Item (I));
            R0 : Integer := R mod (2 ** D);
         begin
            if R0 > Half then
               R0 := R0 - 2 ** D;
            end if;
            Low (I) := R0;
            High (I) := (R - R0) / (2 ** D);
         end;
      end loop;
   end Power2Round;

   --  SimpleBitPack / BitPack of algorithms 16 and 17, as one routine: write
   --  Width bits per coefficient, little-endian across the octet stream.
   procedure Pack_Bits
     (Values : Poly;
      Width  : Positive;
      Offset : Integer;
      Into   : out Stream_Element_Array)
   is
      Accum : Natural := 0;
      Bits  : Natural := 0;
      Cursor : Stream_Element_Offset := Into'First;
   begin
      Into := [others => 0];
      for I in Poly_Index loop
         declare
            V : constant Natural := Natural (Offset - Values (I));
         begin
            Accum := Accum + V * (2 ** Bits);
            Bits := Bits + Width;
            while Bits >= 8 loop
               Into (Cursor) := Stream_Element (Accum mod 256);
               Accum := Accum / 256;
               Bits := Bits - 8;
               Cursor := Cursor + 1;
            end loop;
         end;
      end loop;
   end Pack_Bits;

   --  The same, for values already non-negative (t1), where there is no
   --  offset to subtract from.
   --  The unsigned counterpart of Pack_Bits_Plain, for t1. Unpack_Bits is
   --  offset-based -- it returns Offset - value -- so reading a plain
   --  unsigned field through it yields the negation, which then has to be
   --  undone. Doing that twice is how verification came to compute
   --  A*z + c*t1*2**d instead of minus.
   function Unpack_Bits_Plain
     (Data : Stream_Element_Array; Width : Positive) return Poly
   is
      Result : Poly := [others => 0];
      Accum  : Natural := 0;
      Bits   : Natural := 0;
      Cursor : Stream_Element_Offset := Data'First;
      Span   : constant Natural := 2 ** Width;
   begin
      for I in Poly_Index loop
         while Bits < Width loop
            Accum := Accum + Natural (Data (Cursor)) * (2 ** Bits);
            Bits := Bits + 8;
            Cursor := Cursor + 1;
         end loop;
         Result (I) := Integer (Accum mod Span);
         Accum := Accum / Span;
         Bits := Bits - Width;
      end loop;
      return Result;
   end Unpack_Bits_Plain;

   procedure Pack_Bits_Plain
     (Values : Poly; Width : Positive; Into : out Stream_Element_Array)
   is
      Accum  : Natural := 0;
      Bits   : Natural := 0;
      Cursor : Stream_Element_Offset := Into'First;
   begin
      Into := [others => 0];
      for I in Poly_Index loop
         Accum := Accum + Natural (Values (I)) * (2 ** Bits);
         Bits := Bits + Width;
         while Bits >= 8 loop
            Into (Cursor) := Stream_Element (Accum mod 256);
            Accum := Accum / 256;
            Bits := Bits - 8;
            Cursor := Cursor + 1;
         end loop;
      end loop;
   end Pack_Bits_Plain;

   --  Unpack Width-bit fields written by Pack_Bits/Pack_Bits_Plain. Offset is
   --  what Pack_Bits subtracted from, so zero undoes Pack_Bits_Plain.
   function Unpack_Bits
     (Data : Stream_Element_Array; Width : Positive; Offset : Integer)
      return Poly
   is
      Result : Poly := [others => 0];
      Accum  : Natural := 0;
      Bits   : Natural := 0;
      Cursor : Stream_Element_Offset := Data'First;
      Mask   : constant Natural := 2 ** Width - 1;
   begin
      for I in Poly_Index loop
         while Bits < Width loop
            Accum := Accum + Natural (Data (Cursor)) * (2 ** Bits);
            Bits := Bits + 8;
            Cursor := Cursor + 1;
         end loop;
         Result (I) := Offset - Integer (Accum mod (Mask + 1));
         Accum := Accum / (Mask + 1);
         Bits := Bits - Width;
      end loop;
      return Result;
   end Unpack_Bits;

   --  Decompose, algorithm 36: r = r1 * 2 * gamma2 + r0 with r0 centred.
   procedure Decompose
     (Value : Coefficient; Gamma2 : Positive;
      High : out Integer; Low : out Integer)
   is
      R  : constant Integer := Mod_Q (Value);
      R0 : Integer := R mod (2 * Gamma2);
   begin
      if R0 > Gamma2 then
         R0 := R0 - 2 * Gamma2;
      end if;
      if R - R0 = Q - 1 then
         High := 0;
         Low := R0 - 1;
      else
         High := (R - R0) / (2 * Gamma2);
         Low := R0;
      end if;
   end Decompose;

   function High_Bits (Item : Poly; Gamma2 : Positive) return Poly is
      Result : Poly;
      H, L   : Integer;
   begin
      for I in Poly_Index loop
         Decompose (Item (I), Gamma2, H, L);
         Result (I) := H;
      end loop;
      return Result;
   end High_Bits;

   function Low_Bits (Item : Poly; Gamma2 : Positive) return Poly is
      Result : Poly;
      H, L   : Integer;
   begin
      for I in Poly_Index loop
         Decompose (Item (I), Gamma2, H, L);
         Result (I) := L;
      end loop;
      return Result;
   end Low_Bits;

   --  MakeHint / UseHint, algorithms 39 and 40.
   function Make_Hint
     (Z, R : Coefficient; Gamma2 : Positive) return Natural
   is
      H1, L1, H2, L2 : Integer;
   begin
      Decompose (R, Gamma2, H1, L1);
      Decompose (Mod_Q (R + Z), Gamma2, H2, L2);
      return (if H1 /= H2 then 1 else 0);
   end Make_Hint;

   function Use_Hint
     (Hint : Natural; R : Coefficient; Gamma2 : Positive) return Integer
   is
      M      : constant Integer := (Q - 1) / (2 * Gamma2);
      H, L   : Integer;
   begin
      Decompose (R, Gamma2, H, L);
      if Hint = 0 then
         return H;
      elsif L > 0 then
         return (H + 1) mod M;
      else
         return (H - 1) mod M;
      end if;
   end Use_Hint;

   --  SampleInBall, algorithm 29: tau coefficients of plus or minus one,
   --  placed by a Fisher-Yates pass driven by the challenge digest.
   function Sample_In_Ball
     (Seed : Stream_Element_Array; Tau : Positive) return Poly
   is
      Result : Poly := [others => 0];
      Stream : constant Stream_Element_Array :=
        CryptoLib.SHA3.SHAKE256 (Seed, 8 + 256);
      Cursor : Stream_Element_Offset := Stream'First + 8;
      Bit    : Natural := 0;

      --  The first eight octets are the sign bits, read one at a time. They
      --  are sixty-four bits and Natural is thirty-two, so accumulating them
      --  into one integer overflows -- which it did.
      function Next_Sign return Integer is
         Octet : constant Stream_Element :=
           Stream (Stream'First + Stream_Element_Offset (Bit / 8));
         Value : constant Natural :=
           Natural (Octet / (2 ** (Bit mod 8))) mod 2;
      begin
         Bit := Bit + 1;
         return 1 - 2 * Value;
      end Next_Sign;
   begin
      for I in N - Tau .. N - 1 loop
         declare
            J : Natural;
         begin
            loop
               J := Natural (Stream (Cursor));
               Cursor := Cursor + 1;
               exit when J <= I;
            end loop;
            Result (I) := Result (J);
            Result (J) := Next_Sign;
         end;
      end loop;
      return Result;
   end Sample_In_Ball;

   --  ExpandMask, algorithm 34.
   function Expand_Mask
     (Seed : Stream_Element_Array; Index : Natural; Gamma1 : Positive)
      return Poly
   is
      Width : constant Positive := (if Gamma1 = 2 ** 17 then 18 else 20);
      Bytes : constant Natural := 32 * Width;
      Stream : constant Stream_Element_Array :=
        CryptoLib.SHA3.SHAKE256
          (Seed & [Stream_Element (Index mod 256),
                   Stream_Element (Index / 256)], Bytes);
   begin
      return Unpack_Bits (Stream, Width, Gamma1);
   end Expand_Mask;

   function Infinity_Norm (Item : Poly) return Natural is
      Worst : Natural := 0;
   begin
      for I in Poly_Index loop
         declare
            R : constant Integer := Mod_Q (Item (I));
            V : constant Integer := (if R > (Q - 1) / 2 then Q - R else R);
         begin
            if V > Worst then
               Worst := V;
            end if;
         end;
      end loop;
      return Worst;
   end Infinity_Norm;

   --  The message representative of the external pure interface: a zero
   --  octet, the context length, the context, then the message. The context
   --  is bound in, so a signature made under one does not verify under
   --  another.
   function Representative
     (Context : Stream_Element_Array; Message : Stream_Element_Array)
      return Stream_Element_Array
   is ([0, Stream_Element (Context'Length)] & Context & Message);

   function Key_From_Seed
     (Set         : Parameter_Set;
      Seed        : Ada.Streams.Stream_Element_Array;
      Public_Key  : out Ada.Streams.Stream_Element_Array;
      Private_Key : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      P : constant Parameters := Params (Set);
   begin
      Public_Key := [others => 0];
      Private_Key := [others => 0];
      if Seed'Length /= 32
        or else Natural (Public_Key'Length) /= P.PK_Len
        or else Natural (Private_Key'Length) /= P.SK_Len
      then
         return Handshake_Failed;
      end if;

      declare
         --  FIPS 204 (final) mixes k and l into the seed expansion, which the
         --  original Dilithium did not: a 44 key and a 65 key from the same
         --  seed must not share rho.
         Expanded : constant Stream_Element_Array :=
           CryptoLib.SHA3.SHAKE256
             (Seed & [Stream_Element (P.K), Stream_Element (P.L)], 128);
         Rho      : constant Stream_Element_Array :=
           Expanded (Expanded'First .. Expanded'First + 31);
         Rho_Dash : constant Stream_Element_Array :=
           Expanded (Expanded'First + 32 .. Expanded'First + 95);
         K_Seed   : constant Stream_Element_Array :=
           Expanded (Expanded'First + 96 .. Expanded'First + 127);

         S1 : Poly_Vector (0 .. P.L - 1);
         S2 : Poly_Vector (0 .. P.K - 1);
         T  : Poly_Vector (0 .. P.K - 1) := [others => [others => 0]];
         T1 : Poly_Vector (0 .. P.K - 1);
         T0 : Poly_Vector (0 .. P.K - 1);
      begin
         for R in S1'Range loop
            S1 (R) := Rej_Bounded_Poly
              (Rho_Dash & [Stream_Element (R mod 256),
                           Stream_Element (R / 256)], P.Eta);
         end loop;
         for R in S2'Range loop
            declare
               Index : constant Natural := R + P.L;
            begin
               S2 (R) := Rej_Bounded_Poly
                 (Rho_Dash & [Stream_Element (Index mod 256),
                              Stream_Element (Index / 256)], P.Eta);
            end;
         end loop;

         --  t = A s1 + s2, with the product taken in the NTT domain.
         declare
            S1_Hat : Poly_Vector (S1'Range) := S1;
         begin
            for I in S1_Hat'Range loop
               NTT (S1_Hat (I));
            end loop;
            for R in 0 .. P.K - 1 loop
               declare
                  Acc : Poly := [others => 0];
               begin
                  for C in 0 .. P.L - 1 loop
                     declare
                        A_Hat : constant Poly := Rej_NTT_Poly
                          (Rho & [Stream_Element (C), Stream_Element (R)]);
                        Term  : constant Poly := Pointwise (A_Hat, S1_Hat (C));
                     begin
                        for I in Poly_Index loop
                           Acc (I) := Mod_Q (Acc (I) + Term (I));
                        end loop;
                     end;
                  end loop;
                  Inverse_NTT (Acc);
                  for I in Poly_Index loop
                     T (R) (I) := Mod_Q (Acc (I) + S2 (R) (I));
                  end loop;
               end;
            end loop;
         end;

         for R in T'Range loop
            Power2Round (T (R), T1 (R), T0 (R));
         end loop;

         --  pk = rho || SimpleBitPack (t1, 10 bits)
         Public_Key (Public_Key'First .. Public_Key'First + 31) := Rho;
         for R in T1'Range loop
            declare
               Base : constant Stream_Element_Offset :=
                 Public_Key'First + 32 + Stream_Element_Offset (R) * 320;
            begin
               Pack_Bits_Plain (T1 (R), 10,
                                Public_Key (Base .. Base + 319));
            end;
         end loop;

         declare
            Tr : constant Stream_Element_Array :=
              CryptoLib.SHA3.SHAKE256 (Public_Key, 64);
            Eta_Width : constant Positive := (if P.Eta = 2 then 3 else 4);
            Eta_Bytes : constant Stream_Element_Offset :=
              Stream_Element_Offset (Eta_Width * 32);
            Cursor : Stream_Element_Offset := Private_Key'First;
         begin
            Private_Key (Cursor .. Cursor + 31) := Rho;
            Cursor := Cursor + 32;
            Private_Key (Cursor .. Cursor + 31) := K_Seed;
            Cursor := Cursor + 32;
            Private_Key (Cursor .. Cursor + 63) := Tr;
            Cursor := Cursor + 64;
            for R in S1'Range loop
               Pack_Bits (S1 (R), Eta_Width, P.Eta,
                          Private_Key (Cursor .. Cursor + Eta_Bytes - 1));
               Cursor := Cursor + Eta_Bytes;
            end loop;
            for R in S2'Range loop
               Pack_Bits (S2 (R), Eta_Width, P.Eta,
                          Private_Key (Cursor .. Cursor + Eta_Bytes - 1));
               Cursor := Cursor + Eta_Bytes;
            end loop;
            for R in T0'Range loop
               Pack_Bits (T0 (R), 13, 2 ** (D - 1),
                          Private_Key (Cursor .. Cursor + 415));
               Cursor := Cursor + 416;
            end loop;
         end;
      end;
      return Ok;
   exception
      when others =>
         Public_Key := [others => 0];
         Private_Key := [others => 0];
         return Internal_Error;
   end Key_From_Seed;

   --  Rebuild A-hat, which both signing and verification need and neither
   --  stores: it is a deterministic function of rho.
   function Expand_A_Cell
     (Rho : Stream_Element_Array; Row, Col : Natural) return Poly
   is (Rej_NTT_Poly (Rho & [Stream_Element (Col), Stream_Element (Row)]));

   function Sign
     (Set           : Parameter_Set;
      Private_Key   : Ada.Streams.Stream_Element_Array;
      Message       : Ada.Streams.Stream_Element_Array;
      Context       : Ada.Streams.Stream_Element_Array;
      Rng           : in out CryptoLib.Random.Random_Source;
      Deterministic : Boolean;
      Signature     : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      P : constant Parameters := Params (Set);
      Eta_Width : constant Positive := (if P.Eta = 2 then 3 else 4);
      Eta_Bytes : constant Stream_Element_Offset :=
        Stream_Element_Offset (Eta_Width * 32);
      Z_Width   : constant Positive := (if P.Gamma1 = 2 ** 17 then 18 else 20);
   begin
      Signature := [others => 0];
      if Natural (Private_Key'Length) /= P.SK_Len
        or else Natural (Signature'Length) /= P.Sig_Len
        or else Context'Length > 255
      then
         return Handshake_Failed;
      end if;

      declare
         Base   : constant Stream_Element_Offset := Private_Key'First;
         Rho    : constant Stream_Element_Array := Private_Key (Base .. Base + 31);
         K_Seed : constant Stream_Element_Array :=
           Private_Key (Base + 32 .. Base + 63);
         Tr     : constant Stream_Element_Array :=
           Private_Key (Base + 64 .. Base + 127);
         S1 : Poly_Vector (0 .. P.L - 1);
         S2 : Poly_Vector (0 .. P.K - 1);
         T0 : Poly_Vector (0 .. P.K - 1);
         Cursor : Stream_Element_Offset := Base + 128;
      begin
         for R in S1'Range loop
            S1 (R) := Unpack_Bits
              (Private_Key (Cursor .. Cursor + Eta_Bytes - 1), Eta_Width, P.Eta);
            Cursor := Cursor + Eta_Bytes;
         end loop;
         for R in S2'Range loop
            S2 (R) := Unpack_Bits
              (Private_Key (Cursor .. Cursor + Eta_Bytes - 1), Eta_Width, P.Eta);
            Cursor := Cursor + Eta_Bytes;
         end loop;
         for R in T0'Range loop
            T0 (R) := Unpack_Bits
              (Private_Key (Cursor .. Cursor + 415), 13, 2 ** (D - 1));
            Cursor := Cursor + 416;
         end loop;

         declare
            Mu : constant Stream_Element_Array :=
              CryptoLib.SHA3.SHAKE256
                (Tr & Representative (Context, Message), 64);
            Rnd : Stream_Element_Array (1 .. 32) := [others => 0];
            S1_Hat : Poly_Vector (S1'Range) := S1;
            S2_Hat : Poly_Vector (S2'Range) := S2;
            T0_Hat : Poly_Vector (T0'Range) := T0;
            Kappa  : Natural := 0;
         begin
            if not Deterministic
              and then CryptoLib.Random.Fill (Rng, Rnd) /= Ok
            then
               return Internal_Error;
            end if;
            for I in S1_Hat'Range loop
               NTT (S1_Hat (I));
            end loop;
            for I in S2_Hat'Range loop
               NTT (S2_Hat (I));
            end loop;
            for I in T0_Hat'Range loop
               NTT (T0_Hat (I));
            end loop;

            declare
               Rho_2 : constant Stream_Element_Array :=
                 CryptoLib.SHA3.SHAKE256 (K_Seed & Rnd & Mu, 64);
            begin
               for Attempt in 1 .. 1000 loop
                  declare
                     Y : Poly_Vector (0 .. P.L - 1);
                     W : Poly_Vector (0 .. P.K - 1);
                     W1 : Poly_Vector (0 .. P.K - 1);
                     Y_Hat : Poly_Vector (0 .. P.L - 1);
                  begin
                     for I in Y'Range loop
                        Y (I) := Expand_Mask (Rho_2, Kappa + I, P.Gamma1);
                        Y_Hat (I) := Y (I);
                        NTT (Y_Hat (I));
                     end loop;

                     for R in W'Range loop
                        declare
                           Acc : Poly := [others => 0];
                        begin
                           for C in 0 .. P.L - 1 loop
                              declare
                                 Term : constant Poly := Pointwise
                                   (Expand_A_Cell (Rho, R, C), Y_Hat (C));
                              begin
                                 for I in Poly_Index loop
                                    Acc (I) := Mod_Q (Acc (I) + Term (I));
                                 end loop;
                              end;
                           end loop;
                           Inverse_NTT (Acc);
                           W (R) := Acc;
                           W1 (R) := High_Bits (Acc, P.Gamma2);
                        end;
                     end loop;

                     declare
                        W1_Width : constant Positive :=
                          (if P.Gamma2 = (Q - 1) / 88 then 6 else 4);
                        W1_Bytes : constant Stream_Element_Offset :=
                          Stream_Element_Offset (W1_Width * 32);
                        Packed : Stream_Element_Array
                          (1 .. W1_Bytes * Stream_Element_Offset (P.K));
                     begin
                        for R in W1'Range loop
                           Pack_Bits_Plain
                             (W1 (R), W1_Width,
                              Packed (1 + Stream_Element_Offset (R) * W1_Bytes
                                      .. (Stream_Element_Offset (R) + 1) * W1_Bytes));
                        end loop;

                        declare
                           C_Tilde : constant Stream_Element_Array :=
                             CryptoLib.SHA3.SHAKE256
                               (Mu & Packed, P.C_Bytes);
                           C_Poly : constant Poly :=
                             Sample_In_Ball (C_Tilde, P.Tau);
                           C_Hat  : Poly;
                           Z  : Poly_Vector (0 .. P.L - 1);
                           R0 : Poly_Vector (0 .. P.K - 1);
                           CT0 : Poly_Vector (0 .. P.K - 1);
                           Good : Boolean := True;
                        begin
                           C_Hat := C_Poly;
                           NTT (C_Hat);

                           for I in Z'Range loop
                              declare
                                 Term : Poly := Pointwise (C_Hat, S1_Hat (I));
                              begin
                                 Inverse_NTT (Term);
                                 for J in Poly_Index loop
                                    Z (I) (J) := Mod_Q (Y (I) (J) + Term (J));
                                 end loop;
                              end;
                           end loop;

                           for I in R0'Range loop
                              declare
                                 Term : Poly := Pointwise (C_Hat, S2_Hat (I));
                              begin
                                 Inverse_NTT (Term);
                                 for J in Poly_Index loop
                                    Term (J) := Mod_Q (W (I) (J) - Term (J));
                                 end loop;
                                 R0 (I) := Low_Bits (Term, P.Gamma2);
                              end;
                           end loop;

                           for I in Z'Range loop
                              if Infinity_Norm (Z (I)) >= P.Gamma1 - P.Beta then
                                 Good := False;
                              end if;
                           end loop;
                           for I in R0'Range loop
                              if Infinity_Norm (R0 (I)) >= P.Gamma2 - P.Beta then
                                 Good := False;
                              end if;
                           end loop;

                           if Good then
                              declare
                                 Hints : array (0 .. P.K - 1, Poly_Index) of Natural :=
                                   [others => [others => 0]];
                                 Weight : Natural := 0;
                              begin
                                 for I in CT0'Range loop
                                    declare
                                       Term : Poly := Pointwise (C_Hat, T0_Hat (I));
                                    begin
                                       Inverse_NTT (Term);
                                       CT0 (I) := Term;
                                       if Infinity_Norm (Term) >= P.Gamma2 then
                                          Good := False;
                                       end if;
                                    end;
                                 end loop;

                                 if Good then
                                    for I in CT0'Range loop
                                       declare
                                          Term : Poly := Pointwise (C_Hat, S2_Hat (I));
                                       begin
                                          Inverse_NTT (Term);
                                          for J in Poly_Index loop
                                             declare
                                                WCS : constant Integer :=
                                                  Mod_Q (W (I) (J) - Term (J)
                                                         + CT0 (I) (J));
                                             begin
                                                Hints (I, J) := Make_Hint
                                                  (Mod_Q (-CT0 (I) (J)), WCS,
                                                   P.Gamma2);
                                                Weight := Weight + Hints (I, J);
                                             end;
                                          end loop;
                                       end;
                                    end loop;
                                    if Weight > P.Omega then
                                       Good := False;
                                    end if;
                                 end if;

                                 if Good then
                                    --  sigEncode: c~ || BitPack (z) || hints
                                    declare
                                       Cur : Stream_Element_Offset :=
                                         Signature'First;
                                       Z_Bytes : constant Stream_Element_Offset :=
                                         Stream_Element_Offset (Z_Width * 32);
                                       Fill : Natural := 0;
                                    begin
                                       Signature (Cur .. Cur
                                         + Stream_Element_Offset (P.C_Bytes) - 1) :=
                                         C_Tilde;
                                       Cur := Cur
                                         + Stream_Element_Offset (P.C_Bytes);
                                       for I in Z'Range loop
                                          declare
                                             Zc : Poly;
                                          begin
                                             for J in Poly_Index loop
                                                Zc (J) := Centred (Z (I) (J));
                                             end loop;
                                             Pack_Bits (Zc, Z_Width, P.Gamma1,
                                                        Signature (Cur .. Cur + Z_Bytes - 1));
                                          end;
                                          Cur := Cur + Z_Bytes;
                                       end loop;
                                       --  HintBitPack: the indices, then the
                                       --  running totals per polynomial.
                                       for I in 0 .. P.K - 1 loop
                                          for J in Poly_Index loop
                                             if Hints (I, J) = 1 then
                                                Signature
                                                  (Cur + Stream_Element_Offset (Fill)) :=
                                                  Stream_Element (J);
                                                Fill := Fill + 1;
                                             end if;
                                          end loop;
                                          Signature
                                            (Cur + Stream_Element_Offset (P.Omega + I)) :=
                                            Stream_Element (Fill);
                                       end loop;
                                    end;
                                    return Ok;
                                 end if;
                              end;
                           end if;
                        end;
                     end;
                     Kappa := Kappa + P.L;
                  end;
               end loop;
            end;
         end;
      end;
      Signature := [others => 0];
      return Internal_Error;
   exception
      when others =>
         Signature := [others => 0];
         return Internal_Error;
   end Sign;

   function Verify
     (Set        : Parameter_Set;
      Public_Key : Ada.Streams.Stream_Element_Array;
      Message    : Ada.Streams.Stream_Element_Array;
      Context    : Ada.Streams.Stream_Element_Array;
      Signature  : Ada.Streams.Stream_Element_Array) return Boolean
   is
      P : constant Parameters := Params (Set);
      Z_Width : constant Positive := (if P.Gamma1 = 2 ** 17 then 18 else 20);
   begin
      if Natural (Public_Key'Length) /= P.PK_Len
        or else Natural (Signature'Length) /= P.Sig_Len
        or else Context'Length > 255
      then
         return False;
      end if;

      declare
         Rho : constant Stream_Element_Array :=
           Public_Key (Public_Key'First .. Public_Key'First + 31);
         T1  : Poly_Vector (0 .. P.K - 1);
         C_Tilde : constant Stream_Element_Array :=
           Signature (Signature'First
                      .. Signature'First
                         + Stream_Element_Offset (P.C_Bytes) - 1);
         Z : Poly_Vector (0 .. P.L - 1);
         Hints : array (0 .. P.K - 1, Poly_Index) of Natural :=
           [others => [others => 0]];
         Z_Bytes : constant Stream_Element_Offset :=
           Stream_Element_Offset (Z_Width * 32);
         Cur : Stream_Element_Offset :=
           Signature'First + Stream_Element_Offset (P.C_Bytes);
      begin
         for R in T1'Range loop
            declare
               Base : constant Stream_Element_Offset :=
                 Public_Key'First + 32 + Stream_Element_Offset (R) * 320;
            begin
               T1 (R) := Unpack_Bits_Plain
                 (Public_Key (Base .. Base + 319), 10);
            end;
         end loop;

         for I in Z'Range loop
            Z (I) := Unpack_Bits
              (Signature (Cur .. Cur + Z_Bytes - 1), Z_Width, P.Gamma1);
            Cur := Cur + Z_Bytes;
            if Infinity_Norm (Z (I)) >= P.Gamma1 - P.Beta then
               return False;
            end if;
         end loop;

         --  HintBitUnpack, algorithm 21, with its malformed-encoding
         --  refusals: indices must ascend within a polynomial and the running
         --  totals must not go backwards or past omega.
         declare
            Index : Natural := 0;
         begin
            for I in 0 .. P.K - 1 loop
               declare
                  Stop : constant Natural := Natural
                    (Signature (Cur + Stream_Element_Offset (P.Omega + I)));
                  Last : Integer := -1;
               begin
                  if Stop < Index or else Stop > P.Omega then
                     return False;
                  end if;
                  while Index < Stop loop
                     declare
                        J : constant Natural := Natural
                          (Signature (Cur + Stream_Element_Offset (Index)));
                     begin
                        if J <= Last then
                           return False;
                        end if;
                        Last := J;
                        Hints (I, J) := 1;
                        Index := Index + 1;
                     end;
                  end loop;
               end;
            end loop;
         end;

         declare
            Tr : constant Stream_Element_Array :=
              CryptoLib.SHA3.SHAKE256 (Public_Key, 64);
            Mu : constant Stream_Element_Array :=
              CryptoLib.SHA3.SHAKE256
                (Tr & Representative (Context, Message), 64);
            C_Poly : constant Poly := Sample_In_Ball (C_Tilde, P.Tau);
            C_Hat  : Poly;
            W1 : Poly_Vector (0 .. P.K - 1);
         begin
            C_Hat := C_Poly;
            NTT (C_Hat);

            for R in 0 .. P.K - 1 loop
               declare
                  Acc : Poly := [others => 0];
                  T1_Hat : Poly := T1 (R);
               begin
                  for I in Poly_Index loop
                     T1_Hat (I) := Mod_Q (T1_Hat (I) * (2 ** D));
                  end loop;
                  NTT (T1_Hat);
                  for C in 0 .. P.L - 1 loop
                     declare
                        Z_Hat : Poly := Z (C);
                     begin
                        NTT (Z_Hat);
                        declare
                           Term : constant Poly := Pointwise
                             (Expand_A_Cell (Rho, R, C), Z_Hat);
                        begin
                           for I in Poly_Index loop
                              Acc (I) := Mod_Q (Acc (I) + Term (I));
                           end loop;
                        end;
                     end;
                  end loop;
                  declare
                     CT : constant Poly := Pointwise (C_Hat, T1_Hat);
                  begin
                     for I in Poly_Index loop
                        Acc (I) := Mod_Q (Acc (I) - CT (I));
                     end loop;
                  end;
                  Inverse_NTT (Acc);
                  for I in Poly_Index loop
                     W1 (R) (I) := Use_Hint (Hints (R, I), Acc (I), P.Gamma2);
                  end loop;
               end;
            end loop;

            declare
               W1_Width : constant Positive :=
                 (if P.Gamma2 = (Q - 1) / 88 then 6 else 4);
               W1_Bytes : constant Stream_Element_Offset :=
                 Stream_Element_Offset (W1_Width * 32);
               Packed : Stream_Element_Array
                 (1 .. W1_Bytes * Stream_Element_Offset (P.K));
            begin
               for R in W1'Range loop
                  Pack_Bits_Plain
                    (W1 (R), W1_Width,
                     Packed (1 + Stream_Element_Offset (R) * W1_Bytes
                             .. (Stream_Element_Offset (R) + 1) * W1_Bytes));
               end loop;
               return CryptoLib.SHA3.SHAKE256 (Mu & Packed, P.C_Bytes)
                 = C_Tilde;
            end;
         end;
      end;
   exception
      when others =>
         return False;
   end Verify;

   function Generate_Keypair
     (Set         : Parameter_Set;
      Rng         : in out CryptoLib.Random.Random_Source;
      Public_Key  : out Ada.Streams.Stream_Element_Array;
      Private_Key : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      Seed : Stream_Element_Array (1 .. 32);
   begin
      Public_Key := [others => 0];
      Private_Key := [others => 0];
      if CryptoLib.Random.Fill (Rng, Seed) /= Ok then
         return Internal_Error;
      end if;
      return Key_From_Seed (Set, Seed, Public_Key, Private_Key);
   end Generate_Keypair;

end CryptoLib.MLDSA;
