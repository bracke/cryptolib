with Ada.Streams; use Ada.Streams;
with Interfaces; use Interfaces;
with System;

with CryptoLib.SHA3;
with CryptoLib.Secure_Wipe;

package body CryptoLib.MLKEM is

   use CryptoLib.Errors;

   N : constant := 256;
   Q : constant := 3329;

   subtype Coefficient is Integer range 0 .. Q - 1;
   subtype Poly_Index is Natural range 0 .. N - 1;
   type Poly is array (Poly_Index) of Coefficient;

   --  Module rank is a parameter, so a vector is unconstrained.
   type Poly_Vector is array (Natural range <>) of Poly;
   type Poly_Matrix is array (Natural range <>, Natural range <>) of Poly;

   type Parameters is record
      K      : Positive;   --  module rank
      Eta_1  : Positive;   --  noise width for the key and the ephemeral y
      Eta_2  : Positive;   --  noise width for e1 and e2
      D_U    : Positive;   --  ciphertext u compression width
      D_V    : Positive;   --  ciphertext v compression width
      PK_Len : Positive;
      SK_Len : Positive;
      CT_Len : Positive;
   end record;

   function Params (Set : Parameter_Set) return Parameters is
     (case Set is
         when ML_KEM_512  =>
           (K => 2, Eta_1 => 3, Eta_2 => 2, D_U => 10, D_V => 4,
            PK_Len => 800, SK_Len => 1632, CT_Len => 768),
         when ML_KEM_768  =>
           (K => 3, Eta_1 => 2, Eta_2 => 2, D_U => 10, D_V => 4,
            PK_Len => 1184, SK_Len => 2400, CT_Len => 1088),
         when ML_KEM_1024 =>
           (K => 4, Eta_1 => 2, Eta_2 => 2, D_U => 11, D_V => 5,
            PK_Len => 1568, SK_Len => 3168, CT_Len => 1568));

   function Public_Key_Length (Set : Parameter_Set) return Positive is
     (Params (Set).PK_Len);

   function Secret_Key_Length (Set : Parameter_Set) return Positive is
     (Params (Set).SK_Len);

   function Ciphertext_Length (Set : Parameter_Set) return Positive is
     (Params (Set).CT_Len);

   --  zeta**bit_reverse_7(i) mod q for zeta = 17, a primitive 256th root of
   --  unity modulo 3329. Generated from that definition and checked (order
   --  exactly 256) rather than transcribed.
   Zetas : constant array (0 .. 127) of Coefficient :=
     [1, 1729, 2580, 3289, 2642, 630, 1897, 848,
      1062, 1919, 193, 797, 2786, 3260, 569, 1746,
      296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
      1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
      289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
      650, 1977, 2513, 632, 2865, 33, 1320, 1915,
      2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
      2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
      17, 2761, 583, 2649, 1637, 723, 2288, 1100,
      1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
      1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
      939, 2308, 2437, 2388, 733, 2337, 268, 641,
      1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
      1063, 319, 2773, 757, 2099, 561, 2466, 2594,
      2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
      1722, 1212, 1874, 1029, 2110, 2935, 885, 2154];

   --  The base-case multiplier gammas: zeta**(2*bit_reverse_7(i)+1).
   Gammas : constant array (0 .. 127) of Coefficient :=
     [17, 3312, 2761, 568, 583, 2746, 2649, 680,
      1637, 1692, 723, 2606, 2288, 1041, 1100, 2229,
      1409, 1920, 2662, 667, 3281, 48, 233, 3096,
      756, 2573, 2156, 1173, 3015, 314, 3050, 279,
      1703, 1626, 1651, 1678, 2789, 540, 1789, 1540,
      1847, 1482, 952, 2377, 1461, 1868, 2687, 642,
      939, 2390, 2308, 1021, 2437, 892, 2388, 941,
      733, 2596, 2337, 992, 268, 3061, 641, 2688,
      1584, 1745, 2298, 1031, 2037, 1292, 3220, 109,
      375, 2954, 2549, 780, 2090, 1239, 1645, 1684,
      1063, 2266, 319, 3010, 2773, 556, 757, 2572,
      2099, 1230, 561, 2768, 2466, 863, 2594, 735,
      2804, 525, 1092, 2237, 403, 2926, 1026, 2303,
      1143, 2186, 2150, 1179, 2775, 554, 886, 2443,
      1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300,
      2110, 1219, 2935, 394, 885, 2444, 2154, 1175];

   --  SHA3_256 and SHA3_512 return their own digest types, so H and G get
   --  named wrappers rather than a conversion at each of the six call sites.
   function H (Data : Stream_Element_Array) return Stream_Element_Array is
      Digest : constant CryptoLib.SHA3.SHA3_256_Digest :=
        CryptoLib.SHA3.SHA3_256 (Data);
      Result : Stream_Element_Array (1 .. 32);
   begin
      for I in Result'Range loop
         Result (I) := Digest (Positive (I));
      end loop;
      return Result;
   end H;

   function G (Data : Stream_Element_Array) return Stream_Element_Array is
      Digest : constant CryptoLib.SHA3.SHA3_512_Digest :=
        CryptoLib.SHA3.SHA3_512 (Data);
      Result : Stream_Element_Array (1 .. 64);
   begin
      for I in Result'Range loop
         Result (I) := Digest (Positive (I));
      end loop;
      return Result;
   end G;

   function Reduce (Value : Integer) return Coefficient is
      R : Integer := Value mod Q;
   begin
      if R < 0 then
         R := R + Q;
      end if;
      return R;
   end Reduce;

   function Mul_Mod (Left, Right : Coefficient) return Coefficient is
     (Coefficient (Long_Long_Integer (Left) * Long_Long_Integer (Right)
                   mod Long_Long_Integer (Q)));

   --  Compress_d, FIPS 203 (4.7): round(2**d / q * value) mod 2**d, with the
   --  rounding done in integers rather than floating point.
   function Compress (Value : Coefficient; Bits : Positive) return Natural is
      Numerator : constant Long_Long_Integer :=
        Long_Long_Integer (Value) * (2 ** Bits) * 2 + Long_Long_Integer (Q);
   begin
      return Natural ((Numerator / (Long_Long_Integer (Q) * 2))
                      mod (2 ** Bits));
   end Compress;

   --  Decompress_d: round(q / 2**d * value).
   function Decompress (Value : Natural; Bits : Positive)
      return Coefficient
   is
      Numerator : constant Long_Long_Integer :=
        Long_Long_Integer (Value) * Q * 2 + (2 ** Bits);
   begin
      return Coefficient (Numerator / (2 ** (Bits + 1)));
   end Decompress;

   ----------------------------------------------------------------------
   --  Bit packing
   ----------------------------------------------------------------------

   --  ByteEncode_d over a polynomial whose coefficients already fit in Bits.
   procedure Encode (Item : Poly; Bits : Positive;
                     Into : out Stream_Element_Array)
   is
      Accum  : Unsigned_64 := 0;
      Filled : Natural := 0;
      Cursor : Stream_Element_Offset := Into'First;
   begin
      Into := [others => 0];
      for I in Poly_Index loop
         Accum := Accum or Shift_Left (Unsigned_64 (Item (I)), Filled);
         Filled := Filled + Bits;
         while Filled >= 8 loop
            Into (Cursor) := Stream_Element (Accum and 16#FF#);
            Accum := Shift_Right (Accum, 8);
            Filled := Filled - 8;
            Cursor := Cursor + 1;
         end loop;
      end loop;
   end Encode;

   --  ByteDecode_d. Values come back raw; the caller decompresses or reduces.
   procedure Decode (Data : Stream_Element_Array; Bits : Positive;
                     Item : out Poly)
   is
      Accum  : Unsigned_64 := 0;
      Filled : Natural := 0;
      Cursor : Stream_Element_Offset := Data'First;
      Mask   : constant Unsigned_64 := Shift_Left (Unsigned_64 (1), Bits) - 1;
   begin
      Item := [others => 0];
      for I in Poly_Index loop
         while Filled < Bits loop
            Accum := Accum or Shift_Left (Unsigned_64 (Data (Cursor)), Filled);
            Filled := Filled + 8;
            Cursor := Cursor + 1;
         end loop;
         --  Twelve-bit decoding can carry a value at or above q; FIPS 203
         --  reduces there, and the compressed widths never exceed it.
         Item (I) := Reduce (Integer (Accum and Mask));
         Accum := Shift_Right (Accum, Bits);
         Filled := Filled - Bits;
      end loop;
   end Decode;

   procedure Compress_Encode (Item : Poly; Bits : Positive;
                              Into : out Stream_Element_Array)
   is
      Packed : Poly;
   begin
      for I in Poly_Index loop
         Packed (I) := Compress (Item (I), Bits);
      end loop;
      Encode (Packed, Bits, Into);
   end Compress_Encode;

   procedure Decode_Decompress (Data : Stream_Element_Array; Bits : Positive;
                                Item : out Poly)
   is
      Raw : Poly;
   begin
      Decode (Data, Bits, Raw);
      for I in Poly_Index loop
         Item (I) := Decompress (Raw (I), Bits);
      end loop;
   end Decode_Decompress;

   ----------------------------------------------------------------------
   --  Sampling
   ----------------------------------------------------------------------

   --  SampleNTT, FIPS 203 algorithm 7: rejection sampling three octets at a
   --  time out of SHAKE128 (rho || j || i).
   function Sample_NTT (Rho : Stream_Element_Array; Row, Column : Natural)
      return Poly
   is
      Seed : constant Stream_Element_Array :=
        Rho & [Stream_Element (Column), Stream_Element (Row)];
      Want : Natural := 3 * 168;
      Result : Poly := [others => 0];
      Filled : Natural;
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
                  B2 : constant Integer := Integer (Stream (Cursor + 2));
                  D1 : constant Integer := B0 + 256 * (B1 mod 16);
                  D2 : constant Integer := B1 / 16 + 16 * B2;
               begin
                  if D1 < Q then
                     Result (Filled) := D1;
                     Filled := Filled + 1;
                  end if;
                  if Filled < N and then D2 < Q then
                     Result (Filled) := D2;
                     Filled := Filled + 1;
                  end if;
                  Cursor := Cursor + 3;
               end;
            end loop;
         end;
         exit when Filled = N;
         Want := Want * 2;
         exit when Want > 200_000;
      end loop;
      return Result;
   end Sample_NTT;

   --  SamplePolyCBD_eta, algorithm 8: the centred binomial difference of two
   --  eta-bit popcounts.
   function Sample_CBD (Bytes : Stream_Element_Array; Eta : Positive)
      return Poly
   is
      Result : Poly := [others => 0];

      function Bit (Index : Natural) return Natural is
         Octet : constant Stream_Element :=
           Bytes (Bytes'First + Stream_Element_Offset (Index / 8));
      begin
         return Natural (Shift_Right (Unsigned_8 (Octet),
                                      Index mod 8) and 1);
      end Bit;
   begin
      for I in Poly_Index loop
         declare
            A : Natural := 0;
            B : Natural := 0;
         begin
            for J in 0 .. Eta - 1 loop
               A := A + Bit (2 * I * Eta + J);
               B := B + Bit (2 * I * Eta + Eta + J);
            end loop;
            Result (I) := Reduce (A - B);
         end;
      end loop;
      return Result;
   end Sample_CBD;

   --  PRF_eta (sigma, b) = SHAKE256 (sigma || b, 64 * eta).
   function PRF (Seed : Stream_Element_Array; Nonce : Natural; Eta : Positive)
      return Stream_Element_Array
   is (CryptoLib.SHA3.SHAKE256
         (Seed & [Stream_Element (Nonce)], 64 * Eta));

   ----------------------------------------------------------------------
   --  The transform
   ----------------------------------------------------------------------

   procedure NTT (Item : in out Poly) is
      K_Index : Natural := 1;
      Len     : Natural := 128;
   begin
      while Len >= 2 loop
         declare
            Start : Natural := 0;
         begin
            while Start < N loop
               declare
                  Zeta : constant Coefficient := Zetas (K_Index);
               begin
                  K_Index := K_Index + 1;
                  for J in Start .. Start + Len - 1 loop
                     declare
                        T : constant Coefficient :=
                          Mul_Mod (Zeta, Item (J + Len));
                     begin
                        Item (J + Len) := Reduce (Item (J) - T);
                        Item (J) := Reduce (Item (J) + T);
                     end;
                  end loop;
               end;
               Start := Start + 2 * Len;
            end loop;
         end;
         Len := Len / 2;
      end loop;
   end NTT;

   procedure Inverse_NTT (Item : in out Poly) is
      K_Index : Integer := 127;
      Len     : Natural := 2;
      F       : constant Coefficient := 3303;   --  128**-1 mod q
   begin
      while Len <= 128 loop
         declare
            Start : Natural := 0;
         begin
            while Start < N loop
               declare
                  Zeta : constant Coefficient := Zetas (K_Index);
               begin
                  K_Index := K_Index - 1;
                  for J in Start .. Start + Len - 1 loop
                     declare
                        T : constant Coefficient := Item (J);
                     begin
                        Item (J) := Reduce (T + Item (J + Len));
                        Item (J + Len) :=
                          Mul_Mod (Zeta, Reduce (Item (J + Len) - T));
                     end;
                  end loop;
               end;
               Start := Start + 2 * Len;
            end loop;
         end;
         Len := Len * 2;
      end loop;
      for I in Poly_Index loop
         Item (I) := Mul_Mod (Item (I), F);
      end loop;
   end Inverse_NTT;

   --  MultiplyNTTs, algorithm 11: 128 products in Z_q[x]/(x^2 - gamma).
   function Pointwise (Left, Right : Poly) return Poly is
      Result : Poly;
   begin
      for I in 0 .. 127 loop
         declare
            A0 : constant Coefficient := Left (2 * I);
            A1 : constant Coefficient := Left (2 * I + 1);
            B0 : constant Coefficient := Right (2 * I);
            B1 : constant Coefficient := Right (2 * I + 1);
            G  : constant Coefficient := Gammas (I);
         begin
            Result (2 * I) :=
              Reduce (Mul_Mod (A0, B0) + Mul_Mod (Mul_Mod (A1, B1), G));
            Result (2 * I + 1) :=
              Reduce (Mul_Mod (A0, B1) + Mul_Mod (A1, B0));
         end;
      end loop;
      return Result;
   end Pointwise;

   function Add (Left, Right : Poly) return Poly is
      Result : Poly;
   begin
      for I in Poly_Index loop
         Result (I) := Reduce (Left (I) + Right (I));
      end loop;
      return Result;
   end Add;

   function Subtract (Left, Right : Poly) return Poly is
      Result : Poly;
   begin
      for I in Poly_Index loop
         Result (I) := Reduce (Left (I) - Right (I));
      end loop;
      return Result;
   end Subtract;

   ----------------------------------------------------------------------
   --  K-PKE
   ----------------------------------------------------------------------

   --  A-hat, sampled row by row. FIPS 203 indexes SampleNTT with (j, i) for
   --  A[i][j], and transposes for encryption rather than resampling.
   function Expand_A (Rho : Stream_Element_Array; K : Positive)
      return Poly_Matrix
   is
      Result : Poly_Matrix (0 .. K - 1, 0 .. K - 1);
   begin
      for I in 0 .. K - 1 loop
         for J in 0 .. K - 1 loop
            Result (I, J) := Sample_NTT (Rho, I, J);
         end loop;
      end loop;
      return Result;
   end Expand_A;

   procedure PKE_Keygen
     (P           : Parameters;
      D           : Stream_Element_Array;
      Public_Item : out Stream_Element_Array;
      Secret_Item : out Stream_Element_Array)
   is
      --  G (d || k) -- FIPS 203 folds the module rank into the seed
      --  expansion, which is what keeps the three parameter sets' keys
      --  domain-separated from one another.
      Expanded : constant Stream_Element_Array :=
        G (D & [Stream_Element (P.K)]);
      Rho   : constant Stream_Element_Array :=
        Expanded (Expanded'First .. Expanded'First + 31);
      Sigma : constant Stream_Element_Array :=
        Expanded (Expanded'First + 32 .. Expanded'First + 63);
      A     : constant Poly_Matrix := Expand_A (Rho, P.K);
      S     : Poly_Vector (0 .. P.K - 1);
      E     : Poly_Vector (0 .. P.K - 1);
      T     : Poly_Vector (0 .. P.K - 1);
      Nonce : Natural := 0;
   begin
      for I in S'Range loop
         S (I) := Sample_CBD (PRF (Sigma, Nonce, P.Eta_1), P.Eta_1);
         Nonce := Nonce + 1;
      end loop;
      for I in E'Range loop
         E (I) := Sample_CBD (PRF (Sigma, Nonce, P.Eta_1), P.Eta_1);
         Nonce := Nonce + 1;
      end loop;
      for I in S'Range loop
         NTT (S (I));
         NTT (E (I));
      end loop;

      for I in T'Range loop
         T (I) := [others => 0];
         for J in 0 .. P.K - 1 loop
            T (I) := Add (T (I), Pointwise (A (I, J), S (J)));
         end loop;
         T (I) := Add (T (I), E (I));
      end loop;

      for I in T'Range loop
         Encode (T (I), 12,
                 Public_Item (Public_Item'First
                                + Stream_Element_Offset (I) * 384
                              .. Public_Item'First
                                + Stream_Element_Offset (I + 1) * 384 - 1));
      end loop;
      Public_Item (Public_Item'First + Stream_Element_Offset (P.K) * 384
                   .. Public_Item'Last) := Rho;

      for I in S'Range loop
         Encode (S (I), 12,
                 Secret_Item (Secret_Item'First
                                + Stream_Element_Offset (I) * 384
                              .. Secret_Item'First
                                + Stream_Element_Offset (I + 1) * 384 - 1));
      end loop;
   end PKE_Keygen;

   procedure PKE_Encrypt
     (P           : Parameters;
      Public_Item : Stream_Element_Array;
      Message     : Stream_Element_Array;
      Coins       : Stream_Element_Array;
      Ciphertext_Item : out Stream_Element_Array)
   is
      T   : Poly_Vector (0 .. P.K - 1);
      Rho : constant Stream_Element_Array :=
        Public_Item (Public_Item'First + Stream_Element_Offset (P.K) * 384
                     .. Public_Item'First
                        + Stream_Element_Offset (P.K) * 384 + 31);
      A   : constant Poly_Matrix := Expand_A (Rho, P.K);
      Y   : Poly_Vector (0 .. P.K - 1);
      E1  : Poly_Vector (0 .. P.K - 1);
      U   : Poly_Vector (0 .. P.K - 1);
      E2  : Poly;
      V   : Poly;
      Mu  : Poly;
      Nonce : Natural := 0;
      U_Bytes : constant Stream_Element_Offset :=
        Stream_Element_Offset (32 * P.D_U);
      Cursor : Stream_Element_Offset := Ciphertext_Item'First;
   begin
      for I in T'Range loop
         Decode (Public_Item (Public_Item'First
                                + Stream_Element_Offset (I) * 384
                              .. Public_Item'First
                                + Stream_Element_Offset (I + 1) * 384 - 1),
                 12, T (I));
      end loop;

      for I in Y'Range loop
         Y (I) := Sample_CBD (PRF (Coins, Nonce, P.Eta_1), P.Eta_1);
         Nonce := Nonce + 1;
      end loop;
      for I in E1'Range loop
         E1 (I) := Sample_CBD (PRF (Coins, Nonce, P.Eta_2), P.Eta_2);
         Nonce := Nonce + 1;
      end loop;
      E2 := Sample_CBD (PRF (Coins, Nonce, P.Eta_2), P.Eta_2);

      for I in Y'Range loop
         NTT (Y (I));
      end loop;

      --  u = NTT^-1 (A-hat^T o y-hat) + e1, transposed relative to keygen.
      for I in U'Range loop
         U (I) := [others => 0];
         for J in 0 .. P.K - 1 loop
            U (I) := Add (U (I), Pointwise (A (J, I), Y (J)));
         end loop;
         Inverse_NTT (U (I));
         U (I) := Add (U (I), E1 (I));
      end loop;

      V := [others => 0];
      for J in 0 .. P.K - 1 loop
         V := Add (V, Pointwise (T (J), Y (J)));
      end loop;
      Inverse_NTT (V);
      V := Add (V, E2);

      --  The message as a polynomial: Decompress_1 of ByteDecode_1.
      Decode_Decompress (Message, 1, Mu);
      V := Add (V, Mu);

      for I in U'Range loop
         Compress_Encode (U (I), P.D_U,
                          Ciphertext_Item (Cursor .. Cursor + U_Bytes - 1));
         Cursor := Cursor + U_Bytes;
      end loop;
      Compress_Encode (V, P.D_V,
                       Ciphertext_Item (Cursor .. Ciphertext_Item'Last));
   end PKE_Encrypt;

   function PKE_Decrypt
     (P               : Parameters;
      Secret_Item     : Stream_Element_Array;
      Ciphertext_Item : Stream_Element_Array) return Stream_Element_Array
   is
      S : Poly_Vector (0 .. P.K - 1);
      U : Poly_Vector (0 .. P.K - 1);
      V : Poly;
      W : Poly;
      U_Bytes : constant Stream_Element_Offset :=
        Stream_Element_Offset (32 * P.D_U);
      Cursor : Stream_Element_Offset := Ciphertext_Item'First;
      Message : Stream_Element_Array (1 .. 32);
   begin
      for I in U'Range loop
         Decode_Decompress
           (Ciphertext_Item (Cursor .. Cursor + U_Bytes - 1), P.D_U, U (I));
         Cursor := Cursor + U_Bytes;
      end loop;
      Decode_Decompress
        (Ciphertext_Item (Cursor .. Ciphertext_Item'Last), P.D_V, V);

      for I in S'Range loop
         Decode (Secret_Item (Secret_Item'First
                                + Stream_Element_Offset (I) * 384
                              .. Secret_Item'First
                                + Stream_Element_Offset (I + 1) * 384 - 1),
                 12, S (I));
      end loop;

      for I in U'Range loop
         NTT (U (I));
      end loop;

      W := [others => 0];
      for J in 0 .. P.K - 1 loop
         W := Add (W, Pointwise (S (J), U (J)));
      end loop;
      Inverse_NTT (W);
      W := Subtract (V, W);

      declare
         Bits : Poly;
      begin
         for I in Poly_Index loop
            Bits (I) := Compress (W (I), 1);
         end loop;
         Encode (Bits, 1, Message);
      end;
      return Message;
   end PKE_Decrypt;

   ----------------------------------------------------------------------
   --  The KEM
   ----------------------------------------------------------------------

   function Key_From_Seeds
     (Set        : Parameter_Set;
      D          : Ada.Streams.Stream_Element_Array;
      Z          : Ada.Streams.Stream_Element_Array;
      Public_Key : out Ada.Streams.Stream_Element_Array;
      Secret_Key : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      P : constant Parameters := Params (Set);
      PKE_Secret_Len : constant Stream_Element_Offset :=
        Stream_Element_Offset (P.K) * 384;
   begin
      Public_Key := [others => 0];
      Secret_Key := [others => 0];
      if D'Length /= 32 or else Z'Length /= 32
        or else Natural (Public_Key'Length) /= P.PK_Len
        or else Natural (Secret_Key'Length) /= P.SK_Len
      then
         return Handshake_Failed;
      end if;

      PKE_Keygen
        (P, D, Public_Key,
         Secret_Key (Secret_Key'First
                     .. Secret_Key'First + PKE_Secret_Len - 1));

      --  dk = dk_PKE || ek || H(ek) || z
      declare
         Cursor : Stream_Element_Offset := Secret_Key'First + PKE_Secret_Len;
      begin
         Secret_Key (Cursor .. Cursor
                     + Stream_Element_Offset (P.PK_Len) - 1) := Public_Key;
         Cursor := Cursor + Stream_Element_Offset (P.PK_Len);
         Secret_Key (Cursor .. Cursor + 31) := H (Public_Key);
         Cursor := Cursor + 32;
         Secret_Key (Cursor .. Cursor + 31) := Z;
      end;
      return Ok;
   exception
      when others =>
         Public_Key := [others => 0];
         Secret_Key := [others => 0];
         return Internal_Error;
   end Key_From_Seeds;

   function Generate_Keypair
     (Set        : Parameter_Set;
      Rng        : in out CryptoLib.Random.Random_Source;
      Public_Key : out Ada.Streams.Stream_Element_Array;
      Secret_Key : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      use System;
      D : Stream_Element_Array (1 .. 32) := [others => 0];
      Z : Stream_Element_Array (1 .. 32) := [others => 0];
   begin
      Public_Key := [others => 0];
      Secret_Key := [others => 0];
      if CryptoLib.Random.Fill (Rng, D) /= Ok
        or else CryptoLib.Random.Fill (Rng, Z) /= Ok
      then
         CryptoLib.Secure_Wipe.Wipe (D'Address, D'Length);
         CryptoLib.Secure_Wipe.Wipe (Z'Address, Z'Length);
         return Internal_Error;
      end if;
      return Result : constant CryptoLib.Errors.Status :=
        Key_From_Seeds (Set, D, Z, Public_Key, Secret_Key)
      do
         CryptoLib.Secure_Wipe.Wipe (D'Address, D'Length);
         CryptoLib.Secure_Wipe.Wipe (Z'Address, Z'Length);
      end return;
   end Generate_Keypair;

   function Encapsulate_With_Message
     (Set        : Parameter_Set;
      Public_Key : Ada.Streams.Stream_Element_Array;
      Message    : Ada.Streams.Stream_Element_Array;
      Ciphertext : out Ada.Streams.Stream_Element_Array;
      Shared_Key : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      P : constant Parameters := Params (Set);
   begin
      Ciphertext := [others => 0];
      Shared_Key := [others => 0];
      if Message'Length /= 32
        or else Natural (Public_Key'Length) /= P.PK_Len
        or else Natural (Ciphertext'Length) /= P.CT_Len
        or else Shared_Key'Length /= Shared_Key_Length
      then
         return Handshake_Failed;
      end if;

      declare
         --  (K, r) = G (m || H(ek))
         Expanded : constant Stream_Element_Array :=
           G (Message & H (Public_Key));
      begin
         Shared_Key := Expanded (Expanded'First .. Expanded'First + 31);
         PKE_Encrypt (P, Public_Key, Message,
                      Expanded (Expanded'First + 32 .. Expanded'First + 63),
                      Ciphertext);
      end;
      return Ok;
   exception
      when others =>
         Ciphertext := [others => 0];
         Shared_Key := [others => 0];
         return Internal_Error;
   end Encapsulate_With_Message;

   function Encapsulate
     (Set        : Parameter_Set;
      Rng        : in out CryptoLib.Random.Random_Source;
      Public_Key : Ada.Streams.Stream_Element_Array;
      Ciphertext : out Ada.Streams.Stream_Element_Array;
      Shared_Key : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      use System;
      Message : Stream_Element_Array (1 .. 32) := [others => 0];
   begin
      Ciphertext := [others => 0];
      Shared_Key := [others => 0];
      if CryptoLib.Random.Fill (Rng, Message) /= Ok then
         CryptoLib.Secure_Wipe.Wipe (Message'Address, Message'Length);
         return Internal_Error;
      end if;
      return Result : constant CryptoLib.Errors.Status :=
        Encapsulate_With_Message
          (Set, Public_Key, Message, Ciphertext, Shared_Key)
      do
         CryptoLib.Secure_Wipe.Wipe (Message'Address, Message'Length);
      end return;
   end Encapsulate;

   function Decapsulate
     (Set        : Parameter_Set;
      Secret_Key : Ada.Streams.Stream_Element_Array;
      Ciphertext : Ada.Streams.Stream_Element_Array;
      Shared_Key : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      P : constant Parameters := Params (Set);
      PKE_Secret_Len : constant Stream_Element_Offset :=
        Stream_Element_Offset (P.K) * 384;
   begin
      Shared_Key := [others => 0];
      if Natural (Secret_Key'Length) /= P.SK_Len
        or else Natural (Ciphertext'Length) /= P.CT_Len
        or else Shared_Key'Length /= Shared_Key_Length
      then
         return Handshake_Failed;
      end if;

      declare
         Base : constant Stream_Element_Offset := Secret_Key'First;
         Public_Item : constant Stream_Element_Array :=
           Secret_Key (Base + PKE_Secret_Len
                       .. Base + PKE_Secret_Len
                          + Stream_Element_Offset (P.PK_Len) - 1);
         H_Item : constant Stream_Element_Array :=
           Secret_Key (Base + PKE_Secret_Len
                         + Stream_Element_Offset (P.PK_Len)
                       .. Base + PKE_Secret_Len
                         + Stream_Element_Offset (P.PK_Len) + 31);
         Z_Item : constant Stream_Element_Array :=
           Secret_Key (Secret_Key'Last - 31 .. Secret_Key'Last);
         Message : constant Stream_Element_Array :=
           PKE_Decrypt (P, Secret_Key (Base .. Base + PKE_Secret_Len - 1),
                        Ciphertext);
         Expanded : constant Stream_Element_Array :=
           G (Message & H_Item);
         Candidate : Stream_Element_Array (1 .. Stream_Element_Offset (P.CT_Len));
         --  The implicit-rejection secret, J (z || c).
         Rejection : constant Stream_Element_Array :=
           CryptoLib.SHA3.SHAKE256 (Z_Item & Ciphertext, 32);
         Equal : Stream_Element := 0;
      begin
         PKE_Encrypt (P, Public_Item, Message,
                      Expanded (Expanded'First + 32 .. Expanded'First + 63),
                      Candidate);

         --  Accumulate the difference rather than returning early: which
         --  ciphertext failed, and at which octet, must not be observable.
         for I in Candidate'Range loop
            Equal := Equal or
              (Candidate (I) xor
                 Ciphertext (Ciphertext'First + (I - Candidate'First)));
         end loop;

         declare
            --  0 when the re-encryption matched, 16#FF# when it did not.
            Mask : constant Stream_Element :=
              (if Equal = 0 then 0 else 16#FF#);
         begin
            for I in Shared_Key'Range loop
               declare
                  Offset : constant Stream_Element_Offset :=
                    I - Shared_Key'First;
                  Good : constant Stream_Element :=
                    Expanded (Expanded'First + Offset);
                  Bad  : constant Stream_Element :=
                    Rejection (Rejection'First + Offset);
               begin
                  Shared_Key (I) := (Good and not Mask) or (Bad and Mask);
               end;
            end loop;
         end;
      end;
      return Ok;
   exception
      when others =>
         Shared_Key := [others => 0];
         return Internal_Error;
   end Decapsulate;

end CryptoLib.MLKEM;
