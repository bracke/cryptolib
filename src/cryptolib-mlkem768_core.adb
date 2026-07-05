with CryptoLib.SHA3;

package body CryptoLib.MLKEM768_Core is
   use type Ada.Streams.Stream_Element_Offset;
   use type Ada.Streams.Stream_Element;

   Zetas : constant array (Positive range 1 .. 128) of Integer :=
     [2285, 2571, 2970, 1812, 1493, 1422, 287, 202,
      3158, 622, 1577, 182, 962, 2127, 1855, 1468,
      573, 2004, 264, 383, 2500, 1458, 1727, 3199,
      2648, 1017, 732, 608, 1787, 411, 3124, 1758,
      1223, 652, 2777, 1015, 2036, 1491, 3047, 1785,
      516, 3321, 3009, 2663, 1711, 2167, 126, 1469,
      2476, 3239, 3058, 830, 107, 1908, 3082, 2378,
      2931, 961, 1821, 2604, 448, 2264, 677, 2054,
      2226, 430, 555, 843, 2078, 871, 1550, 105,
      422, 587, 177, 3094, 3038, 2869, 1574, 1653,
      3083, 778, 1159, 3182, 2552, 1483, 2727, 1119,
      1739, 644, 2457, 349, 418, 329, 3173, 3254,
      817, 1097, 603, 610, 1322, 2044, 1864, 384,
      2114, 3193, 1218, 1994, 2455, 220, 2142, 1670,
      2144, 1799, 2051, 794, 1819, 2475, 2459, 478,
      3221, 3021, 996, 991, 958, 1869, 1522, 1628];

   function Montgomery_Reduce (Value : Long_Long_Integer) return Integer is
      QINV : constant Long_Long_Integer := 62209;
      Mask : constant Long_Long_Integer := 16#FFFF#;
      U    : constant Long_Long_Integer := (Value * QINV) mod (Mask + 1);
      T    : constant Long_Long_Integer := (Value - U * Long_Long_Integer (Q_Value)) / 65_536;
   begin
      return Reduce (Integer (T));
   end Montgomery_Reduce;

   function FQ_Mul
     (Left  : Integer;
      Right : Integer)
      return Integer
   is
   begin
      return Montgomery_Reduce (Long_Long_Integer (Left) * Long_Long_Integer (Right));
   end FQ_Mul;

   function Reduce (Value : Integer) return Integer
     with SPARK_Mode => On
   is
      Result : Integer := Value mod Q_Value;
   begin
      if Result < 0 then
         Result := Result + Q_Value;
      end if;
      return Result;
   end Reduce;

   function Power_Of_Two (Bits : Natural) return Integer is
      Result : Integer := 1;
   begin
      for Index_Value in 1 .. Bits loop
         Result := Result * 2;
      end loop;
      return Result;
   end Power_Of_Two;

   function Compress
     (Value : Integer;
      Bits  : Natural)
      return Integer
   is
      Modulus : constant Integer := Power_Of_Two (Bits);
      Clean   : constant Integer := Reduce (Value);
   begin
      --  FIPS 203 Compress_d(x) = Round((2**d / q) * x) mod 2**d.
      --  The integer expression below performs round-to-nearest by adding q/2
      --  before division and is independent of the input sign after Reduce.
      return ((Clean * Modulus + Q_Value / 2) / Q_Value) mod Modulus;
   end Compress;

   function Decompress
     (Value : Integer;
      Bits  : Natural)
      return Integer
   is
      Modulus : constant Integer := Power_Of_Two (Bits);
      Clean   : constant Integer := Value mod Modulus;
   begin
      --  FIPS 203 Decompress_d(y) = Round((q / 2**d) * y).
      return ((Clean * Q_Value) + Modulus / 2) / Modulus;
   end Decompress;

   function SE (Value : Natural) return Ada.Streams.Stream_Element
     with SPARK_Mode => On
   is
   begin
      return Ada.Streams.Stream_Element (Value mod 256);
   end SE;

   function XOF_Input
     (Rho    : Ada.Streams.Stream_Element_Array;
      Row    : Natural;
      Column : Natural)
      return Ada.Streams.Stream_Element_Array
   is
      Result : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Rho'Length + 2));
      Cursor : Ada.Streams.Stream_Element_Offset := Result'First;
   begin
      for Index_Value in Rho'Range loop
         Result (Cursor) := Rho (Index_Value);
         Cursor := Cursor + 1;
      end loop;
      Result (Cursor) := SE (Column);
      Result (Cursor + 1) := SE (Row);
      return Result;
   end XOF_Input;

   function Sample_NTT
     (Rho    : Ada.Streams.Stream_Element_Array;
      Row    : Natural;
      Column : Natural)
      return Polynomial
   is
      Result      : Polynomial := [others => 0];
      Count_Value : Natural := 0;
      --  FIPS 203 RejNTTPoly: absorb rho || j || i into SHAKE128 ONCE and
      --  reject-sample 12-bit candidates (< q) from a single continuous squeeze.
      --  SHAKE is an XOF; the previous code re-absorbed rho||j||i||round with an
      --  incrementing counter, producing a non-standard stream.  One squeeze of
      --  this length yields far more candidates than the 256 coefficients need.
      Buffer      : constant Ada.Streams.Stream_Element_Array :=
        CryptoLib.SHA3.SHAKE128 (XOF_Input (Rho, Row, Column), 168 * 16);
      Offset_Value : Ada.Streams.Stream_Element_Offset := Buffer'First;
   begin
      while Offset_Value + 2 <= Buffer'Last and then Count_Value < N_Value loop
         declare
            B0 : constant Integer := Integer (Buffer (Offset_Value));
            B1 : constant Integer := Integer (Buffer (Offset_Value + 1));
            B2 : constant Integer := Integer (Buffer (Offset_Value + 2));
            D1 : constant Integer := B0 + 256 * (B1 mod 16);
            D2 : constant Integer := (B1 / 16) + 16 * B2;
         begin
            if D1 < Q_Value then
               Result (Count_Value) := D1;
               Count_Value := Count_Value + 1;
            end if;
            if Count_Value < N_Value and then D2 < Q_Value then
               Result (Count_Value) := D2;
               Count_Value := Count_Value + 1;
            end if;
         end;
         Offset_Value := Offset_Value + 3;
      end loop;
      return Result;
   end Sample_NTT;

   function Bit_Count_4 (Value : Integer) return Integer
     with SPARK_Mode => On,
          Post => Bit_Count_4'Result in 0 .. 4
   is
      Result : Integer := 0;
      Clean  : Integer := Value mod 16;
   begin
      for Index_Value in 0 .. 3 loop
         Result := Result + (Clean mod 2);
         Clean := Clean / 2;
      end loop;
      return Result;
   end Bit_Count_4;

   function CBD_Eta2
     (Bytes : Ada.Streams.Stream_Element_Array)
      return Polynomial
   is
      Result : Polynomial := [others => 0];
      Need   : constant Natural := 128;
   begin
      if Bytes'Length < Need then
         return Result;
      end if;

      for Index_Value in 0 .. N_Value - 1 loop
         declare
            Byte_Value : constant Integer := Integer
              (Bytes (Bytes'First + Ada.Streams.Stream_Element_Offset (Index_Value / 2)));
            Low_Nib   : constant Integer := Byte_Value mod 16;
            High_Nib  : constant Integer := Byte_Value / 16;
         begin
            if Index_Value mod 2 = 0 then
               Result (Index_Value) := Bit_Count_4 (Low_Nib mod 4)
                 - Bit_Count_4 (Low_Nib / 4);
            else
               Result (Index_Value) := Bit_Count_4 (High_Nib mod 4)
                 - Bit_Count_4 (High_Nib / 4);
            end if;
            Result (Index_Value) := Reduce (Result (Index_Value));
         end;
      end loop;
      return Result;
   end CBD_Eta2;

   function Add
     (Left  : Polynomial;
      Right : Polynomial)
      return Polynomial
   is
      Result : Polynomial := [others => 0];
   begin
      for Index_Value in Coefficient_Index loop
         Result (Index_Value) := Reduce (Left (Index_Value) + Right (Index_Value));
      end loop;
      return Result;
   end Add;

   function Subtract
     (Left  : Polynomial;
      Right : Polynomial)
      return Polynomial
   is
      Result : Polynomial := [others => 0];
   begin
      for Index_Value in Coefficient_Index loop
         Result (Index_Value) := Reduce (Left (Index_Value) - Right (Index_Value));
      end loop;
      return Result;
   end Subtract;

   function NTT
     (Item : Polynomial)
      return Polynomial
   is
      Result      : Polynomial := Item;
      Len_Value   : Natural := 128;
      --  Zetas (1) is zeta_brv(0) = -1044; the reference NTT starts at
      --  zeta_brv(1), i.e. Zetas (2).  (Zetas (1) is only used by base-case
      --  multiplication.)
      K_Value_NTT : Positive := 2;
   begin
      --  ML-KEM forward NTT, following the Kyber/FIPS 203 butterfly schedule
      --  over R_q = Z_q[x]/(x^256 + 1).  Zetas are stored in Montgomery form,
      --  and products use Montgomery reduction as in the reference algorithm.
      while Len_Value >= 2 loop
         declare
            Start_Value : Natural := 0;
         begin
            while Start_Value < N_Value loop
               declare
                  Zeta_Value : constant Integer := Zetas (K_Value_NTT);
               begin
                  K_Value_NTT := K_Value_NTT + 1;
                  for J_Value in Start_Value .. Start_Value + Len_Value - 1 loop
                     declare
                        T_Value : constant Integer :=
                          FQ_Mul (Zeta_Value, Result (J_Value + Len_Value));
                        A_Value : constant Integer := Result (J_Value);
                     begin
                        Result (J_Value + Len_Value) := Reduce (A_Value - T_Value);
                        Result (J_Value) := Reduce (A_Value + T_Value);
                     end;
                  end loop;
               end;
               Start_Value := Start_Value + 2 * Len_Value;
            end loop;
         end;
         Len_Value := Len_Value / 2;
      end loop;
      return Result;
   end NTT;

   function Inverse_NTT
     (Item : Polynomial)
      return Polynomial
   is
      Result      : Polynomial := Item;
      Len_Value   : Natural := 2;
      --  Mirror of the forward transform's index: the reference inverse NTT
      --  starts at zeta_brv(127), i.e. Zetas (128), and counts down.
      K_Value_NTT : Integer := 128;
      --  Final normalisation.  The butterflies leave 128*x in the NORMAL domain
      --  (this core keeps forward-NTT output in the normal domain, unlike the
      --  reference which stays in Montgomery form).  FQ_Mul applies R^-1, so the
      --  factor that yields x is R/128 = 512, not the reference's mont^2/128.
      F_Value     : constant Integer := 512;
   begin
      --  ML-KEM inverse NTT.  The final multiplication by 1441 is the
      --  reference n^{-1} Montgomery factor for n=256 mod q.
      while Len_Value <= 128 loop
         declare
            Start_Value : Natural := 0;
         begin
            while Start_Value < N_Value loop
               declare
                  Zeta_Value : constant Integer := Zetas (K_Value_NTT);
               begin
                  K_Value_NTT := K_Value_NTT - 1;
                  for J_Value in Start_Value .. Start_Value + Len_Value - 1 loop
                     declare
                        T_Value : constant Integer := Result (J_Value);
                     begin
                        Result (J_Value) := Reduce (T_Value + Result (J_Value + Len_Value));
                        Result (J_Value + Len_Value) :=
                          FQ_Mul (Zeta_Value, Result (J_Value + Len_Value) - T_Value);
                     end;
                  end loop;
               end;
               Start_Value := Start_Value + 2 * Len_Value;
            end loop;
         end;
         Len_Value := Len_Value * 2;
      end loop;

      for Index_Value in Coefficient_Index loop
         Result (Index_Value) := FQ_Mul (Result (Index_Value), F_Value);
      end loop;
      return Result;
   end Inverse_NTT;

   function Ring_Multiply_Reference
     (Left  : Polynomial;
      Right : Polynomial)
      return Polynomial
   is
      Result : Polynomial := [others => 0];
   begin
      --  Slow, direct multiplication in Z_q[x]/(x^256 + 1).  This is retained
      --  as a deterministic audit/reference path for the optimized NTT layer.
      for I_Value in Coefficient_Index loop
         for J_Value in Coefficient_Index loop
            declare
               Product_Value : constant Integer := Left (I_Value) * Right (J_Value);
               Degree_Value  : constant Natural := I_Value + J_Value;
            begin
               if Degree_Value < N_Value then
                  Result (Degree_Value) := Reduce (Result (Degree_Value) + Product_Value);
               else
                  Result (Degree_Value - N_Value) :=
                    Reduce (Result (Degree_Value - N_Value) - Product_Value);
               end if;
            end;
         end loop;
      end loop;
      return Result;
   end Ring_Multiply_Reference;

   function Pointwise_Multiply
     (Left  : Polynomial;
      Right : Polynomial)
      return Polynomial
   is
      --  Conservative correctness-first path: multiply through the reference
      --  ring and return the NTT-domain representation.  This keeps the public
      --  CPA-PKE layer independent from the specialized base-multiplication
      --  schedule until the latter is covered by KATs.
   begin
      return NTT (Ring_Multiply_Reference (Inverse_NTT (Left), Inverse_NTT (Right)));
   end Pointwise_Multiply;

   procedure Put_Bits
     (Output      : in out Ada.Streams.Stream_Element_Array;
      Bit_Offset  : Natural;
      Value       : Integer;
      Width       : Natural)
   is
      Clean : Integer := Value;
   begin
      for Bit_Index in 0 .. Width - 1 loop
         if Clean mod 2 /= 0 then
            declare
               Byte_Index : constant Ada.Streams.Stream_Element_Offset :=
                 Output'First + Ada.Streams.Stream_Element_Offset ((Bit_Offset + Bit_Index) / 8);
               Bit_In_Byte : constant Natural := (Bit_Offset + Bit_Index) mod 8;
            begin
               Output (Byte_Index) := Output (Byte_Index) + SE (2 ** Bit_In_Byte);
            end;
         end if;
         Clean := Clean / 2;
      end loop;
   end Put_Bits;

   function Get_Bits
     (Input      : Ada.Streams.Stream_Element_Array;
      Bit_Offset : Natural;
      Width      : Natural)
      return Integer
   is
      Result : Integer := 0;
      Factor : Integer := 1;
   begin
      for Bit_Index in 0 .. Width - 1 loop
         declare
            Byte_Index : constant Ada.Streams.Stream_Element_Offset :=
              Input'First + Ada.Streams.Stream_Element_Offset ((Bit_Offset + Bit_Index) / 8);
            Bit_In_Byte : constant Natural := (Bit_Offset + Bit_Index) mod 8;
            Byte_Value  : constant Integer := Integer (Input (Byte_Index));
         begin
            if (Byte_Value / (2 ** Bit_In_Byte)) mod 2 = 1 then
               Result := Result + Factor;
            end if;
            Factor := Factor * 2;
         end;
      end loop;
      return Result;
   end Get_Bits;

   function Encode_12
     (Item : Polynomial)
      return Encoded_Poly_12
   is
      Result : Encoded_Poly_12 := [others => 0];
   begin
      for Index_Value in Coefficient_Index loop
         Put_Bits (Result, Index_Value * 12, Reduce (Item (Index_Value)), 12);
      end loop;
      return Result;
   end Encode_12;

   function Decode_12
     (Bytes : Encoded_Poly_12)
      return Polynomial
   is
      Result : Polynomial := [others => 0];
   begin
      for Index_Value in Coefficient_Index loop
         Result (Index_Value) := Reduce (Get_Bits (Bytes, Index_Value * 12, 12));
      end loop;
      return Result;
   end Decode_12;

   function Compress_Encode_10
     (Item : Polynomial)
      return Encoded_Poly_10
   is
      Result : Encoded_Poly_10 := [others => 0];
   begin
      for Index_Value in Coefficient_Index loop
         Put_Bits (Result, Index_Value * 10, Compress (Item (Index_Value), 10), 10);
      end loop;
      return Result;
   end Compress_Encode_10;

   function Decode_Decompress_10
     (Bytes : Encoded_Poly_10)
      return Polynomial
   is
      Result : Polynomial := [others => 0];
   begin
      for Index_Value in Coefficient_Index loop
         Result (Index_Value) := Decompress (Get_Bits (Bytes, Index_Value * 10, 10), 10);
      end loop;
      return Result;
   end Decode_Decompress_10;

   function Compress_Encode_4
     (Item : Polynomial)
      return Encoded_Poly_4
   is
      Result : Encoded_Poly_4 := [others => 0];
   begin
      for Index_Value in Coefficient_Index loop
         Put_Bits (Result, Index_Value * 4, Compress (Item (Index_Value), 4), 4);
      end loop;
      return Result;
   end Compress_Encode_4;

   function Decode_Decompress_4
     (Bytes : Encoded_Poly_4)
      return Polynomial
   is
      Result : Polynomial := [others => 0];
   begin
      for Index_Value in Coefficient_Index loop
         Result (Index_Value) := Decompress (Get_Bits (Bytes, Index_Value * 4, 4), 4);
      end loop;
      return Result;
   end Decode_Decompress_4;

   function Nonce_Input
     (Seed        : MLKEM_Noise_Seed;
      Nonce_Value : Natural)
      return Ada.Streams.Stream_Element_Array
   is
      Result : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Seed'Length + 1));
      Cursor : Ada.Streams.Stream_Element_Offset := Result'First;
   begin
      for Index_Value in Seed'Range loop
         Result (Cursor) := Seed (Index_Value);
         Cursor := Cursor + 1;
      end loop;
      Result (Cursor) := SE (Nonce_Value);
      return Result;
   end Nonce_Input;

   function Sample_Noise_Eta2
     (Seed        : MLKEM_Noise_Seed;
      Nonce_Value : Natural)
      return Polynomial
   is
      Bytes : constant Ada.Streams.Stream_Element_Array :=
        CryptoLib.SHA3.SHAKE256 (Nonce_Input (Seed, Nonce_Value), 128);
   begin
      return CBD_Eta2 (Bytes);
   end Sample_Noise_Eta2;

   function Add
     (Left  : Polyvec;
      Right : Polyvec)
      return Polyvec
   is
      Result : Polyvec := [others => [others => 0]];
   begin
      for Index_Value in Vector_Index loop
         Result (Index_Value) := Add (Left (Index_Value), Right (Index_Value));
      end loop;
      return Result;
   end Add;

   function Subtract
     (Left  : Polyvec;
      Right : Polyvec)
      return Polyvec
   is
      Result : Polyvec := [others => [others => 0]];
   begin
      for Index_Value in Vector_Index loop
         Result (Index_Value) := Subtract (Left (Index_Value), Right (Index_Value));
      end loop;
      return Result;
   end Subtract;

   function Dot_Product
     (Left  : Polyvec;
      Right : Polyvec)
      return Polynomial
   is
      Result : Polynomial := [others => 0];
   begin
      for Index_Value in Vector_Index loop
         Result := Add
           (Result,
            Ring_Multiply_Reference (Left (Index_Value), Right (Index_Value)));
      end loop;
      return Result;
   end Dot_Product;

   function Matrix_Element
     (Rho    : MLKEM_Public_Seed;
      Row    : Natural;
      Column : Natural)
      return Polynomial
   is
   begin
      return Sample_NTT (Rho, Row, Column);
   end Matrix_Element;

   function Encode_12
     (Item : Polyvec)
      return Encoded_Polyvec_12
   is
      Result : Encoded_Polyvec_12 := [others => 0];
   begin
      for Vector_Value in Vector_Index loop
         declare
            Encoded : constant Encoded_Poly_12 := Encode_12 (Item (Vector_Value));
            Base    : constant Ada.Streams.Stream_Element_Offset :=
              Result'First + Ada.Streams.Stream_Element_Offset (Vector_Value * 384);
         begin
            for Offset_Value in 0 .. 383 loop
               Result (Base + Ada.Streams.Stream_Element_Offset (Offset_Value)) :=
                 Encoded (Encoded'First + Ada.Streams.Stream_Element_Offset (Offset_Value));
            end loop;
         end;
      end loop;
      return Result;
   end Encode_12;

   function Decode_12
     (Bytes : Encoded_Polyvec_12)
      return Polyvec
   is
      Result : Polyvec := [others => [others => 0]];
   begin
      for Vector_Value in Vector_Index loop
         declare
            Encoded : Encoded_Poly_12 := [others => 0];
            Base    : constant Ada.Streams.Stream_Element_Offset :=
              Bytes'First + Ada.Streams.Stream_Element_Offset (Vector_Value * 384);
         begin
            for Offset_Value in 0 .. 383 loop
               Encoded (Encoded'First + Ada.Streams.Stream_Element_Offset (Offset_Value)) :=
                 Bytes (Base + Ada.Streams.Stream_Element_Offset (Offset_Value));
            end loop;
            Result (Vector_Value) := Decode_12 (Encoded);
         end;
      end loop;
      return Result;
   end Decode_12;

   function Compress_Encode_10
     (Item : Polyvec)
      return Encoded_Polyvec_10
   is
      Result : Encoded_Polyvec_10 := [others => 0];
   begin
      for Vector_Value in Vector_Index loop
         declare
            Encoded : constant Encoded_Poly_10 := Compress_Encode_10 (Item (Vector_Value));
            Base    : constant Ada.Streams.Stream_Element_Offset :=
              Result'First + Ada.Streams.Stream_Element_Offset (Vector_Value * 320);
         begin
            for Offset_Value in 0 .. 319 loop
               Result (Base + Ada.Streams.Stream_Element_Offset (Offset_Value)) :=
                 Encoded (Encoded'First + Ada.Streams.Stream_Element_Offset (Offset_Value));
            end loop;
         end;
      end loop;
      return Result;
   end Compress_Encode_10;

   function Decode_Decompress_10
     (Bytes : Encoded_Polyvec_10)
      return Polyvec
   is
      Result : Polyvec := [others => [others => 0]];
   begin
      for Vector_Value in Vector_Index loop
         declare
            Encoded : Encoded_Poly_10 := [others => 0];
            Base    : constant Ada.Streams.Stream_Element_Offset :=
              Bytes'First + Ada.Streams.Stream_Element_Offset (Vector_Value * 320);
         begin
            for Offset_Value in 0 .. 319 loop
               Encoded (Encoded'First + Ada.Streams.Stream_Element_Offset (Offset_Value)) :=
                 Bytes (Base + Ada.Streams.Stream_Element_Offset (Offset_Value));
            end loop;
            Result (Vector_Value) := Decode_Decompress_10 (Encoded);
         end;
      end loop;
      return Result;
   end Decode_Decompress_10;

   function Message_To_Poly
     (Message : MLKEM_Message)
      return Polynomial
   is
      Result : Polynomial := [others => 0];
   begin
      for Index_Value in Coefficient_Index loop
         declare
            Byte_Index : constant Ada.Streams.Stream_Element_Offset :=
              Message'First + Ada.Streams.Stream_Element_Offset (Index_Value / 8);
            Bit_Index  : constant Natural := Index_Value mod 8;
            Bit_Value  : constant Integer :=
              (Integer (Message (Byte_Index)) / (2 ** Bit_Index)) mod 2;
         begin
            Result (Index_Value) := Decompress (Bit_Value, 1);
         end;
      end loop;
      return Result;
   end Message_To_Poly;

   function Poly_To_Message
     (Item : Polynomial)
      return MLKEM_Message
   is
      Result : MLKEM_Message := [others => 0];
   begin
      for Index_Value in Coefficient_Index loop
         declare
            Bit_Value  : constant Integer := Compress (Item (Index_Value), 1) mod 2;
            Byte_Index : constant Ada.Streams.Stream_Element_Offset :=
              Result'First + Ada.Streams.Stream_Element_Offset (Index_Value / 8);
            Bit_Index  : constant Natural := Index_Value mod 8;
         begin
            if Bit_Value = 1 then
               Result (Byte_Index) := Result (Byte_Index) + SE (2 ** Bit_Index);
            end if;
         end;
      end loop;
      return Result;
   end Poly_To_Message;

   procedure Copy_To_Public_Key
     (Encoded_T   : Encoded_Polyvec_12;
      Rho         : MLKEM_Public_Seed;
      Public_Item : out PKE_Public_Key)
   is
      Cursor : Ada.Streams.Stream_Element_Offset := Public_Item'First;
   begin
      for Index_Value in Encoded_T'Range loop
         Public_Item (Cursor) := Encoded_T (Index_Value);
         Cursor := Cursor + 1;
      end loop;
      for Index_Value in Rho'Range loop
         Public_Item (Cursor) := Rho (Index_Value);
         Cursor := Cursor + 1;
      end loop;
   end Copy_To_Public_Key;

   procedure Split_Public_Key
     (Public_Item : PKE_Public_Key;
      T_Value     : out Polyvec;
      Rho         : out MLKEM_Public_Seed)
   is
      Encoded_T : Encoded_Polyvec_12 := [others => 0];
      Cursor    : Ada.Streams.Stream_Element_Offset := Public_Item'First;
   begin
      for Index_Value in Encoded_T'Range loop
         Encoded_T (Index_Value) := Public_Item (Cursor);
         Cursor := Cursor + 1;
      end loop;
      T_Value := Decode_12 (Encoded_T);
      for Index_Value in Rho'Range loop
         Rho (Index_Value) := Public_Item (Cursor);
         Cursor := Cursor + 1;
      end loop;
   end Split_Public_Key;

   procedure PKE_Keygen_From_Seeds
     (Rho         : MLKEM_Public_Seed;
      Sigma       : MLKEM_Noise_Seed;
      Public_Item : out PKE_Public_Key;
      Secret_Item : out PKE_Secret_Key)
   is
      S_Value : Polyvec := [others => [others => 0]];
      E_Value : Polyvec := [others => [others => 0]];
      T_Value : Polyvec := [others => [others => 0]];
      Encoded_S : Encoded_Polyvec_12 := [others => 0];
   begin
      --  FIPS 203 K-PKE.KeyGen works in the NTT domain: s-hat = NTT(s),
      --  e-hat = NTT(e), t-hat = A-hat o s-hat + e-hat (pointwise); the public
      --  and secret keys store the NTT representatives t-hat and s-hat.
      for Index_Value in Vector_Index loop
         S_Value (Index_Value) := NTT (Sample_Noise_Eta2 (Sigma, Index_Value));
         E_Value (Index_Value) :=
           NTT (Sample_Noise_Eta2 (Sigma, K_Value + Index_Value));
      end loop;

      for Row_Value in Vector_Index loop
         declare
            Accumulator : Polynomial := [others => 0];
         begin
            for Column_Value in Vector_Index loop
               Accumulator := Add
                 (Accumulator,
                  Pointwise_Multiply
                    (Matrix_Element (Rho, Row_Value, Column_Value),
                     S_Value (Column_Value)));
            end loop;
            T_Value (Row_Value) := Add (Accumulator, E_Value (Row_Value));
         end;
      end loop;

      Copy_To_Public_Key (Encode_12 (T_Value), Rho, Public_Item);
      Encoded_S := Encode_12 (S_Value);
      for Index_Value in Secret_Item'Range loop
         Secret_Item (Index_Value) := Encoded_S (Encoded_S'First + (Index_Value - Secret_Item'First));
      end loop;
   end PKE_Keygen_From_Seeds;

   procedure PKE_Encrypt_Deterministic
     (Public_Item     : PKE_Public_Key;
      Message         : MLKEM_Message;
      Random_Coins    : MLKEM_Noise_Seed;
      Ciphertext_Item : out PKE_Ciphertext)
   is
      T_Value : Polyvec := [others => [others => 0]];
      Rho     : MLKEM_Public_Seed := [others => 0];
      Y_Value : Polyvec := [others => [others => 0]];
      E1_Value : Polyvec := [others => [others => 0]];
      E2_Value : Polynomial := [others => 0];
      U_Value : Polyvec := [others => [others => 0]];
      V_Value : Polynomial := [others => 0];
      Encoded_U : Encoded_Polyvec_10 := [others => 0];
      Encoded_V : Encoded_Poly_4 := [others => 0];
      Cursor    : Ada.Streams.Stream_Element_Offset := Ciphertext_Item'First;
   begin
      --  FIPS 203 K-PKE.Encrypt in the NTT domain: y-hat = NTT(y);
      --  u = NTT^-1(A^T o y-hat) + e1; v = NTT^-1(t-hat^T o y-hat) + e2 + mu.
      --  T_Value already holds t-hat (the public key stores NTT representatives);
      --  the noise vectors e1, e2 stay in the normal domain.
      Split_Public_Key (Public_Item, T_Value, Rho);
      for Index_Value in Vector_Index loop
         Y_Value (Index_Value) :=
           NTT (Sample_Noise_Eta2 (Random_Coins, Index_Value));
         E1_Value (Index_Value) :=
           Sample_Noise_Eta2 (Random_Coins, K_Value + Index_Value);
      end loop;
      E2_Value := Sample_Noise_Eta2 (Random_Coins, 2 * K_Value);

      for Column_Value in Vector_Index loop
         declare
            Accumulator : Polynomial := [others => 0];
         begin
            for Row_Value in Vector_Index loop
               Accumulator := Add
                 (Accumulator,
                  Pointwise_Multiply
                    (Matrix_Element (Rho, Row_Value, Column_Value),
                     Y_Value (Row_Value)));
            end loop;
            U_Value (Column_Value) :=
              Add (Inverse_NTT (Accumulator), E1_Value (Column_Value));
         end;
      end loop;

      declare
         V_Hat : Polynomial := [others => 0];
      begin
         for Index_Value in Vector_Index loop
            V_Hat := Add
              (V_Hat,
               Pointwise_Multiply (T_Value (Index_Value), Y_Value (Index_Value)));
         end loop;
         V_Value := Add (Add (Inverse_NTT (V_Hat), E2_Value),
                         Message_To_Poly (Message));
      end;
      Encoded_U := Compress_Encode_10 (U_Value);
      Encoded_V := Compress_Encode_4 (V_Value);

      for Index_Value in Encoded_U'Range loop
         Ciphertext_Item (Cursor) := Encoded_U (Index_Value);
         Cursor := Cursor + 1;
      end loop;
      for Index_Value in Encoded_V'Range loop
         Ciphertext_Item (Cursor) := Encoded_V (Index_Value);
         Cursor := Cursor + 1;
      end loop;
   end PKE_Encrypt_Deterministic;

   function PKE_Decrypt
     (Secret_Item     : PKE_Secret_Key;
      Ciphertext_Item : PKE_Ciphertext)
      return MLKEM_Message
   is
      Encoded_S : Encoded_Polyvec_12 := [others => 0];
      Encoded_U : Encoded_Polyvec_10 := [others => 0];
      Encoded_V : Encoded_Poly_4 := [others => 0];
      Cursor : Ada.Streams.Stream_Element_Offset := Ciphertext_Item'First;
      S_Value : Polyvec := [others => [others => 0]];
      U_Value : Polyvec := [others => [others => 0]];
      V_Value : Polynomial := [others => 0];
   begin
      for Index_Value in Encoded_S'Range loop
         Encoded_S (Index_Value) := Secret_Item (Secret_Item'First + (Index_Value - Encoded_S'First));
      end loop;
      S_Value := Decode_12 (Encoded_S);

      for Index_Value in Encoded_U'Range loop
         Encoded_U (Index_Value) := Ciphertext_Item (Cursor);
         Cursor := Cursor + 1;
      end loop;
      for Index_Value in Encoded_V'Range loop
         Encoded_V (Index_Value) := Ciphertext_Item (Cursor);
         Cursor := Cursor + 1;
      end loop;

      U_Value := Decode_Decompress_10 (Encoded_U);
      V_Value := Decode_Decompress_4 (Encoded_V);
      --  FIPS 203 K-PKE.Decrypt: w = v - NTT^-1(s-hat^T o NTT(u)); S_Value is
      --  s-hat (the secret key stores NTT representatives).
      declare
         W_Hat : Polynomial := [others => 0];
      begin
         for Index_Value in Vector_Index loop
            W_Hat := Add
              (W_Hat,
               Pointwise_Multiply (S_Value (Index_Value),
                                   NTT (U_Value (Index_Value))));
         end loop;
         return Poly_To_Message (Subtract (V_Value, Inverse_NTT (W_Hat)));
      end;
   end PKE_Decrypt;

end CryptoLib.MLKEM768_Core;
