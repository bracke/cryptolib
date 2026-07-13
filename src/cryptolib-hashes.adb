
package body CryptoLib.Hashes is
   use type Ada.Streams.Stream_Element_Offset;
   --  One-shot SHA-1 via the streaming context, so a large input is hashed
   --  block-at-a-time without allocating the whole padded message on the
   --  stack (mirrors the SHA-256 one-shot below).
   function SHA1
     (Data : Ada.Streams.Stream_Element_Array)
      return SHA1_Digest
   is
      Context_Item : SHA1_Context;
   begin
      Initialize_SHA1 (Context_Item);
      Update (Context_Item, Data);
      return Finalize (Context_Item);
   end SHA1;

   use Interfaces;

   subtype Word is Unsigned_32;

   function MD5
     (Data : Ada.Streams.Stream_Element_Array)
      return MD5_Digest
   is
      subtype Word32 is Unsigned_32;
      S : constant array (Natural range 0 .. 63) of Natural :=
        [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
         5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
      K : constant array (Natural range 0 .. 63) of Word32 :=
        [16#D76AA478#, 16#E8C7B756#, 16#242070DB#, 16#C1BDCEEE#,
         16#F57C0FAF#, 16#4787C62A#, 16#A8304613#, 16#FD469501#,
         16#698098D8#, 16#8B44F7AF#, 16#FFFF5BB1#, 16#895CD7BE#,
         16#6B901122#, 16#FD987193#, 16#A679438E#, 16#49B40821#,
         16#F61E2562#, 16#C040B340#, 16#265E5A51#, 16#E9B6C7AA#,
         16#D62F105D#, 16#02441453#, 16#D8A1E681#, 16#E7D3FBC8#,
         16#21E1CDE6#, 16#C33707D6#, 16#F4D50D87#, 16#455A14ED#,
         16#A9E3E905#, 16#FCEFA3F8#, 16#676F02D9#, 16#8D2A4C8A#,
         16#FFFA3942#, 16#8771F681#, 16#6D9D6122#, 16#FDE5380C#,
         16#A4BEEA44#, 16#4BDECFA9#, 16#F6BB4B60#, 16#BEBFBC70#,
         16#289B7EC6#, 16#EAA127FA#, 16#D4EF3085#, 16#04881D05#,
         16#D9D4D039#, 16#E6DB99E5#, 16#1FA27CF8#, 16#C4AC5665#,
         16#F4292244#, 16#432AFF97#, 16#AB9423A7#, 16#FC93A039#,
         16#655B59C3#, 16#8F0CCC92#, 16#FFEFF47D#, 16#85845DD1#,
         16#6FA87E4F#, 16#FE2CE6E0#, 16#A3014314#, 16#4E0811A1#,
         16#F7537E82#, 16#BD3AF235#, 16#2AD7D2BB#, 16#EB86D391#];
      Total_Length : constant Natural :=
        Data'Length
        + 1
        + Natural ((56 - ((Data'Length + 1) mod 64)) mod 64)
        + 8;
      Padded : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Total_Length)) :=
          [others => 0];
      Bit_Length : constant Unsigned_64 :=
        Unsigned_64 (Data'Length) * 8;
      A0 : Word32 := 16#67452301#;
      B0 : Word32 := 16#EFCDAB89#;
      C0 : Word32 := 16#98BADCFE#;
      D0 : Word32 := 16#10325476#;

      function LE_Word
        (Offset_Value : Ada.Streams.Stream_Element_Offset) return Word32 is
      begin
         return Word32 (Padded (Offset_Value))
           or Shift_Left (Word32 (Padded (Offset_Value + 1)), 8)
           or Shift_Left (Word32 (Padded (Offset_Value + 2)), 16)
           or Shift_Left (Word32 (Padded (Offset_Value + 3)), 24);
      end LE_Word;

      procedure Store_MD5_LE
        (Output      : in out MD5_Digest;
         First_Index : MD5_Digest_Index;
         Value       : Word32) is
      begin
         Output (First_Index) := Ada.Streams.Stream_Element (Value and 16#FF#);
         Output (First_Index + 1) :=
           Ada.Streams.Stream_Element
             (Shift_Right (Value, 8) and 16#FF#);
         Output (First_Index + 2) :=
           Ada.Streams.Stream_Element
             (Shift_Right (Value, 16) and 16#FF#);
         Output (First_Index + 3) :=
           Ada.Streams.Stream_Element
             (Shift_Right (Value, 24) and 16#FF#);
      end Store_MD5_LE;
   begin
      for Offset_Value in 0 .. Data'Length - 1 loop
         Padded (Padded'First + Ada.Streams.Stream_Element_Offset (Offset_Value)) :=
           Data (Data'First + Ada.Streams.Stream_Element_Offset (Offset_Value));
      end loop;
      Padded (Padded'First + Ada.Streams.Stream_Element_Offset (Data'Length)) :=
        16#80#;
      for Offset_Value in 0 .. 7 loop
         Padded (Padded'Last - Ada.Streams.Stream_Element_Offset (7 - Offset_Value)) :=
           Ada.Streams.Stream_Element
             (Shift_Right (Bit_Length, 8 * Offset_Value) and 16#FF#);
      end loop;

      declare
         Block_First : Ada.Streams.Stream_Element_Offset := Padded'First;
      begin
         while Block_First <= Padded'Last loop
            declare
               M       : array (Natural range 0 .. 15) of Word32 :=
                 [others => 0];
               A       : Word32 := A0;
               B       : Word32 := B0;
               C       : Word32 := C0;
               D       : Word32 := D0;
               F_Value : Word32;
               G_Value : Natural;
               Temp    : Word32;
            begin
               for Word_Index in 0 .. 15 loop
                  M (Word_Index) :=
                    LE_Word
                      (Block_First +
                       Ada.Streams.Stream_Element_Offset (Word_Index * 4));
               end loop;
               for Round_Index in 0 .. 63 loop
                  if Round_Index < 16 then
                     F_Value := (B and C) or ((not B) and D);
                     G_Value := Round_Index;
                  elsif Round_Index < 32 then
                     F_Value := (D and B) or ((not D) and C);
                     G_Value := (5 * Round_Index + 1) mod 16;
                  elsif Round_Index < 48 then
                     F_Value := B xor C xor D;
                     G_Value := (3 * Round_Index + 5) mod 16;
                  else
                     F_Value := C xor (B or (not D));
                     G_Value := (7 * Round_Index) mod 16;
                  end if;
                  Temp := D;
                  D := C;
                  C := B;
                  B :=
                    B + Rotate_Left
                      (A + F_Value + K (Round_Index) + M (G_Value),
                       S (Round_Index));
                  A := Temp;
               end loop;
               A0 := A0 + A;
               B0 := B0 + B;
               C0 := C0 + C;
               D0 := D0 + D;
            end;
            Block_First := Block_First + 64;
         end loop;
      end;

      return Result : MD5_Digest :=
        [others => 0]
      do
         Store_MD5_LE (Result, 1, A0);
         Store_MD5_LE (Result, 5, B0);
         Store_MD5_LE (Result, 9, C0);
         Store_MD5_LE (Result, 13, D0);
         Padded := [others => 0];
      end return;
   exception
      when others =>
         return [others => 0];
   end MD5;

   K_Values : constant array (Natural range 0 .. 63) of Word :=
     [16#428A_2F98#, 16#7137_4491#, 16#B5C0_FBCF#, 16#E9B5_DBA5#,
      16#3956_C25B#, 16#59F1_11F1#, 16#923F_82A4#, 16#AB1C_5ED5#,
      16#D807_AA98#, 16#1283_5B01#, 16#2431_85BE#, 16#550C_7DC3#,
      16#72BE_5D74#, 16#80DE_B1FE#, 16#9BDC_06A7#, 16#C19B_F174#,
      16#E49B_69C1#, 16#EFBE_4786#, 16#0FC1_9DC6#, 16#240C_A1CC#,
      16#2DE9_2C6F#, 16#4A74_84AA#, 16#5CB0_A9DC#, 16#76F9_88DA#,
      16#983E_5152#, 16#A831_C66D#, 16#B003_27C8#, 16#BF59_7FC7#,
      16#C6E0_0BF3#, 16#D5A7_9147#, 16#06CA_6351#, 16#1429_2967#,
      16#27B7_0A85#, 16#2E1B_2138#, 16#4D2C_6DFC#, 16#5338_0D13#,
      16#650A_7354#, 16#766A_0ABB#, 16#81C2_C92E#, 16#9272_2C85#,
      16#A2BF_E8A1#, 16#A81A_664B#, 16#C24B_8B70#, 16#C76C_51A3#,
      16#D192_E819#, 16#D699_0624#, 16#F40E_3585#, 16#106A_A070#,
      16#19A4_C116#, 16#1E37_6C08#, 16#2748_774C#, 16#34B0_BCB5#,
      16#391C_0CB3#, 16#4ED8_AA4A#, 16#5B9C_CA4F#, 16#682E_6FF3#,
      16#748F_82EE#, 16#78A5_636F#, 16#84C8_7814#, 16#8CC7_0208#,
      16#90BE_FFFA#, 16#A450_6CEB#, 16#BEF9_A3F7#, 16#C671_78F2#];

   function Rotate_Right (Value : Word; Amount : Natural) return Word
     with SPARK_Mode => On,
          Pre => Amount <= 32
   is
   begin
      return Shift_Right (Value, Amount) or Shift_Left (Value, 32 - Amount);
   end Rotate_Right;

   function Ch (X_Value : Word; Y_Value : Word; Z_Value : Word) return Word
     with SPARK_Mode => On
   is
   begin
      return (X_Value and Y_Value) xor ((not X_Value) and Z_Value);
   end Ch;

   function Maj (X_Value : Word; Y_Value : Word; Z_Value : Word) return Word
     with SPARK_Mode => On
   is
   begin
      return (X_Value and Y_Value) xor (X_Value and Z_Value) xor (Y_Value and Z_Value);
   end Maj;

   function Big_Sigma_0 (Value : Word) return Word
     with SPARK_Mode => On
   is
   begin
      return Rotate_Right (Value, 2) xor Rotate_Right (Value, 13) xor Rotate_Right (Value, 22);
   end Big_Sigma_0;

   function Big_Sigma_1 (Value : Word) return Word
     with SPARK_Mode => On
   is
   begin
      return Rotate_Right (Value, 6) xor Rotate_Right (Value, 11) xor Rotate_Right (Value, 25);
   end Big_Sigma_1;

   function Small_Sigma_0 (Value : Word) return Word
     with SPARK_Mode => On
   is
   begin
      return Rotate_Right (Value, 7) xor Rotate_Right (Value, 18) xor Shift_Right (Value, 3);
   end Small_Sigma_0;

   function Small_Sigma_1 (Value : Word) return Word
     with SPARK_Mode => On
   is
   begin
      return Rotate_Right (Value, 17) xor Rotate_Right (Value, 19) xor Shift_Right (Value, 10);
   end Small_Sigma_1;

   procedure Process_Block (Context_Item : in out SHA256_Context) is
      Work_Items : array (Natural range 0 .. 63) of Word := [others => 0];
      A_Value : Word;
      B_Value : Word;
      C_Value : Word;
      D_Value : Word;
      E_Value : Word;
      F_Value : Word;
      G_Value : Word;
      H_Value : Word;
      Temp_1  : Word;
      Temp_2  : Word;
   begin
      for Index_Value in 0 .. 15 loop
         Work_Items (Index_Value) :=
           Shift_Left (Word (Context_Item.Block_Data (Index_Value * 4)), 24) or
           Shift_Left (Word (Context_Item.Block_Data (Index_Value * 4 + 1)), 16) or
           Shift_Left (Word (Context_Item.Block_Data (Index_Value * 4 + 2)), 8) or
           Word (Context_Item.Block_Data (Index_Value * 4 + 3));
      end loop;

      for Index_Value in 16 .. 63 loop
         Work_Items (Index_Value) := Small_Sigma_1 (Work_Items (Index_Value - 2)) +
           Work_Items (Index_Value - 7) + Small_Sigma_0 (Work_Items (Index_Value - 15)) +
           Work_Items (Index_Value - 16);
      end loop;

      A_Value := Context_Item.State_Data (0);
      B_Value := Context_Item.State_Data (1);
      C_Value := Context_Item.State_Data (2);
      D_Value := Context_Item.State_Data (3);
      E_Value := Context_Item.State_Data (4);
      F_Value := Context_Item.State_Data (5);
      G_Value := Context_Item.State_Data (6);
      H_Value := Context_Item.State_Data (7);

      for Index_Value in 0 .. 63 loop
         Temp_1 := H_Value + Big_Sigma_1 (E_Value) + Ch (E_Value, F_Value, G_Value) +
           K_Values (Index_Value) + Work_Items (Index_Value);
         Temp_2 := Big_Sigma_0 (A_Value) + Maj (A_Value, B_Value, C_Value);
         H_Value := G_Value;
         G_Value := F_Value;
         F_Value := E_Value;
         E_Value := D_Value + Temp_1;
         D_Value := C_Value;
         C_Value := B_Value;
         B_Value := A_Value;
         A_Value := Temp_1 + Temp_2;
      end loop;

      Context_Item.State_Data (0) := Context_Item.State_Data (0) + A_Value;
      Context_Item.State_Data (1) := Context_Item.State_Data (1) + B_Value;
      Context_Item.State_Data (2) := Context_Item.State_Data (2) + C_Value;
      Context_Item.State_Data (3) := Context_Item.State_Data (3) + D_Value;
      Context_Item.State_Data (4) := Context_Item.State_Data (4) + E_Value;
      Context_Item.State_Data (5) := Context_Item.State_Data (5) + F_Value;
      Context_Item.State_Data (6) := Context_Item.State_Data (6) + G_Value;
      Context_Item.State_Data (7) := Context_Item.State_Data (7) + H_Value;
      Context_Item.Block_Data := [others => 0];
      Context_Item.Block_Used := 0;
   end Process_Block;

   procedure Initialize_SHA256 (Context_Item : out SHA256_Context) is
   begin
      Context_Item.State_Data :=
        [16#6A09_E667#, 16#BB67_AE85#, 16#3C6E_F372#, 16#A54F_F53A#,
         16#510E_527F#, 16#9B05_688C#, 16#1F83_D9AB#, 16#5BE0_CD19#];
      Context_Item.Block_Data := [others => 0];
      Context_Item.Block_Used := 0;
      Context_Item.Total_Bytes := 0;
   end Initialize_SHA256;

   procedure Update
     (Context_Item : in out SHA256_Context;
      Data         : Ada.Streams.Stream_Element_Array)
   is
   begin
      for Byte_Value of Data loop
         Context_Item.Block_Data (Context_Item.Block_Used) := Unsigned_8 (Byte_Value);
         Context_Item.Block_Used := Context_Item.Block_Used + 1;
         Context_Item.Total_Bytes := Context_Item.Total_Bytes + 1;
         if Context_Item.Block_Used = 64 then
            Process_Block (Context_Item);
         end if;
      end loop;
   end Update;

   function Finalize
     (Context_Item : in out SHA256_Context)
      return SHA256_Digest
   is
      Length_Bits : constant Unsigned_64 := Context_Item.Total_Bytes * 8;
      Result      : SHA256_Digest := [others => 0];
      Byte_Index  : Natural := 1;
   begin
      Context_Item.Block_Data (Context_Item.Block_Used) := 16#80#;
      Context_Item.Block_Used := Context_Item.Block_Used + 1;

      if Context_Item.Block_Used > 56 then
         while Context_Item.Block_Used < 64 loop
            Context_Item.Block_Data (Context_Item.Block_Used) := 0;
            Context_Item.Block_Used := Context_Item.Block_Used + 1;
         end loop;
         Process_Block (Context_Item);
      end if;

      while Context_Item.Block_Used < 56 loop
         Context_Item.Block_Data (Context_Item.Block_Used) := 0;
         Context_Item.Block_Used := Context_Item.Block_Used + 1;
      end loop;

      for Index_Value in 0 .. 7 loop
         Context_Item.Block_Data (56 + Index_Value) :=
           Unsigned_8 (Shift_Right (Length_Bits, (7 - Index_Value) * 8) and 16#FF#);
      end loop;
      Context_Item.Block_Used := 64;
      Process_Block (Context_Item);

      for Word_Index in 0 .. 7 loop
         Result (SHA256_Digest_Index (Byte_Index)) := Ada.Streams.Stream_Element
           (Shift_Right (Context_Item.State_Data (Word_Index), 24) and 16#FF#);
         Result (SHA256_Digest_Index (Byte_Index + 1)) := Ada.Streams.Stream_Element
           (Shift_Right (Context_Item.State_Data (Word_Index), 16) and 16#FF#);
         Result (SHA256_Digest_Index (Byte_Index + 2)) := Ada.Streams.Stream_Element
           (Shift_Right (Context_Item.State_Data (Word_Index), 8) and 16#FF#);
         Result (SHA256_Digest_Index (Byte_Index + 3)) := Ada.Streams.Stream_Element
           (Context_Item.State_Data (Word_Index) and 16#FF#);
         Byte_Index := Byte_Index + 4;
      end loop;

      return Result;
   end Finalize;

   function SHA256
     (Data : Ada.Streams.Stream_Element_Array)
      return SHA256_Digest
   is
      Context_Item : SHA256_Context;
   begin
      Initialize_SHA256 (Context_Item);
      Update (Context_Item, Data);
      return Finalize (Context_Item);
   end SHA256;

   --  Streaming SHA-1 (FIPS 180-4), block-at-a-time so callers can hash large
   --  inputs without buffering. Mirrors the one-shot SHA1 compression above.
   function Rotate_Left_32 (Value : Word; Amount : Natural) return Word is
     (Shift_Left (Value, Amount) or Shift_Right (Value, 32 - Amount));

   procedure Process_SHA1_Block (Context_Item : in out SHA1_Context) is
      W : array (Natural range 0 .. 79) of Word := [others => 0];
      A, B, C, D, E, F, K, Temp_Value : Word;
   begin
      for Index_Value in 0 .. 15 loop
         W (Index_Value) :=
           Shift_Left (Word (Context_Item.Block_Data (Index_Value * 4)), 24) or
           Shift_Left (Word (Context_Item.Block_Data (Index_Value * 4 + 1)), 16) or
           Shift_Left (Word (Context_Item.Block_Data (Index_Value * 4 + 2)), 8) or
           Word (Context_Item.Block_Data (Index_Value * 4 + 3));
      end loop;

      for Index_Value in 16 .. 79 loop
         W (Index_Value) := Rotate_Left_32
           (W (Index_Value - 3) xor W (Index_Value - 8)
            xor W (Index_Value - 14) xor W (Index_Value - 16), 1);
      end loop;

      A := Context_Item.State_Data (0);
      B := Context_Item.State_Data (1);
      C := Context_Item.State_Data (2);
      D := Context_Item.State_Data (3);
      E := Context_Item.State_Data (4);

      for Round_Index in 0 .. 79 loop
         if Round_Index <= 19 then
            F := (B and C) or ((not B) and D);
            K := 16#5A82_7999#;
         elsif Round_Index <= 39 then
            F := B xor C xor D;
            K := 16#6ED9_EBA1#;
         elsif Round_Index <= 59 then
            F := (B and C) or (B and D) or (C and D);
            K := 16#8F1B_BCDC#;
         else
            F := B xor C xor D;
            K := 16#CA62_C1D6#;
         end if;

         Temp_Value := Rotate_Left_32 (A, 5) + F + E + K + W (Round_Index);
         E := D;
         D := C;
         C := Rotate_Left_32 (B, 30);
         B := A;
         A := Temp_Value;
      end loop;

      Context_Item.State_Data (0) := Context_Item.State_Data (0) + A;
      Context_Item.State_Data (1) := Context_Item.State_Data (1) + B;
      Context_Item.State_Data (2) := Context_Item.State_Data (2) + C;
      Context_Item.State_Data (3) := Context_Item.State_Data (3) + D;
      Context_Item.State_Data (4) := Context_Item.State_Data (4) + E;
      Context_Item.Block_Data := [others => 0];
      Context_Item.Block_Used := 0;
   end Process_SHA1_Block;

   procedure Initialize_SHA1 (Context_Item : out SHA1_Context) is
   begin
      Context_Item.State_Data :=
        [16#6745_2301#, 16#EFCD_AB89#, 16#98BA_DCFE#, 16#1032_5476#,
         16#C3D2_E1F0#];
      Context_Item.Block_Data := [others => 0];
      Context_Item.Block_Used := 0;
      Context_Item.Total_Bytes := 0;
   end Initialize_SHA1;

   procedure Update
     (Context_Item : in out SHA1_Context;
      Data         : Ada.Streams.Stream_Element_Array)
   is
   begin
      for Byte_Value of Data loop
         Context_Item.Block_Data (Context_Item.Block_Used) := Unsigned_8 (Byte_Value);
         Context_Item.Block_Used := Context_Item.Block_Used + 1;
         Context_Item.Total_Bytes := Context_Item.Total_Bytes + 1;
         if Context_Item.Block_Used = 64 then
            Process_SHA1_Block (Context_Item);
         end if;
      end loop;
   end Update;

   function Finalize
     (Context_Item : in out SHA1_Context)
      return SHA1_Digest
   is
      Length_Bits : constant Unsigned_64 := Context_Item.Total_Bytes * 8;
      Result      : SHA1_Digest := [others => 0];
      Byte_Index  : Natural := 1;
   begin
      Context_Item.Block_Data (Context_Item.Block_Used) := 16#80#;
      Context_Item.Block_Used := Context_Item.Block_Used + 1;

      if Context_Item.Block_Used > 56 then
         while Context_Item.Block_Used < 64 loop
            Context_Item.Block_Data (Context_Item.Block_Used) := 0;
            Context_Item.Block_Used := Context_Item.Block_Used + 1;
         end loop;
         Process_SHA1_Block (Context_Item);
      end if;

      while Context_Item.Block_Used < 56 loop
         Context_Item.Block_Data (Context_Item.Block_Used) := 0;
         Context_Item.Block_Used := Context_Item.Block_Used + 1;
      end loop;

      for Index_Value in 0 .. 7 loop
         Context_Item.Block_Data (56 + Index_Value) :=
           Unsigned_8 (Shift_Right (Length_Bits, (7 - Index_Value) * 8) and 16#FF#);
      end loop;
      Context_Item.Block_Used := 64;
      Process_SHA1_Block (Context_Item);

      for Word_Index in 0 .. 4 loop
         Result (SHA1_Digest_Index (Byte_Index)) := Ada.Streams.Stream_Element
           (Shift_Right (Context_Item.State_Data (Word_Index), 24) and 16#FF#);
         Result (SHA1_Digest_Index (Byte_Index + 1)) := Ada.Streams.Stream_Element
           (Shift_Right (Context_Item.State_Data (Word_Index), 16) and 16#FF#);
         Result (SHA1_Digest_Index (Byte_Index + 2)) := Ada.Streams.Stream_Element
           (Shift_Right (Context_Item.State_Data (Word_Index), 8) and 16#FF#);
         Result (SHA1_Digest_Index (Byte_Index + 3)) := Ada.Streams.Stream_Element
           (Context_Item.State_Data (Word_Index) and 16#FF#);
         Byte_Index := Byte_Index + 4;
      end loop;

      return Result;
   end Finalize;

   subtype Word64 is Unsigned_64;

   K512_Values : constant array (Natural range 0 .. 79) of Word64 :=
     [16#428A_2F98_D728_AE22#, 16#7137_4491_23EF_65CD#,
      16#B5C0_FBCF_EC4D_3B2F#, 16#E9B5_DBA5_8189_DBBC#,
      16#3956_C25B_F348_B538#, 16#59F1_11F1_B605_D019#,
      16#923F_82A4_AF19_4F9B#, 16#AB1C_5ED5_DA6D_8118#,
      16#D807_AA98_A303_0242#, 16#1283_5B01_4570_6FBE#,
      16#2431_85BE_4EE4_B28C#, 16#550C_7DC3_D5FF_B4E2#,
      16#72BE_5D74_F27B_896F#, 16#80DE_B1FE_3B16_96B1#,
      16#9BDC_06A7_25C7_1235#, 16#C19B_F174_CF69_2694#,
      16#E49B_69C1_9EF1_4AD2#, 16#EFBE_4786_384F_25E3#,
      16#0FC1_9DC6_8B8C_D5B5#, 16#240C_A1CC_77AC_9C65#,
      16#2DE9_2C6F_592B_0275#, 16#4A74_84AA_6EA6_E483#,
      16#5CB0_A9DC_BD41_FBD4#, 16#76F9_88DA_8311_53B5#,
      16#983E_5152_EE66_DFAB#, 16#A831_C66D_2DB4_3210#,
      16#B003_27C8_98FB_213F#, 16#BF59_7FC7_BEEF_0EE4#,
      16#C6E0_0BF3_3DA8_8FC2#, 16#D5A7_9147_930A_A725#,
      16#06CA_6351_E003_826F#, 16#1429_2967_0A0E_6E70#,
      16#27B7_0A85_46D2_2FFC#, 16#2E1B_2138_5C26_C926#,
      16#4D2C_6DFC_5AC4_2AED#, 16#5338_0D13_9D95_B3DF#,
      16#650A_7354_8BAF_63DE#, 16#766A_0ABB_3C77_B2A8#,
      16#81C2_C92E_47ED_AEE6#, 16#9272_2C85_1482_353B#,
      16#A2BF_E8A1_4CF1_0364#, 16#A81A_664B_BC42_3001#,
      16#C24B_8B70_D0F8_9791#, 16#C76C_51A3_0654_BE30#,
      16#D192_E819_D6EF_5218#, 16#D699_0624_5565_A910#,
      16#F40E_3585_5771_202A#, 16#106A_A070_32BB_D1B8#,
      16#19A4_C116_B8D2_D0C8#, 16#1E37_6C08_5141_AB53#,
      16#2748_774C_DF8E_EB99#, 16#34B0_BCB5_E19B_48A8#,
      16#391C_0CB3_C5C9_5A63#, 16#4ED8_AA4A_E341_8ACB#,
      16#5B9C_CA4F_7763_E373#, 16#682E_6FF3_D6B2_B8A3#,
      16#748F_82EE_5DEF_B2FC#, 16#78A5_636F_4317_2F60#,
      16#84C8_7814_A1F0_AB72#, 16#8CC7_0208_1A64_39EC#,
      16#90BE_FFFA_2363_1E28#, 16#A450_6CEB_DE82_BDE9#,
      16#BEF9_A3F7_B2C6_7915#, 16#C671_78F2_E372_532B#,
      16#CA27_3ECE_EA26_619C#, 16#D186_B8C7_21C0_C207#,
      16#EADA_7DD6_CDE0_EB1E#, 16#F57D_4F7F_EE6E_D178#,
      16#06F0_67AA_7217_6FBA#, 16#0A63_7DC5_A2C8_98A6#,
      16#113F_9804_BEF9_0DAE#, 16#1B71_0B35_131C_471B#,
      16#28DB_77F5_2304_7D84#, 16#32CA_AB7B_40C7_2493#,
      16#3C9E_BE0A_15C9_BEBC#, 16#431D_67C4_9C10_0D4C#,
      16#4CC5_D4BE_CB3E_42B6#, 16#597F_299C_FC65_7E2A#,
      16#5FCB_6FAB_3AD6_FAEC#, 16#6C44_198C_4A47_5817#];

   function Rotate_Right_64 (Value : Word64; Amount : Natural) return Word64
     with SPARK_Mode => On,
          Pre => Amount <= 64
   is
   begin
      return Shift_Right (Value, Amount) or Shift_Left (Value, 64 - Amount);
   end Rotate_Right_64;

   function Ch_64 (X_Value : Word64; Y_Value : Word64; Z_Value : Word64) return Word64
     with SPARK_Mode => On
   is
   begin
      return (X_Value and Y_Value) xor ((not X_Value) and Z_Value);
   end Ch_64;

   function Maj_64 (X_Value : Word64; Y_Value : Word64; Z_Value : Word64) return Word64
     with SPARK_Mode => On
   is
   begin
      return (X_Value and Y_Value) xor (X_Value and Z_Value) xor (Y_Value and Z_Value);
   end Maj_64;

   function Big_Sigma_0_64 (Value : Word64) return Word64
     with SPARK_Mode => On
   is
   begin
      return Rotate_Right_64 (Value, 28) xor Rotate_Right_64 (Value, 34) xor Rotate_Right_64 (Value, 39);
   end Big_Sigma_0_64;

   function Big_Sigma_1_64 (Value : Word64) return Word64
     with SPARK_Mode => On
   is
   begin
      return Rotate_Right_64 (Value, 14) xor Rotate_Right_64 (Value, 18) xor Rotate_Right_64 (Value, 41);
   end Big_Sigma_1_64;

   function Small_Sigma_0_64 (Value : Word64) return Word64
     with SPARK_Mode => On
   is
   begin
      return Rotate_Right_64 (Value, 1) xor Rotate_Right_64 (Value, 8) xor Shift_Right (Value, 7);
   end Small_Sigma_0_64;

   function Small_Sigma_1_64 (Value : Word64) return Word64
     with SPARK_Mode => On
   is
   begin
      return Rotate_Right_64 (Value, 19) xor Rotate_Right_64 (Value, 61) xor Shift_Right (Value, 6);
   end Small_Sigma_1_64;

   procedure Process_SHA512_Block (Context_Item : in out SHA512_Context) is
      Work_Items : array (Natural range 0 .. 79) of Word64 := [others => 0];
      A_Value : Word64;
      B_Value : Word64;
      C_Value : Word64;
      D_Value : Word64;
      E_Value : Word64;
      F_Value : Word64;
      G_Value : Word64;
      H_Value : Word64;
      Temp_1  : Word64;
      Temp_2  : Word64;
   begin
      for Index_Value in 0 .. 15 loop
         Work_Items (Index_Value) :=
           Shift_Left (Word64 (Context_Item.Block_Data (Index_Value * 8)), 56) or
           Shift_Left (Word64 (Context_Item.Block_Data (Index_Value * 8 + 1)), 48) or
           Shift_Left (Word64 (Context_Item.Block_Data (Index_Value * 8 + 2)), 40) or
           Shift_Left (Word64 (Context_Item.Block_Data (Index_Value * 8 + 3)), 32) or
           Shift_Left (Word64 (Context_Item.Block_Data (Index_Value * 8 + 4)), 24) or
           Shift_Left (Word64 (Context_Item.Block_Data (Index_Value * 8 + 5)), 16) or
           Shift_Left (Word64 (Context_Item.Block_Data (Index_Value * 8 + 6)), 8) or
           Word64 (Context_Item.Block_Data (Index_Value * 8 + 7));
      end loop;

      for Index_Value in 16 .. 79 loop
         Work_Items (Index_Value) := Small_Sigma_1_64 (Work_Items (Index_Value - 2)) +
           Work_Items (Index_Value - 7) + Small_Sigma_0_64 (Work_Items (Index_Value - 15)) +
           Work_Items (Index_Value - 16);
      end loop;

      A_Value := Context_Item.State_Data (0);
      B_Value := Context_Item.State_Data (1);
      C_Value := Context_Item.State_Data (2);
      D_Value := Context_Item.State_Data (3);
      E_Value := Context_Item.State_Data (4);
      F_Value := Context_Item.State_Data (5);
      G_Value := Context_Item.State_Data (6);
      H_Value := Context_Item.State_Data (7);

      for Index_Value in 0 .. 79 loop
         Temp_1 := H_Value + Big_Sigma_1_64 (E_Value) + Ch_64 (E_Value, F_Value, G_Value) +
           K512_Values (Index_Value) + Work_Items (Index_Value);
         Temp_2 := Big_Sigma_0_64 (A_Value) + Maj_64 (A_Value, B_Value, C_Value);
         H_Value := G_Value;
         G_Value := F_Value;
         F_Value := E_Value;
         E_Value := D_Value + Temp_1;
         D_Value := C_Value;
         C_Value := B_Value;
         B_Value := A_Value;
         A_Value := Temp_1 + Temp_2;
      end loop;

      Context_Item.State_Data (0) := Context_Item.State_Data (0) + A_Value;
      Context_Item.State_Data (1) := Context_Item.State_Data (1) + B_Value;
      Context_Item.State_Data (2) := Context_Item.State_Data (2) + C_Value;
      Context_Item.State_Data (3) := Context_Item.State_Data (3) + D_Value;
      Context_Item.State_Data (4) := Context_Item.State_Data (4) + E_Value;
      Context_Item.State_Data (5) := Context_Item.State_Data (5) + F_Value;
      Context_Item.State_Data (6) := Context_Item.State_Data (6) + G_Value;
      Context_Item.State_Data (7) := Context_Item.State_Data (7) + H_Value;
      Context_Item.Block_Data := [others => 0];
      Context_Item.Block_Used := 0;
   end Process_SHA512_Block;

   procedure Initialize_SHA384_Internal (Context_Item : out SHA512_Context) is
   begin
      Context_Item.State_Data :=
        [16#CBBB_9D5D_C105_9ED8#, 16#629A_292A_367C_D507#,
         16#9159_015A_3070_DD17#, 16#152F_ECD8_F70E_5939#,
         16#6733_2667_FFC0_0B31#, 16#8EB4_4A87_6858_1511#,
         16#DB0C_2E0D_64F9_8FA7#, 16#47B5_481D_BEFA_4FA4#];
      Context_Item.Block_Data := [others => 0];
      Context_Item.Block_Used := 0;
      Context_Item.Total_Bytes_High := 0;
      Context_Item.Total_Bytes_Low := 0;
   end Initialize_SHA384_Internal;

   procedure Initialize_SHA512 (Context_Item : out SHA512_Context) is
   begin
      Context_Item.State_Data :=
        [16#6A09_E667_F3BC_C908#, 16#BB67_AE85_84CA_A73B#,
         16#3C6E_F372_FE94_F82B#, 16#A54F_F53A_5F1D_36F1#,
         16#510E_527F_ADE6_82D1#, 16#9B05_688C_2B3E_6C1F#,
         16#1F83_D9AB_FB41_BD6B#, 16#5BE0_CD19_137E_2179#];
      Context_Item.Block_Data := [others => 0];
      Context_Item.Block_Used := 0;
      Context_Item.Total_Bytes_High := 0;
      Context_Item.Total_Bytes_Low := 0;
   end Initialize_SHA512;

   procedure Update
     (Context_Item : in out SHA512_Context;
      Data         : Ada.Streams.Stream_Element_Array)
   is
      Old_Low : Word64;
   begin
      for Byte_Value of Data loop
         Context_Item.Block_Data (Context_Item.Block_Used) := Unsigned_8 (Byte_Value);
         Context_Item.Block_Used := Context_Item.Block_Used + 1;
         Old_Low := Context_Item.Total_Bytes_Low;
         Context_Item.Total_Bytes_Low := Context_Item.Total_Bytes_Low + 1;
         if Context_Item.Total_Bytes_Low < Old_Low then
            Context_Item.Total_Bytes_High := Context_Item.Total_Bytes_High + 1;
         end if;
         if Context_Item.Block_Used = 128 then
            Process_SHA512_Block (Context_Item);
         end if;
      end loop;
   end Update;

   function Finalize
     (Context_Item : in out SHA512_Context)
      return SHA512_Digest
   is
      Length_High : constant Word64 := Shift_Left (Context_Item.Total_Bytes_High, 3) or
        Shift_Right (Context_Item.Total_Bytes_Low, 61);
      Length_Low  : constant Word64 := Shift_Left (Context_Item.Total_Bytes_Low, 3);
      Result      : SHA512_Digest := [others => 0];
      Byte_Index  : Natural := 1;
      Current_Word : Word64;
   begin
      Context_Item.Block_Data (Context_Item.Block_Used) := 16#80#;
      Context_Item.Block_Used := Context_Item.Block_Used + 1;

      if Context_Item.Block_Used > 112 then
         while Context_Item.Block_Used < 128 loop
            Context_Item.Block_Data (Context_Item.Block_Used) := 0;
            Context_Item.Block_Used := Context_Item.Block_Used + 1;
         end loop;
         Process_SHA512_Block (Context_Item);
      end if;

      while Context_Item.Block_Used < 112 loop
         Context_Item.Block_Data (Context_Item.Block_Used) := 0;
         Context_Item.Block_Used := Context_Item.Block_Used + 1;
      end loop;

      for Index_Value in 0 .. 7 loop
         Context_Item.Block_Data (112 + Index_Value) :=
           Unsigned_8 (Shift_Right (Length_High, (7 - Index_Value) * 8) and 16#FF#);
         Context_Item.Block_Data (120 + Index_Value) :=
           Unsigned_8 (Shift_Right (Length_Low, (7 - Index_Value) * 8) and 16#FF#);
      end loop;
      Context_Item.Block_Used := 128;
      Process_SHA512_Block (Context_Item);

      for Word_Index in 0 .. 7 loop
         Current_Word := Context_Item.State_Data (Word_Index);
         for Offset_Value in 0 .. 7 loop
            Result (SHA512_Digest_Index (Byte_Index + Offset_Value)) :=
              Ada.Streams.Stream_Element
                (Shift_Right (Current_Word, (7 - Offset_Value) * 8) and 16#FF#);
         end loop;
         Byte_Index := Byte_Index + 8;
      end loop;

      return Result;
   end Finalize;

   function SHA384
     (Data : Ada.Streams.Stream_Element_Array)
      return SHA384_Digest
   is
      Context_Item : SHA512_Context;
      Full_Digest  : SHA512_Digest;
      Result_Item  : SHA384_Digest := [others => 0];
   begin
      Initialize_SHA384_Internal (Context_Item);
      Update (Context_Item, Data);
      Full_Digest := Finalize (Context_Item);
      for Index_Value in Result_Item'Range loop
         Result_Item (Index_Value) := Full_Digest (Index_Value);
      end loop;
      return Result_Item;
   end SHA384;

   function SHA512
     (Data : Ada.Streams.Stream_Element_Array)
      return SHA512_Digest
   is
      Context_Item : SHA512_Context;
   begin
      Initialize_SHA512 (Context_Item);
      Update (Context_Item, Data);
      return Finalize (Context_Item);
   end SHA512;

   XXH_PRIME32_1 : constant Word64 := 16#9E37_79B1#;
   XXH_PRIME32_2 : constant Word64 := 16#85EB_CA77#;
   XXH_PRIME32_3 : constant Word64 := 16#C2B2_AE3D#;

   XXH_PRIME64_1 : constant Word64 := 16#9E37_79B1_85EB_CA87#;
   XXH_PRIME64_2 : constant Word64 := 16#C2B2_AE3D_27D4_EB4F#;
   XXH_PRIME64_3 : constant Word64 := 16#1656_67B1_9E37_79F9#;
   XXH_PRIME64_4 : constant Word64 := 16#85EB_CA77_C2B2_AE63#;
   XXH_PRIME64_5 : constant Word64 := 16#27D4_EB2F_1656_67C5#;
   XXH_PRIME_MX1 : constant Word64 := 16#1656_6791_9E37_79F9#;
   XXH_PRIME_MX2 : constant Word64 := 16#9FB2_1C65_1E98_DF25#;

   type XXH_Secret is array (Natural range 0 .. 191) of Unsigned_8;
   Default_XXH3_Secret : constant XXH_Secret :=
     [16#B8#, 16#FE#, 16#6C#, 16#39#, 16#23#, 16#A4#, 16#4B#, 16#BE#,
      16#7C#, 16#01#, 16#81#, 16#2C#, 16#F7#, 16#21#, 16#AD#, 16#1C#,
      16#DE#, 16#D4#, 16#6D#, 16#E9#, 16#83#, 16#90#, 16#97#, 16#DB#,
      16#72#, 16#40#, 16#A4#, 16#A4#, 16#B7#, 16#B3#, 16#67#, 16#1F#,
      16#CB#, 16#79#, 16#E6#, 16#4E#, 16#CC#, 16#C0#, 16#E5#, 16#78#,
      16#82#, 16#5A#, 16#D0#, 16#7D#, 16#CC#, 16#FF#, 16#72#, 16#21#,
      16#B8#, 16#08#, 16#46#, 16#74#, 16#F7#, 16#43#, 16#24#, 16#8E#,
      16#E0#, 16#35#, 16#90#, 16#E6#, 16#81#, 16#3A#, 16#26#, 16#4C#,
      16#3C#, 16#28#, 16#52#, 16#BB#, 16#91#, 16#C3#, 16#00#, 16#CB#,
      16#88#, 16#D0#, 16#65#, 16#8B#, 16#1B#, 16#53#, 16#2E#, 16#A3#,
      16#71#, 16#64#, 16#48#, 16#97#, 16#A2#, 16#0D#, 16#F9#, 16#4E#,
      16#38#, 16#19#, 16#EF#, 16#46#, 16#A9#, 16#DE#, 16#AC#, 16#D8#,
      16#A8#, 16#FA#, 16#76#, 16#3F#, 16#E3#, 16#9C#, 16#34#, 16#3F#,
      16#F9#, 16#DC#, 16#BB#, 16#C7#, 16#C7#, 16#0B#, 16#4F#, 16#1D#,
      16#8A#, 16#51#, 16#E0#, 16#4B#, 16#CD#, 16#B4#, 16#59#, 16#31#,
      16#C8#, 16#9F#, 16#7E#, 16#C9#, 16#D9#, 16#78#, 16#73#, 16#64#,
      16#EA#, 16#C5#, 16#AC#, 16#83#, 16#34#, 16#D3#, 16#EB#, 16#C3#,
      16#C5#, 16#81#, 16#A0#, 16#FF#, 16#FA#, 16#13#, 16#63#, 16#EB#,
      16#17#, 16#0D#, 16#DD#, 16#51#, 16#B7#, 16#F0#, 16#DA#, 16#49#,
      16#D3#, 16#16#, 16#55#, 16#26#, 16#29#, 16#D4#, 16#68#, 16#9E#,
      16#2B#, 16#16#, 16#BE#, 16#58#, 16#7D#, 16#47#, 16#A1#, 16#FC#,
      16#8F#, 16#F8#, 16#B8#, 16#D1#, 16#7A#, 16#D0#, 16#31#, 16#CE#,
      16#45#, 16#CB#, 16#3A#, 16#8F#, 16#95#, 16#16#, 16#04#, 16#28#,
      16#AF#, 16#D7#, 16#FB#, 16#CA#, 16#BB#, 16#4B#, 16#40#, 16#7E#];

   type XXH128_Value is record
      Low64  : Word64;
      High64 : Word64;
   end record;

   function XXH_Data_Byte
     (Data   : Ada.Streams.Stream_Element_Array;
      Offset : Natural)
      return Word64
     with SPARK_Mode => On,
       Pre => Data'First <= Data'Last
         and then Data'First <= Ada.Streams.Stream_Element_Offset'Last
           - Ada.Streams.Stream_Element_Offset (Offset)
         and then Data'First + Ada.Streams.Stream_Element_Offset (Offset) <= Data'Last,
       Post => XXH_Data_Byte'Result <= 255
   is
   begin
      return Word64
        (Data (Data'First + Ada.Streams.Stream_Element_Offset (Offset)));
   end XXH_Data_Byte;

   function XXH_Read32
     (Data   : Ada.Streams.Stream_Element_Array;
      Offset : Natural)
      return Word
     with SPARK_Mode => On,
       Pre => Offset <= Natural'Last - 3
         and then Data'First <= Data'Last
         and then Data'First <= Ada.Streams.Stream_Element_Offset'Last
           - Ada.Streams.Stream_Element_Offset (Offset + 3)
         and then Data'First + Ada.Streams.Stream_Element_Offset (Offset + 3) <= Data'Last
   is
   begin
      return Word (XXH_Data_Byte (Data, Offset))
        or Shift_Left (Word (XXH_Data_Byte (Data, Offset + 1)), 8)
        or Shift_Left (Word (XXH_Data_Byte (Data, Offset + 2)), 16)
        or Shift_Left (Word (XXH_Data_Byte (Data, Offset + 3)), 24);
   end XXH_Read32;

   function XXH_Read64
     (Data   : Ada.Streams.Stream_Element_Array;
      Offset : Natural)
      return Word64
     with SPARK_Mode => On,
       Pre => Offset <= Natural'Last - 7
         and then Data'First <= Data'Last
         and then Data'First <= Ada.Streams.Stream_Element_Offset'Last
           - Ada.Streams.Stream_Element_Offset (Offset + 7)
         and then Data'First + Ada.Streams.Stream_Element_Offset (Offset + 7) <= Data'Last
   is
      Result : Word64 := 0;
   begin
      for Index_Value in 0 .. 7 loop
         Result := Result
           or Shift_Left (XXH_Data_Byte (Data, Offset + Index_Value),
                          Index_Value * 8);
      end loop;
      return Result;
   end XXH_Read64;

   function XXH_Read_Secret32 (Offset : Natural) return Word
     with SPARK_Mode => On,
       Pre => Offset <= Default_XXH3_Secret'Last - 3
   is
   begin
      return Word (Default_XXH3_Secret (Offset))
        or Shift_Left (Word (Default_XXH3_Secret (Offset + 1)), 8)
        or Shift_Left (Word (Default_XXH3_Secret (Offset + 2)), 16)
        or Shift_Left (Word (Default_XXH3_Secret (Offset + 3)), 24);
   end XXH_Read_Secret32;

   function XXH_Read_Secret64 (Offset : Natural) return Word64
     with SPARK_Mode => On,
       Pre => Offset <= Default_XXH3_Secret'Last - 7
   is
      Result : Word64 := 0;
   begin
      for Index_Value in 0 .. 7 loop
         Result := Result
           or Shift_Left (Word64 (Default_XXH3_Secret (Offset + Index_Value)),
                          Index_Value * 8);
      end loop;
      return Result;
   end XXH_Read_Secret64;

   function XXH_Swap32 (Value : Word) return Word
     with SPARK_Mode => On
   is
   begin
      return Shift_Left (Value and 16#0000_00FF#, 24)
        or Shift_Left (Value and 16#0000_FF00#, 8)
        or Shift_Right (Value and 16#00FF_0000#, 8)
        or Shift_Right (Value and 16#FF00_0000#, 24);
   end XXH_Swap32;

   function XXH_Swap64 (Value : Word64) return Word64
     with SPARK_Mode => On
   is
   begin
      return Shift_Left (Value and 16#0000_0000_0000_00FF#, 56)
        or Shift_Left (Value and 16#0000_0000_0000_FF00#, 40)
        or Shift_Left (Value and 16#0000_0000_00FF_0000#, 24)
        or Shift_Left (Value and 16#0000_0000_FF00_0000#, 8)
        or Shift_Right (Value and 16#0000_00FF_0000_0000#, 8)
        or Shift_Right (Value and 16#0000_FF00_0000_0000#, 24)
        or Shift_Right (Value and 16#00FF_0000_0000_0000#, 40)
        or Shift_Right (Value and 16#FF00_0000_0000_0000#, 56);
   end XXH_Swap64;

   function XXH_Rotl64 (Value : Word64; Amount : Natural) return Word64
     with SPARK_Mode => On,
       Pre => Amount <= 64
   is
   begin
      return Shift_Left (Value, Amount) or Shift_Right (Value, 64 - Amount);
   end XXH_Rotl64;

   function XXH_Rotl32 (Value : Word; Amount : Natural) return Word
     with SPARK_Mode => On,
       Pre => Amount <= 32
   is
   begin
      return Shift_Left (Value, Amount) or Shift_Right (Value, 32 - Amount);
   end XXH_Rotl32;

   function XXH_Avalanche64 (Hash : Word64) return Word64 is
      Result : Word64 := Hash;
   begin
      Result := Result xor Shift_Right (Result, 33);
      Result := Result * XXH_PRIME64_2;
      Result := Result xor Shift_Right (Result, 29);
      Result := Result * XXH_PRIME64_3;
      Result := Result xor Shift_Right (Result, 32);
      return Result;
   end XXH_Avalanche64;

   function XXH3_Avalanche (Hash : Word64) return Word64 is
      Result : Word64 := Hash;
   begin
      Result := Result xor Shift_Right (Result, 37);
      Result := Result * XXH_PRIME_MX1;
      Result := Result xor Shift_Right (Result, 32);
      return Result;
   end XXH3_Avalanche;

   function XXH3_RRMXMX (Hash : Word64; Length : Word64) return Word64 is
      Result : Word64 := Hash;
   begin
      Result := Result xor XXH_Rotl64 (Result, 49) xor XXH_Rotl64 (Result, 24);
      Result := Result * XXH_PRIME_MX2;
      Result := Result xor (Shift_Right (Result, 35) + Length);
      Result := Result * XXH_PRIME_MX2;
      return Result xor Shift_Right (Result, 28);
   end XXH3_RRMXMX;

   function XXH_Mult64_To_128 (LHS : Word64; RHS : Word64) return XXH128_Value is
      Mask32 : constant Word64 := 16#FFFF_FFFF#;
      Lo_Lo  : constant Word64 := (LHS and Mask32) * (RHS and Mask32);
      Hi_Lo  : constant Word64 := Shift_Right (LHS, 32) * (RHS and Mask32);
      Lo_Hi  : constant Word64 := (LHS and Mask32) * Shift_Right (RHS, 32);
      Hi_Hi  : constant Word64 := Shift_Right (LHS, 32) * Shift_Right (RHS, 32);
      Cross  : constant Word64 := Shift_Right (Lo_Lo, 32) + (Hi_Lo and Mask32) + Lo_Hi;
      Upper  : constant Word64 := Shift_Right (Hi_Lo, 32) + Shift_Right (Cross, 32) + Hi_Hi;
      Lower  : constant Word64 := Shift_Left (Cross and Mask32, 32) or (Lo_Lo and Mask32);
   begin
      return (Low64 => Lower, High64 => Upper);
   end XXH_Mult64_To_128;

   function XXH3_Mul128_Fold64 (LHS : Word64; RHS : Word64) return Word64 is
      Product : constant XXH128_Value := XXH_Mult64_To_128 (LHS, RHS);
   begin
      return Product.Low64 xor Product.High64;
   end XXH3_Mul128_Fold64;

   function XXH3_Mix16B
     (Data   : Ada.Streams.Stream_Element_Array;
      Offset : Natural;
      Secret : Natural;
      Seed   : Word64)
      return Word64
   is
      Input_Lo : constant Word64 := XXH_Read64 (Data, Offset);
      Input_Hi : constant Word64 := XXH_Read64 (Data, Offset + 8);
   begin
      return XXH3_Mul128_Fold64
        (Input_Lo xor (XXH_Read_Secret64 (Secret) + Seed),
         Input_Hi xor (XXH_Read_Secret64 (Secret + 8) - Seed));
   end XXH3_Mix16B;

   function XXH3_0_To_16_64
     (Data : Ada.Streams.Stream_Element_Array;
      Len  : Natural)
      return Word64
   is
   begin
      if Len > 8 then
         declare
            Bitflip1 : constant Word64 :=
              XXH_Read_Secret64 (24) xor XXH_Read_Secret64 (32);
            Bitflip2 : constant Word64 :=
              XXH_Read_Secret64 (40) xor XXH_Read_Secret64 (48);
            Input_Lo : constant Word64 := XXH_Read64 (Data, 0) xor Bitflip1;
            Input_Hi : constant Word64 := XXH_Read64 (Data, Len - 8) xor Bitflip2;
            Acc      : constant Word64 :=
              Word64 (Len) + XXH_Swap64 (Input_Lo) + Input_Hi
              + XXH3_Mul128_Fold64 (Input_Lo, Input_Hi);
         begin
            return XXH3_Avalanche (Acc);
         end;
      elsif Len >= 4 then
         declare
            Input1  : constant Word := XXH_Read32 (Data, 0);
            Input2  : constant Word := XXH_Read32 (Data, Len - 4);
            Input64 : constant Word64 := Word64 (Input2) + Shift_Left (Word64 (Input1), 32);
            Keyed   : constant Word64 :=
              Input64 xor (XXH_Read_Secret64 (8) xor XXH_Read_Secret64 (16));
         begin
            return XXH3_RRMXMX (Keyed, Word64 (Len));
         end;
      elsif Len > 0 then
         declare
            C1       : constant Word := Word (XXH_Data_Byte (Data, 0));
            C2       : constant Word := Word (XXH_Data_Byte (Data, Len / 2));
            C3       : constant Word := Word (XXH_Data_Byte (Data, Len - 1));
            Combined : constant Word :=
              Shift_Left (C1, 16) or Shift_Left (C2, 24) or C3
              or Shift_Left (Word (Len), 8);
            Bitflip  : constant Word64 :=
              Word64 (XXH_Read_Secret32 (0) xor XXH_Read_Secret32 (4));
         begin
            return XXH_Avalanche64 (Word64 (Combined) xor Bitflip);
         end;
      else
         return XXH_Avalanche64
           (XXH_Read_Secret64 (56) xor XXH_Read_Secret64 (64));
      end if;
   end XXH3_0_To_16_64;

   function XXH3_17_To_128_64
     (Data : Ada.Streams.Stream_Element_Array;
      Len  : Natural)
      return Word64
   is
      Acc : Word64 := Word64 (Len) * XXH_PRIME64_1;
   begin
      if Len > 32 then
         if Len > 64 then
            if Len > 96 then
               Acc := Acc + XXH3_Mix16B (Data, 48, 96, 0);
               Acc := Acc + XXH3_Mix16B (Data, Len - 64, 112, 0);
            end if;
            Acc := Acc + XXH3_Mix16B (Data, 32, 64, 0);
            Acc := Acc + XXH3_Mix16B (Data, Len - 48, 80, 0);
         end if;
         Acc := Acc + XXH3_Mix16B (Data, 16, 32, 0);
         Acc := Acc + XXH3_Mix16B (Data, Len - 32, 48, 0);
      end if;
      Acc := Acc + XXH3_Mix16B (Data, 0, 0, 0);
      Acc := Acc + XXH3_Mix16B (Data, Len - 16, 16, 0);
      return XXH3_Avalanche (Acc);
   end XXH3_17_To_128_64;

   function XXH3_129_To_240_64
     (Data : Ada.Streams.Stream_Element_Array;
      Len  : Natural)
      return Word64
   is
      Acc       : Word64 := Word64 (Len) * XXH_PRIME64_1;
      Acc_End   : Word64;
      Nb_Rounds : constant Natural := Len / 16;
   begin
      for Index_Value in 0 .. 7 loop
         Acc := Acc + XXH3_Mix16B (Data, 16 * Index_Value, 16 * Index_Value, 0);
      end loop;
      Acc_End := XXH3_Mix16B (Data, Len - 16, 119, 0);
      Acc := XXH3_Avalanche (Acc);
      for Index_Value in 8 .. Nb_Rounds - 1 loop
         Acc_End := Acc_End
           + XXH3_Mix16B (Data, 16 * Index_Value, 16 * (Index_Value - 8) + 3, 0);
      end loop;
      return XXH3_Avalanche (Acc + Acc_End);
   end XXH3_129_To_240_64;

   type XXH_Accumulators is array (Natural range 0 .. 7) of Word64;

   procedure XXH3_Accumulate_512
     (Acc    : in out XXH_Accumulators;
      Data   : Ada.Streams.Stream_Element_Array;
      Offset : Natural;
      Secret : Natural)
   is
   begin
      for Lane in 0 .. 7 loop
         declare
            Data_Val : constant Word64 := XXH_Read64 (Data, Offset + Lane * 8);
            Data_Key : constant Word64 := Data_Val xor XXH_Read_Secret64 (Secret + Lane * 8);
            Swap_Lane : constant Natural :=
              (if Lane mod 2 = 0 then Lane + 1 else Lane - 1);
         begin
            Acc (Swap_Lane) := Acc (Swap_Lane) + Data_Val;
            Acc (Lane) := Acc (Lane)
              + ((Data_Key and 16#FFFF_FFFF#) * Shift_Right (Data_Key, 32));
         end;
      end loop;
   end XXH3_Accumulate_512;

   procedure XXH3_Scramble_Acc
     (Acc    : in out XXH_Accumulators;
      Secret : Natural)
   is
   begin
      for Lane in 0 .. 7 loop
         Acc (Lane) := Acc (Lane) xor Shift_Right (Acc (Lane), 47);
         Acc (Lane) := Acc (Lane) xor XXH_Read_Secret64 (Secret + Lane * 8);
         Acc (Lane) := Acc (Lane) * XXH_PRIME32_1;
      end loop;
   end XXH3_Scramble_Acc;

   procedure XXH3_Long_Loop
     (Acc  : in out XXH_Accumulators;
      Data : Ada.Streams.Stream_Element_Array;
      Len  : Natural)
   is
      Nb_Stripes_Per_Block : constant Natural := 16;
      Block_Length         : constant Natural := 64 * Nb_Stripes_Per_Block;
      Nb_Blocks            : constant Natural := (Len - 1) / Block_Length;
      Last_Block_Start     : constant Natural := Nb_Blocks * Block_Length;
      Nb_Stripes           : constant Natural :=
        ((Len - 1) - Last_Block_Start) / 64;
   begin
      for Block_Index in 0 .. Nb_Blocks - 1 loop
         for Stripe_Index in 0 .. Nb_Stripes_Per_Block - 1 loop
            XXH3_Accumulate_512
              (Acc, Data, Block_Index * Block_Length + Stripe_Index * 64,
               Stripe_Index * 8);
         end loop;
         XXH3_Scramble_Acc (Acc, 128);
      end loop;

      for Stripe_Index in 0 .. Nb_Stripes - 1 loop
         XXH3_Accumulate_512
           (Acc, Data, Last_Block_Start + Stripe_Index * 64, Stripe_Index * 8);
      end loop;
      XXH3_Accumulate_512 (Acc, Data, Len - 64, 121);
   end XXH3_Long_Loop;

   function XXH3_Mix2_Accs
     (Acc    : XXH_Accumulators;
      Lane   : Natural;
      Secret : Natural)
      return Word64
   is
   begin
      return XXH3_Mul128_Fold64
        (Acc (Lane) xor XXH_Read_Secret64 (Secret),
         Acc (Lane + 1) xor XXH_Read_Secret64 (Secret + 8));
   end XXH3_Mix2_Accs;

   function XXH3_Merge_Accs
     (Acc    : XXH_Accumulators;
      Secret : Natural;
      Start  : Word64)
      return Word64
   is
      Result : Word64 := Start;
   begin
      for Index_Value in 0 .. 3 loop
         Result := Result + XXH3_Mix2_Accs (Acc, 2 * Index_Value, Secret + 16 * Index_Value);
      end loop;
      return XXH3_Avalanche (Result);
   end XXH3_Merge_Accs;

   function XXH3_Long_64
     (Data : Ada.Streams.Stream_Element_Array;
      Len  : Natural)
      return Word64
   is
      Acc : XXH_Accumulators :=
        [XXH_PRIME32_3, XXH_PRIME64_1, XXH_PRIME64_2, XXH_PRIME64_3,
         XXH_PRIME64_4, XXH_PRIME32_2, XXH_PRIME64_5, XXH_PRIME32_1];
   begin
      XXH3_Long_Loop (Acc, Data, Len);
      return XXH3_Merge_Accs (Acc, 11, Word64 (Len) * XXH_PRIME64_1);
   end XXH3_Long_64;

   function XXH3_64
     (Data : Ada.Streams.Stream_Element_Array)
      return XXH3_64_Digest
   is
      Len  : constant Natural := Natural (Data'Length);
      Hash : Word64;
   begin
      if Len <= 16 then
         Hash := XXH3_0_To_16_64 (Data, Len);
      elsif Len <= 128 then
         Hash := XXH3_17_To_128_64 (Data, Len);
      elsif Len <= 240 then
         Hash := XXH3_129_To_240_64 (Data, Len);
      else
         Hash := XXH3_Long_64 (Data, Len);
      end if;

      return Result : XXH3_64_Digest := [others => 0] do
         for Index_Value in 0 .. 7 loop
            Result (Index_Value + 1) :=
              Ada.Streams.Stream_Element
                (Shift_Right (Hash, (7 - Index_Value) * 8) and 16#FF#);
         end loop;
      end return;
   exception
      when others =>
         return [others => 0];
   end XXH3_64;

   function XXH128_Mix32B
     (Acc     : XXH128_Value;
      Data    : Ada.Streams.Stream_Element_Array;
      Input_1 : Natural;
      Input_2 : Natural;
      Secret  : Natural;
      Seed    : Word64)
      return XXH128_Value
   is
      Result : XXH128_Value := Acc;
   begin
      Result.Low64 := Result.Low64 + XXH3_Mix16B (Data, Input_1, Secret, Seed);
      Result.Low64 := Result.Low64 xor (XXH_Read64 (Data, Input_2) + XXH_Read64 (Data, Input_2 + 8));
      Result.High64 := Result.High64 + XXH3_Mix16B (Data, Input_2, Secret + 16, Seed);
      Result.High64 := Result.High64 xor (XXH_Read64 (Data, Input_1) + XXH_Read64 (Data, Input_1 + 8));
      return Result;
   end XXH128_Mix32B;

   function XXH3_0_To_16_128
     (Data : Ada.Streams.Stream_Element_Array;
      Len  : Natural)
      return XXH128_Value
   is
   begin
      if Len > 8 then
         declare
            Bitflip_L : constant Word64 := (XXH_Read_Secret64 (32) xor XXH_Read_Secret64 (40));
            Bitflip_H : constant Word64 := (XXH_Read_Secret64 (48) xor XXH_Read_Secret64 (56));
            Input_Lo  : constant Word64 := XXH_Read64 (Data, 0);
            Input_Hi  : constant Word64 := XXH_Read64 (Data, Len - 8);
            M128      : XXH128_Value :=
              XXH_Mult64_To_128 (Input_Lo xor Input_Hi xor Bitflip_L, XXH_PRIME64_1);
            H128      : XXH128_Value;
         begin
            M128.Low64 := M128.Low64 + Shift_Left (Word64 (Len - 1), 54);
            M128.High64 := M128.High64 + (Input_Hi xor Bitflip_H)
              + ((Input_Hi xor Bitflip_H) and 16#FFFF_FFFF#) * (XXH_PRIME32_2 - 1);
            M128.Low64 := M128.Low64 xor XXH_Swap64 (M128.High64);
            H128 := XXH_Mult64_To_128 (M128.Low64, XXH_PRIME64_2);
            H128.High64 := H128.High64 + M128.High64 * XXH_PRIME64_2;
            H128.Low64 := XXH3_Avalanche (H128.Low64);
            H128.High64 := XXH3_Avalanche (H128.High64);
            return H128;
         end;
      elsif Len >= 4 then
         declare
            Input_Lo : constant Word := XXH_Read32 (Data, 0);
            Input_Hi : constant Word := XXH_Read32 (Data, Len - 4);
            Input64  : constant Word64 := Word64 (Input_Lo) + Shift_Left (Word64 (Input_Hi), 32);
            Bitflip  : constant Word64 := (XXH_Read_Secret64 (16) xor XXH_Read_Secret64 (24));
            M128     : XXH128_Value :=
              XXH_Mult64_To_128 (Input64 xor Bitflip,
                                  XXH_PRIME64_1 + Shift_Left (Word64 (Len), 2));
         begin
            M128.High64 := M128.High64 + Shift_Left (M128.Low64, 1);
            M128.Low64 := M128.Low64 xor Shift_Right (M128.High64, 3);
            M128.Low64 := M128.Low64 xor Shift_Right (M128.Low64, 35);
            M128.Low64 := M128.Low64 * XXH_PRIME_MX2;
            M128.Low64 := M128.Low64 xor Shift_Right (M128.Low64, 28);
            M128.High64 := XXH3_Avalanche (M128.High64);
            return M128;
         end;
      elsif Len > 0 then
         declare
            C1         : constant Word := Word (XXH_Data_Byte (Data, 0));
            C2         : constant Word := Word (XXH_Data_Byte (Data, Len / 2));
            C3         : constant Word := Word (XXH_Data_Byte (Data, Len - 1));
            Combined_L : constant Word :=
              Shift_Left (C1, 16) or Shift_Left (C2, 24) or C3
              or Shift_Left (Word (Len), 8);
            Combined_H : constant Word := XXH_Rotl32 (XXH_Swap32 (Combined_L), 13);
            Bitflip_L  : constant Word64 :=
              Word64 (XXH_Read_Secret32 (0) xor XXH_Read_Secret32 (4));
            Bitflip_H  : constant Word64 :=
              Word64 (XXH_Read_Secret32 (8) xor XXH_Read_Secret32 (12));
         begin
            return
              (Low64  => XXH_Avalanche64 (Word64 (Combined_L) xor Bitflip_L),
               High64 => XXH_Avalanche64 (Word64 (Combined_H) xor Bitflip_H));
         end;
      else
         return
           (Low64  => XXH_Avalanche64 (XXH_Read_Secret64 (64) xor XXH_Read_Secret64 (72)),
            High64 => XXH_Avalanche64 (XXH_Read_Secret64 (80) xor XXH_Read_Secret64 (88)));
      end if;
   end XXH3_0_To_16_128;

   function XXH3_17_To_128_128
     (Data : Ada.Streams.Stream_Element_Array;
      Len  : Natural)
      return XXH128_Value
   is
      Acc : XXH128_Value := (Low64 => Word64 (Len) * XXH_PRIME64_1, High64 => 0);
   begin
      if Len > 32 then
         if Len > 64 then
            if Len > 96 then
               Acc := XXH128_Mix32B (Acc, Data, 48, Len - 64, 96, 0);
            end if;
            Acc := XXH128_Mix32B (Acc, Data, 32, Len - 48, 64, 0);
         end if;
         Acc := XXH128_Mix32B (Acc, Data, 16, Len - 32, 32, 0);
      end if;
      Acc := XXH128_Mix32B (Acc, Data, 0, Len - 16, 0, 0);
      return
        (Low64  => XXH3_Avalanche (Acc.Low64 + Acc.High64),
         High64 => 0 - XXH3_Avalanche
           (Acc.Low64 * XXH_PRIME64_1 + Acc.High64 * XXH_PRIME64_4
            + Word64 (Len) * XXH_PRIME64_2));
   end XXH3_17_To_128_128;

   function XXH3_129_To_240_128
     (Data : Ada.Streams.Stream_Element_Array;
      Len  : Natural)
      return XXH128_Value
   is
      Acc : XXH128_Value := (Low64 => Word64 (Len) * XXH_PRIME64_1, High64 => 0);
      I   : Natural := 32;
   begin
      while I < 160 loop
         Acc := XXH128_Mix32B (Acc, Data, I - 32, I - 16, I - 32, 0);
         I := I + 32;
      end loop;
      Acc.Low64 := XXH3_Avalanche (Acc.Low64);
      Acc.High64 := XXH3_Avalanche (Acc.High64);
      I := 160;
      while I <= Len loop
         Acc := XXH128_Mix32B (Acc, Data, I - 32, I - 16, 3 + I - 160, 0);
         I := I + 32;
      end loop;
      Acc := XXH128_Mix32B (Acc, Data, Len - 16, Len - 32, 103, 0);
      return
        (Low64  => XXH3_Avalanche (Acc.Low64 + Acc.High64),
         High64 => 0 - XXH3_Avalanche
           (Acc.Low64 * XXH_PRIME64_1 + Acc.High64 * XXH_PRIME64_4
            + Word64 (Len) * XXH_PRIME64_2));
   end XXH3_129_To_240_128;

   function XXH3_Long_128
     (Data : Ada.Streams.Stream_Element_Array;
      Len  : Natural)
      return XXH128_Value
   is
      Acc : XXH_Accumulators :=
        [XXH_PRIME32_3, XXH_PRIME64_1, XXH_PRIME64_2, XXH_PRIME64_3,
         XXH_PRIME64_4, XXH_PRIME32_2, XXH_PRIME64_5, XXH_PRIME32_1];
   begin
      XXH3_Long_Loop (Acc, Data, Len);
      return
        (Low64  => XXH3_Merge_Accs (Acc, 11, Word64 (Len) * XXH_PRIME64_1),
         High64 => XXH3_Merge_Accs (Acc, 117, not (Word64 (Len) * XXH_PRIME64_2)));
   end XXH3_Long_128;

   function XXH3_128
     (Data : Ada.Streams.Stream_Element_Array)
      return XXH3_128_Digest
   is
      Len  : constant Natural := Natural (Data'Length);
      Hash : XXH128_Value;
   begin
      if Len <= 16 then
         Hash := XXH3_0_To_16_128 (Data, Len);
      elsif Len <= 128 then
         Hash := XXH3_17_To_128_128 (Data, Len);
      elsif Len <= 240 then
         Hash := XXH3_129_To_240_128 (Data, Len);
      else
         Hash := XXH3_Long_128 (Data, Len);
      end if;

      return Result : XXH3_128_Digest := [others => 0] do
         for Index_Value in 0 .. 7 loop
            Result (Index_Value + 1) :=
              Ada.Streams.Stream_Element
                (Shift_Right (Hash.High64, (7 - Index_Value) * 8) and 16#FF#);
            Result (Index_Value + 9) :=
              Ada.Streams.Stream_Element
                (Shift_Right (Hash.Low64, (7 - Index_Value) * 8) and 16#FF#);
         end loop;
      end return;
   exception
      when others =>
         return [others => 0];
   end XXH3_128;

end CryptoLib.Hashes;
