with CryptoLib.Constant_Time;

package body CryptoLib.Ciphers is
   use Ada.Streams;
   use Interfaces;
   use type CryptoLib.Errors.Status;

   subtype Byte is Unsigned_8;
   subtype Word is Unsigned_32;

   Rcon : constant array (Natural range 1 .. 10) of Word :=
     [16#01000000#,
      16#02000000#,
      16#04000000#,
      16#08000000#,
      16#10000000#,
      16#20000000#,
      16#40000000#,
      16#80000000#,
      16#1B000000#,
      16#36000000#];

   subtype Word64 is Unsigned_64;

   type DES_Permutation is array (Positive range <>) of Natural;

   DES_IP : constant DES_Permutation (1 .. 64) :=
     [58,
      50,
      42,
      34,
      26,
      18,
      10,
      2,
      60,
      52,
      44,
      36,
      28,
      20,
      12,
      4,
      62,
      54,
      46,
      38,
      30,
      22,
      14,
      6,
      64,
      56,
      48,
      40,
      32,
      24,
      16,
      8,
      57,
      49,
      41,
      33,
      25,
      17,
      9,
      1,
      59,
      51,
      43,
      35,
      27,
      19,
      11,
      3,
      61,
      53,
      45,
      37,
      29,
      21,
      13,
      5,
      63,
      55,
      47,
      39,
      31,
      23,
      15,
      7];

   DES_FP : constant DES_Permutation (1 .. 64) :=
     [40,
      8,
      48,
      16,
      56,
      24,
      64,
      32,
      39,
      7,
      47,
      15,
      55,
      23,
      63,
      31,
      38,
      6,
      46,
      14,
      54,
      22,
      62,
      30,
      37,
      5,
      45,
      13,
      53,
      21,
      61,
      29,
      36,
      4,
      44,
      12,
      52,
      20,
      60,
      28,
      35,
      3,
      43,
      11,
      51,
      19,
      59,
      27,
      34,
      2,
      42,
      10,
      50,
      18,
      58,
      26,
      33,
      1,
      41,
      9,
      49,
      17,
      57,
      25];

   DES_E : constant DES_Permutation (1 .. 48) :=
     [32,
      1,
      2,
      3,
      4,
      5,
      4,
      5,
      6,
      7,
      8,
      9,
      8,
      9,
      10,
      11,
      12,
      13,
      12,
      13,
      14,
      15,
      16,
      17,
      16,
      17,
      18,
      19,
      20,
      21,
      20,
      21,
      22,
      23,
      24,
      25,
      24,
      25,
      26,
      27,
      28,
      29,
      28,
      29,
      30,
      31,
      32,
      1];

   DES_P : constant DES_Permutation (1 .. 32) :=
     [16,
      7,
      20,
      21,
      29,
      12,
      28,
      17,
      1,
      15,
      23,
      26,
      5,
      18,
      31,
      10,
      2,
      8,
      24,
      14,
      32,
      27,
      3,
      9,
      19,
      13,
      30,
      6,
      22,
      11,
      4,
      25];

   DES_PC1 : constant DES_Permutation (1 .. 56) :=
     [57,
      49,
      41,
      33,
      25,
      17,
      9,
      1,
      58,
      50,
      42,
      34,
      26,
      18,
      10,
      2,
      59,
      51,
      43,
      35,
      27,
      19,
      11,
      3,
      60,
      52,
      44,
      36,
      63,
      55,
      47,
      39,
      31,
      23,
      15,
      7,
      62,
      54,
      46,
      38,
      30,
      22,
      14,
      6,
      61,
      53,
      45,
      37,
      29,
      21,
      13,
      5,
      28,
      20,
      12,
      4];

   DES_PC2 : constant DES_Permutation (1 .. 48) :=
     [14,
      17,
      11,
      24,
      1,
      5,
      3,
      28,
      15,
      6,
      21,
      10,
      23,
      19,
      12,
      4,
      26,
      8,
      16,
      7,
      27,
      20,
      13,
      2,
      41,
      52,
      31,
      37,
      47,
      55,
      30,
      40,
      51,
      45,
      33,
      48,
      44,
      49,
      39,
      56,
      34,
      53,
      46,
      42,
      50,
      36,
      29,
      32];

   DES_Shifts : constant array (Positive range 1 .. 16) of Natural :=
     [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

   DES_S :
     constant array (Natural range 0 .. 7, Natural range 0 .. 63)
     of Unsigned_8 :=
       [[14,
         4,
         13,
         1,
         2,
         15,
         11,
         8,
         3,
         10,
         6,
         12,
         5,
         9,
         0,
         7,
         0,
         15,
         7,
         4,
         14,
         2,
         13,
         1,
         10,
         6,
         12,
         11,
         9,
         5,
         3,
         8,
         4,
         1,
         14,
         8,
         13,
         6,
         2,
         11,
         15,
         12,
         9,
         7,
         3,
         10,
         5,
         0,
         15,
         12,
         8,
         2,
         4,
         9,
         1,
         7,
         5,
         11,
         3,
         14,
         10,
         0,
         6,
         13],
        [15,
         1,
         8,
         14,
         6,
         11,
         3,
         4,
         9,
         7,
         2,
         13,
         12,
         0,
         5,
         10,
         3,
         13,
         4,
         7,
         15,
         2,
         8,
         14,
         12,
         0,
         1,
         10,
         6,
         9,
         11,
         5,
         0,
         14,
         7,
         11,
         10,
         4,
         13,
         1,
         5,
         8,
         12,
         6,
         9,
         3,
         2,
         15,
         13,
         8,
         10,
         1,
         3,
         15,
         4,
         2,
         11,
         6,
         7,
         12,
         0,
         5,
         14,
         9],
        [10,
         0,
         9,
         14,
         6,
         3,
         15,
         5,
         1,
         13,
         12,
         7,
         11,
         4,
         2,
         8,
         13,
         7,
         0,
         9,
         3,
         4,
         6,
         10,
         2,
         8,
         5,
         14,
         12,
         11,
         15,
         1,
         13,
         6,
         4,
         9,
         8,
         15,
         3,
         0,
         11,
         1,
         2,
         12,
         5,
         10,
         14,
         7,
         1,
         10,
         13,
         0,
         6,
         9,
         8,
         7,
         4,
         15,
         14,
         3,
         11,
         5,
         2,
         12],
        [7,
         13,
         14,
         3,
         0,
         6,
         9,
         10,
         1,
         2,
         8,
         5,
         11,
         12,
         4,
         15,
         13,
         8,
         11,
         5,
         6,
         15,
         0,
         3,
         4,
         7,
         2,
         12,
         1,
         10,
         14,
         9,
         10,
         6,
         9,
         0,
         12,
         11,
         7,
         13,
         15,
         1,
         3,
         14,
         5,
         2,
         8,
         4,
         3,
         15,
         0,
         6,
         10,
         1,
         13,
         8,
         9,
         4,
         5,
         11,
         12,
         7,
         2,
         14],
        [2,
         12,
         4,
         1,
         7,
         10,
         11,
         6,
         8,
         5,
         3,
         15,
         13,
         0,
         14,
         9,
         14,
         11,
         2,
         12,
         4,
         7,
         13,
         1,
         5,
         0,
         15,
         10,
         3,
         9,
         8,
         6,
         4,
         2,
         1,
         11,
         10,
         13,
         7,
         8,
         15,
         9,
         12,
         5,
         6,
         3,
         0,
         14,
         11,
         8,
         12,
         7,
         1,
         14,
         2,
         13,
         6,
         15,
         0,
         9,
         10,
         4,
         5,
         3],
        [12,
         1,
         10,
         15,
         9,
         2,
         6,
         8,
         0,
         13,
         3,
         4,
         14,
         7,
         5,
         11,
         10,
         15,
         4,
         2,
         7,
         12,
         9,
         5,
         6,
         1,
         13,
         14,
         0,
         11,
         3,
         8,
         9,
         14,
         15,
         5,
         2,
         8,
         12,
         3,
         7,
         0,
         4,
         10,
         1,
         13,
         11,
         6,
         4,
         3,
         2,
         12,
         9,
         5,
         15,
         10,
         11,
         14,
         1,
         7,
         6,
         0,
         8,
         13],
        [4,
         11,
         2,
         14,
         15,
         0,
         8,
         13,
         3,
         12,
         9,
         7,
         5,
         10,
         6,
         1,
         13,
         0,
         11,
         7,
         4,
         9,
         1,
         10,
         14,
         3,
         5,
         12,
         2,
         15,
         8,
         6,
         1,
         4,
         11,
         13,
         12,
         3,
         7,
         14,
         10,
         15,
         6,
         8,
         0,
         5,
         9,
         2,
         6,
         11,
         13,
         8,
         1,
         4,
         10,
         7,
         9,
         5,
         0,
         15,
         14,
         2,
         3,
         12],
        [13,
         2,
         8,
         4,
         6,
         15,
         11,
         1,
         10,
         9,
         3,
         14,
         5,
         0,
         12,
         7,
         1,
         15,
         13,
         8,
         10,
         3,
         7,
         4,
         12,
         5,
         6,
         11,
         0,
         14,
         9,
         2,
         7,
         11,
         4,
         1,
         9,
         12,
         14,
         2,
         0,
         6,
         10,
         13,
         15,
         3,
         5,
         8,
         2,
         1,
         14,
         7,
         4,
         10,
         8,
         13,
         15,
         12,
         9,
         0,
         3,
         5,
         6,
         11]];

   function DES_Permute
     (Value : Word64; Input_Size : Natural; Table : DES_Permutation)
      return Word64
   is
      Result_Value : Word64 := 0;
      Source_Bit   : Natural;
   begin
      for Index_Value in Table'Range loop
         Result_Value := Shift_Left (Result_Value, 1);
         Source_Bit := Input_Size - Table (Index_Value);
         if (Shift_Right (Value, Source_Bit) and 1) /= 0 then
            Result_Value := Result_Value or 1;
         end if;
      end loop;
      return Result_Value;
   end DES_Permute;

   function DES_Rotate28 (Value : Word64; Count : Natural) return Word64
     with SPARK_Mode => On,
          Pre => Count <= 28
   is
      Mask28 : constant Word64 := 16#0FFFFFFF#;
   begin
      return
        (Shift_Left (Value, Count) or Shift_Right (Value, 28 - Count))
        and Mask28;
   end DES_Rotate28;

   type DES_Subkeys is array (Positive range 1 .. 16) of Word64;

   function DES_Load64
     (Data : Stream_Element_Array; First : Stream_Element_Offset) return Word64
     with SPARK_Mode => On,
          Pre => First >= Data'First
            and then First <= Stream_Element_Offset'Last - 7
            and then First + 7 <= Data'Last
   is
      Result_Value : Word64 := 0;
   begin
      for Offset_Value in 0 .. 7 loop
         Result_Value :=
           Shift_Left (Result_Value, 8)
           or
             Word64
               (Unsigned_8
                  (Data (First + Stream_Element_Offset (Offset_Value))));
      end loop;
      return Result_Value;
   end DES_Load64;

   procedure DES_Store64
     (Value : Word64;
      Data  : in out Stream_Element_Array;
      First : Stream_Element_Offset)
     with SPARK_Mode => On,
          Pre => First >= Data'First
            and then First <= Stream_Element_Offset'Last - 7
            and then First + 7 <= Data'Last
   is
   begin
      for Offset_Value in 0 .. 7 loop
         Data (First + Stream_Element_Offset (Offset_Value)) :=
           Stream_Element
             (Shift_Right (Value, 8 * (7 - Offset_Value)) and 16#FF#);
      end loop;
   end DES_Store64;

   function DES_Make_Subkeys
     (Key_Data : Stream_Element_Array; First : Stream_Element_Offset)
      return DES_Subkeys
   is
      Key64        : constant Word64 := DES_Load64 (Key_Data, First);
      Key56        : constant Word64 := DES_Permute (Key64, 64, DES_PC1);
      C            : Word64 := Shift_Right (Key56, 28) and 16#0FFFFFFF#;
      D            : Word64 := Key56 and 16#0FFFFFFF#;
      Result_Value : DES_Subkeys := [others => 0];
      Combined     : Word64;
   begin
      for Round in 1 .. 16 loop
         C := DES_Rotate28 (C, DES_Shifts (Round));
         D := DES_Rotate28 (D, DES_Shifts (Round));
         Combined := Shift_Left (C, 28) or D;
         Result_Value (Round) := DES_Permute (Combined, 56, DES_PC2);
      end loop;
      return Result_Value;
   end DES_Make_Subkeys;

   function DES_Feistel (Right_Value : Word; Subkey : Word64) return Word is
      Expanded  : constant Word64 :=
        DES_Permute (Word64 (Right_Value), 32, DES_E) xor Subkey;
      S_Output  : Word := 0;
      Six_Bits  : Natural;
      Row_Value : Natural;
      Col_Value : Natural;
      Box_Value : Unsigned_8;
      Permuted  : Word64;
   begin
      for Box_Index in 0 .. 7 loop
         Six_Bits :=
           Natural (Shift_Right (Expanded, 42 - 6 * Box_Index) and 16#3F#);
         Row_Value := (Six_Bits / 32) * 2 + (Six_Bits mod 2);
         Col_Value := (Six_Bits / 2) mod 16;
         Box_Value := DES_S (Box_Index, Row_Value * 16 + Col_Value);
         S_Output := Shift_Left (S_Output, 4) or Word (Box_Value);
      end loop;
      Permuted := DES_Permute (Word64 (S_Output), 32, DES_P);
      return Word (Permuted and 16#FFFFFFFF#);
   end DES_Feistel;

   function DES_Decrypt_Block
     (Block_Value : Word64; Subkeys : DES_Subkeys) return Word64
   is
      Permuted   : constant Word64 := DES_Permute (Block_Value, 64, DES_IP);
      L          : Word := Word (Shift_Right (Permuted, 32) and 16#FFFFFFFF#);
      R          : Word := Word (Permuted and 16#FFFFFFFF#);
      Old_L      : Word;
      Pre_Output : Word64;
   begin
      for Round in reverse 1 .. 16 loop
         Old_L := L;
         L := R;
         R := Old_L xor DES_Feistel (R, Subkeys (Round));
      end loop;
      Pre_Output := Shift_Left (Word64 (R), 32) or Word64 (L);
      return DES_Permute (Pre_Output, 64, DES_FP);
   end DES_Decrypt_Block;

   function DES_Encrypt_Block
     (Block_Value : Word64; Subkeys : DES_Subkeys) return Word64
   is
      Permuted   : constant Word64 := DES_Permute (Block_Value, 64, DES_IP);
      L          : Word := Word (Shift_Right (Permuted, 32) and 16#FFFFFFFF#);
      R          : Word := Word (Permuted and 16#FFFFFFFF#);
      Old_L      : Word;
      Pre_Output : Word64;
   begin
      for Round in 1 .. 16 loop
         Old_L := L;
         L := R;
         R := Old_L xor DES_Feistel (R, Subkeys (Round));
      end loop;
      Pre_Output := Shift_Left (Word64 (R), 32) or Word64 (L);
      return DES_Permute (Pre_Output, 64, DES_FP);
   end DES_Encrypt_Block;

   function DES3_Decrypt_EDE_Block
     (Block_Value : Word64; Key_Data : Stream_Element_Array) return Word64
   is
      K1 : constant DES_Subkeys := DES_Make_Subkeys (Key_Data, Key_Data'First);
      K2 : constant DES_Subkeys :=
        DES_Make_Subkeys
          (Key_Data, Key_Data'First + Stream_Element_Offset (8));
      K3 : constant DES_Subkeys :=
        DES_Make_Subkeys
          (Key_Data, Key_Data'First + Stream_Element_Offset (16));
   begin
      return
        DES_Decrypt_Block
          (DES_Encrypt_Block (DES_Decrypt_Block (Block_Value, K3), K2), K1);
   end DES3_Decrypt_EDE_Block;

   function DES3_Encrypt_EDE_Block
     (Block_Value : Word64; Key_Data : Stream_Element_Array) return Word64
   is
      K1 : constant DES_Subkeys := DES_Make_Subkeys (Key_Data, Key_Data'First);
      K2 : constant DES_Subkeys :=
        DES_Make_Subkeys
          (Key_Data, Key_Data'First + Stream_Element_Offset (8));
      K3 : constant DES_Subkeys :=
        DES_Make_Subkeys
          (Key_Data, Key_Data'First + Stream_Element_Offset (16));
   begin
      return
        DES_Encrypt_Block
          (DES_Decrypt_Block (DES_Encrypt_Block (Block_Value, K1), K2), K3);
   end DES3_Encrypt_EDE_Block;

   function DES_Load_Counter64 (Data : Counter_Block) return Word64
     with SPARK_Mode => On
   is
      Result_Value : Word64 := 0;
   begin
      for Offset_Value in 0 .. 7 loop
         Result_Value :=
           Shift_Left (Result_Value, 8)
           or Word64 (Data (Offset_Value));
      end loop;
      return Result_Value;
   end DES_Load_Counter64;

   procedure DES_Store_Counter64
     (Value : Word64; Data : in out Counter_Block)
     with SPARK_Mode => On
   is
   begin
      for Offset_Value in 0 .. 7 loop
         Data (Offset_Value) :=
           Byte (Shift_Right (Value, 8 * (7 - Offset_Value)) and 16#FF#);
      end loop;
      for Offset_Value in 8 .. 15 loop
         Data (Offset_Value) := 0;
      end loop;
   end DES_Store_Counter64;

   function To_Byte (Value : Stream_Element) return Byte
     with SPARK_Mode => On
   is
   begin
      return Byte (Value);
   end To_Byte;

   function To_Element (Value : Byte) return Stream_Element
     with SPARK_Mode => On
   is
   begin
      return Stream_Element (Value);
   end To_Element;

   function Pack_Word (A, B, C, D : Byte) return Word
     with SPARK_Mode => On
   is
   begin
      return
        Shift_Left (Word (A), 24)
        or Shift_Left (Word (B), 16)
        or Shift_Left (Word (C), 8)
        or Word (D);
   end Pack_Word;

   ----------------------------------------------------------------------------
   --  Constant-time bit-sliced AES S-box.  The bytes are transposed into 8
   --  bit-planes (bit i of every byte lives in plane i, one bit per 16-bit
   --  lane), and the S-box is computed as affine(x**254) over GF(2**8) with
   --  branchless field arithmetic and a public fixed exponent -- no table
   --  lookup and no data-dependent branch, hence no cache-timing side channel.
   --  Verified against the AES S-box / inverse S-box for all 256 inputs.
   ----------------------------------------------------------------------------

   type Bit_Planes is array (0 .. 7) of Interfaces.Unsigned_16;

   function Xtime_BS (A : Bit_Planes) return Bit_Planes is
     [0 => A (7),
      1 => A (0) xor A (7),
      2 => A (1),
      3 => A (2) xor A (7),
      4 => A (3) xor A (7),
      5 => A (4),
      6 => A (5),
      7 => A (6)];

   function GF_Mul_BS (A_In, B : Bit_Planes) return Bit_Planes is
      R : Bit_Planes := [others => 0];
      A : Bit_Planes := A_In;
   begin
      for I in 0 .. 7 loop
         for P in 0 .. 7 loop
            R (P) := R (P) xor (A (P) and B (I));
         end loop;
         A := Xtime_BS (A);
      end loop;
      return R;
   end GF_Mul_BS;

   function GF_Inv_BS (A : Bit_Planes) return Bit_Planes is
      R : Bit_Planes := [0 => 16#FFFF#, others => 0];   --  the field value 1
   begin
      --  R := A ** 254 by square-and-multiply over the public exponent
      --  0b1111_1110: square every step, multiply on the top seven bits.
      for Bit_Index in 0 .. 7 loop
         R := GF_Mul_BS (R, R);
         if Bit_Index <= 6 then
            R := GF_Mul_BS (R, A);
         end if;
      end loop;
      return R;
   end GF_Inv_BS;

   function Rot_Plane (I, N : Integer) return Integer is ((I - N) mod 8);

   function Affine_BS (Y : Bit_Planes) return Bit_Planes is
      S : Bit_Planes;
   begin
      for I in 0 .. 7 loop
         S (I) :=
           Y (I) xor Y (Rot_Plane (I, 1)) xor Y (Rot_Plane (I, 2))
           xor Y (Rot_Plane (I, 3)) xor Y (Rot_Plane (I, 4));
      end loop;
      S (0) := S (0) xor 16#FFFF#;                       --  add constant 0x63
      S (1) := S (1) xor 16#FFFF#;
      S (5) := S (5) xor 16#FFFF#;
      S (6) := S (6) xor 16#FFFF#;
      return S;
   end Affine_BS;

   function Inv_Affine_BS (Y : Bit_Planes) return Bit_Planes is
      S : Bit_Planes;
   begin
      for I in 0 .. 7 loop
         S (I) :=
           Y (Rot_Plane (I, 1)) xor Y (Rot_Plane (I, 3)) xor Y (Rot_Plane (I, 6));
      end loop;
      S (0) := S (0) xor 16#FFFF#;                       --  add constant 0x05
      S (2) := S (2) xor 16#FFFF#;
      return S;
   end Inv_Affine_BS;

   function SBox_BS (A : Bit_Planes) return Bit_Planes is
     (Affine_BS (GF_Inv_BS (A)));
   function Inv_SBox_BS (A : Bit_Planes) return Bit_Planes is
     (GF_Inv_BS (Inv_Affine_BS (A)));

   --  Transpose Count bytes (from the front of State) into bit-planes.
   function Pack (State : Counter_Block; Count : Natural) return Bit_Planes is
      R : Bit_Planes := [others => 0];
   begin
      for J in 0 .. Count - 1 loop
         for I in 0 .. 7 loop
            R (I) := R (I)
              or Shift_Left
                   (Interfaces.Unsigned_16 (Shift_Right (State (J), I) and 1), J);
         end loop;
      end loop;
      return R;
   end Pack;

   procedure Unpack
     (Planes : Bit_Planes; State : in out Counter_Block; Count : Natural)
   is
   begin
      for J in 0 .. Count - 1 loop
         declare
            V : Byte := 0;
         begin
            for I in 0 .. 7 loop
               V := V
                 or Shift_Left (Byte (Shift_Right (Planes (I), J) and 1), I);
            end loop;
            State (J) := V;
         end;
      end loop;
   end Unpack;

   function Sub_Word (Value : Word) return Word is
      Bytes  : Counter_Block := [others => 0];
      Planes : Bit_Planes;
   begin
      Bytes (0) := Byte (Shift_Right (Value, 24) and 16#FF#);
      Bytes (1) := Byte (Shift_Right (Value, 16) and 16#FF#);
      Bytes (2) := Byte (Shift_Right (Value, 8) and 16#FF#);
      Bytes (3) := Byte (Value and 16#FF#);
      Planes := SBox_BS (Pack (Bytes, 4));
      Unpack (Planes, Bytes, 4);
      return Pack_Word (Bytes (0), Bytes (1), Bytes (2), Bytes (3));
   end Sub_Word;

   function Rot_Word (Value : Word) return Word
     with SPARK_Mode => On
   is
   begin
      return Shift_Left (Value, 8) or Shift_Right (Value, 24);
   end Rot_Word;

   procedure Reset (Item : out Cipher_State)
     with SPARK_Mode => On
   is
   begin
      Item.Active_Item := False;
      Item.Direction_Value := Client_To_Server;
      Item.Mode_Value := CTR_Mode;
      Item.Round_Count := 0;
      Item.Round_Keys := [others => 0];
      Item.DES3_Key_Data := [others => 0];
      Item.Counter_Value := [others => 0];
      Item.CTR_Stream_Value := [others => 0];
      Item.CTR_Stream_Offset := 16;
   end Reset;

   function Expand_Key
     (Item     : in out Cipher_State;
      Key_Data : Stream_Element_Array;
      Key_Bits : Natural) return CryptoLib.Errors.Status
   is
      Nk          : constant Natural := Key_Bits / 32;
      Nr          : constant Natural := Nk + 6;
      Total_Words : constant Natural := 4 * (Nr + 1);
      Temp        : Word;
   begin
      if Key_Data'Length < Key_Bits / 8 then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      for Index_Value in 0 .. Nk - 1 loop
         Item.Round_Keys (AES_Word_Index (Index_Value)) :=
           Pack_Word
             (To_Byte
                (Key_Data
                   (Key_Data'First + Stream_Element_Offset (4 * Index_Value))),
              To_Byte
                (Key_Data
                   (Key_Data'First
                    + Stream_Element_Offset (4 * Index_Value + 1))),
              To_Byte
                (Key_Data
                   (Key_Data'First
                    + Stream_Element_Offset (4 * Index_Value + 2))),
              To_Byte
                (Key_Data
                   (Key_Data'First
                    + Stream_Element_Offset (4 * Index_Value + 3))));
      end loop;

      for Index_Value in Nk .. Total_Words - 1 loop
         Temp := Item.Round_Keys (AES_Word_Index (Index_Value - 1));
         if Index_Value mod Nk = 0 then
            Temp := Sub_Word (Rot_Word (Temp)) xor Rcon (Index_Value / Nk);
         elsif Nk > 6 and then Index_Value mod Nk = 4 then
            Temp := Sub_Word (Temp);
         end if;
         Item.Round_Keys (AES_Word_Index (Index_Value)) :=
           Item.Round_Keys (AES_Word_Index (Index_Value - Nk)) xor Temp;
      end loop;

      Item.Round_Count := Nr;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Reset (Item);
         return CryptoLib.Errors.Internal_Error;
   end Expand_Key;

   procedure Add_Round_Key
     (State_Item : in out Counter_Block; Item : Cipher_State; Round : Natural)
     with SPARK_Mode => On,
          Pre => Round <= 14
   is
      Word_Value   : Word;
      Offset_Value : Natural;
   begin
      for Column in 0 .. 3 loop
         Word_Value := Item.Round_Keys (AES_Word_Index (Round * 4 + Column));
         Offset_Value := Column * 4;
         State_Item (Offset_Value) :=
           State_Item (Offset_Value)
           xor Byte (Shift_Right (Word_Value, 24) and 16#FF#);
         State_Item (Offset_Value + 1) :=
           State_Item (Offset_Value + 1)
           xor Byte (Shift_Right (Word_Value, 16) and 16#FF#);
         State_Item (Offset_Value + 2) :=
           State_Item (Offset_Value + 2)
           xor Byte (Shift_Right (Word_Value, 8) and 16#FF#);
         State_Item (Offset_Value + 3) :=
           State_Item (Offset_Value + 3) xor Byte (Word_Value and 16#FF#);
      end loop;
   end Add_Round_Key;

   procedure Sub_Bytes (State_Item : in out Counter_Block) is
   begin
      Unpack (SBox_BS (Pack (State_Item, 16)), State_Item, 16);
   end Sub_Bytes;

   procedure Shift_Rows (State_Item : in out Counter_Block)
     with SPARK_Mode => On
   is
      Copy_Item : constant Counter_Block := State_Item;
   begin
      State_Item (0) := Copy_Item (0);
      State_Item (4) := Copy_Item (4);
      State_Item (8) := Copy_Item (8);
      State_Item (12) := Copy_Item (12);

      State_Item (1) := Copy_Item (5);
      State_Item (5) := Copy_Item (9);
      State_Item (9) := Copy_Item (13);
      State_Item (13) := Copy_Item (1);

      State_Item (2) := Copy_Item (10);
      State_Item (6) := Copy_Item (14);
      State_Item (10) := Copy_Item (2);
      State_Item (14) := Copy_Item (6);

      State_Item (3) := Copy_Item (15);
      State_Item (7) := Copy_Item (3);
      State_Item (11) := Copy_Item (7);
      State_Item (15) := Copy_Item (11);
   end Shift_Rows;

   function Xtime (Value : Byte) return Byte
     with SPARK_Mode => On
   is
      --  Branchless GF(2**8) doubling: reduce with 0x1B iff the top bit is set.
      Mask : constant Byte := Byte (0) - Shift_Right (Value, 7);
   begin
      return Shift_Left (Value, 1) xor (16#1B# and Mask);
   end Xtime;

   procedure Mix_Columns (State_Item : in out Counter_Block)
     with SPARK_Mode => On
   is
      A0, A1, A2, A3   : Byte;
      T_Value, U_Value : Byte;
      Offset_Value     : Natural;
   begin
      for Column in 0 .. 3 loop
         Offset_Value := Column * 4;
         A0 := State_Item (Offset_Value);
         A1 := State_Item (Offset_Value + 1);
         A2 := State_Item (Offset_Value + 2);
         A3 := State_Item (Offset_Value + 3);
         T_Value := A0 xor A1 xor A2 xor A3;
         U_Value := A0;
         State_Item (Offset_Value) :=
           State_Item (Offset_Value) xor T_Value xor Xtime (A0 xor A1);
         State_Item (Offset_Value + 1) :=
           State_Item (Offset_Value + 1) xor T_Value xor Xtime (A1 xor A2);
         State_Item (Offset_Value + 2) :=
           State_Item (Offset_Value + 2) xor T_Value xor Xtime (A2 xor A3);
         State_Item (Offset_Value + 3) :=
           State_Item (Offset_Value + 3)
           xor T_Value
           xor Xtime (A3 xor U_Value);
      end loop;
   end Mix_Columns;

   procedure Encrypt_Block
     (Item      : Cipher_State;
      Block_In  : Counter_Block;
      Block_Out : out Counter_Block) is
   begin
      Block_Out := Block_In;
      Add_Round_Key (Block_Out, Item, 0);
      for Round in 1 .. Item.Round_Count - 1 loop
         Sub_Bytes (Block_Out);
         Shift_Rows (Block_Out);
         Mix_Columns (Block_Out);
         Add_Round_Key (Block_Out, Item, Round);
      end loop;
      Sub_Bytes (Block_Out);
      Shift_Rows (Block_Out);
      Add_Round_Key (Block_Out, Item, Item.Round_Count);
   end Encrypt_Block;

   procedure Increment_Counter (Item : in out Cipher_State)
     with SPARK_Mode => On
   is
   begin
      for Index_Value in reverse Item.Counter_Value'Range loop
         Item.Counter_Value (Index_Value) :=
           Item.Counter_Value (Index_Value) + 1;
         exit when Item.Counter_Value (Index_Value) /= 0;
      end loop;
   end Increment_Counter;

   function Apply_CTR
     (Item       : in out Cipher_State;
      Input_Data : Stream_Element_Array;
      Output     : out Stream_Element_Array) return CryptoLib.Errors.Status
   is
      Key_Stream   : Counter_Block;
      Input_Index  : Stream_Element_Offset := Input_Data'First;
      Output_Index : Stream_Element_Offset := Output'First;
   begin
      if not Item.Active_Item then
         Output := [others => 0];
         return CryptoLib.Errors.Handshake_Failed;
      end if;
      if Output'Length /= Input_Data'Length then
         Output := [others => 0];
         return CryptoLib.Errors.Internal_Error;
      end if;

      while Input_Index <= Input_Data'Last loop
         if Item.CTR_Stream_Offset = 16 then
            Encrypt_Block (Item, Item.Counter_Value, Key_Stream);
            Increment_Counter (Item);
            Item.CTR_Stream_Value := Key_Stream;
            Item.CTR_Stream_Offset := 0;
         end if;

         Output (Output_Index) :=
           To_Element
             (To_Byte (Input_Data (Input_Index))
              xor Item.CTR_Stream_Value (Item.CTR_Stream_Offset));
         Item.CTR_Stream_Offset := Item.CTR_Stream_Offset + 1;
         Input_Index := Input_Index + 1;
         Output_Index := Output_Index + 1;
      end loop;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Item.Active_Item := False;
         Output := [others => 0];
         return CryptoLib.Errors.Internal_Error;
   end Apply_CTR;

   function Initialize
     (Item           : in out Cipher_State;
      Algorithm_Name : String;
      Direction_Item : Cipher_Direction;
      Key_Data       : Stream_Element_Array;
      IV_Data        : Stream_Element_Array) return CryptoLib.Errors.Status
   is
      Key_Bits     : Natural;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Reset (Item);
      Item.Direction_Value := Direction_Item;

      if Algorithm_Name = "aes128-ctr" then
         Key_Bits := 128;
         Item.Mode_Value := CTR_Mode;
      elsif Algorithm_Name = "aes192-ctr" then
         Key_Bits := 192;
         Item.Mode_Value := CTR_Mode;
      elsif Algorithm_Name = "aes256-ctr" then
         Key_Bits := 256;
         Item.Mode_Value := CTR_Mode;
      elsif Algorithm_Name = "aes128-cbc" then
         Key_Bits := 128;
         Item.Mode_Value := CBC_Mode;
      elsif Algorithm_Name = "aes192-cbc" then
         Key_Bits := 192;
         Item.Mode_Value := CBC_Mode;
      elsif Algorithm_Name = "aes256-cbc" then
         Key_Bits := 256;
         Item.Mode_Value := CBC_Mode;
      elsif Algorithm_Name = "3des-cbc" then
         if Key_Data'Length < 24 or else IV_Data'Length < 8 then
            return CryptoLib.Errors.Handshake_Failed;
         end if;
         Item.Mode_Value := DES3_CBC_Mode;
         for Offset_Value in 0 .. 23 loop
            Item.DES3_Key_Data
              (Stream_Element_Offset (Offset_Value + 1)) :=
                Key_Data (Key_Data'First + Stream_Element_Offset (Offset_Value));
         end loop;
         for Offset_Value in 0 .. 7 loop
            Item.Counter_Value (Offset_Value) :=
              To_Byte
                (IV_Data (IV_Data'First + Stream_Element_Offset (Offset_Value)));
         end loop;
         Item.Active_Item := True;
         return CryptoLib.Errors.Ok;
      else
         return CryptoLib.Errors.Unsupported_Feature;
      end if;

      if IV_Data'Length < 16 then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      Status_Value := Expand_Key (Item, Key_Data, Key_Bits);
      if Status_Value /= CryptoLib.Errors.Ok then
         Reset (Item);
         return Status_Value;
      end if;

      for Index_Value in 0 .. 15 loop
         Item.Counter_Value (Index_Value) :=
           To_Byte
             (IV_Data (IV_Data'First + Stream_Element_Offset (Index_Value)));
      end loop;

      Item.Active_Item := True;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Reset (Item);
         return CryptoLib.Errors.Internal_Error;
   end Initialize;

   function Is_Active (Item : Cipher_State) return Boolean
     with SPARK_Mode => On
   is
   begin
      return Item.Active_Item;
   end Is_Active;

   function Block_Size (Item : Cipher_State) return Natural
     with SPARK_Mode => On
   is
   begin
      if Item.Active_Item then
         if Item.Mode_Value = DES3_CBC_Mode then
            return 8;
         end if;
         return 16;
      end if;
      return 8;
   end Block_Size;

   function Apply_CBC_Encrypt
     (Item       : in out Cipher_State;
      Input_Data : Stream_Element_Array;
      Output     : out Stream_Element_Array) return CryptoLib.Errors.Status;

   function Apply_CBC_Decrypt
     (Item       : in out Cipher_State;
      Input_Data : Stream_Element_Array;
      Output     : out Stream_Element_Array) return CryptoLib.Errors.Status;

   function Apply_DES3_CBC_Encrypt
     (Item       : in out Cipher_State;
      Input_Data : Stream_Element_Array;
      Output     : out Stream_Element_Array) return CryptoLib.Errors.Status;

   function Apply_DES3_CBC_Decrypt
     (Item       : in out Cipher_State;
      Input_Data : Stream_Element_Array;
      Output     : out Stream_Element_Array) return CryptoLib.Errors.Status;

   function Encrypt
     (Item      : in out Cipher_State;
      Plaintext : Stream_Element_Array;
      Output    : out Stream_Element_Array) return CryptoLib.Errors.Status is
   begin
      if Item.Mode_Value = DES3_CBC_Mode then
         return Apply_DES3_CBC_Encrypt (Item, Plaintext, Output);
      end if;
      if Item.Mode_Value = CBC_Mode then
         return Apply_CBC_Encrypt (Item, Plaintext, Output);
      end if;
      return Apply_CTR (Item, Plaintext, Output);
   end Encrypt;

   function Decrypt
     (Item       : in out Cipher_State;
      Ciphertext : Stream_Element_Array;
      Output     : out Stream_Element_Array) return CryptoLib.Errors.Status is
   begin
      if Item.Mode_Value = DES3_CBC_Mode then
         return Apply_DES3_CBC_Decrypt (Item, Ciphertext, Output);
      end if;
      if Item.Mode_Value = CBC_Mode then
         return Apply_CBC_Decrypt (Item, Ciphertext, Output);
      end if;
      return Apply_CTR (Item, Ciphertext, Output);
   end Decrypt;

   function Gmul (Left_Value, Right_Value : Byte) return Byte
     with SPARK_Mode => On
   is
      A_Value      : Byte := Left_Value;
      B_Value      : Byte := Right_Value;
      Result_Value : Byte := 0;
      Mask         : Byte;
   begin
      for Bit_Index in 0 .. 7 loop
         Mask := Byte (0) - (B_Value and 1);         --  0xFF iff low bit set
         Result_Value := Result_Value xor (A_Value and Mask);
         A_Value := Xtime (A_Value);
         B_Value := Shift_Right (B_Value, 1);
      end loop;
      return Result_Value;
   end Gmul;

   procedure Inv_Sub_Bytes (State_Item : in out Counter_Block) is
   begin
      Unpack (Inv_SBox_BS (Pack (State_Item, 16)), State_Item, 16);
   end Inv_Sub_Bytes;

   procedure Inv_Shift_Rows (State_Item : in out Counter_Block)
     with SPARK_Mode => On
   is
      Copy_Item : constant Counter_Block := State_Item;
   begin
      State_Item (0) := Copy_Item (0);
      State_Item (4) := Copy_Item (4);
      State_Item (8) := Copy_Item (8);
      State_Item (12) := Copy_Item (12);

      State_Item (1) := Copy_Item (13);
      State_Item (5) := Copy_Item (1);
      State_Item (9) := Copy_Item (5);
      State_Item (13) := Copy_Item (9);

      State_Item (2) := Copy_Item (10);
      State_Item (6) := Copy_Item (14);
      State_Item (10) := Copy_Item (2);
      State_Item (14) := Copy_Item (6);

      State_Item (3) := Copy_Item (7);
      State_Item (7) := Copy_Item (11);
      State_Item (11) := Copy_Item (15);
      State_Item (15) := Copy_Item (3);
   end Inv_Shift_Rows;

   procedure Inv_Mix_Columns (State_Item : in out Counter_Block)
     with SPARK_Mode => On
   is
      A0, A1, A2, A3 : Byte;
      Offset_Value   : Natural;
   begin
      for Column in 0 .. 3 loop
         Offset_Value := Column * 4;
         A0 := State_Item (Offset_Value);
         A1 := State_Item (Offset_Value + 1);
         A2 := State_Item (Offset_Value + 2);
         A3 := State_Item (Offset_Value + 3);
         State_Item (Offset_Value) :=
           Gmul (A0, 16#0E#)
           xor Gmul (A1, 16#0B#)
           xor Gmul (A2, 16#0D#)
           xor Gmul (A3, 16#09#);
         State_Item (Offset_Value + 1) :=
           Gmul (A0, 16#09#)
           xor Gmul (A1, 16#0E#)
           xor Gmul (A2, 16#0B#)
           xor Gmul (A3, 16#0D#);
         State_Item (Offset_Value + 2) :=
           Gmul (A0, 16#0D#)
           xor Gmul (A1, 16#09#)
           xor Gmul (A2, 16#0E#)
           xor Gmul (A3, 16#0B#);
         State_Item (Offset_Value + 3) :=
           Gmul (A0, 16#0B#)
           xor Gmul (A1, 16#0D#)
           xor Gmul (A2, 16#09#)
           xor Gmul (A3, 16#0E#);
      end loop;
   end Inv_Mix_Columns;

   procedure Decrypt_Block
     (Item      : Cipher_State;
      Block_In  : Counter_Block;
      Block_Out : out Counter_Block) is
   begin
      Block_Out := Block_In;
      Add_Round_Key (Block_Out, Item, Item.Round_Count);
      for Round_Index in reverse 1 .. Item.Round_Count - 1 loop
         Inv_Shift_Rows (Block_Out);
         Inv_Sub_Bytes (Block_Out);
         Add_Round_Key (Block_Out, Item, Round_Index);
         Inv_Mix_Columns (Block_Out);
      end loop;
      Inv_Shift_Rows (Block_Out);
      Inv_Sub_Bytes (Block_Out);
      Add_Round_Key (Block_Out, Item, 0);
   end Decrypt_Block;

   function Apply_CBC_Encrypt
     (Item       : in out Cipher_State;
      Input_Data : Stream_Element_Array;
      Output     : out Stream_Element_Array) return CryptoLib.Errors.Status
   is
      Previous_Block : Counter_Block := Item.Counter_Value;
      Plain_Block    : Counter_Block := [others => 0];
      Cipher_Block   : Counter_Block := [others => 0];
      Input_Index    : Stream_Element_Offset := Input_Data'First;
      Output_Index   : Stream_Element_Offset := Output'First;
   begin
      if not Item.Active_Item
        or else Item.Mode_Value /= CBC_Mode
        or else Output'Length /= Input_Data'Length
        or else Input_Data'Length = 0
        or else Input_Data'Length mod 16 /= 0
      then
         Output := [others => 0];
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      while Input_Index <= Input_Data'Last loop
         for Offset_Value in 0 .. 15 loop
            Plain_Block (Offset_Value) :=
              To_Byte
                (Input_Data
                   (Input_Index + Stream_Element_Offset (Offset_Value)))
              xor Previous_Block (Offset_Value);
         end loop;

         Encrypt_Block (Item, Plain_Block, Cipher_Block);

         for Offset_Value in 0 .. 15 loop
            Output (Output_Index + Stream_Element_Offset (Offset_Value)) :=
              To_Element (Cipher_Block (Offset_Value));
         end loop;

         Previous_Block := Cipher_Block;
         Input_Index := Input_Index + 16;
         Output_Index := Output_Index + 16;
      end loop;

      Item.Counter_Value := Previous_Block;
      Plain_Block := [others => 0];
      Cipher_Block := [others => 0];
      Previous_Block := [others => 0];
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Item.Active_Item := False;
         Output := [others => 0];
         return CryptoLib.Errors.Internal_Error;
   end Apply_CBC_Encrypt;

   function Apply_CBC_Decrypt
     (Item       : in out Cipher_State;
      Input_Data : Stream_Element_Array;
      Output     : out Stream_Element_Array) return CryptoLib.Errors.Status
   is
      Previous_Block : Counter_Block := Item.Counter_Value;
      Input_Block    : Counter_Block := [others => 0];
      Plain_Block    : Counter_Block := [others => 0];
      Input_Index    : Stream_Element_Offset := Input_Data'First;
      Output_Index   : Stream_Element_Offset := Output'First;
   begin
      if not Item.Active_Item
        or else Item.Mode_Value /= CBC_Mode
        or else Output'Length /= Input_Data'Length
        or else Input_Data'Length = 0
        or else Input_Data'Length mod 16 /= 0
      then
         Output := [others => 0];
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      while Input_Index <= Input_Data'Last loop
         for Offset_Value in 0 .. 15 loop
            Input_Block (Offset_Value) :=
              To_Byte
                (Input_Data
                   (Input_Index + Stream_Element_Offset (Offset_Value)));
         end loop;

         Decrypt_Block (Item, Input_Block, Plain_Block);

         for Offset_Value in 0 .. 15 loop
            Output (Output_Index + Stream_Element_Offset (Offset_Value)) :=
              To_Element
                (Plain_Block (Offset_Value) xor Previous_Block (Offset_Value));
         end loop;

         Previous_Block := Input_Block;
         Input_Index := Input_Index + 16;
         Output_Index := Output_Index + 16;
      end loop;

      Item.Counter_Value := Previous_Block;
      Input_Block := [others => 0];
      Plain_Block := [others => 0];
      Previous_Block := [others => 0];
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Item.Active_Item := False;
         Output := [others => 0];
         return CryptoLib.Errors.Internal_Error;
   end Apply_CBC_Decrypt;

   function Apply_DES3_CBC_Encrypt
     (Item       : in out Cipher_State;
      Input_Data : Stream_Element_Array;
      Output     : out Stream_Element_Array) return CryptoLib.Errors.Status
   is
      Previous_Block : Word64 := DES_Load_Counter64 (Item.Counter_Value);
      Plain_Block    : Word64;
      Cipher_Block   : Word64;
      Input_Index    : Stream_Element_Offset := Input_Data'First;
      Output_Index   : Stream_Element_Offset := Output'First;
   begin
      if not Item.Active_Item
        or else Item.Mode_Value /= DES3_CBC_Mode
        or else Output'Length /= Input_Data'Length
        or else Input_Data'Length = 0
        or else Input_Data'Length mod 8 /= 0
      then
         Output := [others => 0];
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      while Input_Index <= Input_Data'Last loop
         Plain_Block := DES_Load64 (Input_Data, Input_Index) xor Previous_Block;
         Cipher_Block := DES3_Encrypt_EDE_Block (Plain_Block, Item.DES3_Key_Data);
         DES_Store64 (Cipher_Block, Output, Output_Index);
         Previous_Block := Cipher_Block;
         Input_Index := Input_Index + 8;
         Output_Index := Output_Index + 8;
      end loop;

      DES_Store_Counter64 (Previous_Block, Item.Counter_Value);
      Previous_Block := 0;
      Plain_Block := 0;
      Cipher_Block := 0;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Item.Active_Item := False;
         Output := [others => 0];
         return CryptoLib.Errors.Internal_Error;
   end Apply_DES3_CBC_Encrypt;

   function Apply_DES3_CBC_Decrypt
     (Item       : in out Cipher_State;
      Input_Data : Stream_Element_Array;
      Output     : out Stream_Element_Array) return CryptoLib.Errors.Status
   is
      Previous_Block : Word64 := DES_Load_Counter64 (Item.Counter_Value);
      Input_Block    : Word64;
      Plain_Block    : Word64;
      Input_Index    : Stream_Element_Offset := Input_Data'First;
      Output_Index   : Stream_Element_Offset := Output'First;
   begin
      if not Item.Active_Item
        or else Item.Mode_Value /= DES3_CBC_Mode
        or else Output'Length /= Input_Data'Length
        or else Input_Data'Length = 0
        or else Input_Data'Length mod 8 /= 0
      then
         Output := [others => 0];
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      while Input_Index <= Input_Data'Last loop
         Input_Block := DES_Load64 (Input_Data, Input_Index);
         Plain_Block :=
           DES3_Decrypt_EDE_Block (Input_Block, Item.DES3_Key_Data)
           xor Previous_Block;
         DES_Store64 (Plain_Block, Output, Output_Index);
         Previous_Block := Input_Block;
         Input_Index := Input_Index + 8;
         Output_Index := Output_Index + 8;
      end loop;

      DES_Store_Counter64 (Previous_Block, Item.Counter_Value);
      Previous_Block := 0;
      Input_Block := 0;
      Plain_Block := 0;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Item.Active_Item := False;
         Output := [others => 0];
         return CryptoLib.Errors.Internal_Error;
   end Apply_DES3_CBC_Decrypt;

   subtype Word16 is Unsigned_16;
   type RC2_Key_Schedule is array (Natural range 0 .. 63) of Word16;

   RC2_Pitable : constant array (Natural range 0 .. 255) of Byte :=
     [217, 120, 249, 196, 25, 221, 181, 237, 40, 233, 253, 121, 74, 160,
      216, 157, 198, 126, 55, 131, 43, 118, 83, 142, 98, 76, 100, 136,
      68, 139, 251, 162, 23, 154, 89, 245, 135, 179, 79, 19, 97, 69,
      109, 141, 9, 129, 125, 50, 189, 143, 64, 235, 134, 183, 123, 11,
      240, 149, 33, 34, 92, 107, 78, 130, 84, 214, 101, 147, 206, 96,
      178, 28, 115, 86, 192, 20, 167, 140, 241, 220, 18, 117, 202, 31,
      59, 190, 228, 209, 66, 61, 212, 48, 163, 60, 182, 38, 111, 191,
      14, 218, 70, 105, 7, 87, 39, 242, 29, 155, 188, 148, 67, 3, 248,
      17, 199, 246, 144, 239, 62, 231, 6, 195, 213, 47, 200, 102, 30,
      215, 8, 232, 234, 222, 128, 82, 238, 247, 132, 170, 114, 172, 53,
      77, 106, 42, 150, 26, 210, 113, 90, 21, 73, 116, 75, 159, 208,
      94, 4, 24, 164, 236, 194, 224, 65, 110, 15, 81, 203, 204, 36, 145,
      175, 80, 161, 244, 112, 57, 153, 124, 58, 133, 35, 184, 180, 122,
      252, 2, 54, 91, 37, 85, 151, 49, 45, 93, 250, 152, 227, 138, 146,
      174, 5, 223, 41, 16, 103, 108, 186, 201, 211, 0, 230, 207, 225,
      158, 168, 44, 99, 22, 1, 63, 88, 226, 137, 169, 13, 56, 52, 27,
      171, 51, 255, 176, 187, 72, 12, 95, 185, 177, 205, 46, 197, 243,
      219, 71, 229, 165, 156, 119, 10, 166, 32, 104, 254, 127, 193, 173];

   function RC2_Ror16 (Value : Word16; Count : Natural) return Word16
     with SPARK_Mode => On,
          Pre => Count <= 16
   is
   begin
      return Shift_Right (Value, Count) or Shift_Left (Value, 16 - Count);
   end RC2_Ror16;

   function RC2_Load16
     (Data : Stream_Element_Array; First : Stream_Element_Offset) return Word16
     with SPARK_Mode => On,
          Pre => First >= Data'First
            and then First < Stream_Element_Offset'Last
            and then First + 1 <= Data'Last
   is
   begin
      return
        Word16 (Data (First))
        or Shift_Left (Word16 (Data (First + 1)), 8);
   end RC2_Load16;

   procedure RC2_Store16
     (Value : Word16; Data : in out Stream_Element_Array;
      First : Stream_Element_Offset)
     with SPARK_Mode => On,
          Pre => First >= Data'First
            and then First < Stream_Element_Offset'Last
            and then First + 1 <= Data'Last
   is
   begin
      Data (First) := Stream_Element (Value and 16#FF#);
      Data (First + 1) :=
        Stream_Element (Shift_Right (Value, 8) and 16#FF#);
   end RC2_Store16;

   function RC2_Make_Key
     (Key_Data : Stream_Element_Array; Effective_Bits : Positive)
      return RC2_Key_Schedule
   is
      L_Data : array (Natural range 0 .. 127) of Byte := [others => 0];
      T      : constant Natural := Key_Data'Length;
      T8     : constant Natural := (Effective_Bits + 7) / 8;
      Shift  : constant Natural := 8 + Effective_Bits - 8 * T8;
      TM     : constant Byte := Byte (Shift_Left (Word16'(1), Shift) - 1);
      Result : RC2_Key_Schedule := [others => 0];
   begin
      if T = 0 or else T > 128 or else Effective_Bits > 1_024 then
         return Result;
      end if;
      for Index_Value in 0 .. T - 1 loop
         L_Data (Index_Value) :=
           Byte (Key_Data (Key_Data'First + Stream_Element_Offset (Index_Value)));
      end loop;
      for Index_Value in T .. 127 loop
         L_Data (Index_Value) :=
           RC2_Pitable
             (Natural (L_Data (Index_Value - 1) + L_Data (Index_Value - T)));
      end loop;
      L_Data (128 - T8) :=
        RC2_Pitable (Natural (L_Data (128 - T8) and TM));
      for Index_Value in reverse 0 .. 127 - T8 loop
         L_Data (Index_Value) :=
           RC2_Pitable
             (Natural (L_Data (Index_Value + 1) xor L_Data (Index_Value + T8)));
      end loop;
      for Index_Value in Result'Range loop
         Result (Index_Value) :=
           Word16 (L_Data (2 * Index_Value))
           or Shift_Left (Word16 (L_Data (2 * Index_Value + 1)), 8);
      end loop;
      return Result;
   exception
      when others =>
         return [others => 0];
   end RC2_Make_Key;

   function RC2_Decrypt_Block
     (Block_Value : Stream_Element_Array; Key_Value : RC2_Key_Schedule)
      return Stream_Element_Array
   is
      Result : Stream_Element_Array (1 .. 8) := [others => 0];
      R0     : Word16 := RC2_Load16 (Block_Value, Block_Value'First);
      R1     : Word16 := RC2_Load16 (Block_Value, Block_Value'First + 2);
      R2     : Word16 := RC2_Load16 (Block_Value, Block_Value'First + 4);
      R3     : Word16 := RC2_Load16 (Block_Value, Block_Value'First + 6);
      J      : Integer := 63;
   begin
      for Round_Value in reverse 0 .. 15 loop
         if Round_Value = 10 or else Round_Value = 4 then
            R3 := R3 - Key_Value (Natural (R2 and 16#3F#));
            R2 := R2 - Key_Value (Natural (R1 and 16#3F#));
            R1 := R1 - Key_Value (Natural (R0 and 16#3F#));
            R0 := R0 - Key_Value (Natural (R3 and 16#3F#));
         end if;

         R3 := RC2_Ror16 (R3, 5) - ((R0 and not R2) + (R1 and R2) + Key_Value (J));
         J := J - 1;
         R2 := RC2_Ror16 (R2, 3) - ((R3 and not R1) + (R0 and R1) + Key_Value (J));
         J := J - 1;
         R1 := RC2_Ror16 (R1, 2) - ((R2 and not R0) + (R3 and R0) + Key_Value (J));
         J := J - 1;
         R0 := RC2_Ror16 (R0, 1) - ((R1 and not R3) + (R2 and R3) + Key_Value (J));
         J := J - 1;
      end loop;

      RC2_Store16 (R0, Result, 1);
      RC2_Store16 (R1, Result, 3);
      RC2_Store16 (R2, Result, 5);
      RC2_Store16 (R3, Result, 7);
      return Result;
   end RC2_Decrypt_Block;

   function Decrypt_CBC_Raw
     (Algorithm_Name : String;
      Key_Data       : Stream_Element_Array;
      IV_Data        : Stream_Element_Array;
      Ciphertext     : Stream_Element_Array;
      Plaintext      : out Stream_Element_Array) return CryptoLib.Errors.Status
   is
      State_Item      : Cipher_State;
      Key_Bits        : Natural;
      Status_Value    : CryptoLib.Errors.Status;
      Previous_Block  : Counter_Block := [others => 0];
      Input_Block     : Counter_Block := [others => 0];
      Decrypted_Block : Counter_Block := [others => 0];
      Input_Index     : Stream_Element_Offset := Ciphertext'First;
      Output_Index    : Stream_Element_Offset := Plaintext'First;
   begin
      Plaintext := [others => 0];
      if Plaintext'Length /= Ciphertext'Length or else Ciphertext'Length = 0
      then
         return CryptoLib.Errors.Authentication_Failed;
      end if;

      if Algorithm_Name = "des-cbc" or else Algorithm_Name = "3des-cbc" then
         declare
            Previous_Block : Word64 := 0;
            Input_Block    : Word64;
            Decrypted      : Word64;
            Output_Block   : Word64;
         begin
            if IV_Data'Length < 8
              or else Ciphertext'Length mod 8 /= 0
              or else (Algorithm_Name = "des-cbc" and then Key_Data'Length < 8)
              or else
                (Algorithm_Name = "3des-cbc" and then Key_Data'Length < 24)
            then
               return CryptoLib.Errors.Authentication_Failed;
            end if;
            Previous_Block := DES_Load64 (IV_Data, IV_Data'First);

            while Input_Index <= Ciphertext'Last loop
               Input_Block := DES_Load64 (Ciphertext, Input_Index);
               if Algorithm_Name = "des-cbc" then
                  declare
                     K1 : constant DES_Subkeys :=
                       DES_Make_Subkeys (Key_Data, Key_Data'First);
                  begin
                     Decrypted := DES_Decrypt_Block (Input_Block, K1);
                  end;
               else
                  Decrypted := DES3_Decrypt_EDE_Block (Input_Block, Key_Data);
               end if;
               Output_Block := Decrypted xor Previous_Block;
               DES_Store64 (Output_Block, Plaintext, Output_Index);
               Previous_Block := Input_Block;
               Input_Index := Input_Index + 8;
               Output_Index := Output_Index + 8;
            end loop;
            return CryptoLib.Errors.Ok;
         end;
      elsif Algorithm_Name = "rc2-40-cbc"
        or else Algorithm_Name = "rc2-64-cbc"
        or else Algorithm_Name = "rc2-128-cbc"
      then
         declare
            Previous_Block : Stream_Element_Array (1 .. 8) := [others => 0];
            Input_Block    : Stream_Element_Array (1 .. 8) := [others => 0];
            Decrypted      : Stream_Element_Array (1 .. 8) := [others => 0];
            Effective_Bits : constant Positive :=
              (if Algorithm_Name = "rc2-40-cbc" then 40
               elsif Algorithm_Name = "rc2-64-cbc" then 64
               else 128);
            Required_Key_Length : constant Natural := Effective_Bits / 8;
            Key_Value      : constant RC2_Key_Schedule :=
              RC2_Make_Key (Key_Data, Effective_Bits);
         begin
            if IV_Data'Length < 8
              or else Key_Data'Length < Required_Key_Length
              or else Ciphertext'Length mod 8 /= 0
            then
               return CryptoLib.Errors.Authentication_Failed;
            end if;
            Previous_Block := IV_Data (IV_Data'First .. IV_Data'First + 7);

            while Input_Index <= Ciphertext'Last loop
               Input_Block :=
                 Ciphertext (Input_Index .. Input_Index + 7);
               Decrypted := RC2_Decrypt_Block (Input_Block, Key_Value);
               for Offset_Value in 0 .. 7 loop
                  Plaintext (Output_Index + Stream_Element_Offset (Offset_Value)) :=
                    Decrypted (Decrypted'First + Stream_Element_Offset (Offset_Value))
                    xor Previous_Block
                      (Previous_Block'First + Stream_Element_Offset (Offset_Value));
               end loop;
               Previous_Block := Input_Block;
               Input_Index := Input_Index + 8;
               Output_Index := Output_Index + 8;
            end loop;
            return CryptoLib.Errors.Ok;
         end;
      elsif Algorithm_Name = "aes128-cbc" then
         Key_Bits := 128;
      elsif Algorithm_Name = "aes192-cbc" then
         Key_Bits := 192;
      elsif Algorithm_Name = "aes256-cbc" then
         Key_Bits := 256;
      else
         return CryptoLib.Errors.Unsupported_Feature;
      end if;

      Status_Value := Expand_Key (State_Item, Key_Data, Key_Bits);
      if Status_Value /= CryptoLib.Errors.Ok then
         Reset (State_Item);
         return Status_Value;
      end if;

      for Offset_Value in 0 .. 15 loop
         Previous_Block (Offset_Value) :=
           To_Byte
             (IV_Data (IV_Data'First + Stream_Element_Offset (Offset_Value)));
      end loop;

      while Input_Index <= Ciphertext'Last loop
         for Offset_Value in 0 .. 15 loop
            Input_Block (Offset_Value) :=
              To_Byte
                (Ciphertext
                   (Input_Index + Stream_Element_Offset (Offset_Value)));
         end loop;
         Decrypt_Block (State_Item, Input_Block, Decrypted_Block);
         for Offset_Value in 0 .. 15 loop
            Plaintext (Output_Index + Stream_Element_Offset (Offset_Value)) :=
              To_Element
                (Decrypted_Block (Offset_Value)
                 xor Previous_Block (Offset_Value));
         end loop;
         Previous_Block := Input_Block;
         Input_Index := Input_Index + 16;
         Output_Index := Output_Index + 16;
      end loop;

      Reset (State_Item);
      Input_Block := [others => 0];
      Decrypted_Block := [others => 0];
      Previous_Block := [others => 0];
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Reset (State_Item);
         Plaintext := [others => 0];
      return CryptoLib.Errors.Internal_Error;
   end Decrypt_CBC_Raw;

   function Encrypt_CBC_Raw
     (Algorithm_Name : String;
      Key_Data       : Stream_Element_Array;
      IV_Data        : Stream_Element_Array;
      Plaintext      : Stream_Element_Array;
      Ciphertext     : out Stream_Element_Array) return CryptoLib.Errors.Status
   is
      State_Item   : Cipher_State;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Ciphertext := [others => 0];
      if Ciphertext'Length /= Plaintext'Length or else Plaintext'Length = 0 then
         return CryptoLib.Errors.Authentication_Failed;
      end if;

      Status_Value :=
        Initialize
          (State_Item, Algorithm_Name, Client_To_Server, Key_Data, IV_Data);
      if Status_Value /= CryptoLib.Errors.Ok then
         Reset (State_Item);
         return Status_Value;
      end if;

      Status_Value := Encrypt (State_Item, Plaintext, Ciphertext);
      Reset (State_Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         Ciphertext := [others => 0];
      end if;
      return Status_Value;
   exception
      when others =>
         Reset (State_Item);
         Ciphertext := [others => 0];
         return CryptoLib.Errors.Internal_Error;
   end Encrypt_CBC_Raw;

   procedure Increment_ZIP_AES_Counter (Counter : in out Counter_Block)
     with SPARK_Mode => On
   is
   begin
      for Index_Value in Counter'Range loop
         Counter (Index_Value) := Counter (Index_Value) + 1;
         exit when Counter (Index_Value) /= 0;
      end loop;
   end Increment_ZIP_AES_Counter;

   function Apply_ZIP_AES_CTR
     (Algorithm_Name : String;
      Key_Data       : Stream_Element_Array;
      Input_Data     : Stream_Element_Array;
      Output_Data    : out Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      State_Item   : Cipher_State;
      Key_Bits     : Natural;
      Status_Value : CryptoLib.Errors.Status;
      Counter      : Counter_Block := [others => 0];
      Key_Stream   : Counter_Block;
      Input_Index  : Stream_Element_Offset := Input_Data'First;
      Output_Index : Stream_Element_Offset := Output_Data'First;
      Stream_Index : Natural := 16;
   begin
      Output_Data := [others => 0];
      if Output_Data'Length /= Input_Data'Length then
         return CryptoLib.Errors.Internal_Error;
      end if;

      if Algorithm_Name = "aes128" or else Algorithm_Name = "aes128-ctr" then
         Key_Bits := 128;
      elsif Algorithm_Name = "aes192" or else Algorithm_Name = "aes192-ctr" then
         Key_Bits := 192;
      elsif Algorithm_Name = "aes256" or else Algorithm_Name = "aes256-ctr" then
         Key_Bits := 256;
      else
         return CryptoLib.Errors.Unsupported_Feature;
      end if;

      Status_Value := Expand_Key (State_Item, Key_Data, Key_Bits);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Counter (0) := 1;
      while Input_Index <= Input_Data'Last loop
         if Stream_Index = 16 then
            Encrypt_Block (State_Item, Counter, Key_Stream);
            Increment_ZIP_AES_Counter (Counter);
            Stream_Index := 0;
         end if;
         Output_Data (Output_Index) :=
           To_Element (To_Byte (Input_Data (Input_Index)) xor Key_Stream (Stream_Index));
         Stream_Index := Stream_Index + 1;
         Input_Index := Input_Index + 1;
         Output_Index := Output_Index + 1;
      end loop;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Output_Data := [others => 0];
         return CryptoLib.Errors.Internal_Error;
   end Apply_ZIP_AES_CTR;

   function AES_GCM_Key_Length (Algorithm_Name : String) return Natural
     with SPARK_Mode => On
   is
   begin
      if Algorithm_Name = "aes128-gcm@openssh.com" then
         return 16;
      elsif Algorithm_Name = "aes256-gcm@openssh.com" then
         return 32;
      end if;
      return 0;
   end AES_GCM_Key_Length;

   function AES_GCM_Key_Bits (Algorithm_Name : String) return Natural
     with SPARK_Mode => On
   is
   begin
      if Algorithm_Name = "aes128-gcm@openssh.com" then
         return 128;
      elsif Algorithm_Name = "aes256-gcm@openssh.com" then
         return 256;
      end if;
      return 0;
   end AES_GCM_Key_Bits;

   procedure Store_BE32
     (Value : Unsigned_32; Data : in out Counter_Block; First : Natural)
     with SPARK_Mode => On,
          Pre => First <= 12
   is
   begin
      Data (First) := Byte (Shift_Right (Value, 24) and 16#FF#);
      Data (First + 1) := Byte (Shift_Right (Value, 16) and 16#FF#);
      Data (First + 2) := Byte (Shift_Right (Value, 8) and 16#FF#);
      Data (First + 3) := Byte (Value and 16#FF#);
   end Store_BE32;

   procedure Store_BE64
     (Value : Unsigned_64; Data : in out Counter_Block; First : Natural)
     with SPARK_Mode => On,
          Pre => First <= 8
   is
   begin
      Data (First) := Byte (Shift_Right (Value, 56) and 16#FF#);
      Data (First + 1) := Byte (Shift_Right (Value, 48) and 16#FF#);
      Data (First + 2) := Byte (Shift_Right (Value, 40) and 16#FF#);
      Data (First + 3) := Byte (Shift_Right (Value, 32) and 16#FF#);
      Data (First + 4) := Byte (Shift_Right (Value, 24) and 16#FF#);
      Data (First + 5) := Byte (Shift_Right (Value, 16) and 16#FF#);
      Data (First + 6) := Byte (Shift_Right (Value, 8) and 16#FF#);
      Data (First + 7) := Byte (Value and 16#FF#);
   end Store_BE64;

   procedure Increment_GCM_Counter (Block_Item : in out Counter_Block)
     with SPARK_Mode => On
   is
      Value : Unsigned_32 :=
        Shift_Left (Unsigned_32 (Block_Item (12)), 24)
        or Shift_Left (Unsigned_32 (Block_Item (13)), 16)
        or Shift_Left (Unsigned_32 (Block_Item (14)), 8)
        or Unsigned_32 (Block_Item (15));
   begin
      Value := Value + 1;
      Store_BE32 (Value, Block_Item, 12);
   end Increment_GCM_Counter;

   function Make_GCM_J0 (IV_Data : Stream_Element_Array) return Counter_Block
     with SPARK_Mode => On,
          Pre => IV_Data'Length >= 12
   is
      Result : Counter_Block := [others => 0];
   begin
      --  RFC 5647 aes-gcm@openssh.com uses the 12-octet IV directly as the GCM
      --  nonce (4-octet fixed field + 8-octet invocation counter). Per-packet
      --  IV uniqueness is provided by the caller incrementing the invocation
      --  counter each packet, not by mixing in the SSH sequence number. For a
      --  96-bit IV the pre-counter block J0 is IV || 0x0000_0001.
      for Index_Value in 0 .. 11 loop
         Result (Index_Value) :=
           To_Byte
             (IV_Data (IV_Data'First + Stream_Element_Offset (Index_Value)));
      end loop;
      Result (12) := 0;
      Result (13) := 0;
      Result (14) := 0;
      Result (15) := 1;
      return Result;
   end Make_GCM_J0;

   procedure GCM_Xor_Block
     (Target : in out Counter_Block; Source : Counter_Block)
     with SPARK_Mode => On
   is
   begin
      for Index_Value in Target'Range loop
         Target (Index_Value) := Target (Index_Value) xor Source (Index_Value);
      end loop;
   end GCM_Xor_Block;

   procedure Shift_Right_One (Value : in out Counter_Block)
     with SPARK_Mode => On
   is
      Carry_In  : Byte := 0;
      Carry_Out : Byte;
   begin
      for Index_Value in Value'Range loop
         Carry_Out := Value (Index_Value) and 1;
         Value (Index_Value) :=
           Shift_Right (Value (Index_Value), 1) or Shift_Left (Carry_In, 7);
         Carry_In := Carry_Out;
      end loop;
   end Shift_Right_One;

   procedure Shift_Left_One (Value : in out Counter_Block)
     with SPARK_Mode => On
   is
      Carry_In  : Byte := 0;
      Carry_Out : Byte;
   begin
      for Index_Value in reverse Value'Range loop
         Carry_Out := Shift_Right (Value (Index_Value), 7) and 1;
         Value (Index_Value) :=
           Shift_Left (Value (Index_Value), 1) or Carry_In;
         Carry_In := Carry_Out;
      end loop;
   end Shift_Left_One;

   function GHASH_Multiply
     (Left_Value : Counter_Block; Right_Value : Counter_Block)
      return Counter_Block
   is
      Z_Value : Counter_Block := [others => 0];
      V_Value : Counter_Block := Right_Value;
      X_Value : Counter_Block := Left_Value;
      X_Mask  : Byte;
      R_Mask  : Byte;
   begin
      --  Constant-time: no data-dependent branches.  GHASH runs on the secret
      --  authentication subkey H, so branch timing would leak it (GCM forgery).
      --  Process X most-significant bit first; masks replace the conditionals.
      for Bit_Index in 0 .. 127 loop
         --  Add V to Z iff the top bit of X is set.
         X_Mask := Byte (0) - Shift_Right (X_Value (0), 7);
         for Index_Value in Z_Value'Range loop
            Z_Value (Index_Value) :=
              Z_Value (Index_Value) xor (V_Value (Index_Value) and X_Mask);
         end loop;
         --  GF(2**128) reduction: fold 0xE1 into V(0) iff the bit shifted out
         --  of V was set.
         R_Mask := Byte (0) - (V_Value (15) and 1);
         Shift_Right_One (V_Value);
         V_Value (0) := V_Value (0) xor (16#E1# and R_Mask);
         Shift_Left_One (X_Value);
      end loop;
      return Z_Value;
   end GHASH_Multiply;

   procedure GHASH_Update
     (Y_Value     : in out Counter_Block;
      H_Value     : Counter_Block;
      Block_Value : Counter_Block) is
   begin
      GCM_Xor_Block (Y_Value, Block_Value);
      Y_Value := GHASH_Multiply (Y_Value, H_Value);
   end GHASH_Update;

   function GHASH_Value
     (H_Value    : Counter_Block;
      AAD_Data   : Stream_Element_Array;
      Ciphertext : Stream_Element_Array) return Counter_Block
   is
      Y_Value     : Counter_Block := [others => 0];
      Block_Value : Counter_Block := [others => 0];
      Pos         : Stream_Element_Offset;
      AAD_Bits    : constant Unsigned_64 := Unsigned_64 (AAD_Data'Length) * 8;
      Cipher_Bits : constant Unsigned_64 :=
        Unsigned_64 (Ciphertext'Length) * 8;
   begin
      Pos := AAD_Data'First;
      while Pos <= AAD_Data'Last loop
         Block_Value := [others => 0];
         for Offset_Value in 0 .. 15 loop
            exit when Pos > AAD_Data'Last;
            Block_Value (Offset_Value) := To_Byte (AAD_Data (Pos));
            Pos := Pos + 1;
         end loop;
         GHASH_Update (Y_Value, H_Value, Block_Value);
      end loop;

      Pos := Ciphertext'First;
      while Pos <= Ciphertext'Last loop
         Block_Value := [others => 0];
         for Offset_Value in 0 .. 15 loop
            exit when Pos > Ciphertext'Last;
            Block_Value (Offset_Value) := To_Byte (Ciphertext (Pos));
            Pos := Pos + 1;
         end loop;
         GHASH_Update (Y_Value, H_Value, Block_Value);
      end loop;

      Block_Value := [others => 0];
      Store_BE64 (AAD_Bits, Block_Value, 0);
      Store_BE64 (Cipher_Bits, Block_Value, 8);
      GHASH_Update (Y_Value, H_Value, Block_Value);
      return Y_Value;
   end GHASH_Value;

   function Apply_GCM_CTR
     (State_Item : Cipher_State;
      J0_Value   : Counter_Block;
      Input_Data : Stream_Element_Array;
      Output     : out Stream_Element_Array) return CryptoLib.Errors.Status
   is
      Counter_Value : Counter_Block := J0_Value;
      Key_Stream    : Counter_Block;
      Input_Index   : Stream_Element_Offset := Input_Data'First;
      Output_Index  : Stream_Element_Offset := Output'First;
   begin
      if Output'Length /= Input_Data'Length then
         Output := [others => 0];
         return CryptoLib.Errors.Internal_Error;
      end if;
      Increment_GCM_Counter (Counter_Value);
      while Input_Index <= Input_Data'Last loop
         Encrypt_Block (State_Item, Counter_Value, Key_Stream);
         Increment_GCM_Counter (Counter_Value);
         for Offset_Value in Key_Stream'Range loop
            exit when Input_Index > Input_Data'Last;
            Output (Output_Index) :=
              To_Element
                (To_Byte (Input_Data (Input_Index))
                 xor Key_Stream (Offset_Value));
            Input_Index := Input_Index + 1;
            Output_Index := Output_Index + 1;
         end loop;
      end loop;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Output := [others => 0];
         return CryptoLib.Errors.Internal_Error;
   end Apply_GCM_CTR;

   function GCM_Tag
     (State_Item : Cipher_State;
      J0_Value   : Counter_Block;
      AAD_Data   : Stream_Element_Array;
      Ciphertext : Stream_Element_Array) return Stream_Element_Array
   is
      Zero_Block : constant Counter_Block := [others => 0];
      H_Value    : Counter_Block;
      S_Value    : Counter_Block;
      E0_Value   : Counter_Block;
   begin
      Encrypt_Block (State_Item, Zero_Block, H_Value);
      S_Value := GHASH_Value (H_Value, AAD_Data, Ciphertext);
      Encrypt_Block (State_Item, J0_Value, E0_Value);
      GCM_Xor_Block (S_Value, E0_Value);
      return
         Result :
           Stream_Element_Array
             (1 .. Stream_Element_Offset (AES_GCM_Tag_Length))
      do
         for Index_Value in 0 .. AES_GCM_Tag_Length - 1 loop
            Result (Stream_Element_Offset (Index_Value + 1)) :=
              To_Element (S_Value (Index_Value));
         end loop;
      end return;
   end GCM_Tag;

   function Initialize_GCM_State
     (State_Item     : in out Cipher_State;
      Algorithm_Name : String;
      Key_Data       : Stream_Element_Array) return CryptoLib.Errors.Status
   is
      Key_Bits     : constant Natural := AES_GCM_Key_Bits (Algorithm_Name);
      Status_Value : CryptoLib.Errors.Status;
   begin
      Reset (State_Item);
      if Key_Bits = 0 then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      Status_Value := Expand_Key (State_Item, Key_Data, Key_Bits);
      if Status_Value /= CryptoLib.Errors.Ok then
         Reset (State_Item);
         return Status_Value;
      end if;
      State_Item.Active_Item := True;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Reset (State_Item);
         return CryptoLib.Errors.Internal_Error;
   end Initialize_GCM_State;

   function Encrypt_GCM_Length
     (Algorithm_Name : String;
      Key_Data       : Stream_Element_Array;
      IV_Data        : Stream_Element_Array;
      Sequence       : Unsigned_32;
      Header         : Stream_Element_Array;
      Output         : out Stream_Element_Array) return CryptoLib.Errors.Status
   is
      pragma Unreferenced (Algorithm_Name, Key_Data, IV_Data, Sequence);
   begin
      --  For aes-gcm@openssh.com (RFC 5647) the 4-octet packet-length field is
      --  transmitted in the clear (it is the GCM AAD), so recovering the length
      --  from the wire is the identity transform. Kept as a seam so the callers
      --  can treat every AEAD cipher uniformly.
      Output := [others => 0];
      if Header'Length /= 4 or else Output'Length /= 4 then
         return CryptoLib.Errors.Handshake_Failed;
      end if;
      Output := Header;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Output := [others => 0];
         return CryptoLib.Errors.Internal_Error;
   end Encrypt_GCM_Length;

   function Seal_GCM
     (Algorithm_Name : String;
      Key_Data       : Stream_Element_Array;
      IV_Data        : Stream_Element_Array;
      Sequence       : Unsigned_32;
      Plain_Packet   : Stream_Element_Array;
      Wire_Packet    : out Stream_Element_Array) return CryptoLib.Errors.Status
   is
      pragma Unreferenced (Sequence);
      State_Item   : Cipher_State;
      J0_Value     : Counter_Block;
      Status_Value : CryptoLib.Errors.Status;
   begin
      --  aes-gcm@openssh.com wire = [4-octet length (cleartext, AAD)]
      --  [GCM ciphertext of the body] [16-octet tag]. Only the body
      --  (padding-length || payload || padding) is encrypted; the length is
      --  authenticated in the clear as GCM additional data.
      Wire_Packet := [others => 0];
      if Wire_Packet'Length /= Plain_Packet'Length + AES_GCM_Tag_Length
        or else Plain_Packet'Length < 4
        or else IV_Data'Length < 12
      then
         return CryptoLib.Errors.Internal_Error;
      end if;
      Status_Value :=
        Initialize_GCM_State (State_Item, Algorithm_Name, Key_Data);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      J0_Value := Make_GCM_J0 (IV_Data);
      declare
         Length_Field : constant Stream_Element_Array :=
           Plain_Packet (Plain_Packet'First .. Plain_Packet'First + 3);
         Body_Plain   : constant Stream_Element_Array :=
           Plain_Packet (Plain_Packet'First + 4 .. Plain_Packet'Last);
         Body_Cipher  : Stream_Element_Array (Body_Plain'Range);
         Tag_First    : constant Stream_Element_Offset :=
           Wire_Packet'First + 4 + Stream_Element_Offset (Body_Plain'Length);
      begin
         Status_Value :=
           Apply_GCM_CTR (State_Item, J0_Value, Body_Plain, Body_Cipher);
         if Status_Value /= CryptoLib.Errors.Ok then
            Reset (State_Item);
            return Status_Value;
         end if;
         Wire_Packet (Wire_Packet'First .. Wire_Packet'First + 3) :=
           Length_Field;
         Wire_Packet
           (Wire_Packet'First + 4 .. Tag_First - 1) := Body_Cipher;
         Wire_Packet (Tag_First .. Wire_Packet'Last) :=
           GCM_Tag (State_Item, J0_Value, Length_Field, Body_Cipher);
      end;
      Reset (State_Item);
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Reset (State_Item);
         Wire_Packet := [others => 0];
         return CryptoLib.Errors.Internal_Error;
   end Seal_GCM;

   function Open_GCM
     (Algorithm_Name : String;
      Key_Data       : Stream_Element_Array;
      IV_Data        : Stream_Element_Array;
      Sequence       : Unsigned_32;
      Wire_Packet    : Stream_Element_Array;
      Plain_Packet   : out Stream_Element_Array) return CryptoLib.Errors.Status
   is
      pragma Unreferenced (Sequence);
      State_Item   : Cipher_State;
      J0_Value     : Counter_Block;
      Cipher_Last  : constant Stream_Element_Offset :=
        Wire_Packet'Last - Stream_Element_Offset (AES_GCM_Tag_Length);
      Status_Value : CryptoLib.Errors.Status;
   begin
      --  Inverse of Seal_GCM: the leading 4 octets are the cleartext length
      --  (GCM AAD); the body between it and the trailing 16-octet tag is the
      --  ciphertext. Verify the tag over (length, ciphertext) before decrypting.
      Plain_Packet := [others => 0];
      if Wire_Packet'Length < AES_GCM_Tag_Length + 4
        or else Plain_Packet'Length /= Wire_Packet'Length - AES_GCM_Tag_Length
        or else IV_Data'Length < 12
      then
         return CryptoLib.Errors.Handshake_Failed;
      end if;
      Status_Value :=
        Initialize_GCM_State (State_Item, Algorithm_Name, Key_Data);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      J0_Value := Make_GCM_J0 (IV_Data);
      declare
         Length_Field : constant Stream_Element_Array :=
           Wire_Packet (Wire_Packet'First .. Wire_Packet'First + 3);
         Body_Cipher  : constant Stream_Element_Array :=
           Wire_Packet (Wire_Packet'First + 4 .. Cipher_Last);
         Actual_Tag   : constant Stream_Element_Array :=
           Wire_Packet (Cipher_Last + 1 .. Wire_Packet'Last);
         Wanted_Tag   : constant Stream_Element_Array :=
           GCM_Tag (State_Item, J0_Value, Length_Field, Body_Cipher);
         Body_Plain   : Stream_Element_Array (Body_Cipher'Range);
      begin
         if not CryptoLib.Constant_Time.Equal (Actual_Tag, Wanted_Tag) then
            Reset (State_Item);
            return CryptoLib.Errors.Handshake_Failed;
         end if;
         Status_Value :=
           Apply_GCM_CTR (State_Item, J0_Value, Body_Cipher, Body_Plain);
         if Status_Value = CryptoLib.Errors.Ok then
            Plain_Packet (Plain_Packet'First .. Plain_Packet'First + 3) :=
              Length_Field;
            Plain_Packet (Plain_Packet'First + 4 .. Plain_Packet'Last) :=
              Body_Plain;
         end if;
      end;
      Reset (State_Item);
      return Status_Value;
   exception
      when others =>
         Reset (State_Item);
         Plain_Packet := [others => 0];
         return CryptoLib.Errors.Internal_Error;
   end Open_GCM;

end CryptoLib.Ciphers;
