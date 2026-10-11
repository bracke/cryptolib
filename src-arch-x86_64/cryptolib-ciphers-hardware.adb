with Ada.Unchecked_Conversion;
with System.Machine_Code;

--  AES-NI and PCLMULQDQ, through the compiler's own builtins; this body is
--  compiled with -maes -mpclmul, and called only once CPUID says the
--  processor has both.
package body CryptoLib.Ciphers.Hardware
  with SPARK_Mode => Off
is

   use Interfaces;

   type V2DI is array (1 .. 2) of Integer_64
     with Alignment => 16;
   pragma Machine_Attribute (V2DI, "vector_type");

   --  The same sixteen bytes as two 64-bit words, the low one first.
   type Words is record
      Low, High : Unsigned_64;
   end record
     with Size => 128, Alignment => 16;

   function To_Vector is new Ada.Unchecked_Conversion (Counter_Block, V2DI);
   function To_Block is new Ada.Unchecked_Conversion (V2DI, Counter_Block);
   function As_Words is new Ada.Unchecked_Conversion (Counter_Block, Words);
   function As_Block is new Ada.Unchecked_Conversion (Words, Counter_Block);
   function Vector_Of is new Ada.Unchecked_Conversion (Words, V2DI);
   function Words_Of is new Ada.Unchecked_Conversion (V2DI, Words);

   function Aes_Round (State, Key : V2DI) return V2DI
     with Import, Convention => Intrinsic, External_Name => "__builtin_ia32_aesenc128";
   function Aes_Last_Round (State, Key : V2DI) return V2DI
     with Import, Convention => Intrinsic, External_Name => "__builtin_ia32_aesenclast128";
   function Carryless (Left, Right : V2DI; Which : Integer) return V2DI
     with Import, Convention => Intrinsic, External_Name => "__builtin_ia32_pclmulqdq128";

   function Xor_Of (Left, Right : V2DI) return V2DI is
     (Vector_Of ((Low  => Words_Of (Left).Low xor Words_Of (Right).Low,
                  High => Words_Of (Left).High xor Words_Of (Right).High)));

   --  CPUID leaf 1: ECX bit 25 is AES-NI, bit 1 PCLMULQDQ.
   function Asked return Boolean is
      A, B, C, D : Unsigned_32;
   begin
      System.Machine_Code.Asm
        ("cpuid",
         Outputs  => [Unsigned_32'Asm_Output ("=a", A), Unsigned_32'Asm_Output ("=b", B),
                      Unsigned_32'Asm_Output ("=c", C), Unsigned_32'Asm_Output ("=d", D)],
         Inputs   => [Unsigned_32'Asm_Input ("a", 1), Unsigned_32'Asm_Input ("c", 0)],
         Volatile => True);
      return (Shift_Right (C, 25) and 1) = 1 and then (Shift_Right (C, 1) and 1) = 1;
   end Asked;

   Has_Both : constant Boolean := Asked;

   function Available return Boolean is (Has_Both);

   procedure Encrypt
     (Keys      : Round_Block_Array;
      Rounds    : Natural;
      Block_In  : Counter_Block;
      Block_Out : out Counter_Block)
   is
      State : V2DI := Xor_Of (To_Vector (Block_In), To_Vector (Keys (0)));
   begin
      for Round in 1 .. Rounds - 1 loop
         State := Aes_Round (State, To_Vector (Keys (Round)));
      end loop;
      Block_Out := To_Block (Aes_Last_Round (State, To_Vector (Keys (Rounds))));
   end Encrypt;

   --  GHASH keeps x**0 in the top bit of the first byte. With each byte's
   --  bits reversed and the bytes read low first, x**i is bit i of a
   --  128-bit number, and the product is an ordinary carry-less one,
   --  reduced by x**128 = x**7 + x**2 + x + 1. Reversing the bits of every
   --  byte is the same both ways, and costs no table: no lookup indexed by
   --  the key.
   function Reflected (Value : Unsigned_64) return Unsigned_64 is
      V : Unsigned_64 := Value;
   begin
      V := Shift_Right (V and 16#F0F0_F0F0_F0F0_F0F0#, 4) or Shift_Left (V and 16#0F0F_0F0F_0F0F_0F0F#, 4);
      V := Shift_Right (V and 16#CCCC_CCCC_CCCC_CCCC#, 2) or Shift_Left (V and 16#3333_3333_3333_3333#, 2);
      V := Shift_Right (V and 16#AAAA_AAAA_AAAA_AAAA#, 1) or Shift_Left (V and 16#5555_5555_5555_5555#, 1);
      return V;
   end Reflected;

   function Reflected (Block : Counter_Block) return Words is
      W : constant Words := As_Words (Block);
   begin
      return (Low => Reflected (W.Low), High => Reflected (W.High));
   end Reflected;

   function Multiply (X, H : Counter_Block) return Counter_Block is
      A  : constant V2DI := Vector_Of (Reflected (X));
      B  : constant V2DI := Vector_Of (Reflected (H));
      L  : constant Words := Words_Of (Carryless (A, B, 16#00#));
      M1 : constant Words := Words_Of (Carryless (A, B, 16#01#));
      M2 : constant Words := Words_Of (Carryless (A, B, 16#10#));
      U  : constant Words := Words_Of (Carryless (A, B, 16#11#));
      --  The 255-bit product, four words from the lowest.
      P0 : constant Unsigned_64 := L.Low;
      P1 : constant Unsigned_64 := L.High xor M1.Low xor M2.Low;
      P2 : constant Unsigned_64 := U.Low xor M1.High xor M2.High;
      P3 : constant Unsigned_64 := U.High;

      --  The high half times x**7 + x**2 + x + 1, three words.
      T0 : constant Unsigned_64 :=
        P2 xor Shift_Left (P2, 1) xor Shift_Left (P2, 2) xor Shift_Left (P2, 7);
      T1 : constant Unsigned_64 :=
        P3 xor Shift_Left (P3, 1) xor Shift_Left (P3, 2) xor Shift_Left (P3, 7)
        xor Shift_Right (P2, 63) xor Shift_Right (P2, 62) xor Shift_Right (P2, 57);
      T2 : constant Unsigned_64 :=
        Shift_Right (P3, 63) xor Shift_Right (P3, 62) xor Shift_Right (P3, 57);

      --  What that leaves past x**127, folded once more: a few bits.
      F  : constant Unsigned_64 := T2 xor Shift_Left (T2, 1) xor Shift_Left (T2, 2) xor Shift_Left (T2, 7);
      R  : constant Words := (Low => P0 xor T0 xor F, High => P1 xor T1);
   begin
      return As_Block ((Low => Reflected (R.Low), High => Reflected (R.High)));
   end Multiply;

end CryptoLib.Ciphers.Hardware;
