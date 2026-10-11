with Ada.Unchecked_Conversion;
with System.Machine_Code;

--  The SHA extensions, through the compiler's builtins; this body is
--  compiled with -msha, and called only once CPUID says the processor has
--  them. The two state registers are built from the eight words directly
--  -- A, B, E, F in one, C, D, G, H in the other, the first named highest
--  -- so no shuffle is needed either way.
package body CryptoLib.Hashes.Hardware
  with SPARK_Mode => Off
is

   use Interfaces;

   type V4SI is array (1 .. 4) of Integer_32
     with Alignment => 16;
   pragma Machine_Attribute (V4SI, "vector_type");

   --  The same four lanes as words, the lowest first.
   type Lanes is array (0 .. 3) of Unsigned_32
     with Alignment => 16;

   function To_Vector is new Ada.Unchecked_Conversion (Lanes, V4SI);
   function To_Lanes is new Ada.Unchecked_Conversion (V4SI, Lanes);

   function Rounds_2 (State_CDGH, State_ABEF, Message : V4SI) return V4SI
     with Import, Convention => Intrinsic, External_Name => "__builtin_ia32_sha256rnds2";
   function Message_1 (Earlier, Later : V4SI) return V4SI
     with Import, Convention => Intrinsic, External_Name => "__builtin_ia32_sha256msg1";
   function Message_2 (Partial, Last : V4SI) return V4SI
     with Import, Convention => Intrinsic, External_Name => "__builtin_ia32_sha256msg2";

   K : constant array (0 .. 63) of Unsigned_32 :=
     [16#428A2F98#, 16#71374491#, 16#B5C0FBCF#, 16#E9B5DBA5#, 16#3956C25B#, 16#59F111F1#, 16#923F82A4#, 16#AB1C5ED5#,
      16#D807AA98#, 16#12835B01#, 16#243185BE#, 16#550C7DC3#, 16#72BE5D74#, 16#80DEB1FE#, 16#9BDC06A7#, 16#C19BF174#,
      16#E49B69C1#, 16#EFBE4786#, 16#0FC19DC6#, 16#240CA1CC#, 16#2DE92C6F#, 16#4A7484AA#, 16#5CB0A9DC#, 16#76F988DA#,
      16#983E5152#, 16#A831C66D#, 16#B00327C8#, 16#BF597FC7#, 16#C6E00BF3#, 16#D5A79147#, 16#06CA6351#, 16#14292967#,
      16#27B70A85#, 16#2E1B2138#, 16#4D2C6DFC#, 16#53380D13#, 16#650A7354#, 16#766A0ABB#, 16#81C2C92E#, 16#92722C85#,
      16#A2BFE8A1#, 16#A81A664B#, 16#C24B8B70#, 16#C76C51A3#, 16#D192E819#, 16#D6990624#, 16#F40E3585#, 16#106AA070#,
      16#19A4C116#, 16#1E376C08#, 16#2748774C#, 16#34B0BCB5#, 16#391C0CB3#, 16#4ED8AA4A#, 16#5B9CCA4F#, 16#682E6FF3#,
      16#748F82EE#, 16#78A5636F#, 16#84C87814#, 16#8CC70208#, 16#90BEFFFA#, 16#A4506CEB#, 16#BEF9A3F7#, 16#C67178F2#];

   --  CPUID leaf 7, subleaf 0: EBX bit 29 is the SHA extensions.
   function Asked return Boolean is
      A, B, C, D : Unsigned_32;
   begin
      System.Machine_Code.Asm
        ("cpuid",
         Outputs  => [Unsigned_32'Asm_Output ("=a", A), Unsigned_32'Asm_Output ("=b", B),
                      Unsigned_32'Asm_Output ("=c", C), Unsigned_32'Asm_Output ("=d", D)],
         Inputs   => [Unsigned_32'Asm_Input ("a", 0), Unsigned_32'Asm_Input ("c", 0)],
         Volatile => True);
      if A < 7 then
         return False;
      end if;
      System.Machine_Code.Asm
        ("cpuid",
         Outputs  => [Unsigned_32'Asm_Output ("=a", A), Unsigned_32'Asm_Output ("=b", B),
                      Unsigned_32'Asm_Output ("=c", C), Unsigned_32'Asm_Output ("=d", D)],
         Inputs   => [Unsigned_32'Asm_Input ("a", 7), Unsigned_32'Asm_Input ("c", 0)],
         Volatile => True);
      return (Shift_Right (B, 29) and 1) = 1;
   end Asked;

   --  Asked on first use and kept: unknown, there, not there. Asking twice
   --  at once gives the same answer twice.
   type Answer is (Unknown, Present, Absent);
   Known : Answer := Unknown
     with Atomic;

   function Available return Boolean is
   begin
      if Known = Unknown then
         Known := (if Asked then Present else Absent);
      end if;
      return Known = Present;
   end Available;

   function Plus (Left, Right : Lanes) return Lanes is
     [Left (0) + Right (0), Left (1) + Right (1), Left (2) + Right (2), Left (3) + Right (3)];

   procedure Compress (State : in out SHA256_State; Block : SHA256_Block) is
      --  The message, four words a group, each word read high byte first.
      W        : array (0 .. 15) of Lanes;
      ABEF     : V4SI := To_Vector ([State (5), State (4), State (1), State (0)]);
      CDGH     : V4SI := To_Vector ([State (7), State (6), State (3), State (2)]);
      ABEF_Was : constant V4SI := ABEF;
      CDGH_Was : constant V4SI := CDGH;
   begin
      for Group in 0 .. 3 loop
         for Lane in 0 .. 3 loop
            declare
               At_Byte : constant Natural := Group * 16 + Lane * 4;
            begin
               W (Group) (Lane) :=
                 Shift_Left (Unsigned_32 (Block (At_Byte)), 24) or Shift_Left (Unsigned_32 (Block (At_Byte + 1)), 16)
                 or Shift_Left (Unsigned_32 (Block (At_Byte + 2)), 8) or Unsigned_32 (Block (At_Byte + 3));
            end;
         end loop;
      end loop;
      for Group in 0 .. 15 loop
         if Group >= 4 then
            --  W[t-16] + s0 (W[t-15]), plus W[t-7], then s1 of the last two.
            declare
               Before : constant Lanes := W (Group - 1);
               Two    : constant Lanes := W (Group - 2);
               Seven  : constant Lanes := [Two (1), Two (2), Two (3), Before (0)];
            begin
               W (Group) := To_Lanes
                 (Message_2
                    (To_Vector (Plus (To_Lanes (Message_1 (To_Vector (W (Group - 4)), To_Vector (W (Group - 3)))),
                                      Seven)),
                     To_Vector (Before)));
            end;
         end if;
         declare
            Message : constant Lanes :=
              Plus (W (Group), [K (Group * 4), K (Group * 4 + 1), K (Group * 4 + 2), K (Group * 4 + 3)]);
         begin
            CDGH := Rounds_2 (CDGH, ABEF, To_Vector (Message));
            ABEF := Rounds_2 (ABEF, CDGH, To_Vector ([Message (2), Message (3), 0, 0]));
         end;
      end loop;
      declare
         Front : constant Lanes := Plus (To_Lanes (ABEF), To_Lanes (ABEF_Was));
         Back  : constant Lanes := Plus (To_Lanes (CDGH), To_Lanes (CDGH_Was));
      begin
         State := [Front (3), Front (2), Back (3), Back (2), Front (1), Front (0), Back (1), Back (0)];
      end;
   end Compress;

end CryptoLib.Hashes.Hardware;
