with Ada.Streams;

--  @summary Constant-time fixed-width Montgomery modular exponentiation for
--  moduli larger than GNAT's big-integer cap.
--
--  Fixed-width modular exponentiation for moduli beyond the reach of GNAT's
--  Ada.Numerics.Big_Numbers.Big_Integers (which caps at ~6400 bits).  Used by
--  the large SSH finite-field Diffie-Hellman groups (group16 = 4096-bit,
--  group18 = 8192-bit), whose square-and-multiply intermediates exceed that
--  cap.  Implemented with word-serial Montgomery multiplication.
package CryptoLib.Modexp is

   --  Returns Base**Exponent mod Modulus.  All operands are unsigned
   --  big-endian byte strings; the result is big-endian with the same length
   --  as Modulus.  Modulus must be odd and nonzero (true for every SSH MODP
   --  prime).  Base is assumed already reduced (Base < Modulus), as the DH
   --  callers guarantee (generator 2, and validated peer public values).  The
   --  exponentiation is word-serial constant-time Montgomery, so its timing
   --  depends only on the (public) operand widths, not on the secret exponent.
   --  @param Base     the base, an unsigned big-endian byte string < Modulus
   --  @param Exponent the exponent as an unsigned big-endian byte string
   --  @param Modulus  the odd, nonzero modulus as an unsigned big-endian string
   --  @return Base**Exponent mod Modulus, big-endian, same length as Modulus
   function Mod_Exp
     (Base     : Ada.Streams.Stream_Element_Array;
      Exponent : Ada.Streams.Stream_Element_Array;
      Modulus  : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array;

end CryptoLib.Modexp;
