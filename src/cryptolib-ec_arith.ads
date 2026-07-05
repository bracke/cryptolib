with Ada.Streams;
with Interfaces;

--  @summary Constant-time fixed-width Montgomery modular arithmetic for the
--  NIST prime curves (P-384 / P-521).
--
--  Constant-time fixed-width modular arithmetic for the NIST prime curves,
--  replacing GNAT's variable-time Big_Integers in the ECDSA signer.  Word-
--  serial Montgomery multiplication (CIOS) with branchless conditional
--  subtract/add and select.  A Context caches the modulus, its Montgomery
--  constant, and R**2 mod M.  Elements are little-endian 32-bit word arrays;
--  bytes cross the boundary big-endian.
package CryptoLib.EC_Arith is

   Max_Words : constant := 17;                --  17*32 = 544 bits >= P-521

   subtype Word is Interfaces.Unsigned_32;
   type Element is array (0 .. Max_Words - 1) of Word;

   Zero : constant Element := [others => 0];

   type Context is private;

   --  Build a context from a big-endian modulus (must be odd; both P-384/P-521
   --  field primes and group orders are).
   --  @param Modulus_BE the modulus as big-endian bytes
   --  @return a context caching the modulus, its Montgomery constant N0, and
   --          R**2 mod M
   function Make_Context
     (Modulus_BE : Ada.Streams.Stream_Element_Array) return Context;

   --  The modulus width in bytes (the width of To_Bytes output).
   --  @param Ctx the field/order context
   --  @return the modulus byte length
   function Byte_Length (Ctx : Context) return Natural;

   --  Big-endian bytes -> element (value must already be < modulus).
   --  @param Ctx     the context whose word width is used
   --  @param Data_BE the value as big-endian bytes, already reduced mod modulus
   --  @return the value as a little-endian word-array element
   function From_Bytes
     (Ctx : Context; Data_BE : Ada.Streams.Stream_Element_Array) return Element;

   --  Element -> big-endian bytes of the context's byte length.
   --  @param Ctx the context whose byte length sets the output width
   --  @param A   the element to encode
   --  @return the value as big-endian bytes, Byte_Length wide
   function To_Bytes
     (Ctx : Context; A : Element) return Ada.Streams.Stream_Element_Array;

   --  All modular; inputs and outputs in [0, modulus).
   --  Modular addition (A + B) mod modulus.
   --  @param Ctx the context
   --  @param A   the first addend in [0, modulus)
   --  @param B   the second addend in [0, modulus)
   --  @return (A + B) mod modulus
   function Add (Ctx : Context; A, B : Element) return Element;
   --  Modular subtraction (A - B) mod modulus.
   --  @param Ctx the context
   --  @param A   the minuend in [0, modulus)
   --  @param B   the subtrahend in [0, modulus)
   --  @return (A - B) mod modulus
   function Sub (Ctx : Context; A, B : Element) return Element;

   --  Montgomery multiply: A * B * R**(-1) mod M.  Field arithmetic runs in the
   --  Montgomery domain (To_Mont/From_Mont at the boundary).
   --  @param Ctx the context
   --  @param A   the first factor (Montgomery domain)
   --  @param B   the second factor (Montgomery domain)
   --  @return A * B * R**(-1) mod M (Montgomery domain)
   function Mont_Mul (Ctx : Context; A, B : Element) return Element;
   --  Map a normal-domain element into the Montgomery domain.
   --  @param Ctx the context
   --  @param A   the normal-domain element
   --  @return A * R mod M
   function To_Mont (Ctx : Context; A : Element) return Element;
   --  Map a Montgomery-domain element back to the normal domain.
   --  @param Ctx the context
   --  @param A   the Montgomery-domain element
   --  @return A * R**(-1) mod M (normal domain)
   function From_Mont (Ctx : Context; A : Element) return Element;
   --  The Montgomery representation of one.
   --  @param Ctx the context
   --  @return R mod M
   function One_Mont (Ctx : Context) return Element;

   --  Branchless helpers.  Mask is all-ones (choose A) or zero (choose B).
   --  The all-ones word constant (a true mask for CT_Select).
   --  @return the all-ones 32-bit word
   function All_Ones return Word is (Interfaces.Unsigned_32'Last);
   --  Constant-time per-word select between two elements driven by a mask.
   --  @param Mask all-ones to select A, zero to select B
   --  @param A    the element chosen when Mask is all-ones
   --  @param B    the element chosen when Mask is zero
   --  @return A when Mask is all-ones, B when Mask is zero
   function CT_Select (Mask : Word; A, B : Element) return Element;

   --  Constant-time predicates returning an all-ones / zero mask.
   --  Test whether an element is zero.
   --  @param A the element to test
   --  @return all-ones if A = 0, zero otherwise
   function Is_Zero_Mask (A : Element) return Word;
   --  Test two elements for equality.
   --  @param A the first element
   --  @param B the second element
   --  @return all-ones if A = B, zero otherwise
   function Equal_Mask (A, B : Element) return Word;
   --  Test whether A is greater than or equal to M.
   --  @param A the value to compare
   --  @param M the threshold to compare against
   --  @return all-ones if A >= M, zero otherwise
   function Geq_Mask (A, M : Element) return Word;

   --  Modulus as an element (for reductions across the field/order boundary).
   --  @param Ctx the context
   --  @return the context's modulus as an element
   function Modulus (Ctx : Context) return Element;

private

   type Context is record
      N_Words   : Natural := 1;
      Byte_Len  : Natural := 0;
      M         : Element := [others => 0];
      N0        : Word := 0;
      R2        : Element := [others => 0];
   end record;

end CryptoLib.EC_Arith;
