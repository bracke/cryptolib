--  @summary Arithmetic modulo p = 2**448 - 2**224 - 1, the field both
--  edwards448 and curve448 are defined over.
--
--  A **private child**: machinery for CryptoLib.Ed448 and CryptoLib.X448 and
--  reachable from nowhere else. It was Ed448's alone until X448 needed the
--  same field, and two copies of a field arithmetic is one more than anybody
--  will keep correct -- the same reason CryptoLib.Blowfish exists.
--
--  Field elements are 56 little-endian octets, one per index, each holding a
--  value in 0 .. 255. That representation is deliberately dull: it costs
--  speed and it makes carry propagation something a reader can follow, which
--  for a curve implemented from a specification is the better trade.
--
--  Everything here is constant-time with respect to the values: no branch and
--  no index depends on an operand. Select_Field is the conditional move the
--  Montgomery ladder and the Edwards ladder both need, and the reason neither
--  has to branch on a scalar bit. The jump budgets in
--  tools/bin/check_constant_time hold these routines to it.
private package CryptoLib.Field448 is

   subtype Byte_Value is Natural range 0 .. 255;
   subtype Fe_Index is Natural range 0 .. 55;
   type Field_Element is array (Fe_Index) of Byte_Value;

   --  p itself, as a field element.
   --  @return 2**448 - 2**224 - 1
   function Prime return Field_Element;

   --  Is Left below Right? Returned as a borrow rather than a Boolean so that
   --  callers can use it without branching.
   --  @param Left the first operand
   --  @param Right the second operand
   --  @return 1 when Left < Right, 0 otherwise
   function Borrow_Of (Left : Field_Element; Right : Field_Element)
      return Natural;

   --  @param Left the first addend
   --  @param Right the second addend
   --  @return Left + Right mod p
   function Add_Mod (Left : Field_Element; Right : Field_Element)
      return Field_Element;

   --  @param Left the minuend
   --  @param Right the subtrahend
   --  @return Left - Right mod p
   function Sub_Mod (Left : Field_Element; Right : Field_Element)
      return Field_Element;

   --  @param Left the first factor
   --  @param Right the second factor
   --  @return Left * Right mod p
   function Mul_Mod (Left : Field_Element; Right : Field_Element)
      return Field_Element;

   --  @param Item the value to square
   --  @return Item**2 mod p
   function Square_Mod (Item : Field_Element) return Field_Element;

   --  @param Base the base
   --  @param Exponent the exponent, as a field element
   --  @return Base**Exponent mod p
   function Pow_Mod (Base : Field_Element; Exponent : Field_Element)
      return Field_Element;

   --  The multiplicative inverse, by Fermat: Item**(p-2).
   --  @param Item the value to invert
   --  @return Item**-1 mod p, and zero for zero
   function Inv_Mod (Item : Field_Element) return Field_Element;

   --  @param Left the first operand
   --  @param Right the second operand
   --  @return True when Left >= Right
   function Not_Less (Left : Field_Element; Right : Field_Element)
      return Boolean;

   --  @param Left the first operand
   --  @param Right the second operand
   --  @return True when the two are equal
   function Equal_Field (Left : Field_Element; Right : Field_Element)
      return Boolean;

   --  A square root modulo p, for point decompression.
   --  @param Item the value to take the root of
   --  @return a square root of Item, meaningful only when one exists
   function Sqrt_Mod (Item : Field_Element) return Field_Element;

   --  Subtract Amount when Take is 1, with no branch on either. The
   --  reduction step the scalar arithmetic needs.
   --  @param Item in out: the value
   --  @param Amount the value to subtract
   --  @param Take 1 to subtract, 0 to leave alone
   procedure Conditional_Subtract
     (Item : in out Field_Element; Amount : Field_Element; Take : Natural);

   --  A conditional move with no branch on Choice.
   --  @param Left  returned when Take is 0
   --  @param Right returned when Take is 1
   --  @param Take  0 or 1
   --  @return Right when Take is 1, Left otherwise
   function Select_Field
     (Left : Field_Element; Right : Field_Element; Take : Natural)
      return Field_Element;

end CryptoLib.Field448;
