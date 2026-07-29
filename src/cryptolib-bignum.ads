with Ada.Streams;

--  @summary Fixed-width unsigned big-endian integer arithmetic, for the few
--  operations RSA key generation needs that Modexp does not cover.
--
--  Deliberately not GNAT's Ada.Numerics.Big_Numbers.Big_Integers. A
--  Big_Integer keeps its digits in controlled storage this crate cannot
--  reach, so a prime or a private exponent held in one could not be scrubbed
--  -- and scrubbing secrets is a discipline this library states and keeps.
--  Everything here is a plain Stream_Element_Array the caller owns and can
--  wipe through its own address.
--
--  Only what key generation actually needs is here, and the shape of that set
--  is not accidental. Dividing one large number by another is the hard,
--  error-prone operation, and none of these need it: the RSA public exponent
--  is 65537, so a division by it is a division by a machine integer, and one
--  such division makes both operands of the extended Euclid small enough to
--  finish in Integer arithmetic. There is no general big division here
--  because none was required.
--
--  Timing depends on operand widths, not values. These run on secret primes,
--  but they are not the hardened path -- the exponentiations that touch a
--  secret exponent go through CryptoLib.Modexp.
package CryptoLib.Bignum is

   subtype Octets is Ada.Streams.Stream_Element_Array;

   --  Compare two numbers of any lengths.
   --  @param Left the first number, unsigned big-endian
   --  @param Right the second number, unsigned big-endian
   --  @return -1 when Left is smaller, 0 when equal, 1 when larger
   function Compare (Left, Right : Octets) return Integer;

   --  Is this number zero?
   --  @param Value the number to test
   --  @return True when every octet is zero
   function Is_Zero (Value : Octets) return Boolean;

   --  Add two numbers.
   --  @param Left the first addend
   --  @param Right the second addend
   --  @return the sum, one octet wider than the wider operand
   function Add (Left, Right : Octets) return Octets;

   --  Subtract, where the first operand is known to be the larger.
   --  @param Left the minuend, at least as large as Right
   --  @param Right the subtrahend
   --  @return Left - Right, as wide as Left; meaningless if Right is larger
   function Subtract (Left, Right : Octets) return Octets;

   --  Multiply two numbers.
   --  @param Left the first factor
   --  @param Right the second factor
   --  @return the product, as wide as the two operands together
   function Multiply (Left, Right : Octets) return Octets;

   --  Multiply by a value that fits in a machine integer.
   --  @param Value the large factor
   --  @param Factor the small factor
   --  @return the product, four octets wider than Value
   function Multiply_Small (Value : Octets; Factor : Natural) return Octets;

   --  Divide by a value that fits in a machine integer.
   --
   --  Long division one octet at a time, carrying the remainder: the only
   --  division this package has, and the reason it needs no other.
   --  @param Value the dividend
   --  @param Divisor the divisor, which must not be zero
   --  @param Quotient out: the quotient, as wide as Value
   --  @param Remainder out: the remainder, less than Divisor
   procedure Divide_Small
     (Value     : Octets;
      Divisor   : Positive;
      Quotient  : out Octets;
      Remainder : out Natural);

   --  The remainder of a division by a machine integer.
   --  @param Value the dividend
   --  @param Divisor the divisor, which must not be zero
   --  @return Value mod Divisor
   function Mod_Small (Value : Octets; Divisor : Positive) return Natural;

   --  Subtract a value that fits in a machine integer.
   --  @param Value the minuend, which must be at least Amount
   --  @param Amount the amount to subtract
   --  @return Value - Amount, as wide as Value
   function Subtract_Small (Value : Octets; Amount : Natural) return Octets;

   --  Copy a number into a field of a given width, right-aligned.
   --  @param Value the number to place
   --  @param Width the width of the field in octets
   --  @param Result out: the number, right-aligned and zero-padded
   --  @param Fits out: False when Value has a significant octet that does not
   --    fit, in which case Result is zero
   procedure Resize
     (Value  : Octets;
      Width  : Ada.Streams.Stream_Element_Offset;
      Result : out Octets;
      Fits   : out Boolean);

   --  The inverse of a small value modulo a large one.
   --
   --  Solves Value * Inverse = 1 (mod Modulus) for a Value that fits in a
   --  machine integer. This is the operation RSA key generation needs to turn
   --  the public exponent into the private one, and the reason this package
   --  needs no general division: Modulus = q*Value + r puts r below Value, so
   --  the extended Euclid that follows runs entirely in Integer arithmetic,
   --  and substituting r back leaves one large-by-small multiply.
   --
   --  The result is reduced into [0, Modulus). Roughly half of all inputs
   --  take the branch where the intermediate is negative and has to be folded
   --  back, so both are ordinary paths rather than one being an edge case.
   --  @param Value the small value to invert; must not be zero
   --  @param Modulus the modulus, unsigned big-endian
   --  @param Inverse out: the inverse, as wide as requested, zeroed when
   --    there is none
   --  @param Ok out: False when Value and Modulus share a factor, or the
   --    result does not fit the buffer
   procedure Mod_Inverse_Small
     (Value   : Positive;
      Modulus : Octets;
      Inverse : out Octets;
      Ok      : out Boolean);

   --  The inverse of a large value modulo an odd one.
   --
   --  The binary extended Euclid: halvings, additions, subtractions and
   --  comparisons, and no division at all -- which is why it belongs here.
   --  The modulus must be odd, which an RSA modulus is, and that is exactly
   --  the case this form of the algorithm covers.
   --
   --  Used for RSA blinding, where a fresh inverse is wanted per signature.
   --  @param Value the value to invert, unsigned big-endian
   --  @param Modulus the odd modulus, unsigned big-endian
   --  @param Inverse out: the inverse reduced into [0, Modulus), zeroed when
   --    there is none
   --  @param Ok out: False when Value and Modulus share a factor, when the
   --    modulus is even or zero, or when the result does not fit
   procedure Mod_Inverse
     (Value   : Octets;
      Modulus : Octets;
      Inverse : out Octets;
      Ok      : out Boolean);

   --  The number of significant bits.
   --  @param Value the number to measure
   --  @return the position of its highest set bit, or zero when it is zero
   function Bit_Length (Value : Octets) return Natural;

end CryptoLib.Bignum;
