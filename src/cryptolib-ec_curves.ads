with Ada.Streams;
with CryptoLib.EC_Arith;
with CryptoLib.Errors;

--  @summary The NIST prime curves P-256, P-384 and P-521: their constants,
--  their point arithmetic, and the constant-time scalar ladder.
--
--  This is the layer between CryptoLib.EC_Arith, which knows how to multiply
--  modulo a prime but nothing about curves, and the algorithms that use
--  curves -- CryptoLib.ECDSA for signatures and CryptoLib.ECDH for key
--  agreement. It exists so those two share one ladder and one point addition
--  rather than each carrying a copy: a fault in either would otherwise have
--  to be found twice.
--
--  Point addition is the Renes-Costello-Batina complete formula, which has no
--  exceptional cases -- doubling, the identity and the point at infinity all
--  go through the same arithmetic, so nothing about the operands can be read
--  off which branch was taken. The ladder is fixed-length double-and-add-
--  always with a branchless select on every bit, so neither the scalar's
--  value nor its bit length is visible in the control flow.
--
--  Curve constants are taken from the curves OpenSSL prints, not from memory.
--  All three have a = p - 3, which the shared point arithmetic assumes; a
--  curve where that did not hold could not use this code.
package CryptoLib.EC_Curves is

   use CryptoLib.EC_Arith;

   --  Which of the three curves a value belongs to.
   type Curve_Kind is (Nistp256, Nistp384, Nistp521);

   --  A point in projective (Jacobian-free, X:Y:Z) coordinates, with the
   --  coordinates in Montgomery form for the curve's prime.
   type Point is record
      X, Y, Z : Element;
   end record;

   --  Everything about a curve that the algorithms above need. A bundle of
   --  public constants; nothing here is secret.
   type Curve_Data is record
      Kind        : Curve_Kind;
      Byte_Length : Natural;                    --  width of the order
      Q_Bits      : Natural;                    --  bit length of the order
      Nonce_Shift : Natural;                    --  bits to drop from a nonce
      Field       : Context;                    --  mod p
      Order       : Context;                    --  mod n
      P_Bytes     : Ada.Streams.Stream_Element_Array (1 .. 66);
      N_Bytes     : Ada.Streams.Stream_Element_Array (1 .. 66);
      P_Minus_2   : Ada.Streams.Stream_Element_Array (1 .. 66);
      N_Minus_2   : Ada.Streams.Stream_Element_Array (1 .. 66);
      P_Len       : Natural;                    --  width of the prime
      Base        : Point;
      B3_Mont     : Element;                    --  3*b, Montgomery-p form
      A3_Mont     : Element;                    --  a = -3 mod p, Montgomery-p
   end record;

   --  The P-256 constants.
   --  @return the curve data for NIST P-256
   function P256_Curve return Curve_Data;

   --  The P-384 constants.
   --  @return the curve data for NIST P-384
   function P384_Curve return Curve_Data;

   --  The P-521 constants.
   --  @return the curve data for NIST P-521
   function P521_Curve return Curve_Data;

   --  The constants for a curve named by its kind.
   --  @param Kind which curve
   --  @return that curve's data
   function Curve_Of (Kind : Curve_Kind) return Curve_Data;

   --  Multiply modulo the order or the prime, whichever context is given.
   --  @param Ctx the modulus context
   --  @param A the first factor
   --  @param B the second factor
   --  @return A * B in that context
   function Mul_Mod (Ctx : Context; A, B : Element) return Element;

   --  Renes-Costello-Batina complete projective addition.
   --  @param F the field context
   --  @param A3 a = -3 in Montgomery form
   --  @param B3 3*b in Montgomery form
   --  @param P the first point
   --  @param Q the second point
   --  @return P + Q, correct for every pair including P = Q and infinity
   function Point_Add
     (F : Context; A3, B3 : Element; P, Q : Point) return Point;

   --  Constant-time scalar multiplication over an arbitrary base point.
   --  @param Cv the curve
   --  @param K the scalar
   --  @param Base the point to multiply
   --  @return K * Base
   function Scalar_Mult_Base
     (Cv : Curve_Data; K : Element; Base : Point) return Point;

   --  Constant-time scalar multiplication of the curve's generator.
   --  @param Cv the curve
   --  @param K the scalar
   --  @return K * G
   function Scalar_Mult (Cv : Curve_Data; K : Element) return Point;

   --  Is this point on the curve?
   --
   --  Checks y^2 = x^3 - 3x + b in the field, and refuses the point at
   --  infinity. A caller that multiplies a secret scalar by a point must ask
   --  this first: a point off the curve lies on some other curve whose order
   --  may be smooth, and the result of multiplying it leaks the scalar. That
   --  is the invalid-curve attack, and it recovers a private key outright.
   --  @param Cv the curve
   --  @param P the point to test, with Z = 1 in Montgomery form
   --  @return True when P satisfies the curve equation and is not infinity
   function On_Curve (Cv : Curve_Data; P : Point) return Boolean;

   --  Read an encoded point into projective coordinates.
   --
   --  Accepts the uncompressed SEC 1 encoding: 16#04#, then X and Y, each the
   --  curve's width. A coordinate at or above p is refused here, because the
   --  field arithmetic assumes its operands are reduced and because it is a
   --  non-canonical spelling. Whether the point is on the curve is a separate
   --  question: call On_Curve.
   --  @param Cv the curve
   --  @param Encoded the encoded point
   --  @param P out: the point, meaningful only when the result is True
   --  @return True when the encoding has the right tag and width
   function Parse_Point
     (Cv      : Curve_Data;
      Encoded : Ada.Streams.Stream_Element_Array;
      P       : out Point) return Boolean;

   --  Write a point as 16#04# followed by X and Y.
   --  @param Cv the curve
   --  @param D the scalar whose multiple of the generator is wanted
   --  @param Public_Point out: the encoded point; zeroed on failure
   --  @return Ok, or Authentication_Failed when the result is infinity
   function Affine_Point
     (Cv           : Curve_Data;
      D            : Element;
      Public_Point : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Recover the affine x-coordinate of a point.
   --  @param Cv the curve
   --  @param P the point
   --  @param X_Bytes out: x as the curve's width, big-endian; zeroed on
   --    failure
   --  @return True unless the point is at infinity
   function Affine_X
     (Cv      : Curve_Data;
      P       : Point;
      X_Bytes : out Ada.Streams.Stream_Element_Array) return Boolean;

   --  Read a private scalar, however it was written, and check it is in
   --  [1, n-1].
   --
   --  Two encodings arrive here and both are legitimate: an SSH mpint pads a
   --  value whose top bit is set with a leading zero octet, so it is one
   --  wider than the curve; a raw scalar is exactly the curve's width. They
   --  are told apart by length, which is the only thing that distinguishes
   --  them.
   --  @param Data the scalar as an mpint or as raw big-endian octets
   --  @param Cv the curve
   --  @param Value out: the scalar, meaningful only when the result is True
   --  @return True when the scalar is a usable private key
   function Parse_Private
     (Data  : Ada.Streams.Stream_Element_Array;
      Cv    : Curve_Data;
      Value : out Element) return Boolean;

   --  Mask a uniform random draw down to the order's bit length.
   --
   --  A draw is as wide as the order in octets, which for P-521 is 528 bits
   --  against a 521-bit order: seven bits too many, so a raw draw lands below
   --  n about one time in 128 and rejection sampling runs out of attempts
   --  instead of returning a key. P-256 and P-384 have no excess bits and are
   --  unaffected, which is why this went unnoticed while they were the only
   --  curves that generated keys.
   --
   --  Masking keeps the draw uniform over [0, 2**Q_Bits); the caller still
   --  rejects a value that is zero or at least n, which is what keeps it
   --  uniform over [1, n-1] rather than biased the way reducing mod n would
   --  be.
   --  @param Cv the curve
   --  @param Draw in out: the random octets, narrowed in place
   procedure Trim_To_Order
     (Cv : Curve_Data; Draw : in out Ada.Streams.Stream_Element_Array);

   --  The low L octets of a right-aligned 66-octet modulus slot.
   --  @param S the slot
   --  @param L how many octets the curve actually uses
   --  @return the significant octets
   function Low
     (S : Ada.Streams.Stream_Element_Array; L : Natural)
      return Ada.Streams.Stream_Element_Array;

   --  Modular inverse by Fermat, through the constant-time CryptoLib.Modexp.
   --  @param Value the value to invert
   --  @param Exp_BE the exponent, modulus - 2, big-endian
   --  @param Mod_BE the modulus, big-endian
   --  @param Ctx the context the result belongs to
   --  @return Value**-1 in that context
   function Inv_Mod
     (Value          : Element;
      Exp_BE, Mod_BE : Ada.Streams.Stream_Element_Array;
      Ctx            : Context) return Element;

end CryptoLib.EC_Curves;
