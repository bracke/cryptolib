with Ada.Streams;

--  @summary Low-level ML-KEM-768 arithmetic and K-PKE primitives (FIPS 203).
--
--  The building blocks beneath CryptoLib.MLKEM768: ring arithmetic over
--  R_q = Z_q[x]/(x^256+1) with q = 3329 and module rank k = 3, the number-
--  theoretic transform, coefficient compression, byte (de)serialization, and
--  the deterministic K-PKE keygen/encrypt/decrypt used by the KEM wrapper.
--  Polynomials carry 256 coefficients; a Polyvec is a length-3 vector of them.
--  This package holds no secrets and takes seeds/coins as explicit inputs.
package CryptoLib.MLKEM768_Core is
   pragma Preelaborate;

   N_Value : constant Natural := 256;
   Q_Value : constant Natural := 3329;
   K_Value : constant Natural := 3;
   Eta_1   : constant Natural := 2;
   Eta_2   : constant Natural := 2;
   D_U     : constant Natural := 10;
   D_V     : constant Natural := 4;

   subtype Coefficient_Index is Natural range 0 .. N_Value - 1;
   subtype Vector_Index is Natural range 0 .. K_Value - 1;

   type Polynomial is array (Coefficient_Index) of Integer;
   type Polyvec is array (Vector_Index) of Polynomial;

   subtype Encoded_Poly_12 is Ada.Streams.Stream_Element_Array
     (Ada.Streams.Stream_Element_Offset'(1) .. Ada.Streams.Stream_Element_Offset'(384));
   subtype Encoded_Poly_10 is Ada.Streams.Stream_Element_Array
     (Ada.Streams.Stream_Element_Offset'(1) .. Ada.Streams.Stream_Element_Offset'(320));
   subtype Encoded_Poly_4 is Ada.Streams.Stream_Element_Array
     (Ada.Streams.Stream_Element_Offset'(1) .. Ada.Streams.Stream_Element_Offset'(128));

   subtype Encoded_Polyvec_12 is Ada.Streams.Stream_Element_Array
     (Ada.Streams.Stream_Element_Offset'(1) .. Ada.Streams.Stream_Element_Offset (K_Value * 384));
   subtype Encoded_Polyvec_10 is Ada.Streams.Stream_Element_Array
     (Ada.Streams.Stream_Element_Offset'(1) .. Ada.Streams.Stream_Element_Offset (K_Value * 320));
   subtype MLKEM_Message is Ada.Streams.Stream_Element_Array
     (Ada.Streams.Stream_Element_Offset'(1) .. Ada.Streams.Stream_Element_Offset'(32));
   subtype MLKEM_Public_Seed is Ada.Streams.Stream_Element_Array
     (Ada.Streams.Stream_Element_Offset'(1) .. Ada.Streams.Stream_Element_Offset'(32));
   subtype MLKEM_Noise_Seed is Ada.Streams.Stream_Element_Array
     (Ada.Streams.Stream_Element_Offset'(1) .. Ada.Streams.Stream_Element_Offset'(32));
   subtype PKE_Public_Key is Ada.Streams.Stream_Element_Array
     (Ada.Streams.Stream_Element_Offset'(1) .. Ada.Streams.Stream_Element_Offset'(1184));
   subtype PKE_Secret_Key is Ada.Streams.Stream_Element_Array
     (Ada.Streams.Stream_Element_Offset'(1) .. Ada.Streams.Stream_Element_Offset'(1152));
   subtype PKE_Ciphertext is Ada.Streams.Stream_Element_Array
     (Ada.Streams.Stream_Element_Offset'(1) .. Ada.Streams.Stream_Element_Offset'(1088));

   --  Reduce an integer to its canonical representative in 0 .. q-1.
   --  @param Value the integer to reduce modulo q
   --  @return the residue of Value in 0 .. Q_Value - 1
   function Reduce (Value : Integer) return Integer
     with SPARK_Mode => On,
          Post => Reduce'Result in 0 .. Q_Value - 1;

   --  Compress a coefficient to Bits bits (FIPS 203 Compress_d).
   --  @param Value a coefficient in 0 .. q-1
   --  @param Bits  the target bit width d
   --  @return round(2^Bits / q * Value) mod 2^Bits
   function Compress
     (Value : Integer;
      Bits  : Natural)
      return Integer;

   --  Decompress a Bits-bit value back toward a coefficient (FIPS 203 Decompress_d).
   --  @param Value a compressed value in 0 .. 2^Bits - 1
   --  @param Bits  the source bit width d
   --  @return round(q / 2^Bits * Value), the approximate coefficient in 0 .. q-1
   function Decompress
     (Value : Integer;
      Bits  : Natural)
      return Integer;

   --  Sample matrix entry A-hat[Row][Column] in the NTT domain by rejection
   --  sampling from SHAKE128(rho || Column || Row) (FIPS 203 SampleNTT).
   --  @param Rho    the 32-byte public matrix seed
   --  @param Row    the matrix row index (0 .. k-1)
   --  @param Column the matrix column index (0 .. k-1)
   --  @return the sampled NTT-domain polynomial
   function Sample_NTT
     (Rho    : Ada.Streams.Stream_Element_Array;
      Row    : Natural;
      Column : Natural)
      return Polynomial;

   --  Sample a noise polynomial from the centered binomial distribution with
   --  eta = 2 over the given PRF output (FIPS 203 SamplePolyCBD).
   --  @param Bytes 64*eta = 128 pseudorandom bytes of PRF output
   --  @return the sampled small-coefficient polynomial (reduced mod q)
   function CBD_Eta2
     (Bytes : Ada.Streams.Stream_Element_Array)
      return Polynomial;

   --  Coefficient-wise addition of two polynomials modulo q.
   --  @param Left  the first addend
   --  @param Right the second addend
   --  @return Left + Right reduced coefficient-wise mod q
   function Add
     (Left  : Polynomial;
      Right : Polynomial)
      return Polynomial;

   --  Coefficient-wise subtraction of two polynomials modulo q.
   --  @param Left  the minuend
   --  @param Right the subtrahend
   --  @return Left - Right reduced coefficient-wise mod q
   function Subtract
     (Left  : Polynomial;
      Right : Polynomial)
      return Polynomial;

   --  Forward number-theoretic transform (FIPS 203 NTT).
   --  @param Item a polynomial in the normal domain
   --  @return its NTT representative (hat) domain image
   function NTT
     (Item : Polynomial)
      return Polynomial;

   --  Inverse number-theoretic transform (FIPS 203 NTT^-1).
   --  @param Item a polynomial in the NTT (hat) domain
   --  @return its normal-domain image
   function Inverse_NTT
     (Item : Polynomial)
      return Polynomial;

   --  Base-case pointwise product of two NTT-domain polynomials (FIPS 203
   --  MultiplyNTTs), multiplying the 128 degree-1 factors modulo q.
   --  @param Left  the first NTT-domain operand
   --  @param Right the second NTT-domain operand
   --  @return the NTT-domain product
   function Pointwise_Multiply
     (Left  : Polynomial;
      Right : Polynomial)
      return Polynomial;

   --  Schoolbook ring multiply in R_q = Z_q[x]/(x^256+1), used as a reference
   --  for the normal (non-NTT) domain.
   --  @param Left  the first normal-domain factor
   --  @param Right the second normal-domain factor
   --  @return the reduced product in R_q
   function Ring_Multiply_Reference
     (Left  : Polynomial;
      Right : Polynomial)
      return Polynomial;

   --  Serialize a polynomial as 12-bit coefficients (FIPS 203 ByteEncode_12).
   --  @param Item the polynomial to encode (coefficients in 0 .. q-1)
   --  @return the 384-byte encoding
   function Encode_12
     (Item : Polynomial)
      return Encoded_Poly_12;

   --  Deserialize 12-bit coefficients back into a polynomial (ByteDecode_12).
   --  @param Bytes the 384-byte encoding
   --  @return the decoded polynomial
   function Decode_12
     (Bytes : Encoded_Poly_12)
      return Polynomial;

   --  Compress to 10 bits then serialize (FIPS 203 Compress_10 + ByteEncode_10).
   --  @param Item the polynomial to compress and encode
   --  @return the 320-byte encoding
   function Compress_Encode_10
     (Item : Polynomial)
      return Encoded_Poly_10;

   --  Decode 10-bit values then decompress (ByteDecode_10 + Decompress_10).
   --  @param Bytes the 320-byte encoding
   --  @return the recovered (approximate) polynomial
   function Decode_Decompress_10
     (Bytes : Encoded_Poly_10)
      return Polynomial;

   --  Compress to 4 bits then serialize (FIPS 203 Compress_4 + ByteEncode_4).
   --  @param Item the polynomial to compress and encode
   --  @return the 128-byte encoding
   function Compress_Encode_4
     (Item : Polynomial)
      return Encoded_Poly_4;

   --  Decode 4-bit values then decompress (ByteDecode_4 + Decompress_4).
   --  @param Bytes the 128-byte encoding
   --  @return the recovered (approximate) polynomial
   function Decode_Decompress_4
     (Bytes : Encoded_Poly_4)
      return Polynomial;

   --  Component-wise addition of two length-k polynomial vectors modulo q.
   --  @param Left  the first vector addend
   --  @param Right the second vector addend
   --  @return the vector sum
   function Add
     (Left  : Polyvec;
      Right : Polyvec)
      return Polyvec;

   --  Component-wise subtraction of two length-k polynomial vectors modulo q.
   --  @param Left  the vector minuend
   --  @param Right the vector subtrahend
   --  @return the vector difference
   function Subtract
     (Left  : Polyvec;
      Right : Polyvec)
      return Polyvec;

   --  NTT-domain dot product of two vectors: sum of pointwise products.
   --  @param Left  the first NTT-domain vector
   --  @param Right the second NTT-domain vector
   --  @return the accumulated NTT-domain polynomial
   function Dot_Product
     (Left  : Polyvec;
      Right : Polyvec)
      return Polynomial;

   --  Serialize a vector as 12-bit coefficients (k concatenated ByteEncode_12).
   --  @param Item the polynomial vector to encode
   --  @return the k*384-byte encoding
   function Encode_12
     (Item : Polyvec)
      return Encoded_Polyvec_12;

   --  Deserialize 12-bit coefficients back into a polynomial vector.
   --  @param Bytes the k*384-byte encoding
   --  @return the decoded polynomial vector
   function Decode_12
     (Bytes : Encoded_Polyvec_12)
      return Polyvec;

   --  Compress each component to 10 bits then serialize (used for ciphertext u).
   --  @param Item the polynomial vector to compress and encode
   --  @return the k*320-byte encoding
   function Compress_Encode_10
     (Item : Polyvec)
      return Encoded_Polyvec_10;

   --  Decode 10-bit values then decompress into a polynomial vector.
   --  @param Bytes the k*320-byte encoding
   --  @return the recovered (approximate) polynomial vector
   function Decode_Decompress_10
     (Bytes : Encoded_Polyvec_10)
      return Polyvec;

   --  Expand a 32-byte message into a polynomial, mapping each bit to 0 or q/2
   --  (FIPS 203 Decompress_1 of ByteDecode_1).
   --  @param Message the 32-byte plaintext message
   --  @return the message encoded as a polynomial
   function Message_To_Poly
     (Message : MLKEM_Message)
      return Polynomial;

   --  Recover a 32-byte message from a polynomial by 1-bit compression of each
   --  coefficient (FIPS 203 ByteEncode_1 of Compress_1).
   --  @param Item the decrypted polynomial
   --  @return the recovered 32-byte message
   function Poly_To_Message
     (Item : Polynomial)
      return MLKEM_Message;

   --  Deterministic K-PKE key generation from expanded seeds (FIPS 203
   --  K-PKE.KeyGen): builds t-hat = A-hat o s-hat + e-hat in the NTT domain.
   --  @param Rho         the 32-byte public matrix seed (rho)
   --  @param Sigma       the 32-byte noise seed used to sample s and e
   --  @param Public_Item out; the 1184-byte K-PKE public key (encoded t-hat || rho)
   --  @param Secret_Item out; the 1152-byte K-PKE secret key (encoded s-hat)
   procedure PKE_Keygen_From_Seeds
     (Rho         : MLKEM_Public_Seed;
      Sigma       : MLKEM_Noise_Seed;
      Public_Item : out PKE_Public_Key;
      Secret_Item : out PKE_Secret_Key);

   --  Deterministic K-PKE encryption with caller-supplied coins (FIPS 203
   --  K-PKE.Encrypt): forms u and v and emits the compressed ciphertext.
   --  @param Public_Item     the 1184-byte K-PKE public key
   --  @param Message         the 32-byte plaintext message
   --  @param Random_Coins    the 32-byte seed for the encryption noise (y, e1, e2)
   --  @param Ciphertext_Item out; the 1088-byte ciphertext (encoded u || v)
   procedure PKE_Encrypt_Deterministic
     (Public_Item     : PKE_Public_Key;
      Message         : MLKEM_Message;
      Random_Coins    : MLKEM_Noise_Seed;
      Ciphertext_Item : out PKE_Ciphertext);

   --  K-PKE decryption (FIPS 203 K-PKE.Decrypt): recovers the message as
   --  w = v - NTT^-1(s-hat^T o NTT(u)), then 1-bit compresses it.
   --  @param Secret_Item     the 1152-byte K-PKE secret key (encoded s-hat)
   --  @param Ciphertext_Item the 1088-byte ciphertext
   --  @return the recovered 32-byte message
   function PKE_Decrypt
     (Secret_Item     : PKE_Secret_Key;
      Ciphertext_Item : PKE_Ciphertext)
      return MLKEM_Message;
end CryptoLib.MLKEM768_Core;
