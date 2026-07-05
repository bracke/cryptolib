with Ada.Streams;
with CryptoLib.Random;
with CryptoLib.Errors;

--  @summary ML-KEM-768 module-lattice key-encapsulation mechanism (FIPS 203).
--
--  The FIPS 203 standardization of Kyber at the ML-KEM-768 (module rank 3)
--  security level.  Provides key generation, encapsulation, and decapsulation
--  over fixed-length byte arrays: a 1184-byte public (encapsulation) key, a
--  2400-byte secret (decapsulation) key, a 1088-byte ciphertext, and a 32-byte
--  shared secret.  Decapsulation performs FIPS 203 implicit rejection, so a
--  tampered ciphertext yields a pseudorandom shared secret rather than an error.
package CryptoLib.MLKEM768 is

   Public_Key_Length  : constant Natural := 1184;
   Secret_Key_Length  : constant Natural := 2400;
   Ciphertext_Length  : constant Natural := 1088;
   Shared_Key_Length  : constant Natural := 32;
   Shared_Secret_Length : constant Natural := Shared_Key_Length;

   subtype Public_Key is Ada.Streams.Stream_Element_Array
     (Ada.Streams.Stream_Element_Offset'(1) .. Ada.Streams.Stream_Element_Offset (Public_Key_Length));
   subtype Secret_Key is Ada.Streams.Stream_Element_Array
     (Ada.Streams.Stream_Element_Offset'(1) .. Ada.Streams.Stream_Element_Offset (Secret_Key_Length));
   subtype Ciphertext is Ada.Streams.Stream_Element_Array
     (Ada.Streams.Stream_Element_Offset'(1) .. Ada.Streams.Stream_Element_Offset (Ciphertext_Length));
   subtype Shared_Key is Ada.Streams.Stream_Element_Array
     (Ada.Streams.Stream_Element_Offset'(1) .. Ada.Streams.Stream_Element_Offset (Shared_Key_Length));

   --  Generate a fresh ML-KEM-768 key pair from the random source (FIPS 203
   --  ML-KEM.KeyGen); the secret key embeds the matching public key, its hash,
   --  and the implicit-rejection seed z.
   --  @param Source_Item entropy source drawn on to seed key generation
   --  @param Public_Item out; the 1184-byte public (encapsulation) key
   --  @param Secret_Item out; the 2400-byte secret (decapsulation) key
   --  @return Ok on success, or an error status if the random source failed
   function Generate_Keypair
     (Source_Item : in out CryptoLib.Random.Random_Source;
      Public_Item : out Public_Key;
      Secret_Item : out Secret_Key)
      return CryptoLib.Errors.Status;

   --  Encapsulate to a public key (FIPS 203 ML-KEM.Encaps): draws a random
   --  message, then produces a ciphertext and the 32-byte shared secret.
   --  @param Source_Item entropy source drawn on for the ephemeral message
   --  @param Public_Item the recipient's 1184-byte public key
   --  @param Ciphertext_Item out; the 1088-byte ciphertext to send
   --  @param Shared_Item out; the 32-byte shared secret established
   --  @return Ok on success, or an error status if the random source failed
   function Encapsulate
     (Source_Item     : in out CryptoLib.Random.Random_Source;
      Public_Item     : Public_Key;
      Ciphertext_Item : out Ciphertext;
      Shared_Item     : out Shared_Key)
      return CryptoLib.Errors.Status;

   --  Decapsulate a ciphertext with the secret key (FIPS 203 ML-KEM.Decaps),
   --  recovering the shared secret; on ciphertext mismatch it returns the
   --  implicit-rejection key J(z || c) rather than failing.
   --  @param Secret_Item the 2400-byte secret (decapsulation) key
   --  @param Ciphertext_Item the received 1088-byte ciphertext
   --  @param Shared_Item out; the 32-byte shared secret (or rejection key)
   --  @return Ok (the operation always completes; validity is folded into the key)
   function Decapsulate
     (Secret_Item : Secret_Key;
      Ciphertext_Item : Ciphertext;
      Shared_Item : out Shared_Key)
      return CryptoLib.Errors.Status;

   --  Zeroize a secret key in place once it is no longer needed.
   --  @param Item out; the secret key overwritten with zero
   procedure Clear (Item : out Secret_Key)
     with SPARK_Mode => On;
end CryptoLib.MLKEM768;
