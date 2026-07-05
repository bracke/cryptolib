with Ada.Streams;
with CryptoLib.Random;
with CryptoLib.Errors;

--  @summary Streamlined NTRU Prime sntrup761 key-encapsulation mechanism.
--
--  The sntrup761 KEM profile as used by OpenSSH (ring R = Z[x]/(x^761-x-1),
--  q = 4591, weight w = 286).  Provides key generation, encapsulation, and
--  decapsulation over fixed-length byte arrays: a 1158-byte public key, a
--  1763-byte secret key, a 1039-byte ciphertext, and a 32-byte shared secret.
--  Decapsulation is constant-time and uses implicit rejection, returning a
--  pseudorandom shared secret (keyed by the stored rho) on ciphertext mismatch.
package CryptoLib.SNTRUP761 is

   --  OpenSSH sntrup761 sizes from the NTRU Prime sntrup761 KEM profile.
   Public_Key_Length  : constant Natural := 1158;
   Secret_Key_Length  : constant Natural := 1763;
   Ciphertext_Length  : constant Natural := 1039;
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

   --  Generate a fresh sntrup761 key pair from the random source: samples an
   --  invertible small g and a weight-w short f, publishes h = g/(3f), and packs
   --  f, 1/g, the public key, the rejection seed rho, and the pk-hash cache into
   --  the secret key.
   --  @param Source_Item entropy source drawn on to seed key generation
   --  @param Public_Item out; the 1158-byte public key (encoded h)
   --  @param Secret_Item out; the 1763-byte secret key
   --  @return Ok on success, or an error status if the random source failed
   function Generate_Keypair
     (Source_Item : in out CryptoLib.Random.Random_Source;
      Public_Item : out Public_Key;
      Secret_Item : out Secret_Key)
      return CryptoLib.Errors.Status;

   --  Encapsulate to a public key: draws a weight-w short r, produces the
   --  rounded ciphertext plus confirmation hash, and derives the shared secret.
   --  @param Source_Item entropy source drawn on for the ephemeral short r
   --  @param Public_Item the recipient's 1158-byte public key
   --  @param Ciphertext_Item out; the 1039-byte ciphertext to send
   --  @param Shared_Item out; the 32-byte shared secret established
   --  @return Ok on success, or an error status if the random source failed
   function Encapsulate
     (Source_Item     : in out CryptoLib.Random.Random_Source;
      Public_Item     : Public_Key;
      Ciphertext_Item : out Ciphertext;
      Shared_Item     : out Shared_Key)
      return CryptoLib.Errors.Status;

   --  Decapsulate a ciphertext with the secret key, recovering the shared
   --  secret; constant-time re-encryption checks the ciphertext and, on
   --  mismatch, implicitly rejects by keying the session hash with rho.
   --  @param Secret_Item the 1763-byte secret key
   --  @param Ciphertext_Item the received 1039-byte ciphertext
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
end CryptoLib.SNTRUP761;
