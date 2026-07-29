private with Ada.Finalization;

with CryptoLib.ASN1;
with CryptoLib.ASN1.Errors;
with CryptoLib.X509;

--  @summary Unencrypted PKCS#8 private keys.
--
--  Holds secret material, which shapes the type. A Private_Key is limited, so
--  it cannot be copied into somewhere nobody is scrubbing, and it wipes its
--  own storage when it goes out of scope rather than leaving the key sitting
--  in a dead stack frame.
--
--  The reader this replaced looked for the first occurrence of the two bytes
--  that introduce an octet string of the right length and took what followed.
--  That is not parsing, and what it finds depends on what the key happens to
--  contain: valid keys were read wrongly or not at all according to their own
--  bytes. Everything here is decoded from the structure.
package CryptoLib.PKCS8 is

   subtype Decode_Status is CryptoLib.ASN1.Errors.Decode_Status;
   subtype Decode_Limits is CryptoLib.ASN1.Decode_Limits;
   subtype Octets is CryptoLib.ASN1.Octets;
   subtype Offset is CryptoLib.ASN1.Offset;

   --  The largest private key this will hold, in octets of DER.
   Maximum_Key_Size : constant := 8 * 1024;

   type Private_Key is limited private;

   --  Decode a PKCS#8 PrivateKeyInfo.
   --
   --  Unencrypted only: an EncryptedPrivateKeyInfo is refused rather than
   --  guessed at, since what it needs is a password and there is nowhere here
   --  to put one.
   --  @param Data the DER encoding
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Item receives the decoded key
   --  @param Status Ok on success, otherwise why the input was refused
   procedure Decode_DER
     (Data   : Octets;
      Limits : Decode_Limits;
      Item   : out Private_Key;
      Status : out Decode_Status);

   --  Why an encrypted key could not be opened.
   --
   --  A wrong password and a corrupted file are one answer on purpose. They
   --  cannot be told apart without leaking which it was: the only signal is
   --  whether the decrypted bytes look like padding and a key, and reporting
   --  that separately is an oracle. It is also of no use to a caller, who
   --  must retry or give up either way.
   type Unlock_Status is
     (Ok,
      Not_Encrypted,
      --  A plain PrivateKeyInfo, which Decode_DER reads without a password.
      Unsupported_Scheme,
      --  Not PBES2, or a derivation or cipher this crate does not implement.
      --  The key may be perfectly good; this cannot open it.
      Excessive_Iterations,
      --  More work than the caller's limit allows. An iteration count is a
      --  number in a file somebody else wrote, and honouring an enormous one
      --  is doing what that file says.
      Wrong_Password_Or_Corrupt,
      Malformed);

   --  The most derivation work this will do without being asked otherwise.
   Default_Maximum_Iterations : constant := 10_000_000;

   --  Render an unlock status as short diagnostic text.
   --  @param Status the status to describe
   --  @return lower-case text naming the status
   function Unlock_Image (Status : Unlock_Status) return String;

   --  Open an encrypted PKCS#8 key.
   --
   --  PBES2 only, with PBKDF2 over HMAC-SHA1/256/384/512 and AES-CBC, which
   --  is what every current tool writes.
   --  @param Data the DER encoding of an EncryptedPrivateKeyInfo
   --  @param Password the password protecting it
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Maximum_Iterations the most derivation work to do
   --  @param Item receives the decoded key
   --  @param Status Ok on success, otherwise why the key was not opened
   procedure Decode_Encrypted_DER
     (Data               : Octets;
      Password           : String;
      Limits             : Decode_Limits;
      Item               : out Private_Key;
      Status             : out Unlock_Status;
      Maximum_Iterations : Natural := Default_Maximum_Iterations);

   --  Did this decode?
   --  @param Item the key to inspect
   --  @return True when it holds a decoded key
   function Is_Present (Item : Private_Key) return Boolean;

   --  What kind of key this is.
   --  @param Item the key to inspect
   --  @return the algorithm, Unknown when unrecognised
   function Algorithm_Of
     (Item : Private_Key) return CryptoLib.X509.Public_Key_Algorithm;

   --  The private value itself: an EC scalar or an Ed25519 seed.
   --
   --  Secret. A caller that copies this out has taken responsibility for
   --  scrubbing the copy; CryptoLib.Secure_Wipe is what to scrub it with.
   --  Empty for an RSA key, whose private material is a structure rather than
   --  a single value and which nothing here can use.
   --  @param Item the key to inspect
   --  @return the scalar or seed, empty when there is no single such value
   function Private_Value (Item : Private_Key) return Octets;

   --  An RSA key's public modulus, as the octets it was encoded as.
   --
   --  An RSA private key carries its public parts: the modulus and the public
   --  exponent sit in the RSAPrivateKey beside the secret ones. So deciding
   --  whether such a key belongs to a certificate needs no computation at
   --  all, only a comparison -- which is why this is offered rather than a
   --  derived public key.
   --  @param Item the key to inspect
   --  @return the modulus, empty when the key is not RSA
   function RSA_Modulus (Item : Private_Key) return Octets;

   --  An RSA key's public exponent. See RSA_Modulus.
   --  @param Item the key to inspect
   --  @return the public exponent, empty when the key is not RSA
   function RSA_Exponent (Item : Private_Key) return Octets;

   --  The private exponent d of an RSA key.
   --
   --  Secret, unlike RSA_Modulus and RSA_Exponent beside it, and returned as
   --  a slice of storage this key wipes when it goes out of scope -- so it is
   --  valid only while the key is, and a caller that copies it elsewhere has
   --  taken responsibility for scrubbing the copy.
   --
   --  Empty for a key that is not RSA. The CRT parameters that follow d in an
   --  RSAPrivateKey are not surfaced: CryptoLib.RSA signs without them, and
   --  exposing them would invite a CRT implementation with the fault mode
   --  that comes with it.
   --  @param Item the decoded private key
   --  @return the private exponent as unsigned big-endian octets, or empty
   function RSA_Private_Exponent (Item : Private_Key) return Octets;

   --  Overwrite the key's storage now rather than at end of scope.
   --  @param Item the key to scrub
   procedure Wipe (Item : in out Private_Key);

private

   type Span is record
      First : Offset := 1;
      Last  : Offset := 0;
   end record;

   --  Controlled so that the key is scrubbed however the scope is left,
   --  including by an exception. A key that is only wiped on the path the
   --  author remembered is a key that survives the paths they did not.
   type Private_Key is limited new Ada.Finalization.Limited_Controlled with
      record
         Present   : Boolean := False;
         Kind      : CryptoLib.X509.Public_Key_Algorithm :=
           CryptoLib.X509.Unknown_Public_Key_Algorithm;
         Value     : Span;
         Modulus   : Span;
         Exponent  : Span;
         Private_D : Span;
         Held      : Offset := 0;
         DER       : Octets (1 .. Maximum_Key_Size) := [others => 0];
      end record;

   overriding procedure Finalize (Item : in out Private_Key);

end CryptoLib.PKCS8;
