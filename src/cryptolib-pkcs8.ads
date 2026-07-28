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
         Held      : Offset := 0;
         DER       : Octets (1 .. Maximum_Key_Size) := [others => 0];
      end record;

   overriding procedure Finalize (Item : in out Private_Key);

end CryptoLib.PKCS8;
