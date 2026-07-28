with CryptoLib.ASN1;

--  @summary PBES2 decryption, RFC 8018.
--
--  Its own package because two different things are protected this way and
--  neither should own the code: a PKCS#8 private key, and the contents of a
--  PKCS#12 bundle. Sharing it means the derivation, the cipher selection and
--  the padding check cannot be right for one and wrong for the other.
--
--  PBES2 names a derivation and a cipher separately rather than naming a
--  combination, so what is supported is the cross-product of what this
--  implements: PBKDF2 over HMAC-SHA1, SHA-256, SHA-384 or SHA-512, with AES
--  in CBC at any of its three key sizes. That is what current tools write.
package CryptoLib.PBES2 is

   subtype Octets is CryptoLib.ASN1.Octets;
   subtype Offset is CryptoLib.ASN1.Offset;
   subtype Decode_Limits is CryptoLib.ASN1.Decode_Limits;

   type Unlock_Status is
     (Ok,
      Unsupported_Scheme,
      Excessive_Iterations,
      --  More derivation work than the caller allows. An iteration count is a
      --  number in a file somebody else wrote.
      Wrong_Password_Or_Corrupt,
      --  Deliberately one answer. The two cannot be separated without
      --  reporting which, and that report is an oracle; a caller can do
      --  nothing different about either.
      Buffer_Too_Small,
      Malformed);

   --  The most derivation work this will do unless told otherwise.
   Default_Maximum_Iterations : constant := 10_000_000;

   --  Render an unlock status as short diagnostic text.
   --  @param Status the status to describe
   --  @return lower-case text naming the status
   function Status_Image (Status : Unlock_Status) return String;

   --  Decrypt PBES2-protected content.
   --
   --  Parameters is the PBES2-params SEQUENCE as encoded, taken from the
   --  AlgorithmIdentifier that introduced the ciphertext.
   --  @param Parameters the PBES2 parameters, DER, header included
   --  @param Ciphertext the protected bytes
   --  @param Password the password protecting them
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Output receives the plaintext, padding already removed
   --  @param Last the last index of Output written
   --  @param Status Ok on success, otherwise why nothing was recovered
   --  @param Maximum_Iterations the most derivation work to do
   procedure Decrypt
     (Parameters         : Octets;
      Ciphertext         : Octets;
      Password           : String;
      Limits             : Decode_Limits;
      Output             : out Octets;
      Last               : out Offset;
      Status             : out Unlock_Status;
      Maximum_Iterations : Natural := Default_Maximum_Iterations);

end CryptoLib.PBES2;
