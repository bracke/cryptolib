with Ada.Streams;
with Interfaces;
with CryptoLib.Errors;

--  @summary OpenBSD bcrypt_pbkdf password-based key derivation, as used to
--  protect OpenSSH private keys.
package CryptoLib.BCrypt_PBKDF is

   Max_Salt_Length : constant Natural := 64;
   Max_Rounds        : constant Interfaces.Unsigned_32 := 1_000_000;
   Max_Output_Length : constant Natural := 64;

   --  Derive Output'Length key bytes from Passphrase and Salt_Data using the
   --  bcrypt_pbkdf construction with the given round count. Empty inputs or a
   --  zero round count fail with Authentication_Failed; a salt, round count, or
   --  output larger than the Max_* limits fails with Unsupported_Feature.
   --  @param Passphrase the passphrase (hashed to bytes internally via SHA-512)
   --  @param Salt_Data  the salt bytes (1 .. Max_Salt_Length)
   --  @param Rounds     the number of bcrypt rounds (1 .. Max_Rounds)
   --  @param Output     out: the derived key; zeroized on any failure
   --  @return Ok on success, else Authentication_Failed, Unsupported_Feature,
   --    or Internal_Error
   function Derive
     (Passphrase : String;
      Salt_Data  : Ada.Streams.Stream_Element_Array;
      Rounds     : Interfaces.Unsigned_32;
      Output     : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

end CryptoLib.BCrypt_PBKDF;
