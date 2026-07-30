with Ada.Streams;
with CryptoLib.Errors;

--  @summary bcrypt, the password hash: the `$2b$` modular crypt format.
--
--  Not to be confused with CryptoLib.BCrypt_PBKDF, which is OpenBSD's KDF and
--  shares only the key schedule. This is the one that produces
--  `$2b$12$....` strings and verifies them.
--
--  Prefer CryptoLib.Argon2 for new work. bcrypt makes an attacker spend time
--  and a fixed 4 KiB of memory; Argon2 makes them spend as much memory as you
--  choose, which is what a GPU has least of. bcrypt is here because existing
--  password databases are full of it and they have to be verified before they
--  can be migrated.
--
--  Two limits are inherent to the construction, not to this implementation,
--  and a caller that does not know them will be surprised:
--
--  * **The password is truncated at 72 octets.** Everything past that is
--    ignored, silently, by every bcrypt there is. Refused here instead --
--    see Maximum_Password_Length -- because silently ignoring half of a
--    passphrase is not a thing a library should do on its own authority.
--  * **A NUL octet ends the password.** The key is taken as a C string, so a
--    password containing 16#00# is truncated there. Refused here for the same
--    reason.
--
--  The cost is a base-two logarithm: cost 12 means 2**12 iterations of the
--  key schedule. Each step up doubles the work.
package CryptoLib.Bcrypt is

   --  The longest password bcrypt can take. Past this the construction
   --  ignores the remainder, so this package refuses it instead.
   Maximum_Password_Length : constant := 72;

   --  The cost, as a base-two logarithm of the iteration count. The format
   --  encodes it in two digits, and below 4 it is not a password hash.
   subtype Cost_Factor is Positive range 4 .. 31;

   --  The salt, which is always 16 octets before encoding.
   subtype Salt is Ada.Streams.Stream_Element_Array (1 .. 16);

   --  A `$2b$` hash string: "$2b$", two cost digits, "$", 22 salt characters
   --  and 31 hash characters.
   subtype Hash_String is String (1 .. 60);

   --  Hash a password.
   --  @param Password the password, at most 72 octets and containing no NUL
   --  @param Salt_Data the salt, 16 octets from a random source
   --  @param Cost     the cost factor
   --  @param Result   out: the `$2b$` string; all blanks on failure
   --  @return Ok, or Handshake_Failed when the password is too long or
   --    contains a NUL octet
   function Hash
     (Password  : Ada.Streams.Stream_Element_Array;
      Salt_Data : Salt;
      Cost      : Cost_Factor;
      Result    : out Hash_String) return CryptoLib.Errors.Status;

   --  Does this password produce this hash?
   --
   --  The comparison is constant-time in the hash, so a caller cannot learn
   --  how much of it matched by timing. It is not constant-time in whether
   --  the stored string parses, because a malformed stored hash is a fact
   --  about the database rather than about the password.
   --  @param Password the password offered
   --  @param Stored   the stored `$2b$` string
   --  @return True when the password produces exactly that hash
   function Verify
     (Password : Ada.Streams.Stream_Element_Array;
      Stored   : String) return Boolean;

end CryptoLib.Bcrypt;
