with Ada.Streams;
with CryptoLib.Errors;

--  @summary Argon2 (RFC 9106), the memory-hard password hash: Argon2d,
--  Argon2i and Argon2id.
--
--  This is the one to reach for when hashing a password. PBKDF2 and bcrypt
--  make an attacker spend time; Argon2 makes them spend memory as well, and
--  memory is what a GPU or an ASIC has least of per unit of parallelism. That
--  is the whole point of the design and the reason the Password Hashing
--  Competition chose it.
--
--  Which variant:
--
--  * **Argon2id** unless you have a reason. Its first half-pass indexes
--    memory independently of the password and its remainder indexes
--    dependently, so it resists both the side-channel attack that Argon2d is
--    open to and the time-memory tradeoff that Argon2i is weaker against.
--    RFC 9106 section 4 names it the primary choice.
--  * **Argon2i** when the attacker may watch memory access timing and the
--    input is a secret -- and accept that it needs more passes to match
--    Argon2id's tradeoff resistance.
--  * **Argon2d** only where no side channel exists, such as hashing inside a
--    process nobody else shares. It is here because the RFC defines it and
--    cryptocurrencies use it, not as a recommendation.
--
--  Cost: RFC 9106 section 4 gives two settings. If 2 GiB is affordable,
--  t = 1, m = 2**21 KiB, p = 4. Otherwise t = 3, m = 2**16 KiB (64 MiB),
--  p = 4. Do not lower the memory to buy speed before lowering it is the only
--  option left; memory is the parameter doing the work.
--
--  This implementation is sequential. Lanes still shape the memory and so the
--  output -- a tag computed with p = 4 here is the tag any implementation
--  produces with p = 4 -- but four lanes take four times as long rather than
--  running on four cores.
--
--  Argon2 allocates m KiB and touches all of it. That is deliberate, and it
--  means a caller choosing m from untrusted input has handed over an
--  allocation size; bound it before it gets here.
package CryptoLib.Argon2 is

   --  Which variant. The RFC's y parameter: 0, 1 and 2 in this order.
   type Variant is (Argon2d, Argon2i, Argon2id);

   --  Derive a tag from a password.
   --
   --  Secret and Associated may be empty and usually are. Secret is a key
   --  held apart from the database -- a "pepper" -- so that stolen hashes
   --  cannot be attacked without it; Associated is any extra data to bind the
   --  tag to, such as a user identifier.
   --  @param Kind        which variant
   --  @param Password    the password
   --  @param Salt        the salt, at least 8 octets, unique per password
   --  @param Secret      an optional key, at most 64 octets
   --  @param Associated  optional associated data
   --  @param Iterations  the pass count t, at least 1
   --  @param Memory_KiB  the memory cost m in kibibytes, at least 8 * Lanes
   --  @param Lanes       the parallelism p, at least 1
   --  @param Tag         out: the derived tag, at least 4 octets; zeroed on
   --    failure
   --  @return Ok, or Handshake_Failed when a parameter is out of range,
   --    Internal_Error when the memory cannot be allocated
   function Derive
     (Kind       : Variant;
      Password   : Ada.Streams.Stream_Element_Array;
      Salt       : Ada.Streams.Stream_Element_Array;
      Secret     : Ada.Streams.Stream_Element_Array;
      Associated : Ada.Streams.Stream_Element_Array;
      Iterations : Positive;
      Memory_KiB : Positive;
      Lanes      : Positive;
      Tag        : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Derive with no secret and no associated data, which is the common case.
   --  @param Kind       which variant
   --  @param Password   the password
   --  @param Salt       the salt, at least 8 octets
   --  @param Iterations the pass count t
   --  @param Memory_KiB the memory cost m in kibibytes
   --  @param Lanes      the parallelism p
   --  @param Tag        out: the derived tag, zeroed on failure
   --  @return as above
   function Derive
     (Kind       : Variant;
      Password   : Ada.Streams.Stream_Element_Array;
      Salt       : Ada.Streams.Stream_Element_Array;
      Iterations : Positive;
      Memory_KiB : Positive;
      Lanes      : Positive;
      Tag        : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Does this password reproduce this tag?
   --
   --  Derive gives a caller no safe way to check a password: the obvious
   --  `Tag = Stored` stops at the first differing octet, which is a timing
   --  oracle on the very value the hash exists to protect. This compares
   --  through CryptoLib.Constant_Time.Equal instead, which is the same
   --  guarantee CryptoLib.Bcrypt.Verify already gave -- and Argon2 is the one
   --  this crate tells you to reach for, so it was the wrong way round.
   --
   --  The parameters must be the ones the tag was produced with. Argon2 has a
   --  standard encoding that carries them ($argon2id$v=19$m=...), which this
   --  crate does not implement, so a caller storing a tag must store the
   --  variant, salt, and the three costs beside it.
   --  @param Kind       which variant
   --  @param Password   the password offered
   --  @param Salt       the salt the tag was derived with
   --  @param Iterations the pass count t
   --  @param Memory_KiB the memory cost m in kibibytes
   --  @param Lanes      the parallelism p
   --  @param Tag        the stored tag to check against
   --  @return True only when derivation succeeds and reproduces Tag exactly
   function Verify
     (Kind       : Variant;
      Password   : Ada.Streams.Stream_Element_Array;
      Salt       : Ada.Streams.Stream_Element_Array;
      Iterations : Positive;
      Memory_KiB : Positive;
      Lanes      : Positive;
      Tag        : Ada.Streams.Stream_Element_Array) return Boolean;

   --  As above, with a secret (a pepper) and associated data.
   --  @param Kind       which variant
   --  @param Password   the password offered
   --  @param Salt       the salt the tag was derived with
   --  @param Secret     the secret the tag was derived with
   --  @param Associated the associated data the tag was derived with
   --  @param Iterations the pass count t
   --  @param Memory_KiB the memory cost m in kibibytes
   --  @param Lanes      the parallelism p
   --  @param Tag        the stored tag to check against
   --  @return True only when derivation succeeds and reproduces Tag exactly
   function Verify
     (Kind       : Variant;
      Password   : Ada.Streams.Stream_Element_Array;
      Salt       : Ada.Streams.Stream_Element_Array;
      Secret     : Ada.Streams.Stream_Element_Array;
      Associated : Ada.Streams.Stream_Element_Array;
      Iterations : Positive;
      Memory_KiB : Positive;
      Lanes      : Positive;
      Tag        : Ada.Streams.Stream_Element_Array) return Boolean;

   --  The longest PHC string these parameters can produce.
   --
   --  "$argon2id$v=19$m=4294967295,t=4294967295,p=16777215$" is 51, and the
   --  salt and tag are unpadded base64 of at most 64 octets each, 86
   --  characters, with a separator between them.
   Maximum_Encoded_Length : constant := 225;

   --  Encode a derived tag in the PHC string format:
   --
   --     $argon2id$v=19$m=65536,t=3,p=4$<salt>$<tag>
   --
   --  which is what every other Argon2 implementation reads and writes, and
   --  what makes a stored hash self-describing. Verify takes the parameters
   --  as arguments and so obliges a caller to store them separately;
   --  Verify_Encoded does not, which is the difference that matters when the
   --  costs are raised later and old hashes must still verify.
   --
   --  Salt and tag are limited to 64 octets each, which is past anything a
   --  password hash uses and keeps the result inside Maximum_Encoded_Length.
   --  @param Kind       which variant
   --  @param Salt       the salt the tag was derived with
   --  @param Iterations the pass count t
   --  @param Memory_KiB the memory cost m in kibibytes
   --  @param Lanes      the parallelism p
   --  @param Tag        the derived tag
   --  @param Result     out: the string, from Result'First through Last
   --  @param Last       out: the last character written, Result'First - 1 on
   --    failure
   --  @return Ok, or Handshake_Failed on an empty or over-long salt or tag,
   --    or a Result too small to hold the string
   function Encode
     (Kind       : Variant;
      Salt       : Ada.Streams.Stream_Element_Array;
      Iterations : Positive;
      Memory_KiB : Positive;
      Lanes      : Positive;
      Tag        : Ada.Streams.Stream_Element_Array;
      Result     : out String;
      Last       : out Natural) return CryptoLib.Errors.Status;

   --  Derive and encode in one step, which is how a password is stored.
   --  @param Kind       which variant; Argon2id unless you have a reason
   --  @param Password   the password
   --  @param Salt       the salt, at least 8 octets, from a random source
   --  @param Iterations the pass count t
   --  @param Memory_KiB the memory cost m in kibibytes
   --  @param Lanes      the parallelism p
   --  @param Tag_Length the tag length in octets, at least 4
   --  @param Result     out: the PHC string
   --  @param Last       out: the last character written
   --  @return as Derive and Encode
   function Hash
     (Kind       : Variant;
      Password   : Ada.Streams.Stream_Element_Array;
      Salt       : Ada.Streams.Stream_Element_Array;
      Iterations : Positive;
      Memory_KiB : Positive;
      Lanes      : Positive;
      Tag_Length : Positive;
      Result     : out String;
      Last       : out Natural) return CryptoLib.Errors.Status;

   --  Does this password reproduce this stored PHC string?
   --
   --  The parameters come out of the string, so a caller stores one value and
   --  old hashes keep verifying after the costs are raised. The tag
   --  comparison is constant-time. Parsing is not, and does not need to be:
   --  a malformed stored string is a fact about the database, not about the
   --  password.
   --
   --  Refuses what it cannot verify exactly rather than guessing: an unknown
   --  variant, a version other than 19, a missing or repeated parameter, a
   --  cost this build will not run, and base64 that is not the exact encoding
   --  of what it decodes to.
   --  @param Password the password offered
   --  @param Stored   the stored PHC string
   --  @return True only when the password reproduces the tag it carries
   function Verify_Encoded
     (Password : Ada.Streams.Stream_Element_Array;
      Stored   : String) return Boolean;

end CryptoLib.Argon2;
