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

end CryptoLib.Argon2;
