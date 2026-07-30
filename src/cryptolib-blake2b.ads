with Ada.Streams;

--  @summary BLAKE2b (RFC 7693): a 64-bit hash with a variable digest length,
--  an optional key, and a streaming interface.
--
--  Here because Argon2 is defined on it and needs all three of those: the
--  variable length for its H' construction, the key for nothing, and the
--  streaming interface because Argon2 hashes a dozen separate pieces into one
--  digest without concatenating them first.
--
--  Useful on its own as well. BLAKE2b is faster than SHA-512 on 64-bit
--  hardware and its keyed mode is a MAC without the HMAC construction around
--  it -- but this crate does not offer it as one, because nothing here needs
--  it and a MAC nobody uses is a MAC nobody checks.
--
--  Not constant-time in the sense the ciphers are, and it does not need to be:
--  every operation is add, xor and rotate on whole words, with no table
--  indexed by data and no branch on a value. What it is not is armoured
--  against a caller who hashes a secret and then branches on the result.
package CryptoLib.Blake2b is

   --  A digest length in octets. BLAKE2b's parameter block fixes the ceiling
   --  at 64; there is no longer output, and H' in Argon2 is the construction
   --  that gets past it.
   subtype Digest_Length is Positive range 1 .. 64;

   --  A key length in octets, zero meaning unkeyed.
   subtype Key_Length is Natural range 0 .. 64;

   --  Hash in one call.
   --  @param Data   the message
   --  @param Length the digest length wanted, in octets
   --  @return the digest, Length octets
   function Hash
     (Data   : Ada.Streams.Stream_Element_Array;
      Length : Digest_Length := 64) return Ada.Streams.Stream_Element_Array;

   --  Hash in one call, keyed.
   --  @param Key    the key, at most 64 octets; empty is the same as unkeyed
   --  @param Data   the message
   --  @param Length the digest length wanted, in octets
   --  @return the digest, Length octets
   function Hash
     (Key    : Ada.Streams.Stream_Element_Array;
      Data   : Ada.Streams.Stream_Element_Array;
      Length : Digest_Length := 64) return Ada.Streams.Stream_Element_Array;

   --  A hash in progress.
   type Context is private;

   --  Begin a digest.
   --  @param Item   out: the context
   --  @param Length the digest length this hash will produce
   procedure Initialize
     (Item : out Context; Length : Digest_Length := 64);

   --  Begin a keyed digest.
   --  @param Item   out: the context
   --  @param Key    the key, at most 64 octets
   --  @param Length the digest length this hash will produce
   procedure Initialize
     (Item   : out Context;
      Key    : Ada.Streams.Stream_Element_Array;
      Length : Digest_Length := 64);

   --  Absorb more message.
   --  @param Item in out: the context
   --  @param Data the next piece of the message
   procedure Update
     (Item : in out Context; Data : Ada.Streams.Stream_Element_Array);

   --  Finish, and produce the digest.
   --
   --  The context is scrubbed on the way out, so a caller that drops it after
   --  this leaves no chaining state behind.
   --  @param Item   in out: the context, wiped before return
   --  @param Digest out: the digest; its length is the one Initialize was
   --    given, and a buffer of any other length is a Constraint_Error
   procedure Finalize
     (Item : in out Context; Digest : out Ada.Streams.Stream_Element_Array);

private

   type Word_64 is mod 2 ** 64;
   type Word_Array is array (Natural range <>) of Word_64;
   subtype Block_Index is Ada.Streams.Stream_Element_Offset range 0 .. 127;

   type Context is record
      H          : Word_Array (0 .. 7) := [others => 0];
      Buffer     : Ada.Streams.Stream_Element_Array (Block_Index) :=
        [others => 0];
      Buffered   : Ada.Streams.Stream_Element_Offset := 0;
      Counter    : Word_64 := 0;      --  octets absorbed, low word
      Counter_Hi : Word_64 := 0;      --  and high word
      Out_Length : Digest_Length := 64;
      Started    : Boolean := False;
   end record;

end CryptoLib.Blake2b;
