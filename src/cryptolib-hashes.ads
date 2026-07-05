with Ada.Streams;
with Interfaces;

--  @summary One-shot and incremental cryptographic (MD5/SHA-1/SHA-2) and
--  non-cryptographic (XXH3) digest functions.
package CryptoLib.Hashes is
   pragma Preelaborate;

   subtype MD5_Digest_Index is Positive range 1 .. 16;
   type MD5_Digest is array (MD5_Digest_Index) of Ada.Streams.Stream_Element;

   subtype SHA1_Digest_Index is Positive range 1 .. 20;
   type SHA1_Digest is array (SHA1_Digest_Index) of Ada.Streams.Stream_Element;

   subtype SHA256_Digest_Index is Positive range 1 .. 32;
   type SHA256_Digest is array (SHA256_Digest_Index) of Ada.Streams.Stream_Element;

   subtype SHA384_Digest_Index is Positive range 1 .. 48;
   type SHA384_Digest is array (SHA384_Digest_Index) of Ada.Streams.Stream_Element;

   subtype SHA512_Digest_Index is Positive range 1 .. 64;
   type SHA512_Digest is array (SHA512_Digest_Index) of Ada.Streams.Stream_Element;

   subtype XXH3_64_Digest_Index is Positive range 1 .. 8;
   type XXH3_64_Digest is array (XXH3_64_Digest_Index) of Ada.Streams.Stream_Element;

   subtype XXH3_128_Digest_Index is Positive range 1 .. 16;
   type XXH3_128_Digest is array (XXH3_128_Digest_Index) of Ada.Streams.Stream_Element;

   type SHA256_Context is private;
   type SHA512_Context is private;

   --  Compute the MD5 digest of Data in one shot.
   --  @param Data the message bytes to hash
   --  @return the 16-byte MD5 digest
   function MD5
     (Data : Ada.Streams.Stream_Element_Array)
      return MD5_Digest;

   --  Compute the SHA-1 digest of Data in one shot.
   --  @param Data the message bytes to hash
   --  @return the 20-byte SHA-1 digest
   function SHA1
     (Data : Ada.Streams.Stream_Element_Array)
      return SHA1_Digest;

   --  Reset a SHA-256 context to the initial state so it can accept Update
   --  calls followed by a single Finalize.
   --  @param Context_Item the SHA-256 streaming context to initialize
   procedure Initialize_SHA256 (Context_Item : out SHA256_Context);

   --  Absorb a further chunk of message bytes into a SHA-256 context; may be
   --  called any number of times between Initialize and Finalize.
   --  @param Context_Item the SHA-256 streaming context to update in place
   --  @param Data         the next chunk of message bytes to hash
   procedure Update
     (Context_Item : in out SHA256_Context;
      Data         : Ada.Streams.Stream_Element_Array);

   --  Pad and finish a SHA-256 context, producing the digest of all bytes
   --  absorbed by prior Update calls.
   --  @param Context_Item the SHA-256 streaming context to finalize
   --  @return the 32-byte SHA-256 digest
   function Finalize
     (Context_Item : in out SHA256_Context)
      return SHA256_Digest;

   --  Compute the SHA-256 digest of Data in one shot.
   --  @param Data the message bytes to hash
   --  @return the 32-byte SHA-256 digest
   function SHA256
     (Data : Ada.Streams.Stream_Element_Array)
      return SHA256_Digest;

   --  Compute the SHA-384 digest of Data in one shot.
   --  @param Data the message bytes to hash
   --  @return the 48-byte SHA-384 digest
   function SHA384
     (Data : Ada.Streams.Stream_Element_Array)
      return SHA384_Digest;

   --  Reset a SHA-512 context to the initial state so it can accept Update
   --  calls followed by a single Finalize.
   --  @param Context_Item the SHA-512 streaming context to initialize
   procedure Initialize_SHA512 (Context_Item : out SHA512_Context);

   --  Absorb a further chunk of message bytes into a SHA-512 context; may be
   --  called any number of times between Initialize and Finalize.
   --  @param Context_Item the SHA-512 streaming context to update in place
   --  @param Data         the next chunk of message bytes to hash
   procedure Update
     (Context_Item : in out SHA512_Context;
      Data         : Ada.Streams.Stream_Element_Array);

   --  Pad and finish a SHA-512 context, producing the digest of all bytes
   --  absorbed by prior Update calls.
   --  @param Context_Item the SHA-512 streaming context to finalize
   --  @return the 64-byte SHA-512 digest
   function Finalize
     (Context_Item : in out SHA512_Context)
      return SHA512_Digest;

   --  Compute the SHA-512 digest of Data in one shot.
   --  @param Data the message bytes to hash
   --  @return the 64-byte SHA-512 digest
   function SHA512
     (Data : Ada.Streams.Stream_Element_Array)
      return SHA512_Digest;

   --  Compute the 64-bit XXH3 hash of Data (fast non-cryptographic hash).
   --  @param Data the message bytes to hash
   --  @return the 8-byte XXH3-64 digest
   function XXH3_64
     (Data : Ada.Streams.Stream_Element_Array)
      return XXH3_64_Digest;

   --  Compute the 128-bit XXH3 hash of Data (fast non-cryptographic hash).
   --  @param Data the message bytes to hash
   --  @return the 16-byte XXH3-128 digest
   function XXH3_128
     (Data : Ada.Streams.Stream_Element_Array)
      return XXH3_128_Digest;

private
   type SHA256_Block is array (Natural range 0 .. 63) of Interfaces.Unsigned_8;
   type SHA256_State is array (Natural range 0 .. 7) of Interfaces.Unsigned_32;

   type SHA256_Context is record
      State_Data  : SHA256_State := [others => 0];
      Block_Data  : SHA256_Block := [others => 0];
      Block_Used  : Natural range 0 .. 64 := 0;
      Total_Bytes : Interfaces.Unsigned_64 := 0;
   end record;

   type SHA512_Block is array (Natural range 0 .. 127) of Interfaces.Unsigned_8;
   type SHA512_State is array (Natural range 0 .. 7) of Interfaces.Unsigned_64;

   type SHA512_Context is record
      State_Data       : SHA512_State := [others => 0];
      Block_Data       : SHA512_Block := [others => 0];
      Block_Used       : Natural range 0 .. 128 := 0;
      Total_Bytes_High : Interfaces.Unsigned_64 := 0;
      Total_Bytes_Low  : Interfaces.Unsigned_64 := 0;
   end record;
end CryptoLib.Hashes;
