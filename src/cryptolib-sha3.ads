with Ada.Streams;

--  @summary Keccak-based SHA-3 fixed-length digests and SHAKE extendable-output
--  functions (XOFs).
package CryptoLib.SHA3 is
   pragma Preelaborate;

   subtype SHA3_256_Digest_Index is Positive range 1 .. 32;
   type SHA3_256_Digest is array (SHA3_256_Digest_Index) of Ada.Streams.Stream_Element;

   subtype SHA3_512_Digest_Index is Positive range 1 .. 64;
   type SHA3_512_Digest is array (SHA3_512_Digest_Index) of Ada.Streams.Stream_Element;

   --  Compute the SHA3-256 digest of Data in one shot.
   --  @param Data the message bytes to hash
   --  @return the 32-byte SHA3-256 digest
   function SHA3_256
     (Data : Ada.Streams.Stream_Element_Array)
      return SHA3_256_Digest;

   --  Compute the SHA3-512 digest of Data in one shot.
   --  @param Data the message bytes to hash
   --  @return the 64-byte SHA3-512 digest
   function SHA3_512
     (Data : Ada.Streams.Stream_Element_Array)
      return SHA3_512_Digest;

   --  Squeeze an arbitrary-length output from the SHAKE128 XOF over Data.
   --  @param Data          the message bytes to absorb
   --  @param Output_Length the number of output bytes to produce
   --  @return a Stream_Element_Array of Output_Length bytes
   function SHAKE128
     (Data          : Ada.Streams.Stream_Element_Array;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array;

   --  Squeeze an arbitrary-length output from the SHAKE256 XOF over Data.
   --  @param Data          the message bytes to absorb
   --  @param Output_Length the number of output bytes to produce
   --  @return a Stream_Element_Array of Output_Length bytes
   function SHAKE256
     (Data          : Ada.Streams.Stream_Element_Array;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array;
end CryptoLib.SHA3;
