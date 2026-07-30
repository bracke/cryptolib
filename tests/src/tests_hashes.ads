with Ada.Streams;
with CryptoLib.Hashes;

--  Digests, checksums and fingerprints.
--
--  Each procedure is one group of known-answer or negative tests, and
--  is called from the Tests driver. Splitting the suite by topic is
--  what keeps any one file readable; the driver keeps the order.
package Tests_Hashes is

   procedure Check_MD5
     (Data     : Ada.Streams.Stream_Element_Array;
      Expected : CryptoLib.Hashes.MD5_Digest;
      Label    : String);

   procedure Check_XXH3;

   procedure Check_Adler32;

   procedure Check_CRC32;

   procedure Check_OpenSSH_Fingerprints;

   procedure Check_Streaming_SHA256_SHA512;

   procedure Check_SHA1_Fingerprint;

end Tests_Hashes;
