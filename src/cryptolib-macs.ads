with Ada.Streams;
with CryptoLib.Hashes;

--  @summary HMAC message-authentication codes and password-based key-derivation
--  functions (PBKDF2, PBKDF1, PKCS#12, scrypt, EVP_BytesToKey, 7-Zip AES).
package CryptoLib.Macs is
   pragma Preelaborate;

   subtype HMAC_SHA1_Digest is CryptoLib.Hashes.SHA1_Digest;
   subtype HMAC_SHA256_Digest is CryptoLib.Hashes.SHA256_Digest;
   subtype HMAC_SHA384_Digest is CryptoLib.Hashes.SHA384_Digest;
   subtype HMAC_SHA512_Digest is CryptoLib.Hashes.SHA512_Digest;

   --  Compute HMAC-SHA1 over Message_Data keyed by Key_Data (RFC 2104).
   --  @param Key_Data     the HMAC secret key bytes (any length)
   --  @param Message_Data the message to authenticate
   --  @return the 20-byte HMAC-SHA1 tag
   function HMAC_SHA1
     (Key_Data     : Ada.Streams.Stream_Element_Array;
      Message_Data : Ada.Streams.Stream_Element_Array)
      return HMAC_SHA1_Digest;

   --  Compute HMAC-SHA256 over Message_Data keyed by Key_Data (RFC 2104).
   --  @param Key_Data     the HMAC secret key bytes (any length)
   --  @param Message_Data the message to authenticate
   --  @return the 32-byte HMAC-SHA256 tag
   function HMAC_SHA256
     (Key_Data     : Ada.Streams.Stream_Element_Array;
      Message_Data : Ada.Streams.Stream_Element_Array)
      return HMAC_SHA256_Digest;

   --  Compute HMAC-SHA384 over Message_Data keyed by Key_Data (RFC 2104).
   --  @param Key_Data     the HMAC secret key bytes (any length)
   --  @param Message_Data the message to authenticate
   --  @return the 48-byte HMAC-SHA384 tag
   function HMAC_SHA384
     (Key_Data     : Ada.Streams.Stream_Element_Array;
      Message_Data : Ada.Streams.Stream_Element_Array)
      return HMAC_SHA384_Digest;

   --  Compute HMAC-SHA512 over Message_Data keyed by Key_Data (RFC 2104).
   --  @param Key_Data     the HMAC secret key bytes (any length)
   --  @param Message_Data the message to authenticate
   --  @return the 64-byte HMAC-SHA512 tag
   function HMAC_SHA512
     (Key_Data     : Ada.Streams.Stream_Element_Array;
      Message_Data : Ada.Streams.Stream_Element_Array)
      return HMAC_SHA512_Digest;

   --  Derive a key from a password with PBKDF2 using HMAC-SHA1 as the PRF
   --  (RFC 2898).
   --  @param Password_Data the password/passphrase bytes
   --  @param Salt_Data     the salt bytes
   --  @param Iterations    the PBKDF2 iteration count
   --  @param Output_Length the number of derived key bytes to produce
   --  @return the derived key of Output_Length bytes
   function PBKDF2_HMAC_SHA1
     (Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      Iterations    : Positive;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array;

   --  Derive a key from a password with PBKDF2 using HMAC-SHA256 as the PRF
   --  (RFC 2898).
   --  @param Password_Data the password/passphrase bytes
   --  @param Salt_Data     the salt bytes
   --  @param Iterations    the PBKDF2 iteration count
   --  @param Output_Length the number of derived key bytes to produce
   --  @return the derived key of Output_Length bytes
   function PBKDF2_HMAC_SHA256
     (Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      Iterations    : Positive;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array;

   --  Derive a key from a password with PBKDF2 using HMAC-SHA384 as the PRF
   --  (RFC 2898).
   --  @param Password_Data the password/passphrase bytes
   --  @param Salt_Data     the salt bytes
   --  @param Iterations    the PBKDF2 iteration count
   --  @param Output_Length the number of derived key bytes to produce
   --  @return the derived key of Output_Length bytes
   function PBKDF2_HMAC_SHA384
     (Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      Iterations    : Positive;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array;

   --  Derive a key from a password with PBKDF2 using HMAC-SHA512 as the PRF
   --  (RFC 2898).
   --  @param Password_Data the password/passphrase bytes
   --  @param Salt_Data     the salt bytes
   --  @param Iterations    the PBKDF2 iteration count
   --  @param Output_Length the number of derived key bytes to produce
   --  @return the derived key of Output_Length bytes
   function PBKDF2_HMAC_SHA512
     (Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      Iterations    : Positive;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array;

   --  Derive a key from a password with the legacy PBKDF1 construction using
   --  MD5 as the hash (RFC 2898); Output_Length must not exceed 16 bytes.
   --  @param Password_Data the password/passphrase bytes
   --  @param Salt_Data     the salt bytes
   --  @param Iterations    the PBKDF1 iteration count
   --  @param Output_Length the number of derived key bytes to produce
   --  @return the derived key of Output_Length bytes
   function PBKDF1_MD5
     (Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      Iterations    : Positive;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array;

   --  Derive a key from a password with the legacy PBKDF1 construction using
   --  SHA-1 as the hash (RFC 2898); Output_Length must not exceed 20 bytes.
   --  @param Password_Data the password/passphrase bytes
   --  @param Salt_Data     the salt bytes
   --  @param Iterations    the PBKDF1 iteration count
   --  @param Output_Length the number of derived key bytes to produce
   --  @return the derived key of Output_Length bytes
   function PBKDF1_SHA1
     (Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      Iterations    : Positive;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array;

   --  Derive key material with the PKCS#12 password-based KDF (SHA-1 variant),
   --  used by PFX/P12 files; Id_Byte selects the derived material class.
   --  @param Password_Data the password bytes (typically BMPString/UTF-16BE)
   --  @param Salt_Data     the salt bytes
   --  @param Iterations    the iteration count
   --  @param Id_Byte       the PKCS#12 purpose id (1=key, 2=IV, 3=MAC key)
   --  @param Output_Length the number of derived bytes to produce
   --  @return the derived material of Output_Length bytes
   function PKCS12_KDF_SHA1
     (Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      Iterations    : Positive;
      Id_Byte       : Ada.Streams.Stream_Element;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array;

   --  Derive a key with the scrypt memory-hard KDF using PBKDF2-HMAC-SHA256 as
   --  its inner PRF (RFC 7914).
   --  @param Password_Data the password/passphrase bytes
   --  @param Salt_Data     the salt bytes
   --  @param N             the CPU/memory cost parameter (a power of two)
   --  @param R             the block-size parameter
   --  @param P             the parallelization parameter
   --  @param Output_Length the number of derived key bytes to produce
   --  @return the derived key of Output_Length bytes
   function Scrypt_SHA256
     (Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      N             : Positive;
      R             : Positive;
      P             : Positive;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array;

   --  Derive a key with OpenSSL's legacy EVP_BytesToKey using one MD5 hash
   --  iteration, chaining digests until Output_Length bytes are produced.
   --  @param Password_Data the password/passphrase bytes
   --  @param Salt_Data     the salt bytes (empty for no salt)
   --  @param Output_Length the number of derived key bytes to produce
   --  @return the derived key of Output_Length bytes
   function EVP_Bytes_To_Key_MD5
     (Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array;

   --  7zAES key derivation: SHA-256 over Salt_Data, the 7z UTF-16LE password
   --  bytes, and an 8-byte little-endian counter, for 2**Num_Cycles_Power
   --  rounds, yielding a 32-byte AES-256 key.
   --  @param Password_UTF16LE the 7z password encoded as UTF-16LE bytes
   --  @param Salt_Data        the salt bytes
   --  @param Num_Cycles_Power log2 of the number of hashing rounds (2**power)
   --  @return the 32-byte AES-256 key
   function Seven_Zip_AES_SHA256_KDF
     (Password_UTF16LE : Ada.Streams.Stream_Element_Array;
      Salt_Data        : Ada.Streams.Stream_Element_Array;
      Num_Cycles_Power : Natural)
      return Ada.Streams.Stream_Element_Array;
end CryptoLib.Macs;
