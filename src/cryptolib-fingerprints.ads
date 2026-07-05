with Ada.Streams;
with Ada.Strings.Unbounded;
with CryptoLib.Errors;

--  @summary OpenSSH-format public-key fingerprints (MD5 hex and SHA-256
--  base64) rendered as printable strings.
package CryptoLib.Fingerprints is
   --  Format an OpenSSH MD5 key fingerprint: the colon-separated lowercase hex
   --  of MD5(Data), prefixed with "MD5:".
   --  @param Data  the public-key blob to fingerprint
   --  @param Image out: the rendered fingerprint (empty on failure)
   --  @return Ok on success, else Internal_Error
   function MD5_OpenSSH
     (Data  : Ada.Streams.Stream_Element_Array;
      Image : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Format an OpenSSH SHA-256 key fingerprint: the unpadded base64 of
   --  SHA-256(Data), prefixed with "SHA256:".
   --  @param Data  the public-key blob to fingerprint
   --  @param Image out: the rendered fingerprint (empty on failure)
   --  @return Ok on success, else Internal_Error
   function SHA256_OpenSSH
     (Data  : Ada.Streams.Stream_Element_Array;
      Image : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;
end CryptoLib.Fingerprints;
