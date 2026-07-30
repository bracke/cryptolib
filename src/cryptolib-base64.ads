with Ada.Streams;

--  @summary Unpadded standard base64, the encoding two unrelated formats in
--  this crate both happen to need.
--
--  A **private child**: machinery for CryptoLib's own packages and reachable
--  from nowhere else. OpenSSH key fingerprints are unpadded base64, and so is
--  every field of an Argon2 PHC string; the encoder existed inside
--  CryptoLib.Fingerprints' body, where the second caller could not reach it.
--  One copy, for the same reason CryptoLib.Blowfish exists.
--
--  Standard alphabet -- A-Z a-z 0-9 + / -- and no padding, which is what both
--  formats specify. This is not the URL-safe variant and does not accept `=`.
private package CryptoLib.Base64 is

   --  The encoded length of Count octets, with no padding.
   --  @param Count the number of octets to encode
   --  @return the number of characters the encoding occupies
   function Encoded_Length (Count : Natural) return Natural;

   --  The largest number of octets an encoding of Length characters can
   --  decode to. A length of 1 modulo 4 is not a valid encoding at all.
   --  @param Length the number of characters
   --  @return the octet count, or 0 when Length cannot be an encoding
   function Decoded_Length (Length : Natural) return Natural;

   --  Encode.
   --  @param Data   the octets to encode
   --  @param Into   out: the characters, from Into'First
   --  @param Last   out: the last character written, Into'First - 1 when Into
   --    is too small
   procedure Encode
     (Data : Ada.Streams.Stream_Element_Array;
      Into : out String;
      Last : out Natural);

   --  Decode, strictly.
   --
   --  Refuses anything that is not the exact encoding of some octet string:
   --  a character outside the alphabet, padding, whitespace, a length of 1
   --  modulo 4, and a final group whose unused low bits are not zero -- the
   --  last of these being what lets two different strings decode to the same
   --  octets, which a format that is compared as text must not allow.
   --  @param Text  the characters to decode
   --  @param Into  out: the octets, from Into'First
   --  @param Last  out: the last octet written, Into'First - 1 on failure
   --  @param Valid out: True only when Text is exactly an encoding
   procedure Decode
     (Text  : String;
      Into  : out Ada.Streams.Stream_Element_Array;
      Last  : out Ada.Streams.Stream_Element_Offset;
      Valid : out Boolean);

end CryptoLib.Base64;
