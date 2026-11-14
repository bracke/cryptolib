with Ada.Streams;

--  @summary Standard base64 (RFC 4648 section 4), padded or unpadded, with a
--  decoder that accepts exactly one spelling of each octet string.
--
--  Standard alphabet -- A-Z a-z 0-9 + / -- not the URL-safe variant. The
--  default is no padding, which is what the two formats this crate reads
--  itself specify: OpenSSH key fingerprints are unpadded base64, and so is
--  every field of an Argon2 PHC string. A caller whose format pads -- most
--  text formats do -- passes `Padded => True`. The two forms share one decoder,
--  so the strictness described under Decode holds for both.
--
--  This package is public so that code built on this crate need not carry a
--  second copy of an encoding that is easy to get subtly wrong. CryptoLib.PEM
--  decodes its own armour, line breaks included, and does not go through it.
package CryptoLib.Base64 is
   pragma Preelaborate;

   --  The encoded length of Count octets.
   --  @param Count  the number of octets to encode
   --  @param Padded whether the encoding is padded with `=` to a multiple of 4
   --  @return the number of characters the encoding occupies
   function Encoded_Length
     (Count : Natural; Padded : Boolean := False) return Natural;

   --  The largest number of octets an encoding of Length characters can
   --  decode to. A length of 1 modulo 4 is not a valid unpadded encoding at
   --  all, and a padded one is always a multiple of 4 (it may decode to up to
   --  two octets fewer than the figure given, for its `=`).
   --  @param Length the number of characters
   --  @param Padded whether the encoding is padded
   --  @return the octet count, or 0 when Length cannot be an encoding
   function Decoded_Length
     (Length : Natural; Padded : Boolean := False) return Natural;

   --  Encode.
   --  @param Data   the octets to encode
   --  @param Into   out: the characters, from Into'First
   --  @param Last   out: the last character written, Into'First - 1 when Into
   --    is too small
   --  @param Padded whether to end a short final group with `=` (one for two
   --    octets, two for one) so that the length is a multiple of 4
   procedure Encode
     (Data   : Ada.Streams.Stream_Element_Array;
      Into   : out String;
      Last   : out Natural;
      Padded : Boolean := False);

   --  Decode, strictly.
   --
   --  Refuses anything that is not the exact encoding of some octet string:
   --  a character outside the alphabet, whitespace, padding where Padded is
   --  False, missing or misplaced padding where it is True, a length of 1
   --  modulo 4, and a final group whose unused low bits are not zero -- the
   --  last of these being what lets two different strings decode to the same
   --  octets, which a format that is compared as text must not allow.
   --  @param Text  the characters to decode
   --  @param Into  out: the octets, from Into'First; all zero on a refusal
   --  @param Last  out: the last octet written, Into'First - 1 on failure
   --  @param Valid out: True only when Text is exactly an encoding
   --  @param Padded whether Text must end in `=` to a multiple of 4 (when
   --    False, it must contain none)
   procedure Decode
     (Text   : String;
      Into   : out Ada.Streams.Stream_Element_Array;
      Last   : out Ada.Streams.Stream_Element_Offset;
      Valid  : out Boolean;
      Padded : Boolean := False);

end CryptoLib.Base64;
