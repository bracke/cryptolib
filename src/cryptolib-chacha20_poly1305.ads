with Ada.Streams;
with Interfaces;
with CryptoLib.Errors;

--  @summary The chacha20-poly1305@openssh.com AEAD SSH transport cipher.
--
--  Implements the OpenSSH ChaCha20-Poly1305 construction: two independent
--  256-bit ChaCha20 keys packed as a single 64-byte key (K_2 in bytes 0..31
--  encrypts the packet payload, K_1 in bytes 32..63 encrypts the 4-byte length
--  field), with a Poly1305 one-time key derived from the first keystream block.
--  The 64-bit nonce is the big-endian SSH packet sequence number.
package CryptoLib.ChaCha20_Poly1305 is

   Key_Length : constant Natural := 64;   --  K_2 (0..31) || K_1 (32..63)
   Tag_Length : constant Natural := 16;   --  Poly1305 tag appended to the wire

   --  Encrypt or decrypt the 4-byte packet-length field with the length key
   --  K_1 at ChaCha20 block counter 0 (the keystream XOR is its own inverse).
   --  @param Key_Data the 64-byte key material; only K_1 (bytes 32..63) is used
   --  @param Sequence the SSH packet sequence number, used as the ChaCha20 nonce
   --  @param Header    the 4-byte length field to transform (cleartext or wire)
   --  @param Output    the 4-byte transformed length field
   --  @return Ok on success, Handshake_Failed on a bad length, Internal_Error
   --          on an unexpected exception
   function Encrypt_Length
     (Key_Data : Ada.Streams.Stream_Element_Array;
      Sequence : Interfaces.Unsigned_32;
      Header   : Ada.Streams.Stream_Element_Array;
      Output   : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Seal one SSH packet: encrypt its 4-byte length with K_1 and its body with
   --  K_2 (block counter 1), then append the Poly1305 tag over the whole
   --  ciphertext keyed by the K_2 keystream block 0.
   --  @param Key_Data     the 64-byte key material (K_2 || K_1)
   --  @param Sequence     the SSH packet sequence number, used as the nonce
   --  @param Plain_Packet the cleartext packet: 4-byte length followed by body
   --  @param Wire_Packet  the sealed output; length must be
   --                      Plain_Packet'Length + Tag_Length (encrypted length,
   --                      encrypted body, 16-byte tag)
   --  @return Ok on success, Handshake_Failed on a size mismatch, Internal_Error
   --          on an unexpected exception
   function Seal
     (Key_Data     : Ada.Streams.Stream_Element_Array;
      Sequence     : Interfaces.Unsigned_32;
      Plain_Packet : Ada.Streams.Stream_Element_Array;
      Wire_Packet  : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Open one sealed SSH packet: verify the Poly1305 tag in constant time and,
   --  only if it matches, decrypt the length with K_1 and the body with K_2.
   --  @param Key_Data     the 64-byte key material (K_2 || K_1)
   --  @param Sequence     the SSH packet sequence number, used as the nonce
   --  @param Wire_Packet  the sealed packet: encrypted length, encrypted body,
   --                      trailing 16-byte tag
   --  @param Plain_Packet the recovered cleartext; length must be
   --                      Wire_Packet'Length - Tag_Length
   --  @return Ok on success, Handshake_Failed on a size mismatch or tag
   --          verification failure, Internal_Error on an unexpected exception
   function Open
     (Key_Data     : Ada.Streams.Stream_Element_Array;
      Sequence     : Interfaces.Unsigned_32;
      Wire_Packet  : Ada.Streams.Stream_Element_Array;
      Plain_Packet : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;
end CryptoLib.ChaCha20_Poly1305;
