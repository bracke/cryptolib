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
--
--  This package offers two different AEADs that share ChaCha20 and Poly1305
--  and agree on nothing else. Seal/Open are the OpenSSH construction above.
--  Seal_AEAD/Open_AEAD are RFC 8439's standard AEAD_CHACHA20_POLY1305 -- one
--  32-byte key, a caller-supplied 96-bit nonce, and authenticated additional
--  data -- which is what TLS, IPsec and everything outside SSH mean by
--  "ChaCha20-Poly1305". They are not interchangeable and neither can read the
--  other's output: the SSH one takes two keys, derives its nonce from the
--  packet sequence number, encrypts a length field separately, and has
--  nowhere to put additional data. The naming follows CryptoLib.Ciphers,
--  where Seal_GCM is likewise the SSH packet format and Seal_AEAD the
--  general-purpose one.
--
--  Every failure path zeroes the out buffer before returning, so a status
--  other than Ok leaves no partial or unauthenticated plaintext behind. Open
--  compares the Poly1305 tag in constant time and zeroes on a mismatch.
--  Callers must still check the status -- an all-zero buffer is a plausible
--  plaintext, not a sentinel.
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

   --  The nonce RFC 8439 takes, in octets. Unlike the SSH construction's,
   --  this one is the caller's to choose and to never repeat under one key.
   Nonce_Length : constant Natural := 12;

   --  The key RFC 8439 takes, in octets -- one key, where the SSH
   --  construction packs two into 64.
   AEAD_Key_Length : constant Natural := 32;

   --  Seal under RFC 8439 AEAD_CHACHA20_POLY1305.
   --
   --  The output is the ciphertext followed by the 16-octet tag, which covers
   --  the additional data as well as the ciphertext. Associated_Data is
   --  authenticated and not encrypted; it may be empty, and so may the
   --  plaintext.
   --
   --  A nonce must never repeat under one key. This takes the nonce rather
   --  than deriving it because the protocols that use this AEAD each derive
   --  it their own way -- TLS 1.3 exclusive-ors a record sequence number into
   --  a static IV -- and a nonce invented here would be wrong for all of
   --  them.
   --  @param Key_Data        the 32-octet key
   --  @param Nonce           the 12-octet nonce, unique per key
   --  @param Associated_Data data to authenticate but not encrypt; may be empty
   --  @param Plaintext       the data to encrypt; may be empty
   --  @param Wire            out: ciphertext then tag, Plaintext'Length +
   --    Tag_Length octets, zeroed on failure
   --  @return Ok, or Handshake_Failed on a wrong-length key, nonce or output
   function Seal_AEAD
     (Key_Data        : Ada.Streams.Stream_Element_Array;
      Nonce           : Ada.Streams.Stream_Element_Array;
      Associated_Data : Ada.Streams.Stream_Element_Array;
      Plaintext       : Ada.Streams.Stream_Element_Array;
      Wire            : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Open what Seal_AEAD sealed.
   --
   --  The tag is verified in constant time before any plaintext is produced,
   --  so a forged or altered packet yields no plaintext to discard.
   --  @param Key_Data        the 32-octet key
   --  @param Nonce           the 12-octet nonce used to seal
   --  @param Associated_Data the data authenticated when sealing; may be empty
   --  @param Wire            ciphertext then the 16-octet tag
   --  @param Plaintext       out: the recovered plaintext, Wire'Length -
   --    Tag_Length octets, zeroed on failure or on a bad tag
   --  @return Ok, or Handshake_Failed on a wrong-length argument or a tag
   --    that does not match
   function Open_AEAD
     (Key_Data        : Ada.Streams.Stream_Element_Array;
      Nonce           : Ada.Streams.Stream_Element_Array;
      Associated_Data : Ada.Streams.Stream_Element_Array;
      Wire            : Ada.Streams.Stream_Element_Array;
      Plaintext       : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

end CryptoLib.ChaCha20_Poly1305;
