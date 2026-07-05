with Ada.Streams;
with Interfaces;
with CryptoLib.Errors;

--  @summary Symmetric block ciphers for the SSH transport and archive formats.
--
--  Constant-time, table-free implementations of AES (CTR, CBC and GCM), 3DES
--  and DES (CBC) and RC2 (CBC). A stateful Cipher_State drives the streaming
--  SSH modes (AES-CTR / AES-CBC / 3DES-CBC), while the *_Raw, ZIP and GCM
--  entry points are one-shot helpers keyed per call. Algorithms are selected by
--  their SSH/OpenSSL name string (e.g. "aes256-ctr", "3des-cbc", "rc2-128-cbc",
--  "aes128-gcm@openssh.com").
package CryptoLib.Ciphers is

   AES_GCM_Tag_Length : constant Natural := 16;
   --  Traffic direction, used to select the correct key/IV half of an SSH pair.
   type Cipher_Direction is (Client_To_Server, Server_To_Client);
   --  Opaque per-direction cipher context (round keys, mode, CTR counter).
   type Cipher_State is private;

   --  Clear a cipher context back to its inert default state, wiping any
   --  retained key schedule and counter material.
   --  @param Item the cipher context to reset
   procedure Reset (Item : out Cipher_State)
     with SPARK_Mode => On;

   --  Configure a cipher context for a named streaming algorithm, expanding the
   --  key schedule and loading the initial counter/IV. Supports the SSH names
   --  aes{128,192,256}-{ctr,cbc} and 3des-cbc.
   --  @param Item           the cipher context to initialize
   --  @param Algorithm_Name the SSH cipher name selecting algorithm and mode
   --  @param Direction_Item whether this context is client-to-server or
   --                        server-to-client traffic
   --  @param Key_Data       the raw key bytes (>= the algorithm's key length)
   --  @param IV_Data        the initial IV/counter (16 bytes for AES, 8 for 3DES)
   --  @return Ok on success, Handshake_Failed on a short key/IV,
   --          Unsupported_Feature for an unknown name, Internal_Error on an
   --          unexpected exception
   function Initialize
     (Item           : in out Cipher_State;
      Algorithm_Name : String;
      Direction_Item : Cipher_Direction;
      Key_Data       : Ada.Streams.Stream_Element_Array;
      IV_Data        : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Report whether a cipher context has been successfully initialized.
   --  @param Item the cipher context to query
   --  @return True if Item is ready to encrypt/decrypt, False otherwise
   function Is_Active (Item : Cipher_State) return Boolean
     with SPARK_Mode => On;

   --  Report the cipher's block size in bytes (16 for AES, 8 for 3DES; 8 when
   --  the context is inactive).
   --  @param Item the cipher context to query
   --  @return the block size in bytes
   function Block_Size (Item : Cipher_State) return Natural
     with SPARK_Mode => On;

   --  Encrypt a buffer with an active streaming context, advancing its mode
   --  state (CTR keystream position or CBC/3DES chaining block).
   --  @param Item      the active cipher context, updated in place
   --  @param Plaintext the input bytes (a whole number of blocks for CBC/3DES)
   --  @param Output    the ciphertext; must be the same length as Plaintext
   --  @return Ok on success, Handshake_Failed if inactive, Internal_Error on a
   --          size mismatch or unexpected exception
   function Encrypt
     (Item      : in out Cipher_State;
      Plaintext : Ada.Streams.Stream_Element_Array;
      Output    : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Decrypt a buffer with an active streaming context, advancing its mode
   --  state (CTR keystream position or CBC/3DES chaining block).
   --  @param Item       the active cipher context, updated in place
   --  @param Ciphertext the input bytes (a whole number of blocks for CBC/3DES)
   --  @param Output     the plaintext; must be the same length as Ciphertext
   --  @return Ok on success, Handshake_Failed if inactive, Internal_Error on a
   --          size mismatch or unexpected exception
   function Decrypt
     (Item       : in out Cipher_State;
      Ciphertext : Ada.Streams.Stream_Element_Array;
      Output     : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  One-shot CBC decrypt keyed per call. Handles aes{128,192,256}-cbc,
   --  des-cbc/3des-cbc and rc2-{40,64,128}-cbc; the caller supplies the IV and
   --  is responsible for any padding removal.
   --  @param Algorithm_Name the OpenSSL cipher name selecting the algorithm
   --  @param Key_Data       the raw key bytes for the chosen algorithm
   --  @param IV_Data        the initial chaining IV (>= one block)
   --  @param Ciphertext     the input, a whole number of blocks
   --  @param Plaintext      the decrypted output; same length as Ciphertext
   --  @return Ok on success, Authentication_Failed on a size mismatch,
   --          Unsupported_Feature for an unknown name, Internal_Error on an
   --          unexpected exception
   function Decrypt_CBC_Raw
     (Algorithm_Name : String;
      Key_Data       : Ada.Streams.Stream_Element_Array;
      IV_Data        : Ada.Streams.Stream_Element_Array;
      Ciphertext     : Ada.Streams.Stream_Element_Array;
      Plaintext      : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  One-shot AES-CBC encrypt keyed per call (aes{128,192,256}-cbc). The
   --  caller supplies block-aligned, pre-padded plaintext and the IV.
   --  @param Algorithm_Name the AES-CBC cipher name selecting the key size
   --  @param Key_Data       the raw AES key bytes
   --  @param IV_Data        the initial chaining IV (16 bytes)
   --  @param Plaintext      the input, a whole number of 16-byte blocks
   --  @param Ciphertext     the encrypted output; same length as Plaintext
   --  @return Ok on success, Authentication_Failed on a size mismatch,
   --          Unsupported_Feature for an unknown name, Internal_Error on an
   --          unexpected exception
   function Encrypt_CBC_Raw
     (Algorithm_Name : String;
      Key_Data       : Ada.Streams.Stream_Element_Array;
      IV_Data        : Ada.Streams.Stream_Element_Array;
      Plaintext      : Ada.Streams.Stream_Element_Array;
      Ciphertext     : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Apply the ZIP WinZip AES-CTR keystream (little-endian counter starting at
   --  1) to a buffer; the XOR is its own inverse, so this both encrypts and
   --  decrypts. Selects the key size from an aes{128,192,256}[-ctr] name.
   --  @param Algorithm_Name the AES variant name selecting the key size
   --  @param Key_Data       the raw AES key bytes
   --  @param Input_Data     the input bytes (plaintext or ciphertext)
   --  @param Output_Data    the transformed output; same length as Input_Data
   --  @return Ok on success, Unsupported_Feature for an unknown name,
   --          Internal_Error on a size mismatch or unexpected exception
   function Apply_ZIP_AES_CTR
     (Algorithm_Name : String;
      Key_Data       : Ada.Streams.Stream_Element_Array;
      Input_Data     : Ada.Streams.Stream_Element_Array;
      Output_Data    : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Return the key length in bytes for an aes-gcm@openssh.com algorithm name.
   --  @param Algorithm_Name the GCM cipher name
   --  @return 16 for aes128-gcm@openssh.com, 32 for aes256-gcm@openssh.com,
   --          0 for any other name
   function AES_GCM_Key_Length (Algorithm_Name : String) return Natural
     with SPARK_Mode => On;

   --  Recover the 4-byte packet length for aes-gcm@openssh.com. The length is
   --  transmitted in the clear as GCM additional data, so this is the identity
   --  transform, kept as a uniform seam alongside the ChaCha20 length step.
   --  @param Algorithm_Name the GCM cipher name (unused; uniform signature)
   --  @param Key_Data       the GCM key (unused; uniform signature)
   --  @param IV_Data        the GCM IV (unused; uniform signature)
   --  @param Sequence       the SSH packet sequence number (unused)
   --  @param Header         the 4-byte cleartext length field from the wire
   --  @param Output         the 4-byte length field (a copy of Header)
   --  @return Ok on success, Handshake_Failed on a bad length, Internal_Error
   --          on an unexpected exception
   function Encrypt_GCM_Length
     (Algorithm_Name : String;
      Key_Data       : Ada.Streams.Stream_Element_Array;
      IV_Data        : Ada.Streams.Stream_Element_Array;
      Sequence       : Interfaces.Unsigned_32;
      Header         : Ada.Streams.Stream_Element_Array;
      Output         : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Seal one SSH packet with aes-gcm@openssh.com: encrypt the body with
   --  AES-GCM keeping the 4-byte length field in the clear as AAD, and append
   --  the 16-byte GCM tag over (length, ciphertext).
   --  @param Algorithm_Name the GCM cipher name selecting the key size
   --  @param Key_Data       the AES-GCM key bytes
   --  @param IV_Data        the 12-byte GCM nonce (caller increments per packet)
   --  @param Sequence       the SSH packet sequence number (unused; IV carries
   --                        per-packet uniqueness)
   --  @param Plain_Packet   the cleartext packet: 4-byte length followed by body
   --  @param Wire_Packet    the sealed output; length must be
   --                        Plain_Packet'Length + AES_GCM_Tag_Length
   --  @return Ok on success, Internal_Error on a size mismatch or unexpected
   --          exception, or the propagated init failure status
   function Seal_GCM
     (Algorithm_Name : String;
      Key_Data       : Ada.Streams.Stream_Element_Array;
      IV_Data        : Ada.Streams.Stream_Element_Array;
      Sequence       : Interfaces.Unsigned_32;
      Plain_Packet   : Ada.Streams.Stream_Element_Array;
      Wire_Packet    : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Open one aes-gcm@openssh.com packet: verify the trailing 16-byte tag over
   --  (cleartext length, ciphertext) in constant time and, only on a match,
   --  AES-GCM-decrypt the body.
   --  @param Algorithm_Name the GCM cipher name selecting the key size
   --  @param Key_Data       the AES-GCM key bytes
   --  @param IV_Data        the 12-byte GCM nonce (matching the sender's)
   --  @param Sequence       the SSH packet sequence number (unused)
   --  @param Wire_Packet    the sealed packet: cleartext length, ciphertext
   --                        body, trailing 16-byte tag
   --  @param Plain_Packet   the recovered cleartext; length must be
   --                        Wire_Packet'Length - AES_GCM_Tag_Length
   --  @return Ok on success, Handshake_Failed on a size mismatch or tag
   --          verification failure, Internal_Error on an unexpected exception
   function Open_GCM
     (Algorithm_Name : String;
      Key_Data       : Ada.Streams.Stream_Element_Array;
      IV_Data        : Ada.Streams.Stream_Element_Array;
      Sequence       : Interfaces.Unsigned_32;
      Wire_Packet    : Ada.Streams.Stream_Element_Array;
      Plain_Packet   : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

private
   type AES_Round_Index is range 0 .. 14;
   type AES_Word_Index is range 0 .. 59;
   type AES_Round_Key_Words is
     array (AES_Word_Index) of Interfaces.Unsigned_32;
   type Counter_Block is
     array (Natural range 0 .. 15) of Interfaces.Unsigned_8;
   type Cipher_Mode is (CTR_Mode, CBC_Mode, DES3_CBC_Mode);
   subtype DES3_Key_Buffer is Ada.Streams.Stream_Element_Array (1 .. 24);

   type Cipher_State is record
      Active_Item       : Boolean := False;
      Direction_Value   : Cipher_Direction := Client_To_Server;
      Mode_Value        : Cipher_Mode := CTR_Mode;
      Round_Count       : Natural range 0 .. 14 := 0;
      Round_Keys        : AES_Round_Key_Words := [others => 0];
      DES3_Key_Data     : DES3_Key_Buffer := [others => 0];
      Counter_Value     : Counter_Block := [others => 0];
      CTR_Stream_Value  : Counter_Block := [others => 0];
      CTR_Stream_Offset : Natural range 0 .. 16 := 16;
   end record;
end CryptoLib.Ciphers;
