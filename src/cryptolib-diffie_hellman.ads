with Ada.Streams;
with CryptoLib.Random;
with CryptoLib.Errors;
with CryptoLib.Buffers;

--  @summary Finite-field SSH Diffie-Hellman for the fixed MODP groups 1, 14,
--  16 and 18.
--
--  Implements client-side key generation and shared-secret computation for the
--  RFC 4253 / RFC 3526 Oakley groups: group1 (1024-bit legacy), group14
--  (2048-bit), group16 (4096-bit) and group18 (8192-bit).  Public values and
--  shared secrets are exchanged as SSH mpints; the modular exponentiations for
--  the large groups run through CryptoLib.Modexp because they exceed GNAT's
--  big-integer cap.  Peer public values are range-validated before use.
package CryptoLib.Diffie_Hellman is

   type Supported_Gex_Group is (No_Supported_Gex_Group, Gex_Group14, Gex_Group16, Gex_Group18);

   --  Identify which supported group-exchange (GEX) group a server-offered
   --  (prime, generator) pair corresponds to, or No_Supported_Gex_Group.
   --  @param Prime_Value     the group modulus as a big-endian byte string
   --  @param Generator_Value the group generator as a big-endian byte string
   --  @return the matching Supported_Gex_Group, or No_Supported_Gex_Group
   function Select_Group_Exchange_Group
     (Prime_Value     : Ada.Streams.Stream_Element_Array;
      Generator_Value : Ada.Streams.Stream_Element_Array)
      return Supported_Gex_Group;

   --  Generate a group14 client ephemeral, returning only the public value
   --  (a convenience wrapper over Generate_Group14_Keypair that discards the
   --  private exponent).
   --  @param Source_Item  the randomness source for the private exponent
   --  @param Public_Value out: the client public value g**x mod p as an mpint
   --  @return Ok on success, or an error status on failure
   function Generate_Group14_Client_Value
     (Source_Item : in out CryptoLib.Random.Random_Source;
      Public_Value : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Generate a group1 (1024-bit) ephemeral DH keypair.
   --  @param Source_Item   the randomness source for the private exponent
   --  @param Private_Value out: the private exponent as fixed-width bytes
   --  @param Public_Value  out: the public value g**x mod p as an mpint
   --  @return Ok on success, or an error status on failure
   function Generate_Group1_Keypair
     (Source_Item   : in out CryptoLib.Random.Random_Source;
      Private_Value : out CryptoLib.Buffers.Packet_Buffer;
      Public_Value  : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Compute the group1 shared secret from the client private exponent and the
   --  server public value, validating the peer value lies in (1, p-1).
   --  @param Client_Private_Placeholder the client's private exponent as
   --                                     fixed-width big-endian bytes
   --  @param Server_Public_Value        the server public value as an mpint
   --  @param Shared_Secret              out: the shared secret as an mpint
   --  @return Ok on success, or Handshake_Failed / error status on failure
   function Compute_Group1_Shared_Secret
     (Client_Private_Placeholder : Ada.Streams.Stream_Element_Array;
      Server_Public_Value        : Ada.Streams.Stream_Element_Array;
      Shared_Secret              : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Generate a group14 (2048-bit) ephemeral DH keypair.
   --  @param Source_Item   the randomness source for the private exponent
   --  @param Private_Value out: the private exponent as fixed-width bytes
   --  @param Public_Value  out: the public value g**x mod p as an mpint
   --  @return Ok on success, or an error status on failure
   function Generate_Group14_Keypair
     (Source_Item   : in out CryptoLib.Random.Random_Source;
      Private_Value : out CryptoLib.Buffers.Packet_Buffer;
      Public_Value  : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Compute the group14 shared secret from the client private exponent and
   --  the server public value, validating the peer value lies in (1, p-1).
   --  @param Client_Private_Placeholder the client's private exponent as
   --                                     fixed-width big-endian bytes
   --  @param Server_Public_Value        the server public value as an mpint
   --  @param Shared_Secret              out: the shared secret as an mpint
   --  @return Ok on success, or Handshake_Failed / error status on failure
   function Compute_Group14_Shared_Secret
     (Client_Private_Placeholder : Ada.Streams.Stream_Element_Array;
      Server_Public_Value        : Ada.Streams.Stream_Element_Array;
      Shared_Secret              : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Generate a group16 (4096-bit) ephemeral DH keypair.
   --  @param Source_Item   the randomness source for the private exponent
   --  @param Private_Value out: the private exponent as fixed-width bytes
   --  @param Public_Value  out: the public value g**x mod p as an mpint
   --  @return Ok on success, or an error status on failure
   function Generate_Group16_Keypair
     (Source_Item   : in out CryptoLib.Random.Random_Source;
      Private_Value : out CryptoLib.Buffers.Packet_Buffer;
      Public_Value  : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Compute the group16 shared secret from the client private exponent and
   --  the server public value, validating the peer value lies in (1, p-1).
   --  @param Client_Private_Placeholder the client's private exponent as
   --                                     fixed-width big-endian bytes
   --  @param Server_Public_Value        the server public value as an mpint
   --  @param Shared_Secret              out: the shared secret as an mpint
   --  @return Ok on success, or Handshake_Failed / error status on failure
   function Compute_Group16_Shared_Secret
     (Client_Private_Placeholder : Ada.Streams.Stream_Element_Array;
      Server_Public_Value        : Ada.Streams.Stream_Element_Array;
      Shared_Secret              : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Generate a group18 (8192-bit) ephemeral DH keypair.
   --  @param Source_Item   the randomness source for the private exponent
   --  @param Private_Value out: the private exponent as fixed-width bytes
   --  @param Public_Value  out: the public value g**x mod p as an mpint
   --  @return Ok on success, or an error status on failure
   function Generate_Group18_Keypair
     (Source_Item   : in out CryptoLib.Random.Random_Source;
      Private_Value : out CryptoLib.Buffers.Packet_Buffer;
      Public_Value  : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Compute the group18 shared secret from the client private exponent and
   --  the server public value, validating the peer value lies in (1, p-1).
   --  @param Client_Private_Placeholder the client's private exponent as
   --                                     fixed-width big-endian bytes
   --  @param Server_Public_Value        the server public value as an mpint
   --  @param Shared_Secret              out: the shared secret as an mpint
   --  @return Ok on success, or Handshake_Failed / error status on failure
   function Compute_Group18_Shared_Secret
     (Client_Private_Placeholder : Ada.Streams.Stream_Element_Array;
      Server_Public_Value        : Ada.Streams.Stream_Element_Array;
      Shared_Secret              : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;
end CryptoLib.Diffie_Hellman;
