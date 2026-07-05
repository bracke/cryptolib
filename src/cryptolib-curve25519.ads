with Ada.Streams;
with CryptoLib.Random;
with CryptoLib.Errors;

--  @summary X25519 (Curve25519) elliptic-curve Diffie-Hellman key agreement.
--
--  Implements RFC 7748 X25519: scalar clamping, a constant-time Montgomery
--  ladder over the field 2**255 - 19, and rejection of the all-zero
--  (low-order-point) shared secret.  Keys and secrets are little-endian
--  32-byte values.
package CryptoLib.Curve25519 is

   subtype Public_Key_Index is Positive range 1 .. 32;
   type Public_Key is array (Public_Key_Index) of Ada.Streams.Stream_Element;
   type Private_Key is private;

   --  Generate a fresh keypair: draw 32 random bytes as the private scalar and
   --  compute the public key as X25519(scalar, base point 9).
   --  @param Source_Item  the CSPRNG the private scalar is drawn from
   --  @param Private_Item the generated private key (cleared on any failure)
   --  @param Public_Item  the resulting 32-byte public key
   --  @return Ok on success, the random source's error status, or Internal_Error
   function Generate_Keypair
     (Source_Item : in out CryptoLib.Random.Random_Source;
      Private_Item : out Private_Key;
      Public_Item : out Public_Key)
      return CryptoLib.Errors.Status;

   --  Non-elidable zeroization of private Curve25519 scalar material.
   --  @param Private_Item the private key whose scalar bytes are erased
   procedure Clear (Private_Item : out Private_Key);
   --  Best-effort erasure of private Curve25519 scalar material.

   --  Zero a public-key-sized buffer (also used for shared-secret buffers).
   --  @param Public_Item the 32-byte buffer to erase
   procedure Clear (Public_Item : out Public_Key);
   --  Best-effort erasure of public-sized Curve25519 buffers, including
   --  shared-secret buffers used by the live KEX path.

   --  Compute the X25519 shared secret from a local private key and the peer's
   --  public key; fails closed on an all-zero (low-order) result.
   --  @param Private_Item the local X25519 private key
   --  @param Peer_Public  the 32-byte peer public key (u-coordinate)
   --  @param Secret_Item  the resulting 32-byte shared secret (zeroed on failure)
   --  @return Ok on success, Handshake_Failed if the key is invalid or the
   --          shared secret is all-zero, Internal_Error on an internal fault
   function Shared_Secret
     (Private_Item : Private_Key;
      Peer_Public  : Public_Key;
      Secret_Item  : out Public_Key)
      return CryptoLib.Errors.Status;

   --  Deterministic X25519 scalar multiplication of a raw scalar and peer point.
   --  @param Scalar_Item the 32-byte scalar (clamped internally per RFC 7748)
   --  @param Peer_Public the 32-byte peer u-coordinate
   --  @param Secret_Item the resulting 32-byte shared secret (zeroed on failure)
   --  @return Ok, Handshake_Failed on an all-zero result, or Internal_Error
   function Compute_Raw
     (Scalar_Item : Public_Key;
      Peer_Public : Public_Key;
      Secret_Item : out Public_Key)
      return CryptoLib.Errors.Status;
   --  Deterministic X25519 primitive for protocol validation and fixture
   --  coverage.  The scalar is clamped internally exactly like production
   --  key exchange; all-zero shared-secret output fails closed.

private
   type Private_Key is record
      Data : Public_Key := [others => 0];
      Valid : Boolean := False;
   end record;
end CryptoLib.Curve25519;
