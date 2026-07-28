private with Ada.Finalization;
private with CryptoLib.PKCS8;

with CryptoLib.ASN1;
with CryptoLib.X509;
with CryptoLib.X509.Certificates;

--  @summary A certificate chain and the private key that goes with it.
--
--  What a server or a client is configured with, checked before it is used.
--  The mistake this exists to catch is the ordinary one: a certificate and a
--  key that do not belong together, or a chain assembled in the wrong order,
--  discovered at the first handshake rather than at startup. Both are
--  answerable from the material alone.
--
--  Holds a private key, so it is limited and scrubs itself when it goes out
--  of scope.
--
--  Deciding the material is well formed is not deciding it is trusted. This
--  says the key matches the leaf and the chain hangs together; whether anyone
--  should believe the chain is a question for
--  CryptoLib.X509.Validation, with trust anchors this package knows nothing
--  about.
package CryptoLib.Identities is

   subtype Certificate is CryptoLib.X509.Certificates.Certificate;
   subtype Octets is CryptoLib.ASN1.Octets;

   --  Bounds on what will be held. A chain longer or larger than this is
   --  refused rather than truncated: a silently shortened chain is one that
   --  fails to verify for a reason nobody can see.
   Maximum_Chain      : constant := 8;
   Maximum_Chain_Size : constant := 32 * 1024;

   type Identity_Status is
     (Ok,
      Empty_Chain,
      --  No certificate in the text at all.
      Chain_Too_Long,
      Chain_Too_Large,
      Malformed_Certificate,
      Malformed_Private_Key,
      Key_Mismatch,
      --  The private key does not belong to the leaf certificate. The
      --  configuration error this is here for.
      Chain_Out_Of_Order,
      --  A certificate in the chain was not issued by the one after it.
      --  Checked by name, not by signature: getting the order wrong is a
      --  configuration mistake, and a wrong order that happened to verify is
      --  not a thing that occurs.
      Unsupported_Key);
      --  A key this crate cannot derive a public key from, so the match
      --  cannot be decided. Deliberately not Ok: an unchecked identity must
      --  not be indistinguishable from a checked one.

   type Local_Identity is limited private;

   --  Render an identity status as short diagnostic text.
   --  @param Status the status to describe
   --  @return lower-case text naming the status
   function Status_Image (Status : Identity_Status) return String;

   --  Read a chain and its key, and check they belong together.
   --
   --  The chain is leaf first, as it is written in a PEM file and as TLS
   --  sends it.
   --  @param Certificate_Chain_PEM one or more certificates in PEM form
   --  @param Private_Key_PEM the private key in unencrypted PKCS#8 PEM form
   --  @param Item receives the identity when the material checks out
   --  @param Status Ok, or what is wrong with the material
   procedure Decode
     (Certificate_Chain_PEM : String;
      Private_Key_PEM       : String;
      Item                  : out Local_Identity;
      Status                : out Identity_Status);

   --  Did this check out?
   --  @param Item the identity to inspect
   --  @return True when it holds checked material
   function Is_Present (Item : Local_Identity) return Boolean;

   --  How many certificates the chain holds.
   --  @param Item the identity to inspect
   --  @return the number of certificates, leaf included
   function Chain_Length (Item : Local_Identity) return Natural;

   --  One certificate's encoding, one being the leaf.
   --  @param Item the identity to inspect
   --  @param Index which certificate, one through Chain_Length
   --  @return that certificate's DER
   function Certificate_Bytes
     (Item : Local_Identity; Index : Positive) return Octets;

   --  What kind of key the identity holds.
   --  @param Item the identity to inspect
   --  @return the key algorithm
   function Key_Algorithm_Of
     (Item : Local_Identity) return CryptoLib.X509.Public_Key_Algorithm;

   --  Overwrite the key now rather than at end of scope.
   --  @param Item the identity to scrub
   procedure Wipe (Item : in out Local_Identity);

private

   type Span is record
      First : CryptoLib.ASN1.Offset := 1;
      Last  : CryptoLib.ASN1.Offset := 0;
   end record;

   type Span_Array is array (1 .. Maximum_Chain) of Span;

   type Local_Identity is limited new Ada.Finalization.Limited_Controlled with
      record
         Present : Boolean := False;
         Count   : Natural := 0;
         Spans   : Span_Array;
         Held    : CryptoLib.ASN1.Offset := 0;
         Chain   : Octets (1 .. Maximum_Chain_Size) := [others => 0];
         Key     : CryptoLib.PKCS8.Private_Key;
      end record;

   overriding procedure Finalize (Item : in out Local_Identity);

end CryptoLib.Identities;
