private with Ada.Finalization;

with CryptoLib.ASN1;
with CryptoLib.PKCS8;
with CryptoLib.X509;

--  @summary Reading a PKCS#12 bundle.
--
--  A bundle carries a private key and the certificates that go with it, under
--  one password. This crate could write one and not read one, which is the
--  kind of asymmetry that leaves a caller unable to check what it just
--  produced.
--
--  The MAC is checked before anything inside is believed. A bundle's contents
--  are protected by a password, and the MAC is what says the password was
--  right and that nobody has altered the bundle since; reading bags out of an
--  unverified bundle would mean parsing whatever an attacker chose to put
--  there and calling the results a key and a certificate.
--
--  Holds a private key, so it is limited and scrubs itself when it goes out
--  of scope.
--
--  What is read: the shrouded and unshrouded key bags, and the X.509
--  certificate bags, whether they sit in plain or PBES2-encrypted content. A
--  bundle using other content protection is refused rather than half-read.
package CryptoLib.PKCS12 is

   subtype Decode_Limits is CryptoLib.ASN1.Decode_Limits;
   subtype Octets is CryptoLib.ASN1.Octets;
   subtype Offset is CryptoLib.ASN1.Offset;

   --  What will be held from one bundle.
   Maximum_Certificates : constant := 8;
   Maximum_Content_Size : constant := 64 * 1024;

   type Open_Status is
     (Ok,
      Malformed,
      Unsupported_Scheme,
      --  A content protection or bag type this crate does not implement. The
      --  bundle may be perfectly good; this cannot read it.
      Wrong_Password_Or_Corrupt,
      --  The MAC does not check out. As in PKCS#8, the two are one answer
      --  because they cannot be told apart and a caller can do nothing
      --  different about either.
      No_Mac,
      --  The bundle carries no MAC at all, so nothing vouches for its
      --  contents. Refused rather than read hopefully: a bundle nobody
      --  authenticated is a bundle anybody could have written.
      Too_Many_Certificates,
      Too_Large);

   type Bundle is limited private;

   --  Render an open status as short diagnostic text.
   --  @param Status the status to describe
   --  @return lower-case text naming the status
   function Status_Image (Status : Open_Status) return String;

   --  Open a bundle.
   --  @param Data the DER encoding of the PFX
   --  @param Password the password protecting it
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Item receives the bundle's contents
   --  @param Status Ok on success, otherwise why it was not opened
   procedure Open
     (Data     : Octets;
      Password : String;
      Limits   : Decode_Limits;
      Item     : out Bundle;
      Status   : out Open_Status);

   --  Did this open?
   --  @param Item the bundle to inspect
   --  @return True when it holds verified contents
   function Is_Present (Item : Bundle) return Boolean;

   --  How many certificates the bundle carried.
   --  @param Item the bundle to inspect
   --  @return the number of certificates
   function Certificate_Count (Item : Bundle) return Natural;

   --  One certificate's encoding.
   --  @param Item the bundle to inspect
   --  @param Index which certificate, one through Certificate_Count
   --  @return that certificate's DER
   function Certificate_Bytes
     (Item : Bundle; Index : Positive) return Octets;

   --  Did the bundle carry a private key?
   --  @param Item the bundle to inspect
   --  @return True when a key was found and decoded
   function Has_Private_Key (Item : Bundle) return Boolean;

   --  What kind of key the bundle carried.
   --  @param Item the bundle to inspect
   --  @return the key algorithm
   function Key_Algorithm_Of
     (Item : Bundle) return CryptoLib.X509.Public_Key_Algorithm;

   --  The private value the key holds: an EC scalar or an Ed25519 seed.
   --
   --  Secret. A caller that copies this out has taken responsibility for
   --  scrubbing the copy.
   --  @param Item the bundle to inspect
   --  @return the scalar or seed, empty when there is none
   function Private_Value (Item : Bundle) return Octets;

   --  Overwrite what the bundle holds now rather than at end of scope.
   --  @param Item the bundle to scrub
   procedure Wipe (Item : in out Bundle);

private

   type Span is record
      First : Offset := 1;
      Last  : Offset := 0;
   end record;

   type Span_Array is array (1 .. Maximum_Certificates) of Span;

   type Bundle is limited new Ada.Finalization.Limited_Controlled with record
      Present : Boolean := False;
      Count   : Natural := 0;
      Spans   : Span_Array;
      Filled  : Offset := 0;
      Certs   : Octets (1 .. Maximum_Content_Size) := [others => 0];
      Key     : CryptoLib.PKCS8.Private_Key;
      Has_Key : Boolean := False;
   end record;

   overriding procedure Finalize (Item : in out Bundle);

end CryptoLib.PKCS12;
