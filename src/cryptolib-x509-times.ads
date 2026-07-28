with CryptoLib.ASN1;
with CryptoLib.ASN1.Errors;

--  @summary Decoding the times X.509 writes.
--
--  Its own package because certificates and revocation lists both carry these
--  and neither should have its own reader. A validity window and a nextUpdate
--  are the same encoding read for different reasons, and two readers of one
--  encoding are two chances to read it differently.
package CryptoLib.X509.Times is
   pragma Preelaborate;

   --  Read a UTCTime or GeneralizedTime.
   --
   --  RFC 5280 pins both to UTC, with seconds present and a trailing Z, which
   --  is narrower than ASN.1 permits. The wider forms are refused rather than
   --  interpreted: accepting one would mean guessing a zone, and a validity
   --  window guessed wrong is a certificate honoured after it expired.
   --  @param Data the buffer to read from
   --  @param Position where to read; advanced past the time on success
   --  @param Last the last offset the time may occupy
   --  @param Depth the nesting depth this call is made at
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Value receives the decoded time
   --  @param Status Ok on success, otherwise why it was refused
   procedure Read
     (Data     : CryptoLib.ASN1.Octets;
      Position : in out CryptoLib.ASN1.Offset;
      Last     : CryptoLib.ASN1.Offset;
      Depth    : Natural;
      Limits   : CryptoLib.ASN1.Decode_Limits;
      Value    : out Certificate_Time;
      Status   : out CryptoLib.ASN1.Errors.Decode_Status);

end CryptoLib.X509.Times;
