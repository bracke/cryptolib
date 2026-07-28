with CryptoLib.ASN1;

--  @summary Types shared across the X.509 layer.
--
--  A certificate says who, by whom, for how long, and with which key. The
--  types here are the vocabulary for those answers, kept apart from the
--  decoder so that a caller inspecting a certificate does not have to know
--  how one is parsed.
package CryptoLib.X509 is
   pragma Preelaborate;

   subtype Octets is CryptoLib.ASN1.Octets;
   subtype Offset is CryptoLib.ASN1.Offset;

   --  What a certificate's subject public key is.
   --
   --  Named rather than described so that a caller can refuse an algorithm
   --  without having to recognise an OID. Unknown is not a failure to parse:
   --  a certificate carrying a key this crate cannot use is still a
   --  certificate, and its other fields still mean what they say.
   type Public_Key_Algorithm is
     (RSA,
      ECDSA_P256,
      ECDSA_P384,
      ECDSA_P521,
      Ed25519,
      Ed448,
      Unknown_Public_Key_Algorithm);

   --  How a certificate was signed.
   --
   --  This is the algorithm named in the certificate, not one this crate can
   --  necessarily verify. Whether it can is a separate question, and
   --  conflating the two would make an unverifiable certificate look
   --  malformed.
   type Signature_Algorithm is
     (SHA256_With_RSA,
      SHA384_With_RSA,
      SHA512_With_RSA,
      RSASSA_PSS,
      ECDSA_With_SHA256,
      ECDSA_With_SHA384,
      ECDSA_With_SHA512,
      Ed25519_Signature,
      Ed448_Signature,
      Unknown_Signature_Algorithm);

   --  Which naming attribute a distinguished-name entry carries.
   type Attribute_Kind is
     (Common_Name,
      Organization,
      Organizational_Unit,
      Country,
      Locality,
      State_Or_Province,
      Serial_Number_Attribute,
      Domain_Component,
      Email_Address,
      Unknown_Attribute);

   --  A point in time as a certificate states it.
   --
   --  Held as its parts rather than as an Ada time because a certificate's
   --  validity is written in UTC with second resolution and no zone, and
   --  converting on the way in would introduce a zone and a calendar that the
   --  certificate never mentioned. Comparison for validity is a separate
   --  operation on these fields.
   type Certificate_Time is record
      Year   : Natural := 0;
      Month  : Natural := 0;
      Day    : Natural := 0;
      Hour   : Natural := 0;
      Minute : Natural := 0;
      Second : Natural := 0;
   end record;

   --  Is Left at or before Right?
   --  @param Left the earlier candidate
   --  @param Right the later candidate
   --  @return True when Left is not after Right
   function Is_Not_After
     (Left : Certificate_Time; Right : Certificate_Time) return Boolean;

end CryptoLib.X509;
