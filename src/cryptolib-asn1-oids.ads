--  @summary Object identifiers X.509 needs, as their encoded content octets.
--
--  Held encoded rather than as arc numbers because every use is a comparison
--  against a known identifier. Comparing octets answers that directly; going
--  through numbers would mean a decoder in the path of every comparison, and a
--  decoder that mis-parses an identifier is a decoder that can be steered into
--  matching the wrong one.
--
--  The octets here are the content of the OBJECT IDENTIFIER, without its tag
--  and length -- which is exactly what CryptoLib.ASN1.DER.Read_Object_Identifier
--  hands back.
package CryptoLib.ASN1.OIDs is
   pragma Preelaborate;

   --  Naming attributes, 2.5.4.n
   Common_Name         : constant Octets := [16#55#, 16#04#, 16#03#];
   Surname             : constant Octets := [16#55#, 16#04#, 16#04#];
   Serial_Number       : constant Octets := [16#55#, 16#04#, 16#05#];
   Country             : constant Octets := [16#55#, 16#04#, 16#06#];
   Locality            : constant Octets := [16#55#, 16#04#, 16#07#];
   State_Or_Province   : constant Octets := [16#55#, 16#04#, 16#08#];
   Organization        : constant Octets := [16#55#, 16#04#, 16#0A#];
   Organizational_Unit : constant Octets := [16#55#, 16#04#, 16#0B#];
   Given_Name          : constant Octets := [16#55#, 16#04#, 16#2A#];

   --  0.9.2342.19200300.100.1.25
   Domain_Component : constant Octets :=
     [16#09#, 16#92#, 16#26#, 16#89#, 16#93#, 16#F2#, 16#2C#, 16#64#,
      16#01#, 16#19#];

   --  1.2.840.113549.1.9.1
   Email_Address : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#09#, 16#01#];

   --  Public-key algorithms
   RSA_Encryption : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#01#];
   EC_Public_Key  : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#02#, 16#01#];
   Ed25519        : constant Octets := [16#2B#, 16#65#, 16#70#];
   Ed448          : constant Octets := [16#2B#, 16#65#, 16#71#];

   --  Named curves
   Prime256v1 : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#03#, 16#01#, 16#07#];
   Secp384r1  : constant Octets := [16#2B#, 16#81#, 16#04#, 16#00#, 16#22#];
   Secp521r1  : constant Octets := [16#2B#, 16#81#, 16#04#, 16#00#, 16#23#];

   --  Signature algorithms
   SHA256_With_RSA : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#0B#];
   SHA384_With_RSA : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#0C#];
   SHA512_With_RSA : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#0D#];
   RSASSA_PSS      : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#0A#];
   ECDSA_With_SHA256 : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#04#, 16#03#, 16#02#];
   ECDSA_With_SHA384 : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#04#, 16#03#, 16#03#];
   ECDSA_With_SHA512 : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#04#, 16#03#, 16#04#];

   --  Certificate extensions, 2.5.29.n
   Subject_Key_Identifier   : constant Octets := [16#55#, 16#1D#, 16#0E#];
   Key_Usage                : constant Octets := [16#55#, 16#1D#, 16#0F#];
   Subject_Alternative_Name : constant Octets := [16#55#, 16#1D#, 16#11#];
   Issuer_Alternative_Name  : constant Octets := [16#55#, 16#1D#, 16#12#];
   Basic_Constraints        : constant Octets := [16#55#, 16#1D#, 16#13#];
   CRL_Number               : constant Octets := [16#55#, 16#1D#, 16#14#];
   CRL_Reason_Code          : constant Octets := [16#55#, 16#1D#, 16#15#];
   Delta_CRL_Indicator      : constant Octets := [16#55#, 16#1D#, 16#1B#];
   Issuing_Distribution_Pt  : constant Octets := [16#55#, 16#1D#, 16#1C#];
   Name_Constraints         : constant Octets := [16#55#, 16#1D#, 16#1E#];
   CRL_Distribution_Points  : constant Octets := [16#55#, 16#1D#, 16#1F#];
   Certificate_Policies     : constant Octets := [16#55#, 16#1D#, 16#20#];
   Policy_Mappings          : constant Octets := [16#55#, 16#1D#, 16#21#];
   Authority_Key_Identifier : constant Octets := [16#55#, 16#1D#, 16#23#];
   Policy_Constraints       : constant Octets := [16#55#, 16#1D#, 16#24#];
   Extended_Key_Usage       : constant Octets := [16#55#, 16#1D#, 16#25#];
   Inhibit_Any_Policy       : constant Octets := [16#55#, 16#1D#, 16#36#];
   Freshest_CRL             : constant Octets := [16#55#, 16#1D#, 16#2E#];

   --  1.3.6.1.5.5.7.1.1 and neighbours
   Authority_Information_Access : constant Octets :=
     [16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#01#, 16#01#];
   TLS_Feature : constant Octets :=
     [16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#01#, 16#18#];
   OCSP_No_Check : constant Octets :=
     [16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#30#, 16#01#, 16#05#];

   --  Policy qualifiers, 1.3.6.1.5.5.7.2.n: a pointer to the issuer's
   --  certification practice statement, and a notice meant for a person.
   QT_CPS : constant Octets :=
     [16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#02#, 16#01#];
   QT_User_Notice : constant Octets :=
     [16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#02#, 16#02#];

   --  Access methods, 1.3.6.1.5.5.7.48.n. Note that OCSP_No_Check above sits
   --  under AD_OCSP rather than beside it, so a prefix match would confuse
   --  the two -- they are compared whole.
   AD_OCSP : constant Octets :=
     [16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#30#, 16#01#];
   AD_CA_Issuers : constant Octets :=
     [16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#30#, 16#02#];

   --  1.3.6.1.5.5.7.48.1.2, the OCSP nonce, which sits under AD_OCSP for the
   --  same reason OCSP_No_Check does.
   OCSP_Nonce : constant Octets :=
     [16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#30#, 16#01#, 16#02#];

   --  Extended key usages, 1.3.6.1.5.5.7.3.n
   EKU_Server_Auth : constant Octets :=
     [16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#03#, 16#01#];
   EKU_Client_Auth : constant Octets :=
     [16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#03#, 16#02#];
   EKU_Code_Signing : constant Octets :=
     [16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#03#, 16#03#];
   EKU_Email_Protection : constant Octets :=
     [16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#03#, 16#04#];
   EKU_OCSP_Signing : constant Octets :=
     [16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#03#, 16#09#];

   --  2.5.29.37.0
   EKU_Any : constant Octets := [16#55#, 16#1D#, 16#25#, 16#00#];

   --  OCSP. The basic response is the only response type defined, and SHA-1
   --  is what a CertID hashes the issuer name and key with -- not as a
   --  security choice but because the identifier is a lookup key and the
   --  responder computed it that way.
   OCSP_Basic_Response : constant Octets :=
     [16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#30#, 16#01#,
      16#01#];
   SHA1_Digest_Algorithm : constant Octets :=
     [16#2B#, 16#0E#, 16#03#, 16#02#, 16#1A#];

   --  The SHA-2 digests, named where an algorithm carries its hash in its
   --  parameters rather than in its own identifier -- which RSASSA-PSS does.
   SHA256_Digest_Algorithm : constant Octets :=
     [16#60#, 16#86#, 16#48#, 16#01#, 16#65#, 16#03#, 16#04#, 16#02#, 16#01#];
   SHA384_Digest_Algorithm : constant Octets :=
     [16#60#, 16#86#, 16#48#, 16#01#, 16#65#, 16#03#, 16#04#, 16#02#, 16#02#];
   SHA512_Digest_Algorithm : constant Octets :=
     [16#60#, 16#86#, 16#48#, 16#01#, 16#65#, 16#03#, 16#04#, 16#02#, 16#03#];

   --  Password-based encryption, as an encrypted PKCS#8 key uses it. The
   --  scheme, the derivation, the pseudo-random function and the cipher are
   --  four separate identifiers, because PBES2 composes them rather than
   --  naming a combination.
   PBES2 : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#05#, 16#0D#];
   PBKDF2 : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#05#, 16#0C#];
   HMAC_With_SHA1 : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#02#, 16#07#];
   HMAC_With_SHA256 : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#02#, 16#09#];
   HMAC_With_SHA384 : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#02#, 16#0A#];
   HMAC_With_SHA512 : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#02#, 16#0B#];
   AES128_CBC : constant Octets :=
     [16#60#, 16#86#, 16#48#, 16#01#, 16#65#, 16#03#, 16#04#, 16#01#, 16#02#];
   AES192_CBC : constant Octets :=
     [16#60#, 16#86#, 16#48#, 16#01#, 16#65#, 16#03#, 16#04#, 16#01#, 16#16#];
   AES256_CBC : constant Octets :=
     [16#60#, 16#86#, 16#48#, 16#01#, 16#65#, 16#03#, 16#04#, 16#01#, 16#2A#];

   --  PKCS#7 content types and PKCS#12 bag types, for reading a bundle.
   PKCS7_Data : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#07#, 16#01#];
   PKCS7_Encrypted_Data : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#07#, 16#06#];
   Key_Bag : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#0C#, 16#0A#, 16#01#, 16#01#];
   Shrouded_Key_Bag : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#0C#, 16#0A#, 16#01#, 16#02#];
   Cert_Bag : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#0C#, 16#0A#, 16#01#, 16#03#];
   X509_Certificate_Bag : constant Octets :=
     [16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#09#, 16#16#, 16#01#];

   --  Is the identifier at Item within Data this one?
   --
   --  Takes the element rather than a slice so that a caller cannot
   --  accidentally compare against a range it has already adjusted.
   --  @param Data the buffer the element was read from
   --  @param Item the decoded OBJECT IDENTIFIER
   --  @param Identifier the encoded identifier to compare against
   --  @return True when the element's content is exactly Identifier
   function Matches
     (Data       : Octets;
      Item       : Element;
      Identifier : Octets) return Boolean;

end CryptoLib.ASN1.OIDs;
