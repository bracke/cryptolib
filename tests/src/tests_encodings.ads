--  ASN.1/DER, PEM, PKCS#8, PKCS#10, PKCS#12 and OpenSSH key encodings.
--
--  Each procedure is one group of known-answer or negative tests, and
--  is called from the Tests driver. Splitting the suite by topic is
--  what keeps any one file readable; the driver keeps the order.
package Tests_Encodings is

   procedure Check_Identity_Predicates;

   procedure Check_ASN1_DER;

   procedure Check_Decoder_Robustness;

   procedure Check_CSR_Signing;

   procedure Check_OpenSSH_Key_Unlock;

   procedure Check_OpenSSH_Signature;

   procedure Check_PKCS10;

   procedure Check_PKCS8;

   procedure Check_Identities;

   procedure Check_PKCS8_Encrypted;

   procedure Check_PKCS12;

end Tests_Encodings;
