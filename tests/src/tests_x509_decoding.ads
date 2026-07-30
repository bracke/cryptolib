--  Decoding certificates and reading their fields: serials, validity, extensions, names.
--
--  Each procedure is one group of known-answer or negative tests, and
--  is called from the Tests driver. Splitting the suite by topic is
--  what keeps any one file readable; the driver keeps the order.
package Tests_X509_Decoding is

   procedure Check_X509_Decode;

   procedure Check_X509_Access_Locations;

   procedure Check_Certificate_Ambiguity;

   procedure Check_Serial_Numbers;

   procedure Check_Validity_Window;

   procedure Check_Key_Identifiers;

   procedure Check_Large_Certificate;

   procedure Check_Oversized_Serial;

   procedure Check_Serial_Comparison;

   procedure Check_Validity_Not_Past_Issuer;

   procedure Check_Impossible_Dates;

   procedure Check_Undated_Statement_Ages;

   procedure Check_X509_Extensions;

   procedure Check_X509_Names;

   procedure Check_Certificate_Armour;

end Tests_X509_Decoding;
