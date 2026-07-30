with AUnit;
with AUnit.Test_Cases;

--  ASN.1/DER, PEM, PKCS#8, PKCS#10, PKCS#12 and OpenSSH key encodings.
--
--  Each procedure is one group of known-answer or negative tests, and
--  is called from the Tests driver. Splitting the suite by topic is
--  what keeps any one file readable; the driver keeps the order.
package Tests_Encodings is

   type Test_Case is new AUnit.Test_Cases.Test_Case with null record;

   overriding procedure Register_Tests (Item : in out Test_Case);
   overriding function Name (Item : Test_Case) return AUnit.Message_String;

end Tests_Encodings;
