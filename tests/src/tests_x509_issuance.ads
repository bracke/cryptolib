--  Issuing certificates: local CAs, server, client and email leaves.
--
--  Each procedure is one group of known-answer or negative tests, and
--  is called from the Tests driver. Splitting the suite by topic is
--  what keeps any one file readable; the driver keeps the order.
package Tests_X509_Issuance is

   procedure Check_Certificates;

   procedure Check_P384_Local_CA;

   procedure Check_Ed448_Certificate;

end Tests_X509_Issuance;
