--  CRL and OCSP revocation checking.
--
--  Each procedure is one group of known-answer or negative tests, and
--  is called from the Tests driver. Splitting the suite by topic is
--  what keeps any one file readable; the driver keeps the order.
package Tests_X509_Revocation is

   procedure Check_Revocation_Details;

   procedure Check_X509_CRL;

   procedure Check_OCSP;

   procedure Check_Revocation;

end Tests_X509_Revocation;
