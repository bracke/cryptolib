--  RSA signing and verification, PKCS#1 v1.5 and PSS.
--
--  Each procedure is one group of known-answer or negative tests, and
--  is called from the Tests driver. Splitting the suite by topic is
--  what keeps any one file readable; the driver keeps the order.
package Tests_RSA is

   procedure Check_Weak_RSA_Key;

   procedure Check_RSA_Signing;

   procedure Check_RSA_Verify;

   procedure Check_RSA_PSS;

end Tests_RSA;
