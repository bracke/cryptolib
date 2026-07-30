--  Verifying certificates: signatures, chains, purposes and identity matching.
--
--  Each procedure is one group of known-answer or negative tests, and
--  is called from the Tests driver. Splitting the suite by topic is
--  what keeps any one file readable; the driver keeps the order.
package Tests_X509_Validation is

   procedure Check_X509_Verify;

   procedure Check_Unsupported_Algorithm;

   procedure Check_Verification_Failure_Kinds;

   procedure Check_Chain_Constraint_Bypasses;

   procedure Check_Signature_Algorithm_Agreement;

   procedure Check_X509_Validation;

   procedure Check_X509_Identity;

   procedure Check_X509_Purposes;

   procedure Check_X509_Path_Building;

end Tests_X509_Validation;
