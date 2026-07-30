--  RFC 5280 certificate-policy processing.
--
--  Each procedure is one group of known-answer or negative tests, and
--  is called from the Tests driver. Splitting the suite by topic is
--  what keeps any one file readable; the driver keeps the order.
package Tests_X509_Policies is

   procedure Check_Policy_Processing;

   procedure Check_Policy_Qualifiers;

   procedure Check_Policy_Aware_Path_Building;

   procedure Check_Self_Issued_Policy_Allowance;

   procedure Check_Policy_Tree_Bound;

   procedure Check_Policy_Set_Is_A_Set;

   procedure Check_Policy_Constraint_Skipcerts;

end Tests_X509_Policies;
