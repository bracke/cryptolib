--  RFC 5280 name-constraint processing.
--
--  Each procedure is one group of known-answer or negative tests, and
--  is called from the Tests driver. Splitting the suite by topic is
--  what keeps any one file readable; the driver keeps the order.
package Tests_X509_Name_Constraints is

   procedure Check_Name_Constraint_Depth_Fields;

   procedure Check_Unapplicable_Name_Constraint;

   procedure Check_Name_Constraints;

end Tests_X509_Name_Constraints;
