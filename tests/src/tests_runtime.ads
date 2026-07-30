--  Cross-cutting behaviour: constant time, fail-closed paths, buffer ceilings.
--
--  Each procedure is one group of known-answer or negative tests, and
--  is called from the Tests driver. Splitting the suite by topic is
--  what keeps any one file readable; the driver keeps the order.
package Tests_Runtime is

   procedure Check_Random_Fails_Closed;

   procedure Check_Constant_Time_Equal;

   procedure Check_Buffer_Ceiling;

   procedure Check_Consumer_Entry_Points;

   procedure Check_Manifests_And_Helpers;

   procedure Check_Zero_On_Failure;

end Tests_Runtime;
