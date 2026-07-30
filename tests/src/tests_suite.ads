with AUnit.Test_Suites;

--  The whole cryptolib suite: one AUnit test case per topic, each registering
--  its checks as individual routines. Ordered as the checks were written.
package Tests_Suite is

   function Suite return AUnit.Test_Suites.Access_Test_Suite;

end Tests_Suite;
