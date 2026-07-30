with Ada.Command_Line;

with AUnit;
with AUnit.Reporter.Text;
with AUnit.Run;

with Tests_Suite;

--  The cryptolib test harness. Every check is an AUnit routine, so one broken
--  known-answer vector reports itself and the remaining checks still run --
--  the previous runner raised on the first failure and hid everything after
--  it.
procedure Tests is
   use type AUnit.Status;

   function Run is new AUnit.Run.Test_Runner_With_Status (Tests_Suite.Suite);

   Reporter : AUnit.Reporter.Text.Text_Reporter;
   Status   : AUnit.Status;
begin
   Status := Run (Reporter);
   if Status = AUnit.Failure then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Tests;
