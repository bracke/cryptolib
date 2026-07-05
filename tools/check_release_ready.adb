with Ada.Command_Line;
with Ada.Text_IO;

with Project_Tools.Processes;

--  Self-contained release preflight for the cryptolib crate: build the library,
--  build and run its test suite, and run cryptolib's own verification checks.
--  Run from the cryptolib crate root.
procedure Check_Release_Ready is
   procedure Step (Label : String; Command : String) is
   begin
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("==> " & Label);
      if Project_Tools.Processes.Run_Shell (Command) /= 0 then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "cryptolib release preflight failed during " & Label);
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
         raise Program_Error;
      end if;
   end Step;
begin
   if Ada.Command_Line.Argument_Count /= 0 then
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error, "usage: check_release_ready");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;

   Step ("build cryptolib", "alr build");
   Step ("build test suite", "cd tests && alr build");
   Step ("run test suite", "./tests/bin/tests");
   Step ("check alire manifest", "tools/bin/check_alire_manifest");
   Step ("check test suite", "tools/bin/check_test_suite");
   Step ("check GNATdoc tags", "tools/bin/check_gnatdoc_tags");

   Ada.Text_IO.Put_Line ("cryptolib release preflight passed");
   Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Success);
exception
   when Program_Error =>
      null;  -- a step already set the failure exit status
end Check_Release_Ready;
