with Ada.Command_Line;
with Ada.Text_IO;

with Project_Tools.Alire_Manifests;

--  Release check: the cryptolib crate manifest must be free of Alire pins so it
--  is publishable as-is. cryptolib has no crate dependencies, so alire.toml must
--  stay pin-free; development pins live only in the tooling/test sub-crates.
procedure Check_Alire_Manifest is
begin
   if Ada.Command_Line.Argument_Count /= 0 then
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error, "usage: check_alire_manifest");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;

   Project_Tools.Alire_Manifests.Require_Pin_Free_Crate_Manifest
     (Manifest => "alire.toml",
      Name     => "cryptolib");

   Ada.Text_IO.Put_Line ("cryptolib manifest check passed");
exception
   when Program_Error =>
      null;  -- a Require_* helper already set the failure exit status
end Check_Alire_Manifest;
