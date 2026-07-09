with Ada.Command_Line;
with Ada.Text_IO;

with Project_Tools.Alire_Manifests;
with Project_Tools.Files;

--  Release check: the cryptolib crate manifest must be free of Alire pins so it
--  is publishable as-is. cryptolib has no crate dependencies, so alire.toml must
--  stay pin-free; development pins live only in the tooling/test sub-crates.
procedure Check_Alire_Manifest is
   procedure Require_Text (Path : String; Needle : String) is
   begin
      if not Project_Tools.Files.File_Exists (Path) then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error, "missing Alire toolchain file: " & Path);
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
         raise Program_Error;
      elsif not Project_Tools.Files.File_Contains (Path, Needle) then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "missing Alire GNAT 15 text in " & Path & ": " & Needle);
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
         raise Program_Error;
      end if;
   end Require_Text;

   procedure Require_Alire_GNAT_15 is
   begin
      Require_Text ("alire.toml", "gnat_native = ""^15""");
      Require_Text ("tests/alire.toml", "gnat_native = ""^15""");
      Require_Text ("tools/alire.toml", "gnat_native = ""^15""");
      Require_Text ("alire/alire.lock", "gnat=15.2.1");
      Require_Text ("alire/alire.lock", "version = ""15.2.1""");
      Require_Text ("tests/alire/alire.lock", "gnat=15.2.1");
      Require_Text ("tests/alire/alire.lock", "version = ""15.2.1""");
      Require_Text ("tools/alire/alire.lock", "gnat=15.2.1");
      Require_Text ("tools/alire/alire.lock", "version = ""15.2.1""");
   end Require_Alire_GNAT_15;
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
   Require_Alire_GNAT_15;

   Ada.Text_IO.Put_Line ("cryptolib manifest check passed");
exception
   when Program_Error =>
      null;  -- a Require_* helper already set the failure exit status
end Check_Alire_Manifest;
