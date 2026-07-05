with Ada.Command_Line;
with Ada.Directories;
with Ada.Text_IO;

with Project_Tools.Ada_Source;

--  Documentation check: every public subprogram in cryptolib's spec files must
--  carry GNATdoc-style tags (a leading description plus @param/@return). Guards
--  the documented public API against regressions.
procedure Check_Gnatdoc_Tags is
   Checked : Natural := 0;

   procedure Check_Dir (Dir : String) is
      Search : Ada.Directories.Search_Type;
      Item   : Ada.Directories.Directory_Entry_Type;
   begin
      if not Ada.Directories.Exists (Dir) then
         return;
      end if;
      Ada.Directories.Start_Search
        (Search, Dir, "*.ads",
         Filter => [Ada.Directories.Ordinary_File => True, others => False]);
      while Ada.Directories.More_Entries (Search) loop
         Ada.Directories.Get_Next_Entry (Search, Item);
         Project_Tools.Ada_Source.Require_Public_GNATdoc_Tags
           (Spec_Path => Ada.Directories.Full_Name (Item));
         Checked := Checked + 1;
      end loop;
      Ada.Directories.End_Search (Search);
   end Check_Dir;
begin
   if Ada.Command_Line.Argument_Count /= 0 then
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error, "usage: check_gnatdoc_tags");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;

   Check_Dir ("src");
   Check_Dir ("src-linux");
   Check_Dir ("src-windows");

   Ada.Text_IO.Put_Line
     ("cryptolib GNATdoc tag check passed (" & Checked'Image & " specs)");
exception
   when Program_Error =>
      null;  -- Require_Public_GNATdoc_Tags already set the failure exit status
end Check_Gnatdoc_Tags;
