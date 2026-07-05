with Ada.Command_Line;
with Ada.Strings.Fixed;
with Ada.Text_IO;

with Project_Tools.Files;

--  Test-suite metrics check, adapted for cryptolib's custom Check-based runner
--  (which does not use AUnit registration, so Project_Tools.Aunit_Checks does
--  not apply). Verifies the suite references a broad set of primitive packages
--  and carries a substantial number of assertions.
procedure Check_Test_Suite is
   Suite_Path     : constant String := "tests/src/tests.adb";
   Min_Primitives : constant := 10;
   Min_Assertions : constant := 50;

   function Count (Text : String; Pattern : String) return Natural is
      Result : Natural := 0;
      Index  : Natural := Text'First;
      Found  : Natural;
   begin
      loop
         Found := Ada.Strings.Fixed.Index (Text (Index .. Text'Last), Pattern);
         exit when Found = 0;
         Result := Result + 1;
         Index := Found + Pattern'Length;
         exit when Index > Text'Last;
      end loop;
      return Result;
   end Count;
begin
   if Ada.Command_Line.Argument_Count /= 0 then
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error, "usage: check_test_suite");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;

   if not Project_Tools.Files.File_Exists (Suite_Path) then
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error, "missing test suite: " & Suite_Path);
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;

   declare
      Text       : constant String := Project_Tools.Files.Read_Raw_File (Suite_Path);
      Primitives : constant Natural := Count (Text, "with CryptoLib.");
      Assertions : constant Natural := Count (Text, "Check (");
   begin
      Ada.Text_IO.Put_Line
        ("cryptolib test suite:" & Primitives'Image & " primitive packages,"
         & Assertions'Image & " assertions");
      if Primitives < Min_Primitives or else Assertions < Min_Assertions then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "test suite below expected coverage (need >="
            & Min_Primitives'Image & " primitives,"
            & Min_Assertions'Image & " assertions)");
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
         return;
      end if;
      Ada.Text_IO.Put_Line ("cryptolib test-suite check passed");
   end;
end Check_Test_Suite;
