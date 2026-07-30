with Ada.Command_Line;
with Ada.Containers.Indefinite_Ordered_Sets;
with Ada.Directories;
with Ada.Strings.Fixed;
with Ada.Text_IO;

with Project_Tools.Files;

--  Test-suite metrics check, adapted for cryptolib's custom Check-based runner
--  (which does not use AUnit registration, so Project_Tools.Aunit_Checks does
--  not apply). Verifies the suite references a broad set of primitive packages
--  and carries a substantial number of assertions.
--
--  The suite is a driver plus one package per topic, so this reads the whole
--  of tests/src rather than a single file. The checks are defined in the topic
--  package bodies and called from the driver, which is what makes the
--  never-called test detectable: it is a name the driver does not mention.
procedure Check_Test_Suite is
   Suite_Dir      : constant String := "tests/src";
   Driver_Path    : constant String := "tests/src/tests.adb";
   Min_Primitives : constant := 10;
   Min_Assertions : constant := 50;

   package String_Sets is
     new Ada.Containers.Indefinite_Ordered_Sets (String);

   Primitives : String_Sets.Set;
   Assertions : Natural := 0;
   Defined    : Natural := 0;
   Uncalled   : Natural := 0;

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

   --  Distinct packages, not occurrences: the same with-clause now appears in
   --  a dozen files, and counting it a dozen times would report breadth the
   --  suite does not have.
   procedure Collect_Primitives (Text : String) is
      Marker : constant String := "with CryptoLib.";
      Cursor : Natural := Text'First;
      Found  : Natural;
   begin
      loop
         Found := Ada.Strings.Fixed.Index (Text (Cursor .. Text'Last), Marker);
         exit when Found = 0;
         declare
            First : constant Natural := Found + 5;  --  at "CryptoLib."
            Stop  : Natural := First;
         begin
            while Stop <= Text'Last and then Text (Stop) /= ';' loop
               Stop := Stop + 1;
            end loop;
            Primitives.Include (Text (First .. Stop - 1));
            Cursor := Stop;
         end;
         exit when Cursor > Text'Last;
      end loop;
   end Collect_Primitives;

   --  A test procedure that nobody calls passes every time. The checks live in
   --  the topic packages and the calls live in the driver, so a name the
   --  driver never mentions reads as coverage while testing nothing.
   --
   --  Compared by name rather than by count: some checks take parameters and
   --  are written across several lines, so the two totals differ for reasons
   --  that are nobody's mistake.
   procedure Check_All_Called (Text : String; Driver : String) is
      Marker : constant String := ASCII.LF & "   procedure Check_";
      Cursor : Natural := Text'First;
      Found  : Natural;
   begin
      loop
         Found := Ada.Strings.Fixed.Index (Text (Cursor .. Text'Last), Marker);
         exit when Found = 0;

         declare
            First : constant Natural := Found + Marker'Length - 6;
            Stop  : Natural := First;
         begin
            while Stop <= Text'Last
              and then (Text (Stop) in 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9'
                        or else Text (Stop) = '_')
            loop
               Stop := Stop + 1;
            end loop;

            declare
               Name : constant String := Text (First .. Stop - 1);
               --  A call sits at statement level in the driver's body.
               Call : constant String := ASCII.LF & "   " & Name;
            begin
               Defined := Defined + 1;
               if Ada.Strings.Fixed.Index (Driver, Call) = 0 then
                  Uncalled := Uncalled + 1;
                  Ada.Text_IO.Put_Line
                    (Ada.Text_IO.Standard_Error,
                     "error: " & Name & " is defined but never called");
               end if;
            end;
            Cursor := Stop;
         end;
      end loop;
   end Check_All_Called;
begin
   if Ada.Command_Line.Argument_Count /= 0 then
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error, "usage: check_test_suite");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;

   if not Project_Tools.Files.File_Exists (Driver_Path) then
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error, "missing test suite: " & Driver_Path);
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;

   declare
      Driver : constant String :=
        Project_Tools.Files.Read_Raw_File (Driver_Path);
      Search : Ada.Directories.Search_Type;
      Item   : Ada.Directories.Directory_Entry_Type;
   begin
      Ada.Directories.Start_Search
        (Search    => Search,
         Directory => Suite_Dir,
         Pattern   => "*.ad*",
         Filter    => [Ada.Directories.Ordinary_File => True, others => False]);
      while Ada.Directories.More_Entries (Search) loop
         Ada.Directories.Get_Next_Entry (Search, Item);
         declare
            Name : constant String := Ada.Directories.Simple_Name (Item);
            Text : constant String :=
              Project_Tools.Files.Read_Raw_File
                (Ada.Directories.Full_Name (Item));
         begin
            Collect_Primitives (Text);
            Assertions := Assertions + Count (Text, "Check (");
            --  Definitions only: a spec would count each check a second time,
            --  and the driver defines none.
            if Name'Length > 4
              and then Name (Name'Last - 3 .. Name'Last) = ".adb"
              and then Name /= "tests.adb"
            then
               Check_All_Called (Text, Driver);
            end if;
         end;
      end loop;
      Ada.Directories.End_Search (Search);
   end;

   if Uncalled > 0 then
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error,
         "a test procedure that is never called passes without testing "
         & "anything");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;

   Ada.Text_IO.Put_Line
     ("cryptolib test suite:" & Natural (Primitives.Length)'Image
      & " primitive packages," & Assertions'Image & " assertions,"
      & Defined'Image & " checks, all of them called");
   if Natural (Primitives.Length) < Min_Primitives
     or else Assertions < Min_Assertions
   then
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error,
         "test suite below expected coverage (need >="
         & Min_Primitives'Image & " primitives,"
         & Min_Assertions'Image & " assertions)");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;
   Ada.Text_IO.Put_Line ("cryptolib test-suite check passed");
end Check_Test_Suite;
