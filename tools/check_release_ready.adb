with Ada.Command_Line;
with Ada.Directories;
with Ada.Strings.Fixed;
with Ada.Text_IO;

with Project_Tools.Processes;

--  Self-contained release preflight for the cryptolib crate: build the library,
--  build and run its test suite, and run cryptolib's own verification checks.
--  Run from the cryptolib crate root.
procedure Check_Release_Ready is
   procedure Require_Alire_GNAT_15 is
      Output_Text : constant String :=
        Project_Tools.Processes.Shell_Output_Trimmed
          ("alr exec -- gnatls --version");
   begin
      if Output_Text = "" then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "could not run `alr exec -- gnatls --version`");
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
         raise Program_Error;
      elsif Ada.Strings.Fixed.Index (Output_Text, "GNATLS 15.") = 0 then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "wrong Ada compiler: cryptolib release validation must use Alire GNAT 15; got: "
            & Output_Text);
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
         raise Program_Error;
      end if;

      Ada.Text_IO.Put_Line ("Alire GNAT 15 check passed: " & Output_Text);
   end Require_Alire_GNAT_15;

   procedure Report (Label : String; Status : Integer) is
   begin
      if Status /= 0 then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "cryptolib release preflight failed during " & Label);
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
         raise Program_Error;
      end if;
   end Report;

   procedure Step (Label : String; Command : String) is
   begin
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("==> " & Label);
      Report (Label, Project_Tools.Processes.Run_Shell (Command));
   end Step;

   procedure Step_In (Label : String; Directory : String; Command : String) is
   begin
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("==> " & Label);
      Report
        (Label,
         Project_Tools.Processes.Run_Shell_In_Directory
           (Directory => Directory, Command => Command));
   end Step_In;

   --  Semantically check a per-OS backend this host does not build.
   --
   --  Compiled from obj/, not the crate root: -gnatc still writes an .ali
   --  beside the caller, and running this from the root dropped one there on
   --  every preflight -- which is how a stale cryptolib-os_random.ali came to
   --  be committed. obj/ is ignored, so the artefact goes where artefacts go.
   --
   --  The directory is made and entered from Ada rather than by handing a
   --  `mkdir -p ... && cd ... && ...` string to a shell. This crate's tooling
   --  is Ada; a shell command line is how a program is invoked here, not where
   --  logic is written.
   Platform_Obj : constant String := "obj/platform-check";

   procedure Check_Backend (OS : String) is
      Label : constant String := "check the " & OS & " backend";
   begin
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("==> " & Label);
      Ada.Directories.Create_Path (Platform_Obj);
      Report
        (Label,
         Project_Tools.Processes.Run_Shell_In_Directory
           (Directory => Platform_Obj,
            Command   =>
              "alr exec -- gcc -c -gnatc -gnat2022 -gnatwa "
              & "-I../../src -I../../config "
              & "../../src-" & OS & "/cryptolib-os_random.adb"));
   end Check_Backend;
begin
   if Ada.Command_Line.Argument_Count /= 0 then
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error, "usage: check_release_ready");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;

   Require_Alire_GNAT_15;

   --  Where the style and warning bar actually bites, and it did not until
   --  this step existed.
   --
   --  The switches come from the Alire profile, not from cryptolib.gpr, and
   --  they differ per profile: `release` carries -gnatn and -gnatW8 and
   --  nothing else -- no -gnatwa, no -gnatVa, no -gnaty at all -- while
   --  `validation` adds the full style set plus -gnatwe, which turns every
   --  warning and style breach into an error. A preflight that built only
   --  --release and the default profile therefore printed style complaints at
   --  most, and printing is not enforcing: three had accumulated unnoticed
   --  (two double blank lines and a 122-column line against a 120 limit).
   --
   --  This runs first because a style breach should be the cheapest failure to
   --  get, not one found after a full test run.
   Step ("build cryptolib with warnings as errors", "alr build --validation -- -f");

   --  Forced, both of them. Everything after this inspects what the build
   --  produced -- the test binary's behaviour, and the library's generated
   --  code -- so a preflight that accepted whatever an incremental build
   --  happened to leave could pass on an artefact that no longer matches the
   --  source. That is not hypothetical: the constant-time check was seen
   --  reporting jump counts from a half-rebuilt library.
   --  The constant-time budgets were recorded from a release build, because
   --  that is what a release ships and because the profile changes the
   --  answer: CT_Select has no conditional jump under -O3 and one under the
   --  -Og default. So this check gets its own build rather than inspecting
   --  whatever the previous step left behind.
   Step ("build cryptolib for inspection", "alr build --release -- -f");
   Step ("check constant-time properties", "tools/bin/check_constant_time");

   --  The per-OS backends. Source_Dirs picks one of src-linux, src-macos and
   --  src-windows by host, so the two that are not chosen are compiled by
   --  nothing and can rot without anyone noticing until somebody builds on
   --  that platform. A semantic check is not a test -- it cannot say
   --  BCryptGenRandom was called correctly -- but it does say the file still
   --  compiles against the spec it implements, which is the part that quietly
   --  breaks when a shared declaration changes.
   --
   --  All three rather than "the other one": this checked src-windows alone,
   --  so when src-macos was added it inherited exactly the rot this step
   --  exists to prevent. Naming every backend costs one redundant compile of
   --  whichever is the host's and makes the preflight say the same thing on
   --  every platform. A new src-<os> must be added here too.
   Check_Backend ("linux");
   Check_Backend ("macos");
   Check_Backend ("windows");

   Step ("build cryptolib", "alr build -- -f");
   Step_In ("build test suite", "tests", "alr build -- -f");
   Step ("run test suite", "./tests/bin/tests");
   Step ("check alire manifest", "tools/bin/check_alire_manifest");
   Step ("check test suite", "tools/bin/check_test_suite");
   --  Forced, like the builds above and for the same reason: examples/obj is
   --  not cleaned between runs, and objects left there by a build against a
   --  different libCryptolib.a link against the current one only by luck. That
   --  failure was seen once here, and it is not one worth diagnosing twice.
   Step ("build README examples",
         "alr exec -- gprbuild -q -f -P examples/examples.gpr");
   Step ("check GNATdoc tags", "tools/bin/check_gnatdoc_tags");

   Ada.Text_IO.Put_Line ("cryptolib release preflight passed");
   Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Success);
exception
   when Program_Error =>
      null;  -- a step already set the failure exit status
end Check_Release_Ready;
