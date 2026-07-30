with Ada.Command_Line;
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

   --  Semantically check a per-OS backend this host does not build.
   --
   --  Compiled from obj/, not the crate root: -gnatc still writes an .ali
   --  beside the caller, and running this from the root dropped one there on
   --  every preflight -- which is how a stale cryptolib-os_random.ali came to
   --  be committed. obj/ is ignored, so the artefact goes where artefacts go.
   procedure Check_Backend (OS : String) is
   begin
      Step ("check the " & OS & " backend",
            "mkdir -p obj/platform-check && cd obj/platform-check && "
            & "alr exec -- gcc -c -gnatc -gnat2022 -gnatwa "
            & "-I../../src -I../../config "
            & "../../src-" & OS & "/cryptolib-os_random.adb");
   end Check_Backend;
begin
   if Ada.Command_Line.Argument_Count /= 0 then
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error, "usage: check_release_ready");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;

   Require_Alire_GNAT_15;

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
   Step ("build test suite", "cd tests && alr build -- -f");
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
