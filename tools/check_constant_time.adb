with Ada.Command_Line;
with Ada.Streams.Stream_IO;
with Ada.Strings.Fixed;
with Ada.Text_IO;

with Project_Tools.Files;
with Project_Tools.Processes;

--  Constant-time regression gate for the built library.
--
--  SECURITY.md's constant-time section rested on a spot-check somebody ran
--  once with objdump, and said so: "there is no automated CT regression
--  gate". The properties it claims are mechanical, so a compiler upgrade or
--  an innocent-looking edit can take them away and nothing would say.
--
--  This does not prove constant-timeness, and saying so matters.
--
--  Two things are checked, and they are not equally strong. That no AES
--  lookup table is present is decidable and absolute: the table is either in
--  the binary or it is not. The jump counts are a baseline, not a property.
--  CT_Select and Equal_Mask compile to none at all; Equal keeps eleven, on
--  array lengths, loop indices and the answer it returns. Those are branches
--  on public values, which is what makes them harmless -- and a jump count
--  cannot tell them from a branch on a secret, which is why what follows is
--  a budget rather than a proof.
--
--  So the budgets below say "no more than there were", which catches the
--  regression that actually happens to code like this: a branchless mask
--  rewritten as an `if` adds jumps inside a loop body. It would not catch a
--  data-dependent memory access, which leaves no branch behind at all.
--  The budgets describe a release build, and the preflight makes one for
--  this check specifically. Profile matters more than it looks: CT_Select
--  compiles to no conditional jump at all under -O3 and to one -- its loop
--  bound -- under the -Og default, and the test crate rebuilds the library
--  again under its own profile. A budget is only meaningful against the
--  build it was recorded from, so the check owns which build that is rather
--  than inspecting whatever was left in lib/.
procedure Check_Constant_Time is
   Library_Path : constant String := "lib/libCryptolib.a";
   Dump_Path    : constant String :=
     Project_Tools.Files.Temp_Dir & "/cryptolib-ct-dump.txt";

   Failures : Natural := 0;

   procedure Complain (Message : String) is
   begin
      Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error, "error: " & Message);
      Failures := Failures + 1;
   end Complain;

   --  Search a file for a byte sequence without reading it whole: the
   --  archive runs to megabytes and a String that size does not fit on the
   --  stack. Chunks overlap by the pattern length so a match spanning a
   --  boundary is still found.
   function File_Contains_Bytes (Path : String; Pattern : String)
     return Boolean
   is
      use Ada.Streams;
      Chunk   : constant := 64 * 1024;
      File    : Stream_IO.File_Type;
      Buffer  : Stream_Element_Array (1 .. Chunk + Pattern'Length);
      Last    : Stream_Element_Offset;
      Carried : Stream_Element_Offset := 0;
      Found   : Boolean := False;
   begin
      if Pattern'Length = 0 then
         return False;
      end if;

      Stream_IO.Open (File, Stream_IO.In_File, Path);
      while not Stream_IO.End_Of_File (File) loop
         Stream_IO.Read
           (File, Buffer (Carried + 1 .. Carried + Chunk), Last);
         exit when Last < Carried + 1;

         declare
            Text : String (1 .. Natural (Last));
         begin
            for I in 1 .. Natural (Last) loop
               Text (I) :=
                 Character'Val (Buffer (Stream_Element_Offset (I)));
            end loop;
            if Ada.Strings.Fixed.Index (Text, Pattern) > 0 then
               Found := True;
               exit;
            end if;
         end;

         --  Carry the tail so a pattern straddling two chunks still matches.
         Carried := Stream_Element_Offset (Pattern'Length - 1);
         if Last >= Carried then
            Buffer (1 .. Carried) := Buffer (Last - Carried + 1 .. Last);
         else
            Carried := 0;
         end if;
      end loop;
      Stream_IO.Close (File);
      return Found;
   exception
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return False;
   end File_Contains_Bytes;

   function From_Hex (Values : String) return String is
      Result : String (1 .. Values'Length / 2);
      function Nibble (C : Character) return Natural
      is (case C is
             when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
             when others     => Character'Pos (C) - Character'Pos ('a') + 10);
   begin
      for I in Result'Range loop
         Result (I) :=
           Character'Val
             (Nibble (Values (Values'First + 2 * (I - 1))) * 16
              + Nibble (Values (Values'First + 2 * (I - 1) + 1)));
      end loop;
      return Result;
   end From_Hex;

   --  The AES forward S-box, its inverse, and the first entry of the usual
   --  T-table. Any of them in the binary means a lookup indexed by a secret
   --  byte came back, which is the cache-timing channel the bit-sliced
   --  implementation exists to avoid.
   S_Box         : constant String :=
     From_Hex ("637c777bf26b6fc53001672bfed7ab76");
   Inverse_S_Box : constant String :=
     From_Hex ("52096ad53036a538bf40a39e81f3d7fb");
   T_Table       : constant String := From_Hex ("c66363a5");

   --  Is this disassembly line a conditional jump? The mnemonic follows the
   --  last tab. Unconditional jmp and call are fine: what leaks is a branch
   --  whose direction depends on a secret.
   function Is_Conditional_Jump (Line : String) return Boolean is
      Tab   : constant Natural :=
        Ada.Strings.Fixed.Index (Line, "" & ASCII.HT, Ada.Strings.Backward);
      First : Natural;
      Stop  : Natural;
   begin
      if Tab = 0 or else Tab >= Line'Last then
         return False;
      end if;

      First := Tab + 1;
      Stop := First;
      while Stop <= Line'Last
        and then Line (Stop) not in ' ' | ASCII.HT
      loop
         Stop := Stop + 1;
      end loop;

      declare
         Mnemonic : constant String := Line (First .. Stop - 1);
      begin
         return Mnemonic'Length >= 2
           and then Mnemonic (Mnemonic'First) = 'j'
           and then Mnemonic /= "jmp"
           and then Mnemonic /= "jmpq";
      end;
   end Is_Conditional_Jump;

   --  Count conditional jumps in one routine. Found is False when the symbol
   --  is absent, which is itself a failure: a check that passes because it
   --  looked for a name that no longer exists is worse than no check.
   procedure Inspect
     (Name  : String;
      Jumps : out Natural;
      Found : out Boolean)
   is
      Status : constant Integer :=
        Project_Tools.Processes.Run_Shell
          ("objdump -d --disassemble=" & Name & " " & Library_Path
           & " > " & Dump_Path & " 2>/dev/null");
   begin
      Jumps := 0;
      Found := False;
      if Status /= 0 or else not Project_Tools.Files.File_Exists (Dump_Path)
      then
         return;
      end if;

      declare
         File   : Ada.Text_IO.File_Type;
         Marker : constant String := "<" & Name & ">:";
         Inside : Boolean := False;
      begin
         Ada.Text_IO.Open (File, Ada.Text_IO.In_File, Dump_Path);
         while not Ada.Text_IO.End_Of_File (File) loop
            declare
               Line : constant String := Ada.Text_IO.Get_Line (File);
            begin
               if not Inside then
                  if Ada.Strings.Fixed.Index (Line, Marker) > 0 then
                     Inside := True;
                     Found := True;
                  end if;
               elsif Line'Length = 0 then
                  exit;
               elsif Is_Conditional_Jump (Line) then
                  Jumps := Jumps + 1;
               end if;
            end;
         end loop;
         Ada.Text_IO.Close (File);
      end;
   end Inspect;

   --  Budget is what the routine compiles to today, with what those jumps
   --  are. Going over means new branching where there was none, which is
   --  worth a look; the number changing under a compiler upgrade is worth a
   --  look too, and re-baselining is the answer to that rather than raising
   --  the budget until it stops complaining.
   procedure Require_Within
     (Name : String; Budget : Natural; Because : String)
   is
      Jumps : Natural;
      Found : Boolean;
   begin
      Inspect (Name, Jumps, Found);
      if not Found then
         Complain
           (Name & " was not found in the disassembly; this cannot vouch "
            & "for a routine it cannot see");
      elsif Jumps > Budget then
         Complain
           (Name & " has" & Natural'Image (Jumps)
            & " conditional jumps, above its budget of"
            & Natural'Image (Budget) & " (" & Because
            & "); a new branch here may be one that depends on a secret");
      end if;
   end Require_Within;
begin
   if Ada.Command_Line.Argument_Count /= 0 then
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error, "usage: check_constant_time");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;

   if not Project_Tools.Files.File_Exists (Library_Path) then
      Complain (Library_Path & " is missing; build the library first");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;

   if File_Contains_Bytes (Library_Path, S_Box) then
      Complain
        ("the AES forward S-box table is in the library: AES is supposed to "
         & "be bit-sliced, and a table indexed by a secret byte is a "
         & "cache-timing channel");
   end if;
   if File_Contains_Bytes (Library_Path, Inverse_S_Box) then
      Complain ("the AES inverse S-box table is in the library");
   end if;
   if File_Contains_Bytes (Library_Path, T_Table) then
      Complain ("an AES T-table is in the library");
   end if;

   if Project_Tools.Processes.Run_Shell ("command -v objdump > /dev/null 2>&1")
      /= 0
   then
      Ada.Text_IO.Put_Line
        ("cryptolib constant-time check: objdump unavailable, so only the "
         & "lookup tables were checked");
   else
      Require_Within
        ("cryptolib__constant_time__equal", 11,
         "array lengths, loop bounds, and the returned answer");
      Require_Within
        ("cryptolib__ec_arith__ct_select", 0, "branchless outright");
      Require_Within
        ("cryptolib__modexp__ct_select", 16, "loop bounds and range checks");
      Require_Within
        ("cryptolib__ec_arith__equal_mask", 0, "branchless outright");
      Require_Within
        ("cryptolib__ec_arith__is_zero_mask", 0, "branchless outright");
      Require_Within
        ("cryptolib__ec_arith__geq_mask", 0, "branchless outright");
      Require_Within
        ("cryptolib__ec_arith__all_ones", 0, "branchless outright");

      --  The bit-sliced AES S-box. These are what stands in for the lookup
      --  table the binary is checked not to contain: affine(x^254) over
      --  GF(2^8) with branchless field arithmetic. A branch appearing in any
      --  of them is the substitution becoming data-dependent again.
      Require_Within
        ("cryptolib__ciphers__gf_mul_bs", 0, "branchless outright");
      Require_Within
        ("cryptolib__ciphers__gf_inv_bs", 0, "branchless outright");
      Require_Within
        ("cryptolib__ciphers__affine_bs", 0, "branchless outright");
      Require_Within
        ("cryptolib__ciphers__inv_affine_bs", 0, "branchless outright");
      Require_Within
        ("cryptolib__ciphers__sub_word", 0, "branchless outright");

      --  GHASH runs on the GCM authentication subkey, so its multiply is on
      --  secret input; the one jump is the loop counter over 128 bits.
      Require_Within
        ("cryptolib__ciphers__ghash_multiply", 1, "one loop counter");

      --  sntrup761 replaced mod and hardware division with Barrett
      --  multiply-shift; what is left in each is a GNAT range check that
      --  never fires for an in-range value.
      Require_Within
        ("cryptolib__sntrup761__fq_freeze", 1, "one range check");
      Require_Within
        ("cryptolib__sntrup761__f3_freeze", 1, "one range check");
      Require_Within
        ("cryptolib__sntrup761__swap_flag", 1, "one range check");

      --  Ed448 signing runs the field arithmetic on values derived from the
      --  private scalar, so the borrow chain is secret. Written the obvious
      --  way -- "if Diff < 0 then Item := Diff + 256; Borrow := 1" -- it
      --  compiles to a jns over genuinely different work, which is how it
      --  was first written here. Biasing by 256 so the quotient carries the
      --  sign makes the subtraction single-path; what is left in these is
      --  GNAT range checks that cannot fire and the loop counters.
      --
      --  Conditional_Subtract itself is not listed: the release build
      --  inlines it away, and this refuses to vouch for what it cannot see.
      --  It is inlined into these, though, so a branch reappearing inside it
      --  raises their counts and is caught here rather than nowhere.
      Require_Within
        ("cryptolib__ed448__borrow_of", 4, "range checks and the loop");
      Require_Within
        ("cryptolib__ed448__select_field", 5, "range checks and the loop");
      Require_Within
        ("cryptolib__ed448__sub_mod", 16, "range checks and the loops");
      Require_Within
        ("cryptolib__ed448__add_mod", 14, "range checks and the loops");
      Require_Within
        ("cryptolib__ed448__mul_mod", 22, "range checks and the loops");
   end if;

   if Failures = 0 then
      Ada.Text_IO.Put_Line ("cryptolib constant-time check passed");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Success);
   else
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error, "cryptolib constant-time check failed");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_Constant_Time;
