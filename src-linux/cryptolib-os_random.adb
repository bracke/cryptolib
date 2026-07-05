with Ada.Streams.Stream_IO;
with Interfaces.C;
with System;

--  Linux OS CSPRNG: getrandom(2) preferred, /dev/urandom fallback.  getrandom
--  is a glibc/Linux symbol, so keeping this body Linux-only avoids link
--  failures on platforms that lack it.
package body CryptoLib.OS_Random is

   use type Ada.Streams.Stream_Element_Offset;

   --  getrandom(2): fills Buf with Buflen CSPRNG bytes (blocks until the kernel
   --  pool is seeded when flags = 0).  Returns the count, or -1 on error (e.g.
   --  ENOSYS on kernels < 3.17), driving the /dev/urandom fallback.
   function C_Getrandom
     (Buf    : System.Address;
      Buflen : Interfaces.C.size_t;
      Flags  : Interfaces.C.unsigned) return Interfaces.C.long
     with Import, Convention => C, External_Name => "getrandom";

   procedure Fill_OS
     (Buffer  : out Ada.Streams.Stream_Element_Array;
      Success : out Boolean)
   is
      use type Interfaces.C.long;
      package Stream_IO renames Ada.Streams.Stream_IO;
      File_Item : Stream_IO.File_Type;
      Last_Read : Ada.Streams.Stream_Element_Offset;
      Next_Item : Ada.Streams.Stream_Element_Offset := Buffer'First;
      Got       : Interfaces.C.long;
      Have_Getrandom : Boolean := True;
   begin
      Success := False;
      if Buffer'Length = 0 then
         Success := True;
         return;
      end if;

      --  Preferred source: getrandom(2).
      while Next_Item <= Buffer'Last loop
         Got :=
           C_Getrandom
             (Buffer (Next_Item)'Address,
              Interfaces.C.size_t (Buffer'Last - Next_Item + 1), 0);
         if Got <= 0 then
            Have_Getrandom := False;
            exit;
         end if;
         Next_Item := Next_Item + Ada.Streams.Stream_Element_Offset (Got);
      end loop;
      if Have_Getrandom then
         Success := True;
         return;
      end if;

      --  Fallback: /dev/urandom (kernels without getrandom(2)).
      Next_Item := Buffer'First;
      Stream_IO.Open (File_Item, Stream_IO.In_File, "/dev/urandom");
      while Next_Item <= Buffer'Last loop
         Stream_IO.Read
           (File_Item, Buffer (Next_Item .. Buffer'Last), Last_Read);
         if Last_Read < Next_Item then
            Stream_IO.Close (File_Item);
            Buffer := [others => 0];
            return;
         end if;
         Next_Item := Last_Read + 1;
      end loop;
      Stream_IO.Close (File_Item);
      Success := True;
   exception
      when others =>
         Buffer := [others => 0];
         Success := False;
   end Fill_OS;

end CryptoLib.OS_Random;
