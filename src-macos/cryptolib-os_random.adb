with Ada.Streams.Stream_IO;
with Interfaces.C;
with System;

--  macOS OS CSPRNG: getentropy(2) preferred, /dev/urandom fallback.  getentropy
--  is a libSystem symbol available since macOS 10.12, so keeping this body
--  macOS-only avoids link failures on platforms that lack it.
package body CryptoLib.OS_Random is

   use type Ada.Streams.Stream_Element_Offset;

   --  getentropy(2): fills Buf with Buflen CSPRNG bytes.  Returns 0 on success
   --  and -1 on error, driving the /dev/urandom fallback.  Unlike Linux's
   --  getrandom(2) it is all-or-nothing and refuses Buflen > 256, so callers
   --  must chunk larger requests.
   function C_Getentropy
     (Buf    : System.Address;
      Buflen : Interfaces.C.size_t) return Interfaces.C.int
     with Import, Convention => C, External_Name => "getentropy";

   Max_Getentropy : constant Ada.Streams.Stream_Element_Offset := 256;

   procedure Fill_OS
     (Buffer  : out Ada.Streams.Stream_Element_Array;
      Success : out Boolean)
   is
      use type Interfaces.C.int;
      package Stream_IO renames Ada.Streams.Stream_IO;
      File_Item : Stream_IO.File_Type;
      Last_Read : Ada.Streams.Stream_Element_Offset;
      Next_Item : Ada.Streams.Stream_Element_Offset := Buffer'First;
      Chunk_End : Ada.Streams.Stream_Element_Offset;
      Got       : Interfaces.C.int;
      Have_Getentropy : Boolean := True;
   begin
      Success := False;
      if Buffer'Length = 0 then
         Success := True;
         return;
      end if;

      --  Preferred source: getentropy(2), in chunks of at most 256 bytes.
      while Next_Item <= Buffer'Last loop
         Chunk_End :=
           Ada.Streams.Stream_Element_Offset'Min
             (Buffer'Last, Next_Item + Max_Getentropy - 1);
         Got :=
           C_Getentropy
             (Buffer (Next_Item)'Address,
              Interfaces.C.size_t (Chunk_End - Next_Item + 1));
         if Got /= 0 then
            Have_Getentropy := False;
            exit;
         end if;
         Next_Item := Chunk_End + 1;
      end loop;
      if Have_Getentropy then
         Success := True;
         return;
      end if;

      --  Fallback: /dev/urandom.
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
