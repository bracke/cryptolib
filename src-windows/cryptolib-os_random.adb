with Interfaces;
with System;

--  Windows OS CSPRNG: BCryptGenRandom (bcrypt.dll) with a null algorithm handle
--  and BCRYPT_USE_SYSTEM_PREFERRED_RNG, which draws directly from the system
--  preferred RNG.  Convention => C matches the x64 WINAPI ABI (a 32-bit build
--  would need Convention => Stdcall).  UNVERIFIED on this build host (Linux):
--  written to the documented API but not compiled/linked/run against Windows.
package body CryptoLib.OS_Random is

   pragma Linker_Options ("-lbcrypt");

   BCRYPT_USE_SYSTEM_PREFERRED_RNG : constant := 16#0000_0002#;
   STATUS_SUCCESS                  : constant := 0;

   --  NTSTATUS BCryptGenRandom(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer,
   --                           ULONG cbBuffer, ULONG dwFlags);
   --
   --  ULONG and NTSTATUS are 32 bits on Windows whatever the word size, that
   --  being what LLP64 means. Interfaces.C.unsigned_long would follow the
   --  target's C compiler instead and happens to agree there -- these say so
   --  outright, so the binding does not rest on that agreeing.
   function BCrypt_Gen_Random
     (Algorithm : System.Address;
      Buffer    : System.Address;
      Count     : Interfaces.Unsigned_32;
      Flags     : Interfaces.Unsigned_32) return Interfaces.Integer_32
     with Import, Convention => C, External_Name => "BCryptGenRandom";

   procedure Fill_OS
     (Buffer  : out Ada.Streams.Stream_Element_Array;
      Success : out Boolean)
   is
      use type Interfaces.Integer_32;
      Status : Interfaces.Integer_32;
   begin
      Success := False;
      Buffer  := [others => 0];
      if Buffer'Length = 0 then
         Success := True;
         return;
      end if;
      Status :=
        BCrypt_Gen_Random
          (Algorithm => System.Null_Address,
           Buffer    => Buffer'Address,
           Count     => Interfaces.Unsigned_32 (Buffer'Length),
           Flags     => BCRYPT_USE_SYSTEM_PREFERRED_RNG);
      Success := Status = STATUS_SUCCESS;
      if not Success then
         Buffer := [others => 0];
      end if;
   end Fill_OS;

end CryptoLib.OS_Random;
