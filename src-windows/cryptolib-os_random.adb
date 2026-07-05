with Interfaces.C;
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
   function BCrypt_Gen_Random
     (Algorithm : System.Address;
      Buffer    : System.Address;
      Count     : Interfaces.C.unsigned_long;
      Flags     : Interfaces.C.unsigned_long) return Interfaces.C.long
     with Import, Convention => C, External_Name => "BCryptGenRandom";

   procedure Fill_OS
     (Buffer  : out Ada.Streams.Stream_Element_Array;
      Success : out Boolean)
   is
      use type Interfaces.C.long;
      Status : Interfaces.C.long;
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
           Count     => Interfaces.C.unsigned_long (Buffer'Length),
           Flags     => BCRYPT_USE_SYSTEM_PREFERRED_RNG);
      Success := Status = STATUS_SUCCESS;
      if not Success then
         Buffer := [others => 0];
      end if;
   end Fill_OS;

end CryptoLib.OS_Random;
