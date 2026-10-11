--  A host with no x86-64 instructions to use: the portable code runs.
package body CryptoLib.Hashes.Hardware
  with SPARK_Mode => Off
is

   function Available return Boolean is (False);

   procedure Compress (State : in out SHA256_State; Block : SHA256_Block) is
      pragma Unreferenced (State, Block);
   begin
      raise Program_Error with "no SHA instructions on this host";
   end Compress;

   procedure Compress_SHA1 (State : in out SHA1_State; Block : SHA1_Block) is
      pragma Unreferenced (State, Block);
   begin
      raise Program_Error with "no SHA instructions on this host";
   end Compress_SHA1;

end CryptoLib.Hashes.Hardware;
