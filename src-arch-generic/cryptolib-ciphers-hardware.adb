--  A host with no x86-64 instructions to use: the portable code runs.
package body CryptoLib.Ciphers.Hardware
  with SPARK_Mode => Off
is

   function Available return Boolean is (False);

   procedure Encrypt
     (Keys      : Round_Block_Array;
      Rounds    : Natural;
      Block_In  : Counter_Block;
      Block_Out : out Counter_Block)
   is
      pragma Unreferenced (Keys, Rounds, Block_In);
   begin
      Block_Out := [others => 0];
      raise Program_Error with "no AES instructions on this host";
   end Encrypt;

   function Multiply (X, H : Counter_Block) return Counter_Block is
      pragma Unreferenced (X, H);
   begin
      raise Program_Error with "no carry-less multiply on this host";
      return [others => 0];
   end Multiply;

end CryptoLib.Ciphers.Hardware;
