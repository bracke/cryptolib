with Interfaces;

package body CryptoLib.Secure_Wipe is

   procedure Wipe (Address : System.Address; Length : Natural) is
      type Byte_Buffer is array (1 .. Length) of Interfaces.Unsigned_8
        with Volatile_Components;
      Overlay : Byte_Buffer with Address => Address, Import, Volatile;
   begin
      for Index in Overlay'Range loop
         Overlay (Index) := 0;
      end loop;
   end Wipe;

end CryptoLib.Secure_Wipe;
