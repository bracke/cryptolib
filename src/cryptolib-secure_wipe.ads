with System;

--  @summary Portable, non-elidable secret zeroization.
--
--  Overwrites memory with zero through volatile stores, which the compiler is
--  not permitted to elide -- so it works the same on every target without a
--  libc/OS primitive (explicit_bzero / SecureZeroMemory).  Use it to scrub key
--  material and secret intermediates before they leave scope; a plain
--  "X := [others => 0]" on a dead local is removed by the optimizer.
package CryptoLib.Secure_Wipe is

   --  Zero Length bytes of memory starting at Address. The stores are volatile
   --  and cannot be optimized away even when the target memory is never read.
   --  @param Address the first byte of the region to overwrite
   --  @param Length  the number of bytes to zero
   procedure Wipe (Address : System.Address; Length : Natural);

end CryptoLib.Secure_Wipe;
