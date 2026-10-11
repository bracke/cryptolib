--  AES and GHASH by the processor's own instructions, where it has them:
--  AES-NI for the rounds, PCLMULQDQ for GHASH's carry-less multiply. Both
--  run in time that does not depend on the data, as the bitsliced code
--  they stand in for does, and several hundred times faster -- the
--  bitsliced AES held a TLS download to a megabyte a second on a core.
--  Whether they are there is asked of the processor once; where they are
--  not, or the host is no x86-64, Available is False and the portable code
--  runs.
private package CryptoLib.Ciphers.Hardware
  with SPARK_Mode => Off
is

   --  Whether this processor has AES-NI and PCLMULQDQ.
   --
   --  @return True where Encrypt and Multiply may be called.
   function Available return Boolean;

   --  One block encrypted under an expanded key, as Encrypt_Block does.
   --
   --  @param Keys The round keys, each as its sixteen bytes.
   --  @param Rounds 10, 12 or 14.
   --  @param Block_In The plaintext block.
   --  @param Block_Out The ciphertext block.
   procedure Encrypt
     (Keys      : Round_Block_Array;
      Rounds    : Natural;
      Block_In  : Counter_Block;
      Block_Out : out Counter_Block);

   --  The GHASH product X times H in GF(2**128), as GHASH_Multiply gives it.
   --
   --  @param X The running value.
   --  @param H The hash subkey.
   --  @return The product.
   function Multiply (X, H : Counter_Block) return Counter_Block;

end CryptoLib.Ciphers.Hardware;
