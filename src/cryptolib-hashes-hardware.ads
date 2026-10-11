--  SHA-256 by the processor's own instructions, where it has them: the
--  SHA extensions' rounds and message schedule. Asked of the processor
--  once; where they are not there, or the host is no x86-64, Available is
--  False and the portable code runs.
private package CryptoLib.Hashes.Hardware
  with SPARK_Mode => Off, Preelaborate
is

   --  Whether this processor has the SHA extensions.
   --
   --  @return True where Compress may be called.
   function Available return Boolean;

   --  One 64-byte block folded into the state, as Process_Block folds it.
   --
   --  @param State The eight working words, updated.
   --  @param Block The block.
   procedure Compress (State : in out SHA256_State; Block : SHA256_Block);

   --  One 64-byte block folded into a SHA-1 state, as Process_SHA1_Block
   --  folds it.
   --
   --  @param State The five working words, updated.
   --  @param Block The block.
   procedure Compress_SHA1 (State : in out SHA1_State; Block : SHA1_Block);

end CryptoLib.Hashes.Hardware;
