with Ada.Streams;

--  @summary Per-OS backend that fills a buffer from the operating-system CSPRNG.
--
--  Operating-system CSPRNG access.  The body is selected per platform by the
--  project file (Source_Dirs = "src-" & <host OS>): src-linux uses getrandom(2)
--  with a /dev/urandom fallback; src-macos uses getentropy(2) with the same
--  fallback; src-windows uses BCryptGenRandom.  Callers must fail closed --
--  Success = False means no OS entropy source was available and Buffer has been
--  zeroed.
package CryptoLib.OS_Random is

   --  Fill Buffer with bytes from the operating-system CSPRNG, failing closed.
   --  @param Buffer  the array to fill; zeroed in full when no entropy is available
   --  @param Success True when Buffer was filled with OS entropy, False otherwise
   procedure Fill_OS
     (Buffer  : out Ada.Streams.Stream_Element_Array;
      Success : out Boolean);

end CryptoLib.OS_Random;
