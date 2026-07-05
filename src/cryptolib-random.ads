with Ada.Streams;
with CryptoLib.Errors;

--  @summary CSPRNG source that fails closed: production mode draws from the OS
--  entropy pool, while deterministic and failing modes exist only for testing.
--
--  A Random_Source is configured by one of the Initialize_* procedures and then
--  drained through Fill.  Production_Mode delegates to the OS CSPRNG
--  (getrandom/urandom, BCryptGenRandom); Deterministic_Mode repeats a fixed
--  pattern for reproducible tests; Failing_Mode always reports failure to
--  exercise fail-closed error paths.
package CryptoLib.Random is
   type Random_Source is limited private;

   --  Configure the source to draw from the operating-system CSPRNG.
   --  @param Source_Item the source to initialize in production mode
   procedure Initialize_Production (Source_Item : out Random_Source)
     with SPARK_Mode => On;

   --  Configure the source to emit a fixed, repeating pattern (tests only).
   --  @param Source_Item the source to initialize in deterministic mode
   --  @param Pattern     the byte sequence cycled by Fill; truncated to 256 bytes
   procedure Initialize_Deterministic
     (Source_Item : out Random_Source;
      Pattern     : Ada.Streams.Stream_Element_Array)
     with SPARK_Mode => On;

   --  Configure the source so that every Fill call fails (tests only).
   --  @param Source_Item the source to initialize in failing mode
   procedure Initialize_Failing (Source_Item : out Random_Source)
     with SPARK_Mode => On;

   --  Fill Buffer with bytes according to the source's mode.
   --  @param Source_Item the configured source, advanced as bytes are drawn
   --  @param Buffer      the array to fill; zeroed on failure
   --  @return Ok on success, Internal_Error when the OS/mode cannot supply bytes
   function Fill
     (Source_Item : in out Random_Source;
      Buffer      : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

private
   type Source_Mode is (Production_Mode, Deterministic_Mode, Failing_Mode);

   Max_Deterministic_Pattern_Length : constant Natural := 256;

   type Random_Source is limited record
      Mode_Item      : Source_Mode := Production_Mode;
      Pattern_Data   : Ada.Streams.Stream_Element_Array
        (Ada.Streams.Stream_Element_Offset (1)
         .. Ada.Streams.Stream_Element_Offset
              (Max_Deterministic_Pattern_Length)) := [others => 0];
      Pattern_Length : Natural := 0;
      Cursor_Index   : Natural := 0;
   end record;
end CryptoLib.Random;
