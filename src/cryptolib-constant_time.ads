with Ada.Streams;

--  @summary Constant-time byte-array comparison for secret values such as MAC
--  and authentication tags.
--
--  Equal inspects every byte without an early return, so its running time does
--  not reveal where two arrays first differ -- avoiding the timing side channel
--  of an ordinary "=" when comparing tags, MACs, or other secrets.
package CryptoLib.Constant_Time
  with SPARK_Mode => On
is
   pragma Preelaborate;

   --  Compare two byte arrays in time independent of their contents.
   --  @param Left_Value  the first array
   --  @param Right_Value the second array
   --  @return True when both arrays have equal length and identical bytes
   function Equal
     (Left_Value  : Ada.Streams.Stream_Element_Array;
      Right_Value : Ada.Streams.Stream_Element_Array)
      return Boolean
     with SPARK_Mode => On;
end CryptoLib.Constant_Time;
