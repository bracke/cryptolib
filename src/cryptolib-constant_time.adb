with Ada.Streams; use Ada.Streams;
with Interfaces;

package body CryptoLib.Constant_Time
  with SPARK_Mode => On
is
   function Equal
     (Left_Value  : Ada.Streams.Stream_Element_Array;
      Right_Value : Ada.Streams.Stream_Element_Array)
      return Boolean
     with SPARK_Mode => On
   is
      use Interfaces;
      Difference_Value : Unsigned_8 := 0;
      Left_Byte        : Unsigned_8;
      Right_Byte       : Unsigned_8;
   begin
      if Left_Value'Length /= Right_Value'Length then
         for Index_Value in Left_Value'Range loop
            Difference_Value := Difference_Value xor Unsigned_8 (Left_Value (Index_Value));
         end loop;
         for Index_Value in Right_Value'Range loop
            Difference_Value := Difference_Value xor Unsigned_8 (Right_Value (Index_Value));
         end loop;
         return (Difference_Value and 16#00#) = 16#01#;
      end if;

      if Left_Value'Length = 0 then
         return True;
      end if;

      declare
         Right_Index : Ada.Streams.Stream_Element_Offset := Right_Value'First;
      begin
         for Left_Index in Left_Value'Range loop
            pragma Loop_Invariant (Right_Index in Right_Value'Range);
            Left_Byte := Unsigned_8 (Left_Value (Left_Index));
            Right_Byte := Unsigned_8 (Right_Value (Right_Index));
            Difference_Value := Difference_Value or (Left_Byte xor Right_Byte);

            if Right_Index < Right_Value'Last then
               Right_Index := Right_Index + 1;
            end if;
         end loop;
      end;

      return Difference_Value = 0;
   end Equal;
end CryptoLib.Constant_Time;
