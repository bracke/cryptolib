with CryptoLib.OS_Random;

package body CryptoLib.Random is
   use type Ada.Streams.Stream_Element_Offset;

   procedure Initialize_Production (Source_Item : out Random_Source)
     with SPARK_Mode => On
   is
   begin
      Source_Item.Mode_Item := Production_Mode;
      Source_Item.Pattern_Data := [others => 0];
      Source_Item.Pattern_Length := 0;
      Source_Item.Cursor_Index := 0;
   end Initialize_Production;

   procedure Initialize_Deterministic
     (Source_Item : out Random_Source;
      Pattern     : Ada.Streams.Stream_Element_Array)
     with SPARK_Mode => On
   is
      Cursor : Ada.Streams.Stream_Element_Offset := Pattern'First;
   begin
      Source_Item.Mode_Item := Deterministic_Mode;
      Source_Item.Pattern_Data := [others => 0];
      Source_Item.Pattern_Length := 0;
      Source_Item.Cursor_Index := 0;

      while Cursor <= Pattern'Last
        and then Source_Item.Pattern_Length < Max_Deterministic_Pattern_Length
      loop
         pragma Loop_Invariant
           (Source_Item.Pattern_Length < Max_Deterministic_Pattern_Length);
         pragma Loop_Invariant (Cursor in Pattern'Range);

         Source_Item.Pattern_Length := Source_Item.Pattern_Length + 1;
         Source_Item.Pattern_Data
           (Ada.Streams.Stream_Element_Offset (Source_Item.Pattern_Length)) :=
           Pattern (Cursor);

         exit when Cursor = Pattern'Last;
         Cursor := Cursor + 1;
      end loop;
   end Initialize_Deterministic;

   procedure Initialize_Failing (Source_Item : out Random_Source)
     with SPARK_Mode => On
   is
   begin
      Source_Item.Mode_Item := Failing_Mode;
      Source_Item.Pattern_Data := [others => 0];
      Source_Item.Pattern_Length := 0;
      Source_Item.Cursor_Index := 0;
   end Initialize_Failing;

   function Fill
     (Source_Item : in out Random_Source;
      Buffer      : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
   begin
      if Buffer'Length = 0 then
         return CryptoLib.Errors.Ok;
      end if;

      case Source_Item.Mode_Item is
         when Failing_Mode =>
            Buffer := [others => 0];
            return CryptoLib.Errors.Internal_Error;

         when Deterministic_Mode =>
            if Source_Item.Pattern_Length = 0 then
               Buffer := [others => 0];
               return CryptoLib.Errors.Internal_Error;
            end if;

            for Index_Value in Buffer'Range loop
               Buffer (Index_Value) := Source_Item.Pattern_Data
                 (Ada.Streams.Stream_Element_Offset
                    ((Source_Item.Cursor_Index mod Source_Item.Pattern_Length) + 1));
               Source_Item.Cursor_Index := Source_Item.Cursor_Index + 1;
            end loop;
            return CryptoLib.Errors.Ok;

         when Production_Mode =>
            declare
               Success : Boolean;
            begin
               --  Platform OS CSPRNG (getrandom/urandom on Linux, BCryptGenRandom
               --  on Windows); fail closed if none is available.
               CryptoLib.OS_Random.Fill_OS (Buffer, Success);
               if Success then
                  return CryptoLib.Errors.Ok;
               else
                  return CryptoLib.Errors.Internal_Error;
               end if;
            end;
      end case;
   end Fill;
end CryptoLib.Random;
