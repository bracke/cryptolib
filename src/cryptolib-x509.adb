package body CryptoLib.X509 is

   function Is_Not_After
     (Left : Certificate_Time; Right : Certificate_Time) return Boolean
   is
      --  Compared field by field, most significant first, rather than by
      --  converting to a scalar. A certificate's time has no zone and no
      --  epoch; giving it one to compare it would be inventing information.
      type Field_Index is range 1 .. 6;

      function Field (T : Certificate_Time; I : Field_Index) return Natural
      is (case I is
             when 1 => T.Year,
             when 2 => T.Month,
             when 3 => T.Day,
             when 4 => T.Hour,
             when 5 => T.Minute,
             when 6 => T.Second);
   begin
      for I in Field_Index loop
         if Field (Left, I) /= Field (Right, I) then
            return Field (Left, I) < Field (Right, I);
         end if;
      end loop;

      return True;
   end Is_Not_After;

end CryptoLib.X509;
