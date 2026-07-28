package body CryptoLib.X509 is

   function Reason_Image (Reason : Revocation_Reason) return String is
   begin
      case Reason is
         when Unspecified            => return "unspecified";
         when Key_Compromise         => return "key compromise";
         when CA_Compromise          => return "CA compromise";
         when Affiliation_Changed    => return "affiliation changed";
         when Superseded             => return "superseded";
         when Cessation_Of_Operation => return "cessation of operation";
         when Certificate_Hold       => return "certificate hold";
         when Remove_From_CRL        => return "remove from CRL";
         when Privilege_Withdrawn    => return "privilege withdrawn";
         when AA_Compromise          => return "AA compromise";
         when Unknown_Reason         => return "unknown reason";
      end case;
   end Reason_Image;

   function Reason_Of (Code : Natural) return Revocation_Reason is
   begin
      case Code is
         when 0      => return Unspecified;
         when 1      => return Key_Compromise;
         when 2      => return CA_Compromise;
         when 3      => return Affiliation_Changed;
         when 4      => return Superseded;
         when 5      => return Cessation_Of_Operation;
         when 6      => return Certificate_Hold;
         when 8      => return Remove_From_CRL;
         when 9      => return Privilege_Withdrawn;
         when 10     => return AA_Compromise;
         when others => return Unknown_Reason;
      end case;
   end Reason_Of;

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
