with Ada.Streams;

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

   function Same_Serial
     (Left : CryptoLib.ASN1.Octets; Right : CryptoLib.ASN1.Octets)
      return Boolean
   is
      use type CryptoLib.ASN1.Offset;
      use type Ada.Streams.Stream_Element;
      L : CryptoLib.ASN1.Offset := Left'First;
      R : CryptoLib.ASN1.Offset := Right'First;
   begin
      while L <= Left'Last and then Left (L) = 0 loop
         L := L + 1;
      end loop;
      while R <= Right'Last and then Right (R) = 0 loop
         R := R + 1;
      end loop;

      --  Two serials that are both zero are not a certificate's serial
      --  either way -- RFC 5280 requires a positive one -- so this says no
      --  rather than matching everything that failed to parse.
      if L > Left'Last or else R > Right'Last then
         return False;
      end if;

      if Left'Last - L /= Right'Last - R then
         return False;
      end if;

      while L <= Left'Last loop
         if Left (L) /= Right (R) then
            return False;
         end if;
         L := L + 1;
         R := R + 1;
      end loop;

      return True;
   end Same_Serial;

end CryptoLib.X509;
