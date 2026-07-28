with Ada.Streams;

with CryptoLib.X509.Extensions;

package body CryptoLib.X509.Identity is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.X509.Extensions.General_Name_Kind;

   package X509C renames CryptoLib.X509.Certificates;
   package XE renames CryptoLib.X509.Extensions;

   function Result_Image (Result : Match_Result) return String is
   begin
      case Result is
         when Matched             => return "matched";
         when No_Match            => return "no match";
         when No_Names_Present    => return "no names present";
         when Malformed_Reference => return "malformed reference";
         when Malformed_Identity  => return "malformed identity";
      end case;
   end Result_Image;

   function Lower (C : Character) return Character
   is (if C in 'A' .. 'Z'
       then Character'Val (Character'Pos (C) + 32)
       else C);

   --  A name with one trailing dot means the same as the name without it.
   function Without_Root_Dot (Name : String) return String
   is (if Name'Length > 1 and then Name (Name'Last) = '.'
       then Name (Name'First .. Name'Last - 1)
       else Name);

   --  Is this usable as a DNS name at all?
   --
   --  Empty labels are refused as well as empty names: "a..example.com" has a
   --  label that is nothing, and two readers will not agree on what it means.
   function Well_Formed (Name : String) return Boolean is
      Label_Length : Natural := 0;
   begin
      if Name'Length = 0 then
         return False;
      end if;

      for C of Name loop
         --  A NUL in a name is the classic way to make one reader see
         --  "example.com" where another sees the whole string.
         if C = ASCII.NUL then
            return False;
         end if;

         if C = '.' then
            if Label_Length = 0 then
               return False;
            end if;
            Label_Length := 0;
         else
            Label_Length := Label_Length + 1;
            if Label_Length > 63 then
               return False;
            end if;
         end if;
      end loop;

      return Label_Length /= 0;
   end Well_Formed;

   function Equal_Ignoring_Case (Left : String; Right : String) return Boolean
   is
   begin
      if Left'Length /= Right'Length then
         return False;
      end if;

      for I in 0 .. Left'Length - 1 loop
         if Lower (Left (Left'First + I)) /= Lower (Right (Right'First + I))
         then
            return False;
         end if;
      end loop;

      return True;
   end Equal_Ignoring_Case;

   --  Where the first label ends.
   function First_Dot (Name : String) return Natural is
   begin
      for I in Name'Range loop
         if Name (I) = '.' then
            return I;
         end if;
      end loop;
      return 0;
   end First_Dot;

   --  Does a presented name that begins "*." cover this reference?
   --
   --  The wildcard stands for exactly one label, so the reference must have a
   --  first label of its own and the rest must match exactly. That "exactly
   --  one" is what keeps "*.example.com" away from "a.b.example.com", and the
   --  requirement that the remainder still contain a dot is what keeps it
   --  away from a top-level name.
   function Wildcard_Matches
     (Presented : String; Reference : String) return Boolean
   is
      P_Dot : constant Natural := First_Dot (Presented);
      R_Dot : constant Natural := First_Dot (Reference);
   begin
      if P_Dot = 0 or else R_Dot = 0 then
         return False;
      end if;

      --  The whole first label must be the wildcard. A partial wildcard is
      --  not matched at all rather than being treated as a literal, so that a
      --  certificate carrying one cannot match anything by accident.
      if P_Dot /= Presented'First + 1
        or else Presented (Presented'First) /= '*'
      then
         return False;
      end if;

      declare
         P_Rest : constant String :=
           Presented (P_Dot + 1 .. Presented'Last);
         R_Rest : constant String :=
           Reference (R_Dot + 1 .. Reference'Last);
      begin
         --  Refuse to cover a name with no domain part left, so "*.com"
         --  cannot stand for every name under a top-level label here.
         if First_Dot (P_Rest) = 0 then
            return False;
         end if;

         return Equal_Ignoring_Case (P_Rest, R_Rest);
      end;
   end Wildcard_Matches;

   function Match_DNS_Name
     (Item      : Certificate;
      Reference : String;
      Policy    : Matching_Policy := Default_Policy) return Match_Result
   is
      Wanted  : constant String := Without_Root_Dot (Reference);
      Total   : constant Natural :=
        XE.Subject_Alternative_Name_Count (Item);
      Seen    : Natural := 0;
      Outcome : Match_Result := No_Names_Present;
   begin
      if not Well_Formed (Wanted) then
         return Malformed_Reference;
      end if;

      for I in 1 .. Total loop
         if XE.Subject_Alternative_Name_Kind (Item, I) = XE.DNS_Name then
            Seen := Seen + 1;
            declare
               Presented : constant String :=
                 Without_Root_Dot
                   (XE.Subject_Alternative_Name_Text (Item, I));
            begin
               if Presented'Length = 0
                 or else not Well_Formed
                               (if Presented (Presented'First) = '*'
                                and then Presented'Length > 2
                                then Presented (Presented'First + 2
                                                .. Presented'Last)
                                else Presented)
               then
                  --  Surfaced rather than skipped: a name that cannot be
                  --  read is a reason to distrust the certificate, not a
                  --  reason to try the next entry.
                  return Malformed_Identity;
               end if;

               if Equal_Ignoring_Case (Presented, Wanted) then
                  return Matched;
               end if;

               if Policy.Allow_Wildcards
                 and then Presented'Length > 1
                 and then Presented (Presented'First) = '*'
                 and then Wildcard_Matches (Presented, Wanted)
               then
                  return Matched;
               end if;
            end;
         end if;
      end loop;

      if Seen > 0 then
         Outcome := No_Match;
      end if;

      --  The fallback exists for private CAs that predate the requirement to
      --  put names in the extension. RFC 9525 does not permit it; this is a
      --  concession a caller must ask for by name.
      if Policy.Allow_Common_Name_Fallback and then Seen = 0 then
         declare
            Common : constant String :=
              Without_Root_Dot (X509C.Subject_Common_Name (Item));
         begin
            if Common'Length > 0 and then Well_Formed (Common) then
               if Equal_Ignoring_Case (Common, Wanted) then
                  return Matched;
               end if;
               if Policy.Allow_Wildcards
                 and then Common (Common'First) = '*'
                 and then Wildcard_Matches (Common, Wanted)
               then
                  return Matched;
               end if;
               Outcome := No_Match;
            end if;
         end;
      end if;

      return Outcome;
   end Match_DNS_Name;

   function Match_IP_Address
     (Item    : Certificate;
      Address : Octets;
      Policy  : Matching_Policy := Default_Policy) return Match_Result
   is
      pragma Unreferenced (Policy);

      Total   : constant Natural :=
        XE.Subject_Alternative_Name_Count (Item);
      Seen    : Natural := 0;
   begin
      --  Only the two widths an address has. Anything else is not one, and
      --  guessing what a caller meant by five octets is not this package's
      --  business.
      if Address'Length /= 4 and then Address'Length /= 16 then
         return Malformed_Reference;
      end if;

      for I in 1 .. Total loop
         if XE.Subject_Alternative_Name_Kind (Item, I) = XE.IP_Address then
            Seen := Seen + 1;
            declare
               Presented : constant Octets :=
                 XE.Subject_Alternative_Name_Bytes (Item, I);
            begin
               if Presented'Length /= 4 and then Presented'Length /= 16 then
                  return Malformed_Identity;
               end if;

               if Presented'Length = Address'Length then
                  declare
                     Same : Boolean := True;
                  begin
                     for J in 0 .. Address'Length - 1 loop
                        if Presented (Presented'First + Offset (J))
                          /= Address (Address'First + Offset (J))
                        then
                           Same := False;
                           exit;
                        end if;
                     end loop;
                     if Same then
                        return Matched;
                     end if;
                  end;
               end if;
            end;
         end if;
      end loop;

      return (if Seen > 0 then No_Match else No_Names_Present);
   end Match_IP_Address;

end CryptoLib.X509.Identity;
