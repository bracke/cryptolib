package body CryptoLib.ASN1.OIDs is

   function Matches
     (Data       : Octets;
      Item       : Element;
      Identifier : Octets) return Boolean
   is
   begin
      if Content_Length (Item) /= Identifier'Length then
         return False;
      end if;

      if Identifier'Length = 0 then
         return True;
      end if;

      if Item.First < Data'First or else Item.Last > Data'Last then
         return False;
      end if;

      for I in 0 .. Identifier'Length - 1 loop
         if Data (Item.First + Offset (I)) /= Identifier (Identifier'First + Offset (I))
         then
            return False;
         end if;
      end loop;

      return True;
   end Matches;

end CryptoLib.ASN1.OIDs;
