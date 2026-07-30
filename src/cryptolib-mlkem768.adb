with System;

with CryptoLib.MLKEM;
with CryptoLib.Secure_Wipe;

package body CryptoLib.MLKEM768 is

   --  Every operation here is CryptoLib.MLKEM at ML_KEM_768. This package
   --  predates that one and keeps its fixed-length subtypes, which suit a
   --  caller that only ever wants this parameter set -- ssh_lib's key
   --  exchange is typed on them. What it no longer keeps is a second copy of
   --  the KEM: the algorithm lives in one place, so a correction to the
   --  decapsulation path cannot reach one caller and miss the other.
   Set : constant CryptoLib.MLKEM.Parameter_Set := CryptoLib.MLKEM.ML_KEM_768;

   function Generate_Keypair
     (Source_Item : in out CryptoLib.Random.Random_Source;
      Public_Item : out Public_Key;
      Secret_Item : out Secret_Key)
      return CryptoLib.Errors.Status
   is (CryptoLib.MLKEM.Generate_Keypair
         (Set, Source_Item, Public_Item, Secret_Item));

   function Encapsulate
     (Source_Item     : in out CryptoLib.Random.Random_Source;
      Public_Item     : Public_Key;
      Ciphertext_Item : out Ciphertext;
      Shared_Item     : out Shared_Key)
      return CryptoLib.Errors.Status
   is (CryptoLib.MLKEM.Encapsulate
         (Set, Source_Item, Public_Item, Ciphertext_Item, Shared_Item));

   function Decapsulate
     (Secret_Item     : Secret_Key;
      Ciphertext_Item : Ciphertext;
      Shared_Item     : out Shared_Key)
      return CryptoLib.Errors.Status
   is (CryptoLib.MLKEM.Decapsulate
         (Set, Secret_Item, Ciphertext_Item, Shared_Item));

   procedure Clear (Item : out Secret_Key) is
      use System;
   begin
      Item := [others => 0];
      CryptoLib.Secure_Wipe.Wipe (Item'Address, Item'Length);
   end Clear;

end CryptoLib.MLKEM768;
