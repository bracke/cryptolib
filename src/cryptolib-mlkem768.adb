with CryptoLib.Constant_Time;
with CryptoLib.MLKEM768_Core;
with CryptoLib.SHA3;

package body CryptoLib.MLKEM768 is
   use Ada.Streams;
   use CryptoLib.Errors;

   subtype Seed_32 is Stream_Element_Array
     (Stream_Element_Offset'(1) .. Stream_Element_Offset'(32));
   subtype Digest_64 is Stream_Element_Array
     (Stream_Element_Offset'(1) .. Stream_Element_Offset'(64));

   PKE_Secret_Offset : constant Natural := 0;
   Public_Offset     : constant Natural := CryptoLib.MLKEM768_Core.PKE_Secret_Key'Length;
   Hash_Offset       : constant Natural := Public_Offset + Public_Key_Length;
   Z_Offset          : constant Natural := Hash_Offset + 32;

   function To_Array (Digest : CryptoLib.SHA3.SHA3_256_Digest)
      return Seed_32
     with SPARK_Mode => On
   is
      Result : Seed_32 := [others => 0];
   begin
      for Index_Value in Digest'Range loop
         Result (Stream_Element_Offset (Index_Value)) := Digest (Index_Value);
      end loop;
      return Result;
   end To_Array;

   function To_Array (Digest : CryptoLib.SHA3.SHA3_512_Digest)
      return Digest_64
     with SPARK_Mode => On
   is
      Result : Digest_64 := [others => 0];
   begin
      for Index_Value in Digest'Range loop
         Result (Stream_Element_Offset (Index_Value)) := Digest (Index_Value);
      end loop;
      return Result;
   end To_Array;

   function H (Data : Stream_Element_Array) return Seed_32 is
   begin
      return To_Array (CryptoLib.SHA3.SHA3_256 (Data));
   end H;

   function G (Data : Stream_Element_Array) return Digest_64 is
   begin
      return To_Array (CryptoLib.SHA3.SHA3_512 (Data));
   end G;

   function KDF (Data : Stream_Element_Array) return Shared_Key is
      Expanded : constant Stream_Element_Array :=
        CryptoLib.SHA3.SHAKE256 (Data, Shared_Key_Length);
      Result   : Shared_Key := [others => 0];
   begin
      for Offset_Value in 0 .. Shared_Key_Length - 1 loop
         Result (Result'First + Stream_Element_Offset (Offset_Value)) :=
           Expanded (Expanded'First + Stream_Element_Offset (Offset_Value));
      end loop;
      return Result;
   end KDF;

   procedure Copy_Slice
     (Source_Item : Stream_Element_Array;
      Target_Item : in out Stream_Element_Array;
      Target_Offset : Natural)
   is
   begin
      for Offset_Value in 0 .. Source_Item'Length - 1 loop
         Target_Item
           (Target_Item'First + Stream_Element_Offset (Target_Offset + Offset_Value)) :=
           Source_Item (Source_Item'First + Stream_Element_Offset (Offset_Value));
      end loop;
   end Copy_Slice;

   function Public_From_Secret (Secret_Item : Secret_Key) return Public_Key
     with SPARK_Mode => On
   is
      Result : Public_Key := [others => 0];
   begin
      for Offset_Value in 0 .. Public_Key_Length - 1 loop
         Result (Result'First + Stream_Element_Offset (Offset_Value)) :=
           Secret_Item (Secret_Item'First + Stream_Element_Offset (Public_Offset + Offset_Value));
      end loop;
      return Result;
   end Public_From_Secret;

   function Public_Hash_From_Secret (Secret_Item : Secret_Key) return Seed_32
     with SPARK_Mode => On
   is
      Result : Seed_32 := [others => 0];
   begin
      for Offset_Value in 0 .. 31 loop
         Result (Result'First + Stream_Element_Offset (Offset_Value)) :=
           Secret_Item (Secret_Item'First + Stream_Element_Offset (Hash_Offset + Offset_Value));
      end loop;
      return Result;
   end Public_Hash_From_Secret;

   function Z_From_Secret (Secret_Item : Secret_Key) return Seed_32
     with SPARK_Mode => On
   is
      Result : Seed_32 := [others => 0];
   begin
      for Offset_Value in 0 .. 31 loop
         Result (Result'First + Stream_Element_Offset (Offset_Value)) :=
           Secret_Item (Secret_Item'First + Stream_Element_Offset (Z_Offset + Offset_Value));
      end loop;
      return Result;
   end Z_From_Secret;

   function PKE_Secret_From_Secret (Secret_Item : Secret_Key)
      return CryptoLib.MLKEM768_Core.PKE_Secret_Key
     with SPARK_Mode => On
   is
      Result : CryptoLib.MLKEM768_Core.PKE_Secret_Key := [others => 0];
   begin
      for Offset_Value in 0 .. Result'Length - 1 loop
         Result (Result'First + Stream_Element_Offset (Offset_Value)) :=
           Secret_Item (Secret_Item'First + Stream_Element_Offset (PKE_Secret_Offset + Offset_Value));
      end loop;
      return Result;
   end PKE_Secret_From_Secret;

   function Message_From_Seed (Seed : Seed_32)
      return CryptoLib.MLKEM768_Core.MLKEM_Message
     with SPARK_Mode => On
   is
      Result : CryptoLib.MLKEM768_Core.MLKEM_Message := [others => 0];
   begin
      for Offset_Value in 0 .. 31 loop
         Result (Result'First + Stream_Element_Offset (Offset_Value)) :=
           Seed (Seed'First + Stream_Element_Offset (Offset_Value));
      end loop;
      return Result;
   end Message_From_Seed;

   function Coins_From_Seed (Seed : Seed_32)
      return CryptoLib.MLKEM768_Core.MLKEM_Noise_Seed
     with SPARK_Mode => On
   is
      Result : CryptoLib.MLKEM768_Core.MLKEM_Noise_Seed := [others => 0];
   begin
      for Offset_Value in 0 .. 31 loop
         Result (Result'First + Stream_Element_Offset (Offset_Value)) :=
           Seed (Seed'First + Stream_Element_Offset (Offset_Value));
      end loop;
      return Result;
   end Coins_From_Seed;

   function Combine_2 (Left, Right : Seed_32) return Stream_Element_Array is
      Result : Stream_Element_Array (1 .. 64) := [others => 0];
   begin
      Copy_Slice (Left, Result, 0);
      Copy_Slice (Right, Result, 32);
      return Result;
   end Combine_2;

   function Combine_Key_Material
     (Left : Seed_32;
      Ciphertext_Hash : Seed_32)
      return Stream_Element_Array
   is
      Result : Stream_Element_Array (1 .. 64) := [others => 0];
   begin
      Copy_Slice (Left, Result, 0);
      Copy_Slice (Ciphertext_Hash, Result, 32);
      return Result;
   end Combine_Key_Material;

   procedure Expand_G
     (Message_Seed : Seed_32;
      Public_Hash  : Seed_32;
      Key_Bar      : out Seed_32;
      Coins        : out Seed_32)
   is
      Digest : constant Digest_64 := G (Combine_2 (Message_Seed, Public_Hash));
   begin
      for Offset_Value in 0 .. 31 loop
         Key_Bar (Key_Bar'First + Stream_Element_Offset (Offset_Value)) :=
           Digest (Digest'First + Stream_Element_Offset (Offset_Value));
         Coins (Coins'First + Stream_Element_Offset (Offset_Value)) :=
           Digest (Digest'First + Stream_Element_Offset (32 + Offset_Value));
      end loop;
   end Expand_G;

   function Select_Seed
     (Good_Value : Boolean;
      Good       : Seed_32;
      Bad        : Seed_32)
      return Seed_32
     with SPARK_Mode => On
   is
   begin
      --  Keep selection centralized and full-width.  Constant_Time.Equal
      --  supplies the ciphertext check; this branch only selects the already
      --  computed FIPS 203 KDF input boundary in Ada source.
      if Good_Value then
         return Good;
      end if;
      return Bad;
   end Select_Seed;

   function Generate_Keypair
     (Source_Item : in out CryptoLib.Random.Random_Source;
      Public_Item : out Public_Key;
      Secret_Item : out Secret_Key)
      return Status
   is
      Entropy : Stream_Element_Array (1 .. 64) := [others => 0];
      D       : CryptoLib.MLKEM768_Core.MLKEM_Public_Seed := [others => 0];
      Z       : Seed_32 := [others => 0];
      G_Out   : Digest_64;
      Rho     : CryptoLib.MLKEM768_Core.MLKEM_Public_Seed := [others => 0];
      Sigma   : CryptoLib.MLKEM768_Core.MLKEM_Noise_Seed := [others => 0];
      PKE_SK  : CryptoLib.MLKEM768_Core.PKE_Secret_Key := [others => 0];
      Hash_PK : Seed_32;
      Status_Value : Status;
   begin
      Status_Value := CryptoLib.Random.Fill (Source_Item, Entropy);
      if Status_Value /= Ok then
         Public_Item := [others => 0];
         Secret_Item := [others => 0];
         return Status_Value;
      end if;

      for Offset_Value in 0 .. 31 loop
         D (D'First + Stream_Element_Offset (Offset_Value)) :=
           Entropy (Entropy'First + Stream_Element_Offset (Offset_Value));
         Z (Z'First + Stream_Element_Offset (Offset_Value)) :=
           Entropy (Entropy'First + Stream_Element_Offset (32 + Offset_Value));
      end loop;

      --  FIPS 203 K-PKE.KeyGen: (rho, sigma) = G(d || k), where k is the module
      --  rank (3 for ML-KEM-768).  Kyber round-3 hashed G(d) with no k byte.
      G_Out := G (D & Stream_Element'(3));
      for Offset_Value in 0 .. 31 loop
         Rho (Rho'First + Stream_Element_Offset (Offset_Value)) :=
           G_Out (G_Out'First + Stream_Element_Offset (Offset_Value));
         Sigma (Sigma'First + Stream_Element_Offset (Offset_Value)) :=
           G_Out (G_Out'First + Stream_Element_Offset (32 + Offset_Value));
      end loop;

      CryptoLib.MLKEM768_Core.PKE_Keygen_From_Seeds
        (Rho, Sigma, Public_Item, PKE_SK);
      Hash_PK := H (Public_Item);

      Secret_Item := [others => 0];
      Copy_Slice (PKE_SK, Secret_Item, PKE_Secret_Offset);
      Copy_Slice (Public_Item, Secret_Item, Public_Offset);
      Copy_Slice (Hash_PK, Secret_Item, Hash_Offset);
      Copy_Slice (Z, Secret_Item, Z_Offset);
      return Ok;
   end Generate_Keypair;

   function Encapsulate
     (Source_Item     : in out CryptoLib.Random.Random_Source;
      Public_Item     : Public_Key;
      Ciphertext_Item : out Ciphertext;
      Shared_Item     : out Shared_Key)
      return Status
   is
      M_Seed      : Seed_32 := [others => 0];
      Public_Hash : constant Seed_32 := H (Public_Item);
      Key_Bar     : Seed_32 := [others => 0];
      Coins       : Seed_32 := [others => 0];
      Status_Value : Status;
   begin
      Status_Value := CryptoLib.Random.Fill (Source_Item, M_Seed);
      if Status_Value /= Ok then
         Ciphertext_Item := [others => 0];
         Shared_Item := [others => 0];
         return Status_Value;
      end if;

      Expand_G (M_Seed, Public_Hash, Key_Bar, Coins);
      CryptoLib.MLKEM768_Core.PKE_Encrypt_Deterministic
        (Public_Item,
         Message_From_Seed (M_Seed),
         Coins_From_Seed (Coins),
         Ciphertext_Item);
      --  FIPS 203 ML-KEM.Encaps: the shared key is K = K_bar (the first half of
      --  G(m || H(ek))) directly.  Kyber round-3 applied a final KDF(K_bar||H(c)).
      Shared_Item := Key_Bar;
      return Ok;
   end Encapsulate;

   function Decapsulate
     (Secret_Item : Secret_Key;
      Ciphertext_Item : Ciphertext;
      Shared_Item : out Shared_Key)
      return Status
   is
      PKE_SK       : constant CryptoLib.MLKEM768_Core.PKE_Secret_Key :=
        PKE_Secret_From_Secret (Secret_Item);
      Public_Item  : constant Public_Key := Public_From_Secret (Secret_Item);
      Public_Hash  : constant Seed_32 := Public_Hash_From_Secret (Secret_Item);
      Z_Value      : constant Seed_32 := Z_From_Secret (Secret_Item);
      Message      : constant CryptoLib.MLKEM768_Core.MLKEM_Message :=
        CryptoLib.MLKEM768_Core.PKE_Decrypt (PKE_SK, Ciphertext_Item);
      M_Seed       : Seed_32 := [others => 0];
      Key_Bar      : Seed_32 := [others => 0];
      Coins        : Seed_32 := [others => 0];
      Reencrypted  : Ciphertext := [others => 0];
   begin
      for Offset_Value in 0 .. 31 loop
         M_Seed (M_Seed'First + Stream_Element_Offset (Offset_Value)) :=
           Message (Message'First + Stream_Element_Offset (Offset_Value));
      end loop;

      Expand_G (M_Seed, Public_Hash, Key_Bar, Coins);
      CryptoLib.MLKEM768_Core.PKE_Encrypt_Deterministic
        (Public_Item,
         Message,
         Coins_From_Seed (Coins),
         Reencrypted);

      --  FIPS 203 ML-KEM.Decaps: on success K = K_bar; on implicit rejection
      --  K = J(z || c) = SHAKE256(z || c).  Kyber round-3 used KDF(sel || H(c)).
      declare
         Reject_Key : constant Seed_32 := KDF (Z_Value & Ciphertext_Item);
      begin
         Shared_Item := Select_Seed
           (CryptoLib.Constant_Time.Equal (Ciphertext_Item, Reencrypted),
            Key_Bar,
            Reject_Key);
      end;
      return Ok;
   end Decapsulate;

   procedure Clear (Item : out Secret_Key)
     with SPARK_Mode => On
   is
   begin
      Item := [others => 0];
   end Clear;
end CryptoLib.MLKEM768;
