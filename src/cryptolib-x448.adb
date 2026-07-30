with Ada.Streams; use Ada.Streams;

with CryptoLib.Field448; use CryptoLib.Field448;
with CryptoLib.Secure_Wipe;

package body CryptoLib.X448 is

   use CryptoLib.Errors;

   Zero_Element : constant Field_Element := [others => 0];
   One_Element  : constant Field_Element := [1, others => 0];

   function To_Field (Data : Stream_Element_Array) return Field_Element is
      Result : Field_Element := [others => 0];
   begin
      for I in Fe_Index loop
         Result (I) :=
           Byte_Value (Data (Data'First + Stream_Element_Offset (I)));
      end loop;
      --  RFC 7748 section 5: the u-coordinate is taken modulo p, and for
      --  curve448 there is no high bit to mask -- 56 octets is exactly the
      --  field width, so a value at or above p is reduced rather than
      --  refused.
      if Not_Less (Result, Prime) then
         Result := Sub_Mod (Result, Prime);
      end if;
      return Result;
   end To_Field;

   function From_Field (Item : Field_Element) return Stream_Element_Array is
      Result : Stream_Element_Array (1 .. 56);
   begin
      for I in Fe_Index loop
         Result (Stream_Element_Offset (I) + 1) := Stream_Element (Item (I));
      end loop;
      return Result;
   end From_Field;

   --  A24 as a field element: 39081 = 16#98A9#, little-endian. Multiplied
   --  through the general Mul_Mod rather than a hand-rolled small multiply.
   --  The first attempt here did roll its own and folded only the low octet
   --  of a carry that reaches about 2**16, which is wrong for every input.
   A24_Element : constant Field_Element :=
     [0 => 16#A9#, 1 => 16#98#, others => 0];

   function Mul_A24 (Item : Field_Element) return Field_Element is
     (Mul_Mod (Item, A24_Element));

   --  The Montgomery ladder of RFC 7748 section 5, over the u-coordinate
   --  only. Fixed length, and every step selects with Select_Field rather
   --  than branching, so neither the scalar's value nor its bit length shows
   --  in the control flow.
   function Ladder (Scalar : Private_Key; U : Field_Element)
      return Field_Element
   is
      K  : Stream_Element_Array (1 .. 56) := Scalar;
      X1 : constant Field_Element := U;
      X2 : Field_Element := One_Element;
      Z2 : Field_Element := Zero_Element;
      X3 : Field_Element := U;
      Z3 : Field_Element := One_Element;
      Swap : Natural := 0;
   begin
      --  Clamping, RFC 7748 section 5: clear the low two bits and set the
      --  top one.
      K (K'First) := K (K'First) and 16#FC#;
      K (K'Last) := K (K'Last) or 16#80#;

      for Bit in reverse 0 .. 447 loop
         declare
            Octet : constant Stream_Element :=
              K (K'First + Stream_Element_Offset (Bit / 8));
            Bit_Value : constant Natural :=
              Natural (Octet / (2 ** (Bit mod 8))) mod 2;
            A, B, AA, BB, E, C, D, DA, CB : Field_Element;
         begin
            --  xor on 0/1, which Natural does not provide directly.
            Swap := (Swap + Bit_Value) mod 2;
            declare
               T2 : constant Field_Element := Select_Field (X2, X3, Swap);
               T3 : constant Field_Element := Select_Field (X3, X2, Swap);
               U2 : constant Field_Element := Select_Field (Z2, Z3, Swap);
               U3 : constant Field_Element := Select_Field (Z3, Z2, Swap);
            begin
               X2 := T2; X3 := T3; Z2 := U2; Z3 := U3;
            end;
            Swap := Bit_Value;

            A  := Add_Mod (X2, Z2);
            AA := Square_Mod (A);
            B  := Sub_Mod (X2, Z2);
            BB := Square_Mod (B);
            E  := Sub_Mod (AA, BB);
            C  := Add_Mod (X3, Z3);
            D  := Sub_Mod (X3, Z3);
            DA := Mul_Mod (D, A);
            CB := Mul_Mod (C, B);
            X3 := Square_Mod (Add_Mod (DA, CB));
            Z3 := Mul_Mod (X1, Square_Mod (Sub_Mod (DA, CB)));
            X2 := Mul_Mod (AA, BB);
            Z2 := Mul_Mod (E, Add_Mod (AA, Mul_A24 (E)));
         end;
      end loop;

      declare
         T2 : constant Field_Element := Select_Field (X2, X3, Swap);
         U2 : constant Field_Element := Select_Field (Z2, Z3, Swap);
      begin
         X2 := T2; Z2 := U2;
      end;

      CryptoLib.Secure_Wipe.Wipe (K'Address, K'Length);
      return Mul_Mod (X2, Inv_Mod (Z2));
   end Ladder;

   function Is_Zero (Data : Stream_Element_Array) return Boolean is
      Accum : Stream_Element := 0;
   begin
      for B of Data loop
         Accum := Accum or B;
      end loop;
      return Accum = 0;
   end Is_Zero;

   function Compute_Raw
     (Scalar : Private_Key;
      U      : Public_Key;
      Result : out Shared_Key) return CryptoLib.Errors.Status is
   begin
      Result := From_Field (Ladder (Scalar, To_Field (U)));
      return Ok;
   exception
      when others =>
         Result := [others => 0];
         return Internal_Error;
   end Compute_Raw;

   function Public_Value
     (Private_Item : Private_Key;
      Public_Item  : out Public_Key) return CryptoLib.Errors.Status
   is
      --  The base point's u-coordinate is 5.
      Base : constant Public_Key := [1 => 5, others => 0];
   begin
      --  No pre-zeroing: Compute_Raw assigns Public_Item on every path,
      --  including its exception handler, so a store here would be dead.
      declare
         Status : constant CryptoLib.Errors.Status :=
           Compute_Raw (Private_Item, Base, Public_Item);
      begin
         if Status /= Ok then
            return Status;
         end if;
      end;
      if Is_Zero (Public_Item) then
         Public_Item := [others => 0];
         return Authentication_Failed;
      end if;
      return Ok;
   end Public_Value;

   function Shared_Secret
     (Private_Item : Private_Key;
      Peer_Item    : Public_Key;
      Secret       : out Shared_Key) return CryptoLib.Errors.Status
   is
   begin
      --  As in Public_Value: Compute_Raw always assigns Secret.
      declare
         Status : constant CryptoLib.Errors.Status :=
           Compute_Raw (Private_Item, Peer_Item, Secret);
      begin
         if Status /= Ok then
            Secret := [others => 0];
            return Status;
         end if;
      end;
      --  RFC 7748 section 6.1: a small-order peer value drives this to zero
      --  whatever the scalar was, so an all-zero result is a secret the peer
      --  already knows.
      if Is_Zero (Secret) then
         Secret := [others => 0];
         return Authentication_Failed;
      end if;
      return Ok;
   end Shared_Secret;

   function Generate_Keypair
     (Rng          : in out CryptoLib.Random.Random_Source;
      Private_Item : out Private_Key;
      Public_Item  : out Public_Key) return CryptoLib.Errors.Status is
   begin
      Private_Item := [others => 0];
      Public_Item := [others => 0];
      if CryptoLib.Random.Fill (Rng, Private_Item) /= Ok then
         Private_Item := [others => 0];
         return Internal_Error;
      end if;
      return Result : constant CryptoLib.Errors.Status :=
        Public_Value (Private_Item, Public_Item)
      do
         if Result /= Ok then
            Private_Item := [others => 0];
         end if;
      end return;
   end Generate_Keypair;

   procedure Clear (Private_Item : out Private_Key) is
   begin
      Private_Item := [others => 0];
      CryptoLib.Secure_Wipe.Wipe (Private_Item'Address, Private_Item'Length);
   end Clear;

end CryptoLib.X448;
