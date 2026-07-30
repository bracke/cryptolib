with CryptoLib.Blowfish; use CryptoLib.Blowfish;
with CryptoLib.Hashes;

package body CryptoLib.BCrypt_PBKDF is
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type Interfaces.Unsigned_32;

   --  The Blowfish key schedule lives in CryptoLib.Blowfish now, because
   --  CryptoLib.Bcrypt needs the same routines and a second copy of a cipher
   --  is a second copy to keep correct.
   BCrypt_Words     : constant Natural := 8;
   BCrypt_Hash_Size : constant Ada.Streams.Stream_Element_Offset :=
     Ada.Streams.Stream_Element_Offset (BCrypt_Words * 4);
   SHA512_Size      : constant Ada.Streams.Stream_Element_Offset := 64;

   function Digest_To_Array
     (Digest_Value : CryptoLib.Hashes.SHA512_Digest)
      return Ada.Streams.Stream_Element_Array
     with SPARK_Mode => On
   is
      Result : Ada.Streams.Stream_Element_Array (1 .. SHA512_Size) :=
        [others => 0];
   begin
      for Index_Value in Digest_Value'Range loop
         Result (Ada.Streams.Stream_Element_Offset (Index_Value)) :=
           Digest_Value (Index_Value);
      end loop;
      return Result;
   end Digest_To_Array;

   function SHA512_Array
     (Data : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array is
   begin
      return Digest_To_Array (CryptoLib.Hashes.SHA512 (Data));
   end SHA512_Array;

   procedure BCrypt_Hash
     (SHA2_Pass : Ada.Streams.Stream_Element_Array;
      SHA2_Salt : Ada.Streams.Stream_Element_Array;
      Output    : out Ada.Streams.Stream_Element_Array)
   is
      State_Item   : Blowfish_State;
      Magic_Text   : constant String := "OxychromaticBlowfishSwatDynamite";
      Magic_Data   :
        Ada.Streams.Stream_Element_Array (1 .. BCrypt_Hash_Size) :=
          [others => 0];
      Word_Data    : P_Array := [others => 0];
      Offset_Value : Natural := 0;
   begin
      Output := [others => 0];
      for Index_Value in Magic_Text'Range loop
         Magic_Data (Ada.Streams.Stream_Element_Offset (Index_Value)) :=
           Ada.Streams.Stream_Element
             (Character'Pos (Magic_Text (Index_Value)));
      end loop;

      Init_State (State_Item);
      Expand_State (State_Item, SHA2_Salt, SHA2_Pass);
      for Round_Index in 1 .. 64 loop
         pragma Unreferenced (Round_Index);
         Expand_Zero_State (State_Item, SHA2_Salt);
         Expand_Zero_State (State_Item, SHA2_Pass);
      end loop;

      for Index_Value in 0 .. BCrypt_Words - 1 loop
         Word_Data (Index_Value) := Stream_To_Word (Magic_Data, Offset_Value);
      end loop;

      for Round_Index in 1 .. 64 loop
         pragma Unreferenced (Round_Index);
         Encrypt_Words (State_Item, Word_Data, BCrypt_Words / 2);
      end loop;

      for Index_Value in 0 .. BCrypt_Words - 1 loop
         Output
           (Output'First
            + Ada.Streams.Stream_Element_Offset (Index_Value * 4 + 3)) :=
           Ada.Streams.Stream_Element
             (Interfaces.Shift_Right (Word_Data (Index_Value), 24) and 16#FF#);
         Output
           (Output'First
            + Ada.Streams.Stream_Element_Offset (Index_Value * 4 + 2)) :=
           Ada.Streams.Stream_Element
             (Interfaces.Shift_Right (Word_Data (Index_Value), 16) and 16#FF#);
         Output
           (Output'First
            + Ada.Streams.Stream_Element_Offset (Index_Value * 4 + 1)) :=
           Ada.Streams.Stream_Element
             (Interfaces.Shift_Right (Word_Data (Index_Value), 8) and 16#FF#);
         Output
           (Output'First
            + Ada.Streams.Stream_Element_Offset (Index_Value * 4)) :=
           Ada.Streams.Stream_Element (Word_Data (Index_Value) and 16#FF#);
      end loop;

      Clear_Stream_Array (Magic_Data);
      Clear_P_Array (Word_Data);
      Clear_State (State_Item);
   end BCrypt_Hash;

   function To_Passphrase_Data
     (Passphrase : String) return Ada.Streams.Stream_Element_Array
   is
      Result :
        Ada.Streams.Stream_Element_Array
          (1 .. Ada.Streams.Stream_Element_Offset (Passphrase'Length)) :=
          [others => 0];
   begin
      for Offset_Value in 0 .. Passphrase'Length - 1 loop
         Result (1 + Ada.Streams.Stream_Element_Offset (Offset_Value)) :=
           Ada.Streams.Stream_Element
             (Character'Pos (Passphrase (Passphrase'First + Offset_Value)));
      end loop;
      return Result;
   end To_Passphrase_Data;

   function Derive
     (Passphrase : String;
      Salt_Data  : Ada.Streams.Stream_Element_Array;
      Rounds     : Interfaces.Unsigned_32;
      Output     : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status is
   begin
      Output := [others => 0];

      if Output'Length = 0
        or else Salt_Data'Length = 0
        or else Passphrase'Length = 0
        or else Rounds = 0
      then
         Output := [others => 0];
         return CryptoLib.Errors.Authentication_Failed;
      end if;

      if Output'Length > Max_Output_Length
        or else Salt_Data'Length > Max_Salt_Length
        or else Rounds > Max_Rounds
      then
         Output := [others => 0];
         return CryptoLib.Errors.Unsupported_Feature;
      end if;

      declare
         Pass_Data   : Ada.Streams.Stream_Element_Array :=
           To_Passphrase_Data (Passphrase);
         SHA2_Pass   : Ada.Streams.Stream_Element_Array (1 .. SHA512_Size) :=
           SHA512_Array (Pass_Data);
         Count_Salt  :
           Ada.Streams.Stream_Element_Array
             (1 .. Ada.Streams.Stream_Element_Offset (Salt_Data'Length + 4)) :=
             [others => 0];
         SHA2_Salt   : Ada.Streams.Stream_Element_Array (1 .. SHA512_Size) :=
           [others => 0];
         Out_Data    :
           Ada.Streams.Stream_Element_Array (1 .. BCrypt_Hash_Size) :=
             [others => 0];
         Temp_Data   :
           Ada.Streams.Stream_Element_Array (1 .. BCrypt_Hash_Size) :=
             [others => 0];
         Remaining   : Natural := Output'Length;
         Count_Value : Interfaces.Unsigned_32 := 1;
         Stride      : constant Natural :=
           (Output'Length + Natural (BCrypt_Hash_Size) - 1)
           / Natural (BCrypt_Hash_Size);
         Amount      : constant Natural :=
           (Output'Length + Stride - 1) / Stride;
      begin
         for Offset_Value in 0 .. Salt_Data'Length - 1 loop
            Count_Salt
              (1 + Ada.Streams.Stream_Element_Offset (Offset_Value)) :=
              Salt_Data
                (Salt_Data'First
                 + Ada.Streams.Stream_Element_Offset (Offset_Value));
         end loop;

         while Remaining > 0 loop
            Count_Salt (Count_Salt'Last - 3) :=
              Ada.Streams.Stream_Element
                (Interfaces.Shift_Right (Count_Value, 24) and 16#FF#);
            Count_Salt (Count_Salt'Last - 2) :=
              Ada.Streams.Stream_Element
                (Interfaces.Shift_Right (Count_Value, 16) and 16#FF#);
            Count_Salt (Count_Salt'Last - 1) :=
              Ada.Streams.Stream_Element
                (Interfaces.Shift_Right (Count_Value, 8) and 16#FF#);
            Count_Salt (Count_Salt'Last) :=
              Ada.Streams.Stream_Element (Count_Value and 16#FF#);

            SHA2_Salt := SHA512_Array (Count_Salt);
            BCrypt_Hash (SHA2_Pass, SHA2_Salt, Temp_Data);
            Out_Data := Temp_Data;

            for Round_Index in Interfaces.Unsigned_32'(2) .. Rounds loop
               pragma Unreferenced (Round_Index);
               SHA2_Salt := SHA512_Array (Temp_Data);
               BCrypt_Hash (SHA2_Pass, SHA2_Salt, Temp_Data);
               for Index_Value in Out_Data'Range loop
                  Out_Data (Index_Value) :=
                    Out_Data (Index_Value) xor Temp_Data (Index_Value);
               end loop;
            end loop;

            declare
               Take_Count  : constant Natural :=
                 Natural'Min (Amount, Remaining);
               Base_Offset : constant Natural := Natural (Count_Value - 1);
            begin
               for Index_Value in 0 .. Take_Count - 1 loop
                  Output
                    (Output'First
                     + Ada.Streams.Stream_Element_Offset
                         (Index_Value * Stride + Base_Offset)) :=
                    Out_Data
                      (Out_Data'First
                       + Ada.Streams.Stream_Element_Offset (Index_Value));
               end loop;
               Remaining := Remaining - Take_Count;
            end;

            Count_Value := Count_Value + 1;
         end loop;

         Clear_Stream_Array (Pass_Data);
         Clear_Stream_Array (SHA2_Pass);
         Clear_Stream_Array (Count_Salt);
         Clear_Stream_Array (SHA2_Salt);
         Clear_Stream_Array (Out_Data);
         Clear_Stream_Array (Temp_Data);
      end;

      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Output := [others => 0];
         return CryptoLib.Errors.Internal_Error;
   end Derive;

end CryptoLib.BCrypt_PBKDF;
