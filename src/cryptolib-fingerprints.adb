with CryptoLib.Hashes;

package body CryptoLib.Fingerprints is
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;

   Alphabet : constant String :=
     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
   Hex_Alphabet : constant String := "0123456789abcdef";

   function Base64_No_Padding
     (Data : Stream_Element_Array)
      return String
   is
      Output_Length : constant Natural := (Data'Length * 8 + 5) / 6;
      Result : String (1 .. Output_Length);
      Output_Index : Positive := Result'First;
      Cursor : Stream_Element_Offset := Data'First;
      First_Byte : Natural;
      Second_Byte : Natural;
      Third_Byte : Natural;
      Combined_Value : Natural;
      Remaining_Count : Natural;
   begin
      while Cursor <= Data'Last loop
         Remaining_Count := Natural (Data'Last - Cursor + 1);
         First_Byte := Natural (Data (Cursor));
         if Remaining_Count >= 2 then
            Second_Byte := Natural (Data (Cursor + 1));
         else
            Second_Byte := 0;
         end if;
         if Remaining_Count >= 3 then
            Third_Byte := Natural (Data (Cursor + 2));
         else
            Third_Byte := 0;
         end if;

         Combined_Value := First_Byte * 16#10000# + Second_Byte * 16#100# + Third_Byte;

         Result (Output_Index) := Alphabet (Combined_Value / 16#40000# + 1);
         Output_Index := Output_Index + 1;
         exit when Output_Index > Result'Last;

         Result (Output_Index) := Alphabet ((Combined_Value / 16#1000#) mod 64 + 1);
         Output_Index := Output_Index + 1;
         exit when Output_Index > Result'Last;

         Result (Output_Index) := Alphabet ((Combined_Value / 16#40#) mod 64 + 1);
         Output_Index := Output_Index + 1;
         exit when Output_Index > Result'Last;

         Result (Output_Index) := Alphabet (Combined_Value mod 64 + 1);
         Output_Index := Output_Index + 1;

         Cursor := Cursor + 3;
      end loop;

      return Result;
   end Base64_No_Padding;

   function Hex_Lower (Data : Stream_Element_Array) return String
     with SPARK_Mode => On,
          Pre => Data'First > Data'Last
            or else
              (Data'First <= Stream_Element_Offset'Last - Stream_Element_Offset (Natural'Last / 2 - 1)
               and then Data'Last <= Data'First + Stream_Element_Offset (Natural'Last / 2 - 1))
   is
      Input_Length : constant Natural :=
        (if Data'First > Data'Last then 0 else Natural (Data'Last - Data'First + 1));
      Result : String (1 .. Input_Length * 2) := (others => '0');
      Value  : Natural;
   begin
      for Count in 0 .. Input_Length - 1 loop
         declare
            Data_Index : constant Stream_Element_Offset :=
              Data'First + Stream_Element_Offset (Count);
            Cursor : constant Positive := Result'First + Count * 2;
         begin
            pragma Loop_Invariant (Data_Index in Data'Range);
            pragma Loop_Invariant (Cursor in Result'Range);
            pragma Loop_Invariant (Cursor + 1 in Result'Range);

            Value := Natural (Data (Data_Index));
            Result (Cursor) := Hex_Alphabet (Value / 16 + 1);
            Result (Cursor + 1) := Hex_Alphabet (Value mod 16 + 1);
         end;
      end loop;
      return Result;
   end Hex_Lower;

   function Colonize_Hex (Value : String) return String is
      Result : String (1 .. Value'Length + Natural'Max (0, Value'Length / 2 - 1));
      Input_Cursor  : Positive := Value'First;
      Output_Cursor : Positive := Result'First;
      Pair_Index    : Natural := 0;
   begin
      while Input_Cursor <= Value'Last loop
         if Pair_Index > 0 then
            Result (Output_Cursor) := ':';
            Output_Cursor := Output_Cursor + 1;
         end if;
         Result (Output_Cursor) := Value (Input_Cursor);
         Result (Output_Cursor + 1) := Value (Input_Cursor + 1);
         Input_Cursor := Input_Cursor + 2;
         Output_Cursor := Output_Cursor + 2;
         Pair_Index := Pair_Index + 1;
      end loop;
      return Result;
   end Colonize_Hex;

   function MD5_OpenSSH
     (Data  : Stream_Element_Array;
      Image : out Unbounded_String)
      return Status
   is
      Digest : constant CryptoLib.Hashes.MD5_Digest :=
        CryptoLib.Hashes.MD5 (Data);
      Digest_Bytes : Stream_Element_Array (1 .. 16);
   begin
      Image := Null_Unbounded_String;
      for Index_Value in Digest'Range loop
         Digest_Bytes (Stream_Element_Offset (Index_Value)) :=
           Digest (Index_Value);
      end loop;
      Image := To_Unbounded_String
        ("MD5:" & Colonize_Hex (Hex_Lower (Digest_Bytes)));
      return Ok;
   exception
      when others =>
         Image := Null_Unbounded_String;
         return Internal_Error;
   end MD5_OpenSSH;

   function SHA256_OpenSSH
     (Data  : Stream_Element_Array;
      Image : out Unbounded_String)
      return Status
   is
      Digest : constant CryptoLib.Hashes.SHA256_Digest :=
        CryptoLib.Hashes.SHA256 (Data);
      Digest_Bytes : Stream_Element_Array (1 .. 32);
   begin
      Image := Null_Unbounded_String;
      for Index_Value in Digest'Range loop
         Digest_Bytes (Stream_Element_Offset (Index_Value)) := Digest (Index_Value);
      end loop;
      Image := To_Unbounded_String ("SHA256:" & Base64_No_Padding (Digest_Bytes));
      return Ok;
   exception
      when others =>
         Image := Null_Unbounded_String;
         return Internal_Error;
   end SHA256_OpenSSH;
end CryptoLib.Fingerprints;
