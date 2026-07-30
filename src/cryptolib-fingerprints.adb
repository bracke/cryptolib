with CryptoLib.Base64;
with CryptoLib.Hashes;

package body CryptoLib.Fingerprints is
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;

   Hex_Alphabet : constant String := "0123456789abcdef";

   --  Unpadded base64 through the shared CryptoLib.Base64, which is where it
   --  lives now: the Argon2 PHC string needs the same encoding, and a second
   --  copy of it is one more than anyone will keep correct.
   function Base64_No_Padding
     (Data : Stream_Element_Array)
      return String
   is
      Result : String
        (1 .. CryptoLib.Base64.Encoded_Length (Natural (Data'Length)));
      Last   : Natural;
   begin
      CryptoLib.Base64.Encode (Data, Result, Last);
      return Result (Result'First .. Last);
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
