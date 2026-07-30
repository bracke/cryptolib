with Ada.Streams; use Ada.Streams;
with Ada.Unchecked_Deallocation;
with Interfaces;
with CryptoLib.Secure_Wipe;

package body CryptoLib.Macs is
   use type Interfaces.Unsigned_32;

   --  Shared HMAC key schedule (RFC 2104): the effective key is the raw key
   --  when it fits the hash block, or its digest when it does not. Both pads
   --  start as the key padded with zeros, so the untouched tail is simply the
   --  pad byte itself.
   procedure Fill_HMAC_Pads
     (Effective_Key : Ada.Streams.Stream_Element_Array;
      Inner_Pad     : out Ada.Streams.Stream_Element_Array;
      Outer_Pad     : out Ada.Streams.Stream_Element_Array)
   is
      Cursor_Value : Ada.Streams.Stream_Element_Offset := Inner_Pad'First;
   begin
      Inner_Pad := [others => 16#36#];
      Outer_Pad := [others => 16#5C#];
      for Index_Value in Effective_Key'Range loop
         Inner_Pad (Cursor_Value) := Effective_Key (Index_Value) xor 16#36#;
         Outer_Pad (Cursor_Value) := Effective_Key (Index_Value) xor 16#5C#;
         Cursor_Value := Cursor_Value + 1;
      end loop;
   end Fill_HMAC_Pads;

   procedure Initialize_HMAC_SHA1
     (Context_Item : out HMAC_SHA1_Context;
      Key_Data     : Ada.Streams.Stream_Element_Array)
   is
      Block_Size : constant := 64;
      Inner_Pad  : Ada.Streams.Stream_Element_Array (1 .. Block_Size) :=
        [others => 0];
      Outer_Pad  : Ada.Streams.Stream_Element_Array (1 .. Block_Size) :=
        [others => 0];
   begin
      if Key_Data'Length > Block_Size then
         declare
            Hashed_Key : CryptoLib.Hashes.SHA1_Digest :=
              CryptoLib.Hashes.SHA1 (Key_Data);
            Key_Bytes  : Ada.Streams.Stream_Element_Array (1 .. 20);
         begin
            for Index_Value in Hashed_Key'Range loop
               Key_Bytes (Ada.Streams.Stream_Element_Offset (Index_Value)) :=
                 Hashed_Key (Index_Value);
            end loop;
            Fill_HMAC_Pads (Key_Bytes, Inner_Pad, Outer_Pad);
            CryptoLib.Secure_Wipe.Wipe (Key_Bytes'Address, Key_Bytes'Length);
            CryptoLib.Secure_Wipe.Wipe (Hashed_Key'Address, Hashed_Key'Length);
         end;
      else
         Fill_HMAC_Pads (Key_Data, Inner_Pad, Outer_Pad);
      end if;

      CryptoLib.Hashes.Initialize_SHA1 (Context_Item.Inner);
      CryptoLib.Hashes.Update (Context_Item.Inner, Inner_Pad);
      CryptoLib.Hashes.Initialize_SHA1 (Context_Item.Outer);
      CryptoLib.Hashes.Update (Context_Item.Outer, Outer_Pad);

      CryptoLib.Secure_Wipe.Wipe (Inner_Pad'Address, Inner_Pad'Length);
      CryptoLib.Secure_Wipe.Wipe (Outer_Pad'Address, Outer_Pad'Length);
   end Initialize_HMAC_SHA1;

   procedure Update
     (Context_Item : in out HMAC_SHA1_Context;
      Data         : Ada.Streams.Stream_Element_Array)
   is
   begin
      CryptoLib.Hashes.Update (Context_Item.Inner, Data);
   end Update;

   function Finalize
     (Context_Item : in out HMAC_SHA1_Context)
      return HMAC_SHA1_Digest
   is
      Inner_Digest : constant CryptoLib.Hashes.SHA1_Digest :=
        CryptoLib.Hashes.Finalize (Context_Item.Inner);
      Digest_Bytes : Ada.Streams.Stream_Element_Array (1 .. 20);
   begin
      for Index_Value in Inner_Digest'Range loop
         Digest_Bytes (Ada.Streams.Stream_Element_Offset (Index_Value)) :=
           Inner_Digest (Index_Value);
      end loop;
      CryptoLib.Hashes.Update (Context_Item.Outer, Digest_Bytes);
      return CryptoLib.Hashes.Finalize (Context_Item.Outer);
   end Finalize;

   function HMAC_SHA1
     (Key_Data     : Ada.Streams.Stream_Element_Array;
      Message_Data : Ada.Streams.Stream_Element_Array) return HMAC_SHA1_Digest
   is
      Context_Item : HMAC_SHA1_Context;
   begin
      Initialize_HMAC_SHA1 (Context_Item, Key_Data);
      Update (Context_Item, Message_Data);
      return Finalize (Context_Item);
   end HMAC_SHA1;

   procedure Initialize_HMAC_SHA256
     (Context_Item : out HMAC_SHA256_Context;
      Key_Data     : Ada.Streams.Stream_Element_Array)
   is
      Block_Size : constant := 64;
      Inner_Pad  : Ada.Streams.Stream_Element_Array (1 .. Block_Size) :=
        [others => 0];
      Outer_Pad  : Ada.Streams.Stream_Element_Array (1 .. Block_Size) :=
        [others => 0];
   begin
      if Key_Data'Length > Block_Size then
         declare
            Hashed_Key : CryptoLib.Hashes.SHA256_Digest :=
              CryptoLib.Hashes.SHA256 (Key_Data);
            Key_Bytes  : Ada.Streams.Stream_Element_Array (1 .. 32);
         begin
            for Index_Value in Hashed_Key'Range loop
               Key_Bytes (Ada.Streams.Stream_Element_Offset (Index_Value)) :=
                 Hashed_Key (Index_Value);
            end loop;
            Fill_HMAC_Pads (Key_Bytes, Inner_Pad, Outer_Pad);
            CryptoLib.Secure_Wipe.Wipe (Key_Bytes'Address, Key_Bytes'Length);
            CryptoLib.Secure_Wipe.Wipe (Hashed_Key'Address, Hashed_Key'Length);
         end;
      else
         Fill_HMAC_Pads (Key_Data, Inner_Pad, Outer_Pad);
      end if;

      CryptoLib.Hashes.Initialize_SHA256 (Context_Item.Inner);
      CryptoLib.Hashes.Update (Context_Item.Inner, Inner_Pad);
      CryptoLib.Hashes.Initialize_SHA256 (Context_Item.Outer);
      CryptoLib.Hashes.Update (Context_Item.Outer, Outer_Pad);

      CryptoLib.Secure_Wipe.Wipe (Inner_Pad'Address, Inner_Pad'Length);
      CryptoLib.Secure_Wipe.Wipe (Outer_Pad'Address, Outer_Pad'Length);
   end Initialize_HMAC_SHA256;

   procedure Update
     (Context_Item : in out HMAC_SHA256_Context;
      Data         : Ada.Streams.Stream_Element_Array)
   is
   begin
      CryptoLib.Hashes.Update (Context_Item.Inner, Data);
   end Update;

   function Finalize
     (Context_Item : in out HMAC_SHA256_Context)
      return HMAC_SHA256_Digest
   is
      Inner_Digest : constant CryptoLib.Hashes.SHA256_Digest :=
        CryptoLib.Hashes.Finalize (Context_Item.Inner);
      Digest_Bytes : Ada.Streams.Stream_Element_Array (1 .. 32);
   begin
      for Index_Value in Inner_Digest'Range loop
         Digest_Bytes (Ada.Streams.Stream_Element_Offset (Index_Value)) :=
           Inner_Digest (Index_Value);
      end loop;
      CryptoLib.Hashes.Update (Context_Item.Outer, Digest_Bytes);
      return CryptoLib.Hashes.Finalize (Context_Item.Outer);
   end Finalize;

   function HMAC_SHA256
     (Key_Data     : Ada.Streams.Stream_Element_Array;
      Message_Data : Ada.Streams.Stream_Element_Array)
      return HMAC_SHA256_Digest
   is
      Context_Item : HMAC_SHA256_Context;
   begin
      Initialize_HMAC_SHA256 (Context_Item, Key_Data);
      Update (Context_Item, Message_Data);
      return Finalize (Context_Item);
   end HMAC_SHA256;

   procedure Initialize_HMAC_SHA384
     (Context_Item : out HMAC_SHA384_Context;
      Key_Data     : Ada.Streams.Stream_Element_Array)
   is
      Block_Size : constant := 128;
      Inner_Pad  : Ada.Streams.Stream_Element_Array (1 .. Block_Size) :=
        [others => 0];
      Outer_Pad  : Ada.Streams.Stream_Element_Array (1 .. Block_Size) :=
        [others => 0];
   begin
      if Key_Data'Length > Block_Size then
         declare
            Hashed_Key : CryptoLib.Hashes.SHA384_Digest :=
              CryptoLib.Hashes.SHA384 (Key_Data);
            Key_Bytes  : Ada.Streams.Stream_Element_Array (1 .. 48);
         begin
            for Index_Value in Hashed_Key'Range loop
               Key_Bytes (Ada.Streams.Stream_Element_Offset (Index_Value)) :=
                 Hashed_Key (Index_Value);
            end loop;
            Fill_HMAC_Pads (Key_Bytes, Inner_Pad, Outer_Pad);
            CryptoLib.Secure_Wipe.Wipe (Key_Bytes'Address, Key_Bytes'Length);
            CryptoLib.Secure_Wipe.Wipe (Hashed_Key'Address, Hashed_Key'Length);
         end;
      else
         Fill_HMAC_Pads (Key_Data, Inner_Pad, Outer_Pad);
      end if;

      CryptoLib.Hashes.Initialize_SHA384 (Context_Item.Inner);
      CryptoLib.Hashes.Update (Context_Item.Inner, Inner_Pad);
      CryptoLib.Hashes.Initialize_SHA384 (Context_Item.Outer);
      CryptoLib.Hashes.Update (Context_Item.Outer, Outer_Pad);

      CryptoLib.Secure_Wipe.Wipe (Inner_Pad'Address, Inner_Pad'Length);
      CryptoLib.Secure_Wipe.Wipe (Outer_Pad'Address, Outer_Pad'Length);
   end Initialize_HMAC_SHA384;

   procedure Update
     (Context_Item : in out HMAC_SHA384_Context;
      Data         : Ada.Streams.Stream_Element_Array)
   is
   begin
      CryptoLib.Hashes.Update (Context_Item.Inner, Data);
   end Update;

   function Finalize
     (Context_Item : in out HMAC_SHA384_Context)
      return HMAC_SHA384_Digest
   is
      Inner_Digest : constant CryptoLib.Hashes.SHA384_Digest :=
        CryptoLib.Hashes.Finalize (Context_Item.Inner);
      Digest_Bytes : Ada.Streams.Stream_Element_Array (1 .. 48);
   begin
      for Index_Value in Inner_Digest'Range loop
         Digest_Bytes (Ada.Streams.Stream_Element_Offset (Index_Value)) :=
           Inner_Digest (Index_Value);
      end loop;
      CryptoLib.Hashes.Update (Context_Item.Outer, Digest_Bytes);
      return CryptoLib.Hashes.Finalize (Context_Item.Outer);
   end Finalize;

   function HMAC_SHA384
     (Key_Data     : Ada.Streams.Stream_Element_Array;
      Message_Data : Ada.Streams.Stream_Element_Array)
      return HMAC_SHA384_Digest
   is
      Context_Item : HMAC_SHA384_Context;
   begin
      Initialize_HMAC_SHA384 (Context_Item, Key_Data);
      Update (Context_Item, Message_Data);
      return Finalize (Context_Item);
   end HMAC_SHA384;

   procedure Initialize_HMAC_SHA512
     (Context_Item : out HMAC_SHA512_Context;
      Key_Data     : Ada.Streams.Stream_Element_Array)
   is
      Block_Size : constant := 128;
      Inner_Pad  : Ada.Streams.Stream_Element_Array (1 .. Block_Size) :=
        [others => 0];
      Outer_Pad  : Ada.Streams.Stream_Element_Array (1 .. Block_Size) :=
        [others => 0];
   begin
      if Key_Data'Length > Block_Size then
         declare
            Hashed_Key : CryptoLib.Hashes.SHA512_Digest :=
              CryptoLib.Hashes.SHA512 (Key_Data);
            Key_Bytes  : Ada.Streams.Stream_Element_Array (1 .. 64);
         begin
            for Index_Value in Hashed_Key'Range loop
               Key_Bytes (Ada.Streams.Stream_Element_Offset (Index_Value)) :=
                 Hashed_Key (Index_Value);
            end loop;
            Fill_HMAC_Pads (Key_Bytes, Inner_Pad, Outer_Pad);
            CryptoLib.Secure_Wipe.Wipe (Key_Bytes'Address, Key_Bytes'Length);
            CryptoLib.Secure_Wipe.Wipe (Hashed_Key'Address, Hashed_Key'Length);
         end;
      else
         Fill_HMAC_Pads (Key_Data, Inner_Pad, Outer_Pad);
      end if;

      CryptoLib.Hashes.Initialize_SHA512 (Context_Item.Inner);
      CryptoLib.Hashes.Update (Context_Item.Inner, Inner_Pad);
      CryptoLib.Hashes.Initialize_SHA512 (Context_Item.Outer);
      CryptoLib.Hashes.Update (Context_Item.Outer, Outer_Pad);

      CryptoLib.Secure_Wipe.Wipe (Inner_Pad'Address, Inner_Pad'Length);
      CryptoLib.Secure_Wipe.Wipe (Outer_Pad'Address, Outer_Pad'Length);
   end Initialize_HMAC_SHA512;

   procedure Update
     (Context_Item : in out HMAC_SHA512_Context;
      Data         : Ada.Streams.Stream_Element_Array)
   is
   begin
      CryptoLib.Hashes.Update (Context_Item.Inner, Data);
   end Update;

   function Finalize
     (Context_Item : in out HMAC_SHA512_Context)
      return HMAC_SHA512_Digest
   is
      Inner_Digest : constant CryptoLib.Hashes.SHA512_Digest :=
        CryptoLib.Hashes.Finalize (Context_Item.Inner);
      Digest_Bytes : Ada.Streams.Stream_Element_Array (1 .. 64);
   begin
      for Index_Value in Inner_Digest'Range loop
         Digest_Bytes (Ada.Streams.Stream_Element_Offset (Index_Value)) :=
           Inner_Digest (Index_Value);
      end loop;
      CryptoLib.Hashes.Update (Context_Item.Outer, Digest_Bytes);
      return CryptoLib.Hashes.Finalize (Context_Item.Outer);
   end Finalize;

   function HMAC_SHA512
     (Key_Data     : Ada.Streams.Stream_Element_Array;
      Message_Data : Ada.Streams.Stream_Element_Array)
      return HMAC_SHA512_Digest
   is
      Context_Item : HMAC_SHA512_Context;
   begin
      Initialize_HMAC_SHA512 (Context_Item, Key_Data);
      Update (Context_Item, Message_Data);
      return Finalize (Context_Item);
   end HMAC_SHA512;

   procedure Store_U32_BE
     (Data  : in out Ada.Streams.Stream_Element_Array;
      Pos   : Ada.Streams.Stream_Element_Offset;
      Value : Interfaces.Unsigned_32)
     with SPARK_Mode => On,
          Pre => Pos >= Data'First
            and then Pos <= Ada.Streams.Stream_Element_Offset'Last - 3
            and then Pos + 3 <= Data'Last
   is
   begin
      Data (Pos) := Ada.Streams.Stream_Element (Interfaces.Shift_Right (Value, 24) and 16#FF#);
      Data (Pos + 1) := Ada.Streams.Stream_Element (Interfaces.Shift_Right (Value, 16) and 16#FF#);
      Data (Pos + 2) := Ada.Streams.Stream_Element (Interfaces.Shift_Right (Value, 8) and 16#FF#);
      Data (Pos + 3) := Ada.Streams.Stream_Element (Value and 16#FF#);
   end Store_U32_BE;

   procedure Clear_Stream_Array
     (Item : out Ada.Streams.Stream_Element_Array)
     with SPARK_Mode => On
   is
   begin
      for Index_Value in Item'Range loop
         Item (Index_Value) := 0;
      end loop;
   end Clear_Stream_Array;

   function Digest_Length (Name : String) return Natural
     with SPARK_Mode => On
   is
   begin
      if Name = "sha1" then
         return 20;
      elsif Name = "sha256" then
         return 32;
      elsif Name = "sha384" then
         return 48;
      elsif Name = "sha512" then
         return 64;
      else
         return 0;
      end if;
   end Digest_Length;

   function HMAC_Array
     (Name         : String;
      Key_Data     : Ada.Streams.Stream_Element_Array;
      Message_Data : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array
   is
      Size   : constant Natural := Digest_Length (Name);
      Result : Stream_Element_Array (1 .. Stream_Element_Offset (Size)) :=
        [others => 0];
   begin
      if Name = "sha1" then
         declare
            Digest : constant HMAC_SHA1_Digest :=
              HMAC_SHA1 (Key_Data, Message_Data);
         begin
            for Index_Value in Digest'Range loop
               Result (Stream_Element_Offset (Index_Value)) :=
                 Digest (Index_Value);
            end loop;
         end;
      elsif Name = "sha256" then
         declare
            Digest : constant HMAC_SHA256_Digest :=
              HMAC_SHA256 (Key_Data, Message_Data);
         begin
            for Index_Value in Digest'Range loop
               Result (Stream_Element_Offset (Index_Value)) :=
                 Digest (Index_Value);
            end loop;
         end;
      elsif Name = "sha384" then
         declare
            Digest : constant HMAC_SHA384_Digest :=
              HMAC_SHA384 (Key_Data, Message_Data);
         begin
            for Index_Value in Digest'Range loop
               Result (Stream_Element_Offset (Index_Value)) :=
                 Digest (Index_Value);
            end loop;
         end;
      elsif Name = "sha512" then
         declare
            Digest : constant HMAC_SHA512_Digest :=
              HMAC_SHA512 (Key_Data, Message_Data);
         begin
            for Index_Value in Digest'Range loop
               Result (Stream_Element_Offset (Index_Value)) :=
                 Digest (Index_Value);
            end loop;
         end;
      end if;
      return Result;
   end HMAC_Array;

   function PBKDF2_HMAC
     (Name          : String;
      Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      Iterations    : Positive;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array
   is
      Digest_Size : constant Natural := Digest_Length (Name);
      Blocks      : constant Natural :=
        (if Digest_Size = 0 then 0
         else (Output_Length + Digest_Size - 1) / Digest_Size);
      Result      :
        Stream_Element_Array (1 .. Stream_Element_Offset (Output_Length)) :=
          [others => 0];
      Result_Pos  : Stream_Element_Offset := Result'First;
      Salt_Block  : Stream_Element_Array (1 .. Salt_Data'Length + 4);
   begin
      if Output_Length = 0 or else Digest_Size = 0 then
         return Stream_Element_Array'(1 .. 0 => 0);
      end if;

      if Salt_Data'Length > 0 then
         Salt_Block
           (Salt_Block'First .. Salt_Block'First + Salt_Data'Length - 1) :=
           Salt_Data;
      end if;

      for Block_Index in 1 .. Blocks loop
         declare
            U_Value : Stream_Element_Array
              (1 .. Stream_Element_Offset (Digest_Size)) := [others => 0];
            T_Value : Stream_Element_Array
              (1 .. Stream_Element_Offset (Digest_Size)) := [others => 0];
         begin
            Store_U32_BE
              (Salt_Block, Salt_Block'Last - 3,
               Interfaces.Unsigned_32 (Block_Index));
            U_Value := HMAC_Array (Name, Password_Data, Salt_Block);
            T_Value := U_Value;

            for Round in 2 .. Iterations loop
               U_Value := HMAC_Array (Name, Password_Data, U_Value);
               for I in T_Value'Range loop
                  T_Value (I) := T_Value (I) xor U_Value (I);
               end loop;
            end loop;

            for I in T_Value'Range loop
               exit when Result_Pos > Result'Last;
               Result (Result_Pos) := T_Value (I);
               Result_Pos := Result_Pos + 1;
            end loop;
            Clear_Stream_Array (U_Value);
            Clear_Stream_Array (T_Value);
         end;
      end loop;
      Clear_Stream_Array (Salt_Block);
      return Result;
   end PBKDF2_HMAC;

   function PBKDF2_HMAC_SHA1
     (Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      Iterations    : Positive;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array is
   begin
      return
        PBKDF2_HMAC
          ("sha1", Password_Data, Salt_Data, Iterations, Output_Length);
   end PBKDF2_HMAC_SHA1;

   function PBKDF2_HMAC_SHA256
     (Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      Iterations    : Positive;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array is
   begin
      return
        PBKDF2_HMAC
          ("sha256", Password_Data, Salt_Data, Iterations, Output_Length);
   end PBKDF2_HMAC_SHA256;

   function PBKDF2_HMAC_SHA384
     (Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      Iterations    : Positive;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array is
   begin
      return
        PBKDF2_HMAC
          ("sha384", Password_Data, Salt_Data, Iterations, Output_Length);
   end PBKDF2_HMAC_SHA384;

   function PBKDF2_HMAC_SHA512
     (Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      Iterations    : Positive;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array is
   begin
      return
        PBKDF2_HMAC
          ("sha512", Password_Data, Salt_Data, Iterations, Output_Length);
   end PBKDF2_HMAC_SHA512;

   function PBKDF1
     (Name          : String;
      Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      Iterations    : Positive;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array
   is
      Digest_Size : constant Natural :=
        (if Name = "md5" then 16 elsif Name = "sha1" then 20 else 0);
      Result      :
        Stream_Element_Array (1 .. Stream_Element_Offset (Output_Length)) :=
          [others => 0];
   begin
      if Output_Length = 0 then
         return Stream_Element_Array'(1 .. 0 => 0);
      end if;
      if Digest_Size = 0 or else Output_Length > Digest_Size then
         return Result;
      end if;

      declare
         Initial_Data :
           Stream_Element_Array
             (1 .. Password_Data'Length + Salt_Data'Length) := [others => 0];
         Cursor_Value : Stream_Element_Offset := Initial_Data'First;
         Digest_Data  :
           Stream_Element_Array (1 .. Stream_Element_Offset (Digest_Size)) :=
             [others => 0];
      begin
         for Byte_Value of Password_Data loop
            Initial_Data (Cursor_Value) := Byte_Value;
            Cursor_Value := Cursor_Value + 1;
         end loop;
         for Byte_Value of Salt_Data loop
            Initial_Data (Cursor_Value) := Byte_Value;
            Cursor_Value := Cursor_Value + 1;
         end loop;

         if Name = "md5" then
            declare
               Digest_Value : constant CryptoLib.Hashes.MD5_Digest :=
                 CryptoLib.Hashes.MD5 (Initial_Data);
            begin
               for Index_Value in Digest_Value'Range loop
                  Digest_Data (Stream_Element_Offset (Index_Value)) :=
                    Digest_Value (Index_Value);
               end loop;
            end;
         else
            declare
               Digest_Value : constant CryptoLib.Hashes.SHA1_Digest :=
                 CryptoLib.Hashes.SHA1 (Initial_Data);
            begin
               for Index_Value in Digest_Value'Range loop
                  Digest_Data (Stream_Element_Offset (Index_Value)) :=
                    Digest_Value (Index_Value);
               end loop;
            end;
         end if;
         Clear_Stream_Array (Initial_Data);

         for Round in 2 .. Iterations loop
            if Name = "md5" then
               declare
                  Digest_Value : constant CryptoLib.Hashes.MD5_Digest :=
                    CryptoLib.Hashes.MD5 (Digest_Data);
               begin
                  for Index_Value in Digest_Value'Range loop
                     Digest_Data (Stream_Element_Offset (Index_Value)) :=
                       Digest_Value (Index_Value);
                  end loop;
               end;
            else
               declare
                  Digest_Value : constant CryptoLib.Hashes.SHA1_Digest :=
                    CryptoLib.Hashes.SHA1 (Digest_Data);
               begin
                  for Index_Value in Digest_Value'Range loop
                     Digest_Data (Stream_Element_Offset (Index_Value)) :=
                       Digest_Value (Index_Value);
                  end loop;
               end;
            end if;
         end loop;

         Result := Digest_Data (1 .. Stream_Element_Offset (Output_Length));
         Clear_Stream_Array (Digest_Data);
         return Result;
      end;
   exception
      when others =>
         return [1 .. Stream_Element_Offset (Output_Length) => 0];
   end PBKDF1;

   function PBKDF1_MD5
     (Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      Iterations    : Positive;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array is
   begin
      return
        PBKDF1 ("md5", Password_Data, Salt_Data, Iterations, Output_Length);
   end PBKDF1_MD5;

   function PBKDF1_SHA1
     (Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      Iterations    : Positive;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array is
   begin
      return
        PBKDF1 ("sha1", Password_Data, Salt_Data, Iterations, Output_Length);
   end PBKDF1_SHA1;

   procedure PKCS12_Adjust_Block
     (Data       : in out Stream_Element_Array;
      Block_First : Stream_Element_Offset;
      B_Data      : Stream_Element_Array)
   is
      Carry : Natural := 1;
      Sum   : Natural;
   begin
      for Offset_Value in reverse 0 .. B_Data'Length - 1 loop
         Sum :=
           Natural (Data (Block_First + Stream_Element_Offset (Offset_Value)))
           + Natural (B_Data (B_Data'First + Stream_Element_Offset (Offset_Value)))
           + Carry;
         Data (Block_First + Stream_Element_Offset (Offset_Value)) :=
           Stream_Element (Sum mod 256);
         Carry := Sum / 256;
      end loop;
   end PKCS12_Adjust_Block;

   function PKCS12_KDF_SHA1
     (Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      Iterations    : Positive;
      Id_Byte       : Ada.Streams.Stream_Element;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array
   is
      U_Size          : constant Natural := 20;
      V_Size          : constant Natural := 64;
      S_Length        : constant Natural :=
        (if Salt_Data'Length = 0 then 0
         else V_Size * ((Salt_Data'Length + V_Size - 1) / V_Size));
      Password_BMP_Length : constant Natural := (Password_Data'Length + 1) * 2;
      P_Length        : constant Natural :=
        (if Password_BMP_Length = 0 then 0
         else V_Size * ((Password_BMP_Length + V_Size - 1) / V_Size));
      I_Length        : constant Natural := S_Length + P_Length;
      Block_Count     : constant Natural :=
        (if Output_Length = 0 then 0
         else (Output_Length + U_Size - 1) / U_Size);
      Result          :
        Stream_Element_Array (1 .. Stream_Element_Offset (Output_Length)) :=
          [others => 0];
      Result_Pos      : Stream_Element_Offset := Result'First;
   begin
      if Output_Length = 0 then
         return Stream_Element_Array'(1 .. 0 => 0);
      end if;

      declare
         D_Data       : Stream_Element_Array (1 .. Stream_Element_Offset (V_Size)) :=
           [others => Id_Byte];
         P_BMP        :
           Stream_Element_Array
             (1 .. Stream_Element_Offset (Password_BMP_Length)) :=
             [others => 0];
         I_Data       :
           Stream_Element_Array (1 .. Stream_Element_Offset (I_Length)) :=
             [others => 0];
         P_BMP_Cursor : Stream_Element_Offset := P_BMP'First;
         I_Cursor     : Stream_Element_Offset := I_Data'First;
      begin
         for Byte_Value of Password_Data loop
            P_BMP (P_BMP_Cursor) := 0;
            P_BMP (P_BMP_Cursor + 1) := Byte_Value;
            P_BMP_Cursor := P_BMP_Cursor + 2;
         end loop;
         P_BMP (P_BMP_Cursor) := 0;
         P_BMP (P_BMP_Cursor + 1) := 0;

         for Offset_Value in 0 .. S_Length - 1 loop
            I_Data (I_Cursor) :=
              Salt_Data
                (Salt_Data'First
                 + Stream_Element_Offset (Offset_Value mod Salt_Data'Length));
            I_Cursor := I_Cursor + 1;
         end loop;
         for Offset_Value in 0 .. P_Length - 1 loop
            I_Data (I_Cursor) :=
              P_BMP
                (P_BMP'First
                 + Stream_Element_Offset (Offset_Value mod P_BMP'Length));
            I_Cursor := I_Cursor + 1;
         end loop;

         for Block_Index in 1 .. Block_Count loop
            declare
               A_Data     : Stream_Element_Array (1 .. Stream_Element_Offset (U_Size)) :=
                 [others => 0];
               B_Data     : Stream_Element_Array (1 .. Stream_Element_Offset (V_Size)) :=
                 [others => 0];
               Hash_Input :
                 Stream_Element_Array
                   (1 .. Stream_Element_Offset (V_Size + I_Length)) :=
                   [others => 0];
            begin
               Hash_Input (1 .. Stream_Element_Offset (V_Size)) := D_Data;
               if I_Length > 0 then
                  Hash_Input
                    (Stream_Element_Offset (V_Size) + 1 .. Hash_Input'Last) :=
                    I_Data;
               end if;
               declare
                  Digest_Value : constant CryptoLib.Hashes.SHA1_Digest :=
                    CryptoLib.Hashes.SHA1 (Hash_Input);
               begin
                  for Index_Value in Digest_Value'Range loop
                     A_Data (Stream_Element_Offset (Index_Value)) :=
                       Digest_Value (Index_Value);
                  end loop;
               end;

               for Round in 2 .. Iterations loop
                  declare
                     Digest_Value : constant CryptoLib.Hashes.SHA1_Digest :=
                       CryptoLib.Hashes.SHA1 (A_Data);
                  begin
                     for Index_Value in Digest_Value'Range loop
                        A_Data (Stream_Element_Offset (Index_Value)) :=
                          Digest_Value (Index_Value);
                     end loop;
                  end;
               end loop;

               for Offset_Value in 0 .. V_Size - 1 loop
                  B_Data (B_Data'First + Stream_Element_Offset (Offset_Value)) :=
                    A_Data
                      (A_Data'First
                       + Stream_Element_Offset (Offset_Value mod U_Size));
               end loop;
               for Block_First in 0 .. (I_Length / V_Size) - 1 loop
                  PKCS12_Adjust_Block
                    (I_Data,
                     I_Data'First + Stream_Element_Offset (Block_First * V_Size),
                     B_Data);
               end loop;

               for Index_Value in A_Data'Range loop
                  exit when Result_Pos > Result'Last;
                  Result (Result_Pos) := A_Data (Index_Value);
                  Result_Pos := Result_Pos + 1;
               end loop;
               Clear_Stream_Array (A_Data);
               Clear_Stream_Array (B_Data);
               Clear_Stream_Array (Hash_Input);
            end;
         end loop;

         Clear_Stream_Array (D_Data);
         Clear_Stream_Array (P_BMP);
         Clear_Stream_Array (I_Data);
         return Result;
      end;
   exception
      when others =>
         return [1 .. Stream_Element_Offset (Output_Length) => 0];
   end PKCS12_KDF_SHA1;

   function RotL32
     (Value : Interfaces.Unsigned_32;
      Count : Natural) return Interfaces.Unsigned_32
     with SPARK_Mode => On,
          Pre => Count <= 32
   is
   begin
      return
        Interfaces.Shift_Left (Value, Count)
        or Interfaces.Shift_Right (Value, 32 - Count);
   end RotL32;

   function Load_LE32
     (Data  : Stream_Element_Array;
      First : Stream_Element_Offset) return Interfaces.Unsigned_32
     with SPARK_Mode => On,
          Pre => First >= Data'First
            and then First <= Stream_Element_Offset'Last - 3
            and then First + 3 <= Data'Last
   is
   begin
      return
        Interfaces.Unsigned_32 (Data (First))
        or Interfaces.Shift_Left (Interfaces.Unsigned_32 (Data (First + 1)), 8)
        or Interfaces.Shift_Left (Interfaces.Unsigned_32 (Data (First + 2)), 16)
        or Interfaces.Shift_Left (Interfaces.Unsigned_32 (Data (First + 3)), 24);
   end Load_LE32;

   procedure Store_LE32
     (Value : Interfaces.Unsigned_32;
      Data  : in out Stream_Element_Array;
      First : Stream_Element_Offset)
     with SPARK_Mode => On,
          Pre => First >= Data'First
            and then First <= Stream_Element_Offset'Last - 3
            and then First + 3 <= Data'Last
   is
   begin
      Data (First) := Stream_Element (Value and 16#FF#);
      Data (First + 1) :=
        Stream_Element (Interfaces.Shift_Right (Value, 8) and 16#FF#);
      Data (First + 2) :=
        Stream_Element (Interfaces.Shift_Right (Value, 16) and 16#FF#);
      Data (First + 3) :=
        Stream_Element (Interfaces.Shift_Right (Value, 24) and 16#FF#);
   end Store_LE32;

   procedure Salsa20_8
     (Input_Data  : Stream_Element_Array;
      Output_Data : out Stream_Element_Array)
   is
      subtype Word_Index is Natural range 0 .. 15;
      type Word_Array is array (Word_Index) of Interfaces.Unsigned_32;
      X : Word_Array;
      Z : Word_Array;

      procedure Quarterround (A, B, C, D : Word_Index) is
      begin
         Z (B) := Z (B) xor RotL32 (Z (A) + Z (D), 7);
         Z (C) := Z (C) xor RotL32 (Z (B) + Z (A), 9);
         Z (D) := Z (D) xor RotL32 (Z (C) + Z (B), 13);
         Z (A) := Z (A) xor RotL32 (Z (D) + Z (C), 18);
      end Quarterround;
   begin
      for Index_Value in Word_Index loop
         X (Index_Value) :=
           Load_LE32
             (Input_Data,
              Input_Data'First + Stream_Element_Offset (Index_Value * 4));
         Z (Index_Value) := X (Index_Value);
      end loop;

      for Round in 1 .. 4 loop
         Quarterround (0, 4, 8, 12);
         Quarterround (5, 9, 13, 1);
         Quarterround (10, 14, 2, 6);
         Quarterround (15, 3, 7, 11);
         Quarterround (0, 1, 2, 3);
         Quarterround (5, 6, 7, 4);
         Quarterround (10, 11, 8, 9);
         Quarterround (15, 12, 13, 14);
      end loop;

      for Index_Value in Word_Index loop
         Store_LE32
           (Z (Index_Value) + X (Index_Value),
            Output_Data,
            Output_Data'First + Stream_Element_Offset (Index_Value * 4));
      end loop;
   end Salsa20_8;

   procedure Scrypt_BlockMix
     (Input_Data  : Stream_Element_Array;
      R_Value     : Positive;
      Output_Data : out Stream_Element_Array)
   is
      Block_Size : constant Natural := 64;
      X_Data     : Stream_Element_Array (1 .. 64) := [others => 0];
      T_Data     : Stream_Element_Array (1 .. 64) := [others => 0];
   begin
      X_Data :=
        Input_Data
          (Input_Data'Last - Stream_Element_Offset (Block_Size) + 1
           .. Input_Data'Last);

      for Block_Index in 0 .. 2 * R_Value - 1 loop
         declare
            In_First  : constant Stream_Element_Offset :=
              Input_Data'First + Stream_Element_Offset (Block_Index * Block_Size);
            Out_Block : constant Natural :=
              (if Block_Index mod 2 = 0
               then Block_Index / 2
               else R_Value + Block_Index / 2);
            Out_First : constant Stream_Element_Offset :=
              Output_Data'First + Stream_Element_Offset (Out_Block * Block_Size);
         begin
            for Offset_Value in 0 .. Block_Size - 1 loop
               T_Data (T_Data'First + Stream_Element_Offset (Offset_Value)) :=
                 X_Data (X_Data'First + Stream_Element_Offset (Offset_Value))
                 xor Input_Data (In_First + Stream_Element_Offset (Offset_Value));
            end loop;
            Salsa20_8 (T_Data, X_Data);
            Output_Data
              (Out_First .. Out_First + Stream_Element_Offset (Block_Size - 1)) :=
              X_Data;
         end;
      end loop;
      Clear_Stream_Array (X_Data);
      Clear_Stream_Array (T_Data);
   end Scrypt_BlockMix;

   function Scrypt_Integerify
     (Data : Stream_Element_Array;
      R_Value : Positive;
      N_Value : Positive) return Natural
   is
      Block_Size : constant Natural := 128 * R_Value;
      First      : constant Stream_Element_Offset :=
        Data'First + Stream_Element_Offset (Block_Size - 64);
   begin
      return
        Natural
          (Load_LE32 (Data, First) mod Interfaces.Unsigned_32 (N_Value));
   end Scrypt_Integerify;

   --  V is 128 * r * N octets -- the whole point of scrypt, and far too large
   --  for the stack. At the RFC's own interactive parameters (N = 16384,
   --  r = 8) it is 16 MiB, and it was a stack object here, so every cost
   --  setting worth using raised STORAGE_ERROR. Only the toy parameters the
   --  single old test used fitted. It goes on the heap, and is wiped before
   --  it is freed.
   --  The largest working set ROMix will allocate: 256 MiB, which at r = 8
   --  admits N up to 262144 -- past every cost setting a real key file
   --  carries, and still a bound, because the parameters come from the file.
   Scrypt_Memory_Cap : constant := 256 * 1024 * 1024;

   type Scrypt_Buffer is access Stream_Element_Array;

   procedure Free_Scrypt_Buffer is new Ada.Unchecked_Deallocation
     (Stream_Element_Array, Scrypt_Buffer);

   procedure Scrypt_SMix
     (Block_Data : in out Stream_Element_Array;
      N_Value    : Positive;
      R_Value    : Positive)
   is
      Block_Size : constant Natural := 128 * R_Value;
      V_Data     : Scrypt_Buffer :=
        new Stream_Element_Array'
          (1 .. Stream_Element_Offset (N_Value * Block_Size) => 0);
      X_Data     : Stream_Element_Array (1 .. Stream_Element_Offset (Block_Size)) :=
        Block_Data;
      Y_Data     : Stream_Element_Array (1 .. Stream_Element_Offset (Block_Size)) :=
        [others => 0];
   begin
      for Index_Value in 0 .. N_Value - 1 loop
         declare
            V_First : constant Stream_Element_Offset :=
              V_Data'First + Stream_Element_Offset (Index_Value * Block_Size);
         begin
            V_Data.all
              (V_First .. V_First + Stream_Element_Offset (Block_Size - 1)) :=
              X_Data;
            Scrypt_BlockMix (X_Data, R_Value, Y_Data);
            X_Data := Y_Data;
         end;
      end loop;

      for Index_Value in 0 .. N_Value - 1 loop
         declare
            J_Value : constant Natural :=
              Scrypt_Integerify (X_Data, R_Value, N_Value);
            V_First : constant Stream_Element_Offset :=
              V_Data'First + Stream_Element_Offset (J_Value * Block_Size);
         begin
            for Offset_Value in 0 .. Block_Size - 1 loop
               X_Data
                 (X_Data'First + Stream_Element_Offset (Offset_Value)) :=
                 X_Data (X_Data'First + Stream_Element_Offset (Offset_Value))
                 xor V_Data.all
                       (V_First + Stream_Element_Offset (Offset_Value));
            end loop;
            Scrypt_BlockMix (X_Data, R_Value, Y_Data);
            X_Data := Y_Data;
         end;
      end loop;

      Block_Data := X_Data;
      Clear_Stream_Array (V_Data.all);
      Free_Scrypt_Buffer (V_Data);
      Clear_Stream_Array (X_Data);
      Clear_Stream_Array (Y_Data);
   exception
      when others =>
         --  Do not leak the working set if anything above raises.
         if V_Data /= null then
            Clear_Stream_Array (V_Data.all);
            Free_Scrypt_Buffer (V_Data);
         end if;
         Clear_Stream_Array (X_Data);
         Clear_Stream_Array (Y_Data);
         raise;
   end Scrypt_SMix;

   function Is_Power_Of_Two (Value : Positive) return Boolean
     with SPARK_Mode => On
   is
      Work_Value : Natural := Value;
   begin
      while Work_Value > 1 loop
         pragma Loop_Variant (Decreases => Work_Value);
         if Work_Value mod 2 /= 0 then
            return False;
         end if;
         Work_Value := Work_Value / 2;
      end loop;
      return True;
   end Is_Power_Of_Two;

   function Scrypt_SHA256
     (Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      N             : Positive;
      R             : Positive;
      P             : Positive;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array
   is
      Block_Size : constant Natural := 128 * R;
      B_Length   : constant Natural := P * Block_Size;
   begin
      if Output_Length = 0 then
         return Stream_Element_Array'(1 .. 0 => 0);
      end if;
      --  Bound the working set rather than N alone. N > 16_384 used to be
      --  refused outright, which rejected parameters that turn up in ordinary
      --  files -- OpenSSL writes N = 16384 for a scrypt-encrypted PKCS#8 key
      --  and 32768 and 65536 are both common -- and refusing returns a zeroed
      --  key that a caller then decrypts with, so the failure surfaced as a
      --  wrong passphrase rather than as an unsupported cost. What actually
      --  needs limiting is 128 * r * N, the memory ROMix allocates, because
      --  these numbers arrive from the file being opened and not from the
      --  program.
      if not Is_Power_Of_Two (N)
        or else R > 32
        or else P > 32
        or else N > Scrypt_Memory_Cap / Block_Size
        or else P > Scrypt_Memory_Cap / Block_Size
      then
         return [1 .. Stream_Element_Offset (Output_Length) => 0];
      end if;

      declare
         B_Data : Stream_Element_Array :=
           PBKDF2_HMAC_SHA256 (Password_Data, Salt_Data, 1, B_Length);
      begin
         for Parallel_Index in 0 .. P - 1 loop
            declare
               First      : constant Stream_Element_Offset :=
                 B_Data'First + Stream_Element_Offset (Parallel_Index * Block_Size);
               Last       : constant Stream_Element_Offset :=
                 First + Stream_Element_Offset (Block_Size - 1);
               Block_Data : Stream_Element_Array (1 .. Stream_Element_Offset (Block_Size)) :=
                 B_Data (First .. Last);
            begin
               Scrypt_SMix (Block_Data, N, R);
               B_Data (First .. Last) := Block_Data;
               Clear_Stream_Array (Block_Data);
            end;
         end loop;

         declare
            Result : constant Stream_Element_Array :=
              PBKDF2_HMAC_SHA256
                (Password_Data, B_Data, 1, Output_Length);
         begin
            Clear_Stream_Array (B_Data);
            return Result;
         end;
      end;
   exception
      when others =>
         return [1 .. Stream_Element_Offset (Output_Length) => 0];
   end Scrypt_SHA256;

   function EVP_Bytes_To_Key_MD5
     (Password_Data : Ada.Streams.Stream_Element_Array;
      Salt_Data     : Ada.Streams.Stream_Element_Array;
      Output_Length : Natural)
      return Ada.Streams.Stream_Element_Array
   is
      Result          :
        Stream_Element_Array (1 .. Stream_Element_Offset (Output_Length)) :=
          [others => 0];
      Generated       : Natural := 0;
      Previous_Length : Natural := 0;
      Previous        : Stream_Element_Array (1 .. 16) := [others => 0];
   begin
      if Output_Length = 0 then
         return Stream_Element_Array'(1 .. 0 => 0);
      end if;

      while Generated < Output_Length loop
         declare
            Input_Length : constant Natural :=
              Previous_Length + Password_Data'Length + Salt_Data'Length;
            Input_Data   :
              Stream_Element_Array
                (1 .. Stream_Element_Offset (Input_Length)) := [others => 0];
            Cursor_Value : Stream_Element_Offset := Input_Data'First;
            Digest_Value : CryptoLib.Hashes.MD5_Digest;
         begin
            for Index_Value in 1 .. Previous_Length loop
               Input_Data (Cursor_Value) :=
                 Previous (Stream_Element_Offset (Index_Value));
               Cursor_Value := Cursor_Value + 1;
            end loop;
            for Byte_Value of Password_Data loop
               Input_Data (Cursor_Value) := Byte_Value;
               Cursor_Value := Cursor_Value + 1;
            end loop;
            for Byte_Value of Salt_Data loop
               Input_Data (Cursor_Value) := Byte_Value;
               Cursor_Value := Cursor_Value + 1;
            end loop;
            Digest_Value := CryptoLib.Hashes.MD5 (Input_Data);
            for Index_Value in Digest_Value'Range loop
               Previous (Stream_Element_Offset (Index_Value)) :=
                 Digest_Value (Index_Value);
            end loop;
            Clear_Stream_Array (Input_Data);
            Previous_Length := 16;
         end;

         for Index_Value in Previous'Range loop
            exit when Generated = Output_Length;
            Generated := Generated + 1;
            Result (Stream_Element_Offset (Generated)) :=
              Previous (Index_Value);
         end loop;
      end loop;
      Clear_Stream_Array (Previous);
      return Result;
   exception
      when others =>
      return [1 .. Stream_Element_Offset (Output_Length) => 0];
   end EVP_Bytes_To_Key_MD5;

   function Seven_Zip_AES_SHA256_KDF
     (Password_UTF16LE : Ada.Streams.Stream_Element_Array;
      Salt_Data        : Ada.Streams.Stream_Element_Array;
      Num_Cycles_Power : Natural)
      return Ada.Streams.Stream_Element_Array
   is
      use type Interfaces.Unsigned_64;

      Context_Item : CryptoLib.Hashes.SHA256_Context;
      Counter_Data : Stream_Element_Array (1 .. 8) := [others => 0];
      Rounds       : Interfaces.Unsigned_64 :=
        Interfaces.Unsigned_64 (2) ** Num_Cycles_Power;
   begin
      CryptoLib.Hashes.Initialize_SHA256 (Context_Item);
      loop
         if Salt_Data'Length > 0 then
            CryptoLib.Hashes.Update (Context_Item, Salt_Data);
         end if;

         if Password_UTF16LE'Length > 0 then
            CryptoLib.Hashes.Update (Context_Item, Password_UTF16LE);
         end if;

         CryptoLib.Hashes.Update (Context_Item, Counter_Data);
         for Index_Value in Counter_Data'Range loop
            Counter_Data (Index_Value) := Counter_Data (Index_Value) + 1;
            exit when Counter_Data (Index_Value) /= 0;
         end loop;

         Rounds := Rounds - 1;
         exit when Rounds = 0;
      end loop;

      declare
         Digest_Value : constant CryptoLib.Hashes.SHA256_Digest :=
           CryptoLib.Hashes.Finalize (Context_Item);
         Result       : Stream_Element_Array (1 .. 32);
      begin
         for Index_Value in Digest_Value'Range loop
            Result (Stream_Element_Offset (Index_Value)) :=
              Digest_Value (Index_Value);
         end loop;
         Clear_Stream_Array (Counter_Data);
         return Result;
      end;
   exception
      when others =>
         return [1 .. 32 => 0];
   end Seven_Zip_AES_SHA256_KDF;

end CryptoLib.Macs;
