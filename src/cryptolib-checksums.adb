package body CryptoLib.Checksums is
   procedure Adler32_Reset
     (State : out Adler32_State)
   is
   begin
      State.A := 1;
      State.B := 0;
   end Adler32_Reset;

   procedure Adler32_Update
     (State : in out Adler32_State;
      Byte  : Ada.Streams.Stream_Element)
   is
   begin
      State.A :=
        Adler32_Component
          ((Interfaces.Unsigned_32 (State.A) + Interfaces.Unsigned_32 (Byte)) mod Mod_Adler);
      State.B :=
        Adler32_Component
          ((Interfaces.Unsigned_32 (State.B) + Interfaces.Unsigned_32 (State.A)) mod Mod_Adler);
   end Adler32_Update;

   procedure Adler32_Update
     (State : in out Adler32_State;
      Data  : Ada.Streams.Stream_Element_Array)
   is
   begin
      for I in Data'Range loop
         Adler32_Update (State, Data (I));
      end loop;
   end Adler32_Update;

   procedure Adler32_Update
     (State : in out Adler32_State;
      Data  : Byte_Array)
   is
   begin
      for I in Data'Range loop
         Adler32_Update (State, Ada.Streams.Stream_Element (Data (I)));
      end loop;
   end Adler32_Update;

   function Adler32
     (Data : Ada.Streams.Stream_Element_Array)
      return Interfaces.Unsigned_32
   is
      State : Adler32_State;
   begin
      Adler32_Reset (State);
      Adler32_Update (State, Data);
      return Adler32_Value (State);
   end Adler32;

   function Adler32
     (Data : Byte_Array)
      return Interfaces.Unsigned_32
   is
      State : Adler32_State;
   begin
      Adler32_Reset (State);
      Adler32_Update (State, Data);
      return Adler32_Value (State);
   end Adler32;

   procedure CRC32_Reset
     (State : out CRC32_State)
   is
   begin
      State.CRC := 16#FFFF_FFFF#;
   end CRC32_Reset;

   procedure CRC32_Update
     (State : in out CRC32_State;
      Byte  : Ada.Streams.Stream_Element)
   is
   begin
      CRC32_Update_Raw (State.CRC, Byte);
   end CRC32_Update;

   procedure CRC32_Update_Raw
     (CRC  : in out Interfaces.Unsigned_32;
      Byte : Ada.Streams.Stream_Element)
   is
      Polynomial : constant Interfaces.Unsigned_32 := 16#EDB8_8320#;
      C          : Interfaces.Unsigned_32 :=
        (CRC xor Interfaces.Unsigned_32 (Byte)) and 16#FF#;
   begin
      for J in 1 .. 8 loop
         pragma Unreferenced (J);

         if (C and 1) /= 0 then
            C := Interfaces.Shift_Right (C, 1) xor Polynomial;
         else
            C := Interfaces.Shift_Right (C, 1);
         end if;
      end loop;

      CRC := Interfaces.Shift_Right (CRC, 8) xor C;
   end CRC32_Update_Raw;

   procedure CRC32_Update
     (State : in out CRC32_State;
      Data  : Ada.Streams.Stream_Element_Array)
   is
   begin
      for I in Data'Range loop
         CRC32_Update (State, Data (I));
      end loop;
   end CRC32_Update;

   procedure CRC32_Update
     (State : in out CRC32_State;
      Data  : Byte_Array)
   is
   begin
      for I in Data'Range loop
         CRC32_Update (State, Ada.Streams.Stream_Element (Data (I)));
      end loop;
   end CRC32_Update;

   function CRC32
     (Data : Ada.Streams.Stream_Element_Array)
      return Interfaces.Unsigned_32
   is
      State : CRC32_State;
   begin
      CRC32_Reset (State);
      CRC32_Update (State, Data);
      return CRC32_Value (State);
   end CRC32;

   function CRC32
     (Data : Byte_Array)
      return Interfaces.Unsigned_32
   is
      State : CRC32_State;
   begin
      CRC32_Reset (State);
      CRC32_Update (State, Data);
      return CRC32_Value (State);
   end CRC32;
end CryptoLib.Checksums;
