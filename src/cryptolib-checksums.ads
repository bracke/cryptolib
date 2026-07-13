with Ada.Streams;
with Interfaces;

--  @summary Non-cryptographic checksum functions.
package CryptoLib.Checksums is
   pragma Preelaborate;
   use type Interfaces.Unsigned_32;

   subtype Byte is Interfaces.Unsigned_8;
   type Byte_Array is array (Natural range <>) of Byte;
   --  Natural-indexed byte buffer for callers whose public byte type is not
   --  Ada.Streams.Stream_Element_Array.

   type Adler32_State is private;
   --  Running standard zlib Adler-32 state.

   type CRC32_State is private;
   --  Running standard gzip/ZIP/7z CRC-32 state.

   --  Reset State to the initial Adler-32 value.
   --  @param State the Adler-32 state to reset
   procedure Adler32_Reset (State : out Adler32_State);

   --  Incorporate one byte into State.
   --  @param State running Adler-32 state
   --  @param Byte  byte to incorporate
   procedure Adler32_Update
     (State : in out Adler32_State;
      Byte  : Ada.Streams.Stream_Element);

   --  Incorporate Data into State in order.
   --  @param State running Adler-32 state
   --  @param Data  bytes to incorporate
   procedure Adler32_Update
     (State : in out Adler32_State;
      Data  : Ada.Streams.Stream_Element_Array);

   --  Incorporate Data into State in order.
   --  @param State running Adler-32 state
   --  @param Data  bytes to incorporate
   procedure Adler32_Update
     (State : in out Adler32_State;
      Data  : Byte_Array);

   --  Return the current Adler-32 value.
   --  @param State running Adler-32 state
   --  @return standard Adler-32 value
   function Adler32_Value
     (State : Adler32_State)
      return Interfaces.Unsigned_32;

   --  Compute standard zlib Adler-32 over Data.
   --  @param Data bytes to checksum
   --  @return standard Adler-32 value
   function Adler32
     (Data : Ada.Streams.Stream_Element_Array)
      return Interfaces.Unsigned_32;

   --  Compute standard zlib Adler-32 over Data.
   --  @param Data bytes to checksum
   --  @return standard Adler-32 value
   function Adler32
     (Data : Byte_Array)
      return Interfaces.Unsigned_32;

   --  Reset State to the initial CRC-32 value.
   --  @param State the CRC-32 state to reset
   procedure CRC32_Reset (State : out CRC32_State);

   --  Incorporate one byte into State.
   --  @param State running CRC-32 state
   --  @param Byte  byte to incorporate
   procedure CRC32_Update
     (State : in out CRC32_State;
      Byte  : Ada.Streams.Stream_Element);

   --  Incorporate one byte into a raw unfinalized CRC-32 value.
   --  @param CRC  raw running CRC-32 value
   --  @param Byte byte to incorporate
   procedure CRC32_Update_Raw
     (CRC  : in out Interfaces.Unsigned_32;
      Byte : Ada.Streams.Stream_Element);

   --  Incorporate Data into State in order.
   --  @param State running CRC-32 state
   --  @param Data  bytes to incorporate
   procedure CRC32_Update
     (State : in out CRC32_State;
      Data  : Ada.Streams.Stream_Element_Array);

   --  Incorporate Data into State in order.
   --  @param State running CRC-32 state
   --  @param Data  bytes to incorporate
   procedure CRC32_Update
     (State : in out CRC32_State;
      Data  : Byte_Array);

   --  Return the finalized CRC-32 value.
   --  @param State running CRC-32 state
   --  @return standard finalized CRC-32 value
   function CRC32_Value
     (State : CRC32_State)
      return Interfaces.Unsigned_32;

   --  Compute standard gzip/ZIP/7z CRC-32 over Data.
   --  @param Data bytes to checksum
   --  @return standard finalized CRC-32 value
   function CRC32
     (Data : Ada.Streams.Stream_Element_Array)
      return Interfaces.Unsigned_32;

   --  Compute standard gzip/ZIP/7z CRC-32 over Data.
   --  @param Data bytes to checksum
   --  @return standard finalized CRC-32 value
   function CRC32
     (Data : Byte_Array)
      return Interfaces.Unsigned_32;

private
   Mod_Adler : constant Interfaces.Unsigned_32 := 65_521;
   subtype Adler32_Component is Interfaces.Unsigned_32 range 0 .. Mod_Adler - Interfaces.Unsigned_32'(1);

   type Adler32_State is record
      A : Adler32_Component := 1;
      B : Adler32_Component := 0;
   end record;

   function Adler32_Value
     (State : Adler32_State)
      return Interfaces.Unsigned_32 is
     (Interfaces.Shift_Left (Interfaces.Unsigned_32 (State.B), 16)
      or Interfaces.Unsigned_32 (State.A));

   type CRC32_State is record
      CRC : Interfaces.Unsigned_32 := 16#FFFF_FFFF#;
   end record;

   function CRC32_Value
     (State : CRC32_State)
      return Interfaces.Unsigned_32 is
     (State.CRC xor 16#FFFF_FFFF#);
end CryptoLib.Checksums;
