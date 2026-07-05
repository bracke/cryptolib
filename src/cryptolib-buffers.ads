with Ada.Streams;
with CryptoLib.Errors;

--  @summary Bounded, lazily allocated byte buffer for SSH packets and other
--  binary protocol fields, capped at Max_Packet_Length bytes.
--
--  Storage is allocated on first write and zeroed on Clear, since a
--  Packet_Buffer may hold key material, signatures, or key-derivation inputs.
--  Mutators return an Errors.Status so overflow and allocation failure surface
--  as Internal_Error rather than exceptions.
package CryptoLib.Buffers is

   Max_Packet_Length : constant Natural := 256 * 1024 + 4;

   type Packet_Buffer is private;

   --  Reset the buffer to empty, zeroing any allocated storage.
   --  @param Item the buffer to clear
   procedure Clear (Item : out Packet_Buffer);

   --  Report the number of bytes currently held.
   --  @param Item the buffer to query
   --  @return the byte count, in 0 .. Max_Packet_Length
   function Length (Item : Packet_Buffer) return Natural
     with SPARK_Mode => On;

   --  Report whether the buffer holds no bytes.
   --  @param Item the buffer to query
   --  @return True when the length is zero
   function Is_Empty (Item : Packet_Buffer) return Boolean
     with SPARK_Mode => On;

   --  Replace the buffer's contents with Data.
   --  @param Item the buffer to overwrite
   --  @param Data the bytes to store
   --  @return Ok on success, Internal_Error if Data exceeds the capacity
   function Set
     (Item : out Packet_Buffer;
      Data : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Append Data to the end of the buffer.
   --  @param Item the buffer to extend
   --  @param Data the bytes to append
   --  @return Ok on success, Internal_Error if the result would overflow
   function Append
     (Item : in out Packet_Buffer;
      Data : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Append a single byte to the end of the buffer.
   --  @param Item  the buffer to extend
   --  @param Value the byte to append
   --  @return Ok on success, Internal_Error if the result would overflow
   function Append_Byte
     (Item  : in out Packet_Buffer;
      Value : Ada.Streams.Stream_Element)
      return CryptoLib.Errors.Status;

   --  Return a copy of the buffer's current contents.
   --  @param Item the buffer to read
   --  @return the held bytes as a fresh array, empty when the buffer is empty
   function To_Array
     (Item : Packet_Buffer)
      return Ada.Streams.Stream_Element_Array
     with SPARK_Mode => On;

private
   subtype Buffer_Index is Ada.Streams.Stream_Element_Offset range
     Ada.Streams.Stream_Element_Offset'(1) ..
     Ada.Streams.Stream_Element_Offset (Max_Packet_Length);

   type Buffer_Data is array (Buffer_Index) of Ada.Streams.Stream_Element;
   type Buffer_Data_Access is access Buffer_Data;
   subtype Packet_Length_Offset is Ada.Streams.Stream_Element_Offset range
     0 .. Ada.Streams.Stream_Element_Offset (Max_Packet_Length);

   type Packet_Buffer is record
      Data : Buffer_Data_Access := null;
      Last : Packet_Length_Offset := 0;
   end record;
end CryptoLib.Buffers;
