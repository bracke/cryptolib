
package body CryptoLib.Buffers is
   use Ada.Streams;
   use CryptoLib.Errors;

   function Ensure_Storage (Item : in out Packet_Buffer) return Status is
   begin
      if Item.Data = null then
         Item.Data := new Buffer_Data'[others => 0];
      end if;
      return Ok;
   exception
      when others =>
         Item.Last := 0;
         return Internal_Error;
   end Ensure_Storage;

   procedure Clear (Item : out Packet_Buffer) is
   begin
      --  Packet_Buffer is also used for private-key material, signatures,
      --  session-key derivation inputs, and other protocol binary fields.
      --  Reset retained storage when it exists, but keep default/empty buffers
      --  allocation-free so large container records do not consume stack.
      if Item.Data /= null then
         Item.Data.all := [others => 0];
      end if;
      Item.Last := 0;
   end Clear;

   function Length (Item : Packet_Buffer) return Natural
     with SPARK_Mode => On
   is
   begin
      return Natural (Item.Last);
   end Length;

   function Is_Empty (Item : Packet_Buffer) return Boolean
     with SPARK_Mode => On
   is
   begin
      return Item.Last = 0;
   end Is_Empty;

   function Set
     (Item : out Packet_Buffer;
      Data : Stream_Element_Array)
      return Status
   is
   begin
      Clear (Item);
      return Append (Item, Data);
   exception
      when others =>
         Clear (Item);
         return Internal_Error;
   end Set;

   function Append
     (Item : in out Packet_Buffer;
      Data : Stream_Element_Array)
      return Status
   is
      New_Last : Stream_Element_Offset;
   begin
      if Data'Length = 0 then
         return Ok;
      end if;

      if Natural (Item.Last) + Data'Length > Max_Packet_Length then
         return Internal_Error;
      end if;

      if Ensure_Storage (Item) /= Ok then
         return Internal_Error;
      end if;

      New_Last := Item.Last + Stream_Element_Offset (Data'Length);
      declare
         Target_Index : Stream_Element_Offset := Item.Last + 1;
      begin
         for Source_Index in Data'Range loop
            Item.Data.all (Target_Index) := Data (Source_Index);
            Target_Index := Target_Index + 1;
         end loop;
      end;
      Item.Last := New_Last;
      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Append;

   function Append_Byte
     (Item  : in out Packet_Buffer;
      Value : Stream_Element)
      return Status
   is
      New_Last : Stream_Element_Offset;
   begin
      if Natural (Item.Last) + 1 > Max_Packet_Length then
         return Internal_Error;
      end if;

      if Ensure_Storage (Item) /= Ok then
         return Internal_Error;
      end if;

      New_Last := Item.Last + 1;
      Item.Data.all (New_Last) := Value;
      Item.Last := New_Last;
      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Append_Byte;

   function To_Array
     (Item : Packet_Buffer)
      return Stream_Element_Array
     with SPARK_Mode => On
   is
   begin
      if Item.Last = 0 then
         return Empty : constant Stream_Element_Array (1 .. 0) := [others => 0] do
            null;
         end return;
      end if;

      if Item.Data = null then
         return Empty : constant Stream_Element_Array (1 .. 0) := [others => 0] do
            null;
         end return;
      end if;

      return Stream_Element_Array (Item.Data.all (1 .. Item.Last));
   end To_Array;
end CryptoLib.Buffers;
