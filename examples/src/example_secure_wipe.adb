with Ada.Streams;
with Ada.Text_IO;
with CryptoLib.Secure_Wipe;

--  Scrub key material before it leaves scope. A plain assignment of zeros is a
--  dead store and is removed by the optimizer; this is not.
procedure Example_Secure_Wipe is
   Secret : Ada.Streams.Stream_Element_Array (1 .. 32) := [others => 16#AB#];
begin
   CryptoLib.Secure_Wipe.Wipe (Secret'Address, Secret'Length);
   Ada.Text_IO.Put_Line
     ("first byte after wipe:" & Ada.Streams.Stream_Element'Image (Secret (1)));
end Example_Secure_Wipe;
