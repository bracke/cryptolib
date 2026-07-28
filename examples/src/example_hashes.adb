with Ada.Streams;
with Ada.Text_IO;
with CryptoLib.Hashes;

--  Digest a message with SHA-256.
procedure Example_Hashes is
   Message : constant Ada.Streams.Stream_Element_Array (1 .. 5) :=
     [72, 101, 108, 108, 111];
   Digest  : constant CryptoLib.Hashes.SHA256_Digest :=
     CryptoLib.Hashes.SHA256 (Message);
begin
   Ada.Text_IO.Put_Line
     ("sha256 first byte:" & Ada.Streams.Stream_Element'Image (Digest (1)));
end Example_Hashes;
