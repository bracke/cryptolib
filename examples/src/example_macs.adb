with Ada.Streams;
with Ada.Text_IO;
with CryptoLib.Macs;

--  Authenticate a message, and derive a key from a password.
procedure Example_Macs is
   Key      : constant Ada.Streams.Stream_Element_Array (1 .. 4) := [1, 2, 3, 4];
   Message  : constant Ada.Streams.Stream_Element_Array (1 .. 3) := [65, 66, 67];
   Salt     : constant Ada.Streams.Stream_Element_Array (1 .. 8) := [others => 9];
   Tag      : constant CryptoLib.Macs.HMAC_SHA256_Digest :=
     CryptoLib.Macs.HMAC_SHA256 (Key, Message);
   Derived  : constant Ada.Streams.Stream_Element_Array :=
     CryptoLib.Macs.PBKDF2_HMAC_SHA256 (Key, Salt, 4096, 32);
begin
   Ada.Text_IO.Put_Line ("tag bytes:" & Natural'Image (Tag'Length));
   Ada.Text_IO.Put_Line ("derived bytes:" & Natural'Image (Derived'Length));
end Example_Macs;
