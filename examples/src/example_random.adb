with Ada.Streams;
with Ada.Text_IO;
with CryptoLib.Errors;
with CryptoLib.Random;

--  Draw cryptographically secure random bytes; fail closed.
procedure Example_Random is
   use type CryptoLib.Errors.Status;
   Rng    : CryptoLib.Random.Random_Source;
   Buffer : Ada.Streams.Stream_Element_Array (1 .. 32);
   Status : CryptoLib.Errors.Status;
begin
   CryptoLib.Random.Initialize_Production (Rng);
   Status := CryptoLib.Random.Fill (Rng, Buffer);
   if Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("no entropy source available");
      return;
   end if;
   Ada.Text_IO.Put_Line ("drew" & Natural'Image (Buffer'Length) & " bytes");
end Example_Random;
