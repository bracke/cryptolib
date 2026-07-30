with Ada.Streams;
with Ada.Text_IO;
with CryptoLib.Ed25519;
with CryptoLib.Errors;
with CryptoLib.Random;

--  Sign a message with Ed25519 and verify it, the counterpart to the README's
--  signing fragment.
procedure Example_Ed25519 is
   use type CryptoLib.Errors.Status;
   use type Ada.Streams.Stream_Element_Array;

   Rng     : CryptoLib.Random.Random_Source;
   --  An Ed25519 seed is the same width as its public key.
   Seed    : Ada.Streams.Stream_Element_Array
     (1 .. Ada.Streams.Stream_Element_Offset
             (CryptoLib.Ed25519.Public_Key_Length));
   Public  : Ada.Streams.Stream_Element_Array
     (1 .. Ada.Streams.Stream_Element_Offset
             (CryptoLib.Ed25519.Public_Key_Length));
   Message : constant Ada.Streams.Stream_Element_Array :=
     [1 .. 11 => 16#41#];
   Sig     : Ada.Streams.Stream_Element_Array
     (1 .. Ada.Streams.Stream_Element_Offset
             (CryptoLib.Ed25519.Signature_Length));
   Status  : CryptoLib.Errors.Status;
begin
   CryptoLib.Random.Initialize_Production (Rng);
   Status := CryptoLib.Ed25519.Generate_Keypair (Rng, Seed, Public);
   if Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("no entropy source available");
      return;
   end if;

   Status := CryptoLib.Ed25519.Sign (Seed, Public, Message, Sig);
   if Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("signing failed");
      return;
   end if;

   --  Verify returns Ok only for a valid, canonical signature.
   Status := CryptoLib.Ed25519.Verify (Public, Sig, Message);
   Ada.Text_IO.Put_Line
     ("signature verifies: " & Boolean'Image (Status = CryptoLib.Errors.Ok));

   --  And a message it does not cover must not verify.
   Status :=
     CryptoLib.Ed25519.Verify (Public, Sig, Message & Ada.Streams.Stream_Element'(0));
   Ada.Text_IO.Put_Line
     ("a changed message verifies: "
      & Boolean'Image (Status = CryptoLib.Errors.Ok));
end Example_Ed25519;
