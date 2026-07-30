with Ada.Text_IO;
with CryptoLib.Curve25519;
with CryptoLib.Errors;
with CryptoLib.Random;

--  Agree an X25519 shared secret, the counterpart to the README's key-exchange
--  fragment. Both sides reach the same 32 octets.
procedure Example_Curve25519 is
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Curve25519.Public_Key;

   Rng : CryptoLib.Random.Random_Source;
   A_Private, B_Private : CryptoLib.Curve25519.Private_Key;
   A_Public,  B_Public  : CryptoLib.Curve25519.Public_Key;
   A_Secret,  B_Secret  : CryptoLib.Curve25519.Public_Key;
   Status : CryptoLib.Errors.Status;
begin
   CryptoLib.Random.Initialize_Production (Rng);
   Status := CryptoLib.Curve25519.Generate_Keypair (Rng, A_Private, A_Public);
   if Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("no entropy source available");
      return;
   end if;
   Status := CryptoLib.Curve25519.Generate_Keypair (Rng, B_Private, B_Public);
   if Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("no entropy source available");
      return;
   end if;

   --  Each side multiplies its own private scalar by the other's public point.
   --  Handshake_Failed here means the peer sent a low-order point, which would
   --  make the shared secret all zeros.
   Status := CryptoLib.Curve25519.Shared_Secret (A_Private, B_Public, A_Secret);
   if Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("peer point refused");
      return;
   end if;
   Status := CryptoLib.Curve25519.Shared_Secret (B_Private, A_Public, B_Secret);
   if Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("peer point refused");
      return;
   end if;

   Ada.Text_IO.Put_Line
     ("both sides agree: " & Boolean'Image (A_Secret = B_Secret));

   --  Scrub the private scalars when done with them.
   CryptoLib.Curve25519.Clear (A_Private);
   CryptoLib.Curve25519.Clear (B_Private);
end Example_Curve25519;
