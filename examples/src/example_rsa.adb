with Ada.Streams;
with Ada.Text_IO;
with CryptoLib.Errors;
with CryptoLib.Random;
with CryptoLib.RSA;

--  Generate an RSA key, sign with PSS, verify, the counterpart to the README's
--  RSA fragment.
--
--  Generate_Keypair_With_Primes rather than Generate_Keypair because the CRT
--  parameters make signing about twice as fast and are what a private key file
--  has to carry. A caller that only wants to sign can use the shorter form.
procedure Example_RSA is
   use type CryptoLib.Errors.Status;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;

   Rng : CryptoLib.Random.Random_Source;
   K   : constant Ada.Streams.Stream_Element_Offset :=
     Ada.Streams.Stream_Element_Offset
       (CryptoLib.RSA.Modulus_Octets (CryptoLib.RSA.RSA_2048));

   Modulus, Private_Exponent, Signature : Ada.Streams.Stream_Element_Array
     (1 .. K);
   Public_Exponent : Ada.Streams.Stream_Element_Array (1 .. 3);
   P, Q, DP, DQ, QI : Ada.Streams.Stream_Element_Array (1 .. K / 2);
   Message : constant Ada.Streams.Stream_Element_Array := [1 .. 9 => 16#5A#];
   Status  : CryptoLib.Errors.Status;
begin
   CryptoLib.Random.Initialize_Production (Rng);
   Status := CryptoLib.RSA.Generate_Keypair_With_Primes
     (CryptoLib.RSA.RSA_2048, Rng, Modulus, Public_Exponent,
      Private_Exponent, P, Q, DP, DQ, QI);
   if Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("key generation failed");
      return;
   end if;

   --  Signing is blinded and the result is checked against the public exponent
   --  before it is returned, so a fault yields an error rather than a
   --  signature. Passing the CRT parameters is optional; omitting all five
   --  signs the slower way.
   Status := CryptoLib.RSA.Sign_PSS
     (Modulus, Public_Exponent, Private_Exponent, CryptoLib.RSA.SHA256,
      Salt_Length => 32, Message => Message, Rng => Rng,
      Signature => Signature,
      Prime_P => P, Prime_Q => Q, Exponent_P => DP, Exponent_Q => DQ,
      Coefficient => QI);
   if Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("signing failed");
      return;
   end if;

   Status := CryptoLib.RSA.Verify_PSS
     (Modulus, Public_Exponent, CryptoLib.RSA.SHA256, 32, Message, Signature);
   Ada.Text_IO.Put_Line
     ("signature verifies: " & Boolean'Image (Status = CryptoLib.Errors.Ok));

   --  A message the signature does not cover must not verify.
   Status := CryptoLib.RSA.Verify_PSS
     (Modulus, Public_Exponent, CryptoLib.RSA.SHA256, 32,
      Message & Ada.Streams.Stream_Element'(0), Signature);
   Ada.Text_IO.Put_Line
     ("a changed message verifies: "
      & Boolean'Image (Status = CryptoLib.Errors.Ok));
end Example_RSA;
