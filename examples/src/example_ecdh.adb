with Ada.Streams;
with Ada.Text_IO;
with CryptoLib.EC_Curves;
with CryptoLib.ECDH;
with CryptoLib.Errors;
with CryptoLib.Random;

--  Agree a shared secret over NIST P-256, the counterpart to the README's
--  ECDH fragment. Prefer X25519 where the choice is yours; these curves are
--  here for protocols that require them.
procedure Example_ECDH is
   use type CryptoLib.Errors.Status;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;

   Curve : constant CryptoLib.ECDH.Curve_Id := CryptoLib.EC_Curves.Nistp256;
   Width : constant Ada.Streams.Stream_Element_Offset :=
     Ada.Streams.Stream_Element_Offset (CryptoLib.ECDH.Secret_Length (Curve));
   Point : constant Ada.Streams.Stream_Element_Offset :=
     Ada.Streams.Stream_Element_Offset
       (CryptoLib.ECDH.Public_Key_Length (Curve));

   Rng : CryptoLib.Random.Random_Source;
   A_Private, B_Private, A_Secret, B_Secret :
     Ada.Streams.Stream_Element_Array (1 .. Width);
   A_Public, B_Public : Ada.Streams.Stream_Element_Array (1 .. Point);
   Status : CryptoLib.Errors.Status;
begin
   CryptoLib.Random.Initialize_Production (Rng);
   Status := CryptoLib.ECDH.Generate_Keypair (Curve, Rng, A_Private, A_Public);
   if Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("key generation failed");
      return;
   end if;
   Status := CryptoLib.ECDH.Generate_Keypair (Curve, Rng, B_Private, B_Public);
   if Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("key generation failed");
      return;
   end if;

   --  The peer's point is validated before the private scalar touches it: a
   --  point off the curve would leak the scalar, which is the invalid-curve
   --  attack.
   Status := CryptoLib.ECDH.Shared_Secret (Curve, A_Private, B_Public, A_Secret);
   if Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("peer point refused");
      return;
   end if;
   Status := CryptoLib.ECDH.Shared_Secret (Curve, B_Private, A_Public, B_Secret);
   Ada.Text_IO.Put_Line
     ("both sides agree: "
      & Boolean'Image (Status = CryptoLib.Errors.Ok
                       and then A_Secret = B_Secret));

   --  A point that is not on the curve is refused rather than multiplied.
   declare
      Off_Curve : Ada.Streams.Stream_Element_Array := B_Public;
   begin
      Off_Curve (Off_Curve'Last) := Off_Curve (Off_Curve'Last) + 1;
      Ada.Text_IO.Put_Line
        ("an off-curve peer point is accepted: "
         & Boolean'Image (CryptoLib.ECDH.Valid_Peer_Point (Curve, Off_Curve)));
   end;
end Example_ECDH;
