with Ada.Streams; use Ada.Streams;
with System;

with CryptoLib.EC_Arith;  use CryptoLib.EC_Arith;
with CryptoLib.EC_Curves; use CryptoLib.EC_Curves;
with CryptoLib.Secure_Wipe;

package body CryptoLib.ECDH is

   use CryptoLib.Errors;

   function Secret_Length (Curve : Curve_Id) return Positive
   is (Curve_Of (Curve).P_Len);

   function Public_Key_Length (Curve : Curve_Id) return Positive
   is (2 * Curve_Of (Curve).P_Len + 1);

   function Valid_Peer_Point
     (Curve      : Curve_Id;
      Peer_Point : Stream_Element_Array) return Boolean
   is
      Cv : constant Curve_Data := Curve_Of (Curve);
      Q  : Point;
   begin
      --  Encoding and coordinate range first, then the curve equation. Each
      --  refusal is a thing a peer can send.
      if not Parse_Point (Cv, Peer_Point, Q) then
         return False;
      end if;
      return On_Curve (Cv, Q);
   exception
      when others =>
         return False;
   end Valid_Peer_Point;

   function Public_Key
     (Curve          : Curve_Id;
      Private_Scalar : Stream_Element_Array;
      Public_Point   : out Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      Cv : constant Curve_Data := Curve_Of (Curve);
      D  : Element;

      procedure Scrub is
         use System;
      begin
         CryptoLib.Secure_Wipe.Wipe (D'Address, D'Size / Storage_Unit);
      end Scrub;
   begin
      Public_Point := [others => 0];
      if Natural (Public_Point'Length) /= Public_Key_Length (Curve) then
         return Handshake_Failed;
      end if;
      if not Parse_Private (Private_Scalar, Cv, D) then
         Scrub;
         return Authentication_Failed;
      end if;
      return Result : constant CryptoLib.Errors.Status :=
        Affine_Point (Cv, D, Public_Point)
      do
         Scrub;
      end return;
   exception
      when others =>
         Public_Point := [others => 0];
         Scrub;
         return Internal_Error;
   end Public_Key;

   function Generate_Keypair
     (Curve          : Curve_Id;
      Rng            : in out CryptoLib.Random.Random_Source;
      Private_Scalar : out Stream_Element_Array;
      Public_Point   : out Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      Cv       : constant Curve_Data := Curve_Of (Curve);
      Attempts : constant := 64;
      D        : Element;

      procedure Scrub is
         use System;
      begin
         CryptoLib.Secure_Wipe.Wipe (D'Address, D'Size / Storage_Unit);
      end Scrub;
   begin
      Private_Scalar := [others => 0];
      Public_Point := [others => 0];
      if Natural (Private_Scalar'Length) /= Secret_Length (Curve)
        or else Natural (Public_Point'Length) /= Public_Key_Length (Curve)
      then
         return Handshake_Failed;
      end if;

      --  A uniform draw is a valid scalar only when it lands in [1, n-1].
      --  Redrawing keeps the distribution honest where reducing mod n would
      --  bias it toward the low end.
      for Attempt in 1 .. Attempts loop
         if CryptoLib.Random.Fill (Rng, Private_Scalar) /= Ok then
            Private_Scalar := [others => 0];
            return Internal_Error;
         end if;
         Trim_To_Order (Cv, Private_Scalar);
         if Parse_Private (Private_Scalar, Cv, D) then
            return Result : constant CryptoLib.Errors.Status :=
              Affine_Point (Cv, D, Public_Point)
            do
               Scrub;
               if Result /= Ok then
                  Private_Scalar := [others => 0];
               end if;
            end return;
         end if;
      end loop;

      Private_Scalar := [others => 0];
      Scrub;
      return Internal_Error;
   exception
      when others =>
         Private_Scalar := [others => 0];
         Public_Point := [others => 0];
         Scrub;
         return Internal_Error;
   end Generate_Keypair;

   function Shared_Secret
     (Curve          : Curve_Id;
      Private_Scalar : Stream_Element_Array;
      Peer_Point     : Stream_Element_Array;
      Secret         : out Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      Cv : constant Curve_Data := Curve_Of (Curve);
      D  : Element;
      Q  : Point;

      procedure Scrub is
         use System;
      begin
         CryptoLib.Secure_Wipe.Wipe (D'Address, D'Size / Storage_Unit);
      end Scrub;
   begin
      Secret := [others => 0];
      if Natural (Secret'Length) /= Secret_Length (Curve) then
         return Handshake_Failed;
      end if;

      --  Validate the peer's point before the scalar is anywhere near it.
      --  An off-curve point lies on a curve the peer chose, and multiplying
      --  it by d leaks d.
      if not Parse_Point (Cv, Peer_Point, Q)
        or else not On_Curve (Cv, Q)
      then
         return Authentication_Failed;
      end if;
      if not Parse_Private (Private_Scalar, Cv, D) then
         Scrub;
         return Authentication_Failed;
      end if;

      declare
         --  The ladder is the same fixed-length double-and-add-always one
         --  the signer uses, over the peer's point instead of the generator.
         Shared : Point := Scalar_Mult_Base (Cv, D, Q);
         Ok_X   : constant Boolean := Affine_X (Cv, Shared, Secret);

         procedure Scrub_Point is
            use System;
         begin
            CryptoLib.Secure_Wipe.Wipe
              (Shared'Address, Shared'Size / Storage_Unit);
         end Scrub_Point;
      begin
         Scrub;
         Scrub_Point;
         if not Ok_X then
            --  d*Q at infinity. With a scalar in [1, n-1], a cofactor of 1
            --  and a point that passed On_Curve this is unreachable; it is
            --  refused rather than trusted not to happen.
            Secret := [others => 0];
            return Authentication_Failed;
         end if;
      end;
      return Ok;
   exception
      when others =>
         Secret := [others => 0];
         Scrub;
         return Internal_Error;
   end Shared_Secret;

end CryptoLib.ECDH;
