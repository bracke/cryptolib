with CryptoLib.Constant_Time;
with CryptoLib.Hashes;
with CryptoLib.Modexp;

package body CryptoLib.RSA is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;

   subtype Octets is Ada.Streams.Stream_Element_Array;
   subtype Offset is Ada.Streams.Stream_Element_Offset;

   --  The DigestInfo that precedes the digest in a PKCS#1 v1.5 block, with
   --  its own length already folded in. Held as constants rather than built
   --  from an encoder: these never vary, and a value that never varies is
   --  better checked against a reference than recomputed. Each was derived
   --  from the DigestInfo definition and then confirmed against the block
   --  OpenSSL actually produces.
   SHA256_Prefix : constant Octets :=
     [16#30#, 16#31#, 16#30#, 16#0D#, 16#06#, 16#09#, 16#60#, 16#86#,
      16#48#, 16#01#, 16#65#, 16#03#, 16#04#, 16#02#, 16#01#, 16#05#,
      16#00#, 16#04#, 16#20#];

   SHA384_Prefix : constant Octets :=
     [16#30#, 16#41#, 16#30#, 16#0D#, 16#06#, 16#09#, 16#60#, 16#86#,
      16#48#, 16#01#, 16#65#, 16#03#, 16#04#, 16#02#, 16#02#, 16#05#,
      16#00#, 16#04#, 16#30#];

   SHA512_Prefix : constant Octets :=
     [16#30#, 16#51#, 16#30#, 16#0D#, 16#06#, 16#09#, 16#60#, 16#86#,
      16#48#, 16#01#, 16#65#, 16#03#, 16#04#, 16#02#, 16#03#, 16#05#,
      16#00#, 16#04#, 16#40#];

   --  Where the value starts, ignoring leading zero octets.
   function Value_First (Data : Octets) return Offset is
   begin
      for I in Data'Range loop
         if Data (I) /= 0 then
            return I;
         end if;
      end loop;
      return Data'Last + 1;
   end Value_First;

   function Modulus_Bits (Modulus : Octets) return Natural is
      First : constant Offset := Value_First (Modulus);
      Top   : Natural;
      Bits  : Natural;
   begin
      if First > Modulus'Last then
         return 0;
      end if;

      Bits := Natural (Modulus'Last - First) * 8;
      Top := Natural (Modulus (First));
      while Top > 0 loop
         Bits := Bits + 1;
         Top := Top / 2;
      end loop;
      return Bits;
   end Modulus_Bits;

   --  Is Left < Right, both unsigned big-endian of the same length?
   function Less_Than (Left : Octets; Right : Octets) return Boolean is
   begin
      if Left'Length /= Right'Length then
         return False;
      end if;

      for I in 0 .. Left'Length - 1 loop
         declare
            L : constant Ada.Streams.Stream_Element :=
              Left (Left'First + Offset (I));
            R : constant Ada.Streams.Stream_Element :=
              Right (Right'First + Offset (I));
         begin
            if L /= R then
               return L < R;
            end if;
         end;
      end loop;

      return False;
   end Less_Than;

   function Verify_PKCS1_V1_5
     (Modulus   : Octets;
      Exponent  : Octets;
      Hash      : Hash_Algorithm;
      Message   : Octets;
      Signature : Octets)
      return CryptoLib.Errors.Status
   is
      Mod_First : constant Offset := Value_First (Modulus);
      Exp_First : constant Offset := Value_First (Exponent);
   begin
      if Mod_First > Modulus'Last or else Exp_First > Exponent'Last then
         --  A zero modulus or exponent.
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      declare
         N : constant Octets := Modulus (Mod_First .. Modulus'Last);
         E : constant Octets := Exponent (Exp_First .. Exponent'Last);
         K : constant Natural := Natural (N'Length);
      begin
         --  Montgomery arithmetic needs an odd modulus, and an RSA modulus is
         --  a product of two odd primes. An even one is not an RSA modulus.
         if N (N'Last) mod 2 = 0 then
            return CryptoLib.Errors.Handshake_Failed;
         end if;

         --  RFC 8017 requires the signature to be exactly as long as the
         --  modulus. Accepting a shorter one and padding it would accept a
         --  signature that was never produced for this key.
         if Natural (Signature'Length) /= K then
            return CryptoLib.Errors.Handshake_Failed;
         end if;

         if not Less_Than (Signature, N) then
            return CryptoLib.Errors.Handshake_Failed;
         end if;

         declare
            Prefix_Length : constant Natural :=
              (case Hash is
                  when SHA256 => Natural (SHA256_Prefix'Length),
                  when SHA384 => Natural (SHA384_Prefix'Length),
                  when SHA512 => Natural (SHA512_Prefix'Length));
            Digest_Length : constant Natural :=
              (case Hash is
                  when SHA256 => 32,
                  when SHA384 => 48,
                  when SHA512 => 64);
            Block_Length  : constant Natural :=
              Prefix_Length + Digest_Length;
         begin
            --  Two leading octets, at least eight padding octets, and the
            --  separator. A modulus smaller than that cannot hold a valid
            --  block, so no signature under it could ever verify.
            if K < Block_Length + 11 then
               return CryptoLib.Errors.Handshake_Failed;
            end if;

            declare
               Recovered : constant Octets :=
                 CryptoLib.Modexp.Mod_Exp (Signature, E, N);
               Expected  : Octets (1 .. Offset (K)) := [others => 16#FF#];
               Tail      : constant Offset :=
                 Offset (K) - Offset (Block_Length) + 1;
            begin
               if Recovered'Length /= Expected'Length then
                  return CryptoLib.Errors.Internal_Error;
               end if;

               --  EM = 00 01 FF..FF 00 || DigestInfo, fully determined: the
               --  only freedom is how many FF octets, and that follows from
               --  the modulus size. Nothing here is scanned for or inferred
               --  from the recovered block.
               Expected (1) := 16#00#;
               Expected (2) := 16#01#;
               Expected (Tail - 1) := 16#00#;

               case Hash is
                  when SHA256 =>
                     Expected (Tail .. Tail + SHA256_Prefix'Length - 1) :=
                       SHA256_Prefix;
                  when SHA384 =>
                     Expected (Tail .. Tail + SHA384_Prefix'Length - 1) :=
                       SHA384_Prefix;
                  when SHA512 =>
                     Expected (Tail .. Tail + SHA512_Prefix'Length - 1) :=
                       SHA512_Prefix;
               end case;

               declare
                  Digest_First : constant Offset :=
                    Tail + Offset (Prefix_Length);
               begin
                  case Hash is
                     when SHA256 =>
                        Expected (Digest_First .. Expected'Last) :=
                          Octets (CryptoLib.Hashes.SHA256 (Message));
                     when SHA384 =>
                        Expected (Digest_First .. Expected'Last) :=
                          Octets (CryptoLib.Hashes.SHA384 (Message));
                     when SHA512 =>
                        Expected (Digest_First .. Expected'Last) :=
                          Octets (CryptoLib.Hashes.SHA512 (Message));
                  end case;
               end;

               if CryptoLib.Constant_Time.Equal (Recovered, Expected) then
                  return CryptoLib.Errors.Ok;
               else
                  return CryptoLib.Errors.Authentication_Failed;
               end if;
            end;
         end;
      end;
   end Verify_PKCS1_V1_5;

end CryptoLib.RSA;
