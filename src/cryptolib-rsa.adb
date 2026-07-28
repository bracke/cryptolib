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

   --  Hash Message with the chosen digest.
   function Digest_Of
     (Hash : Hash_Algorithm; Message : Octets) return Octets
   is
   begin
      case Hash is
         when SHA256 => return Octets (CryptoLib.Hashes.SHA256 (Message));
         when SHA384 => return Octets (CryptoLib.Hashes.SHA384 (Message));
         when SHA512 => return Octets (CryptoLib.Hashes.SHA512 (Message));
      end case;
   end Digest_Of;

   function Digest_Length (Hash : Hash_Algorithm) return Natural
   is (case Hash is
          when SHA256 => 32,
          when SHA384 => 48,
          when SHA512 => 64);

   --  MGF1 from RFC 8017: the seed, then a counter, hashed repeatedly and
   --  concatenated until there is enough. The counter is four octets
   --  big-endian, and getting its width wrong produces a mask that is wrong
   --  only after the first block -- which is why this is written out rather
   --  than improvised at the call site.
   procedure MGF1
     (Hash : Hash_Algorithm;
      Seed : Octets;
      Mask : out Octets)
   is
      HLen    : constant Natural := Digest_Length (Hash);
      Counter : Natural := 0;
      Cursor  : Offset := Mask'First;
   begin
      Mask := [others => 0];

      while Cursor <= Mask'Last loop
         declare
            Input : Octets (1 .. Seed'Length + 4);
            Block : Octets (1 .. Offset (HLen));
            Take  : Offset;
         begin
            Input (1 .. Seed'Length) := Seed;
            Input (Seed'Length + 1) :=
              Ada.Streams.Stream_Element (Counter / 16_777_216);
            Input (Seed'Length + 2) :=
              Ada.Streams.Stream_Element ((Counter / 65_536) mod 256);
            Input (Seed'Length + 3) :=
              Ada.Streams.Stream_Element ((Counter / 256) mod 256);
            Input (Seed'Length + 4) :=
              Ada.Streams.Stream_Element (Counter mod 256);

            Block := Digest_Of (Hash, Input);

            Take := Offset'Min (Block'Length, Mask'Last - Cursor + 1);
            Mask (Cursor .. Cursor + Take - 1) :=
              Block (Block'First .. Block'First + Take - 1);
            Cursor := Cursor + Take;
            Counter := Counter + 1;
         end;
      end loop;
   end MGF1;

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

   function Verify_PSS
     (Modulus     : Octets;
      Exponent    : Octets;
      Hash        : Hash_Algorithm;
      Salt_Length : Natural;
      Message     : Octets;
      Signature   : Octets)
      return CryptoLib.Errors.Status
   is
      Mod_First : constant Offset := Value_First (Modulus);
      Exp_First : constant Offset := Value_First (Exponent);
   begin
      if Mod_First > Modulus'Last or else Exp_First > Exponent'Last then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      declare
         N     : constant Octets := Modulus (Mod_First .. Modulus'Last);
         E     : constant Octets := Exponent (Exp_First .. Exponent'Last);
         K     : constant Natural := Natural (N'Length);
         HLen  : constant Natural := Digest_Length (Hash);
         Bits  : constant Natural := Modulus_Bits (Modulus);
      begin
         if N (N'Last) mod 2 = 0
           or else Natural (Signature'Length) /= K
           or else not Less_Than (Signature, N)
         then
            return CryptoLib.Errors.Handshake_Failed;
         end if;

         --  emLen is the width of the encoded message, which is one bit
         --  narrower than the modulus. When the modulus is a whole number of
         --  octets that costs an octet, and forgetting it shifts everything
         --  that follows.
         declare
            Em_Bits : constant Natural := Bits - 1;
            Em_Len  : constant Natural := (Em_Bits + 7) / 8;
            Spare   : constant Natural := 8 * Em_Len - Em_Bits;
         begin
            if Em_Len < HLen + Salt_Length + 2 then
               return CryptoLib.Errors.Handshake_Failed;
            end if;

            declare
               Full : constant Octets :=
                 CryptoLib.Modexp.Mod_Exp (Signature, E, N);
               EM   : Octets (1 .. Offset (Em_Len));
            begin
               if Full'Length < Em_Len then
                  return CryptoLib.Errors.Internal_Error;
               end if;

               --  Mod_Exp returns the modulus's width; the encoded message is
               --  its rightmost emLen octets.
               EM := Full (Full'Last - Offset (Em_Len) + 1 .. Full'Last);

               if EM (EM'Last) /= 16#BC# then
                  return CryptoLib.Errors.Authentication_Failed;
               end if;

               --  The bits the encoding does not use must be zero. A verifier
               --  that skipped this would accept encodings that differ only
               --  in bits nobody signed.
               if Spare > 0
                 and then Natural (EM (EM'First)) / (2 ** (8 - Spare)) /= 0
               then
                  return CryptoLib.Errors.Authentication_Failed;
               end if;

               declare
                  DB_Len   : constant Offset := Offset (Em_Len - HLen - 1);
                  Masked   : constant Octets :=
                    EM (EM'First .. EM'First + DB_Len - 1);
                  H        : constant Octets :=
                    EM (EM'First + DB_Len .. EM'Last - 1);
                  Mask     : Octets (1 .. DB_Len);
                  DB       : Octets (1 .. DB_Len);
               begin
                  MGF1 (Hash, H, Mask);

                  for I in DB'Range loop
                     DB (I) := Masked (Masked'First + I - DB'First)
                       xor Mask (I);
                  end loop;

                  if Spare > 0 then
                     DB (DB'First) :=
                       Ada.Streams.Stream_Element
                         (Natural (DB (DB'First)) mod (2 ** (8 - Spare)));
                  end if;

                  --  DB is padding zeros, then a single 16#01#, then the
                  --  salt. The separator's position is fixed by the stated
                  --  salt length rather than searched for: searching is how a
                  --  signature made with one salt length gets accepted as
                  --  though it had another.
                  declare
                     Sep : constant Offset := DB'Last - Offset (Salt_Length);
                  begin
                     if Sep < DB'First then
                        return CryptoLib.Errors.Authentication_Failed;
                     end if;

                     for I in DB'First .. Sep - 1 loop
                        if DB (I) /= 0 then
                           return CryptoLib.Errors.Authentication_Failed;
                        end if;
                     end loop;

                     if DB (Sep) /= 16#01# then
                        return CryptoLib.Errors.Authentication_Failed;
                     end if;

                     declare
                        Salt   : constant Octets :=
                          DB (Sep + 1 .. DB'Last);
                        Digest : constant Octets :=
                          Digest_Of (Hash, Message);
                        Primed : Octets (1 .. 8 + Offset (HLen)
                                          + Offset (Salt_Length));
                     begin
                        --  M' = eight zero octets || mHash || salt.
                        Primed := [others => 0];
                        Primed (9 .. 8 + Offset (HLen)) := Digest;
                        if Salt'Length > 0 then
                           Primed (9 + Offset (HLen) .. Primed'Last) := Salt;
                        end if;

                        if CryptoLib.Constant_Time.Equal
                             (H, Digest_Of (Hash, Primed))
                        then
                           return CryptoLib.Errors.Ok;
                        else
                           return CryptoLib.Errors.Authentication_Failed;
                        end if;
                     end;
                  end;
               end;
            end;
         end;
      end;
   end Verify_PSS;

end CryptoLib.RSA;
