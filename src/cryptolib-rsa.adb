with CryptoLib.Constant_Time;
with CryptoLib.Hashes;
with CryptoLib.Bignum;
with CryptoLib.Modexp;
with CryptoLib.Secure_Wipe;
with System;

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

   --  EM for RSASSA-PKCS1-v1_5: 00 01 FF..FF 00 || DigestInfo || H(message).
   --
   --  One body, used to build the block a signature must decrypt to and to
   --  build the block a signature is made from. Verification's whole argument
   --  is that it compares against a fully determined block rather than
   --  parsing what it recovered; signing has to produce exactly that block or
   --  the two disagree about what a valid signature is.
   --  @param Hash    which digest
   --  @param Message the message to encode
   --  @param K       the modulus length in octets
   --  @param Block   out: the encoded block, K octets
   --  @param Usable  out: False when K is too small to hold the block
   procedure Encode_PKCS1_V1_5
     (Hash    : Hash_Algorithm;
      Message : Octets;
      K       : Natural;
      Block   : out Octets;
      Usable  : out Boolean)
   is
      Prefix_Length : constant Natural :=
        (case Hash is
            when SHA256 => Natural (SHA256_Prefix'Length),
            when SHA384 => Natural (SHA384_Prefix'Length),
            when SHA512 => Natural (SHA512_Prefix'Length));
      Block_Length : constant Natural := Prefix_Length + Digest_Length (Hash);
      Tail : constant Offset := Offset (K) - Offset (Block_Length) + 1;
   begin
      Block := [others => 16#FF#];
      Usable := False;
      --  Two leading octets, at least eight padding octets, the separator.
      if K < Block_Length + 11 or else Natural (Block'Length) /= K then
         return;
      end if;

      Block (Block'First) := 16#00#;
      Block (Block'First + 1) := 16#01#;
      Block (Block'First + Tail - 2) := 16#00#;

      case Hash is
         when SHA256 =>
            Block (Block'First + Tail - 1
                   .. Block'First + Tail - 2 + SHA256_Prefix'Length) :=
              SHA256_Prefix;
         when SHA384 =>
            Block (Block'First + Tail - 1
                   .. Block'First + Tail - 2 + SHA384_Prefix'Length) :=
              SHA384_Prefix;
         when SHA512 =>
            Block (Block'First + Tail - 1
                   .. Block'First + Tail - 2 + SHA512_Prefix'Length) :=
              SHA512_Prefix;
      end case;

      declare
         Digest_First : constant Offset :=
           Block'First + Tail - 1 + Offset (Prefix_Length);
      begin
         case Hash is
            when SHA256 =>
               Block (Digest_First .. Block'Last) :=
                 Octets (CryptoLib.Hashes.SHA256 (Message));
            when SHA384 =>
               Block (Digest_First .. Block'Last) :=
                 Octets (CryptoLib.Hashes.SHA384 (Message));
            when SHA512 =>
               Block (Digest_First .. Block'Last) :=
                 Octets (CryptoLib.Hashes.SHA512 (Message));
         end case;
      end;
      Usable := True;
   end Encode_PKCS1_V1_5;

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
         begin
            declare
               Recovered : constant Octets :=
                 CryptoLib.Modexp.Mod_Exp (Signature, E, N);
               Expected  : Octets (1 .. Offset (K));
               Usable    : Boolean;
            begin
               Encode_PKCS1_V1_5 (Hash, Message, K, Expected, Usable);
               if not Usable then
                  --  A modulus too small to hold a valid block: no signature
                  --  under it could ever verify.
                  return CryptoLib.Errors.Handshake_Failed;
               end if;
               if Recovered'Length /= Expected'Length then
                  return CryptoLib.Errors.Internal_Error;
               end if;

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

   --  Draw a blinding factor and store the pair: r**e, which the input is
   --  multiplied by, and r inverse, which undoes it. This is where the one
   --  modular inverse gets paid.
   function Draw_Pair
     (Modulus         : Octets;
      Public_Exponent : Octets;
      Rng             : in out CryptoLib.Random.Random_Source;
      Pair            : in out Blinding_Pair) return Boolean
   is
      use type CryptoLib.Errors.Status;
      Tries : constant := 16;
      R     : Octets (Modulus'Range) := [others => 0];
      R_Inv : Octets (Modulus'Range) := [others => 0];
      Found : Boolean := False;

      procedure Scrub is
      begin
         CryptoLib.Secure_Wipe.Wipe (R'Address, R'Length);
         CryptoLib.Secure_Wipe.Wipe (R_Inv'Address, R_Inv'Length);
      end Scrub;
   begin
      if Natural (Modulus'Length) > Maximum_Pair_Width then
         return False;
      end if;
      for Attempt in 1 .. Tries loop
         if CryptoLib.Random.Fill (Rng, R) /= CryptoLib.Errors.Ok then
            Scrub;
            return False;
         end if;
         --  Below the modulus, and away from zero and one where it would blind
         --  nothing. Anything sharing a factor with the modulus has no
         --  inverse, which for an RSA modulus means having stumbled on a prime
         --  factor -- it never happens, and it is answered rather than
         --  assumed.
         if CryptoLib.Bignum.Compare (R, Modulus) >= 0 then
            R := CryptoLib.Bignum.Subtract (R, Modulus);
         end if;
         if CryptoLib.Bignum.Bit_Length (R) > 1 then
            CryptoLib.Bignum.Mod_Inverse (R, Modulus, R_Inv, Found);
            exit when Found;
         end if;
      end loop;
      if not Found then
         Scrub;
         return False;
      end if;

      Pair.Factor := [others => 0];
      Pair.Inverse := [others => 0];
      Pair.Width := Modulus'Length;
      Pair.Factor (1 .. Modulus'Length) :=
        CryptoLib.Modexp.Mod_Exp (R, Public_Exponent, Modulus);
      Pair.Inverse (1 .. Modulus'Length) := R_Inv;
      Pair.Ready := True;
      Scrub;
      return True;
   end Draw_Pair;

   --  The private operation, plus the check that it worked.
   --
   --  Exponentiating with d is the only place a secret is touched; Modexp is
   --  constant-time in the exponent. The result is then raised to the public
   --  exponent and compared with what went in, which costs one cheap
   --  exponentiation and catches a fault in the private one. Releasing a
   --  faulty RSA signature is not a wrong answer -- next to a correct one it
   --  can give up the factorisation -- so a mismatch returns nothing.
   function Private_Operation
     (Block            : Octets;
      Modulus          : Octets;
      Public_Exponent  : Octets;
      Private_Exponent : Octets;
      Rng              : in out CryptoLib.Random.Random_Source;
      Pair             : in out Blinding_Pair;
      Signature        : out Octets;
      Prime_P          : Octets := [1 .. 0 => 0];
      Prime_Q          : Octets := [1 .. 0 => 0];
      Exponent_P       : Octets := [1 .. 0 => 0];
      Exponent_Q       : Octets := [1 .. 0 => 0];
      Coefficient      : Octets := [1 .. 0 => 0])
      return CryptoLib.Errors.Status
   is
      use type CryptoLib.Errors.Status;

      --  CRT is used when every part of it is there, and the plain
      --  exponentiation when any is missing. Both go through the same
      --  blinding and the same check afterwards.
      Use_CRT : constant Boolean :=
        Prime_P'Length > 0 and then Prime_Q'Length > 0
        and then Exponent_P'Length > 0 and then Exponent_Q'Length > 0
        and then Coefficient'Length > 0;

      --  s = s2 + q * (qinv * (s1 - s2) mod p), with s1 and s2 the halves
      --  taken modulo each prime. Two exponentiations at half the width cost
      --  about a quarter of one at full width.
      --
      --  A fault in either half yields a signature that does not verify, and
      --  releasing a faulty CRT signature next to a correct one gives up the
      --  factorisation outright -- the Bellcore attack. That is why CRT is
      --  only safe here: Private_Operation raises every candidate to the
      --  public exponent and refuses a mismatch, which is the countermeasure,
      --  and it was already in place before CRT arrived.
      function CRT_Exponentiate (Block : Octets) return Octets is
         package BN renames CryptoLib.Bignum;
         Half : constant Offset := Prime_P'Length;
         M_Mod_P, M_Mod_Q : Octets (1 .. Half) := [others => 0];
         Fine : Boolean;
      begin
         BN.Mod_Reduce (Block, Prime_P, M_Mod_P, Fine);
         if not Fine then
            return [1 .. 0 => 0];
         end if;
         BN.Mod_Reduce (Block, Prime_Q, M_Mod_Q, Fine);
         if not Fine then
            return [1 .. 0 => 0];
         end if;

         declare
            S1 : constant Octets :=
              CryptoLib.Modexp.Mod_Exp (M_Mod_P, Exponent_P, Prime_P);
            S2 : constant Octets :=
              CryptoLib.Modexp.Mod_Exp (M_Mod_Q, Exponent_Q, Prime_Q);
            --  The difference is taken modulo p, so s2 has to come below p
            --  first -- but the s2 added at the end is the unreduced one.
            --  Using one value for both is wrong, and quietly so.
            S2_Mod_P : Octets (1 .. Half) := S2;
            Diff     : Octets (1 .. Half);
            Result   : Octets (1 .. Block'Length) := [others => 0];
         begin
            if BN.Compare (S2_Mod_P, Prime_P) >= 0 then
               S2_Mod_P := BN.Subtract (S2_Mod_P, Prime_P);
            end if;
            if BN.Compare (S1, S2_Mod_P) >= 0 then
               Diff := BN.Subtract (S1, S2_Mod_P);
            else
               declare
                  Lifted : Octets (1 .. Half + 1);
                  Held   : Boolean;
               begin
                  BN.Resize (BN.Add (S1, Prime_P), Lifted'Length, Lifted,
                             Held);
                  if not Held then
                     return [1 .. 0 => 0];
                  end if;
                  Diff := BN.Subtract (Lifted, S2_Mod_P) (2 .. Half + 1);
               end;
            end if;

            declare
               H  : constant Octets :=
                 CryptoLib.Modexp.Mod_Mul (Coefficient, Diff, Prime_P);
               HQ : constant Octets := BN.Multiply (H, Prime_Q);
            begin
               BN.Resize (BN.Add (HQ, S2), Result'Length, Result, Fine);
               if not Fine then
                  return [1 .. 0 => 0];
               end if;
               return Result;
            end;
         end;
      end CRT_Exponentiate;

      procedure Scrub is
      begin
         --  The pair itself is the caller's to wipe; nothing secret is held
         --  locally here any more.
         null;
      end Scrub;
   begin
      Signature := [others => 0];

      --  A pair already started is reused and squared; one that is not is
      --  drawn here. A caller passing a throwaway pair therefore behaves
      --  exactly as it did before pairs existed, and one that keeps a pair
      --  pays the inverse once instead of every time.
      if Pair.Ready then
         if Pair.Width /= Modulus'Length then
            --  A pair from another key would blind with a factor whose
            --  inverse does not undo it.
            Scrub;
            return CryptoLib.Errors.Handshake_Failed;
         end if;
      elsif not Draw_Pair (Modulus, Public_Exponent, Rng, Pair) then
         --  Signing unblinded would be the wrong way to recover here.
         Scrub;
         return CryptoLib.Errors.Internal_Error;
      end if;

      declare
         R_To_E  : constant Octets := Pair.Factor (1 .. Pair.Width);
         R_Undo  : constant Octets := Pair.Inverse (1 .. Pair.Width);
         --  What the secret exponentiation actually sees is the message
         --  multiplied by a uniformly random value, so nothing correlated
         --  with its input tells an observer anything about the message.
         Blinded : constant Octets :=
           CryptoLib.Modexp.Mod_Mul (Block, R_To_E, Modulus);
         Raw     : constant Octets :=
           (if Use_CRT
            then CRT_Exponentiate (Blinded)
            else CryptoLib.Modexp.Mod_Exp
                   (Blinded, Private_Exponent, Modulus));
         --  m**d * r * r**-1 = m**d: the blinding cancels exactly.
         Candidate : constant Octets :=
           CryptoLib.Modexp.Mod_Mul (Raw, R_Undo, Modulus);
         Round_Trip : constant Octets :=
           CryptoLib.Modexp.Mod_Exp (Candidate, Public_Exponent, Modulus);
      begin
         if Raw'Length /= Modulus'Length
           or else Candidate'Length /= Signature'Length
           or else Round_Trip'Length /= Block'Length
         then
            Scrub;
            return CryptoLib.Errors.Internal_Error;
         end if;
         if not CryptoLib.Constant_Time.Equal (Round_Trip, Block) then
            Scrub;
            return CryptoLib.Errors.Authentication_Failed;
         end if;
         Signature := Candidate;
      end;

      --  Refresh by squaring both halves. Squaring r and r inverse leaves them
      --  inverses of each other, so the pair stays consistent while the factor
      --  a watcher would have to guess changes on every signature. Two
      --  multiplications where a fresh pair would cost an inverse.
      Pair.Factor (1 .. Pair.Width) :=
        CryptoLib.Modexp.Mod_Mul
          (Pair.Factor (1 .. Pair.Width), Pair.Factor (1 .. Pair.Width),
           Modulus);
      Pair.Inverse (1 .. Pair.Width) :=
        CryptoLib.Modexp.Mod_Mul
          (Pair.Inverse (1 .. Pair.Width), Pair.Inverse (1 .. Pair.Width),
           Modulus);

      Scrub;
      return CryptoLib.Errors.Ok;
   end Private_Operation;

   --  Shared entry checks: strip leading zeros, refuse a modulus that is not
   --  one, and size the output.
   procedure Prepare
     (Modulus          : Octets;
      Public_Exponent  : Octets;
      Private_Exponent : Octets;
      Signature        : Octets;
      N_First, E_First, D_First : out Offset;
      K                : out Natural;
      Usable           : out Boolean)
   is
   begin
      N_First := Value_First (Modulus);
      E_First := Value_First (Public_Exponent);
      D_First := Value_First (Private_Exponent);
      K := 0;
      Usable := False;
      if N_First > Modulus'Last
        or else E_First > Public_Exponent'Last
        or else D_First > Private_Exponent'Last
      then
         return;
      end if;
      --  Montgomery arithmetic needs an odd modulus, and an RSA modulus is a
      --  product of two odd primes.
      if Modulus (Modulus'Last) mod 2 = 0 then
         return;
      end if;
      K := Natural (Modulus'Last - N_First + 1);
      if Natural (Signature'Length) /= K then
         K := 0;
         return;
      end if;
      Usable := True;
   end Prepare;

   function Sign_PKCS1_V1_5
     (Modulus          : Octets;
      Public_Exponent  : Octets;
      Private_Exponent : Octets;
      Hash             : Hash_Algorithm;
      Message          : Octets;
      Rng              : in out CryptoLib.Random.Random_Source;
      Pair             : in out Blinding_Pair;
      Signature        : out Octets;
      Prime_P          : Octets := [1 .. 0 => 0];
      Prime_Q          : Octets := [1 .. 0 => 0];
      Exponent_P       : Octets := [1 .. 0 => 0];
      Exponent_Q       : Octets := [1 .. 0 => 0];
      Coefficient      : Octets := [1 .. 0 => 0]) return CryptoLib.Errors.Status
   is
      N_First, E_First, D_First : Offset;
      K      : Natural;
      Usable : Boolean;
   begin
      Signature := [others => 0];
      Prepare (Modulus, Public_Exponent, Private_Exponent, Signature,
               N_First, E_First, D_First, K, Usable);
      if not Usable then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      declare
         Block : Octets (1 .. Offset (K));
         Fits  : Boolean;
      begin
         Encode_PKCS1_V1_5 (Hash, Message, K, Block, Fits);
         if not Fits then
            return CryptoLib.Errors.Handshake_Failed;
         end if;
         return Private_Operation
           (Block,
            Modulus (N_First .. Modulus'Last),
            Public_Exponent (E_First .. Public_Exponent'Last),
            Private_Exponent (D_First .. Private_Exponent'Last),
            Rng, Pair, Signature,
            Prime_P, Prime_Q, Exponent_P, Exponent_Q, Coefficient);
      end;
   exception
      when others =>
         Signature := [others => 0];
         return CryptoLib.Errors.Internal_Error;
   end Sign_PKCS1_V1_5;

   function Sign_PSS
     (Modulus          : Octets;
      Public_Exponent  : Octets;
      Private_Exponent : Octets;
      Hash             : Hash_Algorithm;
      Salt_Length      : Natural;
      Message          : Octets;
      Rng              : in out CryptoLib.Random.Random_Source;
      Pair             : in out Blinding_Pair;
      Signature        : out Octets;
      Prime_P          : Octets := [1 .. 0 => 0];
      Prime_Q          : Octets := [1 .. 0 => 0];
      Exponent_P       : Octets := [1 .. 0 => 0];
      Exponent_Q       : Octets := [1 .. 0 => 0];
      Coefficient      : Octets := [1 .. 0 => 0]) return CryptoLib.Errors.Status
   is
      N_First, E_First, D_First : Offset;
      K      : Natural;
      Usable : Boolean;
      H_Len  : constant Natural := Digest_Length (Hash);
   begin
      Signature := [others => 0];
      Prepare (Modulus, Public_Exponent, Private_Exponent, Signature,
               N_First, E_First, D_First, K, Usable);
      if not Usable then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      declare
         --  RFC 8017 9.1.1: emBits is modBits - 1, so the block is one bit
         --  short of the modulus and EM is never numerically larger than n.
         Em_Bits : constant Natural :=
           Modulus_Bits (Modulus (N_First .. Modulus'Last)) - 1;
         Em_Len  : constant Natural := (Em_Bits + 7) / 8;
         Spare   : constant Natural := 8 * Em_Len - Em_Bits;
      begin
         if Em_Len < H_Len + Salt_Length + 2 then
            --  The modulus cannot hold a digest, this salt, the separator and
            --  the trailer. Refused rather than silently shortening the salt.
            return CryptoLib.Errors.Handshake_Failed;
         end if;

         declare
            Salt   : Octets (1 .. Offset (Salt_Length));
            M_Hash : constant Octets := Digest_Of (Hash, Message);
            Block  : Octets (1 .. Offset (Em_Len)) := [others => 0];
            DB_Len : constant Offset := Offset (Em_Len - H_Len - 1);
         begin
            if Salt_Length > 0 then
               declare
                  use type CryptoLib.Errors.Status;
               begin
                  if CryptoLib.Random.Fill (Rng, Salt) /= CryptoLib.Errors.Ok
                  then
                     return CryptoLib.Errors.Internal_Error;
                  end if;
               end;
            end if;

            declare
               --  M' = eight zero octets || mHash || salt, hashed to H.
               Primed : Octets (1 .. 8 + Offset (H_Len) + Salt'Length) :=
                 [others => 0];
            begin
               Primed (9 .. 8 + Offset (H_Len)) := M_Hash;
               if Salt_Length > 0 then
                  Primed (9 + Offset (H_Len) .. Primed'Last) := Salt;
               end if;

               declare
                  H_Value : constant Octets := Digest_Of (Hash, Primed);
                  DB      : Octets (1 .. DB_Len) := [others => 0];
                  Mask    : Octets (1 .. DB_Len);
               begin
                  --  DB = PS (zeros) || 01 || salt
                  DB (DB_Len - Salt'Length) := 16#01#;
                  if Salt_Length > 0 then
                     DB (DB_Len - Salt'Length + 1 .. DB_Len) := Salt;
                  end if;

                  MGF1 (Hash, H_Value, Mask);
                  for I in DB'Range loop
                     DB (I) := DB (I) xor Mask (I);
                  end loop;

                  --  Clear the leftmost spare bits, so EM stays below the
                  --  modulus. Without this the signature can exceed n and
                  --  RFC 8017's verifier refuses it.
                  if Spare > 0 then
                     DB (DB'First) :=
                       DB (DB'First)
                       and Ada.Streams.Stream_Element (2 ** (8 - Spare) - 1);
                  end if;

                  Block (1 .. DB_Len) := DB;
                  Block (DB_Len + 1 .. DB_Len + Offset (H_Len)) := H_Value;
                  Block (Block'Last) := 16#BC#;
               end;
            end;

            --  A modulus whose bit length is one more than a multiple of
            --  eight gives an EM one octet shorter than the modulus; the
            --  private operation wants a full-width block.
            declare
               Padded : Octets (1 .. Offset (K)) := [others => 0];
            begin
               Padded (Offset (K) - Block'Length + 1 .. Offset (K)) := Block;
               return Private_Operation
                 (Padded,
                  Modulus (N_First .. Modulus'Last),
                  Public_Exponent (E_First .. Public_Exponent'Last),
                  Private_Exponent (D_First .. Private_Exponent'Last),
                  Rng, Pair, Signature,
                  Prime_P, Prime_Q, Exponent_P, Exponent_Q, Coefficient);
            end;
         end;
      end;
   exception
      when others =>
         Signature := [others => 0];
         return CryptoLib.Errors.Internal_Error;
   end Sign_PSS;


   procedure Wipe (Pair : in out Blinding_Pair) is
   begin
      CryptoLib.Secure_Wipe.Wipe (Pair.Factor'Address, Pair.Factor'Length);
      CryptoLib.Secure_Wipe.Wipe (Pair.Inverse'Address, Pair.Inverse'Length);
      Pair.Width := 0;
      Pair.Ready := False;
   end Wipe;

   function Start_Blinding
     (Modulus         : Octets;
      Public_Exponent : Octets;
      Rng             : in out CryptoLib.Random.Random_Source;
      Pair            : out Blinding_Pair) return CryptoLib.Errors.Status
   is
      N_First : constant Offset := Value_First (Modulus);
      E_First : constant Offset := Value_First (Public_Exponent);
   begin
      Wipe (Pair);
      if N_First > Modulus'Last or else E_First > Public_Exponent'Last then
         return CryptoLib.Errors.Handshake_Failed;
      end if;
      if Modulus (Modulus'Last) mod 2 = 0 then
         return CryptoLib.Errors.Handshake_Failed;
      end if;
      if not Draw_Pair
               (Modulus (N_First .. Modulus'Last),
                Public_Exponent (E_First .. Public_Exponent'Last), Rng, Pair)
      then
         Wipe (Pair);
         return CryptoLib.Errors.Internal_Error;
      end if;
      return CryptoLib.Errors.Ok;
   end Start_Blinding;

   --  The forms without a pair: a throwaway pair per call, which is one
   --  inverse per signature and exactly what these did before pairs existed.
   function Sign_PKCS1_V1_5
     (Modulus          : Octets;
      Public_Exponent  : Octets;
      Private_Exponent : Octets;
      Hash             : Hash_Algorithm;
      Message          : Octets;
      Rng              : in out CryptoLib.Random.Random_Source;
      Signature        : out Octets;
      Prime_P          : Octets := [1 .. 0 => 0];
      Prime_Q          : Octets := [1 .. 0 => 0];
      Exponent_P       : Octets := [1 .. 0 => 0];
      Exponent_Q       : Octets := [1 .. 0 => 0];
      Coefficient      : Octets := [1 .. 0 => 0])
      return CryptoLib.Errors.Status
   is
      Once   : Blinding_Pair;
      Result : constant CryptoLib.Errors.Status :=
        Sign_PKCS1_V1_5
          (Modulus, Public_Exponent, Private_Exponent, Hash, Message, Rng,
           Once, Signature, Prime_P, Prime_Q, Exponent_P, Exponent_Q,
           Coefficient);
   begin
      Wipe (Once);
      return Result;
   end Sign_PKCS1_V1_5;

   function Sign_PSS
     (Modulus          : Octets;
      Public_Exponent  : Octets;
      Private_Exponent : Octets;
      Hash             : Hash_Algorithm;
      Salt_Length      : Natural;
      Message          : Octets;
      Rng              : in out CryptoLib.Random.Random_Source;
      Signature        : out Octets;
      Prime_P          : Octets := [1 .. 0 => 0];
      Prime_Q          : Octets := [1 .. 0 => 0];
      Exponent_P       : Octets := [1 .. 0 => 0];
      Exponent_Q       : Octets := [1 .. 0 => 0];
      Coefficient      : Octets := [1 .. 0 => 0])
      return CryptoLib.Errors.Status
   is
      Once   : Blinding_Pair;
      Result : constant CryptoLib.Errors.Status :=
        Sign_PSS
          (Modulus, Public_Exponent, Private_Exponent, Hash, Salt_Length,
           Message, Rng, Once, Signature, Prime_P, Prime_Q, Exponent_P,
           Exponent_Q, Coefficient);
   begin
      Wipe (Once);
      return Result;
   end Sign_PSS;

   function Modulus_Octets (Size : Modulus_Size) return Positive
   is (case Size is
          when RSA_2048 => 256,
          when RSA_3072 => 384,
          when RSA_4096 => 512);

   --  Enough small primes to strike most composites before any
   --  exponentiation. Each one removed here is a Miller-Rabin round not run.
   Small_Primes : constant array (Positive range <>) of Positive :=
     [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
      71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
      149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
      227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
      307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383,
      389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
      467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569,
      571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647,
      653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743,
      751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839,
      853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
      947, 953, 967, 971, 977, 983, 991, 997];

   --  Miller-Rabin rounds. The candidates here are random rather than
   --  adversarial, where a handful of rounds already puts the error far below
   --  anything that matters; this is generous because key generation happens
   --  once and the cost is not the operation anyone waits on.
   Rabin_Rounds : constant := 24;

   --  Is this odd candidate probably prime?
   function Probably_Prime
     (Candidate : Octets;
      Rng       : in out CryptoLib.Random.Random_Source) return Boolean
   is
      use type CryptoLib.Errors.Status;
      package BN renames CryptoLib.Bignum;

      N_Minus_1 : constant Octets := BN.Subtract_Small (Candidate, 1);
      Odd_Part  : Octets := N_Minus_1;
      Twos      : Natural := 0;
      One       : constant Octets := [1 => 1];
   begin
      for P of Small_Primes loop
         if BN.Mod_Small (Candidate, P) = 0 then
            --  Divisible by a small prime, and not that prime itself: every
            --  candidate here is far larger than the table.
            return False;
         end if;
      end loop;

      --  n - 1 = Odd_Part * 2**Twos
      loop
         exit when (Odd_Part (Odd_Part'Last) and 1) = 1;
         declare
            Halved    : Octets (Odd_Part'Range);
            Remainder : Natural;
         begin
            BN.Divide_Small (Odd_Part, 2, Halved, Remainder);
            Odd_Part := Halved;
            Twos := Twos + 1;
         end;
      end loop;

      for Round in 1 .. Rabin_Rounds loop
         declare
            Base : Octets (Candidate'Range);
            X    : Octets (Candidate'Range);
         begin
            if CryptoLib.Random.Fill (Rng, Base) /= CryptoLib.Errors.Ok then
               return False;
            end if;
            --  Bring the base below n. The candidate's top two bits are set,
            --  so a draw of the same width needs at most one subtraction.
            if BN.Compare (Base, Candidate) >= 0 then
               Base := BN.Subtract (Base, Candidate);
            end if;
            if BN.Compare (Base, One) <= 0 then
               Base := [others => 0];
               Base (Base'Last) := 2;
            end if;

            X := CryptoLib.Modexp.Mod_Exp (Base, Odd_Part, Candidate);
            if BN.Compare (X, One) /= 0
              and then BN.Compare (X, N_Minus_1) /= 0
            then
               declare
                  Witnessed : Boolean := True;
                  Square    : constant Octets := [1 => 2];
               begin
                  for Step in 1 .. Twos - 1 loop
                     X := CryptoLib.Modexp.Mod_Exp (X, Square, Candidate);
                     if BN.Compare (X, N_Minus_1) = 0 then
                        Witnessed := False;
                        exit;
                     end if;
                  end loop;
                  if Witnessed then
                     return False;
                  end if;
               end;
            end if;
         end;
      end loop;
      return True;
   end Probably_Prime;

   --  Draw a prime of the given width, with the top two bits set so the
   --  product of two of them has exactly twice the width.
   function Draw_Prime
     (Width : Offset;
      Rng   : in out CryptoLib.Random.Random_Source;
      Value : out Octets) return Boolean
   is
      use type CryptoLib.Errors.Status;
      package BN renames CryptoLib.Bignum;
      Attempts : constant := 20_000;
   begin
      Value := [others => 0];
      for Attempt in 1 .. Attempts loop
         if CryptoLib.Random.Fill (Rng, Value) /= CryptoLib.Errors.Ok then
            Value := [others => 0];
            return False;
         end if;
         Value (Value'First) := Value (Value'First) or 16#C0#;
         Value (Value'Last) := Value (Value'Last) or 1;

         --  e must be coprime to p - 1, or no private exponent exists.
         if BN.Mod_Small (BN.Subtract_Small (Value, 1),
                          Generated_Public_Exponent) /= 0
           and then Probably_Prime (Value, Rng)
         then
            return True;
         end if;
      end loop;
      Value := [others => 0];
      return False;
   end Draw_Prime;

   --  The private exponent is the inverse of the public one modulo Phi.
   function Inverse_Of_E (Phi : Octets; D : out Octets) return Boolean is
      Ok : Boolean;
   begin
      CryptoLib.Bignum.Mod_Inverse_Small
        (Generated_Public_Exponent, Phi, D, Ok);
      return Ok;
   end Inverse_Of_E;

   --  One body. Generate_Keypair below throws the primes away rather than
   --  running a second, near-identical generator that could drift from this
   --  one.
   function Generate_Keypair_With_Primes
     (Size             : Modulus_Size;
      Rng              : in out CryptoLib.Random.Random_Source;
      Modulus          : out Octets;
      Public_Exponent  : out Octets;
      Private_Exponent : out Octets;
      Prime_P          : out Octets;
      Prime_Q          : out Octets;
      Exponent_P       : out Octets;
      Exponent_Q       : out Octets;
      Coefficient      : out Octets) return CryptoLib.Errors.Status
   is
      package BN renames CryptoLib.Bignum;
      use type CryptoLib.Errors.Status;

      K        : constant Natural := Modulus_Octets (Size);
      Half     : constant Offset := Offset (K) / 2;
      Attempts : constant := 200;
   begin
      Modulus := [others => 0];
      Public_Exponent := [others => 0];
      Private_Exponent := [others => 0];
      Prime_P := [others => 0];
      Prime_Q := [others => 0];
      Exponent_P := [others => 0];
      Exponent_Q := [others => 0];
      Coefficient := [others => 0];

      if Natural (Modulus'Length) /= K
        or else Natural (Private_Exponent'Length) /= K
        or else Public_Exponent'Length /= 3
        or else Prime_P'Length /= Half
        or else Prime_Q'Length /= Half
        or else Exponent_P'Length /= Half
        or else Exponent_Q'Length /= Half
        or else Coefficient'Length /= Half
      then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      for Attempt in 1 .. Attempts loop
         declare
            P, Q : Octets (1 .. Half) := [others => 0];

            procedure Scrub_Primes is
            begin
               CryptoLib.Secure_Wipe.Wipe (P'Address, P'Length);
               CryptoLib.Secure_Wipe.Wipe (Q'Address, Q'Length);
            end Scrub_Primes;
         begin
            if not Draw_Prime (Half, Rng, P)
              or else not Draw_Prime (Half, Rng, Q)
            then
               Scrub_Primes;
               return CryptoLib.Errors.Internal_Error;
            end if;

            --  Primes too close together are found by Fermat's method in
            --  moments. With both top bits set they never should be; checked
            --  rather than assumed.
            declare
               Difference : constant Octets :=
                 (if BN.Compare (P, Q) >= 0
                  then BN.Subtract (P, Q) else BN.Subtract (Q, P));
            begin
               if BN.Bit_Length (Difference)
                 < Natural (Half) * 8 - 100
               then
                  Scrub_Primes;
                  goto Continue;
               end if;
            end;

            declare
               N   : constant Octets := BN.Multiply (P, Q);
               Phi : constant Octets :=
                 BN.Multiply (BN.Subtract_Small (P, 1),
                              BN.Subtract_Small (Q, 1));
               D    : Octets (1 .. Offset (K)) := [others => 0];
               Fits : Boolean;

               procedure Scrub_All is
               begin
                  CryptoLib.Secure_Wipe.Wipe (D'Address, D'Length);
                  Scrub_Primes;
               end Scrub_All;
            begin
               if BN.Bit_Length (N) /= K * 8 then
                  Scrub_All;
                  goto Continue;
               end if;
               if not Inverse_Of_E (Phi, D) then
                  Scrub_All;
                  goto Continue;
               end if;
               --  A private exponent below the square root of the modulus is
               --  recoverable by Wiener's continued-fraction attack.
               if BN.Bit_Length (D) <= Natural (Half) * 8 then
                  Scrub_All;
                  goto Continue;
               end if;

               BN.Resize (N, Modulus'Length, Modulus, Fits);
               if not Fits then
                  Scrub_All;
                  goto Continue;
               end if;

               --  The CRT parameters, from inverses rather than divisions:
               --  e*dp = 1 mod (p-1) makes dp the same value as d mod (p-1),
               --  and the coefficient is q inverse mod p, which the binary
               --  extended Euclid gives since p is odd.
               declare
                  P_Minus : constant Octets := BN.Subtract_Small (P, 1);
                  Q_Minus : constant Octets := BN.Subtract_Small (Q, 1);
                  DP, DQ, QI : Octets (1 .. Half) := [others => 0];
                  Fine : Boolean;
               begin
                  CryptoLib.Bignum.Mod_Inverse_Small
                    (Generated_Public_Exponent, P_Minus, DP, Fine);
                  if not Fine then
                     Scrub_All;
                     goto Continue;
                  end if;
                  CryptoLib.Bignum.Mod_Inverse_Small
                    (Generated_Public_Exponent, Q_Minus, DQ, Fine);
                  if not Fine then
                     Scrub_All;
                     goto Continue;
                  end if;
                  CryptoLib.Bignum.Mod_Inverse (Q, P, QI, Fine);
                  if not Fine then
                     Scrub_All;
                     goto Continue;
                  end if;
                  Exponent_P := DP;
                  Exponent_Q := DQ;
                  Coefficient := QI;
               end;

               Prime_P := P;
               Prime_Q := Q;
               Private_Exponent := D;
               Public_Exponent := [16#01#, 16#00#, 16#01#];
               Scrub_All;

               --  The key has to work. Signing and verifying once here costs
               --  one key generation and catches a modulus, exponent or
               --  inverse that is subtly wrong -- which a caller would
               --  otherwise discover as a signature nobody accepts.
               declare
                  Probe : constant Octets := [1 .. 8 => 16#5A#];
                  Sig   : Octets (1 .. Offset (K));
               begin
                  if Sign_PKCS1_V1_5
                       (Modulus, Public_Exponent, Private_Exponent,
                        SHA256, Probe, Rng, Sig) /= CryptoLib.Errors.Ok
                    or else Verify_PKCS1_V1_5
                       (Modulus, Public_Exponent, SHA256, Probe, Sig)
                         /= CryptoLib.Errors.Ok
                  then
                     Modulus := [others => 0];
                     Public_Exponent := [others => 0];
                     CryptoLib.Secure_Wipe.Wipe
                       (Private_Exponent'Address, Private_Exponent'Length);
                     Private_Exponent := [others => 0];
                     Prime_P := [others => 0];
                     Prime_Q := [others => 0];
                     Exponent_P := [others => 0];
                     Exponent_Q := [others => 0];
                     Coefficient := [others => 0];
                     goto Continue;
                  end if;
               end;
               return CryptoLib.Errors.Ok;
            end;
         end;
         <<Continue>>
      end loop;

      Modulus := [others => 0];
      Public_Exponent := [others => 0];
      Private_Exponent := [others => 0];
      Prime_P := [others => 0];
      Prime_Q := [others => 0];
      return CryptoLib.Errors.Internal_Error;
   exception
      when others =>
         Modulus := [others => 0];
         Public_Exponent := [others => 0];
         CryptoLib.Secure_Wipe.Wipe
           (Private_Exponent'Address, Private_Exponent'Length);
         Private_Exponent := [others => 0];
         CryptoLib.Secure_Wipe.Wipe (Prime_P'Address, Prime_P'Length);
         CryptoLib.Secure_Wipe.Wipe (Prime_Q'Address, Prime_Q'Length);
         Prime_P := [others => 0];
         Prime_Q := [others => 0];
         Exponent_P := [others => 0];
         Exponent_Q := [others => 0];
         Coefficient := [others => 0];
         return CryptoLib.Errors.Internal_Error;
   end Generate_Keypair_With_Primes;

   function Generate_Keypair
     (Size             : Modulus_Size;
      Rng              : in out CryptoLib.Random.Random_Source;
      Modulus          : out Octets;
      Public_Exponent  : out Octets;
      Private_Exponent : out Octets) return CryptoLib.Errors.Status
   is
      Half : constant Offset := Offset (Modulus_Octets (Size)) / 2;
      P, Q, DP, DQ, QI : Octets (1 .. Half) := [others => 0];
      Result : CryptoLib.Errors.Status;

      procedure Scrub is
      begin
         CryptoLib.Secure_Wipe.Wipe (P'Address, P'Length);
         CryptoLib.Secure_Wipe.Wipe (Q'Address, Q'Length);
         CryptoLib.Secure_Wipe.Wipe (DP'Address, DP'Length);
         CryptoLib.Secure_Wipe.Wipe (DQ'Address, DQ'Length);
         CryptoLib.Secure_Wipe.Wipe (QI'Address, QI'Length);
      end Scrub;
   begin
      Result := Generate_Keypair_With_Primes
        (Size, Rng, Modulus, Public_Exponent, Private_Exponent,
         P, Q, DP, DQ, QI);
      --  The primes and CRT parameters are wiped rather than returned: a
      --  caller of this face asked for what signing needs.
      Scrub;
      return Result;
   end Generate_Keypair;

end CryptoLib.RSA;
