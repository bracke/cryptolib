with Ada.Containers.Generic_Array_Sort;
with Ada.Unchecked_Conversion;
with Interfaces;
with System;
with CryptoLib.Hashes;
with CryptoLib.Secure_Wipe;

--  Streamlined NTRU Prime 761 (sntrup761), a faithful port of the reference
--  implementation (as bundled in OpenSSH's sntrup761.c).  R = Z[x]/(x^761-x-1),
--  q = 4591, w = 286.  Coefficients are kept in signed Integer; freezes reduce
--  to the centred representatives {-1,0,1} (mod 3) and [-q12, q12] (mod q).

package body CryptoLib.SNTRUP761 is

   use Ada.Streams;
   use Interfaces;
   use type CryptoLib.Errors.Status;

   P_Value    : constant := 761;
   Q_Value    : constant := 4591;
   W_Value    : constant := 286;
   Q12        : constant := (Q_Value - 1) / 2;         --  2295
   Small_Bytes : constant := (P_Value + 3) / 4;        --  191
   Secret_Keys_Bytes : constant := 2 * Small_Bytes;    --  382
   Rounded_Bytes : constant := 1007;                   --  Rq/3 encoded length
   Hash_Bytes  : constant := 32;
   Confirm_Bytes : constant := 32;

   subtype Coeff_Index is Natural range 0 .. P_Value - 1;
   type Coeff_Array is array (Coeff_Index) of Integer;   --  Fq or small poly
   subtype Ext_Index is Natural range 0 .. P_Value;
   type Ext_Array is array (Ext_Index) of Integer;       --  recip work arrays

   type Int_Array is array (Natural range <>) of Integer;
   type U16_Array is array (Natural range <>) of Unsigned_16;
   type U32_Array is array (Natural range <>) of Unsigned_32;

   --  Zeroize secret stack material without the store being optimized away.
   procedure Wipe (Item : in out Coeff_Array) is
   begin
      CryptoLib.Secure_Wipe.Wipe
        (Item'Address, Item'Size / System.Storage_Unit);
   end Wipe;

   procedure Wipe (Item : in out Ext_Array) is
   begin
      CryptoLib.Secure_Wipe.Wipe
        (Item'Address, Item'Size / System.Storage_Unit);
   end Wipe;

   ----------------------------------------------------------------------------
   --  Field reductions (centred representatives)
   ----------------------------------------------------------------------------

   --  The freezes reduce secret coefficients, so they must not use hardware
   --  integer division (variable latency on x86).  Port the reference's
   --  branchless Barrett multiply-shift.  Arithmetic shift right is done on a
   --  64-bit two's-complement reinterpretation (no data-dependent branch); the
   --  wide intermediate keeps every product well inside Integer_64.

   function I64_To_U64 is new
     Ada.Unchecked_Conversion (Integer_64, Unsigned_64);
   function U64_To_I64 is new
     Ada.Unchecked_Conversion (Unsigned_64, Integer_64);

   function ASR (X : Integer_64; N : Natural) return Integer_64 is
     (U64_To_I64 (Shift_Right_Arithmetic (I64_To_U64 (X), N)));

   function F3_Freeze (X : Integer) return Integer is
      Xi : constant Integer_64 := Integer_64 (X);
   begin
      return Integer (Xi - 3 * ASR (10923 * Xi + 16384, 15));
   end F3_Freeze;

   function Fq_Freeze (X : Integer) return Integer is
      Q16 : constant := (16#10000# + Q_Value / 2) / Q_Value;     --  14
      Q20 : constant := (16#100000# + Q_Value / 2) / Q_Value;    --  228
      Q28 : constant := (16#10000000# + Q_Value / 2) / Q_Value;  --  58470
      Xi  : Integer_64 := Integer_64 (X);
   begin
      Xi := Xi - Q_Value * ASR (Q16 * Xi, 16);
      Xi := Xi - Q_Value * ASR (Q20 * Xi, 20);
      return Integer (Xi - Q_Value * ASR (Q28 * Xi + 16#8000000#, 28));
   end Fq_Freeze;

   ----------------------------------------------------------------------------
   --  Ring arithmetic in R = Z[x]/(x^p - x - 1), so x^p = x + 1.
   ----------------------------------------------------------------------------

   procedure Fold (FG : in out Int_Array) is
   begin
      for I in P_Value .. 2 * P_Value - 2 loop
         FG (I - P_Value) := FG (I - P_Value) + FG (I);
      end loop;
      for I in P_Value .. 2 * P_Value - 2 loop
         FG (I - P_Value + 1) := FG (I - P_Value + 1) + FG (I);
      end loop;
   end Fold;

   function Rq_Mult_Small (F : Coeff_Array; G : Coeff_Array) return Coeff_Array
   is
      FG : Int_Array (0 .. 2 * P_Value - 2) := [others => 0];
      H  : Coeff_Array;
   begin
      for I in Coeff_Index loop
         for J in Coeff_Index loop
            FG (I + J) := FG (I + J) + F (I) * G (J);
         end loop;
      end loop;
      Fold (FG);
      for I in Coeff_Index loop
         H (I) := Fq_Freeze (FG (I));
      end loop;
      return H;
   end Rq_Mult_Small;

   function Rq_Mult3 (F : Coeff_Array) return Coeff_Array is
      H : Coeff_Array;
   begin
      for I in Coeff_Index loop
         H (I) := Fq_Freeze (3 * F (I));
      end loop;
      return H;
   end Rq_Mult3;

   function R3_Mult (F : Coeff_Array; G : Coeff_Array) return Coeff_Array is
      FG : Int_Array (0 .. 2 * P_Value - 2) := [others => 0];
      H  : Coeff_Array;
   begin
      for I in Coeff_Index loop
         for J in Coeff_Index loop
            FG (I + J) := FG (I + J) + F (I) * G (J);
         end loop;
      end loop;
      Fold (FG);
      for I in Coeff_Index loop
         H (I) := F3_Freeze (FG (I));
      end loop;
      return H;
   end R3_Mult;

   function R3_From_Rq (R : Coeff_Array) return Coeff_Array is
      H : Coeff_Array;
   begin
      for I in Coeff_Index loop
         H (I) := F3_Freeze (R (I));
      end loop;
      return H;
   end R3_From_Rq;

   function Round_Poly (A : Coeff_Array) return Coeff_Array is
      H : Coeff_Array;
   begin
      for I in Coeff_Index loop
         H (I) := A (I) - F3_Freeze (A (I));
      end loop;
      return H;
   end Round_Poly;

   --  0 when the weight is exactly w, all-ones (-1) otherwise.
   function Weightw_Mask (R : Coeff_Array) return Integer is
      Weight : Natural := 0;
   begin
      for I in Coeff_Index loop
         if R (I) /= 0 then
            Weight := Weight + 1;
         end if;
      end loop;
      return (if Weight = W_Value then 0 else -1);
   end Weightw_Mask;

   ----------------------------------------------------------------------------
   --  Reciprocals (constant-time divstep; port of the reference).
   ----------------------------------------------------------------------------

   --  Branchless divstep swap decision: 1 when Delta_V > 0 and G0 /= 0, else 0.
   --  The divstep operates on secret key material, so the swap must not branch.
   function Swap_Flag (Delta_V, G0 : Integer) return Integer is
      Delta_Pos  : constant Unsigned_32 :=
        Shift_Right (Unsigned_32'Mod (-Delta_V), 31);       --  1 iff Delta_V > 0
      G0_Word    : constant Unsigned_32 := Unsigned_32'Mod (G0);
      G0_Nonzero : constant Unsigned_32 :=
        Shift_Right (G0_Word or (Unsigned_32 (0) - G0_Word), 31);
   begin
      return Integer (Delta_Pos and G0_Nonzero);
   end Swap_Flag;

   function Fq_Recip (A1 : Integer) return Integer is
      Ai : Integer := A1;
   begin
      for I in 1 .. Q_Value - 3 loop
         Ai := Fq_Freeze (A1 * Ai);
      end loop;
      return Ai;                                        --  A1**(q-2) mod q
   end Fq_Recip;

   --  1/in in R3; Status_Value = 0 on success (in invertible).
   procedure R3_Recip
     (In_Poly : Coeff_Array; Out_Poly : out Coeff_Array;
      Status_Value : out Integer)
   is
      F : Ext_Array := [others => 0];
      G : Ext_Array := [others => 0];
      V : Ext_Array := [others => 0];
      R : Ext_Array := [others => 0];
      Delta_V : Integer := 1;
      Sign, Do_Swap : Integer;
   begin
      R (0) := 1;
      F (0) := 1; F (P_Value - 1) := -1; F (P_Value) := -1;
      for I in Coeff_Index loop
         G (P_Value - 1 - I) := In_Poly (I);
      end loop;
      for Loop_I in 0 .. 2 * P_Value - 2 loop
         for I in reverse 1 .. P_Value loop
            V (I) := V (I - 1);
         end loop;
         V (0) := 0;
         Sign := (-G (0)) * F (0);
         Do_Swap := Swap_Flag (Delta_V, G (0));
         Delta_V := Delta_V - 2 * Delta_V * Do_Swap + 1;   --  negate iff swap
         for I in Ext_Index loop
            declare
               D_FG : constant Integer := (F (I) - G (I)) * Do_Swap;
               D_VR : constant Integer := (V (I) - R (I)) * Do_Swap;
            begin
               F (I) := F (I) - D_FG; G (I) := G (I) + D_FG;
               V (I) := V (I) - D_VR; R (I) := R (I) + D_VR;
            end;
         end loop;
         for I in Ext_Index loop
            G (I) := F3_Freeze (G (I) + Sign * F (I));
         end loop;
         for I in Ext_Index loop
            R (I) := F3_Freeze (R (I) + Sign * V (I));
         end loop;
         for I in Coeff_Index loop
            G (I) := G (I + 1);
         end loop;
         G (P_Value) := 0;
      end loop;
      Sign := F (0);
      for I in Coeff_Index loop
         Out_Poly (I) := Sign * V (P_Value - 1 - I);
      end loop;
      Status_Value := (if Delta_V = 0 then 0 else -1);
      Wipe (F); Wipe (G); Wipe (V); Wipe (R);
   end R3_Recip;

   --  1/(3*in) in Rq.
   procedure Rq_Recip3
     (In_Poly : Coeff_Array; Out_Poly : out Coeff_Array;
      Status_Value : out Integer)
   is
      F : Ext_Array := [others => 0];
      G : Ext_Array := [others => 0];
      V : Ext_Array := [others => 0];
      R : Ext_Array := [others => 0];
      Delta_V : Integer := 1;
      F0, G0, Scale, Do_Swap : Integer;
   begin
      R (0) := Fq_Recip (3);
      F (0) := 1; F (P_Value - 1) := -1; F (P_Value) := -1;
      for I in Coeff_Index loop
         G (P_Value - 1 - I) := In_Poly (I);
      end loop;
      for Loop_I in 0 .. 2 * P_Value - 2 loop
         for I in reverse 1 .. P_Value loop
            V (I) := V (I - 1);
         end loop;
         V (0) := 0;
         Do_Swap := Swap_Flag (Delta_V, G (0));
         Delta_V := Delta_V - 2 * Delta_V * Do_Swap + 1;   --  negate iff swap
         for I in Ext_Index loop
            declare
               D_FG : constant Integer := (F (I) - G (I)) * Do_Swap;
               D_VR : constant Integer := (V (I) - R (I)) * Do_Swap;
            begin
               F (I) := F (I) - D_FG; G (I) := G (I) + D_FG;
               V (I) := V (I) - D_VR; R (I) := R (I) + D_VR;
            end;
         end loop;
         F0 := F (0);
         G0 := G (0);
         for I in Ext_Index loop
            G (I) := Fq_Freeze (F0 * G (I) - G0 * F (I));
         end loop;
         for I in Ext_Index loop
            R (I) := Fq_Freeze (F0 * R (I) - G0 * V (I));
         end loop;
         for I in Coeff_Index loop
            G (I) := G (I + 1);
         end loop;
         G (P_Value) := 0;
      end loop;
      Scale := Fq_Recip (F (0));
      for I in Coeff_Index loop
         Out_Poly (I) := Fq_Freeze (Scale * V (P_Value - 1 - I));
      end loop;
      Status_Value := (if Delta_V = 0 then 0 else -1);
      Wipe (F); Wipe (G); Wipe (V); Wipe (R);
   end Rq_Recip3;

   ----------------------------------------------------------------------------
   --  Radix Encode/Decode (Bernstein's recursive coder).
   ----------------------------------------------------------------------------

   procedure U32_Divmod
     (Q_Out : out Unsigned_32; R_Out : out Unsigned_16;
      X : Unsigned_32; M : Unsigned_16)
   is
      V  : constant Unsigned_32 := 16#80000000# / Unsigned_32 (M);
      Xv : Unsigned_32 := X;
      Qp : Unsigned_32;
      Qr : Unsigned_32;
   begin
      Qp := Unsigned_32 (Shift_Right (Unsigned_64 (Xv) * Unsigned_64 (V), 31));
      Xv := Xv - Qp * Unsigned_32 (M);
      Qr := Qp;
      Qp := Unsigned_32 (Shift_Right (Unsigned_64 (Xv) * Unsigned_64 (V), 31));
      Xv := Xv - Qp * Unsigned_32 (M);
      Qr := Qr + Qp;
      Xv := Xv - Unsigned_32 (M);
      Qr := Qr + 1;
      if (Xv and 16#80000000#) /= 0 then                --  negative -> mask
         Xv := Xv + Unsigned_32 (M);
         Qr := Qr - 1;
      end if;
      Q_Out := Qr;
      R_Out := Unsigned_16 (Xv and 16#FFFF#);
   end U32_Divmod;

   function U32_Mod (X : Unsigned_32; M : Unsigned_16) return Unsigned_16 is
      Q_Out : Unsigned_32;
      R_Out : Unsigned_16;
   begin
      U32_Divmod (Q_Out, R_Out, X, M);
      return R_Out;
   end U32_Mod;

   procedure Encode
     (Out_Buf : in out Stream_Element_Array;
      Cursor  : in out Stream_Element_Offset;
      R : U16_Array; M : U16_Array)
   is
   begin
      if R'Length = 1 then
         declare
            Rr : Unsigned_16 := R (R'First);
            Mm : Unsigned_16 := M (M'First);
         begin
            while Mm > 1 loop
               Out_Buf (Cursor) := Stream_Element (Rr and 16#FF#);
               Cursor := Cursor + 1;
               Rr := Shift_Right (Rr, 8);
               Mm := Shift_Right (Mm + 255, 8);
            end loop;
         end;
      elsif R'Length > 1 then
         declare
            Len  : constant Natural := R'Length;
            Half : constant Natural := (Len + 1) / 2;
            R2   : U16_Array (0 .. Half - 1) := [others => 0];
            M2   : U16_Array (0 .. Half - 1) := [others => 0];
            I    : Natural := 0;
         begin
            while I < Len - 1 loop
               declare
                  M0 : constant Unsigned_32 := Unsigned_32 (M (M'First + I));
                  Rr : Unsigned_32 :=
                    Unsigned_32 (R (R'First + I))
                    + Unsigned_32 (R (R'First + I + 1)) * M0;
                  Mm : Unsigned_32 := Unsigned_32 (M (M'First + I + 1)) * M0;
               begin
                  while Mm >= 16384 loop
                     Out_Buf (Cursor) := Stream_Element (Rr and 16#FF#);
                     Cursor := Cursor + 1;
                     Rr := Shift_Right (Rr, 8);
                     Mm := Shift_Right (Mm + 255, 8);
                  end loop;
                  R2 (I / 2) := Unsigned_16 (Rr and 16#FFFF#);
                  M2 (I / 2) := Unsigned_16 (Mm and 16#FFFF#);
               end;
               I := I + 2;
            end loop;
            if I < Len then
               R2 (I / 2) := R (R'First + I);
               M2 (I / 2) := M (M'First + I);
            end if;
            Encode (Out_Buf, Cursor, R2, M2);
         end;
      end if;
   end Encode;

   procedure Decode
     (Out_R  : out U16_Array;
      S      : Stream_Element_Array;
      Cursor : in out Stream_Element_Offset;
      M      : U16_Array)
   is
   begin
      if M'Length = 1 then
         declare
            M0 : constant Unsigned_16 := M (M'First);
         begin
            if M0 = 1 then
               Out_R (Out_R'First) := 0;
            elsif M0 <= 256 then
               Out_R (Out_R'First) := U32_Mod (Unsigned_32 (S (Cursor)), M0);
               Cursor := Cursor + 1;
            else
               Out_R (Out_R'First) :=
                 U32_Mod (Unsigned_32 (S (Cursor))
                          + Shift_Left (Unsigned_32 (S (Cursor + 1)), 8), M0);
               Cursor := Cursor + 2;
            end if;
         end;
      elsif M'Length > 1 then
         declare
            Len  : constant Natural := M'Length;
            Half : constant Natural := (Len + 1) / 2;
            R2   : U16_Array (0 .. Half - 1);
            M2   : U16_Array (0 .. Half - 1) := [others => 0];
            Bottom_R : U32_Array (0 .. Len / 2 - 1) := [others => 0];
            Bottom_T : U32_Array (0 .. Len / 2 - 1) := [others => 0];
            I : Natural := 0;
         begin
            while I < Len - 1 loop
               declare
                  Mm : constant Unsigned_32 :=
                    Unsigned_32 (M (M'First + I))
                    * Unsigned_32 (M (M'First + I + 1));
               begin
                  if Mm > 256 * 16383 then
                     Bottom_T (I / 2) := 256 * 256;
                     Bottom_R (I / 2) :=
                       Unsigned_32 (S (Cursor))
                       + 256 * Unsigned_32 (S (Cursor + 1));
                     Cursor := Cursor + 2;
                     M2 (I / 2) :=
                       Unsigned_16
                         (Shift_Right (Shift_Right (Mm + 255, 8) + 255, 8)
                          and 16#FFFF#);
                  elsif Mm >= 16384 then
                     Bottom_T (I / 2) := 256;
                     Bottom_R (I / 2) := Unsigned_32 (S (Cursor));
                     Cursor := Cursor + 1;
                     M2 (I / 2) :=
                       Unsigned_16 (Shift_Right (Mm + 255, 8) and 16#FFFF#);
                  else
                     Bottom_T (I / 2) := 1;
                     Bottom_R (I / 2) := 0;
                     M2 (I / 2) := Unsigned_16 (Mm and 16#FFFF#);
                  end if;
               end;
               I := I + 2;
            end loop;
            if I < Len then
               M2 (I / 2) := M (M'First + I);
            end if;
            Decode (R2, S, Cursor, M2);
            I := 0;
            while I < Len - 1 loop
               declare
                  Rr : constant Unsigned_32 :=
                    Bottom_R (I / 2)
                    + Bottom_T (I / 2) * Unsigned_32 (R2 (I / 2));
                  R1 : Unsigned_32;
                  R0 : Unsigned_16;
               begin
                  U32_Divmod (R1, R0, Rr, M (M'First + I));
                  R1 := Unsigned_32 (U32_Mod (R1, M (M'First + I + 1)));
                  Out_R (Out_R'First + I) := R0;
                  Out_R (Out_R'First + I + 1) := Unsigned_16 (R1 and 16#FFFF#);
               end;
               I := I + 2;
            end loop;
            if I < Len then
               Out_R (Out_R'First + I) := R2 (I / 2);
            end if;
         end;
      end if;
   end Decode;

   ----------------------------------------------------------------------------
   --  Poly <-> bytes encoders.
   ----------------------------------------------------------------------------

   procedure Rq_Encode (S : out Stream_Element_Array; R : Coeff_Array) is
      RR  : U16_Array (0 .. P_Value - 1);
      MM  : constant U16_Array (0 .. P_Value - 1) := [others => Q_Value];
      Cur : Stream_Element_Offset := S'First;
   begin
      for I in Coeff_Index loop
         RR (I) := Unsigned_16 (R (I) + Q12);
      end loop;
      Encode (S, Cur, RR, MM);
   end Rq_Encode;

   function Rq_Decode (S : Stream_Element_Array) return Coeff_Array is
      RR  : U16_Array (0 .. P_Value - 1);
      MM  : constant U16_Array (0 .. P_Value - 1) := [others => Q_Value];
      Cur : Stream_Element_Offset := S'First;
      R   : Coeff_Array;
   begin
      Decode (RR, S, Cur, MM);
      for I in Coeff_Index loop
         R (I) := Integer (RR (I)) - Q12;
      end loop;
      return R;
   end Rq_Decode;

   procedure Rounded_Encode (S : out Stream_Element_Array; R : Coeff_Array) is
      RR  : U16_Array (0 .. P_Value - 1);
      MM  : constant U16_Array (0 .. P_Value - 1) :=
        [others => (Q_Value + 2) / 3];
      Cur : Stream_Element_Offset := S'First;
   begin
      for I in Coeff_Index loop
         RR (I) :=
           Unsigned_16
             (Shift_Right (Unsigned_32 (R (I) + Q12) * 10923, 15) and 16#FFFF#);
      end loop;
      Encode (S, Cur, RR, MM);
   end Rounded_Encode;

   function Rounded_Decode (S : Stream_Element_Array) return Coeff_Array is
      RR  : U16_Array (0 .. P_Value - 1);
      MM  : constant U16_Array (0 .. P_Value - 1) :=
        [others => (Q_Value + 2) / 3];
      Cur : Stream_Element_Offset := S'First;
      R   : Coeff_Array;
   begin
      Decode (RR, S, Cur, MM);
      for I in Coeff_Index loop
         R (I) := Integer (RR (I)) * 3 - Q12;
      end loop;
      return R;
   end Rounded_Decode;

   procedure Small_Encode (S : out Stream_Element_Array; F : Coeff_Array) is
      Cur : Stream_Element_Offset := S'First;
      Idx : Natural := 0;
   begin
      for I in 0 .. P_Value / 4 - 1 loop
         declare
            X : Integer := 0;
         begin
            for J in 0 .. 3 loop
               X := X + (F (Idx) + 1) * (2 ** (2 * J));
               Idx := Idx + 1;
            end loop;
            S (Cur) := Stream_Element (X mod 256);
            Cur := Cur + 1;
         end;
      end loop;
      S (Cur) := Stream_Element ((F (Idx) + 1) mod 256);
   end Small_Encode;

   function Small_Decode (S : Stream_Element_Array) return Coeff_Array is
      Cur : Stream_Element_Offset := S'First;
      Idx : Natural := 0;
      F   : Coeff_Array;
   begin
      for I in 0 .. P_Value / 4 - 1 loop
         declare
            X : constant Integer := Integer (S (Cur));
         begin
            Cur := Cur + 1;
            for J in 0 .. 3 loop
               F (Idx) := ((X / (2 ** (2 * J))) mod 4) - 1;
               Idx := Idx + 1;
            end loop;
         end;
      end loop;
      F (Idx) := (Integer (S (Cur)) mod 4) - 1;
      return F;
   end Small_Decode;

   ----------------------------------------------------------------------------
   --  Hashing (SHA-512 with a domain-separation prefix byte).
   ----------------------------------------------------------------------------

   subtype Hash_Out is Stream_Element_Array (1 .. Hash_Bytes);

   function Hash_Prefix
     (B : Stream_Element; In_Data : Stream_Element_Array) return Hash_Out
   is
      X  : Stream_Element_Array (0 .. In_Data'Length);
      Dg : CryptoLib.Hashes.SHA512_Digest;
      R  : Hash_Out;
   begin
      X (0) := B;
      for I in 0 .. In_Data'Length - 1 loop
         X (Stream_Element_Offset (I + 1)) :=
           In_Data (In_Data'First + Stream_Element_Offset (I));
      end loop;
      Dg := CryptoLib.Hashes.SHA512 (X);
      for I in 1 .. Hash_Bytes loop
         R (Stream_Element_Offset (I)) := Dg (I);
      end loop;
      return R;
   end Hash_Prefix;

   function Hash_Confirm
     (R_Enc : Stream_Element_Array; Cache : Hash_Out) return Hash_Out
   is
      X : Stream_Element_Array (0 .. 2 * Hash_Bytes - 1);
      H : constant Hash_Out := Hash_Prefix (3, R_Enc);
   begin
      for I in 0 .. Hash_Bytes - 1 loop
         X (Stream_Element_Offset (I)) :=
           H (H'First + Stream_Element_Offset (I));
         X (Stream_Element_Offset (Hash_Bytes + I)) :=
           Cache (Cache'First + Stream_Element_Offset (I));
      end loop;
      return Hash_Prefix (2, X);
   end Hash_Confirm;

   function Hash_Session
     (B : Stream_Element; R_Enc : Stream_Element_Array;
      C : Stream_Element_Array) return Shared_Key
   is
      X : Stream_Element_Array
        (0 .. Stream_Element_Offset (Hash_Bytes + Ciphertext_Length - 1));
      H : constant Hash_Out := Hash_Prefix (3, R_Enc);
      Result : Shared_Key;
   begin
      for I in 0 .. Hash_Bytes - 1 loop
         X (Stream_Element_Offset (I)) :=
           H (H'First + Stream_Element_Offset (I));
      end loop;
      for I in 0 .. Ciphertext_Length - 1 loop
         X (Stream_Element_Offset (Hash_Bytes + I)) :=
           C (C'First + Stream_Element_Offset (I));
      end loop;
      declare
         Full : constant Hash_Out := Hash_Prefix (B, X);
      begin
         for I in 1 .. Shared_Key_Length loop
            Result (Result'First + Stream_Element_Offset (I - 1)) :=
              Full (Full'First + Stream_Element_Offset (I - 1));
         end loop;
      end;
      return Result;
   end Hash_Session;

   ----------------------------------------------------------------------------
   --  Random small / short (weight-w) polynomials.
   ----------------------------------------------------------------------------

   procedure Sort_U32 is new Ada.Containers.Generic_Array_Sort
     (Index_Type => Natural, Element_Type => Unsigned_32,
      Array_Type => U32_Array, "<" => "<");

   function Draw_U32
     (Source : in out CryptoLib.Random.Random_Source; Ok : in out Boolean)
      return Unsigned_32
   is
      B : Stream_Element_Array (1 .. 4);
   begin
      if CryptoLib.Random.Fill (Source, B) /= CryptoLib.Errors.Ok then
         Ok := False;
         return 0;
      end if;
      return Unsigned_32 (B (1))
        or Shift_Left (Unsigned_32 (B (2)), 8)
        or Shift_Left (Unsigned_32 (B (3)), 16)
        or Shift_Left (Unsigned_32 (B (4)), 24);
   end Draw_U32;

   procedure Small_Random
     (Source : in out CryptoLib.Random.Random_Source;
      Out_Poly : out Coeff_Array; Ok : in out Boolean)
   is
      L : Unsigned_32;
   begin
      for I in Coeff_Index loop
         L := Draw_U32 (Source, Ok);
         Out_Poly (I) :=
           Integer (Shift_Right ((L and 16#3FFFFFFF#) * 3, 30)) - 1;
      end loop;
   end Small_Random;

   procedure Short_Random
     (Source : in out CryptoLib.Random.Random_Source;
      Out_Poly : out Coeff_Array; Ok : in out Boolean)
   is
      L : U32_Array (Coeff_Index);
   begin
      for I in Coeff_Index loop
         L (I) := Draw_U32 (Source, Ok);
      end loop;
      for I in 0 .. W_Value - 1 loop
         L (I) := L (I) and 16#FFFFFFFE#;                --  even -> nonzero
      end loop;
      for I in W_Value .. P_Value - 1 loop
         L (I) := (L (I) and 16#FFFFFFFD#) or 1;         --  low bits 01 -> zero
      end loop;
      Sort_U32 (L);
      for I in Coeff_Index loop
         Out_Poly (I) := Integer (L (I) and 3) - 1;
      end loop;
   end Short_Random;

   ----------------------------------------------------------------------------
   --  KEM operations
   ----------------------------------------------------------------------------

   procedure Clear (Item : out Secret_Key) is
   begin
      Item := [others => 0];
   end Clear;

   --  Build the ciphertext (rounded encryption + confirm hash) and r_enc from r.
   procedure Hide
     (C : out Ciphertext; R_Enc : out Stream_Element_Array;
      R : Coeff_Array; H : Coeff_Array; Cache : Hash_Out)
   is
      Enc     : constant Coeff_Array := Round_Poly (Rq_Mult_Small (H, R));
      Rounded : Stream_Element_Array (1 .. Rounded_Bytes);
      Confirm : Hash_Out;
   begin
      Small_Encode (R_Enc, R);
      Rounded_Encode (Rounded, Enc);
      Confirm := Hash_Confirm (R_Enc, Cache);
      for I in 0 .. Rounded_Bytes - 1 loop
         C (C'First + Stream_Element_Offset (I)) :=
           Rounded (Rounded'First + Stream_Element_Offset (I));
      end loop;
      for I in 0 .. Confirm_Bytes - 1 loop
         C (C'First + Stream_Element_Offset (Rounded_Bytes + I)) :=
           Confirm (Confirm'First + Stream_Element_Offset (I));
      end loop;
   end Hide;

   function Generate_Keypair
     (Source_Item : in out CryptoLib.Random.Random_Source;
      Public_Item : out Public_Key;
      Secret_Item : out Secret_Key)
      return CryptoLib.Errors.Status
   is
      G, Ginv, F, Finv, H : Coeff_Array;
      Recip_Status : Integer;
      Ok  : Boolean := True;
      Cur : Stream_Element_Offset;
      Rho : Stream_Element_Array (1 .. Small_Bytes);
   begin
      Public_Item := [others => 0];
      Secret_Item := [others => 0];

      loop
         Small_Random (Source_Item, G, Ok);
         if not Ok then
            return CryptoLib.Errors.Internal_Error;
         end if;
         R3_Recip (G, Ginv, Recip_Status);
         exit when Recip_Status = 0;
      end loop;

      Short_Random (Source_Item, F, Ok);
      if not Ok then
         return CryptoLib.Errors.Internal_Error;
      end if;
      Rq_Recip3 (F, Finv, Recip_Status);                 --  finv = 1/(3f)
      H := Rq_Mult_Small (Finv, G);                       --  h = g/(3f)

      Rq_Encode (Public_Item, H);
      declare
         SK_F    : Stream_Element_Array (1 .. Small_Bytes);
         SK_Ginv : Stream_Element_Array (1 .. Small_Bytes);
         Cache   : Hash_Out;
      begin
         Small_Encode (SK_F, F);
         Small_Encode (SK_Ginv, Ginv);
         if CryptoLib.Random.Fill (Source_Item, Rho) /= CryptoLib.Errors.Ok
         then
            return CryptoLib.Errors.Internal_Error;
         end if;
         Cache := Hash_Prefix (4, Public_Item);
         Cur := Secret_Item'First;
         for E of SK_F loop
            Secret_Item (Cur) := E; Cur := Cur + 1;
         end loop;
         for E of SK_Ginv loop
            Secret_Item (Cur) := E; Cur := Cur + 1;
         end loop;
         for E of Public_Item loop
            Secret_Item (Cur) := E; Cur := Cur + 1;
         end loop;
         for E of Rho loop
            Secret_Item (Cur) := E; Cur := Cur + 1;
         end loop;
         for E of Cache loop
            Secret_Item (Cur) := E; Cur := Cur + 1;
         end loop;
      end;
      Wipe (G); Wipe (Ginv); Wipe (F); Wipe (Finv);
      return CryptoLib.Errors.Ok;
   end Generate_Keypair;

   function Encapsulate
     (Source_Item     : in out CryptoLib.Random.Random_Source;
      Public_Item     : Public_Key;
      Ciphertext_Item : out Ciphertext;
      Shared_Item     : out Shared_Key)
      return CryptoLib.Errors.Status
   is
      H     : constant Coeff_Array := Rq_Decode (Public_Item);
      Cache : constant Hash_Out := Hash_Prefix (4, Public_Item);
      R     : Coeff_Array;
      R_Enc : Stream_Element_Array (1 .. Small_Bytes);
      Ok    : Boolean := True;
   begin
      Ciphertext_Item := [others => 0];
      Shared_Item := [others => 0];
      Short_Random (Source_Item, R, Ok);
      if not Ok then
         return CryptoLib.Errors.Internal_Error;
      end if;
      Hide (Ciphertext_Item, R_Enc, R, H, Cache);
      Shared_Item := Hash_Session (1, R_Enc, Ciphertext_Item);
      return CryptoLib.Errors.Ok;
   end Encapsulate;

   function Decapsulate
     (Secret_Item : Secret_Key;
      Ciphertext_Item : Ciphertext;
      Shared_Item : out Shared_Key)
      return CryptoLib.Errors.Status
   is
      F_Off     : constant Stream_Element_Offset := Secret_Item'First;
      Ginv_Off  : constant Stream_Element_Offset := F_Off + Small_Bytes;
      PK_Off    : constant Stream_Element_Offset := F_Off + Secret_Keys_Bytes;
      Rho_Off   : constant Stream_Element_Offset :=
        PK_Off + Stream_Element_Offset (Public_Key_Length);
      Cache_Off : constant Stream_Element_Offset := Rho_Off + Small_Bytes;

      F     : constant Coeff_Array :=
        Small_Decode (Secret_Item (F_Off .. F_Off + Small_Bytes - 1));
      Ginv  : constant Coeff_Array :=
        Small_Decode (Secret_Item (Ginv_Off .. Ginv_Off + Small_Bytes - 1));
      PK    : Public_Key;
      Cache : Hash_Out;

      C_Poly : constant Coeff_Array :=
        Rounded_Decode
          (Ciphertext_Item (Ciphertext_Item'First
             .. Ciphertext_Item'First + Rounded_Bytes - 1));
      CF   : constant Coeff_Array := Rq_Mult_Small (C_Poly, F);
      CF3  : constant Coeff_Array := Rq_Mult3 (CF);
      E    : constant Coeff_Array := R3_From_Rq (CF3);
      Ev   : constant Coeff_Array := R3_Mult (E, Ginv);
      Mask_Value : constant Integer := Weightw_Mask (Ev);
      R    : Coeff_Array;

      C_New : Ciphertext;
      R_Enc : Stream_Element_Array (1 .. Small_Bytes);
      B_Val : Stream_Element;
   begin
      for I in 0 .. Public_Key_Length - 1 loop
         PK (PK'First + Stream_Element_Offset (I)) :=
           Secret_Item (PK_Off + Stream_Element_Offset (I));
      end loop;
      for I in 0 .. Hash_Bytes - 1 loop
         Cache (Cache'First + Stream_Element_Offset (I)) :=
           Secret_Item (Cache_Off + Stream_Element_Offset (I));
      end loop;

      --  Branchless select of the recovered r: Ev on success, the fixed
      --  weight-w fallback on decryption failure (Weightw_Mask is 0 or -1).
      declare
         Fail : constant Integer := -Mask_Value;      --  0 on success, 1 on fail
      begin
         for I in Coeff_Index loop
            R (I) :=
              Ev (I) + ((if I < W_Value then 1 else 0) - Ev (I)) * Fail;
         end loop;
      end;

      Hide (C_New, R_Enc, R, Rq_Decode (PK), Cache);

      --  Constant-time ciphertext comparison + implicit rejection: fold the
      --  byte differences into one accumulator, then branchlessly overwrite
      --  r_enc with rho and pick the session prefix byte (1 = match, 0 = reject).
      declare
         Diff_Acc : Stream_Element := 0;
         Neq      : Integer;
         Mask8    : Stream_Element;
      begin
         for I in Ciphertext_Item'Range loop
            Diff_Acc :=
              Diff_Acc
              or (Ciphertext_Item (I)
                  xor C_New (C_New'First + (I - Ciphertext_Item'First)));
         end loop;
         Neq :=
           Integer
             (Shift_Right
                (Unsigned_32 (Diff_Acc) or (Unsigned_32 (0) - Unsigned_32 (Diff_Acc)),
                 31));
         Mask8 := Stream_Element (0) - Stream_Element (Neq);
         for I in 0 .. Small_Bytes - 1 loop
            declare
               Idx : constant Stream_Element_Offset :=
                 R_Enc'First + Stream_Element_Offset (I);
               Rho_Byte : constant Stream_Element :=
                 Secret_Item (Rho_Off + Stream_Element_Offset (I));
            begin
               R_Enc (Idx) :=
                 R_Enc (Idx) xor (Mask8 and (R_Enc (Idx) xor Rho_Byte));
            end;
         end loop;
         B_Val := Stream_Element (1 - Neq);
      end;

      Shared_Item := Hash_Session (B_Val, R_Enc, Ciphertext_Item);
      return CryptoLib.Errors.Ok;
   end Decapsulate;

end CryptoLib.SNTRUP761;
