with CryptoLib.Ciphers;

package body CryptoLib.UMAC is

   use Ada.Streams;
   use Interfaces;
   use type CryptoLib.Errors.Status;

   subtype U32 is Unsigned_32;
   subtype U64 is Unsigned_64;

   --  Streamed-key/state arrays are indexed 0 .. Streams-1; UMAC-64 uses two
   --  streams (STREAMS=2), UMAC-128 four (STREAMS=4). L3 arithmetic works in
   --  the fields modulo p36 = 2**36-5 and p64 = 2**64-59.
   type U64_Array is array (0 .. 3) of U64;

   P36 : constant U64 := 16#0000000FFFFFFFFB#;   --  2**36 - 5
   P64 : constant U64 := 16#FFFFFFFFFFFFFFC5#;    --  2**64 - 59
   M36 : constant U64 := 16#0000000FFFFFFFFF#;    --  low 36 bits

   L1_KEY_LEN : constant Natural := 1024;         --  L1 (NH) block length

   ----------------------------------------------------------------------------
   --  Predicates (unchanged public contract)
   ----------------------------------------------------------------------------

   function Is_OpenSSH_UMAC_Name
     (Name_Text : String)
      return Boolean
      with SPARK_Mode => On
   is
   begin
      return Name_Text = "umac-64@openssh.com"
        or else Name_Text = "umac-128@openssh.com"
        or else Name_Text = "umac-64-etm@openssh.com"
        or else Name_Text = "umac-128-etm@openssh.com";
   end Is_OpenSSH_UMAC_Name;

   function Is_Implemented
     (Name_Text : String)
      return Boolean
      with SPARK_Mode => On
   is
   begin
      return Is_OpenSSH_UMAC_Name (Name_Text);
   end Is_Implemented;

   function Is_EtM_Name
     (Name_Text : String)
      return Boolean
      with SPARK_Mode => On
   is
   begin
      return Name_Text = "umac-64-etm@openssh.com"
        or else Name_Text = "umac-128-etm@openssh.com";
   end Is_EtM_Name;

   function Tag_Length
     (Name_Text : String)
      return Natural
      with SPARK_Mode => On
   is
   begin
      if Name_Text = "umac-64@openssh.com"
        or else Name_Text = "umac-64-etm@openssh.com"
      then
         return UMAC_64_Length;
      elsif Name_Text = "umac-128@openssh.com"
        or else Name_Text = "umac-128-etm@openssh.com"
      then
         return UMAC_128_Length;
      end if;
      return 0;
   end Tag_Length;

   ----------------------------------------------------------------------------
   --  Primitive helpers
   ----------------------------------------------------------------------------

   --  Raw AES-128 block encryption (ECB): aes128-ctr with the block as the
   --  initial counter and a zero plaintext yields E(Key, Block).
   function AES_Block
     (Key_Data : UMAC_Key;
      Block    : Stream_Element_Array)
      return Stream_Element_Array
   is
      State        : CryptoLib.Ciphers.Cipher_State;
      Counter_IV   : Stream_Element_Array (1 .. 16) := [others => 0];
      Zero_Input   : constant Stream_Element_Array (1 .. 16) := [others => 0];
      Output_Data  : Stream_Element_Array (1 .. 16) := [others => 0];
      Status_Value : CryptoLib.Errors.Status;
   begin
      if Block'Length /= 16 then
         return Output_Data;
      end if;

      for Index_Value in 0 .. 15 loop
         Counter_IV (Counter_IV'First + Stream_Element_Offset (Index_Value)) :=
           Block (Block'First + Stream_Element_Offset (Index_Value));
      end loop;

      Status_Value := CryptoLib.Ciphers.Initialize
        (State, "aes128-ctr", CryptoLib.Ciphers.Client_To_Server,
         Key_Data, Counter_IV);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Output_Data;
      end if;

      Status_Value := CryptoLib.Ciphers.Encrypt (State, Zero_Input, Output_Data);
      if Status_Value /= CryptoLib.Errors.Ok then
         Output_Data := [others => 0];
      end if;
      return Output_Data;
   exception
      when others =>
         return [1 .. 16 => 0];
   end AES_Block;

   function Byte_Val
     (Data : Stream_Element_Array; Offset : Natural) return U32
   is (U32 (Data (Data'First + Stream_Element_Offset (Offset))));

   function LE32 (Data : Stream_Element_Array; Offset : Natural) return U32 is
     (Byte_Val (Data, Offset)
      or Shift_Left (Byte_Val (Data, Offset + 1), 8)
      or Shift_Left (Byte_Val (Data, Offset + 2), 16)
      or Shift_Left (Byte_Val (Data, Offset + 3), 24));

   function BE32 (Data : Stream_Element_Array; Offset : Natural) return U32 is
     (Shift_Left (Byte_Val (Data, Offset), 24)
      or Shift_Left (Byte_Val (Data, Offset + 1), 16)
      or Shift_Left (Byte_Val (Data, Offset + 2), 8)
      or Byte_Val (Data, Offset + 3));

   function BE64 (Data : Stream_Element_Array; Offset : Natural) return U64 is
     (Shift_Left (U64 (BE32 (Data, Offset)), 32) or U64 (BE32 (Data, Offset + 4)));

   function Key_Word (Key : Stream_Element_Array; Word_Index : Natural)
      return U32
   is (BE32 (Key, 4 * Word_Index));

   function MUL64 (A, B : U32) return U64 is (U64 (A) * U64 (B));

   procedure Store_BE32
     (Into : in out Stream_Element_Array; Offset : Natural; Value : U32)
   is
   begin
      Into (Into'First + Stream_Element_Offset (Offset)) :=
        Stream_Element (Shift_Right (Value, 24) and 16#FF#);
      Into (Into'First + Stream_Element_Offset (Offset + 1)) :=
        Stream_Element (Shift_Right (Value, 16) and 16#FF#);
      Into (Into'First + Stream_Element_Offset (Offset + 2)) :=
        Stream_Element (Shift_Right (Value, 8) and 16#FF#);
      Into (Into'First + Stream_Element_Offset (Offset + 3)) :=
        Stream_Element (Value and 16#FF#);
   end Store_BE32;

   ----------------------------------------------------------------------------
   --  KDF (RFC 4418 / OpenSSH): T_i = AES(Key, index@byte7 || i@byte15)
   ----------------------------------------------------------------------------

   function KDF
     (Key : UMAC_Key; Index_Value : Unsigned_8; Length : Natural)
      return Stream_Element_Array
   is
      Result  : Stream_Element_Array (0 .. Stream_Element_Offset (Length) - 1) :=
        [others => 0];
      Block   : Stream_Element_Array (1 .. 16) := [others => 0];
      Counter : Unsigned_8 := 1;
      Pos     : Natural := 0;
   begin
      Block (8) := Stream_Element (Index_Value);
      while Pos < Length loop
         Block (16) := Stream_Element (Counter);
         declare
            Out_Block : constant Stream_Element_Array := AES_Block (Key, Block);
         begin
            for I in 0 .. 15 loop
               exit when Pos + I >= Length;
               Result (Result'First + Stream_Element_Offset (Pos + I)) :=
                 Out_Block (Out_Block'First + Stream_Element_Offset (I));
            end loop;
         end;
         Pos := Pos + 16;
         Counter := Counter + 1;
      end loop;
      return Result;
   end KDF;

   ----------------------------------------------------------------------------
   --  L1 (NH) hash of one <=1024-byte block, returning per-stream 64-bit
   --  values already including the block bit-length (nh_final semantics).
   ----------------------------------------------------------------------------

   function NH_Block
     (Nh_Key  : Stream_Element_Array;
      Streams : Positive;
      Message : Stream_Element_Array;
      Offset  : Natural;
      Blen    : Natural)
      return U64_Array
   is
      Nh_Len : constant Natural :=
        (if Blen = 0 then 32 else ((Blen + 31) / 32) * 32);
      Padded : Stream_Element_Array (0 .. Stream_Element_Offset (Nh_Len) - 1) :=
        [others => 0];
      Sub    : constant Natural := Nh_Len / 32;
      Nbits  : constant U64 := U64 (Blen) * 8;
      H      : U64_Array := [others => 0];
   begin
      for I in 0 .. Blen - 1 loop
         Padded (Stream_Element_Offset (I)) :=
           Message (Message'First + Stream_Element_Offset (Offset + I));
      end loop;

      for J in 0 .. Sub - 1 loop
         declare
            D : array (0 .. 7) of U32;
         begin
            for P in 0 .. 7 loop
               D (P) := LE32 (Padded, 32 * J + 4 * P);
            end loop;
            for S in 0 .. Streams - 1 loop
               for P in 0 .. 3 loop
                  H (S) := H (S)
                    + MUL64 (Key_Word (Nh_Key, 8 * J + 4 * S + P) + D (P),
                             Key_Word (Nh_Key, 8 * J + 4 * S + 4 + P)
                               + D (P + 4));
               end loop;
            end loop;
         end;
      end loop;

      for S in 0 .. Streams - 1 loop
         H (S) := H (S) + Nbits;
      end loop;
      return H;
   end NH_Block;

   ----------------------------------------------------------------------------
   --  L2 (POLY) hash step, per RFC 4418 / OpenSSH poly64 + poly_hash.
   ----------------------------------------------------------------------------

   function Poly64 (Cur, Key, Data : U64) return U64 is
      Key_Hi : constant U32 := U32 (Shift_Right (Key, 32) and 16#FFFFFFFF#);
      Key_Lo : constant U32 := U32 (Key and 16#FFFFFFFF#);
      Cur_Hi : constant U32 := U32 (Shift_Right (Cur, 32) and 16#FFFFFFFF#);
      Cur_Lo : constant U32 := U32 (Cur and 16#FFFFFFFF#);
      X      : constant U64 := MUL64 (Key_Hi, Cur_Lo) + MUL64 (Cur_Hi, Key_Lo);
      X_Lo   : constant U32 := U32 (X and 16#FFFFFFFF#);
      X_Hi   : constant U32 := U32 (Shift_Right (X, 32) and 16#FFFFFFFF#);
      T      : constant U64 := Shift_Left (U64 (X_Lo), 32);
      Res    : U64;
   begin
      Res := (MUL64 (Key_Hi, Cur_Hi) + U64 (X_Hi)) * 59 + MUL64 (Key_Lo, Cur_Lo);
      Res := Res + T;
      if Res < T then
         Res := Res + 59;
      end if;
      Res := Res + Data;
      if Res < Data then
         Res := Res + 59;
      end if;
      return Res;
   end Poly64;

   procedure Poly_Hash (Accum : in out U64; Key : U64; Data : U64) is
   begin
      if Shift_Right (Data, 32) = 16#FFFFFFFF# then
         Accum := Poly64 (Accum, Key, P64 - 1);
         Accum := Poly64 (Accum, Key, Data - 59);
      else
         Accum := Poly64 (Accum, Key, Data);
      end if;
   end Poly_Hash;

   ----------------------------------------------------------------------------
   --  L3 inner-product hash of a 64-bit value: four 16-bit chunks against
   --  four p36-reduced keys, reduced mod p36, XORed with the translation key.
   ----------------------------------------------------------------------------

   function L3
     (K0, K1, K2, K3 : U64; Data : U64; Trans : U32) return U32
   is
      T   : constant U64 :=
        K0 * (Shift_Right (Data, 48) and 16#FFFF#)
        + K1 * (Shift_Right (Data, 32) and 16#FFFF#)
        + K2 * (Shift_Right (Data, 16) and 16#FFFF#)
        + K3 * (Data and 16#FFFF#);
      Ret : U64 := (T and M36) + 5 * Shift_Right (T, 36);
   begin
      if Ret >= P36 then
         Ret := Ret - P36;
      end if;
      return U32 (Ret and 16#FFFFFFFF#) xor Trans;
   end L3;

   ----------------------------------------------------------------------------
   --  Full UHASH: derive the sub-keys, run L1/L2/L3, return Streams*4 bytes.
   ----------------------------------------------------------------------------

   function UHash
     (Key     : UMAC_Key;
      Streams : Positive;
      Message : Stream_Element_Array)
      return Stream_Element_Array
   is
      Nh_Key   : constant Stream_Element_Array :=
        KDF (Key, 1, L1_KEY_LEN + 16 * (Streams - 1));
      Poly_Buf : constant Stream_Element_Array :=
        KDF (Key, 2, (8 * Streams + 4) * 8);
      Ip_Buf   : constant Stream_Element_Array :=
        KDF (Key, 3, (8 * Streams + 4) * 8);
      Trans_Buf : constant Stream_Element_Array := KDF (Key, 4, Streams * 4);

      Poly_Key   : U64_Array := [others => 0];
      Ip_Keys    : array (0 .. 15) of U64 := [others => 0];
      Ip_Trans   : array (0 .. 3) of U32 := [others => 0];
      Poly_Accum : U64_Array := [others => 1];

      Total  : constant Natural := Message'Length;
      Result : Stream_Element_Array
        (0 .. Stream_Element_Offset (4 * Streams) - 1) := [others => 0];
   begin
      for I in 0 .. Streams - 1 loop
         Poly_Key (I) := BE64 (Poly_Buf, 24 * I) and 16#01FFFFFF01FFFFFF#;
         for J in 0 .. 3 loop
            Ip_Keys (4 * I + J) := BE64 (Ip_Buf, (8 * I + 4 + J) * 8) mod P36;
         end loop;
         Ip_Trans (I) := BE32 (Trans_Buf, 4 * I);
      end loop;

      if Total <= L1_KEY_LEN then
         --  Short message: single L1 block straight into L3 (no POLY).
         declare
            H : constant U64_Array := NH_Block (Nh_Key, Streams, Message, 0, Total);
         begin
            for S in 0 .. Streams - 1 loop
               Store_BE32
                 (Result, 4 * S,
                  L3 (Ip_Keys (4 * S), Ip_Keys (4 * S + 1),
                      Ip_Keys (4 * S + 2), Ip_Keys (4 * S + 3),
                      H (S), Ip_Trans (S)));
            end loop;
         end;
      else
         --  Long message: POLY over each 1024-byte L1 block, then L3.
         declare
            Full : constant Natural := Total / L1_KEY_LEN;
            Rem_Len : constant Natural := Total mod L1_KEY_LEN;
         begin
            for B in 0 .. Full - 1 loop
               declare
                  H : constant U64_Array :=
                    NH_Block (Nh_Key, Streams, Message, B * L1_KEY_LEN,
                              L1_KEY_LEN);
               begin
                  for S in 0 .. Streams - 1 loop
                     Poly_Hash (Poly_Accum (S), Poly_Key (S), H (S));
                  end loop;
               end;
            end loop;

            if Rem_Len /= 0 then
               declare
                  H : constant U64_Array :=
                    NH_Block (Nh_Key, Streams, Message, Full * L1_KEY_LEN,
                              Rem_Len);
               begin
                  for S in 0 .. Streams - 1 loop
                     Poly_Hash (Poly_Accum (S), Poly_Key (S), H (S));
                  end loop;
               end;
            end if;

            for S in 0 .. Streams - 1 loop
               if Poly_Accum (S) >= P64 then
                  Poly_Accum (S) := Poly_Accum (S) - P64;
               end if;
               Store_BE32
                 (Result, 4 * S,
                  L3 (Ip_Keys (4 * S), Ip_Keys (4 * S + 1),
                      Ip_Keys (4 * S + 2), Ip_Keys (4 * S + 3),
                      Poly_Accum (S), Ip_Trans (S)));
            end loop;
         end;
      end if;

      return Result;
   end UHash;

   ----------------------------------------------------------------------------
   --  PDF pad: AES(prf_key, nonce) with prf_key = KDF(key, 0, 16); for the
   --  8-byte tag the low bit of the nonce selects the cache half.
   ----------------------------------------------------------------------------

   function Pad
     (Key : UMAC_Key; Nonce : Stream_Element_Array; Tag_Len : Natural)
      return Stream_Element_Array
   is
      Prf_Bytes : constant Stream_Element_Array := KDF (Key, 0, 16);
      Prf_Key   : UMAC_Key;
      Aes_In    : Stream_Element_Array (1 .. 16) := [others => 0];
      Low_Bit   : constant U32 := Byte_Val (Nonce, 7) and 1;
   begin
      for I in Prf_Key'Range loop
         Prf_Key (I) := Prf_Bytes (Prf_Bytes'First + (I - Prf_Key'First));
      end loop;

      for I in 0 .. 7 loop
         Aes_In (Aes_In'First + Stream_Element_Offset (I)) :=
           Nonce (Nonce'First + Stream_Element_Offset (I));
      end loop;

      if Tag_Len = UMAC_64_Length then
         --  Clear the indexing bit before enciphering.
         Aes_In (8) := Stream_Element (U32 (Aes_In (8)) and 16#FE#);
      end if;

      declare
         Cache : constant Stream_Element_Array := AES_Block (Prf_Key, Aes_In);
         Out_Pad : Stream_Element_Array
           (0 .. Stream_Element_Offset (Tag_Len) - 1);
         Base  : constant Natural :=
           (if Tag_Len = UMAC_64_Length then Natural (Low_Bit) * 8 else 0);
      begin
         for I in 0 .. Tag_Len - 1 loop
            Out_Pad (Stream_Element_Offset (I)) :=
              Cache (Cache'First + Stream_Element_Offset (Base + I));
         end loop;
         return Out_Pad;
      end;
   end Pad;

   ----------------------------------------------------------------------------
   --  Public entry points
   ----------------------------------------------------------------------------

   function Generate_With_Nonce
     (Name_Text    : String;
      Key_Data     : UMAC_Key;
      Nonce        : Ada.Streams.Stream_Element_Array;
      Message_Data : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array
   is
      Tag_Len : constant Natural := Tag_Length (Name_Text);
      Streams : constant Natural := Tag_Len / 4;
   begin
      if Tag_Len = 0 or else Nonce'Length /= 8 then
         return [1 .. 0 => 0];
      end if;

      declare
         Hash_Out : constant Stream_Element_Array :=
           UHash (Key_Data, Streams, Message_Data);
         Pad_Out  : constant Stream_Element_Array :=
           Pad (Key_Data, Nonce, Tag_Len);
         Tag      : Stream_Element_Array (1 .. Stream_Element_Offset (Tag_Len));
      begin
         for I in 0 .. Tag_Len - 1 loop
            Tag (Tag'First + Stream_Element_Offset (I)) :=
              Hash_Out (Hash_Out'First + Stream_Element_Offset (I))
              xor Pad_Out (Pad_Out'First + Stream_Element_Offset (I));
         end loop;
         return Tag;
      end;
   exception
      when others =>
         return [1 .. 0 => 0];
   end Generate_With_Nonce;

   function Generate
     (Name_Text       : String;
      Key_Data        : UMAC_Key;
      Sequence_Value  : Interfaces.Unsigned_32;
      Message_Data    : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array
   is
      --  SSH nonce is the 64-bit sequence number, big-endian; the sequence
      --  here is 32-bit, so the high four bytes are zero.
      Nonce : Stream_Element_Array (1 .. 8) := [others => 0];
   begin
      Nonce (5) := Stream_Element (Shift_Right (Sequence_Value, 24) and 16#FF#);
      Nonce (6) := Stream_Element (Shift_Right (Sequence_Value, 16) and 16#FF#);
      Nonce (7) := Stream_Element (Shift_Right (Sequence_Value, 8) and 16#FF#);
      Nonce (8) := Stream_Element (Sequence_Value and 16#FF#);
      return Generate_With_Nonce (Name_Text, Key_Data, Nonce, Message_Data);
   end Generate;

   function Fail_Closed_Status
     (Name_Text : String)
      return CryptoLib.Errors.Status
      with SPARK_Mode => On
   is
   begin
      if Is_OpenSSH_UMAC_Name (Name_Text)
        and then not Is_Implemented (Name_Text)
      then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;

      if Is_OpenSSH_UMAC_Name (Name_Text) then
         return CryptoLib.Errors.Ok;
      end if;

      return CryptoLib.Errors.Handshake_Failed;
   end Fail_Closed_Status;

end CryptoLib.UMAC;
