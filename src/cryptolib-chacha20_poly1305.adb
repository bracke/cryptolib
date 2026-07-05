with CryptoLib.Constant_Time;

package body CryptoLib.ChaCha20_Poly1305 is
   use Ada.Streams;
   use Interfaces;
   use CryptoLib.Errors;

   subtype Byte is Unsigned_8;
   subtype Word is Unsigned_32;
   subtype Double_Word is Unsigned_64;
   type Word_Array is array (Natural range <>) of Word;
   type Byte_Array is array (Natural range <>) of Byte;

   Sigma : constant Byte_Array (0 .. 15) :=
     [16#65#,
      16#78#,
      16#70#,
      16#61#,
      16#6E#,
      16#64#,
      16#20#,
      16#33#,
      16#32#,
      16#2D#,
      16#62#,
      16#79#,
      16#74#,
      16#65#,
      16#20#,
      16#6B#];

   function To_Byte (Value : Stream_Element) return Byte
   is (Byte (Value))
     with SPARK_Mode => On;
   function To_Element (Value : Byte) return Stream_Element
   is (Stream_Element (Value))
     with SPARK_Mode => On;

   function Load32 (Data : Byte_Array; Offset : Natural) return Word
     with SPARK_Mode => On,
          Pre => Offset >= Data'First
            and then Offset <= Natural'Last - 3
            and then Offset + 3 <= Data'Last
   is
   begin
      return
        Word (Data (Offset))
        or Shift_Left (Word (Data (Offset + 1)), 8)
        or Shift_Left (Word (Data (Offset + 2)), 16)
        or Shift_Left (Word (Data (Offset + 3)), 24);
   end Load32;

   procedure Store32 (Value : Word; Data : in out Byte_Array; Offset : Natural)
     with SPARK_Mode => On,
          Pre => Offset >= Data'First
            and then Offset <= Natural'Last - 3
            and then Offset + 3 <= Data'Last
   is
   begin
      Data (Offset) := Byte (Value and 16#FF#);
      Data (Offset + 1) := Byte (Shift_Right (Value, 8) and 16#FF#);
      Data (Offset + 2) := Byte (Shift_Right (Value, 16) and 16#FF#);
      Data (Offset + 3) := Byte (Shift_Right (Value, 24) and 16#FF#);
   end Store32;

   function Rotate_Left_32 (Value : Word; Amount : Natural) return Word
     with SPARK_Mode => On,
          Pre => Amount <= 32
   is
   begin
      return Shift_Left (Value, Amount) or Shift_Right (Value, 32 - Amount);
   end Rotate_Left_32;

   procedure Quarter_Round
     (State_Item : in out Word_Array; A, B, C, D : Natural)
     with SPARK_Mode => On,
          Pre => A in State_Item'Range
            and then B in State_Item'Range
            and then C in State_Item'Range
            and then D in State_Item'Range
   is
   begin
      State_Item (A) := State_Item (A) + State_Item (B);
      State_Item (D) := Rotate_Left_32 (State_Item (D) xor State_Item (A), 16);
      State_Item (C) := State_Item (C) + State_Item (D);
      State_Item (B) := Rotate_Left_32 (State_Item (B) xor State_Item (C), 12);
      State_Item (A) := State_Item (A) + State_Item (B);
      State_Item (D) := Rotate_Left_32 (State_Item (D) xor State_Item (A), 8);
      State_Item (C) := State_Item (C) + State_Item (D);
      State_Item (B) := Rotate_Left_32 (State_Item (B) xor State_Item (C), 7);
   end Quarter_Round;

   procedure Make_Nonce (Sequence : Unsigned_32; Nonce : out Byte_Array)
     with SPARK_Mode => On,
          Pre => Nonce'First <= 8 and then Nonce'Last >= 11
   is
   begin
      --  chacha20-poly1305@openssh.com uses DJB ChaCha20: the 8-byte IV is the
      --  big-endian packet sequence number, loaded into ChaCha state words [14]
      --  and [15] (the block-counter words [12]/[13] are handled separately).
      --  In this 96-bit-nonce (RFC 8439) layout, state word [15] corresponds to
      --  nonce bytes 8..11, so the sequence number's low 32 bits go there; the
      --  high 32 bits sit in state[14] (nonce bytes 4..7) and stay zero for
      --  sequence numbers below 2**32.
      Nonce := [others => 0];
      Nonce (8) := Byte (Shift_Right (Sequence, 24) and 16#FF#);
      Nonce (9) := Byte (Shift_Right (Sequence, 16) and 16#FF#);
      Nonce (10) := Byte (Shift_Right (Sequence, 8) and 16#FF#);
      Nonce (11) := Byte (Sequence and 16#FF#);
   end Make_Nonce;

   procedure ChaCha20_Block
     (Key_Data : Byte_Array;
      Counter  : Word;
      Nonce    : Byte_Array;
      Output   : out Byte_Array)
   is
      State_Item : Word_Array (0 .. 15);
      Working    : Word_Array (0 .. 15);
   begin
      State_Item (0) := Load32 (Sigma, 0);
      State_Item (1) := Load32 (Sigma, 4);
      State_Item (2) := Load32 (Sigma, 8);
      State_Item (3) := Load32 (Sigma, 12);
      for Index_Value in 0 .. 7 loop
         State_Item (4 + Index_Value) := Load32 (Key_Data, Index_Value * 4);
      end loop;
      State_Item (12) := Counter;
      State_Item (13) := Load32 (Nonce, 0);
      State_Item (14) := Load32 (Nonce, 4);
      State_Item (15) := Load32 (Nonce, 8);

      Working := State_Item;
      for Round_Index in 1 .. 10 loop
         Quarter_Round (Working, 0, 4, 8, 12);
         Quarter_Round (Working, 1, 5, 9, 13);
         Quarter_Round (Working, 2, 6, 10, 14);
         Quarter_Round (Working, 3, 7, 11, 15);
         Quarter_Round (Working, 0, 5, 10, 15);
         Quarter_Round (Working, 1, 6, 11, 12);
         Quarter_Round (Working, 2, 7, 8, 13);
         Quarter_Round (Working, 3, 4, 9, 14);
      end loop;
      for Index_Value in 0 .. 15 loop
         Store32
           (Working (Index_Value) + State_Item (Index_Value),
            Output,
            Index_Value * 4);
      end loop;
   end ChaCha20_Block;

   procedure Apply_ChaCha20
     (Key_Data : Byte_Array;
      Sequence : Unsigned_32;
      Counter  : Word;
      Input    : Stream_Element_Array;
      Output   : out Stream_Element_Array)
   is
      Nonce   : Byte_Array (0 .. 11);
      Block   : Byte_Array (0 .. 63);
      Count   : Word := Counter;
      In_Pos  : Stream_Element_Offset := Input'First;
      Out_Pos : Stream_Element_Offset := Output'First;
   begin
      Make_Nonce (Sequence, Nonce);
      while In_Pos <= Input'Last loop
         ChaCha20_Block (Key_Data, Count, Nonce, Block);
         Count := Count + 1;
         for Offset_Value in Block'Range loop
            exit when In_Pos > Input'Last;
            Output (Out_Pos) :=
              To_Element (To_Byte (Input (In_Pos)) xor Block (Offset_Value));
            In_Pos := In_Pos + 1;
            Out_Pos := Out_Pos + 1;
         end loop;
      end loop;
   end Apply_ChaCha20;

   function Read_Key
     (Key_Data : Stream_Element_Array; Offset : Natural) return Byte_Array
     with SPARK_Mode => On,
          Pre => Offset <= Natural'Last - 31
            and then (if Key_Data'First > 0
                      then Stream_Element_Offset (Offset + 31)
                        <= Stream_Element_Offset'Last - Key_Data'First
                      else True)
            and then Key_Data'First + Stream_Element_Offset (Offset + 31) <= Key_Data'Last
   is
      Result : Byte_Array (0 .. 31);
   begin
      for Index_Value in Result'Range loop
         Result (Index_Value) :=
           To_Byte
             (Key_Data
                (Key_Data'First
                 + Stream_Element_Offset (Offset + Index_Value)));
      end loop;
      return Result;
   end Read_Key;

   function Poly1305_Tag
     (One_Time_Key : Byte_Array; Message_Data : Stream_Element_Array)
      return Stream_Element_Array
   is
      Mask26             : constant Double_Word := 16#3FF_FFFF#;
      R0                 : constant Double_Word :=
        Double_Word (Load32 (One_Time_Key, 0)) and Mask26;
      R1                 : constant Double_Word :=
        Shift_Right (Double_Word (Load32 (One_Time_Key, 3)), 2)
        and 16#3FF_FF03#;
      R2                 : constant Double_Word :=
        Shift_Right (Double_Word (Load32 (One_Time_Key, 6)), 4)
        and 16#3FF_C0FF#;
      R3                 : constant Double_Word :=
        Shift_Right (Double_Word (Load32 (One_Time_Key, 9)), 6)
        and 16#3F0_3FFF#;
      R4                 : constant Double_Word :=
        Shift_Right (Double_Word (Load32 (One_Time_Key, 12)), 8)
        and 16#00F_FFFF#;
      S1                 : constant Double_Word := R1 * 5;
      S2                 : constant Double_Word := R2 * 5;
      S3                 : constant Double_Word := R3 * 5;
      S4                 : constant Double_Word := R4 * 5;
      H0, H1, H2, H3, H4 : Double_Word := 0;
      Pos                : Stream_Element_Offset := Message_Data'First;
      Tag                : Stream_Element_Array (1 .. 16) := [others => 0];
   begin
      while Pos <= Message_Data'Last loop
         declare
            Block : Byte_Array (0 .. 16) := [others => 0];
            Take  : Natural := 0;
         begin
            while Take < 16 and then Pos <= Message_Data'Last loop
               Block (Take) := To_Byte (Message_Data (Pos));
               Take := Take + 1;
               Pos := Pos + 1;
            end loop;
            Block (Take) := 1;

            H0 := H0 + (Double_Word (Load32 (Block, 0)) and Mask26);
            H1 :=
              H1
              + (Shift_Right (Double_Word (Load32 (Block, 3)), 2) and Mask26);
            H2 :=
              H2
              + (Shift_Right (Double_Word (Load32 (Block, 6)), 4) and Mask26);
            H3 :=
              H3
              + (Shift_Right (Double_Word (Load32 (Block, 9)), 6) and Mask26);
            --  Limb 4 covers message bits 104..129 starting at byte 13; the
            --  block's high bit (byte 16, set to 1 above) lands at local bit
            --  24, so this reads from byte 13 with no shift.
            H4 :=
              H4 + (Double_Word (Load32 (Block, 13)) and Mask26);

            declare
               D0 : constant Double_Word :=
                 H0 * R0 + H1 * S4 + H2 * S3 + H3 * S2 + H4 * S1;
               D1 : Double_Word :=
                 H0 * R1 + H1 * R0 + H2 * S4 + H3 * S3 + H4 * S2;
               D2 : Double_Word :=
                 H0 * R2 + H1 * R1 + H2 * R0 + H3 * S4 + H4 * S3;
               D3 : Double_Word :=
                 H0 * R3 + H1 * R2 + H2 * R1 + H3 * R0 + H4 * S4;
               D4 : Double_Word :=
                 H0 * R4 + H1 * R3 + H2 * R2 + H3 * R1 + H4 * R0;
               C  : Double_Word;
            begin
               C := Shift_Right (D0, 26);
               H0 := D0 and Mask26;
               D1 := D1 + C;
               C := Shift_Right (D1, 26);
               H1 := D1 and Mask26;
               D2 := D2 + C;
               C := Shift_Right (D2, 26);
               H2 := D2 and Mask26;
               D3 := D3 + C;
               C := Shift_Right (D3, 26);
               H3 := D3 and Mask26;
               D4 := D4 + C;
               C := Shift_Right (D4, 26);
               H4 := D4 and Mask26;
               H0 := H0 + C * 5;
               C := Shift_Right (H0, 26);
               H0 := H0 and Mask26;
               H1 := H1 + C;
            end;
         end;
      end loop;

      --  Final carry propagation: the per-block loop leaves the top limbs only
      --  partially reduced (H1 may still exceed 26 bits), so a full carry chain
      --  must run before the limbs are recombined into the 128-bit tag.
      declare
         C : Double_Word;
      begin
         C := Shift_Right (H1, 26); H1 := H1 and Mask26; H2 := H2 + C;
         C := Shift_Right (H2, 26); H2 := H2 and Mask26; H3 := H3 + C;
         C := Shift_Right (H3, 26); H3 := H3 and Mask26; H4 := H4 + C;
         C := Shift_Right (H4, 26); H4 := H4 and Mask26; H0 := H0 + C * 5;
         C := Shift_Right (H0, 26); H0 := H0 and Mask26; H1 := H1 + C;
      end;

      declare
         --  Recombine the five 26-bit limbs into four 32-bit words. Each word
         --  must be masked to 32 bits here: the high limb bits shifted past
         --  bit 31 belong to the next word, so leaving them in would double-
         --  count them when the pad-carry propagates upward.
         F0    : Double_Word :=
           (H0 or Shift_Left (H1, 26)) and 16#FFFF_FFFF#;
         F1    : Double_Word :=
           (Shift_Right (H1, 6) or Shift_Left (H2, 20)) and 16#FFFF_FFFF#;
         F2    : Double_Word :=
           (Shift_Right (H2, 12) or Shift_Left (H3, 14)) and 16#FFFF_FFFF#;
         F3    : Double_Word :=
           (Shift_Right (H3, 18) or Shift_Left (H4, 8)) and 16#FFFF_FFFF#;
         Pad0  : constant Double_Word :=
           Double_Word (Load32 (One_Time_Key, 16));
         Pad1  : constant Double_Word :=
           Double_Word (Load32 (One_Time_Key, 20));
         Pad2  : constant Double_Word :=
           Double_Word (Load32 (One_Time_Key, 24));
         Pad3  : constant Double_Word :=
           Double_Word (Load32 (One_Time_Key, 28));
         Carry : Double_Word;
      begin
         F0 := F0 + Pad0;
         Carry := Shift_Right (F0, 32);
         F0 := F0 and 16#FFFF_FFFF#;
         F1 := F1 + Pad1 + Carry;
         Carry := Shift_Right (F1, 32);
         F1 := F1 and 16#FFFF_FFFF#;
         F2 := F2 + Pad2 + Carry;
         Carry := Shift_Right (F2, 32);
         F2 := F2 and 16#FFFF_FFFF#;
         F3 := F3 + Pad3 + Carry;
         for Index_Value in 0 .. 3 loop
            Tag (1 + Stream_Element_Offset (Index_Value)) :=
              To_Element (Byte (Shift_Right (F0, 8 * Index_Value) and 16#FF#));
            Tag (5 + Stream_Element_Offset (Index_Value)) :=
              To_Element (Byte (Shift_Right (F1, 8 * Index_Value) and 16#FF#));
            Tag (9 + Stream_Element_Offset (Index_Value)) :=
              To_Element (Byte (Shift_Right (F2, 8 * Index_Value) and 16#FF#));
            Tag (13 + Stream_Element_Offset (Index_Value)) :=
              To_Element (Byte (Shift_Right (F3, 8 * Index_Value) and 16#FF#));
         end loop;
      end;
      return Tag;
   end Poly1305_Tag;

   function Encrypt_Length
     (Key_Data : Stream_Element_Array;
      Sequence : Unsigned_32;
      Header   : Stream_Element_Array;
      Output   : out Stream_Element_Array) return Status
   is
      Length_Key : Byte_Array (0 .. 31);
   begin
      if Key_Data'Length < Key_Length
        or else Header'Length /= 4
        or else Output'Length /= 4
      then
         Output := [others => 0];
         return Handshake_Failed;
      end if;
      Length_Key := Read_Key (Key_Data, 32);
      Apply_ChaCha20 (Length_Key, Sequence, 0, Header, Output);
      return Ok;
   exception
      when others =>
         Output := [others => 0];
         return Internal_Error;
   end Encrypt_Length;

   function Seal
     (Key_Data     : Stream_Element_Array;
      Sequence     : Unsigned_32;
      Plain_Packet : Stream_Element_Array;
      Wire_Packet  : out Stream_Element_Array) return Status
   is
      Length_Key   : Byte_Array (0 .. 31);
      Payload_Key  : Byte_Array (0 .. 31);
      Header_In    : Stream_Element_Array (1 .. 4);
      Header_Out   : Stream_Element_Array (1 .. 4);
      Body_In      :
        Stream_Element_Array
          (1 .. Stream_Element_Offset (Plain_Packet'Length - 4));
      Body_Out     : Stream_Element_Array (Body_In'Range);
      One_Time_Key : Byte_Array (0 .. 31) := [others => 0];
      Zero_Block   : constant Stream_Element_Array (1 .. 32) := [others => 0];
      OTK_Stream   : Stream_Element_Array (1 .. 32);
   begin
      if Key_Data'Length < Key_Length
        or else Plain_Packet'Length < 5
        or else Wire_Packet'Length /= Plain_Packet'Length + Tag_Length
      then
         Wire_Packet := [others => 0];
         return Handshake_Failed;
      end if;
      Length_Key := Read_Key (Key_Data, 32);
      Payload_Key := Read_Key (Key_Data, 0);
      Header_In := Plain_Packet (Plain_Packet'First .. Plain_Packet'First + 3);
      Body_In := Plain_Packet (Plain_Packet'First + 4 .. Plain_Packet'Last);
      Apply_ChaCha20 (Length_Key, Sequence, 0, Header_In, Header_Out);
      Apply_ChaCha20 (Payload_Key, Sequence, 1, Body_In, Body_Out);
      Apply_ChaCha20 (Payload_Key, Sequence, 0, Zero_Block, OTK_Stream);
      for Index_Value in One_Time_Key'Range loop
         One_Time_Key (Index_Value) :=
           To_Byte
             (OTK_Stream
                (OTK_Stream'First + Stream_Element_Offset (Index_Value)));
      end loop;
      Wire_Packet (Wire_Packet'First .. Wire_Packet'First + 3) := Header_Out;
      Wire_Packet
        (Wire_Packet'First + 4
         .. Wire_Packet'First + 3 + Stream_Element_Offset (Body_Out'Length)) :=
        Body_Out;
      declare
         Auth_Data : constant Stream_Element_Array :=
           Wire_Packet
             (Wire_Packet'First
              ..
                Wire_Packet'First
                + Stream_Element_Offset (Plain_Packet'Length)
                - 1);
         Tag       : constant Stream_Element_Array :=
           Poly1305_Tag (One_Time_Key, Auth_Data);
      begin
         Wire_Packet
           (Wire_Packet'First
            + Stream_Element_Offset (Plain_Packet'Length)
            .. Wire_Packet'Last) :=
           Tag;
      end;
      return Ok;
   exception
      when others =>
         Wire_Packet := [others => 0];
         return Internal_Error;
   end Seal;

   function Open
     (Key_Data     : Stream_Element_Array;
      Sequence     : Unsigned_32;
      Wire_Packet  : Stream_Element_Array;
      Plain_Packet : out Stream_Element_Array) return Status
   is
      Length_Key   : Byte_Array (0 .. 31);
      Payload_Key  : Byte_Array (0 .. 31);
      Header_In    : Stream_Element_Array (1 .. 4);
      Header_Out   : Stream_Element_Array (1 .. 4);
      Body_In      :
        Stream_Element_Array
          (1 .. Stream_Element_Offset (Wire_Packet'Length - Tag_Length - 4));
      Body_Out     : Stream_Element_Array (Body_In'Range);
      One_Time_Key : Byte_Array (0 .. 31) := [others => 0];
      Zero_Block   : constant Stream_Element_Array (1 .. 32) := [others => 0];
      OTK_Stream   : Stream_Element_Array (1 .. 32);
   begin
      if Key_Data'Length < Key_Length
        or else Wire_Packet'Length < 5 + Tag_Length
        or else Plain_Packet'Length + Tag_Length /= Wire_Packet'Length
      then
         Plain_Packet := [others => 0];
         return Handshake_Failed;
      end if;
      Payload_Key := Read_Key (Key_Data, 0);
      Apply_ChaCha20 (Payload_Key, Sequence, 0, Zero_Block, OTK_Stream);
      for Index_Value in One_Time_Key'Range loop
         One_Time_Key (Index_Value) :=
           To_Byte
             (OTK_Stream
                (OTK_Stream'First + Stream_Element_Offset (Index_Value)));
      end loop;
      declare
         Auth_Data  : constant Stream_Element_Array :=
           Wire_Packet
             (Wire_Packet'First
              .. Wire_Packet'Last - Stream_Element_Offset (Tag_Length));
         Actual_Tag : constant Stream_Element_Array :=
           Wire_Packet
             (Wire_Packet'Last
              - Stream_Element_Offset (Tag_Length)
              + 1
              .. Wire_Packet'Last);
         Wanted_Tag : constant Stream_Element_Array :=
           Poly1305_Tag (One_Time_Key, Auth_Data);
      begin
         if not CryptoLib.Constant_Time.Equal (Actual_Tag, Wanted_Tag)
         then
            Plain_Packet := [others => 0];
            return Handshake_Failed;
         end if;
      end;
      Length_Key := Read_Key (Key_Data, 32);
      Header_In := Wire_Packet (Wire_Packet'First .. Wire_Packet'First + 3);
      Body_In :=
        Wire_Packet
          (Wire_Packet'First + 4
           .. Wire_Packet'Last - Stream_Element_Offset (Tag_Length));
      Apply_ChaCha20 (Length_Key, Sequence, 0, Header_In, Header_Out);
      Apply_ChaCha20 (Payload_Key, Sequence, 1, Body_In, Body_Out);
      Plain_Packet (Plain_Packet'First .. Plain_Packet'First + 3) :=
        Header_Out;
      Plain_Packet (Plain_Packet'First + 4 .. Plain_Packet'Last) := Body_Out;
      return Ok;
   exception
      when others =>
         Plain_Packet := [others => 0];
         return Internal_Error;
   end Open;
end CryptoLib.ChaCha20_Poly1305;
