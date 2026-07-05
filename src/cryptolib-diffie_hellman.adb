with CryptoLib.Modexp;

package body CryptoLib.Diffie_Hellman is
   use Ada.Streams;
   use CryptoLib.Errors;

   --  The group16/18 private exponents are generated at 512 bits, so pass only
   --  the low 64 bytes to the modexp.  Its iteration count tracks the exponent
   --  buffer length (public), so this both keeps it constant-time in the secret
   --  value and avoids exponentiating the zero-padded high half of the fixed
   --  512/1024-byte limb array.
   function Exponent_Bytes
     (Full : Stream_Element_Array) return Stream_Element_Array
   is (Full (Full'Last - 63 .. Full'Last));

   subtype Limb_Index is Natural range 0 .. 255;
   type Big_Value is array (Limb_Index) of Natural range 0 .. 255;

   Group14_Prime : constant Big_Value :=
     [16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#C9#,
      16#0F#,
      16#DA#,
      16#A2#,
      16#21#,
      16#68#,
      16#C2#,
      16#34#,
      16#C4#,
      16#C6#,
      16#62#,
      16#8B#,
      16#80#,
      16#DC#,
      16#1C#,
      16#D1#,
      16#29#,
      16#02#,
      16#4E#,
      16#08#,
      16#8A#,
      16#67#,
      16#CC#,
      16#74#,
      16#02#,
      16#0B#,
      16#BE#,
      16#A6#,
      16#3B#,
      16#13#,
      16#9B#,
      16#22#,
      16#51#,
      16#4A#,
      16#08#,
      16#79#,
      16#8E#,
      16#34#,
      16#04#,
      16#DD#,
      16#EF#,
      16#95#,
      16#19#,
      16#B3#,
      16#CD#,
      16#3A#,
      16#43#,
      16#1B#,
      16#30#,
      16#2B#,
      16#0A#,
      16#6D#,
      16#F2#,
      16#5F#,
      16#14#,
      16#37#,
      16#4F#,
      16#E1#,
      16#35#,
      16#6D#,
      16#6D#,
      16#51#,
      16#C2#,
      16#45#,
      16#E4#,
      16#85#,
      16#B5#,
      16#76#,
      16#62#,
      16#5E#,
      16#7E#,
      16#C6#,
      16#F4#,
      16#4C#,
      16#42#,
      16#E9#,
      16#A6#,
      16#37#,
      16#ED#,
      16#6B#,
      16#0B#,
      16#FF#,
      16#5C#,
      16#B6#,
      16#F4#,
      16#06#,
      16#B7#,
      16#ED#,
      16#EE#,
      16#38#,
      16#6B#,
      16#FB#,
      16#5A#,
      16#89#,
      16#9F#,
      16#A5#,
      16#AE#,
      16#9F#,
      16#24#,
      16#11#,
      16#7C#,
      16#4B#,
      16#1F#,
      16#E6#,
      16#49#,
      16#28#,
      16#66#,
      16#51#,
      16#EC#,
      16#E4#,
      16#5B#,
      16#3D#,
      16#C2#,
      16#00#,
      16#7C#,
      16#B8#,
      16#A1#,
      16#63#,
      16#BF#,
      16#05#,
      16#98#,
      16#DA#,
      16#48#,
      16#36#,
      16#1C#,
      16#55#,
      16#D3#,
      16#9A#,
      16#69#,
      16#16#,
      16#3F#,
      16#A8#,
      16#FD#,
      16#24#,
      16#CF#,
      16#5F#,
      16#83#,
      16#65#,
      16#5D#,
      16#23#,
      16#DC#,
      16#A3#,
      16#AD#,
      16#96#,
      16#1C#,
      16#62#,
      16#F3#,
      16#56#,
      16#20#,
      16#85#,
      16#52#,
      16#BB#,
      16#9E#,
      16#D5#,
      16#29#,
      16#07#,
      16#70#,
      16#96#,
      16#96#,
      16#6D#,
      16#67#,
      16#0C#,
      16#35#,
      16#4E#,
      16#4A#,
      16#BC#,
      16#98#,
      16#04#,
      16#F1#,
      16#74#,
      16#6C#,
      16#08#,
      16#CA#,
      16#18#,
      16#21#,
      16#7C#,
      16#32#,
      16#90#,
      16#5E#,
      16#46#,
      16#2E#,
      16#36#,
      16#CE#,
      16#3B#,
      16#E3#,
      16#9E#,
      16#77#,
      16#2C#,
      16#18#,
      16#0E#,
      16#86#,
      16#03#,
      16#9B#,
      16#27#,
      16#83#,
      16#A2#,
      16#EC#,
      16#07#,
      16#A2#,
      16#8F#,
      16#B5#,
      16#C5#,
      16#5D#,
      16#F0#,
      16#6F#,
      16#4C#,
      16#52#,
      16#C9#,
      16#DE#,
      16#2B#,
      16#CB#,
      16#F6#,
      16#95#,
      16#58#,
      16#17#,
      16#18#,
      16#39#,
      16#95#,
      16#49#,
      16#7C#,
      16#EA#,
      16#95#,
      16#6A#,
      16#E5#,
      16#15#,
      16#D2#,
      16#26#,
      16#18#,
      16#98#,
      16#FA#,
      16#05#,
      16#10#,
      16#15#,
      16#72#,
      16#8E#,
      16#5A#,
      16#8A#,
      16#AC#,
      16#AA#,
      16#68#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#];

   Zero_Value : constant Big_Value := [others => 0];

   Group1_Prime : constant Big_Value :=
     [0 .. 127 => 0,
      128 => 16#FF#,
      129 => 16#FF#,
      130 => 16#FF#,
      131 => 16#FF#,
      132 => 16#FF#,
      133 => 16#FF#,
      134 => 16#FF#,
      135 => 16#FF#,
      136 => 16#C9#,
      137 => 16#0F#,
      138 => 16#DA#,
      139 => 16#A2#,
      140 => 16#21#,
      141 => 16#68#,
      142 => 16#C2#,
      143 => 16#34#,
      144 => 16#C4#,
      145 => 16#C6#,
      146 => 16#62#,
      147 => 16#8B#,
      148 => 16#80#,
      149 => 16#DC#,
      150 => 16#1C#,
      151 => 16#D1#,
      152 => 16#29#,
      153 => 16#02#,
      154 => 16#4E#,
      155 => 16#08#,
      156 => 16#8A#,
      157 => 16#67#,
      158 => 16#CC#,
      159 => 16#74#,
      160 => 16#02#,
      161 => 16#0B#,
      162 => 16#BE#,
      163 => 16#A6#,
      164 => 16#3B#,
      165 => 16#13#,
      166 => 16#9B#,
      167 => 16#22#,
      168 => 16#51#,
      169 => 16#4A#,
      170 => 16#08#,
      171 => 16#79#,
      172 => 16#8E#,
      173 => 16#34#,
      174 => 16#04#,
      175 => 16#DD#,
      176 => 16#EF#,
      177 => 16#95#,
      178 => 16#19#,
      179 => 16#B3#,
      180 => 16#CD#,
      181 => 16#3A#,
      182 => 16#43#,
      183 => 16#1B#,
      184 => 16#30#,
      185 => 16#2B#,
      186 => 16#0A#,
      187 => 16#6D#,
      188 => 16#F2#,
      189 => 16#5F#,
      190 => 16#14#,
      191 => 16#37#,
      192 => 16#4F#,
      193 => 16#E1#,
      194 => 16#35#,
      195 => 16#6D#,
      196 => 16#6D#,
      197 => 16#51#,
      198 => 16#C2#,
      199 => 16#45#,
      200 => 16#E4#,
      201 => 16#85#,
      202 => 16#B5#,
      203 => 16#76#,
      204 => 16#62#,
      205 => 16#5E#,
      206 => 16#7E#,
      207 => 16#C6#,
      208 => 16#F4#,
      209 => 16#4C#,
      210 => 16#42#,
      211 => 16#E9#,
      212 => 16#A6#,
      213 => 16#37#,
      214 => 16#ED#,
      215 => 16#6B#,
      216 => 16#0B#,
      217 => 16#FF#,
      218 => 16#5C#,
      219 => 16#B6#,
      220 => 16#F4#,
      221 => 16#06#,
      222 => 16#B7#,
      223 => 16#ED#,
      224 => 16#EE#,
      225 => 16#38#,
      226 => 16#6B#,
      227 => 16#FB#,
      228 => 16#5A#,
      229 => 16#89#,
      230 => 16#9F#,
      231 => 16#A5#,
      232 => 16#AE#,
      233 => 16#9F#,
      234 => 16#24#,
      235 => 16#11#,
      236 => 16#7C#,
      237 => 16#4B#,
      238 => 16#1F#,
      239 => 16#E6#,
      240 => 16#49#,
      241 => 16#28#,
      242 => 16#66#,
      243 => 16#51#,
      244 => 16#EC#,
      245 => 16#E6#,
      246 => 16#53#,
      247 => 16#81#,
      248 => 16#FF#,
      249 => 16#FF#,
      250 => 16#FF#,
      251 => 16#FF#,
      252 => 16#FF#,
      253 => 16#FF#,
      254 => 16#FF#,
      255 => 16#FF#];

   function Compare
     (Left_Item : Big_Value; Right_Item : Big_Value) return Integer is
   begin
      for Index_Value in Limb_Index loop
         if Left_Item (Index_Value) < Right_Item (Index_Value) then
            return -1;
         elsif Left_Item (Index_Value) > Right_Item (Index_Value) then
            return 1;
         end if;
      end loop;
      return 0;
   end Compare;

   function Is_Zero (Item : Big_Value) return Boolean is
   begin
      return Compare (Item, Zero_Value) = 0;
   end Is_Zero;

   function From_Fixed_Bytes (Data : Stream_Element_Array) return Big_Value is
      Result_Value : Big_Value := [others => 0];
      Source_Index : Stream_Element_Offset := Data'Last;
   begin
      for Offset_Value in reverse Limb_Index loop
         exit when Source_Index < Data'First;
         Result_Value (Offset_Value) := Natural (Data (Source_Index));
         Source_Index := Source_Index - 1;
      end loop;
      return Result_Value;
   end From_Fixed_Bytes;

   function From_Mpint
     (Data : Stream_Element_Array; Result_Value : out Big_Value) return Status
   is
      First_Index : Stream_Element_Offset := Data'First;
      Copy_Length : Natural;
   begin
      Result_Value := [others => 0];
      if Data'Length = 0 then
         return Handshake_Failed;
      end if;
      if Data (First_Index) = 0 then
         if Data'Length = 1 then
            return Handshake_Failed;
         end if;
         First_Index := First_Index + 1;
      elsif Data (First_Index) >= 16#80# then
         return Handshake_Failed;
      end if;
      Copy_Length := Natural (Data'Last - First_Index + 1);
      if Copy_Length > 256 then
         return Handshake_Failed;
      end if;
      Result_Value := From_Fixed_Bytes (Data (First_Index .. Data'Last));
      if Is_Zero (Result_Value) then
         return Handshake_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Result_Value := [others => 0];
         return Internal_Error;
   end From_Mpint;

   function Generate_Group14_Client_Value
     (Source_Item  : in out CryptoLib.Random.Random_Source;
      Public_Value : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Private_Value : CryptoLib.Buffers.Packet_Buffer;
   begin
      return
        Generate_Group14_Keypair (Source_Item, Private_Value, Public_Value);
   end Generate_Group14_Client_Value;

   procedure Subtract_In_Place_Group14
     (Left_Item : in out Big_Value; Right_Item : Big_Value)
   is
      Borrow_Value : Integer := 0;
      Diff_Value   : Integer;
   begin
      for Index_Value in reverse Limb_Index loop
         Diff_Value :=
           Left_Item (Index_Value) - Right_Item (Index_Value) - Borrow_Value;
         if Diff_Value < 0 then
            Diff_Value := Diff_Value + 256;
            Borrow_Value := 1;
         else
            Borrow_Value := 0;
         end if;
         Left_Item (Index_Value) := Diff_Value;
      end loop;
   end Subtract_In_Place_Group14;

   function Is_Valid_Public
     (Item : Big_Value; Prime_Value : Big_Value) return Boolean;

   function Is_Valid_Public_Group14 (Item : Big_Value) return Boolean is
   begin
      return Is_Valid_Public (Item, Group14_Prime);
   end Is_Valid_Public_Group14;

   function Is_Valid_Public
     (Item : Big_Value; Prime_Value : Big_Value) return Boolean
   is
      Lower_Bound : Big_Value := [others => 0];
      Upper_Bound : Big_Value := Prime_Value;
   begin
      Lower_Bound (255) := 1;
      Subtract_In_Place_Group14 (Upper_Bound, Lower_Bound);
      return
        Compare (Item, Lower_Bound) > 0
        and then Compare (Item, Upper_Bound) < 0;
   end Is_Valid_Public;

   function To_Fixed_Array_Group14
     (Item : Big_Value) return Stream_Element_Array
   is
      Result_Value : Stream_Element_Array (1 .. 256);
   begin
      for Index_Value in Limb_Index loop
         Result_Value (Stream_Element_Offset (Index_Value + 1)) :=
           Stream_Element (Item (Index_Value));
      end loop;
      return Result_Value;
   end To_Fixed_Array_Group14;

   function Set_Mpint_Group14
     (Buffer_Item : out CryptoLib.Buffers.Packet_Buffer;
      Value_Item  : Big_Value) return Status
   is
      First_Nonzero : Natural := 256;
      Raw_Data      : constant Stream_Element_Array :=
        To_Fixed_Array_Group14 (Value_Item);
   begin
      CryptoLib.Buffers.Clear (Buffer_Item);
      for Index_Value in Raw_Data'Range loop
         if Raw_Data (Index_Value) /= 0 then
            First_Nonzero := Natural (Index_Value);
            exit;
         end if;
      end loop;
      if First_Nonzero = 256 and then Raw_Data (256) = 0 then
         return
           CryptoLib.Buffers.Set
             (Buffer_Item, [1 => Stream_Element'(0)]);
      end if;
      if Raw_Data (Stream_Element_Offset (First_Nonzero)) >= 16#80# then
         declare
            Mpint_Data :
              Stream_Element_Array
                (1 .. Stream_Element_Offset (258 - First_Nonzero));
            Out_Index  : Stream_Element_Offset := Mpint_Data'First;
         begin
            Mpint_Data (Out_Index) := 0;
            Out_Index := Out_Index + 1;
            for Source_Index in
              Stream_Element_Offset (First_Nonzero) .. Raw_Data'Last
            loop
               Mpint_Data (Out_Index) := Raw_Data (Source_Index);
               Out_Index := Out_Index + 1;
            end loop;
            return CryptoLib.Buffers.Set (Buffer_Item, Mpint_Data);
         end;
      else
         return
           CryptoLib.Buffers.Set
             (Buffer_Item,
              Raw_Data
                (Stream_Element_Offset (First_Nonzero) .. Raw_Data'Last));
      end if;
   exception
      when others =>
         CryptoLib.Buffers.Clear (Buffer_Item);
         return Internal_Error;
   end Set_Mpint_Group14;

   function Generate_Group14_Private
     (Source_Item   : in out CryptoLib.Random.Random_Source;
      Private_Value : out Big_Value) return Status
   is
      --  RFC 3526 group14 has an estimated exponent range of 220-320 bits.
      --  Use a 256-bit random exponent for the 2048-bit group.
      Random_Data  : Stream_Element_Array (1 .. 32);
      Status_Value : Status;
   begin
      Private_Value := [others => 0];
      Status_Value := CryptoLib.Random.Fill (Source_Item, Random_Data);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Random_Data (1) := Random_Data (1) and 16#7F#;
      Random_Data (32) := Random_Data (32) or 1;
      for Offset_Value in 0 .. 31 loop
         Private_Value (224 + Offset_Value) :=
           Natural (Random_Data (Stream_Element_Offset (Offset_Value + 1)));
      end loop;
      if Is_Zero (Private_Value) then
         Private_Value (255) := 1;
      end if;
      return Ok;
   exception
      when others =>
         Private_Value := [others => 0];
         return Internal_Error;
   end Generate_Group14_Private;

   function Generate_Group1_Private
     (Source_Item   : in out CryptoLib.Random.Random_Source;
      Private_Value : out Big_Value) return Status
   is
      --  RFC 4253 group1 is a 1024-bit Oakley group.  Use a 160-bit random
      --  exponent for the legacy SHA-1 fallback boundary.
      Random_Data  : Stream_Element_Array (1 .. 20);
      Status_Value : Status;
   begin
      Private_Value := [others => 0];
      Status_Value := CryptoLib.Random.Fill (Source_Item, Random_Data);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Random_Data (1) := Random_Data (1) and 16#7F#;
      Random_Data (20) := Random_Data (20) or 1;
      for Offset_Value in 0 .. 19 loop
         Private_Value (236 + Offset_Value) :=
           Natural (Random_Data (Stream_Element_Offset (Offset_Value + 1)));
      end loop;
      if Is_Zero (Private_Value) then
         Private_Value (255) := 1;
      end if;
      return Ok;
   exception
      when others =>
         Private_Value := [others => 0];
         return Internal_Error;
   end Generate_Group1_Private;

   function Generate_Group1_Keypair
     (Source_Item   : in out CryptoLib.Random.Random_Source;
      Private_Value : out CryptoLib.Buffers.Packet_Buffer;
      Public_Value  : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Private_Big  : Big_Value;
      Public_Big   : Big_Value;
      Status_Value : Status;
   begin
      CryptoLib.Buffers.Clear (Private_Value);
      CryptoLib.Buffers.Clear (Public_Value);
      Status_Value := Generate_Group1_Private (Source_Item, Private_Big);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Public_Big :=
        From_Fixed_Bytes
          (CryptoLib.Modexp.Mod_Exp
             (Ada.Streams.Stream_Element_Array'(1 => 2),
              Exponent_Bytes (To_Fixed_Array_Group14 (Private_Big)),
              To_Fixed_Array_Group14 (Group1_Prime)));
      Status_Value :=
        CryptoLib.Buffers.Set
          (Private_Value, To_Fixed_Array_Group14 (Private_Big));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      return Set_Mpint_Group14 (Public_Value, Public_Big);
   exception
      when others =>
         CryptoLib.Buffers.Clear (Private_Value);
         CryptoLib.Buffers.Clear (Public_Value);
         return Internal_Error;
   end Generate_Group1_Keypair;

   function Compute_Group1_Shared_Secret
     (Client_Private_Placeholder : Ada.Streams.Stream_Element_Array;
      Server_Public_Value        : Ada.Streams.Stream_Element_Array;
      Shared_Secret              : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Private_Big  : Big_Value;
      Server_Big   : Big_Value;
      Shared_Big   : Big_Value;
      Status_Value : Status;
   begin
      CryptoLib.Buffers.Clear (Shared_Secret);
      if Client_Private_Placeholder'Length > 256 then
         return Handshake_Failed;
      end if;
      Private_Big := From_Fixed_Bytes (Client_Private_Placeholder);
      if Is_Zero (Private_Big) then
         return Handshake_Failed;
      end if;
      Status_Value := From_Mpint (Server_Public_Value, Server_Big);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if not Is_Valid_Public (Server_Big, Group1_Prime) then
         return Handshake_Failed;
      end if;
      Shared_Big :=
        From_Fixed_Bytes
          (CryptoLib.Modexp.Mod_Exp
             (To_Fixed_Array_Group14 (Server_Big),
              Exponent_Bytes (To_Fixed_Array_Group14 (Private_Big)),
              To_Fixed_Array_Group14 (Group1_Prime)));
      if Is_Zero (Shared_Big) then
         return Handshake_Failed;
      end if;
      return Set_Mpint_Group14 (Shared_Secret, Shared_Big);
   exception
      when others =>
         CryptoLib.Buffers.Clear (Shared_Secret);
         return Internal_Error;
   end Compute_Group1_Shared_Secret;

   function Generate_Group14_Keypair
     (Source_Item   : in out CryptoLib.Random.Random_Source;
      Private_Value : out CryptoLib.Buffers.Packet_Buffer;
      Public_Value  : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Private_Big  : Big_Value;
      Public_Big   : Big_Value;
      Status_Value : Status;
   begin
      CryptoLib.Buffers.Clear (Private_Value);
      CryptoLib.Buffers.Clear (Public_Value);
      Status_Value := Generate_Group14_Private (Source_Item, Private_Big);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Public_Big :=
        From_Fixed_Bytes
          (CryptoLib.Modexp.Mod_Exp
             (Ada.Streams.Stream_Element_Array'(1 => 2),
              Exponent_Bytes (To_Fixed_Array_Group14 (Private_Big)),
              To_Fixed_Array_Group14 (Group14_Prime)));
      Status_Value :=
        CryptoLib.Buffers.Set
          (Private_Value, To_Fixed_Array_Group14 (Private_Big));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      return Set_Mpint_Group14 (Public_Value, Public_Big);
   exception
      when others =>
         CryptoLib.Buffers.Clear (Private_Value);
         CryptoLib.Buffers.Clear (Public_Value);
         return Internal_Error;
   end Generate_Group14_Keypair;

   function Compute_Group14_Shared_Secret
     (Client_Private_Placeholder : Ada.Streams.Stream_Element_Array;
      Server_Public_Value        : Ada.Streams.Stream_Element_Array;
      Shared_Secret              : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Private_Big  : Big_Value;
      Server_Big   : Big_Value;
      Shared_Big   : Big_Value;
      Status_Value : Status;
   begin
      CryptoLib.Buffers.Clear (Shared_Secret);
      if Client_Private_Placeholder'Length > 256 then
         return Handshake_Failed;
      end if;
      Private_Big := From_Fixed_Bytes (Client_Private_Placeholder);
      if Is_Zero (Private_Big) then
         return Handshake_Failed;
      end if;
      Status_Value := From_Mpint (Server_Public_Value, Server_Big);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if not Is_Valid_Public_Group14 (Server_Big) then
         return Handshake_Failed;
      end if;
      Shared_Big :=
        From_Fixed_Bytes
          (CryptoLib.Modexp.Mod_Exp
             (To_Fixed_Array_Group14 (Server_Big),
              Exponent_Bytes (To_Fixed_Array_Group14 (Private_Big)),
              To_Fixed_Array_Group14 (Group14_Prime)));
      if Is_Zero (Shared_Big) then
         return Handshake_Failed;
      end if;
      return Set_Mpint_Group14 (Shared_Secret, Shared_Big);
   exception
      when others =>
         CryptoLib.Buffers.Clear (Shared_Secret);
         return Internal_Error;
   end Compute_Group14_Shared_Secret;

   subtype Group16_Limb_Index is Natural range 0 .. 511;
   type Group16_Value is array (Group16_Limb_Index) of Natural range 0 .. 255;

   Group16_Prime : constant Group16_Value :=
     [16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#C9#,
      16#0F#,
      16#DA#,
      16#A2#,
      16#21#,
      16#68#,
      16#C2#,
      16#34#,
      16#C4#,
      16#C6#,
      16#62#,
      16#8B#,
      16#80#,
      16#DC#,
      16#1C#,
      16#D1#,
      16#29#,
      16#02#,
      16#4E#,
      16#08#,
      16#8A#,
      16#67#,
      16#CC#,
      16#74#,
      16#02#,
      16#0B#,
      16#BE#,
      16#A6#,
      16#3B#,
      16#13#,
      16#9B#,
      16#22#,
      16#51#,
      16#4A#,
      16#08#,
      16#79#,
      16#8E#,
      16#34#,
      16#04#,
      16#DD#,
      16#EF#,
      16#95#,
      16#19#,
      16#B3#,
      16#CD#,
      16#3A#,
      16#43#,
      16#1B#,
      16#30#,
      16#2B#,
      16#0A#,
      16#6D#,
      16#F2#,
      16#5F#,
      16#14#,
      16#37#,
      16#4F#,
      16#E1#,
      16#35#,
      16#6D#,
      16#6D#,
      16#51#,
      16#C2#,
      16#45#,
      16#E4#,
      16#85#,
      16#B5#,
      16#76#,
      16#62#,
      16#5E#,
      16#7E#,
      16#C6#,
      16#F4#,
      16#4C#,
      16#42#,
      16#E9#,
      16#A6#,
      16#37#,
      16#ED#,
      16#6B#,
      16#0B#,
      16#FF#,
      16#5C#,
      16#B6#,
      16#F4#,
      16#06#,
      16#B7#,
      16#ED#,
      16#EE#,
      16#38#,
      16#6B#,
      16#FB#,
      16#5A#,
      16#89#,
      16#9F#,
      16#A5#,
      16#AE#,
      16#9F#,
      16#24#,
      16#11#,
      16#7C#,
      16#4B#,
      16#1F#,
      16#E6#,
      16#49#,
      16#28#,
      16#66#,
      16#51#,
      16#EC#,
      16#E4#,
      16#5B#,
      16#3D#,
      16#C2#,
      16#00#,
      16#7C#,
      16#B8#,
      16#A1#,
      16#63#,
      16#BF#,
      16#05#,
      16#98#,
      16#DA#,
      16#48#,
      16#36#,
      16#1C#,
      16#55#,
      16#D3#,
      16#9A#,
      16#69#,
      16#16#,
      16#3F#,
      16#A8#,
      16#FD#,
      16#24#,
      16#CF#,
      16#5F#,
      16#83#,
      16#65#,
      16#5D#,
      16#23#,
      16#DC#,
      16#A3#,
      16#AD#,
      16#96#,
      16#1C#,
      16#62#,
      16#F3#,
      16#56#,
      16#20#,
      16#85#,
      16#52#,
      16#BB#,
      16#9E#,
      16#D5#,
      16#29#,
      16#07#,
      16#70#,
      16#96#,
      16#96#,
      16#6D#,
      16#67#,
      16#0C#,
      16#35#,
      16#4E#,
      16#4A#,
      16#BC#,
      16#98#,
      16#04#,
      16#F1#,
      16#74#,
      16#6C#,
      16#08#,
      16#CA#,
      16#18#,
      16#21#,
      16#7C#,
      16#32#,
      16#90#,
      16#5E#,
      16#46#,
      16#2E#,
      16#36#,
      16#CE#,
      16#3B#,
      16#E3#,
      16#9E#,
      16#77#,
      16#2C#,
      16#18#,
      16#0E#,
      16#86#,
      16#03#,
      16#9B#,
      16#27#,
      16#83#,
      16#A2#,
      16#EC#,
      16#07#,
      16#A2#,
      16#8F#,
      16#B5#,
      16#C5#,
      16#5D#,
      16#F0#,
      16#6F#,
      16#4C#,
      16#52#,
      16#C9#,
      16#DE#,
      16#2B#,
      16#CB#,
      16#F6#,
      16#95#,
      16#58#,
      16#17#,
      16#18#,
      16#39#,
      16#95#,
      16#49#,
      16#7C#,
      16#EA#,
      16#95#,
      16#6A#,
      16#E5#,
      16#15#,
      16#D2#,
      16#26#,
      16#18#,
      16#98#,
      16#FA#,
      16#05#,
      16#10#,
      16#15#,
      16#72#,
      16#8E#,
      16#5A#,
      16#8A#,
      16#AA#,
      16#C4#,
      16#2D#,
      16#AD#,
      16#33#,
      16#17#,
      16#0D#,
      16#04#,
      16#50#,
      16#7A#,
      16#33#,
      16#A8#,
      16#55#,
      16#21#,
      16#AB#,
      16#DF#,
      16#1C#,
      16#BA#,
      16#64#,
      16#EC#,
      16#FB#,
      16#85#,
      16#04#,
      16#58#,
      16#DB#,
      16#EF#,
      16#0A#,
      16#8A#,
      16#EA#,
      16#71#,
      16#57#,
      16#5D#,
      16#06#,
      16#0C#,
      16#7D#,
      16#B3#,
      16#97#,
      16#0F#,
      16#85#,
      16#A6#,
      16#E1#,
      16#E4#,
      16#C7#,
      16#AB#,
      16#F5#,
      16#AE#,
      16#8C#,
      16#DB#,
      16#09#,
      16#33#,
      16#D7#,
      16#1E#,
      16#8C#,
      16#94#,
      16#E0#,
      16#4A#,
      16#25#,
      16#61#,
      16#9D#,
      16#CE#,
      16#E3#,
      16#D2#,
      16#26#,
      16#1A#,
      16#D2#,
      16#EE#,
      16#6B#,
      16#F1#,
      16#2F#,
      16#FA#,
      16#06#,
      16#D9#,
      16#8A#,
      16#08#,
      16#64#,
      16#D8#,
      16#76#,
      16#02#,
      16#73#,
      16#3E#,
      16#C8#,
      16#6A#,
      16#64#,
      16#52#,
      16#1F#,
      16#2B#,
      16#18#,
      16#17#,
      16#7B#,
      16#20#,
      16#0C#,
      16#BB#,
      16#E1#,
      16#17#,
      16#57#,
      16#7A#,
      16#61#,
      16#5D#,
      16#6C#,
      16#77#,
      16#09#,
      16#88#,
      16#C0#,
      16#BA#,
      16#D9#,
      16#46#,
      16#E2#,
      16#08#,
      16#E2#,
      16#4F#,
      16#A0#,
      16#74#,
      16#E5#,
      16#AB#,
      16#31#,
      16#43#,
      16#DB#,
      16#5B#,
      16#FC#,
      16#E0#,
      16#FD#,
      16#10#,
      16#8E#,
      16#4B#,
      16#82#,
      16#D1#,
      16#20#,
      16#A9#,
      16#21#,
      16#08#,
      16#01#,
      16#1A#,
      16#72#,
      16#3C#,
      16#12#,
      16#A7#,
      16#87#,
      16#E6#,
      16#D7#,
      16#88#,
      16#71#,
      16#9A#,
      16#10#,
      16#BD#,
      16#BA#,
      16#5B#,
      16#26#,
      16#99#,
      16#C3#,
      16#27#,
      16#18#,
      16#6A#,
      16#F4#,
      16#E2#,
      16#3C#,
      16#1A#,
      16#94#,
      16#68#,
      16#34#,
      16#B6#,
      16#15#,
      16#0B#,
      16#DA#,
      16#25#,
      16#83#,
      16#E9#,
      16#CA#,
      16#2A#,
      16#D4#,
      16#4C#,
      16#E8#,
      16#DB#,
      16#BB#,
      16#C2#,
      16#DB#,
      16#04#,
      16#DE#,
      16#8E#,
      16#F9#,
      16#2E#,
      16#8E#,
      16#FC#,
      16#14#,
      16#1F#,
      16#BE#,
      16#CA#,
      16#A6#,
      16#28#,
      16#7C#,
      16#59#,
      16#47#,
      16#4E#,
      16#6B#,
      16#C0#,
      16#5D#,
      16#99#,
      16#B2#,
      16#96#,
      16#4F#,
      16#A0#,
      16#90#,
      16#C3#,
      16#A2#,
      16#23#,
      16#3B#,
      16#A1#,
      16#86#,
      16#51#,
      16#5B#,
      16#E7#,
      16#ED#,
      16#1F#,
      16#61#,
      16#29#,
      16#70#,
      16#CE#,
      16#E2#,
      16#D7#,
      16#AF#,
      16#B8#,
      16#1B#,
      16#DD#,
      16#76#,
      16#21#,
      16#70#,
      16#48#,
      16#1C#,
      16#D0#,
      16#06#,
      16#91#,
      16#27#,
      16#D5#,
      16#B0#,
      16#5A#,
      16#A9#,
      16#93#,
      16#B4#,
      16#EA#,
      16#98#,
      16#8D#,
      16#8F#,
      16#DD#,
      16#C1#,
      16#86#,
      16#FF#,
      16#B7#,
      16#DC#,
      16#90#,
      16#A6#,
      16#C0#,
      16#8F#,
      16#4D#,
      16#F4#,
      16#35#,
      16#C9#,
      16#34#,
      16#06#,
      16#31#,
      16#99#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#];

   Zero_Group16 : constant Group16_Value := [others => 0];

   function Compare_Group16
     (Left_Item : Group16_Value; Right_Item : Group16_Value) return Integer is
   begin
      for Index_Value in Group16_Limb_Index loop
         if Left_Item (Index_Value) < Right_Item (Index_Value) then
            return -1;
         elsif Left_Item (Index_Value) > Right_Item (Index_Value) then
            return 1;
         end if;
      end loop;
      return 0;
   end Compare_Group16;

   function Is_Zero_Group16 (Item : Group16_Value) return Boolean is
   begin
      return Compare_Group16 (Item, Zero_Group16) = 0;
   end Is_Zero_Group16;

   function From_Fixed_Bytes_Group16
     (Data : Stream_Element_Array) return Group16_Value
   is
      Result_Value : Group16_Value := [others => 0];
      Source_Index : Stream_Element_Offset := Data'Last;
   begin
      for Offset_Value in reverse Group16_Limb_Index loop
         exit when Source_Index < Data'First;
         Result_Value (Offset_Value) := Natural (Data (Source_Index));
         Source_Index := Source_Index - 1;
      end loop;
      return Result_Value;
   end From_Fixed_Bytes_Group16;

   function From_Mpint_Group16
     (Data : Stream_Element_Array; Result_Value : out Group16_Value)
      return Status
   is
      First_Index : Stream_Element_Offset := Data'First;
      Copy_Length : Natural;
   begin
      Result_Value := [others => 0];
      if Data'Length = 0 then
         return Handshake_Failed;
      end if;
      if Data (First_Index) = 0 then
         if Data'Length = 1 then
            return Handshake_Failed;
         end if;
         First_Index := First_Index + 1;
      elsif Data (First_Index) >= 16#80# then
         return Handshake_Failed;
      end if;
      Copy_Length := Natural (Data'Last - First_Index + 1);
      if Copy_Length > 512 then
         return Handshake_Failed;
      end if;
      Result_Value :=
        From_Fixed_Bytes_Group16 (Data (First_Index .. Data'Last));
      if Is_Zero_Group16 (Result_Value) then
         return Handshake_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Result_Value := [others => 0];
         return Internal_Error;
   end From_Mpint_Group16;

   procedure Subtract_In_Place_Group16
     (Left_Item : in out Group16_Value; Right_Item : Group16_Value)
   is
      Borrow_Value : Integer := 0;
      Diff_Value   : Integer;
   begin
      for Index_Value in reverse Group16_Limb_Index loop
         Diff_Value :=
           Left_Item (Index_Value) - Right_Item (Index_Value) - Borrow_Value;
         if Diff_Value < 0 then
            Diff_Value := Diff_Value + 256;
            Borrow_Value := 1;
         else
            Borrow_Value := 0;
         end if;
         Left_Item (Index_Value) := Diff_Value;
      end loop;
   end Subtract_In_Place_Group16;

   function Is_Valid_Public_Group16 (Item : Group16_Value) return Boolean is
      Lower_Bound : Group16_Value := [others => 0];
      Upper_Bound : Group16_Value := Group16_Prime;
   begin
      Lower_Bound (511) := 1;
      Subtract_In_Place_Group16 (Upper_Bound, Lower_Bound);
      return
        Compare_Group16 (Item, Lower_Bound) > 0
        and then Compare_Group16 (Item, Upper_Bound) < 0;
   end Is_Valid_Public_Group16;

   function To_Fixed_Array_Group16
     (Item : Group16_Value) return Stream_Element_Array
   is
      Result_Value : Stream_Element_Array (1 .. 512);
   begin
      for Index_Value in Group16_Limb_Index loop
         Result_Value (Stream_Element_Offset (Index_Value + 1)) :=
           Stream_Element (Item (Index_Value));
      end loop;
      return Result_Value;
   end To_Fixed_Array_Group16;

   function Set_Mpint_Group16
     (Buffer_Item : out CryptoLib.Buffers.Packet_Buffer;
      Value_Item  : Group16_Value) return Status
   is
      First_Nonzero : Natural := 512;
      Raw_Data      : constant Stream_Element_Array :=
        To_Fixed_Array_Group16 (Value_Item);
   begin
      CryptoLib.Buffers.Clear (Buffer_Item);
      for Index_Value in Raw_Data'Range loop
         if Raw_Data (Index_Value) /= 0 then
            First_Nonzero := Natural (Index_Value);
            exit;
         end if;
      end loop;
      if First_Nonzero = 512 and then Raw_Data (512) = 0 then
         return
           CryptoLib.Buffers.Set
             (Buffer_Item, [1 => Stream_Element'(0)]);
      end if;
      if Raw_Data (Stream_Element_Offset (First_Nonzero)) >= 16#80# then
         declare
            Mpint_Data :
              Stream_Element_Array
                (1 .. Stream_Element_Offset (514 - First_Nonzero));
            Out_Index  : Stream_Element_Offset := Mpint_Data'First;
         begin
            Mpint_Data (Out_Index) := 0;
            Out_Index := Out_Index + 1;
            for Source_Index in
              Stream_Element_Offset (First_Nonzero) .. Raw_Data'Last
            loop
               Mpint_Data (Out_Index) := Raw_Data (Source_Index);
               Out_Index := Out_Index + 1;
            end loop;
            return CryptoLib.Buffers.Set (Buffer_Item, Mpint_Data);
         end;
      else
         return
           CryptoLib.Buffers.Set
             (Buffer_Item,
              Raw_Data
                (Stream_Element_Offset (First_Nonzero) .. Raw_Data'Last));
      end if;
   exception
      when others =>
         CryptoLib.Buffers.Clear (Buffer_Item);
         return Internal_Error;
   end Set_Mpint_Group16;

   function Generate_Group16_Private
     (Source_Item   : in out CryptoLib.Random.Random_Source;
      Private_Value : out Group16_Value) return Status
   is
      --  RFC 3526 group16 has an estimated exponent range of 300-480 bits.
      --  Use a 512-bit random exponent to avoid weakening the 4096-bit group.
      Random_Data  : Stream_Element_Array (1 .. 64);
      Status_Value : Status;
   begin
      Private_Value := [others => 0];
      Status_Value := CryptoLib.Random.Fill (Source_Item, Random_Data);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Random_Data (1) := Random_Data (1) and 16#7F#;
      Random_Data (64) := Random_Data (64) or 1;
      for Offset_Value in 0 .. 63 loop
         Private_Value (448 + Offset_Value) :=
           Natural (Random_Data (Stream_Element_Offset (Offset_Value + 1)));
      end loop;
      if Is_Zero_Group16 (Private_Value) then
         Private_Value (511) := 1;
      end if;
      return Ok;
   exception
      when others =>
         Private_Value := [others => 0];
         return Internal_Error;
   end Generate_Group16_Private;

   function Generate_Group16_Keypair
     (Source_Item   : in out CryptoLib.Random.Random_Source;
      Private_Value : out CryptoLib.Buffers.Packet_Buffer;
      Public_Value  : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Private_Big  : Group16_Value;
      Public_Big   : Group16_Value;
      Status_Value : Status;
   begin
      CryptoLib.Buffers.Clear (Private_Value);
      CryptoLib.Buffers.Clear (Public_Value);
      Status_Value := Generate_Group16_Private (Source_Item, Private_Big);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      --  4096-bit modexp exceeds GNAT Big_Integers' cap; use Montgomery.
      Public_Big :=
        From_Fixed_Bytes_Group16
          (CryptoLib.Modexp.Mod_Exp
             (Ada.Streams.Stream_Element_Array'(1 => 2),
              Exponent_Bytes (To_Fixed_Array_Group16 (Private_Big)),
              To_Fixed_Array_Group16 (Group16_Prime)));
      Status_Value :=
        CryptoLib.Buffers.Set
          (Private_Value, To_Fixed_Array_Group16 (Private_Big));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      return Set_Mpint_Group16 (Public_Value, Public_Big);
   exception
      when others =>
         CryptoLib.Buffers.Clear (Private_Value);
         CryptoLib.Buffers.Clear (Public_Value);
         return Internal_Error;
   end Generate_Group16_Keypair;

   function Compute_Group16_Shared_Secret
     (Client_Private_Placeholder : Ada.Streams.Stream_Element_Array;
      Server_Public_Value        : Ada.Streams.Stream_Element_Array;
      Shared_Secret              : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Private_Big  : Group16_Value;
      Server_Big   : Group16_Value;
      Shared_Big   : Group16_Value;
      Status_Value : Status;
   begin
      CryptoLib.Buffers.Clear (Shared_Secret);
      if Client_Private_Placeholder'Length > 512 then
         return Handshake_Failed;
      end if;
      Private_Big := From_Fixed_Bytes_Group16 (Client_Private_Placeholder);
      if Is_Zero_Group16 (Private_Big) then
         return Handshake_Failed;
      end if;
      Status_Value := From_Mpint_Group16 (Server_Public_Value, Server_Big);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if not Is_Valid_Public_Group16 (Server_Big) then
         return Handshake_Failed;
      end if;
      Shared_Big :=
        From_Fixed_Bytes_Group16
          (CryptoLib.Modexp.Mod_Exp
             (To_Fixed_Array_Group16 (Server_Big),
              Exponent_Bytes (To_Fixed_Array_Group16 (Private_Big)),
              To_Fixed_Array_Group16 (Group16_Prime)));
      if Is_Zero_Group16 (Shared_Big) then
         return Handshake_Failed;
      end if;
      return Set_Mpint_Group16 (Shared_Secret, Shared_Big);
   exception
      when others =>
         CryptoLib.Buffers.Clear (Shared_Secret);
         return Internal_Error;
   end Compute_Group16_Shared_Secret;

   subtype Group18_Limb_Index is Natural range 0 .. 1023;
   type Group18_Value is array (Group18_Limb_Index) of Natural range 0 .. 255;

   Group18_Prime : constant Group18_Value :=
     [16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#C9#,
      16#0F#,
      16#DA#,
      16#A2#,
      16#21#,
      16#68#,
      16#C2#,
      16#34#,
      16#C4#,
      16#C6#,
      16#62#,
      16#8B#,
      16#80#,
      16#DC#,
      16#1C#,
      16#D1#,
      16#29#,
      16#02#,
      16#4E#,
      16#08#,
      16#8A#,
      16#67#,
      16#CC#,
      16#74#,
      16#02#,
      16#0B#,
      16#BE#,
      16#A6#,
      16#3B#,
      16#13#,
      16#9B#,
      16#22#,
      16#51#,
      16#4A#,
      16#08#,
      16#79#,
      16#8E#,
      16#34#,
      16#04#,
      16#DD#,
      16#EF#,
      16#95#,
      16#19#,
      16#B3#,
      16#CD#,
      16#3A#,
      16#43#,
      16#1B#,
      16#30#,
      16#2B#,
      16#0A#,
      16#6D#,
      16#F2#,
      16#5F#,
      16#14#,
      16#37#,
      16#4F#,
      16#E1#,
      16#35#,
      16#6D#,
      16#6D#,
      16#51#,
      16#C2#,
      16#45#,
      16#E4#,
      16#85#,
      16#B5#,
      16#76#,
      16#62#,
      16#5E#,
      16#7E#,
      16#C6#,
      16#F4#,
      16#4C#,
      16#42#,
      16#E9#,
      16#A6#,
      16#37#,
      16#ED#,
      16#6B#,
      16#0B#,
      16#FF#,
      16#5C#,
      16#B6#,
      16#F4#,
      16#06#,
      16#B7#,
      16#ED#,
      16#EE#,
      16#38#,
      16#6B#,
      16#FB#,
      16#5A#,
      16#89#,
      16#9F#,
      16#A5#,
      16#AE#,
      16#9F#,
      16#24#,
      16#11#,
      16#7C#,
      16#4B#,
      16#1F#,
      16#E6#,
      16#49#,
      16#28#,
      16#66#,
      16#51#,
      16#EC#,
      16#E4#,
      16#5B#,
      16#3D#,
      16#C2#,
      16#00#,
      16#7C#,
      16#B8#,
      16#A1#,
      16#63#,
      16#BF#,
      16#05#,
      16#98#,
      16#DA#,
      16#48#,
      16#36#,
      16#1C#,
      16#55#,
      16#D3#,
      16#9A#,
      16#69#,
      16#16#,
      16#3F#,
      16#A8#,
      16#FD#,
      16#24#,
      16#CF#,
      16#5F#,
      16#83#,
      16#65#,
      16#5D#,
      16#23#,
      16#DC#,
      16#A3#,
      16#AD#,
      16#96#,
      16#1C#,
      16#62#,
      16#F3#,
      16#56#,
      16#20#,
      16#85#,
      16#52#,
      16#BB#,
      16#9E#,
      16#D5#,
      16#29#,
      16#07#,
      16#70#,
      16#96#,
      16#96#,
      16#6D#,
      16#67#,
      16#0C#,
      16#35#,
      16#4E#,
      16#4A#,
      16#BC#,
      16#98#,
      16#04#,
      16#F1#,
      16#74#,
      16#6C#,
      16#08#,
      16#CA#,
      16#18#,
      16#21#,
      16#7C#,
      16#32#,
      16#90#,
      16#5E#,
      16#46#,
      16#2E#,
      16#36#,
      16#CE#,
      16#3B#,
      16#E3#,
      16#9E#,
      16#77#,
      16#2C#,
      16#18#,
      16#0E#,
      16#86#,
      16#03#,
      16#9B#,
      16#27#,
      16#83#,
      16#A2#,
      16#EC#,
      16#07#,
      16#A2#,
      16#8F#,
      16#B5#,
      16#C5#,
      16#5D#,
      16#F0#,
      16#6F#,
      16#4C#,
      16#52#,
      16#C9#,
      16#DE#,
      16#2B#,
      16#CB#,
      16#F6#,
      16#95#,
      16#58#,
      16#17#,
      16#18#,
      16#39#,
      16#95#,
      16#49#,
      16#7C#,
      16#EA#,
      16#95#,
      16#6A#,
      16#E5#,
      16#15#,
      16#D2#,
      16#26#,
      16#18#,
      16#98#,
      16#FA#,
      16#05#,
      16#10#,
      16#15#,
      16#72#,
      16#8E#,
      16#5A#,
      16#8A#,
      16#AA#,
      16#C4#,
      16#2D#,
      16#AD#,
      16#33#,
      16#17#,
      16#0D#,
      16#04#,
      16#50#,
      16#7A#,
      16#33#,
      16#A8#,
      16#55#,
      16#21#,
      16#AB#,
      16#DF#,
      16#1C#,
      16#BA#,
      16#64#,
      16#EC#,
      16#FB#,
      16#85#,
      16#04#,
      16#58#,
      16#DB#,
      16#EF#,
      16#0A#,
      16#8A#,
      16#EA#,
      16#71#,
      16#57#,
      16#5D#,
      16#06#,
      16#0C#,
      16#7D#,
      16#B3#,
      16#97#,
      16#0F#,
      16#85#,
      16#A6#,
      16#E1#,
      16#E4#,
      16#C7#,
      16#AB#,
      16#F5#,
      16#AE#,
      16#8C#,
      16#DB#,
      16#09#,
      16#33#,
      16#D7#,
      16#1E#,
      16#8C#,
      16#94#,
      16#E0#,
      16#4A#,
      16#25#,
      16#61#,
      16#9D#,
      16#CE#,
      16#E3#,
      16#D2#,
      16#26#,
      16#1A#,
      16#D2#,
      16#EE#,
      16#6B#,
      16#F1#,
      16#2F#,
      16#FA#,
      16#06#,
      16#D9#,
      16#8A#,
      16#08#,
      16#64#,
      16#D8#,
      16#76#,
      16#02#,
      16#73#,
      16#3E#,
      16#C8#,
      16#6A#,
      16#64#,
      16#52#,
      16#1F#,
      16#2B#,
      16#18#,
      16#17#,
      16#7B#,
      16#20#,
      16#0C#,
      16#BB#,
      16#E1#,
      16#17#,
      16#57#,
      16#7A#,
      16#61#,
      16#5D#,
      16#6C#,
      16#77#,
      16#09#,
      16#88#,
      16#C0#,
      16#BA#,
      16#D9#,
      16#46#,
      16#E2#,
      16#08#,
      16#E2#,
      16#4F#,
      16#A0#,
      16#74#,
      16#E5#,
      16#AB#,
      16#31#,
      16#43#,
      16#DB#,
      16#5B#,
      16#FC#,
      16#E0#,
      16#FD#,
      16#10#,
      16#8E#,
      16#4B#,
      16#82#,
      16#D1#,
      16#20#,
      16#A9#,
      16#21#,
      16#08#,
      16#01#,
      16#1A#,
      16#72#,
      16#3C#,
      16#12#,
      16#A7#,
      16#87#,
      16#E6#,
      16#D7#,
      16#88#,
      16#71#,
      16#9A#,
      16#10#,
      16#BD#,
      16#BA#,
      16#5B#,
      16#26#,
      16#99#,
      16#C3#,
      16#27#,
      16#18#,
      16#6A#,
      16#F4#,
      16#E2#,
      16#3C#,
      16#1A#,
      16#94#,
      16#68#,
      16#34#,
      16#B6#,
      16#15#,
      16#0B#,
      16#DA#,
      16#25#,
      16#83#,
      16#E9#,
      16#CA#,
      16#2A#,
      16#D4#,
      16#4C#,
      16#E8#,
      16#DB#,
      16#BB#,
      16#C2#,
      16#DB#,
      16#04#,
      16#DE#,
      16#8E#,
      16#F9#,
      16#2E#,
      16#8E#,
      16#FC#,
      16#14#,
      16#1F#,
      16#BE#,
      16#CA#,
      16#A6#,
      16#28#,
      16#7C#,
      16#59#,
      16#47#,
      16#4E#,
      16#6B#,
      16#C0#,
      16#5D#,
      16#99#,
      16#B2#,
      16#96#,
      16#4F#,
      16#A0#,
      16#90#,
      16#C3#,
      16#A2#,
      16#23#,
      16#3B#,
      16#A1#,
      16#86#,
      16#51#,
      16#5B#,
      16#E7#,
      16#ED#,
      16#1F#,
      16#61#,
      16#29#,
      16#70#,
      16#CE#,
      16#E2#,
      16#D7#,
      16#AF#,
      16#B8#,
      16#1B#,
      16#DD#,
      16#76#,
      16#21#,
      16#70#,
      16#48#,
      16#1C#,
      16#D0#,
      16#06#,
      16#91#,
      16#27#,
      16#D5#,
      16#B0#,
      16#5A#,
      16#A9#,
      16#93#,
      16#B4#,
      16#EA#,
      16#98#,
      16#8D#,
      16#8F#,
      16#DD#,
      16#C1#,
      16#86#,
      16#FF#,
      16#B7#,
      16#DC#,
      16#90#,
      16#A6#,
      16#C0#,
      16#8F#,
      16#4D#,
      16#F4#,
      16#35#,
      16#C9#,
      16#34#,
      16#02#,
      16#84#,
      16#92#,
      16#36#,
      16#C3#,
      16#FA#,
      16#B4#,
      16#D2#,
      16#7C#,
      16#70#,
      16#26#,
      16#C1#,
      16#D4#,
      16#DC#,
      16#B2#,
      16#60#,
      16#26#,
      16#46#,
      16#DE#,
      16#C9#,
      16#75#,
      16#1E#,
      16#76#,
      16#3D#,
      16#BA#,
      16#37#,
      16#BD#,
      16#F8#,
      16#FF#,
      16#94#,
      16#06#,
      16#AD#,
      16#9E#,
      16#53#,
      16#0E#,
      16#E5#,
      16#DB#,
      16#38#,
      16#2F#,
      16#41#,
      16#30#,
      16#01#,
      16#AE#,
      16#B0#,
      16#6A#,
      16#53#,
      16#ED#,
      16#90#,
      16#27#,
      16#D8#,
      16#31#,
      16#17#,
      16#97#,
      16#27#,
      16#B0#,
      16#86#,
      16#5A#,
      16#89#,
      16#18#,
      16#DA#,
      16#3E#,
      16#DB#,
      16#EB#,
      16#CF#,
      16#9B#,
      16#14#,
      16#ED#,
      16#44#,
      16#CE#,
      16#6C#,
      16#BA#,
      16#CE#,
      16#D4#,
      16#BB#,
      16#1B#,
      16#DB#,
      16#7F#,
      16#14#,
      16#47#,
      16#E6#,
      16#CC#,
      16#25#,
      16#4B#,
      16#33#,
      16#20#,
      16#51#,
      16#51#,
      16#2B#,
      16#D7#,
      16#AF#,
      16#42#,
      16#6F#,
      16#B8#,
      16#F4#,
      16#01#,
      16#37#,
      16#8C#,
      16#D2#,
      16#BF#,
      16#59#,
      16#83#,
      16#CA#,
      16#01#,
      16#C6#,
      16#4B#,
      16#92#,
      16#EC#,
      16#F0#,
      16#32#,
      16#EA#,
      16#15#,
      16#D1#,
      16#72#,
      16#1D#,
      16#03#,
      16#F4#,
      16#82#,
      16#D7#,
      16#CE#,
      16#6E#,
      16#74#,
      16#FE#,
      16#F6#,
      16#D5#,
      16#5E#,
      16#70#,
      16#2F#,
      16#46#,
      16#98#,
      16#0C#,
      16#82#,
      16#B5#,
      16#A8#,
      16#40#,
      16#31#,
      16#90#,
      16#0B#,
      16#1C#,
      16#9E#,
      16#59#,
      16#E7#,
      16#C9#,
      16#7F#,
      16#BE#,
      16#C7#,
      16#E8#,
      16#F3#,
      16#23#,
      16#A9#,
      16#7A#,
      16#7E#,
      16#36#,
      16#CC#,
      16#88#,
      16#BE#,
      16#0F#,
      16#1D#,
      16#45#,
      16#B7#,
      16#FF#,
      16#58#,
      16#5A#,
      16#C5#,
      16#4B#,
      16#D4#,
      16#07#,
      16#B2#,
      16#2B#,
      16#41#,
      16#54#,
      16#AA#,
      16#CC#,
      16#8F#,
      16#6D#,
      16#7E#,
      16#BF#,
      16#48#,
      16#E1#,
      16#D8#,
      16#14#,
      16#CC#,
      16#5E#,
      16#D2#,
      16#0F#,
      16#80#,
      16#37#,
      16#E0#,
      16#A7#,
      16#97#,
      16#15#,
      16#EE#,
      16#F2#,
      16#9B#,
      16#E3#,
      16#28#,
      16#06#,
      16#A1#,
      16#D5#,
      16#8B#,
      16#B7#,
      16#C5#,
      16#DA#,
      16#76#,
      16#F5#,
      16#50#,
      16#AA#,
      16#3D#,
      16#8A#,
      16#1F#,
      16#BF#,
      16#F0#,
      16#EB#,
      16#19#,
      16#CC#,
      16#B1#,
      16#A3#,
      16#13#,
      16#D5#,
      16#5C#,
      16#DA#,
      16#56#,
      16#C9#,
      16#EC#,
      16#2E#,
      16#F2#,
      16#96#,
      16#32#,
      16#38#,
      16#7F#,
      16#E8#,
      16#D7#,
      16#6E#,
      16#3C#,
      16#04#,
      16#68#,
      16#04#,
      16#3E#,
      16#8F#,
      16#66#,
      16#3F#,
      16#48#,
      16#60#,
      16#EE#,
      16#12#,
      16#BF#,
      16#2D#,
      16#5B#,
      16#0B#,
      16#74#,
      16#74#,
      16#D6#,
      16#E6#,
      16#94#,
      16#F9#,
      16#1E#,
      16#6D#,
      16#BE#,
      16#11#,
      16#59#,
      16#74#,
      16#A3#,
      16#92#,
      16#6F#,
      16#12#,
      16#FE#,
      16#E5#,
      16#E4#,
      16#38#,
      16#77#,
      16#7C#,
      16#B6#,
      16#A9#,
      16#32#,
      16#DF#,
      16#8C#,
      16#D8#,
      16#BE#,
      16#C4#,
      16#D0#,
      16#73#,
      16#B9#,
      16#31#,
      16#BA#,
      16#3B#,
      16#C8#,
      16#32#,
      16#B6#,
      16#8D#,
      16#9D#,
      16#D3#,
      16#00#,
      16#74#,
      16#1F#,
      16#A7#,
      16#BF#,
      16#8A#,
      16#FC#,
      16#47#,
      16#ED#,
      16#25#,
      16#76#,
      16#F6#,
      16#93#,
      16#6B#,
      16#A4#,
      16#24#,
      16#66#,
      16#3A#,
      16#AB#,
      16#63#,
      16#9C#,
      16#5A#,
      16#E4#,
      16#F5#,
      16#68#,
      16#34#,
      16#23#,
      16#B4#,
      16#74#,
      16#2B#,
      16#F1#,
      16#C9#,
      16#78#,
      16#23#,
      16#8F#,
      16#16#,
      16#CB#,
      16#E3#,
      16#9D#,
      16#65#,
      16#2D#,
      16#E3#,
      16#FD#,
      16#B8#,
      16#BE#,
      16#FC#,
      16#84#,
      16#8A#,
      16#D9#,
      16#22#,
      16#22#,
      16#2E#,
      16#04#,
      16#A4#,
      16#03#,
      16#7C#,
      16#07#,
      16#13#,
      16#EB#,
      16#57#,
      16#A8#,
      16#1A#,
      16#23#,
      16#F0#,
      16#C7#,
      16#34#,
      16#73#,
      16#FC#,
      16#64#,
      16#6C#,
      16#EA#,
      16#30#,
      16#6B#,
      16#4B#,
      16#CB#,
      16#C8#,
      16#86#,
      16#2F#,
      16#83#,
      16#85#,
      16#DD#,
      16#FA#,
      16#9D#,
      16#4B#,
      16#7F#,
      16#A2#,
      16#C0#,
      16#87#,
      16#E8#,
      16#79#,
      16#68#,
      16#33#,
      16#03#,
      16#ED#,
      16#5B#,
      16#DD#,
      16#3A#,
      16#06#,
      16#2B#,
      16#3C#,
      16#F5#,
      16#B3#,
      16#A2#,
      16#78#,
      16#A6#,
      16#6D#,
      16#2A#,
      16#13#,
      16#F8#,
      16#3F#,
      16#44#,
      16#F8#,
      16#2D#,
      16#DF#,
      16#31#,
      16#0E#,
      16#E0#,
      16#74#,
      16#AB#,
      16#6A#,
      16#36#,
      16#45#,
      16#97#,
      16#E8#,
      16#99#,
      16#A0#,
      16#25#,
      16#5D#,
      16#C1#,
      16#64#,
      16#F3#,
      16#1C#,
      16#C5#,
      16#08#,
      16#46#,
      16#85#,
      16#1D#,
      16#F9#,
      16#AB#,
      16#48#,
      16#19#,
      16#5D#,
      16#ED#,
      16#7E#,
      16#A1#,
      16#B1#,
      16#D5#,
      16#10#,
      16#BD#,
      16#7E#,
      16#E7#,
      16#4D#,
      16#73#,
      16#FA#,
      16#F3#,
      16#6B#,
      16#C3#,
      16#1E#,
      16#CF#,
      16#A2#,
      16#68#,
      16#35#,
      16#90#,
      16#46#,
      16#F4#,
      16#EB#,
      16#87#,
      16#9F#,
      16#92#,
      16#40#,
      16#09#,
      16#43#,
      16#8B#,
      16#48#,
      16#1C#,
      16#6C#,
      16#D7#,
      16#88#,
      16#9A#,
      16#00#,
      16#2E#,
      16#D5#,
      16#EE#,
      16#38#,
      16#2B#,
      16#C9#,
      16#19#,
      16#0D#,
      16#A6#,
      16#FC#,
      16#02#,
      16#6E#,
      16#47#,
      16#95#,
      16#58#,
      16#E4#,
      16#47#,
      16#56#,
      16#77#,
      16#E9#,
      16#AA#,
      16#9E#,
      16#30#,
      16#50#,
      16#E2#,
      16#76#,
      16#56#,
      16#94#,
      16#DF#,
      16#C8#,
      16#1F#,
      16#56#,
      16#E8#,
      16#80#,
      16#B9#,
      16#6E#,
      16#71#,
      16#60#,
      16#C9#,
      16#80#,
      16#DD#,
      16#98#,
      16#ED#,
      16#D3#,
      16#DF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#];

   Zero_Group18 : constant Group18_Value := [others => 0];

   function Compare_Group18
     (Left_Item : Group18_Value; Right_Item : Group18_Value) return Integer is
   begin
      for Index_Value in Group18_Limb_Index loop
         if Left_Item (Index_Value) < Right_Item (Index_Value) then
            return -1;
         elsif Left_Item (Index_Value) > Right_Item (Index_Value) then
            return 1;
         end if;
      end loop;
      return 0;
   end Compare_Group18;

   function Is_Zero_Group18 (Item : Group18_Value) return Boolean is
   begin
      return Compare_Group18 (Item, Zero_Group18) = 0;
   end Is_Zero_Group18;

   function From_Fixed_Bytes_Group18
     (Data : Stream_Element_Array) return Group18_Value
   is
      Result_Value : Group18_Value := [others => 0];
      Source_Index : Stream_Element_Offset := Data'Last;
   begin
      for Offset_Value in reverse Group18_Limb_Index loop
         exit when Source_Index < Data'First;
         Result_Value (Offset_Value) := Natural (Data (Source_Index));
         Source_Index := Source_Index - 1;
      end loop;
      return Result_Value;
   end From_Fixed_Bytes_Group18;

   function From_Mpint_Group18
     (Data : Stream_Element_Array; Result_Value : out Group18_Value)
      return Status
   is
      First_Index : Stream_Element_Offset := Data'First;
      Copy_Length : Natural;
   begin
      Result_Value := [others => 0];
      if Data'Length = 0 then
         return Handshake_Failed;
      end if;
      if Data (First_Index) = 0 then
         if Data'Length = 1 then
            return Handshake_Failed;
         end if;
         First_Index := First_Index + 1;
      elsif Data (First_Index) >= 16#80# then
         return Handshake_Failed;
      end if;
      Copy_Length := Natural (Data'Last - First_Index + 1);
      if Copy_Length > 1024 then
         return Handshake_Failed;
      end if;
      Result_Value :=
        From_Fixed_Bytes_Group18 (Data (First_Index .. Data'Last));
      if Is_Zero_Group18 (Result_Value) then
         return Handshake_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Result_Value := [others => 0];
         return Internal_Error;
   end From_Mpint_Group18;

   procedure Subtract_In_Place_Group18
     (Left_Item : in out Group18_Value; Right_Item : Group18_Value)
   is
      Borrow_Value : Integer := 0;
      Diff_Value   : Integer;
   begin
      for Index_Value in reverse Group18_Limb_Index loop
         Diff_Value :=
           Left_Item (Index_Value) - Right_Item (Index_Value) - Borrow_Value;
         if Diff_Value < 0 then
            Diff_Value := Diff_Value + 256;
            Borrow_Value := 1;
         else
            Borrow_Value := 0;
         end if;
         Left_Item (Index_Value) := Diff_Value;
      end loop;
   end Subtract_In_Place_Group18;

   function Is_Valid_Public_Group18 (Item : Group18_Value) return Boolean is
      Lower_Bound : Group18_Value := [others => 0];
      Upper_Bound : Group18_Value := Group18_Prime;
   begin
      Lower_Bound (1023) := 1;
      Subtract_In_Place_Group18 (Upper_Bound, Lower_Bound);
      return
        Compare_Group18 (Item, Lower_Bound) > 0
        and then Compare_Group18 (Item, Upper_Bound) < 0;
   end Is_Valid_Public_Group18;

   function To_Fixed_Array_Group18
     (Item : Group18_Value) return Stream_Element_Array
   is
      Result_Value : Stream_Element_Array (1 .. 1024);
   begin
      for Index_Value in Group18_Limb_Index loop
         Result_Value (Stream_Element_Offset (Index_Value + 1)) :=
           Stream_Element (Item (Index_Value));
      end loop;
      return Result_Value;
   end To_Fixed_Array_Group18;

   function Set_Mpint_Group18
     (Buffer_Item : out CryptoLib.Buffers.Packet_Buffer;
      Value_Item  : Group18_Value) return Status
   is
      First_Nonzero : Natural := 1024;
      Raw_Data      : constant Stream_Element_Array :=
        To_Fixed_Array_Group18 (Value_Item);
   begin
      CryptoLib.Buffers.Clear (Buffer_Item);
      for Index_Value in Raw_Data'Range loop
         if Raw_Data (Index_Value) /= 0 then
            First_Nonzero := Natural (Index_Value);
            exit;
         end if;
      end loop;
      if First_Nonzero = 1024 and then Raw_Data (1024) = 0 then
         return
           CryptoLib.Buffers.Set
             (Buffer_Item, [1 => Stream_Element'(0)]);
      end if;
      if Raw_Data (Stream_Element_Offset (First_Nonzero)) >= 16#80# then
         declare
            Mpint_Data :
              Stream_Element_Array
                (1 .. Stream_Element_Offset (1026 - First_Nonzero));
            Out_Index  : Stream_Element_Offset := Mpint_Data'First;
         begin
            Mpint_Data (Out_Index) := 0;
            Out_Index := Out_Index + 1;
            for Source_Index in
              Stream_Element_Offset (First_Nonzero) .. Raw_Data'Last
            loop
               Mpint_Data (Out_Index) := Raw_Data (Source_Index);
               Out_Index := Out_Index + 1;
            end loop;
            return CryptoLib.Buffers.Set (Buffer_Item, Mpint_Data);
         end;
      else
         return
           CryptoLib.Buffers.Set
             (Buffer_Item,
              Raw_Data
                (Stream_Element_Offset (First_Nonzero) .. Raw_Data'Last));
      end if;
   exception
      when others =>
         CryptoLib.Buffers.Clear (Buffer_Item);
         return Internal_Error;
   end Set_Mpint_Group18;

   function Generate_Group18_Private
     (Source_Item   : in out CryptoLib.Random.Random_Source;
      Private_Value : out Group18_Value) return Status
   is
      --  RFC 3526 group18 has an estimated exponent range of roughly 400-620 bits.
      --  Use a 640-bit random exponent to avoid weakening the 8192-bit group
      --  while keeping native Ada modular exponentiation bounded.
      Random_Data  : Stream_Element_Array (1 .. 80);
      Status_Value : Status;
   begin
      Private_Value := [others => 0];
      Status_Value := CryptoLib.Random.Fill (Source_Item, Random_Data);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Random_Data (1) := Random_Data (1) and 16#7F#;
      Random_Data (80) := Random_Data (80) or 1;
      for Offset_Value in 0 .. 79 loop
         Private_Value (944 + Offset_Value) :=
           Natural (Random_Data (Stream_Element_Offset (Offset_Value + 1)));
      end loop;
      if Is_Zero_Group18 (Private_Value) then
         Private_Value (1023) := 1;
      end if;
      return Ok;
   exception
      when others =>
         Private_Value := [others => 0];
         return Internal_Error;
   end Generate_Group18_Private;

   function Generate_Group18_Keypair
     (Source_Item   : in out CryptoLib.Random.Random_Source;
      Private_Value : out CryptoLib.Buffers.Packet_Buffer;
      Public_Value  : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Private_Big  : Group18_Value;
      Public_Big   : Group18_Value;
      Status_Value : Status;
   begin
      CryptoLib.Buffers.Clear (Private_Value);
      CryptoLib.Buffers.Clear (Public_Value);
      Status_Value := Generate_Group18_Private (Source_Item, Private_Big);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      --  8192-bit modexp exceeds GNAT Big_Integers' cap; use Montgomery.
      Public_Big :=
        From_Fixed_Bytes_Group18
          (CryptoLib.Modexp.Mod_Exp
             (Ada.Streams.Stream_Element_Array'(1 => 2),
              Exponent_Bytes (To_Fixed_Array_Group18 (Private_Big)),
              To_Fixed_Array_Group18 (Group18_Prime)));
      Status_Value :=
        CryptoLib.Buffers.Set
          (Private_Value, To_Fixed_Array_Group18 (Private_Big));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      return Set_Mpint_Group18 (Public_Value, Public_Big);
   exception
      when others =>
         CryptoLib.Buffers.Clear (Private_Value);
         CryptoLib.Buffers.Clear (Public_Value);
         return Internal_Error;
   end Generate_Group18_Keypair;

   function Compute_Group18_Shared_Secret
     (Client_Private_Placeholder : Ada.Streams.Stream_Element_Array;
      Server_Public_Value        : Ada.Streams.Stream_Element_Array;
      Shared_Secret              : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Private_Big  : Group18_Value;
      Server_Big   : Group18_Value;
      Shared_Big   : Group18_Value;
      Status_Value : Status;
   begin
      CryptoLib.Buffers.Clear (Shared_Secret);
      if Client_Private_Placeholder'Length > 1024 then
         return Handshake_Failed;
      end if;
      Private_Big := From_Fixed_Bytes_Group18 (Client_Private_Placeholder);
      if Is_Zero_Group18 (Private_Big) then
         return Handshake_Failed;
      end if;
      Status_Value := From_Mpint_Group18 (Server_Public_Value, Server_Big);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if not Is_Valid_Public_Group18 (Server_Big) then
         return Handshake_Failed;
      end if;
      Shared_Big :=
        From_Fixed_Bytes_Group18
          (CryptoLib.Modexp.Mod_Exp
             (To_Fixed_Array_Group18 (Server_Big),
              Exponent_Bytes (To_Fixed_Array_Group18 (Private_Big)),
              To_Fixed_Array_Group18 (Group18_Prime)));
      if Is_Zero_Group18 (Shared_Big) then
         return Handshake_Failed;
      end if;
      return Set_Mpint_Group18 (Shared_Secret, Shared_Big);
   exception
      when others =>
         CryptoLib.Buffers.Clear (Shared_Secret);
         return Internal_Error;
   end Compute_Group18_Shared_Secret;

   function Select_Group_Exchange_Group
     (Prime_Value     : Ada.Streams.Stream_Element_Array;
      Generator_Value : Ada.Streams.Stream_Element_Array)
      return Supported_Gex_Group
   is
      Generator_Offset : Stream_Element_Offset := Generator_Value'First;
      G14              : Big_Value;
      G16              : Group16_Value;
      G18              : Group18_Value;
      Status_Value     : Status;
   begin
      if Generator_Value'Length = 0 then
         return No_Supported_Gex_Group;
      end if;
      if Generator_Value (Generator_Offset) = 0
        and then Generator_Value'Length > 1
      then
         Generator_Offset := Generator_Offset + 1;
      end if;
      if Generator_Offset /= Generator_Value'Last
        or else Generator_Value (Generator_Offset) /= 2
      then
         return No_Supported_Gex_Group;
      end if;

      Status_Value := From_Mpint (Prime_Value, G14);
      if Status_Value = Ok and then Compare (G14, Group14_Prime) = 0 then
         return Gex_Group14;
      end if;

      Status_Value := From_Mpint_Group16 (Prime_Value, G16);
      if Status_Value = Ok and then Compare_Group16 (G16, Group16_Prime) = 0
      then
         return Gex_Group16;
      end if;

      Status_Value := From_Mpint_Group18 (Prime_Value, G18);
      if Status_Value = Ok and then Compare_Group18 (G18, Group18_Prime) = 0
      then
         return Gex_Group18;
      end if;

      return No_Supported_Gex_Group;
   exception
      when others =>
         return No_Supported_Gex_Group;
   end Select_Group_Exchange_Group;

end CryptoLib.Diffie_Hellman;
