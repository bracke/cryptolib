with Ada.Streams; use Ada.Streams;
with Interfaces;

with CryptoLib.Blowfish; use CryptoLib.Blowfish;
with CryptoLib.Constant_Time;
with CryptoLib.Secure_Wipe;

package body CryptoLib.Bcrypt is

   use CryptoLib.Errors;
   use type Interfaces.Unsigned_32;

   --  bcrypt's own base64 alphabet, which is not RFC 4648's: it starts at
   --  "./" and has no padding. Sharing the name with base64 and not the
   --  alphabet is a trap, so nothing here is reused from CryptoLib.PEM.
   Alphabet : constant String :=
     "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

   --  "OrpheanBeholderScryDoubt": the 24 octets bcrypt encrypts, and the
   --  reason its output is 23 -- the last octet is dropped, which is a wart
   --  of the original implementation that every other one now reproduces.
   Magic : constant String := "OrpheanBeholderScryDoubt";

   Magic_Words : constant := 6;         --  24 octets

   function Encode (Data : Stream_Element_Array) return String is
      Result : String (1 .. (Natural (Data'Length) * 8 + 5) / 6);
      Cursor : Natural := Result'First;
      Accum  : Natural := 0;
      Bits   : Natural := 0;
   begin
      for B of Data loop
         Accum := Accum * 256 + Natural (B);
         Bits := Bits + 8;
         while Bits >= 6 loop
            Bits := Bits - 6;
            Result (Cursor) := Alphabet ((Accum / (2 ** Bits)) mod 64 + 1);
            Cursor := Cursor + 1;
         end loop;
         --  Keep only the bits not yet emitted. Without this the accumulator
         --  grows by eight bits per octet and overflows Natural partway
         --  through a 16-octet salt.
         Accum := Accum mod (2 ** Bits);
      end loop;
      if Bits > 0 then
         Result (Cursor) :=
           Alphabet ((Accum * (2 ** (6 - Bits))) mod 64 + 1);
      end if;
      return Result;
   end Encode;

   procedure Decode
     (Text : String; Data : out Stream_Element_Array; Ok : out Boolean)
   is
      Accum  : Natural := 0;
      Bits   : Natural := 0;
      Cursor : Stream_Element_Offset := Data'First;
   begin
      Data := [others => 0];
      Ok := False;
      for C of Text loop
         declare
            Position : Natural := 0;
         begin
            for I in Alphabet'Range loop
               if Alphabet (I) = C then
                  Position := I - Alphabet'First;
                  exit;
               end if;
            end loop;
            if Position = 0 and then C /= Alphabet (Alphabet'First) then
               return;
            end if;
            Accum := Accum * 64 + Position;
            Bits := Bits + 6;
            if Bits >= 8 then
               Bits := Bits - 8;
               if Cursor > Data'Last then
                  return;
               end if;
               Data (Cursor) :=
                 Stream_Element ((Accum / (2 ** Bits)) mod 256);
               Cursor := Cursor + 1;
            end if;
            Accum := Accum mod (2 ** Bits);
         end;
      end loop;
      Ok := Cursor > Data'Last;
   end Decode;

   --  The raw 23-octet hash: EksBlowfish with the given cost, then 64 ECB
   --  encryptions of the magic text.
   procedure Raw_Hash
     (Password  : Stream_Element_Array;
      Salt_Data : Salt;
      Cost      : Cost_Factor;
      Digest    : out Stream_Element_Array)
   is
      State  : Blowfish_State;
      Words  : P_Array := [others => 0];
      Key    : Stream_Element_Array (1 .. Password'Length + 1);
      Rounds : constant Natural := 2 ** Cost;
      Offset : Natural := 0;
   begin
      Digest := [others => 0];

      --  The key is the password with its terminating NUL, which is what
      --  makes "secret" and "secret\0" the same key everywhere else too.
      Key (1 .. Password'Length) := Password;
      Key (Key'Last) := 0;

      Init_State (State);
      Expand_State (State, Salt_Data, Key);
      for Round in 1 .. Rounds loop
         pragma Unreferenced (Round);
         Expand_Zero_State (State, Key);
         Expand_Zero_State (State, Salt_Data);
      end loop;

      declare
         Magic_Data : Stream_Element_Array (1 .. Magic'Length);
      begin
         for J in Magic'Range loop
            Magic_Data (Stream_Element_Offset (J)) :=
              Stream_Element (Character'Pos (Magic (J)));
         end loop;
         for I in 0 .. Magic_Words - 1 loop
            Words (I) := Stream_To_Word (Magic_Data, Offset);
         end loop;
      end;

      for Round in 1 .. 64 loop
         pragma Unreferenced (Round);
         Encrypt_Words (State, Words, Magic_Words / 2);
      end loop;

      --  Big-endian words, and only 23 of the 24 octets.
      for I in 0 .. Magic_Words - 1 loop
         for J in 0 .. 3 loop
            declare
               At_Index : constant Stream_Element_Offset :=
                 Digest'First + Stream_Element_Offset (I * 4 + J);
            begin
               if At_Index <= Digest'Last then
                  Digest (At_Index) :=
                    Stream_Element
                      (Interfaces.Shift_Right (Words (I), 24 - 8 * J)
                       and 16#FF#);
               end if;
            end;
         end loop;
      end loop;

      CryptoLib.Secure_Wipe.Wipe (Key'Address, Key'Length);
      Clear_P_Array (Words);
      Clear_State (State);
   end Raw_Hash;

   function Hash
     (Password  : Ada.Streams.Stream_Element_Array;
      Salt_Data : Salt;
      Cost      : Cost_Factor;
      Result    : out Hash_String) return CryptoLib.Errors.Status
   is
      Digest : Stream_Element_Array (1 .. 23);
      Cost_Image : String (1 .. 2);
   begin
      Result := [others => ' '];

      if Password'Length > Maximum_Password_Length then
         return Handshake_Failed;
      end if;
      for B of Password loop
         if B = 0 then
            return Handshake_Failed;
         end if;
      end loop;

      Raw_Hash (Password, Salt_Data, Cost, Digest);

      Cost_Image (1) := Character'Val (Character'Pos ('0') + Cost / 10);
      Cost_Image (2) := Character'Val (Character'Pos ('0') + Cost mod 10);
      Result := "$2b$" & Cost_Image & "$"
        & Encode (Salt_Data) & Encode (Digest);

      CryptoLib.Secure_Wipe.Wipe (Digest'Address, Digest'Length);
      return Ok;
   exception
      when others =>
         Result := [others => ' '];
         return Internal_Error;
   end Hash;

   function Verify
     (Password : Ada.Streams.Stream_Element_Array;
      Stored   : String) return Boolean
   is
      Salt_Data : Salt;
      Cost      : Natural;
      Ok        : Boolean;
      Computed  : Hash_String;
   begin
      if Stored'Length /= 60
        or else Stored (Stored'First .. Stored'First + 3) /= "$2b$"
        or else Stored (Stored'First + 6) /= '$'
        or else Stored (Stored'First + 4) not in '0' .. '9'
        or else Stored (Stored'First + 5) not in '0' .. '9'
      then
         return False;
      end if;

      Cost := (Character'Pos (Stored (Stored'First + 4))
               - Character'Pos ('0')) * 10
        + (Character'Pos (Stored (Stored'First + 5)) - Character'Pos ('0'));
      if Cost not in Cost_Factor then
         return False;
      end if;

      Decode (Stored (Stored'First + 7 .. Stored'First + 28), Salt_Data, Ok);
      if not Ok then
         return False;
      end if;

      if Hash (Password, Salt_Data, Cost, Computed) /= CryptoLib.Errors.Ok
      then
         return False;
      end if;

      --  Constant-time over the whole string, so nothing is learned from how
      --  far a wrong password got.
      declare
         Left  : Stream_Element_Array (1 .. 60);
         Right : Stream_Element_Array (1 .. 60);
      begin
         for I in 1 .. 60 loop
            Left (Stream_Element_Offset (I)) :=
              Stream_Element (Character'Pos (Computed (I)));
            Right (Stream_Element_Offset (I)) :=
              Stream_Element (Character'Pos (Stored (Stored'First + I - 1)));
         end loop;
         return CryptoLib.Constant_Time.Equal (Left, Right);
      end;
   exception
      when others =>
         return False;
   end Verify;

end CryptoLib.Bcrypt;
