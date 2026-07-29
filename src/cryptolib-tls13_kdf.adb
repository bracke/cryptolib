with Ada.Streams; use Ada.Streams;

with CryptoLib.Hashes;
with CryptoLib.Secure_Wipe;

package body CryptoLib.TLS13_KDF is

   use CryptoLib.Errors;

   Label_Prefix : constant String := "tls13 ";

   function Hash_Length (Hash : Hash_Algorithm) return Positive
   is (CryptoLib.HKDF.PRK_Length (Hash));

   function Transcript_Of
     (Hash : Hash_Algorithm; Messages : Stream_Element_Array)
      return Stream_Element_Array
   is
   begin
      case Hash is
         when CryptoLib.HKDF.SHA256 =>
            return Stream_Element_Array (CryptoLib.Hashes.SHA256 (Messages));
         when CryptoLib.HKDF.SHA384 =>
            return Stream_Element_Array (CryptoLib.Hashes.SHA384 (Messages));
         when CryptoLib.HKDF.SHA512 =>
            return Stream_Element_Array (CryptoLib.Hashes.SHA512 (Messages));
      end case;
   end Transcript_Of;

   function Expand_Label
     (Hash    : Hash_Algorithm;
      Secret  : Stream_Element_Array;
      Label   : String;
      Context : Stream_Element_Array;
      Output  : out Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      Full_Label : constant String := Label_Prefix & Label;

      --  HkdfLabel, RFC 8446 7.1:
      --     uint16 length;
      --     opaque label<7..255>;    -- one length octet, then the text
      --     opaque context<0..255>;  -- one length octet, then the octets
      Info_Length : constant Stream_Element_Offset :=
        2 + 1 + Stream_Element_Offset (Full_Label'Length)
        + 1 + Context'Length;
      Info   : Stream_Element_Array (1 .. Info_Length) := [others => 0];
      Cursor : Stream_Element_Offset;
      Status : CryptoLib.Errors.Status;
   begin
      Output := [others => 0];

      if Natural (Secret'Length) /= Hash_Length (Hash) then
         return Handshake_Failed;
      end if;
      if Label'Length = 0
        or else Label'Length > Maximum_Label_Length
        or else Natural (Context'Length) > Maximum_Context_Length
      then
         return Handshake_Failed;
      end if;
      --  The length field is a uint16, so it cannot name more output than
      --  that. HKDF's own 255-block ceiling is checked where it applies.
      if Output'Length > 16#FFFF# then
         return Unsupported_Feature;
      end if;

      Info (1) := Stream_Element (Output'Length / 256);
      Info (2) := Stream_Element (Output'Length mod 256);
      Info (3) := Stream_Element (Full_Label'Length);
      Cursor := 4;
      for Index_Value in Full_Label'Range loop
         Info (Cursor) := Character'Pos (Full_Label (Index_Value));
         Cursor := Cursor + 1;
      end loop;
      Info (Cursor) := Stream_Element (Context'Length);
      Cursor := Cursor + 1;
      if Context'Length > 0 then
         Info (Cursor .. Cursor + Context'Length - 1) := Context;
      end if;

      Status := CryptoLib.HKDF.Expand (Hash, Secret, Info, Output);
      if Status /= Ok then
         Output := [others => 0];
      end if;
      return Status;
   exception
      when others =>
         Output := [others => 0];
         return Internal_Error;
   end Expand_Label;

   function Derive_Secret_From_Transcript
     (Hash            : Hash_Algorithm;
      Secret          : Stream_Element_Array;
      Label           : String;
      Transcript_Hash : Stream_Element_Array;
      Output          : out Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
   begin
      Output := [others => 0];
      --  Derive-Secret's output is the hash's own width by definition; a
      --  caller asking for another length is asking for something that is
      --  not Derive-Secret.
      if Natural (Output'Length) /= Hash_Length (Hash)
        or else Natural (Transcript_Hash'Length) /= Hash_Length (Hash)
      then
         return Handshake_Failed;
      end if;
      return Expand_Label (Hash, Secret, Label, Transcript_Hash, Output);
   exception
      when others =>
         Output := [others => 0];
         return Internal_Error;
   end Derive_Secret_From_Transcript;

   function Derive_Secret
     (Hash     : Hash_Algorithm;
      Secret   : Stream_Element_Array;
      Label    : String;
      Messages : Stream_Element_Array;
      Output   : out Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      Digest : Stream_Element_Array
        (1 .. Stream_Element_Offset (Hash_Length (Hash))) := [others => 0];
      Status : CryptoLib.Errors.Status;

      procedure Scrub is
      begin
         CryptoLib.Secure_Wipe.Wipe (Digest'Address, Digest'Length);
      end Scrub;
   begin
      Output := [others => 0];
      Digest := Transcript_Of (Hash, Messages);
      Status :=
        Derive_Secret_From_Transcript (Hash, Secret, Label, Digest, Output);
      Scrub;
      return Status;
   exception
      when others =>
         Output := [others => 0];
         Scrub;
         return Internal_Error;
   end Derive_Secret;

end CryptoLib.TLS13_KDF;
