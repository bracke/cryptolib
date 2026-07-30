with Ada.Streams;
with Ada.Text_IO;
with CryptoLib.ChaCha20_Poly1305;
with CryptoLib.Errors;

--  Seal and open one SSH packet with chacha20-poly1305@openssh.com, the
--  counterpart to the README's AEAD fragment. This is the OpenSSH
--  construction; Seal_AEAD and Open_AEAD in the same package are RFC 8439,
--  which is a different AEAD with a different key and nonce.
procedure Example_Chacha20_Poly1305 is
   use type CryptoLib.Errors.Status;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;

   --  K_2 in the first 32 octets, K_1 in the second: two independent keys.
   Key   : constant Ada.Streams.Stream_Element_Array
     (1 .. Ada.Streams.Stream_Element_Offset
             (CryptoLib.ChaCha20_Poly1305.Key_Length)) := [others => 7];
   --  A packet is a 4-octet length field followed by its body.
   Plain : constant Ada.Streams.Stream_Element_Array :=
     [16#00#, 16#00#, 16#00#, 16#04#, 16#41#, 16#42#, 16#43#, 16#44#];
   Wire  : Ada.Streams.Stream_Element_Array
     (1 .. Ada.Streams.Stream_Element_Offset (Plain'Length)
           + Ada.Streams.Stream_Element_Offset
               (CryptoLib.ChaCha20_Poly1305.Tag_Length));
   Back  : Ada.Streams.Stream_Element_Array
     (1 .. Ada.Streams.Stream_Element_Offset (Plain'Length));
   Status : CryptoLib.Errors.Status;
begin
   --  The nonce is the SSH packet sequence number, so it must not repeat
   --  under one key.
   Status := CryptoLib.ChaCha20_Poly1305.Seal (Key, 0, Plain, Wire);
   if Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("sealing failed");
      return;
   end if;

   Status := CryptoLib.ChaCha20_Poly1305.Open (Key, 0, Wire, Back);
   Ada.Text_IO.Put_Line
     ("round trip: " & Boolean'Image (Status = CryptoLib.Errors.Ok
                                      and then Back = Plain));

   --  A flipped tag bit must fail, and leave no plaintext behind.
   declare
      Tampered : Ada.Streams.Stream_Element_Array := Wire;
   begin
      Tampered (Tampered'Last) := Tampered (Tampered'Last) xor 1;
      Status := CryptoLib.ChaCha20_Poly1305.Open (Key, 0, Tampered, Back);
      --  Back is zeroed on a bad tag, which is the property worth showing.
      Ada.Text_IO.Put_Line
        ("tampered packet opens: "
         & Boolean'Image (Status = CryptoLib.Errors.Ok)
         & ", plaintext left: "
         & Boolean'Image (Back /= [Back'Range => 0]));
   end;
end Example_Chacha20_Poly1305;
