with Ada.Streams; use Ada.Streams;

with CryptoLib.Macs;
with CryptoLib.Secure_Wipe;

package body CryptoLib.HKDF is

   use CryptoLib.Errors;

   function PRK_Length (Hash : Hash_Algorithm) return Positive
   is (case Hash is
          when SHA256 => 32,
          when SHA384 => 48,
          when SHA512 => 64);

   --  RFC 5869 counts output blocks in a single octet starting at 1, so the
   --  last block it can name is the 255th.
   function Maximum_Output (Hash : Hash_Algorithm) return Positive
   is (255 * PRK_Length (Hash));

   --  One HMAC under the chosen hash. The key is whatever the caller has --
   --  a salt in Extract, a pseudorandom key in Expand -- and HMAC accepts
   --  any length by construction, which is why neither step constrains it.
   function Mac
     (Hash    : Hash_Algorithm;
      Key     : Stream_Element_Array;
      Message : Stream_Element_Array) return Stream_Element_Array
   is
   begin
      case Hash is
         when SHA256 =>
            return Stream_Element_Array
                     (CryptoLib.Macs.HMAC_SHA256 (Key, Message));
         when SHA384 =>
            return Stream_Element_Array
                     (CryptoLib.Macs.HMAC_SHA384 (Key, Message));
         when SHA512 =>
            return Stream_Element_Array
                     (CryptoLib.Macs.HMAC_SHA512 (Key, Message));
      end case;
   end Mac;

   function Extract
     (Hash               : Hash_Algorithm;
      Salt               : Ada.Streams.Stream_Element_Array;
      Input_Key_Material : Ada.Streams.Stream_Element_Array;
      PRK                : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      Width : constant Stream_Element_Offset :=
        Stream_Element_Offset (PRK_Length (Hash));
   begin
      PRK := [others => 0];
      if PRK'Length /= Width then
         return Handshake_Failed;
      end if;

      --  RFC 5869 2.2: an absent salt is a string of HashLen zeros, not an
      --  error.
      --
      --  Written out even though it changes nothing. HMAC pads a key
      --  shorter than its block with zeros, so an empty key and a block of
      --  HashLen zeros are the same key by the time either reaches the
      --  compression function -- no test can tell these two branches apart,
      --  and deleting this one leaves every vector passing. It stays because
      --  the specification says what the salt is rather than what HMAC will
      --  do with it, and because a reader checking this against the RFC
      --  should find the sentence they are looking for.
      if Salt'Length = 0 then
         declare
            Zeros : constant Stream_Element_Array (1 .. Width) :=
              [others => 0];
         begin
            PRK := Mac (Hash, Zeros, Input_Key_Material);
         end;
      else
         PRK := Mac (Hash, Salt, Input_Key_Material);
      end if;
      return Ok;
   exception
      when others =>
         PRK := [others => 0];
         return Internal_Error;
   end Extract;

   function Expand
     (Hash   : Hash_Algorithm;
      PRK    : Ada.Streams.Stream_Element_Array;
      Info   : Ada.Streams.Stream_Element_Array;
      Output : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      Width : constant Stream_Element_Offset :=
        Stream_Element_Offset (PRK_Length (Hash));

      --  T (0) is empty, and every block after it is fed the one before.
      Previous : Stream_Element_Array (1 .. Width) := [others => 0];
      Have_Previous : Boolean := False;
      Filled   : Stream_Element_Offset := 0;
      Counter  : Stream_Element := 0;

      procedure Scrub is
      begin
         CryptoLib.Secure_Wipe.Wipe (Previous'Address, Previous'Length);
      end Scrub;
   begin
      Output := [others => 0];

      if PRK'Length < Width then
         return Handshake_Failed;
      end if;
      if Natural (Output'Length) > Maximum_Output (Hash) then
         --  Refused rather than wrapped: the counter is one octet, and a
         --  256th block would reuse the first one's.
         return Unsupported_Feature;
      end if;
      if Output'Length = 0 then
         return Ok;
      end if;

      while Filled < Output'Length loop
         Counter := Counter + 1;
         declare
            Message : constant Stream_Element_Array :=
              (if Have_Previous then Previous else [1 .. 0 => 0])
              & Info & [1 => Counter];
            Block   : constant Stream_Element_Array :=
              Mac (Hash, PRK (PRK'First .. PRK'First + Width - 1), Message);
            Take    : constant Stream_Element_Offset :=
              Stream_Element_Offset'Min (Width, Output'Length - Filled);
         begin
            Output (Output'First + Filled
                    .. Output'First + Filled + Take - 1) :=
              Block (Block'First .. Block'First + Take - 1);
            Previous := Block;
            Have_Previous := True;
            Filled := Filled + Take;
         end;
      end loop;

      Scrub;
      return Ok;
   exception
      when others =>
         Output := [others => 0];
         Scrub;
         return Internal_Error;
   end Expand;

   function Derive
     (Hash               : Hash_Algorithm;
      Salt               : Ada.Streams.Stream_Element_Array;
      Input_Key_Material : Ada.Streams.Stream_Element_Array;
      Info               : Ada.Streams.Stream_Element_Array;
      Output             : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      PRK    : Stream_Element_Array
        (1 .. Stream_Element_Offset (PRK_Length (Hash))) := [others => 0];
      Status : CryptoLib.Errors.Status;

      procedure Scrub is
      begin
         CryptoLib.Secure_Wipe.Wipe (PRK'Address, PRK'Length);
      end Scrub;
   begin
      Output := [others => 0];

      Status := Extract (Hash, Salt, Input_Key_Material, PRK);
      if Status /= Ok then
         Scrub;
         return Status;
      end if;

      Status := Expand (Hash, PRK, Info, Output);
      Scrub;
      if Status /= Ok then
         Output := [others => 0];
      end if;
      return Status;
   exception
      when others =>
         Output := [others => 0];
         Scrub;
         return Internal_Error;
   end Derive;

end CryptoLib.HKDF;
