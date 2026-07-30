with Ada.Streams;
with Ada.Text_IO;
with CryptoLib.Errors;
with CryptoLib.HKDF;
with CryptoLib.TLS13_KDF;

--  The first steps of a TLS 1.3 key schedule, the counterpart to the README's
--  fragment. These are the derivations RFC 8446 section 7.1 defines; composing
--  them into the full schedule is the protocol's job and needs its state.
procedure Example_TLS13_KDF is
   use type CryptoLib.Errors.Status;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type Ada.Streams.Stream_Element_Array;

   Hash  : constant CryptoLib.TLS13_KDF.Hash_Algorithm := CryptoLib.HKDF.SHA256;
   Empty : constant Ada.Streams.Stream_Element_Array (1 .. 0) := [others => 0];
   Zeros : constant Ada.Streams.Stream_Element_Array (1 .. 32) := [others => 0];

   Early, Derived : Ada.Streams.Stream_Element_Array (1 .. 32);
   Traffic_Key    : Ada.Streams.Stream_Element_Array (1 .. 16);
   Traffic_IV     : Ada.Streams.Stream_Element_Array (1 .. 12);
   Status : CryptoLib.Errors.Status;
begin
   --  Early secret: extract with no salt over the PSK, or zeros when there is
   --  no PSK. This value is RFC 8448's, so it can be checked against the
   --  published handshake.
   Status := CryptoLib.HKDF.Extract (Hash, Empty, Zeros, Early);
   if Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("extract failed");
      return;
   end if;

   --  Derive-Secret (early, "derived", "") is what the next Extract takes as
   --  its salt. The label goes in without the "tls13 " prefix; that is added
   --  for you.
   Status := CryptoLib.TLS13_KDF.Derive_Secret
     (Hash, Early, "derived", Empty, Derived);
   if Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("derive failed");
      return;
   end if;
   Ada.Text_IO.Put_Line
     ("derived secret matches RFC 8448: "
      & Boolean'Image
          (Derived (Derived'First) = 16#6F#
           and then Derived (Derived'First + 1) = 16#26#));

   --  A record-protection key and its nonce come from Expand-Label at the
   --  widths the cipher suite fixes.
   Status := CryptoLib.TLS13_KDF.Expand_Label
     (Hash, Derived, "key", Empty, Traffic_Key);
   if Status = CryptoLib.Errors.Ok then
      Status := CryptoLib.TLS13_KDF.Expand_Label
        (Hash, Derived, "iv", Empty, Traffic_IV);
   end if;
   Ada.Text_IO.Put_Line
     ("key and iv derived: " & Boolean'Image (Status = CryptoLib.Errors.Ok));
   Ada.Text_IO.Put_Line
     ("and they differ: " & Boolean'Image (Traffic_Key (1 .. 12) /= Traffic_IV));
end Example_TLS13_KDF;
