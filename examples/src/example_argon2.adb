with Ada.Streams;
with Ada.Text_IO;
with CryptoLib.Argon2;
with CryptoLib.Bcrypt;
with CryptoLib.Constant_Time;
with CryptoLib.Errors;
with CryptoLib.Random;

--  Hash a password with Argon2id, and verify a legacy bcrypt hash.
procedure Example_Argon2 is
   use type CryptoLib.Errors.Status;

   Rng      : CryptoLib.Random.Random_Source;
   Salt     : Ada.Streams.Stream_Element_Array (1 .. 16);
   Tag      : Ada.Streams.Stream_Element_Array (1 .. 32);
   Again    : Ada.Streams.Stream_Element_Array (1 .. 32);
   Password : constant Ada.Streams.Stream_Element_Array :=
     [Character'Pos ('h'), Character'Pos ('u'), Character'Pos ('n'),
      Character'Pos ('t'), Character'Pos ('e'), Character'Pos ('r'),
      Character'Pos ('2')];
begin
   --  A fresh salt per password, from the OS. Storing it alongside the tag is
   --  expected; it is not a secret.
   CryptoLib.Random.Initialize_Production (Rng);
   if CryptoLib.Random.Fill (Rng, Salt) /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("no entropy source available");
      return;
   end if;

   --  RFC 9106's second recommended setting: 64 MiB, three passes, four
   --  lanes. Lower the memory only when it is the last parameter left.
   if CryptoLib.Argon2.Derive
        (Kind       => CryptoLib.Argon2.Argon2id,
         Password   => Password,
         Salt       => Salt,
         Iterations => 3,
         Memory_KiB => 65536,
         Lanes      => 4,
         Tag        => Tag) /= CryptoLib.Errors.Ok
   then
      Ada.Text_IO.Put_Line ("argon2 refused those parameters");
      return;
   end if;

   --  Verifying is deriving again with the stored salt and comparing in
   --  constant time. Never with "=" on the tag.
   if CryptoLib.Argon2.Derive
        (Kind       => CryptoLib.Argon2.Argon2id,
         Password   => Password,
         Salt       => Salt,
         Iterations => 3,
         Memory_KiB => 65536,
         Lanes      => 4,
         Tag        => Again) /= CryptoLib.Errors.Ok
   then
      Ada.Text_IO.Put_Line ("argon2 refused those parameters");
      return;
   end if;

   Ada.Text_IO.Put_Line
     ("argon2id verifies: "
      & Boolean'Image (CryptoLib.Constant_Time.Equal (Tag, Again)));

   --  Existing databases hold bcrypt. Verify against it, and re-hash with
   --  Argon2 the next time the password is offered.
   Ada.Text_IO.Put_Line
     ("legacy bcrypt verifies: "
      & Boolean'Image
          (CryptoLib.Bcrypt.Verify
             (Password,
              "$2b$04$abcdefghijklmnopqrstuuV3duMsC0HpUex6N9qapiuOHHWkwRXVm")));
end Example_Argon2;
