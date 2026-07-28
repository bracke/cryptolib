with Ada.Streams;
with System.Storage_Elements;

with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.OIDs;
with CryptoLib.Ciphers;
with CryptoLib.Errors;
with CryptoLib.Macs;
with CryptoLib.Secure_Wipe;

package body CryptoLib.PKCS8 is

   use CryptoLib.ASN1;
   use CryptoLib.ASN1.Errors;
   use CryptoLib.X509;
   use type Ada.Streams.Stream_Element;
   use type CryptoLib.Errors.Status;
   use type Ada.Streams.Stream_Element_Offset;

   package DER_Reader renames CryptoLib.ASN1.DER;
   package OID_Table renames CryptoLib.ASN1.OIDs;

   Empty_Octets : constant Octets (1 .. 0) := [others => 0];

   procedure Wipe (Item : in out Private_Key) is
   begin
      if Item.Held > 0 then
         CryptoLib.Secure_Wipe.Wipe
           (Item.DER (Item.DER'First)'Address, Natural (Item.Held));
      end if;
      Item.Present := False;
      Item.Kind := Unknown_Public_Key_Algorithm;
      Item.Value := (First => 1, Last => 0);
      Item.Held := 0;
   end Wipe;

   overriding procedure Finalize (Item : in out Private_Key) is
   begin
      Wipe (Item);
   end Finalize;

   procedure Decode_DER
     (Data   : Octets;
      Limits : Decode_Limits;
      Item   : out Private_Key;
      Status : out Decode_Status)
   is
      Cursor : Offset;
      Outer  : Element;
      Field  : Element;
      Alg    : Element;
      Alg_ID : Element;
      Param  : Element;
      Has_P  : Boolean := False;
      Inner  : Offset;
      Kind   : Public_Key_Algorithm := Unknown_Public_Key_Algorithm;
   begin
      Status := Ok;
      Wipe (Item);

      if Data'Length = 0 then
         Status := Truncated_Input;
         return;
      end if;

      if Natural (Data'Length) > Maximum_Key_Size
        or else Natural (Data'Length) > Limits.Maximum_Input_Size
      then
         Status := Size_Limit_Exceeded;
         return;
      end if;

      for I in Data'Range loop
         Item.DER (Offset (I - Data'First) + 1) := Data (I);
      end loop;
      Item.Held := Data'Length;

      declare
         Work : Octets renames Item.DER;
         Last : constant Offset := Item.Held;
      begin
         Cursor := Work'First;
         DER_Reader.Read_Sequence
           (Work, Cursor, Last, 0, Limits, Outer, Status);
         if Status /= Ok then
            Wipe (Item);
            return;
         end if;

         if not DER_Reader.At_End (Cursor, Last) then
            Status := Trailing_Data;
            Wipe (Item);
            return;
         end if;

         Inner := Outer.First;

         --  version INTEGER. An EncryptedPrivateKeyInfo begins with an
         --  AlgorithmIdentifier instead, so a SEQUENCE here rather than an
         --  integer is the encrypted form and is refused as unsupported
         --  rather than as malformed.
         declare
            Look : Offset := Inner;
            Peek : Element;
            Try  : Decode_Status;
         begin
            DER_Reader.Read (Work, Look, Outer.Last, 1, Limits, Peek, Try);
            if Try = Ok and then Peek.Constructed then
               Status := Unsupported_Encoding;
               Wipe (Item);
               return;
            end if;
         end;

         declare
            Version : Natural;
         begin
            DER_Reader.Read_Small_Integer
              (Work, Inner, Outer.Last, 1, Limits, Version, Status);
            if Status /= Ok then
               Wipe (Item);
               return;
            end if;
            if Version > 1 then
               Status := Unsupported_Encoding;
               Wipe (Item);
               return;
            end if;
         end;

         --  privateKeyAlgorithm
         DER_Reader.Read_Sequence
           (Work, Inner, Outer.Last, 1, Limits, Alg, Status);
         if Status /= Ok then
            Wipe (Item);
            return;
         end if;

         declare
            Part : Offset := Alg.First;
         begin
            DER_Reader.Read_Object_Identifier
              (Work, Part, Alg.Last, 2, Limits, Alg_ID, Status);
            if Status /= Ok then
               Wipe (Item);
               return;
            end if;

            if not DER_Reader.At_End (Part, Alg.Last) then
               DER_Reader.Read
                 (Work, Part, Alg.Last, 2, Limits, Param, Status);
               if Status /= Ok then
                  Wipe (Item);
                  return;
               end if;
               Has_P := True;
            end if;
         end;

         if OID_Table.Matches (Work, Alg_ID, OID_Table.Ed25519) then
            Kind := Ed25519;
         elsif OID_Table.Matches (Work, Alg_ID, OID_Table.Ed448) then
            Kind := Ed448;
         elsif OID_Table.Matches (Work, Alg_ID, OID_Table.RSA_Encryption) then
            Kind := RSA;
         elsif OID_Table.Matches (Work, Alg_ID, OID_Table.EC_Public_Key) then
            if not Has_P then
               Kind := Unknown_Public_Key_Algorithm;
            elsif OID_Table.Matches (Work, Param, OID_Table.Prime256v1) then
               Kind := ECDSA_P256;
            elsif OID_Table.Matches (Work, Param, OID_Table.Secp384r1) then
               Kind := ECDSA_P384;
            elsif OID_Table.Matches (Work, Param, OID_Table.Secp521r1) then
               Kind := ECDSA_P521;
            else
               Kind := Unknown_Public_Key_Algorithm;
            end if;
         end if;

         Item.Kind := Kind;

         --  privateKey OCTET STRING
         DER_Reader.Read_Octet_String
           (Work, Inner, Outer.Last, 1, Limits, Field, Status);
         if Status /= Ok then
            Wipe (Item);
            return;
         end if;

         case Kind is
            when Ed25519 | Ed448 =>
               --  The seed is itself wrapped in an octet string, which is
               --  the one place this encoding doubles up.
               declare
                  Within : Offset := Field.First;
                  Seed   : Element;
               begin
                  DER_Reader.Read_Octet_String
                    (Work, Within, Field.Last, 2, Limits, Seed, Status);
                  if Status /= Ok then
                     Wipe (Item);
                     return;
                  end if;
                  Item.Value := (First => Seed.First, Last => Seed.Last);
               end;

            when ECDSA_P256 | ECDSA_P384 | ECDSA_P521 =>
               --  ECPrivateKey ::= SEQUENCE { version, privateKey OCTET
               --  STRING, [0] parameters, [1] publicKey }. The scalar is the
               --  octet string, found by walking to it rather than by
               --  looking for bytes that resemble it.
               declare
                  Within : Offset := Field.First;
                  Key    : Element;
                  Scalar : Element;
                  Ver    : Natural;
               begin
                  DER_Reader.Read_Sequence
                    (Work, Within, Field.Last, 2, Limits, Key, Status);
                  if Status /= Ok then
                     Wipe (Item);
                     return;
                  end if;

                  declare
                     Part : Offset := Key.First;
                  begin
                     DER_Reader.Read_Small_Integer
                       (Work, Part, Key.Last, 3, Limits, Ver, Status);
                     if Status /= Ok then
                        Wipe (Item);
                        return;
                     end if;

                     DER_Reader.Read_Octet_String
                       (Work, Part, Key.Last, 3, Limits, Scalar, Status);
                     if Status /= Ok then
                        Wipe (Item);
                        return;
                     end if;
                     Item.Value :=
                       (First => Scalar.First, Last => Scalar.Last);
                  end;
               end;

            when others =>
               --  RSA and anything unrecognised: the structure decoded, and
               --  there is no single private value to hand back.
               Item.Value := (First => 1, Last => 0);
         end case;

         Item.Present := True;
      end;
   end Decode_DER;

   function Is_Present (Item : Private_Key) return Boolean
   is (Item.Present);

   function Algorithm_Of (Item : Private_Key) return Public_Key_Algorithm
   is (Item.Kind);

   function Private_Value (Item : Private_Key) return Octets
   is (if not Item.Present or else Item.Value.Last < Item.Value.First
       then Empty_Octets
       else Item.DER (Item.Value.First .. Item.Value.Last));

   function Unlock_Image (Status : Unlock_Status) return String is
   begin
      case Status is
         when Ok                        => return "ok";
         when Not_Encrypted             => return "not encrypted";
         when Unsupported_Scheme        => return "unsupported scheme";
         when Excessive_Iterations      => return "excessive iterations";
         when Wrong_Password_Or_Corrupt =>
            return "wrong password or corrupt";
         when Malformed                 => return "malformed";
      end case;
   end Unlock_Image;

   --  Read an AlgorithmIdentifier, reporting its OID and its parameters.
   procedure Read_Algorithm
     (Data       : Octets;
      Position   : in out Offset;
      Last       : Offset;
      Depth      : Natural;
      Limits     : Decode_Limits;
      Identifier : out Element;
      Parameter  : out Element;
      Has_Param  : out Boolean;
      Status     : out Decode_Status)
   is
      Cursor : Offset := Position;
      Alg    : Element;
      Inner  : Offset;
   begin
      Identifier := (others => <>);
      Parameter := (others => <>);
      Has_Param := False;

      DER_Reader.Read_Sequence
        (Data, Cursor, Last, Depth, Limits, Alg, Status);
      if Status /= Ok then
         return;
      end if;

      Inner := Alg.First;
      DER_Reader.Read_Object_Identifier
        (Data, Inner, Alg.Last, Depth + 1, Limits, Identifier, Status);
      if Status /= Ok then
         return;
      end if;

      if not DER_Reader.At_End (Inner, Alg.Last) then
         DER_Reader.Read
           (Data, Inner, Alg.Last, Depth + 1, Limits, Parameter, Status);
         if Status /= Ok then
            return;
         end if;
         Has_Param := True;
      end if;

      Position := Cursor;
   end Read_Algorithm;

   type PRF_Kind is (HMAC_SHA1, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512);

   procedure Decode_Encrypted_DER
     (Data               : Octets;
      Password           : String;
      Limits             : Decode_Limits;
      Item               : out Private_Key;
      Status             : out Unlock_Status;
      Maximum_Iterations : Natural := Default_Maximum_Iterations)
   is
      Parse  : Decode_Status;
      Cursor : Offset;
      Outer  : Element;
      Alg_ID : Element;
      Param  : Element;
      Has_P  : Boolean;
      Body_S : Element;

      Salt_Span  : Element;
      IV_Span    : Element;
      Iterations : Natural := 0;
      Key_Length : Natural := 0;
      PRF        : PRF_Kind := HMAC_SHA1;
      Cipher     : Natural := 0;   --  key octets: 16, 24 or 32
   begin
      Wipe (Item);
      Status := Malformed;

      if Data'Length = 0 then
         return;
      end if;

      Cursor := Data'First;
      DER_Reader.Read_Sequence
        (Data, Cursor, Data'Last, 0, Limits, Outer, Parse);
      if Parse /= Ok then
         return;
      end if;

      Cursor := Outer.First;
      Read_Algorithm
        (Data, Cursor, Outer.Last, 1, Limits, Alg_ID, Param, Has_P, Parse);
      if Parse /= Ok then
         return;
      end if;

      if not OID_Table.Matches (Data, Alg_ID, OID_Table.PBES2) then
         --  A plain key has an INTEGER version here rather than an
         --  algorithm, so it will have failed above; anything that parses and
         --  is not PBES2 is a scheme this does not implement.
         Status := Unsupported_Scheme;
         return;
      end if;

      if not Has_P then
         return;
      end if;

      DER_Reader.Read_Octet_String
        (Data, Cursor, Outer.Last, 1, Limits, Body_S, Parse);
      if Parse /= Ok then
         return;
      end if;

      --  PBES2-params ::= SEQUENCE { keyDerivationFunc, encryptionScheme }
      declare
         Inner : Offset := Param.First;
         KDF   : Element;
         Enc   : Element;
         KDF_P : Element;
         Enc_P : Element;
         Got_K : Boolean;
         Got_E : Boolean;
         Params : Element;
      begin
         Cursor := Encoded_First (Param);
         DER_Reader.Read_Sequence
           (Data, Cursor, Outer.Last, 2, Limits, Params, Parse);
         if Parse /= Ok then
            return;
         end if;

         Inner := Params.First;
         Read_Algorithm
           (Data, Inner, Params.Last, 3, Limits, KDF, KDF_P, Got_K, Parse);
         if Parse /= Ok then
            return;
         end if;

         Read_Algorithm
           (Data, Inner, Params.Last, 3, Limits, Enc, Enc_P, Got_E, Parse);
         if Parse /= Ok then
            return;
         end if;

         if not OID_Table.Matches (Data, KDF, OID_Table.PBKDF2)
           or else not Got_K
         then
            Status := Unsupported_Scheme;
            return;
         end if;

         --  The cipher, and with it the key length the derivation must
         --  produce.
         if OID_Table.Matches (Data, Enc, OID_Table.AES256_CBC) then
            Cipher := 32;
         elsif OID_Table.Matches (Data, Enc, OID_Table.AES192_CBC) then
            Cipher := 24;
         elsif OID_Table.Matches (Data, Enc, OID_Table.AES128_CBC) then
            Cipher := 16;
         else
            Status := Unsupported_Scheme;
            return;
         end if;

         if not Got_E or else Content_Length (Enc_P) /= 16 then
            --  AES-CBC takes its IV here, and a block cipher without one
            --  cannot be run.
            return;
         end if;
         IV_Span := Enc_P;

         --  PBKDF2-params ::= SEQUENCE { salt, iterationCount,
         --      keyLength OPTIONAL, prf DEFAULT hmacWithSHA1 }
         declare
            Walk : Offset := KDF_P.First;
            Set  : Element;
         begin
            Cursor := Encoded_First (KDF_P);
            DER_Reader.Read_Sequence
              (Data, Cursor, Params.Last, 4, Limits, Set, Parse);
            if Parse /= Ok then
               return;
            end if;

            Walk := Set.First;
            DER_Reader.Read_Octet_String
              (Data, Walk, Set.Last, 5, Limits, Salt_Span, Parse);
            if Parse /= Ok then
               return;
            end if;

            DER_Reader.Read_Small_Integer
              (Data, Walk, Set.Last, 5, Limits, Iterations, Parse);
            if Parse /= Ok then
               return;
            end if;

            if Iterations = 0 then
               return;
            end if;

            if Iterations > Maximum_Iterations then
               Status := Excessive_Iterations;
               return;
            end if;

            --  keyLength and prf are both optional and either may be absent.
            while not DER_Reader.At_End (Walk, Set.Last) loop
               declare
                  Look : Offset := Walk;
                  Peek : Element;
                  Try  : Decode_Status;
               begin
                  DER_Reader.Read
                    (Data, Look, Set.Last, 5, Limits, Peek, Try);
                  exit when Try /= Ok;

                  if Peek.Class = Universal
                    and then Peek.Number = Tag_Integer
                  then
                     DER_Reader.Read_Small_Integer
                       (Data, Walk, Set.Last, 5, Limits, Key_Length, Parse);
                     exit when Parse /= Ok;
                  elsif Peek.Class = Universal
                    and then Peek.Number = Tag_Sequence
                  then
                     declare
                        PRF_OID : Element;
                        PRF_P   : Element;
                        Got_P   : Boolean;
                     begin
                        Read_Algorithm
                          (Data, Walk, Set.Last, 5, Limits, PRF_OID, PRF_P,
                           Got_P, Parse);
                        exit when Parse /= Ok;

                        if OID_Table.Matches
                             (Data, PRF_OID, OID_Table.HMAC_With_SHA256)
                        then
                           PRF := HMAC_SHA256;
                        elsif OID_Table.Matches
                                (Data, PRF_OID, OID_Table.HMAC_With_SHA384)
                        then
                           PRF := HMAC_SHA384;
                        elsif OID_Table.Matches
                                (Data, PRF_OID, OID_Table.HMAC_With_SHA512)
                        then
                           PRF := HMAC_SHA512;
                        elsif OID_Table.Matches
                                (Data, PRF_OID, OID_Table.HMAC_With_SHA1)
                        then
                           PRF := HMAC_SHA1;
                        else
                           Status := Unsupported_Scheme;
                           return;
                        end if;
                     end;
                  else
                     Walk := Look;
                  end if;
               end;
            end loop;
         end;
      end;

      --  A stated key length that disagrees with the cipher is a file that
      --  cannot mean what it says.
      if Key_Length /= 0 and then Key_Length /= Cipher then
         Status := Unsupported_Scheme;
         return;
      end if;

      declare
         Pass : Ada.Streams.Stream_Element_Array (1 .. Password'Length);
         Salt : constant Octets :=
           (if Is_Empty (Salt_Span) then Empty_Octets
            else Data (Salt_Span.First .. Salt_Span.Last));
         IV   : constant Octets := Data (IV_Span.First .. IV_Span.Last);
         Key  : Ada.Streams.Stream_Element_Array (1 .. Offset (Cipher));
         Text : Ada.Streams.Stream_Element_Array
           (1 .. Offset (Content_Length (Body_S)));
      begin
         for I in Password'Range loop
            Pass (Offset (I - Password'First) + 1) :=
              Character'Pos (Password (I));
         end loop;

         if Text'Length = 0 or else Text'Length mod 16 /= 0 then
            --  CBC ciphertext is whole blocks.
            CryptoLib.Secure_Wipe.Wipe (Pass'Address, Pass'Length);
            return;
         end if;

         case PRF is
            when HMAC_SHA1 =>
               Key := CryptoLib.Macs.PBKDF2_HMAC_SHA1
                 (Pass, Salt, Iterations, Key'Length);
            when HMAC_SHA256 =>
               Key := CryptoLib.Macs.PBKDF2_HMAC_SHA256
                 (Pass, Salt, Iterations, Key'Length);
            when HMAC_SHA384 =>
               Key := CryptoLib.Macs.PBKDF2_HMAC_SHA384
                 (Pass, Salt, Iterations, Key'Length);
            when HMAC_SHA512 =>
               Key := CryptoLib.Macs.PBKDF2_HMAC_SHA512
                 (Pass, Salt, Iterations, Key'Length);
         end case;

         CryptoLib.Secure_Wipe.Wipe (Pass'Address, Pass'Length);

         if CryptoLib.Ciphers.Decrypt_CBC_Raw
              (Algorithm_Name =>
                 (case Cipher is
                     when 16     => "aes128-cbc",
                     when 24     => "aes192-cbc",
                     when others => "aes256-cbc"),
               Key_Data   => Key,
               IV_Data    => IV,
               Ciphertext => Data (Body_S.First .. Body_S.Last),
               Plaintext  => Text) /= CryptoLib.Errors.Ok
         then
            CryptoLib.Secure_Wipe.Wipe (Key'Address, Key'Length);
            CryptoLib.Secure_Wipe.Wipe (Text'Address, Text'Length);
            Status := Wrong_Password_Or_Corrupt;
            return;
         end if;

         CryptoLib.Secure_Wipe.Wipe (Key'Address, Key'Length);

         --  PKCS#7 padding. A wrong password yields bytes that are unlikely
         --  to be padding, and when they are, the key beneath them will not
         --  parse. Both come back as one answer: telling them apart is an
         --  oracle and is of no use to the caller.
         declare
            Pad  : constant Natural := Natural (Text (Text'Last));
            Body_Last : Offset;
         begin
            if Pad = 0 or else Pad > 16 or else Offset (Pad) > Text'Length
            then
               CryptoLib.Secure_Wipe.Wipe (Text'Address, Text'Length);
               Status := Wrong_Password_Or_Corrupt;
               return;
            end if;

            for I in 0 .. Offset (Pad) - 1 loop
               if Natural (Text (Text'Last - I)) /= Pad then
                  CryptoLib.Secure_Wipe.Wipe (Text'Address, Text'Length);
                  Status := Wrong_Password_Or_Corrupt;
                  return;
               end if;
            end loop;

            Body_Last := Text'Last - Offset (Pad);
            if Body_Last < Text'First then
               CryptoLib.Secure_Wipe.Wipe (Text'Address, Text'Length);
               Status := Wrong_Password_Or_Corrupt;
               return;
            end if;

            Decode_DER
              (Text (Text'First .. Body_Last), Limits, Item, Parse);
            CryptoLib.Secure_Wipe.Wipe (Text'Address, Text'Length);

            if Parse /= Ok or else not Is_Present (Item) then
               Wipe (Item);
               Status := Wrong_Password_Or_Corrupt;
               return;
            end if;
         end;
      end;

      Status := Ok;
   end Decode_Encrypted_DER;

end CryptoLib.PKCS8;
