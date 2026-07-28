with Ada.Streams;

with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.Errors;
with CryptoLib.ASN1.OIDs;
with CryptoLib.Ciphers;
with CryptoLib.Errors;
with CryptoLib.Macs;
with CryptoLib.Secure_Wipe;

package body CryptoLib.PBES2 is

   use CryptoLib.ASN1;
   use CryptoLib.ASN1.Errors;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.Errors.Status;

   package DER_Reader renames CryptoLib.ASN1.DER;
   package OID_Table renames CryptoLib.ASN1.OIDs;

   Empty_Octets : constant Octets (1 .. 0) := [others => 0];

   function Status_Image (Status : Unlock_Status) return String is
   begin
      case Status is
         when Ok                        => return "ok";
         when Unsupported_Scheme        => return "unsupported scheme";
         when Excessive_Iterations      => return "excessive iterations";
         when Wrong_Password_Or_Corrupt =>
            return "wrong password or corrupt";
         when Buffer_Too_Small          => return "buffer too small";
         when Malformed                 => return "malformed";
      end case;
   end Status_Image;

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
      Status     : out CryptoLib.ASN1.Errors.Decode_Status)
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

   procedure Decrypt
     (Parameters         : Octets;
      Ciphertext         : Octets;
      Password           : String;
      Limits             : Decode_Limits;
      Output             : out Octets;
      Last               : out Offset;
      Status             : out Unlock_Status;
      Maximum_Iterations : Natural := Default_Maximum_Iterations)
   is
      Parse  : CryptoLib.ASN1.Errors.Decode_Status;
      Cursor : Offset;
      Params : Element;

      Salt_Span  : Element;
      IV_Span    : Element;
      Iterations : Natural := 0;
      Key_Length : Natural := 0;
      PRF        : PRF_Kind := HMAC_SHA1;
      Cipher     : Natural := 0;
   begin
      Last := Output'First - 1;
      Status := Malformed;

      if Parameters'Length = 0 or else Ciphertext'Length = 0 then
         return;
      end if;

      --  PBES2-params ::= SEQUENCE { keyDerivationFunc, encryptionScheme }
      declare
         Inner : Offset;
         KDF   : Element;
         Enc   : Element;
         KDF_P : Element;
         Enc_P : Element;
         Got_K : Boolean;
         Got_E : Boolean;
      begin
         Cursor := Parameters'First;
         DER_Reader.Read_Sequence
           (Parameters, Cursor, Parameters'Last, 0, Limits, Params, Parse);
         if Parse /= Ok then
            return;
         end if;

         Inner := Params.First;
         Read_Algorithm
           (Parameters, Inner, Params.Last, 1, Limits, KDF, KDF_P, Got_K,
            Parse);
         if Parse /= Ok then
            return;
         end if;

         Read_Algorithm
           (Parameters, Inner, Params.Last, 1, Limits, Enc, Enc_P, Got_E,
            Parse);
         if Parse /= Ok then
            return;
         end if;

         if not OID_Table.Matches (Parameters, KDF, OID_Table.PBKDF2)
           or else not Got_K
         then
            Status := Unsupported_Scheme;
            return;
         end if;

         if OID_Table.Matches (Parameters, Enc, OID_Table.AES256_CBC) then
            Cipher := 32;
         elsif OID_Table.Matches (Parameters, Enc, OID_Table.AES192_CBC) then
            Cipher := 24;
         elsif OID_Table.Matches (Parameters, Enc, OID_Table.AES128_CBC) then
            Cipher := 16;
         else
            Status := Unsupported_Scheme;
            return;
         end if;

         if not Got_E or else Content_Length (Enc_P) /= 16 then
            return;
         end if;
         IV_Span := Enc_P;

         --  PBKDF2-params ::= SEQUENCE { salt, iterationCount,
         --      keyLength OPTIONAL, prf DEFAULT hmacWithSHA1 }
         declare
            Walk : Offset;
            Set  : Element;
         begin
            Cursor := Encoded_First (KDF_P);
            DER_Reader.Read_Sequence
              (Parameters, Cursor, Params.Last, 2, Limits, Set, Parse);
            if Parse /= Ok then
               return;
            end if;

            Walk := Set.First;
            DER_Reader.Read_Octet_String
              (Parameters, Walk, Set.Last, 3, Limits, Salt_Span, Parse);
            if Parse /= Ok then
               return;
            end if;

            DER_Reader.Read_Small_Integer
              (Parameters, Walk, Set.Last, 3, Limits, Iterations, Parse);
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

            while not DER_Reader.At_End (Walk, Set.Last) loop
               declare
                  Look : Offset := Walk;
                  Peek : Element;
                  Try  : CryptoLib.ASN1.Errors.Decode_Status;
               begin
                  DER_Reader.Read
                    (Parameters, Look, Set.Last, 3, Limits, Peek, Try);
                  exit when Try /= Ok;

                  if Peek.Class = Universal
                    and then Peek.Number = Tag_Integer
                  then
                     DER_Reader.Read_Small_Integer
                       (Parameters, Walk, Set.Last, 3, Limits, Key_Length,
                        Parse);
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
                          (Parameters, Walk, Set.Last, 3, Limits, PRF_OID,
                           PRF_P, Got_P, Parse);
                        exit when Parse /= Ok;

                        if OID_Table.Matches
                             (Parameters, PRF_OID, OID_Table.HMAC_With_SHA256)
                        then
                           PRF := HMAC_SHA256;
                        elsif OID_Table.Matches
                                (Parameters, PRF_OID,
                                 OID_Table.HMAC_With_SHA384)
                        then
                           PRF := HMAC_SHA384;
                        elsif OID_Table.Matches
                                (Parameters, PRF_OID,
                                 OID_Table.HMAC_With_SHA512)
                        then
                           PRF := HMAC_SHA512;
                        elsif OID_Table.Matches
                                (Parameters, PRF_OID,
                                 OID_Table.HMAC_With_SHA1)
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

      if Key_Length /= 0 and then Key_Length /= Cipher then
         Status := Unsupported_Scheme;
         return;
      end if;

      if Ciphertext'Length mod 16 /= 0 then
         return;
      end if;

      if Output'Length < Ciphertext'Length then
         Status := Buffer_Too_Small;
         return;
      end if;

      declare
         Pass : Ada.Streams.Stream_Element_Array
           (1 .. Offset (Password'Length));
         Salt : constant Octets :=
           (if Is_Empty (Salt_Span) then Empty_Octets
            else Parameters (Salt_Span.First .. Salt_Span.Last));
         IV   : constant Octets :=
           Parameters (IV_Span.First .. IV_Span.Last);
         Key  : Ada.Streams.Stream_Element_Array (1 .. Offset (Cipher));
         Text : Ada.Streams.Stream_Element_Array
           (1 .. Ciphertext'Length);
      begin
         for I in Password'Range loop
            Pass (Offset (I - Password'First) + 1) :=
              Character'Pos (Password (I));
         end loop;

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
               Ciphertext => Ciphertext,
               Plaintext  => Text) /= CryptoLib.Errors.Ok
         then
            CryptoLib.Secure_Wipe.Wipe (Key'Address, Key'Length);
            CryptoLib.Secure_Wipe.Wipe (Text'Address, Text'Length);
            Status := Wrong_Password_Or_Corrupt;
            return;
         end if;

         CryptoLib.Secure_Wipe.Wipe (Key'Address, Key'Length);

         --  PKCS#7 padding. A wrong password yields bytes that are unlikely
         --  to be padding, and when they are, whatever is beneath them will
         --  not parse. Both come back as one answer.
         declare
            Pad : constant Natural := Natural (Text (Text'Last));
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

            Last := Output'First + Text'Length - Offset (Pad) - 1;
            if Last < Output'First then
               CryptoLib.Secure_Wipe.Wipe (Text'Address, Text'Length);
               Status := Wrong_Password_Or_Corrupt;
               return;
            end if;

            Output (Output'First .. Last) :=
              Text (Text'First .. Text'Last - Offset (Pad));
            CryptoLib.Secure_Wipe.Wipe (Text'Address, Text'Length);
         end;
      end;

      Status := Ok;
   end Decrypt;

end CryptoLib.PBES2;
