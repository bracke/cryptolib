with Ada.Streams;
with System.Storage_Elements;

with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.OIDs;
with CryptoLib.PBES2;
with CryptoLib.Secure_Wipe;

package body CryptoLib.PKCS8 is

   use CryptoLib.ASN1;
   use CryptoLib.ASN1.Errors;
   use CryptoLib.X509;
   use type Ada.Streams.Stream_Element;
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
      Item.Modulus := (First => 1, Last => 0);
      Item.Exponent := (First => 1, Last => 0);
      Item.Private_D := (First => 1, Last => 0);
      Item.Prime_P := (First => 1, Last => 0);
      Item.Prime_Q := (First => 1, Last => 0);
      Item.Exp_P := (First => 1, Last => 0);
      Item.Exp_Q := (First => 1, Last => 0);
      Item.Coeff := (First => 1, Last => 0);
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

            when RSA =>
               --  RSAPrivateKey ::= SEQUENCE { version, modulus,
               --      publicExponent, privateExponent, ... }. There is no
               --  single private value to hand back, but the public parts are
               --  here and are what decides whether this key belongs to a
               --  given certificate.
               declare
                  Within : Offset := Field.First;
                  Key    : Element;
                  Number : Element;
                  Ver    : Natural;
                  Minus  : Boolean;
               begin
                  Item.Value := (First => 1, Last => 0);

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

                     DER_Reader.Read_Integer
                       (Work, Part, Key.Last, 3, Limits, Number, Minus,
                        Status);
                     if Status /= Ok or else Minus then
                        Wipe (Item);
                        Status := Invalid_Value;
                        return;
                     end if;
                     Item.Modulus :=
                       (First => Number.First, Last => Number.Last);

                     DER_Reader.Read_Integer
                       (Work, Part, Key.Last, 3, Limits, Number, Minus,
                        Status);
                     if Status /= Ok or else Minus then
                        Wipe (Item);
                        Status := Invalid_Value;
                        return;
                     end if;
                     Item.Exponent :=
                       (First => Number.First, Last => Number.Last);

                     --  privateExponent, the field after publicExponent.
                     --  Read so a parsed key can be signed with; the CRT
                     --  parameters after it are deliberately left alone.
                     DER_Reader.Read_Integer
                       (Work, Part, Key.Last, 3, Limits, Number, Minus,
                        Status);
                     if Status /= Ok or else Minus then
                        Wipe (Item);
                        Status := Invalid_Value;
                        return;
                     end if;
                     Item.Private_D :=
                       (First => Number.First, Last => Number.Last);

                     --  prime1, prime2, exponent1, exponent2, coefficient, in
                     --  the order RFC 3447 fixes. A key missing any of them is
                     --  not a two-prime RSAPrivateKey, so a short read is a
                     --  refusal rather than a partial set.
                     for Field_Of in 1 .. 5 loop
                        DER_Reader.Read_Integer
                          (Work, Part, Key.Last, 3, Limits, Number, Minus,
                           Status);
                        if Status /= Ok or else Minus then
                           Wipe (Item);
                           Status := Invalid_Value;
                           return;
                        end if;
                        case Field_Of is
                           when 1 => Item.Prime_P :=
                             (First => Number.First, Last => Number.Last);
                           when 2 => Item.Prime_Q :=
                             (First => Number.First, Last => Number.Last);
                           when 3 => Item.Exp_P :=
                             (First => Number.First, Last => Number.Last);
                           when 4 => Item.Exp_Q :=
                             (First => Number.First, Last => Number.Last);
                           when others => Item.Coeff :=
                             (First => Number.First, Last => Number.Last);
                        end case;
                     end loop;
                  end;
               end;

            when others =>
               --  Unrecognised: the structure decoded, and there is nothing
               --  here this can name.
               Item.Value := (First => 1, Last => 0);
         end case;

         Item.Present := True;
      end;
   end Decode_DER;

   function Is_Present (Item : Private_Key) return Boolean
   is (Item.Present);

   function Algorithm_Of (Item : Private_Key) return Public_Key_Algorithm
   is (Item.Kind);

   function RSA_Modulus (Item : Private_Key) return Octets
   is (if not Item.Present or else Item.Modulus.Last < Item.Modulus.First
       then Empty_Octets
       else Item.DER (Item.Modulus.First .. Item.Modulus.Last));

   function RSA_Exponent (Item : Private_Key) return Octets
   is (if not Item.Present or else Item.Exponent.Last < Item.Exponent.First
       then Empty_Octets
       else Item.DER (Item.Exponent.First .. Item.Exponent.Last));

   function RSA_Private_Exponent (Item : Private_Key) return Octets
   is (if not Item.Present or else Item.Private_D.Last < Item.Private_D.First
       then Empty_Octets
       else Item.DER (Item.Private_D.First .. Item.Private_D.Last));

   function RSA_Prime_P (Item : Private_Key) return Octets
   is (if not Item.Present or else Item.Prime_P.Last < Item.Prime_P.First
       then Empty_Octets
       else Item.DER (Item.Prime_P.First .. Item.Prime_P.Last));

   function RSA_Prime_Q (Item : Private_Key) return Octets
   is (if not Item.Present or else Item.Prime_Q.Last < Item.Prime_Q.First
       then Empty_Octets
       else Item.DER (Item.Prime_Q.First .. Item.Prime_Q.Last));

   function RSA_Exponent_P (Item : Private_Key) return Octets
   is (if not Item.Present or else Item.Exp_P.Last < Item.Exp_P.First
       then Empty_Octets
       else Item.DER (Item.Exp_P.First .. Item.Exp_P.Last));

   function RSA_Exponent_Q (Item : Private_Key) return Octets
   is (if not Item.Present or else Item.Exp_Q.Last < Item.Exp_Q.First
       then Empty_Octets
       else Item.DER (Item.Exp_Q.First .. Item.Exp_Q.Last));

   function RSA_Coefficient (Item : Private_Key) return Octets
   is (if not Item.Present or else Item.Coeff.Last < Item.Coeff.First
       then Empty_Octets
       else Item.DER (Item.Coeff.First .. Item.Coeff.Last));

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
   begin
      Wipe (Item);
      Status := Malformed;

      if Data'Length = 0 then
         return;
      end if;

      --  EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm,
      --      encryptedData OCTET STRING }
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

      declare
         Plain : Octets (1 .. Offset (Content_Length (Body_S)));
         Last  : Offset;
         Undo  : CryptoLib.PBES2.Unlock_Status;
      begin
         CryptoLib.PBES2.Decrypt
           (Parameters => Data (Encoded_First (Param) .. Encoded_Last (Param)),
            Ciphertext => Data (Body_S.First .. Body_S.Last),
            Password   => Password,
            Limits     => Limits,
            Output     => Plain,
            Last       => Last,
            Status     => Undo,
            Maximum_Iterations => Maximum_Iterations);

         case Undo is
            when CryptoLib.PBES2.Ok =>
               null;
            when CryptoLib.PBES2.Unsupported_Scheme =>
               Status := Unsupported_Scheme;
               return;
            when CryptoLib.PBES2.Excessive_Iterations =>
               Status := Excessive_Iterations;
               return;
            when CryptoLib.PBES2.Wrong_Password_Or_Corrupt =>
               Status := Wrong_Password_Or_Corrupt;
               return;
            when others =>
               return;
         end case;

         --  What came out has to be a key. A wrong password that survived the
         --  padding check will not survive this.
         Decode_DER (Plain (Plain'First .. Last), Limits, Item, Parse);
         CryptoLib.Secure_Wipe.Wipe (Plain'Address, Plain'Length);

         if Parse /= Ok or else not Is_Present (Item) then
            Wipe (Item);
            Status := Wrong_Password_Or_Corrupt;
            return;
         end if;
      end;

      Status := Ok;
   end Decode_Encrypted_DER;

end CryptoLib.PKCS8;
