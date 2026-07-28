with Ada.Streams;

with CryptoLib.ASN1.Errors;
with CryptoLib.ECDSA;
with CryptoLib.Ed25519;
with CryptoLib.Errors;
with CryptoLib.ASN1.DER;
with CryptoLib.PEM;

package body CryptoLib.Identities is

   use CryptoLib.X509;

   subtype Offset is CryptoLib.ASN1.Offset;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.ASN1.Errors.Decode_Status;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.PEM.Decode_Status;

   package X509C renames CryptoLib.X509.Certificates;

   Empty_Octets : constant Octets (1 .. 0) := [others => 0];

   function Status_Image (Status : Identity_Status) return String is
   begin
      case Status is
         when Ok                    => return "ok";
         when Empty_Chain           => return "empty chain";
         when Chain_Too_Long        => return "chain too long";
         when Chain_Too_Large       => return "chain too large";
         when Malformed_Certificate => return "malformed certificate";
         when Malformed_Private_Key => return "malformed private key";
         when Key_Mismatch          => return "key mismatch";
         when Chain_Out_Of_Order    => return "chain out of order";
         when Unsupported_Key       => return "unsupported key";
      end case;
   end Status_Image;

   procedure Wipe (Item : in out Local_Identity) is
   begin
      CryptoLib.PKCS8.Wipe (Item.Key);
      Item.Present := False;
      Item.Count := 0;
      Item.Held := 0;
   end Wipe;

   overriding procedure Finalize (Item : in out Local_Identity) is
   begin
      Wipe (Item);
   end Finalize;

   function Same_Bytes (Left : Octets; Right : Octets) return Boolean is
   begin
      if Left'Length /= Right'Length or else Left'Length = 0 then
         return False;
      end if;
      for I in 0 .. Left'Length - 1 loop
         if Left (Left'First + Offset (I)) /= Right (Right'First + Offset (I))
         then
            return False;
         end if;
      end loop;
      return True;
   end Same_Bytes;

   --  Does the private key belong to this certificate?
   --
   --  By deriving the public key the private one implies and comparing it
   --  with what the certificate carries. Nothing weaker will do: a comparison
   --  that looked for the key's bytes somewhere in the certificate would
   --  match a certificate that merely mentions the key, which is not the same
   --  as one issued for it.
   --  Compare two unsigned integers written as octets, ignoring the leading
   --  zero a DER INTEGER carries to stay positive.
   function Same_Number (Left : Octets; Right : Octets) return Boolean is
      L : Offset := Left'First;
      R : Offset := Right'First;
   begin
      while L <= Left'Last and then Left (L) = 0 loop
         L := L + 1;
      end loop;
      while R <= Right'Last and then Right (R) = 0 loop
         R := R + 1;
      end loop;

      if L > Left'Last or else R > Right'Last then
         return False;
      end if;

      if Left'Last - L /= Right'Last - R then
         return False;
      end if;

      while L <= Left'Last loop
         if Left (L) /= Right (R) then
            return False;
         end if;
         L := L + 1;
         R := R + 1;
      end loop;

      return True;
   end Same_Number;

   function Key_Matches
     (Key_Item : CryptoLib.PKCS8.Private_Key;
      Leaf     : Certificate;
      Decided  : out Boolean) return Boolean
   is
      Kind : constant Public_Key_Algorithm :=
        CryptoLib.PKCS8.Algorithm_Of (Key_Item);
   begin
      Decided := False;

      if X509C.Public_Key_Algorithm_Of (Leaf) /= Kind then
         Decided := True;
         return False;
      end if;

      case Kind is
         when ECDSA_P256 | ECDSA_P384 | ECDSA_P521 =>
            --  Derive the public point the scalar implies and compare it with
            --  what the certificate carries. The curve decides the widths;
            --  the arithmetic is the same on all three.
            declare
               Scalar : constant Octets :=
                 CryptoLib.PKCS8.Private_Value (Key_Item);
               Curve  : constant CryptoLib.ECDSA.Curve_Id :=
                 (case Kind is
                     when ECDSA_P256 => CryptoLib.ECDSA.Nistp256,
                     when ECDSA_P384 => CryptoLib.ECDSA.Nistp384,
                     when others     => CryptoLib.ECDSA.Nistp521);
               Width  : constant Offset :=
                 (case Kind is
                     when ECDSA_P256 => 65,
                     when ECDSA_P384 => 97,
                     when others     => 133);
               Point  : Ada.Streams.Stream_Element_Array (1 .. Width);
            begin
               if Scalar'Length = 0 then
                  return False;
               end if;
               if CryptoLib.ECDSA.Public_Key_Raw (Curve, Scalar, Point)
                 /= CryptoLib.Errors.Ok
               then
                  return False;
               end if;
               Decided := True;
               return Same_Bytes (Point, X509C.Public_Key (Leaf));
            end;

         when CryptoLib.X509.Ed25519 =>
            declare
               Seed  : constant Octets :=
                 CryptoLib.PKCS8.Private_Value (Key_Item);
               Point : Ada.Streams.Stream_Element_Array (1 .. 32);
            begin
               if Seed'Length /= 32 then
                  return False;
               end if;
               if CryptoLib.Ed25519.Public_Key_From_Seed (Seed, Point)
                 /= CryptoLib.Errors.Ok
               then
                  return False;
               end if;
               Decided := True;
               return Same_Bytes (Point, X509C.Public_Key (Leaf));
            end;

         when CryptoLib.X509.RSA =>
            --  An RSA private key carries its own public parts, so this is a
            --  comparison rather than a derivation: the modulus and exponent
            --  in the key against the two integers in the certificate's
            --  public key. Compared as numbers, because a DER INTEGER carries
            --  a leading zero when its top bit would otherwise make it
            --  negative and the same modulus arrives written both ways.
            declare
               Limits : constant CryptoLib.ASN1.Decode_Limits :=
                 CryptoLib.ASN1.Default_Limits;
               Key    : constant Octets := X509C.Public_Key (Leaf);
               Cursor : CryptoLib.ASN1.Offset;
               Outer  : CryptoLib.ASN1.Element;
               Field  : CryptoLib.ASN1.Element;
               Status : CryptoLib.ASN1.Errors.Decode_Status;
               Minus  : Boolean;
            begin
               if Key'Length = 0 then
                  return False;
               end if;

               Cursor := Key'First;
               CryptoLib.ASN1.DER.Read_Sequence
                 (Key, Cursor, Key'Last, 0, Limits, Outer, Status);
               if Status /= CryptoLib.ASN1.Errors.Ok then
                  return False;
               end if;

               Cursor := Outer.First;
               CryptoLib.ASN1.DER.Read_Integer
                 (Key, Cursor, Outer.Last, 1, Limits, Field, Minus, Status);
               if Status /= CryptoLib.ASN1.Errors.Ok or else Minus then
                  return False;
               end if;

               Decided := True;

               if not Same_Number
                        (Key (Field.First .. Field.Last),
                         CryptoLib.PKCS8.RSA_Modulus (Key_Item))
               then
                  return False;
               end if;

               CryptoLib.ASN1.DER.Read_Integer
                 (Key, Cursor, Outer.Last, 1, Limits, Field, Minus, Status);
               if Status /= CryptoLib.ASN1.Errors.Ok or else Minus then
                  return False;
               end if;

               return Same_Number
                        (Key (Field.First .. Field.Last),
                         CryptoLib.PKCS8.RSA_Exponent (Key_Item));
            end;

         when others =>
            --  Ed448 and anything unrecognised. The match cannot be decided,
            --  which is reported rather than guessed.
            return False;
      end case;
   end Key_Matches;

   procedure Decode
     (Certificate_Chain_PEM : String;
      Private_Key_PEM       : String;
      Item                  : out Local_Identity;
      Status                : out Identity_Status)
   is
      Cursor : Positive := Certificate_Chain_PEM'First;
      Filled : Offset := 0;
      Count  : Natural := 0;
   begin
      Wipe (Item);
      Status := Ok;

      --  The chain, leaf first, each block decoded where the last one ended.
      loop
         declare
            Room : constant Offset := Maximum_Chain_Size - Filled;
            Last : Offset;
            PEM_Status : CryptoLib.PEM.Decode_Status;
         begin
            exit when Room <= 0;

            CryptoLib.PEM.Decode_Block
              (Certificate_Chain_PEM,
               CryptoLib.PEM.Certificate_Label,
               Cursor,
               Item.Chain (Filled + 1 .. Filled + Room),
               Last,
               PEM_Status);

            exit when PEM_Status = CryptoLib.PEM.No_Block_Found;

            if PEM_Status = CryptoLib.PEM.Buffer_Too_Small then
               Status := Chain_Too_Large;
               Wipe (Item);
               return;
            end if;

            if PEM_Status /= CryptoLib.PEM.Ok then
               Status := Malformed_Certificate;
               Wipe (Item);
               return;
            end if;

            if Count = Maximum_Chain then
               Status := Chain_Too_Long;
               Wipe (Item);
               return;
            end if;

            Count := Count + 1;
            Item.Spans (Count) := (First => Filled + 1, Last => Last);
            Filled := Last;
         end;
      end loop;

      if Count = 0 then
         Status := Empty_Chain;
         Wipe (Item);
         return;
      end if;

      Item.Count := Count;
      Item.Held := Filled;

      --  Every certificate must decode, and each must be issued by the one
      --  after it. A chain in the wrong order is a configuration mistake that
      --  otherwise shows up as a handshake failure somewhere else.
      declare
         Decode_Status : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         for I in 1 .. Count loop
            declare
               Cert : constant Certificate :=
                 X509C.Decode_DER
                   (Item.Chain (Item.Spans (I).First .. Item.Spans (I).Last),
                    CryptoLib.ASN1.Default_Limits, Decode_Status);
            begin
               if Decode_Status /= CryptoLib.ASN1.Errors.Ok
                 or else not X509C.Is_Present (Cert)
               then
                  Status := Malformed_Certificate;
                  Wipe (Item);
                  return;
               end if;

               if I < Count then
                  declare
                     Above : constant Certificate :=
                       X509C.Decode_DER
                         (Item.Chain (Item.Spans (I + 1).First
                                      .. Item.Spans (I + 1).Last),
                          CryptoLib.ASN1.Default_Limits, Decode_Status);
                  begin
                     if Decode_Status /= CryptoLib.ASN1.Errors.Ok then
                        Status := Malformed_Certificate;
                        Wipe (Item);
                        return;
                     end if;

                     if not Same_Bytes
                              (X509C.Issuer_Bytes (Cert),
                               X509C.Subject_Bytes (Above))
                     then
                        Status := Chain_Out_Of_Order;
                        Wipe (Item);
                        return;
                     end if;
                  end;
               end if;
            end;
         end loop;
      end;

      --  The key.
      declare
         Key_DER : constant String := Private_Key_PEM;
         Buffer  : Ada.Streams.Stream_Element_Array
           (1 .. Offset (CryptoLib.PEM.Maximum_Decoded_Length (Key_DER)));
         Last    : Offset;
         From    : Positive := Key_DER'First;
         PEM_St  : CryptoLib.PEM.Decode_Status;
         Key_St  : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         CryptoLib.PEM.Decode_Block
           (Key_DER, CryptoLib.PEM.Private_Key_Label, From, Buffer, Last,
            PEM_St);
         if PEM_St /= CryptoLib.PEM.Ok then
            Status := Malformed_Private_Key;
            Wipe (Item);
            return;
         end if;

         CryptoLib.PKCS8.Decode_DER
           (Buffer (Buffer'First .. Last), CryptoLib.ASN1.Default_Limits,
            Item.Key, Key_St);
         if Key_St /= CryptoLib.ASN1.Errors.Ok
           or else not CryptoLib.PKCS8.Is_Present (Item.Key)
         then
            Status := Malformed_Private_Key;
            Wipe (Item);
            return;
         end if;
      end;

      declare
         Decode_Status : CryptoLib.ASN1.Errors.Decode_Status;
         Leaf : constant Certificate :=
           X509C.Decode_DER
             (Item.Chain (Item.Spans (1).First .. Item.Spans (1).Last),
              CryptoLib.ASN1.Default_Limits, Decode_Status);
         Decided : Boolean;
         Matches : constant Boolean := Key_Matches (Item.Key, Leaf, Decided);
      begin
         if not Decided then
            Status := Unsupported_Key;
            Wipe (Item);
            return;
         end if;

         if not Matches then
            Status := Key_Mismatch;
            Wipe (Item);
            return;
         end if;
      end;

      Item.Present := True;
   end Decode;

   function Is_Present (Item : Local_Identity) return Boolean
   is (Item.Present);

   function Chain_Length (Item : Local_Identity) return Natural
   is (if Item.Present then Item.Count else 0);

   function Certificate_Bytes
     (Item : Local_Identity; Index : Positive) return Octets
   is (if not Item.Present or else Index > Item.Count
       then Empty_Octets
       else Item.Chain (Item.Spans (Index).First .. Item.Spans (Index).Last));

   function Key_Algorithm_Of
     (Item : Local_Identity) return Public_Key_Algorithm
   is (CryptoLib.PKCS8.Algorithm_Of (Item.Key));

end CryptoLib.Identities;
