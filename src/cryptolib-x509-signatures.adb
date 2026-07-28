with Ada.Streams;

with CryptoLib.ASN1;
with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.Errors;
with CryptoLib.ECDSA;
with CryptoLib.Ed25519;
with CryptoLib.Errors;
with CryptoLib.RSA;

package body CryptoLib.X509.Signatures is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.ASN1.Errors.Decode_Status;
   use type CryptoLib.Errors.Status;

   package X509C renames CryptoLib.X509.Certificates;
   package DER_Reader renames CryptoLib.ASN1.DER;

   P256_Component : constant := 32;
   P256_Point     : constant := 65;
   P384_Component : constant := 48;
   P384_Point     : constant := 97;
   P521_Component : constant := 66;
   P521_Point     : constant := 133;
   Ed25519_Key    : constant := 32;
   Ed25519_Sig    : constant := 64;

   function Result_Image (Result : Verification_Result) return String is
   begin
      case Result is
         when Valid                 => return "valid";
         when Invalid_Signature     => return "invalid signature";
         when Algorithm_Mismatch    => return "algorithm mismatch";
         when Unsupported_Algorithm => return "unsupported algorithm";
         when Malformed_Signature   => return "malformed signature";
         when Missing_Input         => return "missing input";
      end case;
   end Result_Image;

   function Is_Supported (Algorithm : Signature_Algorithm) return Boolean
   is (Algorithm in ECDSA_With_SHA256 | ECDSA_With_SHA384 | ECDSA_With_SHA512
       | Ed25519_Signature
       | SHA256_With_RSA | SHA384_With_RSA | SHA512_With_RSA);

   --  Take an RSAPublicKey apart into its modulus and exponent.
   --
   --  The key sits inside the SubjectPublicKeyInfo BIT STRING as its own
   --  SEQUENCE of two integers, so this is a second decode within the first.
   procedure Split_RSA_Key
     (Key      : Ada.Streams.Stream_Element_Array;
      Mod_First : out Ada.Streams.Stream_Element_Offset;
      Mod_Last  : out Ada.Streams.Stream_Element_Offset;
      Exp_First : out Ada.Streams.Stream_Element_Offset;
      Exp_Last  : out Ada.Streams.Stream_Element_Offset;
      Ok        : out Boolean)
   is
      Limits : constant CryptoLib.ASN1.Decode_Limits :=
        CryptoLib.ASN1.Default_Limits;
      Cursor : Ada.Streams.Stream_Element_Offset;
      Outer  : CryptoLib.ASN1.Element;
      Item   : CryptoLib.ASN1.Element;
      Status : CryptoLib.ASN1.Errors.Decode_Status;
      Signed : Boolean;
   begin
      Mod_First := 1;
      Mod_Last  := 0;
      Exp_First := 1;
      Exp_Last  := 0;
      Ok := False;

      if Key'Length = 0 then
         return;
      end if;

      Cursor := Key'First;
      DER_Reader.Read_Sequence
        (Key, Cursor, Key'Last, 0, Limits, Outer, Status);
      if Status /= CryptoLib.ASN1.Errors.Ok
        or else not DER_Reader.At_End (Cursor, Key'Last)
      then
         return;
      end if;

      Cursor := Outer.First;
      DER_Reader.Read_Integer
        (Key, Cursor, Outer.Last, 1, Limits, Item, Signed, Status);
      if Status /= CryptoLib.ASN1.Errors.Ok or else Signed then
         return;
      end if;
      Mod_First := Item.First;
      Mod_Last  := Item.Last;

      DER_Reader.Read_Integer
        (Key, Cursor, Outer.Last, 1, Limits, Item, Signed, Status);
      if Status /= CryptoLib.ASN1.Errors.Ok or else Signed then
         return;
      end if;
      Exp_First := Item.First;
      Exp_Last  := Item.Last;

      Ok := DER_Reader.At_End (Cursor, Outer.Last);
   end Split_RSA_Key;

   --  Copy an ECDSA signature component into a fixed-width field.
   --
   --  A DER INTEGER is minimal and signed, so r may arrive with a leading
   --  zero it does not need in a fixed-width field, or shorter than the field
   --  when its top bytes happen to be zero. Both are ordinary; a component
   --  genuinely wider than the curve is not.
   procedure Place_Component
     (Source : Ada.Streams.Stream_Element_Array;
      Target : out Ada.Streams.Stream_Element_Array;
      Ok     : out Boolean)
   is
      First : Ada.Streams.Stream_Element_Offset := Source'First;
   begin
      Target := [others => 0];
      Ok := False;

      while First <= Source'Last and then Source (First) = 0 loop
         First := First + 1;
      end loop;

      if First > Source'Last then
         --  A zero component is not a signature component.
         return;
      end if;

      if Source'Last - First + 1 > Target'Length then
         return;
      end if;

      Target (Target'Last - (Source'Last - First) .. Target'Last) :=
        Source (First .. Source'Last);
      Ok := True;
   end Place_Component;

   --  Split a DER ECDSA-Sig-Value into its two components.
   procedure Split_ECDSA_Signature
     (Signature : Ada.Streams.Stream_Element_Array;
      R         : out Ada.Streams.Stream_Element_Array;
      S         : out Ada.Streams.Stream_Element_Array;
      Ok        : out Boolean)
   is
      Limits : constant CryptoLib.ASN1.Decode_Limits :=
        CryptoLib.ASN1.Default_Limits;
      Cursor : Ada.Streams.Stream_Element_Offset;
      Outer  : CryptoLib.ASN1.Element;
      Item   : CryptoLib.ASN1.Element;
      Status : CryptoLib.ASN1.Errors.Decode_Status;
      Signed : Boolean;
   begin
      R := [others => 0];
      S := [others => 0];
      Ok := False;

      if Signature'Length = 0 then
         return;
      end if;

      Cursor := Signature'First;
      DER_Reader.Read_Sequence
        (Signature, Cursor, Signature'Last, 0, Limits, Outer, Status);
      if Status /= CryptoLib.ASN1.Errors.Ok then
         return;
      end if;

      if not DER_Reader.At_End (Cursor, Signature'Last) then
         return;
      end if;

      Cursor := Outer.First;
      DER_Reader.Read_Integer
        (Signature, Cursor, Outer.Last, 1, Limits, Item, Signed, Status);
      if Status /= CryptoLib.ASN1.Errors.Ok or else Signed then
         return;
      end if;
      Place_Component (Signature (Item.First .. Item.Last), R, Ok);
      if not Ok then
         return;
      end if;

      DER_Reader.Read_Integer
        (Signature, Cursor, Outer.Last, 1, Limits, Item, Signed, Status);
      if Status /= CryptoLib.ASN1.Errors.Ok or else Signed then
         Ok := False;
         return;
      end if;
      Place_Component (Signature (Item.First .. Item.Last), S, Ok);
      if not Ok then
         return;
      end if;

      --  Two integers and nothing else.
      Ok := DER_Reader.At_End (Cursor, Outer.Last);
   end Split_ECDSA_Signature;

   function Verify_Certificate_Signature
     (Item   : CryptoLib.X509.Certificates.Certificate;
      Issuer : CryptoLib.X509.Certificates.Certificate)
      return Verification_Result
   is
      Algorithm : constant Signature_Algorithm :=
        X509C.Signature_Algorithm_Of (Item);
      Key_Kind  : constant Public_Key_Algorithm :=
        X509C.Public_Key_Algorithm_Of (Issuer);
   begin
      if not X509C.Is_Present (Item) or else not X509C.Is_Present (Issuer) then
         return Missing_Input;
      end if;

      if not Is_Supported (Algorithm) then
         return Unsupported_Algorithm;
      end if;

      declare
         Message : constant Ada.Streams.Stream_Element_Array :=
           X509C.TBS_Bytes (Item);
         Sig     : constant Ada.Streams.Stream_Element_Array :=
           X509C.Signature_Bytes (Item);
         Key     : constant Ada.Streams.Stream_Element_Array :=
           X509C.Public_Key (Issuer);
      begin
         if Message'Length = 0 or else Sig'Length = 0 or else Key'Length = 0
         then
            return Missing_Input;
         end if;

         case Algorithm is
            when ECDSA_With_SHA256 | ECDSA_With_SHA384 | ECDSA_With_SHA512 =>
               --  The algorithm names the digest; the key names the curve.
               --  They are independent -- a P-521 key signing with SHA-256 is
               --  ordinary and legal -- so pairing them would refuse
               --  certificates that are perfectly valid.
               declare
                  Curve : constant CryptoLib.ECDSA.Curve_Id :=
                    (case Key_Kind is
                        when ECDSA_P256 => CryptoLib.ECDSA.Nistp256,
                        when ECDSA_P384 => CryptoLib.ECDSA.Nistp384,
                        when others     => CryptoLib.ECDSA.Nistp521);
                  Digest : constant CryptoLib.ECDSA.Digest_Id :=
                    (case Algorithm is
                        when ECDSA_With_SHA256 => CryptoLib.ECDSA.SHA256,
                        when ECDSA_With_SHA384 => CryptoLib.ECDSA.SHA384,
                        when others            => CryptoLib.ECDSA.SHA512);
                  Point_Length : constant Natural :=
                    (case Key_Kind is
                        when ECDSA_P256 => P256_Point,
                        when ECDSA_P384 => P384_Point,
                        when others     => P521_Point);
                  Width : constant Ada.Streams.Stream_Element_Offset :=
                    (case Key_Kind is
                        when ECDSA_P256 => P256_Component,
                        when ECDSA_P384 => P384_Component,
                        when others     => P521_Component);
               begin
                  if Key_Kind not in ECDSA_P256 | ECDSA_P384 | ECDSA_P521 then
                     return Algorithm_Mismatch;
                  end if;

                  --  Only the uncompressed point form. A compressed point
                  --  would have to be decompressed to be used, and this crate
                  --  does not do that; saying so beats guessing.
                  if Natural (Key'Length) /= Point_Length
                    or else Key (Key'First) /= 16#04#
                  then
                     return Malformed_Signature;
                  end if;

                  declare
                     R  : Ada.Streams.Stream_Element_Array (1 .. Width);
                     S  : Ada.Streams.Stream_Element_Array (1 .. Width);
                     Ok : Boolean;
                  begin
                     Split_ECDSA_Signature (Sig, R, S, Ok);
                     if not Ok then
                        return Malformed_Signature;
                     end if;

                     if CryptoLib.ECDSA.Verify_Signature
                          (Curve         => Curve,
                           Digest        => Digest,
                           Public_Point  => Key,
                           Message_Bytes => Message,
                           R_Bytes       => R,
                           S_Bytes       => S) = CryptoLib.Errors.Ok
                     then
                        return Valid;
                     else
                        return Invalid_Signature;
                     end if;
                  end;
               end;

            when SHA256_With_RSA | SHA384_With_RSA | SHA512_With_RSA =>
               if Key_Kind /= RSA then
                  return Algorithm_Mismatch;
               end if;

               declare
                  Mod_First : Ada.Streams.Stream_Element_Offset;
                  Mod_Last  : Ada.Streams.Stream_Element_Offset;
                  Exp_First : Ada.Streams.Stream_Element_Offset;
                  Exp_Last  : Ada.Streams.Stream_Element_Offset;
                  Ok        : Boolean;
               begin
                  Split_RSA_Key
                    (Key, Mod_First, Mod_Last, Exp_First, Exp_Last, Ok);
                  if not Ok then
                     return Malformed_Signature;
                  end if;

                  declare
                     Digest : constant CryptoLib.RSA.Hash_Algorithm :=
                       (case Algorithm is
                           when SHA256_With_RSA => CryptoLib.RSA.SHA256,
                           when SHA384_With_RSA => CryptoLib.RSA.SHA384,
                           when others          => CryptoLib.RSA.SHA512);
                     Outcome : constant CryptoLib.Errors.Status :=
                       CryptoLib.RSA.Verify_PKCS1_V1_5
                         (Modulus   => Key (Mod_First .. Mod_Last),
                          Exponent  => Key (Exp_First .. Exp_Last),
                          Hash      => Digest,
                          Message   => Message,
                          Signature => Sig);
                  begin
                     if Outcome = CryptoLib.Errors.Ok then
                        return Valid;
                     elsif Outcome = CryptoLib.Errors.Authentication_Failed
                     then
                        return Invalid_Signature;
                     else
                        --  A key or signature that cannot be used at all:
                        --  wrong-length signature, unusable modulus.
                        return Malformed_Signature;
                     end if;
                  end;
               end;

            when Ed25519_Signature =>
               if Key_Kind /= Ed25519 then
                  return Algorithm_Mismatch;
               end if;

               if Key'Length /= Ed25519_Key then
                  return Malformed_Signature;
               end if;

               if Sig'Length /= Ed25519_Sig then
                  return Malformed_Signature;
               end if;

               if CryptoLib.Ed25519.Verify
                    (Public_Key_Bytes => Key,
                     Signature_Bytes  => Sig,
                     Message_Bytes    => Message) = CryptoLib.Errors.Ok
               then
                  return Valid;
               else
                  return Invalid_Signature;
               end if;

            when others =>
               return Unsupported_Algorithm;
         end case;
      end;
   end Verify_Certificate_Signature;

end CryptoLib.X509.Signatures;
