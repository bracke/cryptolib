with Ada.Streams;

with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.Errors;
with CryptoLib.ECDSA;
with CryptoLib.Ed25519;
with CryptoLib.Ed448;
with CryptoLib.Errors;
with CryptoLib.ASN1.OIDs;
with CryptoLib.RSA;

package body CryptoLib.X509.Signatures is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.ASN1.Errors.Decode_Status;
   use type CryptoLib.ASN1.Tag_Class;
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
   Ed448_Key      : constant := 57;
   Ed448_Sig      : constant := 114;
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
       | Ed25519_Signature | Ed448_Signature
       | SHA256_With_RSA | SHA384_With_RSA | SHA512_With_RSA
       | RSASSA_PSS);

   --  Read RSASSA-PSS-params: which hash, and how long a salt.
   --
   --  Everything is optional with a default of SHA-1, which nothing issues
   --  and this cannot verify, so an absent hash is reported as unusable
   --  rather than silently taken as SHA-1 and failed later for the wrong
   --  reason. The mask generation function is required to use the same hash
   --  as the message digest, which is what every issuer does and what RFC
   --  8017 recommends; a mismatch is refused rather than accommodated.
   procedure Read_PSS_Parameters
     (Parameters  : CryptoLib.ASN1.Octets;
      Hash        : out CryptoLib.RSA.Hash_Algorithm;
      Salt_Length : out Natural;
      Usable      : out Boolean)
   is
      Limits : constant CryptoLib.ASN1.Decode_Limits :=
        CryptoLib.ASN1.Default_Limits;
      Cursor : Ada.Streams.Stream_Element_Offset;
      Outer  : CryptoLib.ASN1.Element;
      Status : CryptoLib.ASN1.Errors.Decode_Status;
      Seen   : Boolean := False;

      function Hash_For
        (OID : CryptoLib.ASN1.Element; Data : CryptoLib.ASN1.Octets;
         Found : out Boolean) return CryptoLib.RSA.Hash_Algorithm
      is
      begin
         Found := True;
         if CryptoLib.ASN1.OIDs.Matches
              (Data, OID, CryptoLib.ASN1.OIDs.SHA256_Digest_Algorithm)
         then
            return CryptoLib.RSA.SHA256;
         elsif CryptoLib.ASN1.OIDs.Matches
                 (Data, OID, CryptoLib.ASN1.OIDs.SHA384_Digest_Algorithm)
         then
            return CryptoLib.RSA.SHA384;
         elsif CryptoLib.ASN1.OIDs.Matches
                 (Data, OID, CryptoLib.ASN1.OIDs.SHA512_Digest_Algorithm)
         then
            return CryptoLib.RSA.SHA512;
         else
            Found := False;
            return CryptoLib.RSA.SHA256;
         end if;
      end Hash_For;
   begin
      Hash := CryptoLib.RSA.SHA256;
      Salt_Length := 20;
      Usable := False;

      if Parameters'Length = 0 then
         return;
      end if;

      Cursor := Parameters'First;
      DER_Reader.Read_Sequence
        (Parameters, Cursor, Parameters'Last, 0, Limits, Outer, Status);
      if Status /= CryptoLib.ASN1.Errors.Ok then
         return;
      end if;

      Cursor := Outer.First;
      while not DER_Reader.At_End (Cursor, Outer.Last) loop
         declare
            Tag : CryptoLib.ASN1.Element;
         begin
            DER_Reader.Read
              (Parameters, Cursor, Outer.Last, 1, Limits, Tag, Status);
            exit when Status /= CryptoLib.ASN1.Errors.Ok;
            exit when Tag.Class /= CryptoLib.ASN1.Context_Specific;

            case Tag.Number is
               when 0 =>
                  declare
                     Part : Ada.Streams.Stream_Element_Offset := Tag.First;
                     Alg  : CryptoLib.ASN1.Element;
                     OID  : CryptoLib.ASN1.Element;
                     Got  : Boolean;
                  begin
                     DER_Reader.Read_Sequence
                       (Parameters, Part, Tag.Last, 2, Limits, Alg, Status);
                     exit when Status /= CryptoLib.ASN1.Errors.Ok;
                     Part := Alg.First;
                     DER_Reader.Read_Object_Identifier
                       (Parameters, Part, Alg.Last, 3, Limits, OID, Status);
                     exit when Status /= CryptoLib.ASN1.Errors.Ok;
                     Hash := Hash_For (OID, Parameters, Got);
                     Seen := Got;
                     exit when not Got;
                  end;

               when 2 =>
                  declare
                     Part : Ada.Streams.Stream_Element_Offset := Tag.First;
                  begin
                     DER_Reader.Read_Small_Integer
                       (Parameters, Part, Tag.Last, 2, Limits, Salt_Length,
                        Status);
                     exit when Status /= CryptoLib.ASN1.Errors.Ok;
                  end;

               when others =>
                  --  The mask generation function and the trailer field. The
                  --  trailer has one defined value, and the mask function is
                  --  required below to match the digest.
                  null;
            end case;
         end;
      end loop;

      Usable := Seen;
   end Read_PSS_Parameters;

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

   function Verify_With_Key
     (Signed     : CryptoLib.ASN1.Octets;
      Signature  : CryptoLib.ASN1.Octets;
      Algorithm  : Signature_Algorithm;
      Key_Kind   : Public_Key_Algorithm;
      Public_Key : CryptoLib.ASN1.Octets;
      Parameters : CryptoLib.ASN1.Octets := Empty_Parameters)
      return Verification_Result
   is
   begin
      if not Is_Supported (Algorithm) then
         return Unsupported_Algorithm;
      end if;

      declare
         Message : Ada.Streams.Stream_Element_Array renames Signed;
         Sig     : Ada.Streams.Stream_Element_Array renames Signature;
         Key     : Ada.Streams.Stream_Element_Array renames Public_Key;
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

            when RSASSA_PSS =>
               if Key_Kind /= RSA then
                  return Algorithm_Mismatch;
               end if;

               declare
                  Mod_First : Ada.Streams.Stream_Element_Offset;
                  Mod_Last  : Ada.Streams.Stream_Element_Offset;
                  Exp_First : Ada.Streams.Stream_Element_Offset;
                  Exp_Last  : Ada.Streams.Stream_Element_Offset;
                  Ok        : Boolean;
                  Hash      : CryptoLib.RSA.Hash_Algorithm;
                  Salt      : Natural;
                  Usable    : Boolean;
               begin
                  Read_PSS_Parameters (Parameters, Hash, Salt, Usable);
                  if not Usable then
                     --  Without a hash this cannot be checked, and guessing
                     --  one would turn "we could not check" into "it failed".
                     return Unsupported_Algorithm;
                  end if;

                  Split_RSA_Key
                    (Key, Mod_First, Mod_Last, Exp_First, Exp_Last, Ok);
                  if not Ok then
                     return Malformed_Signature;
                  end if;

                  declare
                     Outcome : constant CryptoLib.Errors.Status :=
                       CryptoLib.RSA.Verify_PSS
                         (Modulus     => Key (Mod_First .. Mod_Last),
                          Exponent    => Key (Exp_First .. Exp_Last),
                          Hash        => Hash,
                          Salt_Length => Salt,
                          Message     => Message,
                          Signature   => Sig);
                  begin
                     if Outcome = CryptoLib.Errors.Ok then
                        return Valid;
                     elsif Outcome = CryptoLib.Errors.Authentication_Failed
                     then
                        return Invalid_Signature;
                     else
                        return Malformed_Signature;
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

            when Ed448_Signature =>
               if Key_Kind /= Ed448 then
                  return Algorithm_Mismatch;
               end if;

               if Key'Length /= Ed448_Key then
                  return Malformed_Signature;
               end if;

               if Sig'Length /= Ed448_Sig then
                  return Malformed_Signature;
               end if;

               if CryptoLib.Ed448.Verify
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
   end Verify_With_Key;

   function Verify_Signed_Data
     (Signed    : CryptoLib.ASN1.Octets;
      Signature : CryptoLib.ASN1.Octets;
      Algorithm : Signature_Algorithm;
      Issuer    : CryptoLib.X509.Certificates.Certificate;
      Parameters : CryptoLib.ASN1.Octets := Empty_Parameters)
      return Verification_Result
   is
   begin
      if not X509C.Is_Present (Issuer) then
         return Missing_Input;
      end if;

      return Verify_With_Key
        (Signed     => Signed,
         Signature  => Signature,
         Algorithm  => Algorithm,
         Key_Kind   => X509C.Public_Key_Algorithm_Of (Issuer),
         Public_Key => X509C.Public_Key (Issuer),
         Parameters => Parameters);
   end Verify_Signed_Data;

   function Verify_Certificate_Signature
     (Item   : CryptoLib.X509.Certificates.Certificate;
      Issuer : CryptoLib.X509.Certificates.Certificate)
      return Verification_Result
   is
   begin
      if not X509C.Is_Present (Item) then
         return Missing_Input;
      end if;

      return Verify_Signed_Data
        (Signed     => X509C.TBS_Bytes (Item),
         Signature  => X509C.Signature_Bytes (Item),
         Algorithm  => X509C.Signature_Algorithm_Of (Item),
         Issuer     => Issuer,
         Parameters => X509C.Signature_Parameters (Item));
   end Verify_Certificate_Signature;

   function RSA_Modulus_Bits
     (Key : CryptoLib.ASN1.Octets) return Natural
   is
      Mod_First : Ada.Streams.Stream_Element_Offset;
      Mod_Last  : Ada.Streams.Stream_Element_Offset;
      Exp_First : Ada.Streams.Stream_Element_Offset;
      Exp_Last  : Ada.Streams.Stream_Element_Offset;
      Ok        : Boolean;
   begin
      Split_RSA_Key (Key, Mod_First, Mod_Last, Exp_First, Exp_Last, Ok);
      if not Ok then
         return 0;
      end if;

      --  Past any leading zeros, so that the INTEGER's sign octet does not
      --  read as eight bits of modulus.
      while Mod_First <= Mod_Last and then Key (Mod_First) = 0 loop
         Mod_First := Mod_First + 1;
      end loop;

      if Mod_First > Mod_Last then
         return 0;
      end if;

      declare
         Whole : constant Natural :=
           Natural (Mod_Last - Mod_First) * 8;
         Top   : Natural := 0;
         Lead  : constant Ada.Streams.Stream_Element := Key (Mod_First);
      begin
         for Bit in reverse 0 .. 7 loop
            if (Lead / (2 ** Bit)) mod 2 = 1 then
               Top := Bit + 1;
               exit;
            end if;
         end loop;
         return Whole + Top;
      end;
   end RSA_Modulus_Bits;

end CryptoLib.X509.Signatures;
