with Ada.Streams;

with CryptoLib.ASN1;
with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.Errors;
with CryptoLib.ECDSA;
with CryptoLib.Ed25519;
with CryptoLib.Errors;

package body CryptoLib.X509.Signatures is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.ASN1.Errors.Decode_Status;
   use type CryptoLib.Errors.Status;

   package X509C renames CryptoLib.X509.Certificates;
   package DER_Reader renames CryptoLib.ASN1.DER;

   P384_Component : constant := 48;
   P384_Point     : constant := 97;
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
   is (Algorithm in ECDSA_With_SHA384 | Ed25519_Signature);

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
            when ECDSA_With_SHA384 =>
               if Key_Kind /= ECDSA_P384 then
                  return Algorithm_Mismatch;
               end if;

               --  Only the uncompressed point form. A compressed point would
               --  have to be decompressed to be used, and this crate does not
               --  do that; saying so beats guessing.
               if Key'Length /= P384_Point
                 or else Key (Key'First) /= 16#04#
               then
                  return Malformed_Signature;
               end if;

               declare
                  R  : Ada.Streams.Stream_Element_Array
                    (1 .. P384_Component);
                  S  : Ada.Streams.Stream_Element_Array
                    (1 .. P384_Component);
                  Ok : Boolean;
               begin
                  Split_ECDSA_Signature (Sig, R, S, Ok);
                  if not Ok then
                     return Malformed_Signature;
                  end if;

                  if CryptoLib.ECDSA.Verify_Nistp384_Raw
                       (Public_Point  => Key,
                        Message_Bytes => Message,
                        R_Bytes       => R,
                        S_Bytes       => S) = CryptoLib.Errors.Ok
                  then
                     return Valid;
                  else
                     return Invalid_Signature;
                  end if;
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
