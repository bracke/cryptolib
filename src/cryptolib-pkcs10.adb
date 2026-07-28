with Ada.Streams;

with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.OIDs;
with CryptoLib.X509.Names;

package body CryptoLib.PKCS10 is

   use CryptoLib.ASN1;
   use CryptoLib.ASN1.Errors;
   use CryptoLib.X509;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;

   package DER_Reader renames CryptoLib.ASN1.DER;
   package OID_Table renames CryptoLib.ASN1.OIDs;

   Empty_Octets : constant Octets (1 .. 0) := [others => 0];

   function Slice (Item : Request; Where : Span) return Octets
   is (if Where.Last < Where.First
       then Empty_Octets
       else Item.DER (Where.First .. Where.Last));

   function Signature_Algorithm_For
     (Data : Octets; OID : Element) return Signature_Algorithm
   is
   begin
      if OID_Table.Matches (Data, OID, OID_Table.ECDSA_With_SHA384) then
         return ECDSA_With_SHA384;
      elsif OID_Table.Matches (Data, OID, OID_Table.ECDSA_With_SHA256) then
         return ECDSA_With_SHA256;
      elsif OID_Table.Matches (Data, OID, OID_Table.ECDSA_With_SHA512) then
         return ECDSA_With_SHA512;
      elsif OID_Table.Matches (Data, OID, OID_Table.SHA256_With_RSA) then
         return SHA256_With_RSA;
      elsif OID_Table.Matches (Data, OID, OID_Table.SHA384_With_RSA) then
         return SHA384_With_RSA;
      elsif OID_Table.Matches (Data, OID, OID_Table.SHA512_With_RSA) then
         return SHA512_With_RSA;
      elsif OID_Table.Matches (Data, OID, OID_Table.RSASSA_PSS) then
         return RSASSA_PSS;
      elsif OID_Table.Matches (Data, OID, OID_Table.Ed25519) then
         return Ed25519_Signature;
      elsif OID_Table.Matches (Data, OID, OID_Table.Ed448) then
         return Ed448_Signature;
      else
         return Unknown_Signature_Algorithm;
      end if;
   end Signature_Algorithm_For;

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

   function Decode_DER
     (Data   : Octets;
      Limits : Decode_Limits;
      Status : out Decode_Status) return Request
   is
      Result : Request (Data'Length);
      Shift  : constant Offset := 1 - Data'First;
      Work   : Octets renames Result.DER;

      Cursor : Offset;
      Outer  : Element;
      Info   : Element;
      Field  : Element;
      Alg_ID : Element;
      Param  : Element;
      Has_P  : Boolean;
      Inner  : Offset;
   begin
      Status := Ok;

      if Data'Length = 0 then
         Status := Truncated_Input;
         return Result;
      end if;

      if Natural (Data'Length) > Limits.Maximum_Input_Size then
         Status := Size_Limit_Exceeded;
         return Result;
      end if;

      for I in Data'Range loop
         Work (I + Shift) := Data (I);
      end loop;

      Cursor := Work'First;
      DER_Reader.Read_Sequence
        (Work, Cursor, Work'Last, 0, Limits, Outer, Status);
      if Status /= Ok then
         return Result;
      end if;

      if not DER_Reader.At_End (Cursor, Work'Last) then
         Status := Trailing_Data;
         return Result;
      end if;

      Cursor := Outer.First;
      DER_Reader.Read_Sequence
        (Work, Cursor, Outer.Last, 1, Limits, Info, Status);
      if Status /= Ok then
         return Result;
      end if;
      Result.TBS :=
        (First => Encoded_First (Info), Last => Encoded_Last (Info));

      Read_Algorithm
        (Work, Cursor, Outer.Last, 1, Limits, Alg_ID, Param, Has_P, Status);
      if Status /= Ok then
         return Result;
      end if;
      Result.Algorithm := Signature_Algorithm_For (Work, Alg_ID);

      declare
         Unused : Natural;
      begin
         DER_Reader.Read_Bit_String
           (Work, Cursor, Outer.Last, 1, Limits, Field, Unused, Status);
         if Status /= Ok then
            return Result;
         end if;
         if Unused /= 0 then
            Status := Invalid_Value;
            return Result;
         end if;
         Result.Signature := (First => Field.First, Last => Field.Last);
      end;

      if not DER_Reader.At_End (Cursor, Outer.Last) then
         Status := Trailing_Data;
         return Result;
      end if;

      --  CertificationRequestInfo ::= SEQUENCE { version, subject,
      --      subjectPKInfo, attributes [0] IMPLICIT }
      Inner := Info.First;

      declare
         Version : Natural;
      begin
         DER_Reader.Read_Small_Integer
           (Work, Inner, Info.Last, 2, Limits, Version, Status);
         if Status /= Ok then
            return Result;
         end if;
         if Version /= 0 then
            --  Only v1 is defined. A later one would have rules this does not
            --  know, so reading it as v1 would be reading it wrongly.
            Status := Unsupported_Encoding;
            return Result;
         end if;
      end;

      DER_Reader.Read_Sequence
        (Work, Inner, Info.Last, 2, Limits, Field, Status);
      if Status /= Ok then
         return Result;
      end if;
      Result.Subject :=
        (First => Encoded_First (Field), Last => Encoded_Last (Field));

      declare
         SPKI   : Element;
         Within : Offset;
         Bits   : Element;
         Unused : Natural;
      begin
         DER_Reader.Read_Sequence
           (Work, Inner, Info.Last, 2, Limits, SPKI, Status);
         if Status /= Ok then
            return Result;
         end if;
         Result.SPKI :=
           (First => Encoded_First (SPKI), Last => Encoded_Last (SPKI));

         Within := SPKI.First;
         Read_Algorithm
           (Work, Within, SPKI.Last, 3, Limits, Alg_ID, Param, Has_P, Status);
         if Status /= Ok then
            return Result;
         end if;

         if OID_Table.Matches (Work, Alg_ID, OID_Table.Ed25519) then
            Result.Key_Kind := Ed25519;
         elsif OID_Table.Matches (Work, Alg_ID, OID_Table.Ed448) then
            Result.Key_Kind := Ed448;
         elsif OID_Table.Matches (Work, Alg_ID, OID_Table.RSA_Encryption) then
            Result.Key_Kind := RSA;
         elsif OID_Table.Matches (Work, Alg_ID, OID_Table.EC_Public_Key) then
            if not Has_P then
               Result.Key_Kind := Unknown_Public_Key_Algorithm;
            elsif OID_Table.Matches (Work, Param, OID_Table.Prime256v1) then
               Result.Key_Kind := ECDSA_P256;
            elsif OID_Table.Matches (Work, Param, OID_Table.Secp384r1) then
               Result.Key_Kind := ECDSA_P384;
            elsif OID_Table.Matches (Work, Param, OID_Table.Secp521r1) then
               Result.Key_Kind := ECDSA_P521;
            else
               Result.Key_Kind := Unknown_Public_Key_Algorithm;
            end if;
         else
            Result.Key_Kind := Unknown_Public_Key_Algorithm;
         end if;

         DER_Reader.Read_Bit_String
           (Work, Within, SPKI.Last, 3, Limits, Bits, Unused, Status);
         if Status /= Ok then
            return Result;
         end if;
         if Unused /= 0 then
            Status := Invalid_Value;
            return Result;
         end if;
         Result.SPKI_Key := (First => Bits.First, Last => Bits.Last);

         if not DER_Reader.At_End (Within, SPKI.Last) then
            Status := Trailing_Data;
            return Result;
         end if;
      end;

      --  attributes [0] IMPLICIT SET OF Attribute. Present but not
      --  interpreted: a requested extension is a request, and what a CA puts
      --  in the certificate is the CA's decision rather than the asker's.
      if not DER_Reader.At_End (Inner, Info.Last) then
         declare
            Attributes : Element;
         begin
            DER_Reader.Read_Expected
              (Work, Inner, Info.Last, 2, Limits,
               Context_Specific, 0, True, Attributes, Status);
            if Status /= Ok then
               return Result;
            end if;
         end;
      end if;

      if not DER_Reader.At_End (Inner, Info.Last) then
         Status := Trailing_Data;
         return Result;
      end if;

      Result.Present := True;
      return Result;
   end Decode_DER;

   function Is_Present (Item : Request) return Boolean
   is (Item.Present);

   function Subject_Bytes (Item : Request) return Octets
   is (Slice (Item, Item.Subject));

   function Subject_Common_Name (Item : Request) return String
   is (CryptoLib.X509.Names.Common_Name_Of (Subject_Bytes (Item)));

   function Public_Key_Info_Bytes (Item : Request) return Octets
   is (Slice (Item, Item.SPKI));

   function Public_Key (Item : Request) return Octets
   is (Slice (Item, Item.SPKI_Key));

   function Public_Key_Algorithm_Of
     (Item : Request) return Public_Key_Algorithm
   is (Item.Key_Kind);

   function Signature_Algorithm_Of
     (Item : Request) return Signature_Algorithm
   is (Item.Algorithm);

   function TBS_Bytes (Item : Request) return Octets
   is (Slice (Item, Item.TBS));

   function Verify_Signature
     (Item : Request) return CryptoLib.X509.Signatures.Verification_Result
   is
   begin
      if not Item.Present then
         return CryptoLib.X509.Signatures.Missing_Input;
      end if;

      --  Against the key the request carries: that is what makes it proof of
      --  possession rather than an assertion.
      return CryptoLib.X509.Signatures.Verify_With_Key
        (Signed     => TBS_Bytes (Item),
         Signature  => Slice (Item, Item.Signature),
         Algorithm  => Item.Algorithm,
         Key_Kind   => Item.Key_Kind,
         Public_Key => Public_Key (Item));
   end Verify_Signature;

end CryptoLib.PKCS10;
