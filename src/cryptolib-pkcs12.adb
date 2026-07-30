with Ada.Streams;

with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.Errors;
with CryptoLib.ASN1.OIDs;
with CryptoLib.Constant_Time;
with CryptoLib.Macs;
with CryptoLib.Secure_Wipe;

package body CryptoLib.PKCS12 is

   use CryptoLib.ASN1;
   use CryptoLib.ASN1.Errors;
   use type CryptoLib.PKCS8.Unlock_Status;
   use type CryptoLib.PBES2.Unlock_Status;
   use type Ada.Streams.Stream_Element_Offset;

   package DER_Reader renames CryptoLib.ASN1.DER;
   package OID_Table renames CryptoLib.ASN1.OIDs;

   Empty_Octets : constant Octets (1 .. 0) := [others => 0];

   function Status_Image (Status : Open_Status) return String is
   begin
      case Status is
         when Ok                        => return "ok";
         when Malformed                 => return "malformed";
         when Unsupported_Scheme        => return "unsupported scheme";
         when Wrong_Password_Or_Corrupt =>
            return "wrong password or corrupt";
         when No_Mac                    => return "no mac";
         when Too_Many_Certificates     => return "too many certificates";
         when Too_Large                 => return "too large";
      end case;
   end Status_Image;

   procedure Wipe (Item : in out Bundle) is
   begin
      CryptoLib.PKCS8.Wipe (Item.Key);
      if Item.Filled > 0 then
         CryptoLib.Secure_Wipe.Wipe
           (Item.Certs (Item.Certs'First)'Address, Natural (Item.Filled));
      end if;
      Item.Present := False;
      Item.Count := 0;
      Item.Filled := 0;
      Item.Has_Key := False;
   end Wipe;

   overriding procedure Finalize (Item : in out Bundle) is
   begin
      Wipe (Item);
   end Finalize;

   --  Read a ContentInfo, reporting its type and the content it wraps.
   procedure Read_Content_Info
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Kind     : out Element;
      Content  : out Element;
      Present  : out Boolean;
      Status   : out CryptoLib.ASN1.Errors.Decode_Status)
   is
      Cursor : Offset := Position;
      Outer  : Element;
      Inner  : Offset;
      Tag    : Element;
   begin
      Kind := (others => <>);
      Content := (others => <>);
      Present := False;

      DER_Reader.Read_Sequence
        (Data, Cursor, Last, Depth, Limits, Outer, Status);
      if Status /= Ok then
         return;
      end if;

      Inner := Outer.First;
      DER_Reader.Read_Object_Identifier
        (Data, Inner, Outer.Last, Depth + 1, Limits, Kind, Status);
      if Status /= Ok then
         return;
      end if;

      if not DER_Reader.At_End (Inner, Outer.Last) then
         DER_Reader.Read_Expected
           (Data, Inner, Outer.Last, Depth + 1, Limits,
            Context_Specific, 0, True, Tag, Status);
         if Status /= Ok then
            return;
         end if;
         Content := Tag;
         Present := True;
      end if;

      Position := Cursor;
   end Read_Content_Info;

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

   --  Take the certificates and the key out of a SafeContents.
   procedure Read_Safe_Contents
     (Data     : Octets;
      Region   : Element;
      Password : String;
      Limits   : Decode_Limits;
      Item     : in out Bundle;
      Status   : out Open_Status)
   is
      Parse  : CryptoLib.ASN1.Errors.Decode_Status;
      Cursor : Offset;
      Bags   : Element;
   begin
      Status := Ok;

      Cursor := Region.First;
      DER_Reader.Read_Sequence
        (Data, Cursor, Region.Last, 4, Limits, Bags, Parse);
      if Parse /= Ok then
         Status := Malformed;
         return;
      end if;

      Cursor := Bags.First;
      while not DER_Reader.At_End (Cursor, Bags.Last) loop
         declare
            Bag   : Element;
            Inner : Offset;
            Kind  : Element;
            Tag   : Element;
         begin
            DER_Reader.Read_Sequence
              (Data, Cursor, Bags.Last, 5, Limits, Bag, Parse);
            if Parse /= Ok then
               Status := Malformed;
               return;
            end if;

            Inner := Bag.First;
            DER_Reader.Read_Object_Identifier
              (Data, Inner, Bag.Last, 6, Limits, Kind, Parse);
            if Parse /= Ok then
               Status := Malformed;
               return;
            end if;

            DER_Reader.Read_Expected
              (Data, Inner, Bag.Last, 6, Limits,
               Context_Specific, 0, True, Tag, Parse);
            if Parse /= Ok then
               Status := Malformed;
               return;
            end if;

            if OID_Table.Matches (Data, Kind, OID_Table.Cert_Bag) then
               --  CertBag ::= SEQUENCE { certId, certValue [0] OCTET STRING }
               declare
                  Part : Offset := Tag.First;
                  Seq  : Element;
                  CID  : Element;
                  Wrap : Element;
                  Body_S : Element;
               begin
                  DER_Reader.Read_Sequence
                    (Data, Part, Tag.Last, 7, Limits, Seq, Parse);
                  if Parse /= Ok then
                     Status := Malformed;
                     return;
                  end if;

                  Part := Seq.First;
                  DER_Reader.Read_Object_Identifier
                    (Data, Part, Seq.Last, 8, Limits, CID, Parse);
                  if Parse /= Ok then
                     Status := Malformed;
                     return;
                  end if;

                  if OID_Table.Matches
                       (Data, CID, OID_Table.X509_Certificate_Bag)
                  then
                     DER_Reader.Read_Expected
                       (Data, Part, Seq.Last, 8, Limits,
                        Context_Specific, 0, True, Wrap, Parse);
                     if Parse /= Ok then
                        Status := Malformed;
                        return;
                     end if;

                     Part := Wrap.First;
                     DER_Reader.Read_Octet_String
                       (Data, Part, Wrap.Last, 9, Limits, Body_S, Parse);
                     if Parse /= Ok then
                        Status := Malformed;
                        return;
                     end if;

                     if Item.Count = Maximum_Certificates then
                        Status := Too_Many_Certificates;
                        return;
                     end if;

                     declare
                        Size : constant Offset :=
                          Offset (Content_Length (Body_S));
                     begin
                        if Item.Filled + Size > Maximum_Content_Size then
                           Status := Too_Large;
                           return;
                        end if;

                        Item.Certs (Item.Filled + 1 .. Item.Filled + Size) :=
                          Data (Body_S.First .. Body_S.Last);
                        Item.Count := Item.Count + 1;
                        Item.Spans (Item.Count) :=
                          (First => Item.Filled + 1,
                           Last  => Item.Filled + Size);
                        Item.Filled := Item.Filled + Size;
                     end;
                  end if;
               end;

            elsif OID_Table.Matches (Data, Kind, OID_Table.Key_Bag) then
               declare
                  Parsed : CryptoLib.ASN1.Errors.Decode_Status;
               begin
                  CryptoLib.PKCS8.Decode_DER
                    (Data (Tag.First .. Tag.Last), Limits, Item.Key, Parsed);
                  Item.Has_Key := Parsed = Ok;
               end;

            elsif OID_Table.Matches
                    (Data, Kind, OID_Table.Shrouded_Key_Bag)
            then
               declare
                  Unlock : CryptoLib.PKCS8.Unlock_Status;
               begin
                  CryptoLib.PKCS8.Decode_Encrypted_DER
                    (Data (Tag.First .. Tag.Last), Password, Limits,
                     Item.Key, Unlock);
                  if Unlock = CryptoLib.PKCS8.Ok then
                     Item.Has_Key := True;
                  elsif Unlock = CryptoLib.PKCS8.Unsupported_Scheme then
                     Status := Unsupported_Scheme;
                     return;
                  end if;
               end;
            end if;
         end;
      end loop;
   end Read_Safe_Contents;

   procedure Open
     (Data     : Octets;
      Password : String;
      Limits   : Decode_Limits;
      Item     : out Bundle;
      Status   : out Open_Status;
      Maximum_Iterations : Natural := Default_Maximum_Iterations)
   is
      Parse   : CryptoLib.ASN1.Errors.Decode_Status;
      Cursor  : Offset;
      Outer   : Element;
      Version : Natural;
      Kind    : Element;
      Content : Element;
      Present : Boolean;
      Safe    : Element;
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
      DER_Reader.Read_Small_Integer
        (Data, Cursor, Outer.Last, 1, Limits, Version, Parse);
      if Parse /= Ok then
         return;
      end if;

      Read_Content_Info
        (Data, Cursor, Outer.Last, 1, Limits, Kind, Content, Present, Parse);
      if Parse /= Ok or else not Present then
         return;
      end if;

      if not OID_Table.Matches (Data, Kind, OID_Table.PKCS7_Data) then
         Status := Unsupported_Scheme;
         return;
      end if;

      declare
         Inner : Offset := Content.First;
      begin
         DER_Reader.Read_Octet_String
           (Data, Inner, Content.Last, 2, Limits, Safe, Parse);
         if Parse /= Ok then
            return;
         end if;
      end;

      --  The MAC, before anything inside is looked at. A bundle nobody
      --  authenticated is a bundle anybody could have written, and parsing
      --  bags out of one means parsing whatever was put there.
      if DER_Reader.At_End (Cursor, Outer.Last) then
         Status := No_Mac;
         return;
      end if;

      declare
         Mac_Data : Element;
         Walk     : Offset := Cursor;
         Digest   : Element;
         Alg      : Element;
         Alg_OID  : Element;
         Stored   : Element;
         Salt     : Element;
         Rounds   : Natural := 1;
         Inner    : Offset;
      begin
         DER_Reader.Read_Sequence
           (Data, Walk, Outer.Last, 1, Limits, Mac_Data, Parse);
         if Parse /= Ok then
            return;
         end if;

         Inner := Mac_Data.First;
         DER_Reader.Read_Sequence
           (Data, Inner, Mac_Data.Last, 2, Limits, Digest, Parse);
         if Parse /= Ok then
            return;
         end if;

         declare
            Part : Offset := Digest.First;
         begin
            DER_Reader.Read_Sequence
              (Data, Part, Digest.Last, 3, Limits, Alg, Parse);
            if Parse /= Ok then
               return;
            end if;

            declare
               Which : Offset := Alg.First;
            begin
               DER_Reader.Read_Object_Identifier
                 (Data, Which, Alg.Last, 4, Limits, Alg_OID, Parse);
               if Parse /= Ok then
                  return;
               end if;
            end;

            if not OID_Table.Matches
                     (Data, Alg_OID, OID_Table.SHA1_Digest_Algorithm)
            then
               --  Only the SHA-1 MAC, which is what the format specifies and
               --  what every writer emits.
               Status := Unsupported_Scheme;
               return;
            end if;

            DER_Reader.Read_Octet_String
              (Data, Part, Digest.Last, 3, Limits, Stored, Parse);
            if Parse /= Ok then
               return;
            end if;
         end;

         DER_Reader.Read_Octet_String
           (Data, Inner, Mac_Data.Last, 2, Limits, Salt, Parse);
         if Parse /= Ok then
            return;
         end if;

         if not DER_Reader.At_End (Inner, Mac_Data.Last) then
            DER_Reader.Read_Small_Integer
              (Data, Inner, Mac_Data.Last, 2, Limits, Rounds, Parse);
            if Parse /= Ok then
               return;
            end if;
         end if;

         --  Before the derivation, not after: the point is not to notice
         --  afterwards that it cost too much.
         if Rounds = 0 or else Rounds > Maximum_Iterations then
            Status := Unsupported_Scheme;
            return;
         end if;

         --  PKCS#12 keys its KDF from the password as a BMPString, which is
         --  the one place it differs from every other password-based scheme
         --  here. PKCS12_KDF_SHA1 does that widening itself, so what goes in
         --  is the plain password: handing it one already widened derives a
         --  key for a password nobody typed, and the bundle fails its own
         --  MAC. The generator's own comment records the same mistake being
         --  made once before, and writing this reader repeated it.
         declare
            Plain : Ada.Streams.Stream_Element_Array
              (1 .. Offset (Password'Length));
            Key   : Ada.Streams.Stream_Element_Array (1 .. 20);
            Salt_Bytes : constant Octets :=
              (if Is_Empty (Salt) then Empty_Octets
               else Data (Salt.First .. Salt.Last));
         begin
            for I in Password'Range loop
               Plain (Offset (I - Password'First) + 1) :=
                 Character'Pos (Password (I));
            end loop;

            Key := CryptoLib.Macs.PKCS12_KDF_SHA1
              (Plain, Salt_Bytes, Rounds, 3, 20);

            declare
               Computed : constant Ada.Streams.Stream_Element_Array :=
                 Ada.Streams.Stream_Element_Array
                   (CryptoLib.Macs.HMAC_SHA1
                      (Key, Data (Safe.First .. Safe.Last)));
            begin
               CryptoLib.Secure_Wipe.Wipe (Plain'Address, Plain'Length);
               CryptoLib.Secure_Wipe.Wipe (Key'Address, Key'Length);

               if not CryptoLib.Constant_Time.Equal
                        (Computed, Data (Stored.First .. Stored.Last))
               then
                  Status := Wrong_Password_Or_Corrupt;
                  return;
               end if;
            end;
         end;
      end;

      --  Only now, with the bundle vouched for, are its contents read.
      declare
         Walk : Offset := Safe.First;
         List : Element;
      begin
         DER_Reader.Read_Sequence
           (Data, Walk, Safe.Last, 3, Limits, List, Parse);
         if Parse /= Ok then
            return;
         end if;

         Walk := List.First;
         while not DER_Reader.At_End (Walk, List.Last) loop
            declare
               Bag_Kind    : Element;
               Bag_Content : Element;
               Bag_Present : Boolean;
            begin
               Read_Content_Info
                 (Data, Walk, List.Last, 4, Limits, Bag_Kind, Bag_Content,
                  Bag_Present, Parse);
               if Parse /= Ok or else not Bag_Present then
                  return;
               end if;

               if OID_Table.Matches
                    (Data, Bag_Kind, OID_Table.PKCS7_Data)
               then
                  declare
                     Inner : Offset := Bag_Content.First;
                     Body_S : Element;
                  begin
                     DER_Reader.Read_Octet_String
                       (Data, Inner, Bag_Content.Last, 5, Limits, Body_S,
                        Parse);
                     if Parse /= Ok then
                        return;
                     end if;

                     Read_Safe_Contents
                       (Data, Body_S, Password, Limits, Item, Status);
                     if Status /= Ok then
                        return;
                     end if;
                  end;
               elsif OID_Table.Matches
                       (Data, Bag_Kind, OID_Table.PKCS7_Encrypted_Data)
               then
                  --  EncryptedData ::= SEQUENCE { version,
                  --      EncryptedContentInfo }, and the content info names
                  --  the same PBES2 that shrouds a key bag. Certificates in a
                  --  bundle are usually protected this way -- it is what
                  --  "openssl pkcs12 -export" writes by default -- so a
                  --  reader that skipped it would report a bundle full of
                  --  certificates as having none.
                  declare
                     Part    : Offset := Bag_Content.First;
                     Enc     : Element;
                     Info    : Element;
                     Version : Natural;
                     Kind2   : Element;
                     Alg_ID  : Element;
                     Param   : Element;
                     Has_P   : Boolean;
                     Body_T  : Element;
                     Walk2   : Offset;
                  begin
                     DER_Reader.Read_Sequence
                       (Data, Part, Bag_Content.Last, 5, Limits, Enc, Parse);
                     if Parse /= Ok then
                        return;
                     end if;

                     Walk2 := Enc.First;
                     DER_Reader.Read_Small_Integer
                       (Data, Walk2, Enc.Last, 6, Limits, Version, Parse);
                     if Parse /= Ok then
                        return;
                     end if;

                     DER_Reader.Read_Sequence
                       (Data, Walk2, Enc.Last, 6, Limits, Info, Parse);
                     if Parse /= Ok then
                        return;
                     end if;

                     Walk2 := Info.First;
                     DER_Reader.Read_Object_Identifier
                       (Data, Walk2, Info.Last, 7, Limits, Kind2, Parse);
                     if Parse /= Ok then
                        return;
                     end if;

                     Read_Algorithm
                       (Data, Walk2, Info.Last, 7, Limits, Alg_ID, Param,
                        Has_P, Parse);
                     if Parse /= Ok then
                        return;
                     end if;

                     if not OID_Table.Matches
                              (Data, Alg_ID, OID_Table.PBES2)
                       or else not Has_P
                     then
                        Status := Unsupported_Scheme;
                        return;
                     end if;

                     --  encryptedContent is [0] IMPLICIT, so it is a
                     --  primitive context tag rather than an OCTET STRING.
                     DER_Reader.Read_Expected
                       (Data, Walk2, Info.Last, 7, Limits,
                        Context_Specific, 0, False, Body_T, Parse);
                     if Parse /= Ok then
                        return;
                     end if;

                     declare
                        Plain : Octets
                          (1 .. Offset (Content_Length (Body_T)));
                        Last  : Offset;
                        Undo  : CryptoLib.PBES2.Unlock_Status;
                     begin
                        CryptoLib.PBES2.Decrypt
                          (Parameters =>
                             Data (Encoded_First (Param)
                                   .. Encoded_Last (Param)),
                           Ciphertext => Data (Body_T.First .. Body_T.Last),
                           Password   => Password,
                           Limits     => Limits,
                           Output     => Plain,
                           Last       => Last,
                           Status     => Undo,
                           Maximum_Iterations => Maximum_Iterations);

                        if Undo = CryptoLib.PBES2.Unsupported_Scheme then
                           Status := Unsupported_Scheme;
                           return;
                        elsif Undo /= CryptoLib.PBES2.Ok then
                           Status := Wrong_Password_Or_Corrupt;
                           return;
                        end if;

                        declare
                           Region : Element;
                           Scan   : Offset := Plain'First;
                        begin
                           --  The plaintext is a SafeContents, read the same
                           --  way as an unencrypted one.
                           DER_Reader.Read
                             (Plain, Scan, Last, 5, Limits, Region, Parse);
                           if Parse /= Ok then
                              Status := Malformed;
                              return;
                           end if;

                           Read_Safe_Contents
                             (Plain (Plain'First .. Last),
                              (Class => Universal, Constructed => True,
                               Number => Tag_Sequence,
                               Header_First => Plain'First,
                               First => Plain'First, Last => Last),
                              Password, Limits, Item, Status);
                        end;

                        CryptoLib.Secure_Wipe.Wipe
                          (Plain'Address, Plain'Length);
                        if Status /= Ok then
                           return;
                        end if;
                     end;
                  end;
               else
                  Status := Unsupported_Scheme;
                  return;
               end if;
            end;
         end loop;
      end;

      Item.Present := True;
      Status := Ok;
   end Open;

   function Is_Present (Item : Bundle) return Boolean
   is (Item.Present);

   function Certificate_Count (Item : Bundle) return Natural
   is (if Item.Present then Item.Count else 0);

   function Certificate_Bytes
     (Item : Bundle; Index : Positive) return Octets
   is (if not Item.Present or else Index > Item.Count
       then Empty_Octets
       else Item.Certs (Item.Spans (Index).First .. Item.Spans (Index).Last));

   function Has_Private_Key (Item : Bundle) return Boolean
   is (Item.Present and then Item.Has_Key);

   function Key_Algorithm_Of
     (Item : Bundle) return CryptoLib.X509.Public_Key_Algorithm
   is (CryptoLib.PKCS8.Algorithm_Of (Item.Key));

   function Private_Value (Item : Bundle) return Octets
   is (if Item.Present and then Item.Has_Key
       then CryptoLib.PKCS8.Private_Value (Item.Key)
       else Empty_Octets);

end CryptoLib.PKCS12;
