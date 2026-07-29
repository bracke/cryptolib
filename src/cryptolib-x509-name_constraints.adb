with Ada.Streams;

with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.Errors;
with CryptoLib.X509.Extensions;
with CryptoLib.X509.Names;

package body CryptoLib.X509.Name_Constraints is

   use CryptoLib.ASN1;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.ASN1.Errors.Decode_Status;
   use type CryptoLib.X509.Extensions.General_Name_Kind;

   package DER_Reader renames CryptoLib.ASN1.DER;
   package XE renames CryptoLib.X509.Extensions;
   package XN renames CryptoLib.X509.Names;

   function Verdict_Image (Result : Verdict) return String is
   begin
      case Result is
         when Permitted              => return "permitted";
         when Excluded               => return "excluded";
         when Unsupported_Constraint => return "unsupported constraint";
         when Malformed              => return "malformed";
      end case;
   end Verdict_Image;

   function Lower (C : Character) return Character
   is (if C in 'A' .. 'Z'
       then Character'Val (Character'Pos (C) + 32)
       else C);

   --  Is Name within the DNS subtree Base?
   --
   --  RFC 5280 gives a subtree, not a suffix: "example.com" covers
   --  "example.com" and "a.example.com" but not "notexample.com". Matching on
   --  the string ending alone would admit the third, which is the whole point
   --  of the constraint. A leading dot, which some issuers write, means the
   --  same subtree without its own root.
   function Within_DNS (Base : String; Name : String) return Boolean is
      Root   : constant String :=
        (if Base'Length > 0 and then Base (Base'First) = '.'
         then Base (Base'First + 1 .. Base'Last)
         else Base);
      Dotted : constant Boolean :=
        Base'Length > 0 and then Base (Base'First) = '.';

      function Same (Left : String; Right : String) return Boolean is
      begin
         if Left'Length /= Right'Length then
            return False;
         end if;
         for I in 0 .. Left'Length - 1 loop
            if Lower (Left (Left'First + I)) /= Lower (Right (Right'First + I))
            then
               return False;
            end if;
         end loop;
         return True;
      end Same;
   begin
      if Root'Length = 0 then
         --  An empty base is the whole namespace.
         return True;
      end if;

      if Name'Length < Root'Length then
         return False;
      end if;

      if Name'Length = Root'Length then
         --  The subtree's own root, which a dotted base excludes.
         return not Dotted and then Same (Name, Root);
      end if;

      --  Longer: the character before the suffix has to be the label
      --  separator, or this is a different name that merely ends the same.
      return Name (Name'Last - Root'Length) = '.'
        and then Same (Name (Name'Last - Root'Length + 1 .. Name'Last), Root);
   end Within_DNS;

   --  Is Address within the subtree Base, which is an address followed by a
   --  mask of the same width?
   function Within_IP (Base : Octets; Address : Octets) return Boolean is
      Width : constant Offset := Base'Length / 2;
   begin
      if Base'Length /= 8 and then Base'Length /= 32 then
         return False;
      end if;

      if Address'Length /= Width then
         return False;
      end if;

      for I in 0 .. Width - 1 loop
         declare
            Mask : constant Ada.Streams.Stream_Element :=
              Base (Base'First + Width + I);
            Net  : constant Ada.Streams.Stream_Element :=
              Base (Base'First + I);
            Have : constant Ada.Streams.Stream_Element :=
              Address (Address'First + I);
         begin
            if (Have and Mask) /= (Net and Mask) then
               return False;
            end if;
         end;
      end loop;

      return True;
   end Within_IP;

   --  Does this common name read as a host name?
   --
   --  A subject common name may be a host, or a person, or an organisation.
   --  Treating "Example Ltd" as a DNS name and refusing it against a domain
   --  subtree would reject chains that are perfectly valid, so only something
   --  shaped like a host is considered one: a dot, and nothing in it that a
   --  host name cannot contain.
   function Looks_Like_Host (Name : String) return Boolean is
      Dotted : Boolean := False;
   begin
      if Name'Length = 0 then
         return False;
      end if;

      for C of Name loop
         if C = '.' then
            Dotted := True;
         elsif not (C in 'a' .. 'z' or else C in 'A' .. 'Z'
                    or else C in '0' .. '9'
                    or else C = '-' or else C = '*' or else C = '_')
         then
            return False;
         end if;
      end loop;

      return Dotted;
   end Looks_Like_Host;

   --  The name a DNS subtree has to be applied to, beyond the alternative
   --  names.
   --
   --  A certificate with no DNS alternative name may still be used for a host
   --  if its common name is read as one, and CryptoLib.X509.Identity will do
   --  that when a caller asks for the old behaviour. Constraining only the
   --  alternative names would then leave a constrained CA able to certify any
   --  host at all, so long as it named it in the field the constraint did not
   --  look at. The two must cover the same ground.
   --
   --  Only for end-entity certificates, and only when there is no DNS
   --  alternative name -- which is exactly when the common name can be read
   --  as a host. A CA's common name is a name, not a service identity, and
   --  refusing a CA called "ca.example.org" beneath a subtree for another
   --  domain would reject a chain nobody meant to forbid.
   function Host_From_Common_Name (Item : Certificate) return String is
      Constraints : constant XE.Basic_Constraints :=
        XE.Get_Basic_Constraints (Item);
      Common      : constant String :=
        CryptoLib.X509.Certificates.Subject_Common_Name (Item);
   begin
      if Constraints.Present and then Constraints.Is_CA then
         return "";
      end if;

      for N in 1 .. XE.Subject_Alternative_Name_Count (Item) loop
         if XE.Subject_Alternative_Name_Kind (Item, N) = XE.DNS_Name then
            return "";
         end if;
      end loop;

      return (if Looks_Like_Host (Common) then Common else "");
   end Host_From_Common_Name;

   --  Is Base an initial run of RDNs of Subject?
   --
   --  A directory-name subtree is a prefix of the distinguished name, not an
   --  equality: a base of "C=DK, O=Example" covers every name beginning with
   --  those two, which is how a CA is limited to one organisation. The RDNs
   --  are compared as encoded, which can only be too strict -- being too
   --  strict costs a chain that could have been built, being too lax admits
   --  one that should not have been.
   function Within_DN
     (Base_Data : Octets; Base : Element;
      Subj_Data : Octets) return Boolean
   is
      Limits    : constant Decode_Limits := Default_Limits;
      Base_Seq  : Element;
      Subj_Seq  : Element;
      Base_At   : Offset;
      Subj_At   : Offset;
      Status    : CryptoLib.ASN1.Errors.Decode_Status;
   begin
      --  The base is a Name, which is a CHOICE, so its context tag is
      --  explicit and the RDNSequence sits inside it.
      Base_At := Base.First;
      DER_Reader.Read_Sequence
        (Base_Data, Base_At, Base.Last, 5, Limits, Base_Seq, Status);
      if Status /= CryptoLib.ASN1.Errors.Ok then
         return False;
      end if;

      --  The subject is a whole Name as encoded, so the sequence is read
      --  from its start. Reading it as though its header had already been
      --  consumed finds the first relative name where the sequence should be,
      --  and nothing matches anything.
      Subj_At := Subj_Data'First;
      DER_Reader.Read_Sequence
        (Subj_Data, Subj_At, Subj_Data'Last, 5, Limits, Subj_Seq, Status);
      if Status /= CryptoLib.ASN1.Errors.Ok then
         return False;
      end if;

      Base_At := Base_Seq.First;
      Subj_At := Subj_Seq.First;

      while not DER_Reader.At_End (Base_At, Base_Seq.Last) loop
         declare
            Base_RDN : Element;
            Subj_RDN : Element;
         begin
            DER_Reader.Read
              (Base_Data, Base_At, Base_Seq.Last, 6, Limits, Base_RDN,
               Status);
            if Status /= CryptoLib.ASN1.Errors.Ok then
               return False;
            end if;

            if DER_Reader.At_End (Subj_At, Subj_Seq.Last) then
               --  The subject is shorter than the base, so the base cannot be
               --  a prefix of it.
               return False;
            end if;

            DER_Reader.Read
              (Subj_Data, Subj_At, Subj_Seq.Last, 6, Limits, Subj_RDN,
               Status);
            if Status /= CryptoLib.ASN1.Errors.Ok then
               return False;
            end if;

            declare
               Left  : constant Octets :=
                 Base_Data (Encoded_First (Base_RDN) .. Encoded_Last (Base_RDN));
               Right : constant Octets :=
                 Subj_Data (Encoded_First (Subj_RDN) .. Encoded_Last (Subj_RDN));
            begin
               if Left'Length /= Right'Length then
                  return False;
               end if;
               for I in 0 .. Left'Length - 1 loop
                  if Left (Left'First + Offset (I))
                    /= Right (Right'First + Offset (I))
                  then
                     return False;
                  end if;
               end loop;
            end;
         end;
      end loop;

      return True;
   end Within_DN;

   --  The host a URI names.
   --
   --  A URI subtree constrains the host and nothing else, so "example.com"
   --  covers "http://www.example.com/anything". Anything before an "@" is
   --  credentials rather than a host, and a port or a path ends it.
   function Host_Of_URI (URI : String) return String is
      Start : Natural := URI'First;
      Stop  : Natural;
      At_At : Natural := 0;
   begin
      for I in URI'Range loop
         if I + 2 <= URI'Last and then URI (I .. I + 2) = "://" then
            Start := I + 3;
            exit;
         end if;
      end loop;

      Stop := URI'Last;
      for I in Start .. URI'Last loop
         if URI (I) = '/' or else URI (I) = ':' or else URI (I) = '?'
           or else URI (I) = '#'
         then
            Stop := I - 1;
            exit;
         end if;
      end loop;

      for I in Start .. Stop loop
         if URI (I) = '@' then
            At_At := I;
         end if;
      end loop;

      if At_At /= 0 then
         Start := At_At + 1;
      end if;

      if Stop < Start then
         return "";
      end if;

      return URI (Start .. Stop);
   end Host_Of_URI;

   --  The host part of a mail address.
   function Host_Of_Address (Address : String) return String is
      At_Sign : Natural := 0;
   begin
      for I in Address'Range loop
         if Address (I) = '@' then
            At_Sign := I;
         end if;
      end loop;

      if At_Sign = 0 or else At_Sign = Address'Last then
         return "";
      end if;

      return Address (At_Sign + 1 .. Address'Last);
   end Host_Of_Address;

   --  Is this address within the mail subtree Base?
   --
   --  RFC 5280 gives the constraint three readings, told apart by its own
   --  shape. With an "@" it is one mailbox and must match entirely. Without
   --  one it is a host, and every mailbox on that host is covered -- but not
   --  on a host below it. With a leading dot it is a domain, and every host
   --  under it is covered while the domain's own host is not. Collapsing
   --  these into a suffix test would let a constraint for one mailbox cover a
   --  whole domain.
   function Within_Email (Base : String; Address : String) return Boolean is
      Host : constant String := Host_Of_Address (Address);

      function Same_Fold (Left : String; Right : String) return Boolean is
      begin
         if Left'Length /= Right'Length then
            return False;
         end if;
         for I in 0 .. Left'Length - 1 loop
            if Lower (Left (Left'First + I))
              /= Lower (Right (Right'First + I))
            then
               return False;
            end if;
         end loop;
         return True;
      end Same_Fold;

      Mailbox : Boolean := False;
   begin
      if Base'Length = 0 or else Host'Length = 0 then
         return False;
      end if;

      for C of Base loop
         if C = '@' then
            Mailbox := True;
         end if;
      end loop;

      if Mailbox then
         --  One mailbox. The local part is compared exactly, since a mail
         --  system may distinguish case there and this has no business
         --  deciding it does not; the host is compared without case, as host
         --  names are.
         declare
            Base_Host : constant String := Host_Of_Address (Base);
            Base_At   : Natural := 0;
            Addr_At   : Natural := 0;
         begin
            for I in Base'Range loop
               if Base (I) = '@' then
                  Base_At := I;
               end if;
            end loop;
            for I in Address'Range loop
               if Address (I) = '@' then
                  Addr_At := I;
               end if;
            end loop;

            if Base_At = 0 or else Addr_At = 0 then
               return False;
            end if;

            return Base (Base'First .. Base_At - 1)
                     = Address (Address'First .. Addr_At - 1)
              and then Same_Fold (Base_Host, Host);
         end;
      end if;

      if Base (Base'First) = '.' then
         --  A domain: every host under it, but not the domain's own host.
         return Within_DNS (Base, Host);
      end if;

      --  A host: every mailbox on it, and nothing below it.
      return Same_Fold (Base, Host);
   end Within_Email;

   --  The mail address a constraint has to be applied to beyond the
   --  alternative names.
   --
   --  Legacy certificates put the address in the subject's emailAddress
   --  attribute rather than in an alternative name, and a reader that goes
   --  looking for an address will find it there when there is no other. Same
   --  reasoning as the common name: constrain the field that can be read, or
   --  a constrained CA can certify any address by writing it where the
   --  constraint does not look. Only for end-entity certificates, and only
   --  when there is no rfc822 alternative name.
   function Address_From_Subject (Item : Certificate) return String is
      Constraints : constant XE.Basic_Constraints :=
        XE.Get_Basic_Constraints (Item);
      Where       : Natural;
   begin
      if Constraints.Present and then Constraints.Is_CA then
         return "";
      end if;

      for N in 1 .. XE.Subject_Alternative_Name_Count (Item) loop
         if XE.Subject_Alternative_Name_Kind (Item, N) = XE.Email_Address then
            return "";
         end if;
      end loop;

      Where :=
        XN.Find_Attribute
          (Item, XN.Subject_Name, CryptoLib.X509.Email_Address);
      if Where = 0 then
         return "";
      end if;

      return XN.Attribute_Text (Item, XN.Subject_Name, Where);
   end Address_From_Subject;

   --  Walk one GeneralSubtrees, applying every base to the certificate.
   --
   --  Reports whether any subtree of a given kind was present, and whether
   --  the certificate fell inside one, because "permitted" and "excluded"
   --  ask opposite questions of the same walk.
   procedure Scan_Subtrees
     (Data       : Octets;
      Region     : Element;
      Item       : Certificate;
      Any_DNS    : out Boolean;
      Any_IP     : out Boolean;
      Any_DN     : out Boolean;
      Any_URI    : out Boolean;
      Any_Mail   : out Boolean;
      Inside_DNS : out Boolean;
      Inside_IP  : out Boolean;
      Inside_DN  : out Boolean;
      Inside_URI : out Boolean;
      Inside_Mail : out Boolean;
      Usable     : out Boolean)
   is
      Limits : constant Decode_Limits := Default_Limits;
      Cursor : Offset := Region.First;
      Status : CryptoLib.ASN1.Errors.Decode_Status;
      Names  : constant Natural := XE.Subject_Alternative_Name_Count (Item);
      Common : constant String := Host_From_Common_Name (Item);
      Mail   : constant String := Address_From_Subject (Item);
   begin
      Any_DNS := False;
      Any_IP := False;
      Any_DN := False;
      Any_URI := False;
      Any_Mail := False;
      Inside_DNS := False;
      Inside_IP := False;
      Inside_DN := False;
      Inside_URI := False;
      Inside_Mail := False;
      Usable := True;

      while not DER_Reader.At_End (Cursor, Region.Last) loop
         declare
            Subtree : Element;
            Inner   : Offset;
            Base    : Element;
         begin
            DER_Reader.Read_Sequence
              (Data, Cursor, Region.Last, 3, Limits, Subtree, Status);
            if Status /= CryptoLib.ASN1.Errors.Ok then
               Usable := False;
               return;
            end if;

            Inner := Subtree.First;
            DER_Reader.Read
              (Data, Inner, Subtree.Last, 4, Limits, Base, Status);
            if Status /= CryptoLib.ASN1.Errors.Ok then
               Usable := False;
               return;
            end if;

            if Base.Class /= Context_Specific then
               Usable := False;
               return;
            end if;

            --  GeneralSubtree ::= SEQUENCE { base, minimum [0] DEFAULT 0,
            --                                maximum [1] OPTIONAL }
            --
            --  RFC 5280 4.2.1.10 says the minimum MUST be zero and the
            --  maximum MUST be absent, and DER leaves out a DEFAULT that
            --  holds, so anything following the base is a depth restriction
            --  on the subtree that this does not know how to apply. Say so
            --  rather than skip it: a minimum on a permitted subtree narrows
            --  what the CA allowed, and ignoring it would permit names the
            --  CA did not -- the same reasoning as the name forms below,
            --  and the same answer.
            if not DER_Reader.At_End (Inner, Subtree.Last) then
               Usable := False;
               return;
            end if;

            case Base.Number is
               when 2 =>
                  Any_DNS := True;
                  declare
                     Text : String (1 .. Content_Length (Base));
                  begin
                     for I in Text'Range loop
                        Text (I) :=
                          Character'Val (Data (Base.First + Offset (I - 1)));
                     end loop;

                     for N in 1 .. Names loop
                        if XE.Subject_Alternative_Name_Kind (Item, N)
                          = XE.DNS_Name
                          and then Within_DNS
                                     (Text,
                                      XE.Subject_Alternative_Name_Text
                                        (Item, N))
                        then
                           Inside_DNS := True;
                        end if;
                     end loop;

                     if Common'Length > 0
                       and then Within_DNS (Text, Common)
                     then
                        Inside_DNS := True;
                     end if;
                  end;

               when 7 =>
                  Any_IP := True;
                  for N in 1 .. Names loop
                     if XE.Subject_Alternative_Name_Kind (Item, N)
                       = XE.IP_Address
                       and then Within_IP
                                  (Data (Base.First .. Base.Last),
                                   XE.Subject_Alternative_Name_Bytes
                                     (Item, N))
                     then
                        Inside_IP := True;
                     end if;
                  end loop;

               when 1 =>
                  --  An rfc822 subtree.
                  Any_Mail := True;
                  declare
                     Text : String (1 .. Content_Length (Base));
                  begin
                     for I in Text'Range loop
                        Text (I) :=
                          Character'Val (Data (Base.First + Offset (I - 1)));
                     end loop;

                     for N in 1 .. Names loop
                        if XE.Subject_Alternative_Name_Kind (Item, N)
                          = XE.Email_Address
                          and then Within_Email
                                     (Text,
                                      XE.Subject_Alternative_Name_Text
                                        (Item, N))
                        then
                           Inside_Mail := True;
                        end if;
                     end loop;

                     if Mail'Length > 0
                       and then Within_Email (Text, Mail)
                     then
                        Inside_Mail := True;
                     end if;
                  end;

               when 4 =>
                  --  A directory-name subtree, which constrains the subject
                  --  itself rather than an alternative name -- that is how a
                  --  CA is limited to an organisation rather than a domain.
                  Any_DN := True;
                  declare
                     Subject : constant Octets :=
                       CryptoLib.X509.Certificates.Subject_Bytes (Item);
                  begin
                     if Subject'Length > 0
                       and then Within_DN (Data, Base, Subject)
                     then
                        Inside_DN := True;
                     end if;
                  end;

               when 6 =>
                  --  A URI subtree constrains the host the URI names.
                  Any_URI := True;
                  declare
                     Text : String (1 .. Content_Length (Base));
                  begin
                     for I in Text'Range loop
                        Text (I) :=
                          Character'Val (Data (Base.First + Offset (I - 1)));
                     end loop;

                     for N in 1 .. Names loop
                        if XE.Subject_Alternative_Name_Kind (Item, N)
                          = XE.URI
                          and then Within_DNS
                                     (Text,
                                      Host_Of_URI
                                        (XE.Subject_Alternative_Name_Text
                                           (Item, N)))
                        then
                           Inside_URI := True;
                        end if;
                     end loop;
                  end;

               when others =>
                  --  A form this cannot apply -- an EDI party name, an
                  --  x400Address, a registered identifier. Saying so beats
                  --  ignoring it: an unapplied constraint is not a
                  --  constraint.
                  Usable := False;
                  return;
            end case;
         end;
      end loop;
   end Scan_Subtrees;

   function Check
     (Constraints_Value : Octets;
      Item              : Certificate) return Verdict
   is
      Limits : constant Decode_Limits := Default_Limits;
      Cursor : Offset;
      Outer  : Element;
      Status : CryptoLib.ASN1.Errors.Decode_Status;

      Names : constant Natural := XE.Subject_Alternative_Name_Count (Item);

      Has_DNS : Boolean := False;
      Has_IP  : Boolean := False;
      Has_URI : Boolean := False;
      Has_Mail : Boolean := False;
      Has_DN  : constant Boolean :=
        CryptoLib.X509.Certificates.Subject_Bytes (Item)'Length > 0;
   begin
      if Constraints_Value'Length = 0 then
         return Malformed;
      end if;

      for N in 1 .. Names loop
         if XE.Subject_Alternative_Name_Kind (Item, N) = XE.DNS_Name then
            Has_DNS := True;
         elsif XE.Subject_Alternative_Name_Kind (Item, N) = XE.IP_Address then
            Has_IP := True;
         elsif XE.Subject_Alternative_Name_Kind (Item, N) = XE.URI then
            Has_URI := True;
         elsif XE.Subject_Alternative_Name_Kind (Item, N) = XE.Email_Address
         then
            Has_Mail := True;
         end if;
      end loop;

      --  As with the common name: an address the reader will find counts as
      --  an address for this purpose.
      if Address_From_Subject (Item)'Length > 0 then
         Has_Mail := True;
      end if;

      --  A common name that will be read as a host counts as a DNS name for
      --  this purpose, or the permitted-subtree test below would not apply to
      --  it and a CN-only certificate would pass unconstrained.
      if Host_From_Common_Name (Item)'Length > 0 then
         Has_DNS := True;
      end if;

      Cursor := Constraints_Value'First;
      DER_Reader.Read_Sequence
        (Constraints_Value, Cursor, Constraints_Value'Last, 0, Limits,
         Outer, Status);
      if Status /= CryptoLib.ASN1.Errors.Ok then
         return Malformed;
      end if;

      Cursor := Outer.First;
      while not DER_Reader.At_End (Cursor, Outer.Last) loop
         declare
            Tag        : Element;
            Any_DNS    : Boolean;
            Any_IP     : Boolean;
            Any_DN     : Boolean;
            Any_URI    : Boolean;
            Any_Mail   : Boolean;
            Inside_DNS : Boolean;
            Inside_IP  : Boolean;
            Inside_DN  : Boolean;
            Inside_URI : Boolean;
            Inside_Mail : Boolean;
            Usable     : Boolean;
         begin
            DER_Reader.Read
              (Constraints_Value, Cursor, Outer.Last, 1, Limits, Tag, Status);
            if Status /= CryptoLib.ASN1.Errors.Ok
              or else Tag.Class /= Context_Specific
            then
               return Malformed;
            end if;

            Scan_Subtrees
              (Constraints_Value, Tag, Item, Any_DNS, Any_IP, Any_DN, Any_URI,
               Any_Mail, Inside_DNS, Inside_IP, Inside_DN, Inside_URI,
               Inside_Mail, Usable);
            if not Usable then
               return Unsupported_Constraint;
            end if;

            case Tag.Number is
               when 0 =>
                  --  Permitted: a name of a constrained kind must fall inside
                  --  one of the subtrees for that kind. A certificate with no
                  --  name of that kind is not caught, since a subtree
                  --  restricts only names of its own type.
                  if Any_DNS and then Has_DNS and then not Inside_DNS then
                     return Excluded;
                  end if;
                  if Any_IP and then Has_IP and then not Inside_IP then
                     return Excluded;
                  end if;
                  if Any_DN and then Has_DN and then not Inside_DN then
                     return Excluded;
                  end if;
                  if Any_URI and then Has_URI and then not Inside_URI then
                     return Excluded;
                  end if;
                  if Any_Mail and then Has_Mail and then not Inside_Mail then
                     return Excluded;
                  end if;

               when 1 =>
                  --  Excluded: falling inside any subtree is fatal.
                  if Inside_DNS or else Inside_IP or else Inside_DN
                    or else Inside_URI or else Inside_Mail
                  then
                     return Excluded;
                  end if;

               when others =>
                  return Malformed;
            end case;
         end;
      end loop;

      return Permitted;
   end Check;

end CryptoLib.X509.Name_Constraints;
