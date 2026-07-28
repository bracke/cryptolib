with CryptoLib.X509.Certificates;

--  @summary Taking a distinguished name apart.
--
--  A name is a sequence of relative names, each a set of attribute/value
--  pairs, and flattening one to a string throws away which attribute each
--  value belonged to. That matters: "CN=example.com" and "O=example.com" are
--  different statements, and a caller reading a formatted name back cannot
--  reliably tell them apart once escaping enters into it.
--
--  So the attributes are offered as attributes, and formatting is a separate
--  operation. Display and comparison are different problems: a formatted name
--  is for a person to read, and comparing two of them is not how to decide
--  whether two certificates name the same subject. For that, compare the
--  encoded names -- CryptoLib.X509.Certificates.Issuer_Bytes and
--  Subject_Bytes are the bytes an issuer signed.
package CryptoLib.X509.Names is

   subtype Certificate is CryptoLib.X509.Certificates.Certificate;

   type Name_Selector is (Subject_Name, Issuer_Name);

   --  How a value's text was encoded.
   --
   --  Reported rather than hidden because the wide encodings cannot be handed
   --  back as an Ada String without a conversion this package declines to
   --  make silently.
   type Directory_String_Kind is
     (Printable_String,
      UTF8_String,
      IA5_String,
      Teletex_String,
      BMP_String,
      Universal_String,
      Other_String);

   --  How many attributes does this name carry?
   --
   --  Counted across all the relative names, so a name written as one
   --  multi-valued relative name and one written as several single-valued
   --  ones both report what they hold.
   --  @param Item the certificate to inspect
   --  @param Which the subject or the issuer
   --  @return the number of attribute/value pairs
   function Attribute_Count
     (Item : Certificate; Which : Name_Selector) return Natural;

   --  Which attribute is this?
   --  @param Item the certificate to inspect
   --  @param Which the subject or the issuer
   --  @param Index which attribute, one through Attribute_Count
   --  @return the attribute kind, Unknown_Attribute when unrecognised
   function Attribute_Kind_At
     (Item  : Certificate;
      Which : Name_Selector;
      Index : Positive) return Attribute_Kind;

   --  The attribute's identifier, for one this package does not name.
   --  @param Item the certificate to inspect
   --  @param Which the subject or the issuer
   --  @param Index which attribute, one through Attribute_Count
   --  @return the attribute's OID content octets
   function Attribute_Identifier
     (Item  : Certificate;
      Which : Name_Selector;
      Index : Positive) return Octets;

   --  How the value was encoded.
   --  @param Item the certificate to inspect
   --  @param Which the subject or the issuer
   --  @param Index which attribute, one through Attribute_Count
   --  @return the value's string kind
   function Attribute_String_Kind
     (Item  : Certificate;
      Which : Name_Selector;
      Index : Positive) return Directory_String_Kind;

   --  The value's octets, exactly as encoded.
   --  @param Item the certificate to inspect
   --  @param Which the subject or the issuer
   --  @param Index which attribute, one through Attribute_Count
   --  @return the value's octets
   function Attribute_Bytes
     (Item  : Certificate;
      Which : Name_Selector;
      Index : Positive) return Octets;

   --  The value as text.
   --
   --  Only for the byte-oriented encodings. A BMPString or UniversalString
   --  holds two or four octets per character and comes back empty here rather
   --  than as its octets reinterpreted: handing those back as an Ada String
   --  would produce something that looks like text, is not the text, and
   --  compares unequal to it. Use Attribute_Bytes and convert deliberately.
   --  @param Item the certificate to inspect
   --  @param Which the subject or the issuer
   --  @param Index which attribute, one through Attribute_Count
   --  @return the value as text, "" for a wide encoding
   function Attribute_Text
     (Item  : Certificate;
      Which : Name_Selector;
      Index : Positive) return String;

   --  Find the first attribute of a kind.
   --  @param Item the certificate to inspect
   --  @param Which the subject or the issuer
   --  @param Kind the attribute to look for
   --  @return its index, zero when the name carries none
   function Find_Attribute
     (Item  : Certificate;
      Which : Name_Selector;
      Kind  : Attribute_Kind) return Natural;

   --  Render the name for a person to read, in RFC 4514 order and escaping.
   --
   --  For display and for logs. Not for comparison: two names that format
   --  alike need not be the same name, and two encodings of one name need not
   --  format alike.
   --  @param Item the certificate to inspect
   --  @param Which the subject or the issuer
   --  @return the formatted name, "" when there is nothing to format
   function Format
     (Item : Certificate; Which : Name_Selector) return String;

end CryptoLib.X509.Names;
