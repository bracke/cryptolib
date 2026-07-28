with CryptoLib.ASN1;
with CryptoLib.ASN1.Errors;

--  @summary An immutable parsed certificate.
--
--  A Certificate owns the DER it was decoded from and holds everything else
--  as offsets into that copy. Two consequences are deliberate. The exact
--  signed bytes survive, so a signature can be verified over what was
--  actually signed rather than over a re-encoding that has to be trusted to
--  match. And a decoded certificate has no dependence on the caller's buffer,
--  so it can outlive the text it arrived in.
--
--  Decoding answers only "is this a certificate, and what does it say". It
--  says nothing about whether the certificate is trusted, current, correctly
--  signed, or fit for any purpose. Those are separate questions with separate
--  answers, and a type that mixed them would let a caller believe it had
--  checked one by asking the other.
package CryptoLib.X509.Certificates is

   subtype Decode_Status is CryptoLib.ASN1.Errors.Decode_Status;
   subtype Decode_Limits is CryptoLib.ASN1.Decode_Limits;

   --  The most extensions this crate will hold for one certificate. Well past
   --  what real certificates carry; a certificate with more is refused rather
   --  than silently truncated.
   Maximum_Extensions : constant := 32;

   type Certificate (Length : Offset) is private;

   --  Decode a certificate from DER.
   --
   --  Check Status before anything else: on failure the result is an empty
   --  certificate whose accessors return empty values, not a partial parse.
   --  @param Data the DER encoding
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Status Ok on success, otherwise why the input was refused
   --  @return the decoded certificate, or an empty one on failure
   function Decode_DER
     (Data   : Octets;
      Limits : Decode_Limits;
      Status : out Decode_Status) return Certificate;

   --  Is this a certificate that decoded successfully?
   --  @param Item the certificate to inspect
   --  @return True when the certificate holds a decoded encoding
   function Is_Present (Item : Certificate) return Boolean;

   --  The X.509 version, 1 through 3.
   --  @param Item the certificate to inspect
   --  @return the version number, 1 when the field was absent
   function Version (Item : Certificate) return Natural;

   --  The serial number, as the octets it was encoded as.
   --
   --  Not a machine integer: serial numbers run to twenty octets and are
   --  compared, printed, and matched against revocation lists as strings of
   --  bytes. Narrowing one to fit an integer would lose certificates.
   --  @param Item the certificate to inspect
   --  @return the serial number's content octets
   function Serial_Number (Item : Certificate) return Octets;

   --  The whole issuer Name, as encoded.
   --  @param Item the certificate to inspect
   --  @return the issuer's DER encoding, header included
   function Issuer_Bytes (Item : Certificate) return Octets;

   --  The whole subject Name, as encoded.
   --  @param Item the certificate to inspect
   --  @return the subject's DER encoding, header included
   function Subject_Bytes (Item : Certificate) return Octets;

   --  The first common name in the subject, if there is one.
   --  @param Item the certificate to inspect
   --  @return the common name, "" when the subject carries none
   function Subject_Common_Name (Item : Certificate) return String;

   --  The first common name in the issuer, if there is one.
   --  @param Item the certificate to inspect
   --  @return the common name, "" when the issuer carries none
   function Issuer_Common_Name (Item : Certificate) return String;

   --  Does this certificate name itself as its own issuer?
   --
   --  A byte comparison of the two encoded names. Self-issued is not the same
   --  as self-signed, and neither is the same as trusted: this answers only
   --  the first.
   --  @param Item the certificate to inspect
   --  @return True when issuer and subject encode identically
   function Is_Self_Issued (Item : Certificate) return Boolean;

   --  When the certificate's validity begins.
   --  @param Item the certificate to inspect
   --  @return the notBefore time
   function Not_Before (Item : Certificate) return Certificate_Time;

   --  When the certificate's validity ends.
   --  @param Item the certificate to inspect
   --  @return the notAfter time
   function Not_After (Item : Certificate) return Certificate_Time;

   --  The algorithm named in the certificate's signature.
   --  @param Item the certificate to inspect
   --  @return the signature algorithm, Unknown when unrecognised
   function Signature_Algorithm_Of
     (Item : Certificate) return Signature_Algorithm;

   --  The signature algorithm's parameters, as encoded.
   --
   --  Empty for the algorithms that have none. RSASSA-PSS is why this is
   --  exported: PSS states its hash, its mask generation function and its
   --  salt length here rather than in the algorithm's name, so a verifier
   --  that cannot see the parameters cannot check a PSS signature at all --
   --  it can only guess, and a guess that happens to be right proves nothing.
   --  @param Item the certificate to inspect
   --  @return the parameters' DER, header included, empty when absent
   function Signature_Parameters (Item : Certificate) return Octets;

   --  The algorithm of the subject public key.
   --  @param Item the certificate to inspect
   --  @return the public-key algorithm, Unknown when unrecognised
   function Public_Key_Algorithm_Of
     (Item : Certificate) return Public_Key_Algorithm;

   --  The subject public key itself, without its BIT STRING wrapper.
   --  @param Item the certificate to inspect
   --  @return the public key's octets
   function Public_Key (Item : Certificate) return Octets;

   --  The whole SubjectPublicKeyInfo, as encoded.
   --
   --  This is what a key identifier is computed over, so it is offered whole
   --  as well as in parts.
   --  @param Item the certificate to inspect
   --  @return the SubjectPublicKeyInfo DER, header included
   function Public_Key_Info_Bytes (Item : Certificate) return Octets;

   --  The exact bytes the signature was computed over.
   --
   --  The TBSCertificate as it arrived, not a re-encoding of it.
   --  @param Item the certificate to inspect
   --  @return the signed TBSCertificate DER, header included
   function TBS_Bytes (Item : Certificate) return Octets;

   --  The signature value, without its BIT STRING wrapper.
   --  @param Item the certificate to inspect
   --  @return the signature octets
   function Signature_Bytes (Item : Certificate) return Octets;

   --  The certificate's own DER, as decoded.
   --  @param Item the certificate to inspect
   --  @return the whole certificate encoding
   function DER_Bytes (Item : Certificate) return Octets;

   --  How many extensions does this certificate carry?
   --  @param Item the certificate to inspect
   --  @return the number of extensions, zero when there are none
   function Extension_Count (Item : Certificate) return Natural;

   --  One extension's identifier.
   --  @param Item the certificate to inspect
   --  @param Index which extension, one through Extension_Count
   --  @return the extension's OID content octets
   function Extension_Identifier
     (Item : Certificate; Index : Positive) return Octets;

   --  Is this extension marked critical?
   --
   --  A validator must refuse a certificate carrying a critical extension it
   --  does not understand, so this is reported for every extension whether or
   --  not this crate recognises it.
   --  @param Item the certificate to inspect
   --  @param Index which extension, one through Extension_Count
   --  @return True when the extension is critical
   function Extension_Is_Critical
     (Item : Certificate; Index : Positive) return Boolean;

   --  One extension's value, the content of its OCTET STRING.
   --  @param Item the certificate to inspect
   --  @param Index which extension, one through Extension_Count
   --  @return the extension's value octets, undecoded
   function Extension_Value
     (Item : Certificate; Index : Positive) return Octets;

   --  Find an extension by identifier.
   --  @param Item the certificate to inspect
   --  @param Identifier the encoded OID to look for
   --  @return the extension's index, zero when it is not present
   function Find_Extension
     (Item : Certificate; Identifier : Octets) return Natural;

private

   type Extension_Record is record
      OID_First   : Offset  := 1;
      OID_Last    : Offset  := 0;
      Critical    : Boolean := False;
      Value_First : Offset  := 1;
      Value_Last  : Offset  := 0;
   end record;

   type Extension_Array is
     array (1 .. Maximum_Extensions) of Extension_Record;

   --  A span within the certificate's own DER copy. Empty is Last < First,
   --  which is how an absent optional field is represented.
   type Span is record
      First : Offset := 1;
      Last  : Offset := 0;
   end record;

   type Certificate (Length : Offset) is record
      Present         : Boolean := False;
      Version_Number  : Natural := 1;
      Serial          : Span;
      Issuer          : Span;
      Subject         : Span;
      SPKI            : Span;
      SPKI_Key        : Span;
      TBS             : Span;
      Signature       : Span;
      Sig_Parameters  : Span;
      Valid_From      : Certificate_Time;
      Valid_To        : Certificate_Time;
      Sig_Algorithm   : Signature_Algorithm := Unknown_Signature_Algorithm;
      Key_Algorithm   : Public_Key_Algorithm := Unknown_Public_Key_Algorithm;
      Extension_Total : Natural := 0;
      Extensions      : Extension_Array;
      DER             : Octets (1 .. Length) := [others => 0];
   end record;

end CryptoLib.X509.Certificates;
