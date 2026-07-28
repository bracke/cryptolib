with CryptoLib.ASN1;
with CryptoLib.ASN1.Errors;
with CryptoLib.X509;
with CryptoLib.X509.Signatures;

--  @summary Certification requests, PKCS#10.
--
--  A request says "here is a name, here is a public key, please certify
--  that they go together", and it is signed by the private key belonging to
--  the public key it carries. That signature is the only thing in the request
--  a CA has any reason to believe: the name is a claim, the attributes are
--  claims, and the signature is proof that whoever asked holds the key they
--  are asking about.
--
--  So Verify_Signature is not an optional nicety. A CA that issues from an
--  unverified request will happily certify a key its requester does not have,
--  which is a certificate issued to somebody who cannot use it -- or, if the
--  key belongs to someone else, to somebody who should not have it.
package CryptoLib.PKCS10 is

   subtype Decode_Status is CryptoLib.ASN1.Errors.Decode_Status;
   subtype Decode_Limits is CryptoLib.ASN1.Decode_Limits;
   subtype Octets is CryptoLib.ASN1.Octets;
   subtype Offset is CryptoLib.ASN1.Offset;

   type Request (Length : Offset) is private;

   --  Decode a certification request from DER.
   --  @param Data the DER encoding
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Status Ok on success, otherwise why the input was refused
   --  @return the decoded request, or an empty one on failure
   function Decode_DER
     (Data   : Octets;
      Limits : Decode_Limits;
      Status : out Decode_Status) return Request;

   --  Did this decode?
   --  @param Item the request to inspect
   --  @return True when it holds a decoded encoding
   function Is_Present (Item : Request) return Boolean;

   --  The subject name, as encoded.
   --  @param Item the request to inspect
   --  @return the subject's DER, header included
   function Subject_Bytes (Item : Request) return Octets;

   --  The first common name in the subject.
   --  @param Item the request to inspect
   --  @return the common name, "" when the subject carries none
   function Subject_Common_Name (Item : Request) return String;

   --  The whole SubjectPublicKeyInfo, as encoded.
   --  @param Item the request to inspect
   --  @return the SubjectPublicKeyInfo DER, header included
   function Public_Key_Info_Bytes (Item : Request) return Octets;

   --  The public key itself, without its BIT STRING wrapper.
   --  @param Item the request to inspect
   --  @return the public key's octets
   function Public_Key (Item : Request) return Octets;

   --  What kind of key the request carries.
   --  @param Item the request to inspect
   --  @return the public-key algorithm, Unknown when unrecognised
   function Public_Key_Algorithm_Of
     (Item : Request) return CryptoLib.X509.Public_Key_Algorithm;

   --  How the request was signed.
   --  @param Item the request to inspect
   --  @return the signature algorithm, Unknown when unrecognised
   function Signature_Algorithm_Of
     (Item : Request) return CryptoLib.X509.Signature_Algorithm;

   --  The exact bytes the signature was computed over.
   --  @param Item the request to inspect
   --  @return the signed CertificationRequestInfo DER, header included
   function TBS_Bytes (Item : Request) return Octets;

   --  Does the requester hold the key it is asking about?
   --
   --  Checks the request's signature against the request's own public key.
   --  That is the whole content of a PKCS#10 signature: it proves possession
   --  and nothing else. It does not say the name is the requester's to ask
   --  for, which is what a CA's own policy is for.
   --  @param Item the request to check
   --  @return Valid only when the signature verifies under the carried key
   function Verify_Signature
     (Item : Request) return CryptoLib.X509.Signatures.Verification_Result;

private

   type Span is record
      First : Offset := 1;
      Last  : Offset := 0;
   end record;

   type Request (Length : Offset) is record
      Present   : Boolean := False;
      Subject   : Span;
      SPKI      : Span;
      SPKI_Key  : Span;
      TBS       : Span;
      Signature : Span;
      Key_Kind  : CryptoLib.X509.Public_Key_Algorithm :=
        CryptoLib.X509.Unknown_Public_Key_Algorithm;
      Algorithm : CryptoLib.X509.Signature_Algorithm :=
        CryptoLib.X509.Unknown_Signature_Algorithm;
      DER       : Octets (1 .. Length) := [others => 0];
   end record;

end CryptoLib.PKCS10;
