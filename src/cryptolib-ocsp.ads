with CryptoLib.ASN1;
with CryptoLib.ASN1.Errors;
with CryptoLib.X509;
with CryptoLib.X509.Certificates;

--  @summary OCSP request building and response checking.
--
--  The protocol objects and the cryptography, and nothing else. This does not
--  make network requests: a response arrives from a responder the application
--  chose to ask, or stapled to a TLS handshake by the peer, and either way
--  getting hold of it is not a job for a crypto library.
--
--  Who is allowed to answer is the part worth being careful about. A response
--  is acceptable when the certificate's own issuer signed it, or when a
--  responder the issuer delegated to did. A delegated responder has to be
--  issued by that same issuer and carry the OCSP signing extended key usage:
--  without both, anyone holding any certificate from any CA could answer for
--  anybody's. Responder_Status reports which of the two happened, so a caller
--  is never left to assume.
package CryptoLib.OCSP is

   subtype Decode_Status is CryptoLib.ASN1.Errors.Decode_Status;
   subtype Decode_Limits is CryptoLib.ASN1.Decode_Limits;
   subtype Octets is CryptoLib.ASN1.Octets;
   subtype Offset is CryptoLib.ASN1.Offset;
   subtype Certificate is CryptoLib.X509.Certificates.Certificate;
   subtype Certificate_Time is CryptoLib.X509.Certificate_Time;
   subtype Revocation_Details is CryptoLib.X509.Revocation_Details;

   --  What the responder said about the whole request.
   type Response_Status is
     (Successful,
      Malformed_Request,
      Internal_Error,
      Try_Later,
      Signature_Required,
      Unauthorized,
      Unknown_Response_Status);

   --  What the responder said about the certificate.
   --
   --  Unknown is not good. It means the responder does not know the
   --  certificate, which for a responder that should know every certificate
   --  its issuer signed is a reason for suspicion rather than a shrug.
   type Certificate_Status is (Good, Revoked, Unknown);

   --  Whether the answer came from the issuer or from a delegate.
   type Responder_Kind is
     (Issuer_Signed,
      Delegate_Signed,
      Not_Established);

   --  Why a response was not accepted.
   type Verification_Result is
     (Accepted,
      Not_Successful,
      --  The responder declined to answer. Look at Response_Status.
      Malformed_Response,
      Wrong_Certificate,
      --  The response is about a different certificate than the one asked
      --  about. A response can be perfectly valid and about somebody else.
      Nonce_Missing,
      --  A nonce was sent and the response carries none, so nothing ties it
      --  to the request. Separate from Nonce_Mismatch because it is the
      --  ordinary behaviour of a responder serving pre-signed responses,
      --  which a caller may decide to tolerate; a wrong nonce is not.
      Nonce_Mismatch,
      --  The response carries a different nonce than the one sent. That is
      --  somebody else's answer, or a replayed one.
      Unknown_Responder,
      --  Signed by something that is neither the issuer nor a responder the
      --  issuer delegated to.
      Delegate_Not_Authorized,
      --  Signed by a certificate the issuer did sign, which does not carry
      --  the OCSP signing extended key usage.
      Invalid_Signature,
      Unsupported_Algorithm,
      Missing_Input);

   type Response (Length : Offset) is private;

   --  Ask, or verify, without a nonce.
   No_Nonce : constant Octets (1 .. 0) := [others => 0];

   --  The longest nonce this will send, RFC 8954's bound.
   Maximum_Nonce_Length : constant := 32;

   --  Render a verification result as short diagnostic text.
   --  @param Result the result to describe
   --  @return lower-case text naming the result
   function Result_Image (Result : Verification_Result) return String;

   --  Build an OCSP request asking about one certificate.
   --
   --  The CertID hashes the issuer's name and public key with SHA-1. That is
   --  not a security choice: the identifier is a lookup key that responders
   --  compute the same way, and using anything else asks a question no
   --  responder can answer.
   --  A nonce, when given, is sent as a request extension and ties the
   --  answer to this question. Without one a response stands on its own and
   --  can be replayed for as long as it remains current: an attacker who
   --  captured a "good" answer before the certificate was revoked can keep
   --  presenting it until nextUpdate. It must be unpredictable -- generate it
   --  with CryptoLib.Random, not from a counter or a clock -- and it must be
   --  kept, because checking the answer means comparing against it.
   --
   --  It is optional because it has to be. Many public responders serve
   --  pre-signed responses and either ignore a nonce or refuse the request
   --  outright, so a library that always sent one would fail against them.
   --  @param Item the certificate being asked about
   --  @param Issuer the certificate that issued it
   --  @param Output receives the request's DER
   --  @param Last the last index of Output written
   --  @param Status Ok on success, otherwise why no request was built
   --  @param Nonce the nonce to send, or No_Nonce to send none
   procedure Build_Request
     (Item   : Certificate;
      Issuer : Certificate;
      Output : out Octets;
      Last   : out Offset;
      Status : out Decode_Status;
      Nonce  : Octets := No_Nonce);

   --  An upper bound on a request's size, for sizing the buffer.
   --  @return the largest number of octets Build_Request can produce
   function Maximum_Request_Length return Natural
   is (512);

   --  Decode a response.
   --  @param Data the response's DER
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Status Ok on success, otherwise why the input was refused
   --  @return the decoded response, or an empty one on failure
   function Decode_Response
     (Data   : Octets;
      Limits : Decode_Limits;
      Status : out Decode_Status) return Response;

   --  Did this decode?
   --  @param Item the response to inspect
   --  @return True when it holds a decoded encoding
   function Is_Present (Item : Response) return Boolean;

   --  What the responder said about the request as a whole.
   --  @param Item the response to inspect
   --  @return the response status
   function Status_Of (Item : Response) return Response_Status;

   --  What the responder said about the certificate.
   --
   --  Meaningful only once Verify has accepted the response: before that it
   --  is an unauthenticated claim.
   --  @param Item the response to inspect
   --  @return the certificate status
   function Certificate_Status_Of (Item : Response) return Certificate_Status;

   --  When the responder last knew this to be true.
   --  @param Item the response to inspect
   --  @return the thisUpdate time
   function This_Update (Item : Response) return Certificate_Time;

   --  Whether the response says when it stops being current.
   --  @param Item the response to inspect
   --  @return True when a nextUpdate is present
   function Has_Next_Update (Item : Response) return Boolean;

   --  See Has_Next_Update.
   --  @param Item the response to inspect
   --  @return the nextUpdate time, meaningless when absent
   function Next_Update (Item : Response) return Certificate_Time;

   --  When the certificate was revoked, and why.
   --
   --  Meaningful only once Verify has accepted the response, and only when
   --  Certificate_Status_Of says Revoked; Present is False otherwise. A
   --  responder is not obliged to give a reason, and one that does not is
   --  not saying "unspecified".
   --  @param Item the response to inspect
   --  @return what the response says about the revocation
   function Revocation_Of (Item : Response) return Revocation_Details;

   --  Does the response carry a nonce?
   --  @param Item the response to inspect
   --  @return True when a nonce extension is present
   function Has_Nonce (Item : Response) return Boolean;

   --  The nonce the response carries.
   --
   --  Unauthenticated until Verify has accepted the response: the nonce is
   --  inside the signed data, but nothing has checked the signature yet.
   --  @param Item the response to inspect
   --  @return the nonce octets, empty when the response carries none
   function Nonce (Item : Response) return Octets;

   --  Who signed the response, once Verify has established it.
   --  @param Item the response to inspect
   --  @return which kind of responder signed it
   function Responder (Item : Response) return Responder_Kind;

   --  Check that this response answers for this certificate and was signed by
   --  someone entitled to answer.
   --
   --  Accepted means the signature holds, the response is about the
   --  certificate asked about, and the signer was the issuer or a responder
   --  the issuer delegated to. It does not mean the certificate is good --
   --  read Certificate_Status_Of for that -- nor that the response is current,
   --  which is a question about times and the caller's tolerance.
   --  Pass the nonce that was sent as Expected_Nonce and the response must
   --  carry it. Leaving it No_Nonce checks nothing, which is right for a
   --  stapled response or one fetched without a nonce, and wrong for one
   --  fetched with a nonce that nobody then compares.
   --  @param Item the response to check, updated with who signed it
   --  @param Subject the certificate the response should be about
   --  @param Issuer that certificate's issuer
   --  @param Expected_Nonce the nonce that was sent, or No_Nonce
   --  @return Accepted, or why not
   function Verify
     (Item           : in out Response;
      Subject        : Certificate;
      Issuer         : Certificate;
      Expected_Nonce : Octets := No_Nonce) return Verification_Result;

private

   type Span is record
      First : Offset := 1;
      Last  : Offset := 0;
   end record;

   type Response (Length : Offset) is record
      Present      : Boolean := False;
      Outcome      : Response_Status := Unknown_Response_Status;
      Cert_State   : Certificate_Status := Unknown;
      TBS          : Span;
      Signature    : Span;
      Signer_Cert  : Span;
      Has_Signer   : Boolean := False;
      Responses    : Span;
      Nonce_At     : Span;
      Has_Nonce_Ext : Boolean := False;
      Revocation   : CryptoLib.X509.Revocation_Details;
      Name_Hash    : Span;
      Key_Hash     : Span;
      Serial       : Span;
      Issued       : Certificate_Time;
      Due          : Certificate_Time;
      Due_Present  : Boolean := False;
      Algorithm    : CryptoLib.X509.Signature_Algorithm :=
        CryptoLib.X509.Unknown_Signature_Algorithm;
      Signed_By    : Responder_Kind := Not_Established;
      DER          : Octets (1 .. Length) := [others => 0];
   end record;

end CryptoLib.OCSP;
