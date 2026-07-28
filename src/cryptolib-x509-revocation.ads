with CryptoLib.OCSP;
with CryptoLib.X509.Certificates;
with CryptoLib.X509.CRLs;

--  @summary Asking whether a certificate has been revoked, with material the
--  caller already has.
--
--  Deliberately not part of path validation, and deliberately not fetching
--  anything. A validator that went to the network would make every validation
--  a request that can hang, fail, or be watched; and a caller that has a
--  stapled OCSP response or a CRL from disk should not have to pretend it
--  came from somewhere else. So the material is passed in, and what to do
--  when there is none is the caller's policy rather than this package's
--  assumption.
--
--  Freshness is checked here because nothing else was checking it. A CRL
--  states when it was issued and usually when the next is due; a response
--  states the same. Reading "not revoked" off a statement made years ago and
--  treating it as current is how a revoked certificate keeps working, so a
--  statement outside its own window answers Stale rather than Not_Revoked.
package CryptoLib.X509.Revocation is

   subtype Certificate is CryptoLib.X509.Certificates.Certificate;

   type Revocation_Answer is
     (Not_Revoked,
      --  The statement covers this certificate, is current, and does not
      --  revoke it.
      Revoked,
      Unknown,
      --  The responder does not know the certificate. Not the same as good:
      --  for a responder that should know every certificate its issuer
      --  signed, it is a reason for suspicion.
      Stale,
      --  The statement is outside its own validity window, so it says nothing
      --  about now.
      Wrong_Issuer,
      --  The statement is about a different issuer's certificates.
      Untrusted_Signature,
      --  The statement is not signed by anyone entitled to make it.
      Malformed);
      --  The statement did not decode, or the certificate did not.

   --  Render an answer as short diagnostic text.
   --  @param Answer the answer to describe
   --  @return lower-case text naming the answer
   function Answer_Image (Answer : Revocation_Answer) return String;

   --  Ask a revocation list about a certificate.
   --
   --  The list must be signed by the certificate's issuer and must be about
   --  that issuer's certificates: a CRL signed by a key you trust but issued
   --  by somebody else says nothing about yours.
   --  @param Item the certificate in question
   --  @param Issuer the certificate that issued it
   --  @param List the revocation list to consult
   --  @param At_Time the time to judge the list's freshness against
   --  @return what the list says, or why it cannot say
   function Check_Against_CRL
     (Item    : Certificate;
      Issuer  : Certificate;
      List    : CryptoLib.X509.CRLs.Revocation_List;
      At_Time : Certificate_Time) return Revocation_Answer;

   --  As above, and say when the certificate was revoked and why.
   --
   --  Details is filled only when the answer is Revoked, and only from the
   --  statement that produced that answer. It stays Present-False otherwise,
   --  so a caller cannot read a revocation time off a list that did not
   --  revoke anything.
   --  @param Item the certificate in question
   --  @param Issuer the certificate that issued it
   --  @param List the revocation list to consult
   --  @param At_Time the time to judge the list's freshness against
   --  @param Details receives when and why, when the answer is Revoked
   --  @return what the list says, or why it cannot say
   function Check_Against_CRL
     (Item    : Certificate;
      Issuer  : Certificate;
      List    : CryptoLib.X509.CRLs.Revocation_List;
      At_Time : Certificate_Time;
      Details : out Revocation_Details) return Revocation_Answer;

   --  Ask an OCSP response about a certificate.
   --
   --  The response must be about this certificate and signed by the issuer or
   --  by a responder the issuer authorised; CryptoLib.OCSP decides both.
   --  @param Item the certificate in question
   --  @param Issuer the certificate that issued it
   --  @param Response the response to consult
   --  @param At_Time the time to judge the response's freshness against
   --  @return what the response says, or why it cannot say
   function Check_Against_OCSP
     (Item     : Certificate;
      Issuer   : Certificate;
      Response : in out CryptoLib.OCSP.Response;
      At_Time  : Certificate_Time) return Revocation_Answer;

   --  As above, and say when the certificate was revoked and why.
   --
   --  Details is filled only when the answer is Revoked. A responder that
   --  revokes without giving a time is possible and leaves Details
   --  Present-False: the answer is still Revoked, since not saying when does
   --  not unsay the revocation.
   --  @param Item the certificate in question
   --  @param Issuer the certificate that issued it
   --  @param Response the response to consult
   --  @param At_Time the time to judge the response's freshness against
   --  @param Details receives when and why, when the answer is Revoked
   --  @return what the response says, or why it cannot say
   function Check_Against_OCSP
     (Item     : Certificate;
      Issuer   : Certificate;
      Response : in out CryptoLib.OCSP.Response;
      At_Time  : Certificate_Time;
      Details  : out Revocation_Details) return Revocation_Answer;

end CryptoLib.X509.Revocation;
