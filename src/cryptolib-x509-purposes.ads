with CryptoLib.X509.Certificates;

--  @summary May this certificate be used for what you want to use it for?
--
--  The third of the three questions a caller has to ask, after "does the
--  chain hold" and "is it for this name". A certificate can chain to a
--  trusted root, name the right host, and still be a code-signing
--  certificate.
--
--  The rules come from RFC 5280's basicConstraints, keyUsage, and
--  extendedKeyUsage, and the one that governs everything here is what absence
--  means. An extension that is not present does not constrain the
--  certificate: a certificate with no extended key usage may be used for any
--  purpose, and reading that as "no purposes permitted" would reject most of
--  the private PKI in existence. An extension that is present and does not
--  list the purpose does forbid it. The two are opposite conclusions from
--  neighbouring states, which is why Get_* in CryptoLib.X509.Extensions
--  reports presence separately in the first place.
package CryptoLib.X509.Purposes is

   subtype Certificate is CryptoLib.X509.Certificates.Certificate;

   type Certificate_Purpose is
     (TLS_Server,
      TLS_Client,
      Code_Signing,
      Email_Protection,
      Certificate_Authority,
      OCSP_Signing);

   type Purpose_Result is
     (Permitted,
      Not_A_CA,
      --  Asked whether it may act as a CA, and its basic constraints say no
      --  or are absent. Absent counts as no here, unlike everywhere else in
      --  this package: RFC 5280 requires a CA to say so, and a certificate
      --  that does not is not one.
      Key_Usage_Forbids,
      --  A key usage is present and does not permit what this purpose needs.
      Extended_Key_Usage_Forbids,
      --  An extended key usage is present and does not name this purpose,
      --  nor anyExtendedKeyUsage.
      Missing_Input);
      --  A certificate that did not decode was handed in.

   --  Render a purpose result as short diagnostic text.
   --  @param Result the result to describe
   --  @return lower-case text naming the result
   function Result_Image (Result : Purpose_Result) return String;

   --  May this certificate be used for this purpose?
   --
   --  Answers from the certificate alone. It says nothing about whether the
   --  certificate is trusted, current, or correctly signed.
   --  @param Item the certificate to check
   --  @param Purpose what the caller wants to use it for
   --  @return Permitted, or why not
   function Check_Purpose
     (Item    : Certificate;
      Purpose : Certificate_Purpose) return Purpose_Result;

end CryptoLib.X509.Purposes;
