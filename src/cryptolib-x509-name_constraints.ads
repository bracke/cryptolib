with CryptoLib.ASN1;
with CryptoLib.X509.Certificates;

--  @summary Enforcing a CA's name constraints on the certificates below it.
--
--  A constrained CA says which names it may certify: an enterprise root
--  limited to its own domain, a cross-signed intermediate limited to what the
--  signer was willing to vouch for. The extension is normally critical,
--  because a relying party that ignored it would accept exactly the
--  certificates the constraint exists to prevent.
--
--  That is why this exists rather than the extension simply being added to
--  the list of ones a validator recognises. Recognising it without enforcing
--  it turns a conservative refusal into a silent bypass, which is worse than
--  refusing to validate the chain at all.
--
--  DNS names, IP addresses, directory names and URIs are enforced. A
--  directory-name subtree constrains the certificate's own subject rather
--  than an alternative name, which is how a CA is limited to an organisation
--  rather than to a domain; a URI subtree constrains the host the URI names.
--  A constraint naming a form still not applied here -- an email subtree, an
--  EDI party name -- is reported as unsupported rather than ignored, so a
--  chain whose constraints this cannot fully apply is refused rather than
--  half-checked.
package CryptoLib.X509.Name_Constraints is

   subtype Certificate is CryptoLib.X509.Certificates.Certificate;
   subtype Octets is CryptoLib.ASN1.Octets;

   type Verdict is
     (Permitted,
      --  Every name the certificate carries is inside the permitted subtrees
      --  and outside the excluded ones.
      Excluded,
      --  A name falls in an excluded subtree, or outside the permitted ones.
      Unsupported_Constraint,
      --  The constraints name a form this cannot apply. Refused rather than
      --  ignored: a constraint that is not applied is not a constraint.
      Malformed);

   --  Render a verdict as short diagnostic text.
   --  @param Result the verdict to describe
   --  @return lower-case text naming the verdict
   function Verdict_Image (Result : Verdict) return String;

   --  Does this certificate stay within these constraints?
   --
   --  Constraints_Value is the nameConstraints extension's value, as
   --  CryptoLib.X509.Certificates.Extension_Value gives it.
   --
   --  A certificate carrying no name of a constrained kind is permitted by
   --  that constraint: RFC 5280 applies a subtree only to names of its own
   --  type, so a certificate with no DNS name is not caught by a DNS
   --  restriction.
   --  @param Constraints_Value the encoded nameConstraints extension value
   --  @param Item the certificate to check
   --  @return whether the certificate's names are within the constraints
   function Check
     (Constraints_Value : Octets;
      Item              : Certificate) return Verdict;

end CryptoLib.X509.Name_Constraints;
