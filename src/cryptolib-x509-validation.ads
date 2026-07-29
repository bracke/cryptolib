with CryptoLib.X509.Certificates;
with CryptoLib.X509.Policies;

--  @summary Validating one proposed certificate path against explicit trust.
--
--  This checks a path the caller already has. It does not search for one:
--  finding a path through cross-signed roots and repeated subjects is a
--  different and much harder problem, and keeping the two apart means the
--  checking can be believed without also trusting a search.
--
--  Trust is the caller's to supply and is never inferred. A self-signed
--  certificate at the end of a chain is not a trust anchor; it is a
--  certificate that says so about itself. Is_Trust_Anchor is asked, and if it
--  says no the path fails however well formed it is.
--
--  What is checked, and nothing beyond it: signatures along the path, issuer
--  and subject linkage, validity windows against a supplied time, basic
--  constraints and path length, key usage for certificate signing,
--  termination at a trust anchor, name constraints applied by every CA above
--  a certificate rather than only its immediate issuer, and the presence of
--  critical extensions this crate cannot interpret.
--
--  Certificate policy processing and revocation are NOT done here. A critical
--  policyConstraints or inhibitAnyPolicy makes the chain fail rather than be
--  accepted with the demand ignored; certificatePolicies restricts nothing
--  without a caller-supplied policy set. Revocation lives in
--  X509.Revocation and is never consulted from here, so a valid result says
--  the path holds, not that nothing on it has since been revoked.
package CryptoLib.X509.Validation is

   subtype Certificate is CryptoLib.X509.Certificates.Certificate;

   type Validation_Failure is
     (None,
      Malformed_Certificate,
      --  A certificate in the path did not decode.
      Empty_Path,
      Path_Too_Long,
      --  Longer than the caller's policy allows, before any other work.
      Invalid_Signature,
      --  A certificate is not signed by the key of the one above it.
      Unsupported_Signature_Algorithm,
      --  A signature this crate cannot verify. Nothing was checked, so the
      --  path is refused rather than accepted on faith.
      Issuer_Mismatch,
      --  A certificate's issuer name is not the next certificate's subject.
      Certificate_Expired,
      Certificate_Not_Yet_Valid,
      Invalid_Basic_Constraints,
      --  An issuer does not assert that it is a CA.
      Path_Length_Exceeded,
      --  More intermediates below an issuer than its pathLenConstraint
      --  permits.
      Invalid_Key_Usage,
      --  An issuer's key usage does not permit signing certificates.
      Name_Constraint_Violation,
      --  A certificate carries a name the CA above it was not permitted to
      --  certify.
      Unsupported_Name_Constraint,
      --  A CA constrains a form of name this crate cannot apply. Refused
      --  rather than checked against only the part that could be applied: a
      --  constraint half-applied is not the constraint the issuer imposed.
      Unknown_Critical_Extension,
      --  A certificate carries a critical extension this crate cannot
      --  interpret, so what it means cannot be established.
      Duplicate_Certificate,
      --  The same certificate appears twice, which is a loop.
      No_Trust_Anchor,
      --  The path is well formed and ends somewhere the caller does not
      --  trust. This is the failure that means "correct but not trusted",
      --  and it is deliberately not the same as a bad signature.
      Policy_Not_Established);
      --  RFC 5280 section 6.1 policy processing rejected the path: some
      --  certificate demanded an explicit policy that nothing below it
      --  provides. Only reachable when a certificate asks for it, or when
      --  the caller does.

   --  What a caller insists on.
   type Validation_Policy is record
      Maximum_Path_Length       : Positive := 8;
      Require_Basic_Constraints : Boolean := True;
      Require_Key_Cert_Sign     : Boolean := True;
      Reject_Unknown_Critical   : Boolean := True;

      --  RFC 5280 section 6.1's three initial inputs. All off by default,
      --  which records policies without letting them refuse a path: a caller
      --  that has not thought about policies gets the behaviour it expects,
      --  and one that has can demand an explicit policy of the whole chain.
      Policy_Options            : CryptoLib.X509.Policies.Policy_Options :=
        CryptoLib.X509.Policies.Default_Options;

      --  Which policies the caller will accept. Empty accepts any, and
      --  naming some only refuses a path when a certificate in it required
      --  an explicit policy -- see X509.Policies.Accepted_Policies, which
      --  says why that is less than it sounds.
      Accepted_Policies         : CryptoLib.X509.Policies.Accepted_Policies :=
        CryptoLib.X509.Policies.Accept_Any;
   end record;

   Default_Policy : constant Validation_Policy :=
     (Maximum_Path_Length       => 8,
      Require_Basic_Constraints => True,
      Require_Key_Cert_Sign     => True,
      Reject_Unknown_Critical   => True,
      Policy_Options            =>
        CryptoLib.X509.Policies.Default_Options,
      Accepted_Policies         =>
        CryptoLib.X509.Policies.Accept_Any);

   --  Why a path failed, and where.
   --
   --  Index is the position in the path, one being the leaf, so a caller can
   --  say which certificate was the problem rather than only that there was
   --  one. Zero when the failure belongs to the path as a whole.
   type Validation_Result is record
      Valid   : Boolean := False;
      Failure : Validation_Failure := None;
      Index   : Natural := 0;

      --  The policies the authorities in the path actually agreed on, which
      --  is not the same as what the leaf asserts: a certificate may name a
      --  policy its issuers never granted, and this is the set that survived
      --  every one of them. Empty when no certificate named any.
      Policies : CryptoLib.X509.Policies.Policy_Outcome;
   end record;

   --  Render a failure as short diagnostic text.
   --  @param Failure the failure to describe
   --  @return lower-case text naming the failure
   function Failure_Image (Failure : Validation_Failure) return String;

   --  The path being checked, and what the caller trusts.
   --
   --  An interface rather than an array or a set of callbacks. An array will
   --  not do because a Certificate carries its own length, so certificates of
   --  different sizes cannot share one. Access-to-subprogram will not do
   --  either: Ada's accessibility rules forbid passing a subprogram declared
   --  inside another one, and a caller assembling a chain does so inside a
   --  subprogram every time. Deriving a type costs the caller a few lines and
   --  works wherever it is written.
   --
   --  It also leaves storage entirely to the caller: certificates held in a
   --  file, a buffer, or a TLS message need not be copied into a shape this
   --  package chose.
   type Path_Source is limited interface;

   --  How many certificates the path holds.
   --  @param Source the path being checked
   --  @return the number of certificates, at least one
   function Length (Source : Path_Source) return Positive is abstract;

   --  The certificate at a position, one being the leaf.
   --  @param Source the path being checked
   --  @param Index which certificate, one through Length
   --  @return the certificate at that position
   function Certificate_At
     (Source : Path_Source; Index : Positive) return Certificate is abstract;

   --  Is this certificate one the caller trusts?
   --
   --  Asked only of the last certificate in the path. Answering by asking
   --  whether it is self-signed would defeat the purpose: trust is
   --  configuration, not a property a certificate can assert about itself.
   --  @param Source the path being checked
   --  @param Item the certificate in question
   --  @return True when the caller trusts it as an anchor
   function Is_Trust_Anchor
     (Source : Path_Source; Item : Certificate) return Boolean is abstract;

   --  Check a proposed path.
   --
   --  A valid result means every check listed for this package passed. It
   --  does not mean the leaf is fit for any particular purpose or names any
   --  particular host; those are separate questions.
   --  @param Source the path to check and the trust to check it against
   --  @param Validation_Time the time to judge validity windows against
   --  @param Policy what the caller insists on
   --  @return the outcome, with the position of the first failure
   function Validate_Path
     (Source          : Path_Source'Class;
      Validation_Time : Certificate_Time;
      Policy          : Validation_Policy := Default_Policy)
      return Validation_Result;

end CryptoLib.X509.Validation;
