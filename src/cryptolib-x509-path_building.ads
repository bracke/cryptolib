with CryptoLib.X509.Certificates;
with CryptoLib.X509.Policies;

--  @summary Finding a path from a certificate to a trust anchor.
--
--  Separate from validating one, and the separation is not tidiness. A
--  builder searches and may be wrong about what it finds; a validator checks
--  and must not be. Keeping them apart means the checking can be believed
--  without also trusting the search, and it means a path found here still has
--  to go through CryptoLib.X509.Validation before anything is concluded from
--  it.
--
--  The search matches on issuer and subject names and then verifies the
--  signature before following a link. Verifying during the search is what
--  makes cross-signed roots work: two certificates can carry the same subject
--  name and different keys, so a builder that took the first name match and
--  gave up would fail to find a path that exists. Names narrow the search;
--  signatures decide it.
--
--  The search is bounded in three ways, because a hostile pool of
--  certificates is otherwise an invitation to spend the afternoon: by depth,
--  by how many links may be examined, and by refusing to use a certificate
--  twice in one path. When a bound stops the search, that is reported rather
--  than being indistinguishable from having found nothing.
package CryptoLib.X509.Path_Building is

   subtype Certificate is CryptoLib.X509.Certificates.Certificate;

   --  The certificates available to build from, and what the caller trusts.
   --
   --  An interface for the reasons given in CryptoLib.X509.Validation: a
   --  Certificate carries its own length so an array will not hold a mixture,
   --  and Ada forbids passing a subprogram declared inside another, which is
   --  where a caller would write one.
   type Candidate_Source is limited interface;

   --  How many certificates are available.
   --  @param Source the pool to search
   --  @return the number of candidates
   function Count (Source : Candidate_Source) return Natural is abstract;

   --  One of the available certificates.
   --  @param Source the pool to search
   --  @param Index which candidate, one through Count
   --  @return the certificate at that position
   function Candidate
     (Source : Candidate_Source; Index : Positive) return Certificate
      is abstract;

   --  Is this certificate a trust anchor?
   --
   --  Asked of candidates as the search reaches them. Trust is configuration:
   --  a certificate being self-signed says nothing about whether it is
   --  trusted, and this is the only thing that does.
   --  @param Source the pool to search
   --  @param Item the certificate in question
   --  @return True when the caller trusts it as an anchor
   function Is_Trust_Anchor
     (Source : Candidate_Source; Item : Certificate) return Boolean
      is abstract;

   Maximum_Path : constant := 10;

   type Search_Limits is record
      Maximum_Depth : Positive := 6;
      --  How many certificates above the leaf the search may go.
      Maximum_Links : Positive := 200;
      --  How many issuer links may be examined, each costing a signature
      --  verification at most. The budget that stops a hostile pool.
   end record;

   Default_Limits : constant Search_Limits :=
     (Maximum_Depth => 6, Maximum_Links => 200);

   --  Which candidates make up the path, leaf-first above the leaf.
   type Path_Indices is array (1 .. Maximum_Path) of Positive;

   type Build_Result is record
      Found     : Boolean := False;
      Length    : Natural := 0;
      --  How many candidates are in Indices. The leaf is not among them: a
      --  path of length one is the leaf and its anchor.
      Indices   : Path_Indices := [others => 1];
      Examined  : Natural := 0;
      --  How many links were looked at, for a caller that wants to know what
      --  a search cost.
      Exhausted : Boolean := False;
      --  A bound stopped the search. There may be a path that was not
      --  reached, so this is not the same as there being none.
   end record;

   --  Search for a path from Leaf to a trust anchor.
   --
   --  A found path is a proposal, not a verdict. It has been checked link by
   --  link for names and signatures, and it has NOT been checked for validity
   --  windows, basic constraints, key usage, or critical extensions. Hand it
   --  to CryptoLib.X509.Validation before believing it.
   --  Policies are checked during the search, for the same reason signatures
   --  are: a path that cannot satisfy them is not a path worth proposing,
   --  and stopping at the first one found would miss one that works. A pool
   --  holding two cross-signed roots, one of which grants the policy the
   --  chain needs, is the case -- the same shape as the cross-signing that
   --  makes signature checking necessary here.
   --
   --  With the defaults this only rejects a path some certificate in it
   --  demanded an explicit policy for and nothing supplied, which is a path
   --  Validate_Path would refuse anyway. Naming policies in Accepted makes
   --  the search find one that establishes them.
   --  @param Leaf the certificate to build up from
   --  @param Source the certificates available and the trust to reach
   --  @param Limits what the caller will spend on the search
   --  @param Options RFC 5280 section 6.1's three initial inputs
   --  @param Accepted which policies the caller will accept, empty for any
   --  @return the path found, or a result saying none was
   function Build_Path
     (Leaf     : Certificate;
      Source   : Candidate_Source'Class;
      Limits   : Search_Limits := Default_Limits;
      Options  : CryptoLib.X509.Policies.Policy_Options :=
        CryptoLib.X509.Policies.Default_Options;
      Accepted : CryptoLib.X509.Policies.Accepted_Policies :=
        CryptoLib.X509.Policies.Accept_Any) return Build_Result;

end CryptoLib.X509.Path_Building;
