with CryptoLib.ASN1;
with CryptoLib.X509.Certificates;

--  @summary Certificate policies, and the RFC 5280 section 6.1 processing
--  that decides what a chain's policies actually are.
--
--  A policy identifier says under which rules a certificate was issued. On its
--  own it restricts nothing -- it is an assertion, and it takes a relying
--  party asking for a particular policy to make it mean anything. What gives
--  the extension teeth is the rest of the machinery: policyConstraints can
--  demand that every certificate below it name an acceptable policy,
--  policyMappings lets one CA declare its policy equivalent to another's, and
--  inhibitAnyPolicy withdraws the wildcard.
--
--  Those three are why this exists rather than the identifiers simply being
--  read out of a certificate. Before this, a critical policyConstraints or
--  inhibitAnyPolicy made a chain fail, which was correct but blunt: honouring
--  the extension is a capability, and refusing everything that carries one is
--  how a conservative validator turns into one nobody can use.
--
--  The processing is a tree. Each level of the path adds the policies its
--  certificate asserts, keeping only those reachable from the level above,
--  and a chain satisfies a policy when a leaf of that tree still names it.
--  Three counters run alongside it, each counting down the certificates until
--  some permission is withdrawn.
package CryptoLib.X509.Policies is

   subtype Certificate is CryptoLib.X509.Certificates.Certificate;
   subtype Octets is CryptoLib.ASN1.Octets;

   --  An object identifier is short. Nothing standard approaches this, and a
   --  certificate naming a longer one is naming a policy this cannot hold.
   Maximum_Policy_Length : constant := 40;

   --  How many policies one certificate may assert, how many mappings it may
   --  declare, and how wide the tree may grow. A certificate in the wild
   --  carries one or two policies; the tree is bounded because it is built
   --  from attacker-supplied input and must not be able to grow without end.
   Maximum_Policies : constant := 16;
   Maximum_Mappings : constant := 16;
   Maximum_Nodes    : constant := 64;

   --  Running out of room is reported rather than truncated, and the engine
   --  carries guards that say so wherever a set could overflow. Most of them
   --  cannot fire while these bounds stand: no certificate contributes more
   --  policies than a mapping set can name, so the gathering steps reach
   --  their limit exactly and never pass it. That is worth having the
   --  compiler hold to, because the alternative to an unreachable guard is
   --  not a reachable one -- it is a truncation path that no test covers,
   --  arrived at by changing a number here.
   pragma Compile_Time_Error
     (Maximum_Mappings > Maximum_Policies,
      "a certificate could map more policies than a policy set can hold, "
      & "which reaches truncation guards the suite does not exercise");
   pragma Compile_Time_Error
     (Maximum_Nodes < Maximum_Policies,
      "the tree could not hold one node per policy of a single certificate");

   --  One policy identifier, held as the OID's content octets.
   type Policy_Value is private;

   --  The special identifier 2.5.29.32.0, which asserts every policy.
   --  @return the anyPolicy identifier
   function Any_Policy return Policy_Value;

   --  Read an identifier from its encoded content octets.
   --  @param Encoded the OID's content octets, without tag or length
   --  @return the identifier, empty when it is longer than this can hold
   function To_Policy (Encoded : Octets) return Policy_Value;

   --  Does this hold an identifier at all?
   --  @param Item the identifier to inspect
   --  @return True when it names something
   function Is_Present (Item : Policy_Value) return Boolean;

   --  Is this the anyPolicy wildcard?
   --  @param Item the identifier to inspect
   --  @return True when it is 2.5.29.32.0
   function Is_Any (Item : Policy_Value) return Boolean;

   --  Do these name the same policy?
   --  @param Left one identifier
   --  @param Right the other
   --  @return True when they are the same identifier
   function Same (Left : Policy_Value; Right : Policy_Value) return Boolean;

   --  The identifier's content octets, for a caller that wants to report it.
   --  @param Item the identifier to render
   --  @return the content octets, empty when it names nothing
   function Encoded_Value (Item : Policy_Value) return Octets;

   type Policy_Array is array (Positive range <>) of Policy_Value;

   --  What a policy says to a person reading it.
   --
   --  RFC 5280 4.2.1.4 defines two: a pointer to the issuer's certification
   --  practice statement, and a notice meant to be displayed. Neither
   --  changes whether a policy applies -- section 6.1 never consults them --
   --  so they are read for a caller that wants to show why a certificate
   --  claims what it claims, and for nothing else.
   type Qualifier_Kind is (CPS_Uri, User_Notice, Other_Qualifier);

   --  The RFC bounds DisplayText at 200 characters and a CPS pointer is a
   --  URI; anything longer is recorded as truncated rather than kept.
   Maximum_Qualifier_Text : constant := 200;
   Maximum_Qualifiers     : constant := 2;

   type Policy_Qualifier is record
      Kind      : Qualifier_Kind := Other_Qualifier;
      Truncated : Boolean := False;
      Length    : Natural := 0;
      Text      : String (1 .. Maximum_Qualifier_Text) := [others => ' '];
   end record;

   type Qualifier_Array is
     array (1 .. Maximum_Qualifiers) of Policy_Qualifier;

   --  One policy, with whatever it says about itself.
   type Policy_Entry is record
      Value            : Policy_Value;
      Qualifier_Count  : Natural := 0;
      Qualifiers       : Qualifier_Array;
   end record;

   type Entry_Array is array (1 .. Maximum_Policies) of Policy_Entry;

   --  What a certificate's certificatePolicies extension says.
   --
   --  Present and Count are separate: a certificate with no extension does
   --  not constrain policies, while one asserting an empty sequence is
   --  malformed. Well_Formed records that the extension parsed; a malformed
   --  one is not read as an absent one, because absent has a meaning here
   --  (section 6.1.3 (e) empties the tree) and getting that backwards would
   --  turn a broken certificate into a permissive one.
   type Policy_Set is record
      Present     : Boolean := False;
      Well_Formed : Boolean := False;
      Has_Any     : Boolean := False;
      Count       : Natural := 0;
      Values      : Policy_Array (1 .. Maximum_Policies);

      --  The same policies, with their qualifiers. Values is kept beside
      --  this because the processing in section 6.1 only ever needs the
      --  identifiers, and threading the text through the tree would carry
      --  a couple of hundred bytes a node for something the tree never
      --  reads.
      Entries     : Entry_Array;
   end record;

   --  One policyMappings entry: the issuer's policy, and what it maps to in
   --  the subject's domain.
   type Policy_Mapping is record
      Issuer_Policy  : Policy_Value;
      Subject_Policy : Policy_Value;
   end record;

   type Mapping_Array is array (Positive range <>) of Policy_Mapping;

   type Mapping_Set is record
      Present     : Boolean := False;
      Well_Formed : Boolean := False;
      Count       : Natural := 0;
      Values      : Mapping_Array (1 .. Maximum_Mappings);
   end record;

   --  policyConstraints. Each field is a count of certificates that may still
   --  appear before the constraint takes effect, so zero means "from here
   --  down", and absent means never.
   type Policy_Constraints is record
      Present                 : Boolean := False;
      Well_Formed             : Boolean := False;
      Has_Require_Explicit    : Boolean := False;
      Require_Explicit        : Natural := 0;
      Has_Inhibit_Mapping     : Boolean := False;
      Inhibit_Mapping         : Natural := 0;
   end record;

   --  inhibitAnyPolicy: how many more certificates may still use anyPolicy.
   type Inhibit_Any_Policy is record
      Present     : Boolean := False;
      Well_Formed : Boolean := False;
      Value       : Natural := 0;
   end record;

   --  Read the certificatePolicies extension.
   --  @param Item the certificate to inspect
   --  @return what it asserts; Present is False when the extension is absent
   function Policies_Of (Item : Certificate) return Policy_Set;

   --  Read the policyMappings extension.
   --  @param Item the certificate to inspect
   --  @return the mappings; Present is False when the extension is absent
   function Mappings_Of (Item : Certificate) return Mapping_Set;

   --  Read the policyConstraints extension.
   --  @param Item the certificate to inspect
   --  @return the constraints; Present is False when the extension is absent
   function Constraints_Of (Item : Certificate) return Policy_Constraints;

   --  Read the inhibitAnyPolicy extension.
   --  @param Item the certificate to inspect
   --  @return the value; Present is False when the extension is absent
   function Inhibit_Of (Item : Certificate) return Inhibit_Any_Policy;

   -----------------------------------------------------------------------
   --  RFC 5280 section 6.1 policy processing
   -----------------------------------------------------------------------

   --  What the caller insists on before processing starts.
   --
   --  These are the RFC's initial-explicit-policy,
   --  initial-policy-mapping-inhibit and initial-any-policy-inhibit. All
   --  three default to off, which is what a relying party that has not
   --  thought about policies wants: policies are then recorded and reported
   --  but never cause a refusal on their own.
   type Policy_Options is record
      Require_Explicit_Policy : Boolean := False;
      Inhibit_Policy_Mapping  : Boolean := False;
      Inhibit_Any_Policy      : Boolean := False;
   end record;

   Default_Options : constant Policy_Options := (others => False);

   --  The policies a caller will accept: RFC 5280's user-initial-policy-set.
   --
   --  An empty set is the RFC's any-policy, which accepts whatever the path
   --  establishes. Naming policies here only decides the outcome when some
   --  certificate required an explicit policy -- otherwise section 6.1.5
   --  succeeds on the explicit_policy counter alone and the set is reported
   --  rather than enforced. That is the RFC's behaviour and OpenSSL's, and it
   --  surprises people: asking for a policy does not by itself make a chain
   --  that lacks it fail.
   type Accepted_Policies is record
      Count  : Natural := 0;
      Values : Policy_Array (1 .. Maximum_Policies);
   end record;

   --  Accept whatever the path establishes.
   --  @return an empty set, the RFC's any-policy
   function Accept_Any return Accepted_Policies;

   --  What processing concluded.
   --
   --  Acceptable is the section 6.1.5 verdict. Values holds the policies the
   --  authorities in the path actually agreed on, which is what a caller
   --  wanting to act on a policy should read rather than the leaf's own
   --  assertion -- a certificate may name a policy its issuers never granted.
   --
   --  Exhausted says the tree outgrew what this can hold. It is reported
   --  rather than silently truncated, and it makes the outcome unacceptable:
   --  a partial tree can only ever be too permissive, since the pruning that
   --  removes policies is what the missing nodes would have carried.
   type Policy_Outcome is record
      Acceptable : Boolean := False;
      Exhausted  : Boolean := False;
      Count      : Natural := 0;
      Values     : Policy_Array (1 .. Maximum_Policies);
   end record;

   --  The processing state, driven one certificate at a time.
   --
   --  Kept as a driver rather than given the whole path because the path
   --  belongs to X509.Validation, which calls this; handing it back would
   --  make the two packages depend on each other.
   type Engine (Path_Length : Positive) is private;

   --  Begin processing a path of Path_Length certificates below the anchor.
   --  @param Item the state to initialise
   --  @param Options what the caller insists on
   procedure Start (Item : out Engine; Options : Policy_Options);

   --  Process one certificate.
   --
   --  Called for each certificate below the trust anchor in issuing order:
   --  the one the anchor signed first, the end-entity certificate last. That
   --  is the order the RFC counts in, and the opposite of how a path is
   --  usually held.
   --  @param Item the state to advance
   --  @param Subject the certificate at this position
   --  @param Self_Issued whether its subject and issuer names are the same
   --  @param Accepted False when this certificate cannot satisfy the
   --  policies still required, which ends processing
   procedure Step
     (Item        : in out Engine;
      Subject     : Certificate;
      Self_Issued : Boolean;
      Accepted    : out Boolean);

   --  Did the tree outgrow what this can hold?
   --
   --  Worth asking separately from the verdict. A path refused because it
   --  establishes no acceptable policy is the certificates' doing; one
   --  refused because the tree ran out of room is this implementation's, and
   --  an operator looking at a rejection needs to know which.
   --  @param Item the state to inspect
   --  @return True when a node could not be recorded
   function Exhausted (Item : Engine) return Boolean;

   --  Conclude, intersecting what survived with what the caller accepts.
   --
   --  An empty Wanted means any policy, which is the RFC's
   --  user-initial-policy-set of anyPolicy and the ordinary case.
   --  @param Item the state to conclude
   --  @param Wanted the policies the caller will accept, or none for any
   --  @return the verdict and the policies the path establishes
   function Finish
     (Item : in out Engine; Wanted : Policy_Array) return Policy_Outcome;

private

   type Policy_Octets is
     array (1 .. Maximum_Policy_Length) of CryptoLib.ASN1.Octet;

   type Policy_Value is record
      Length : Natural := 0;
      Data   : Policy_Octets := [others => 0];
   end record;

   --  One node of the valid_policy_tree. Parent is an index into the same
   --  array, zero for the root; Depth is how many certificates have been
   --  processed above it. A node is removed by clearing In_Use rather than
   --  by moving anything, so parent indices stay meaningful.
   type Tree_Node is record
      In_Use   : Boolean := False;
      Depth    : Natural := 0;
      Parent   : Natural := 0;
      Valid    : Policy_Value;
      Expected : Policy_Array (1 .. Maximum_Policies);
      Expected_Count : Natural := 0;
   end record;

   type Node_Array is array (1 .. Maximum_Nodes) of Tree_Node;

   type Engine (Path_Length : Positive) is record
      Nodes            : Node_Array;
      Depth            : Natural := 0;
      Tree_Empty       : Boolean := False;
      Exhausted        : Boolean := False;
      Explicit_Policy  : Natural := 0;
      Policy_Mapping   : Natural := 0;
      Inhibit_Any      : Natural := 0;
      Last_Constraints : Policy_Constraints;
   end record;

end CryptoLib.X509.Policies;
