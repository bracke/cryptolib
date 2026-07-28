with CryptoLib.X509.Certificates;

--  @summary Does this certificate speak for the name you asked for?
--
--  The check a caller must make after a path validates and which validating a
--  path does not make for it. A chain can be impeccable and belong to someone
--  else entirely.
--
--  Follows RFC 9525, which supersedes RFC 6125. Two of its positions are
--  worth stating because they differ from what older code does:
--
--  The subject common name is not consulted. It is not a place to put a
--  service identity, has not been for many years, and a certificate that
--  carries a name only there is one that no modern issuer should have
--  produced. Common_Name_Fallback exists for callers with an old private CA
--  they cannot reissue, defaults to False, and should stay that way.
--
--  Wildcards match one label, in the leftmost position, and must be the whole
--  label. "*.example.com" matches "a.example.com" and does not match
--  "example.com" or "a.b.example.com". Partial wildcards such as
--  "www*.example.com" are not matched at all: RFC 9525 says implementations
--  should not support them, and a partial wildcard is how a name like
--  "www*.example.com" is made to cover "www.attacker.example.com" in readers
--  that glob loosely.
--
--  Addresses are compared as octets and never as text. This package will not
--  take an address as a string, because the moment it did somebody would
--  compare "10.0.0.1" with "10.000.000.001" and find them different while the
--  addresses are the same.
--
--  Internationalized names are compared as they are encoded. A certificate
--  carries A-labels (the "xn--" form); a caller holding a U-label must
--  convert it before asking, because doing that here would mean an IDNA
--  implementation inside a crypto library, and IDNA is where mapping choices
--  turn into different names.
package CryptoLib.X509.Identity is

   subtype Certificate is CryptoLib.X509.Certificates.Certificate;

   type Match_Result is
     (Matched,
      No_Match,
      --  The certificate carries names and none of them is this one.
      No_Names_Present,
      --  The certificate carries no name of the kind asked about. Distinct
      --  from No_Match so that a caller can tell "this certificate is not for
      --  you" from "this certificate does not say who it is for".
      Malformed_Reference,
      --  The name asked about is not a name: empty, or with a NUL in it.
      Malformed_Identity);
      --  A name in the certificate is not usable -- an embedded NUL, an empty
      --  label, an address of the wrong width. Reported rather than skipped:
      --  a certificate carrying such a name is one to be suspicious of, and
      --  quietly ignoring the entry is how a name like "example.com\0.evil"
      --  gets to be treated as two different things by two readers.

   type Matching_Policy is record
      Allow_Wildcards            : Boolean := True;
      Allow_Common_Name_Fallback : Boolean := False;
   end record;

   Default_Policy : constant Matching_Policy :=
     (Allow_Wildcards            => True,
      Allow_Common_Name_Fallback => False);

   --  Render a match result as short diagnostic text.
   --  @param Result the result to describe
   --  @return lower-case text naming the result
   function Result_Image (Result : Match_Result) return String;

   --  Does this certificate speak for this DNS name?
   --
   --  Comparison is ASCII case-insensitive. A single trailing dot on either
   --  side is ignored, being the same name written absolutely.
   --  @param Item the certificate to check
   --  @param Reference the DNS name the caller asked for
   --  @param Policy what the caller permits
   --  @return whether the certificate carries a matching name
   function Match_DNS_Name
     (Item      : Certificate;
      Reference : String;
      Policy    : Matching_Policy := Default_Policy) return Match_Result;

   --  Does this certificate speak for this IP address?
   --
   --  Address is the address in its network form: four octets for IPv4,
   --  sixteen for IPv6. Wildcards never apply.
   --  @param Item the certificate to check
   --  @param Address the address the caller asked for, as octets
   --  @param Policy what the caller permits; wildcards are ignored here
   --  @return whether the certificate carries a matching address
   function Match_IP_Address
     (Item    : Certificate;
      Address : Octets;
      Policy  : Matching_Policy := Default_Policy) return Match_Result;

end CryptoLib.X509.Identity;
