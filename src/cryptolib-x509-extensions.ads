with CryptoLib.X509.Certificates;

--  @summary Reading the extensions that decide what a certificate is for.
--
--  The certificate model hands back extensions as undecoded octets, because
--  what an extension means is a separate question from whether a certificate
--  is well formed. This is where the ones that govern validation are given
--  their meaning.
--
--  Every accessor reports whether the extension was present, separately from
--  what it said. That distinction carries weight: a certificate with no key
--  usage extension is unconstrained by key usage, while one with an empty key
--  usage permits nothing. Folding "absent" into "all false" would turn the
--  first into the second and reject certificates that are perfectly valid.
package CryptoLib.X509.Extensions is

   subtype Certificate is CryptoLib.X509.Certificates.Certificate;

   --  Whether this certificate may act as a CA, and how deep below it a
   --  chain may run.
   type Basic_Constraints is record
      Present         : Boolean := False;
      Well_Formed     : Boolean := False;
      Is_CA           : Boolean := False;
      Has_Path_Length : Boolean := False;
      Path_Length     : Natural := 0;
   end record;

   --  What the subject's key may be used for.
   --
   --  Certificate_Sign is the one that matters for chain building: a CA
   --  certificate without it may not sign certificates, whatever its basic
   --  constraints say.
   type Key_Usage is record
      Present           : Boolean := False;
      Well_Formed       : Boolean := False;
      Digital_Signature : Boolean := False;
      Non_Repudiation   : Boolean := False;
      Key_Encipherment  : Boolean := False;
      Data_Encipherment : Boolean := False;
      Key_Agreement     : Boolean := False;
      Certificate_Sign  : Boolean := False;
      CRL_Sign          : Boolean := False;
      Encipher_Only     : Boolean := False;
      Decipher_Only     : Boolean := False;
   end record;

   --  Which purposes the certificate is issued for.
   --
   --  Any_Purpose is anyExtendedKeyUsage, which readmits every purpose and so
   --  must be checked before concluding that a purpose is absent.
   --  Has_Unrecognised records that the certificate named a purpose this
   --  crate does not know, which is not an error: it means the set is wider
   --  than what is reported here, so absence of a flag is not permission to
   --  assume the purpose is excluded.
   type Extended_Key_Usage is record
      Present          : Boolean := False;
      Well_Formed      : Boolean := False;
      Any_Purpose      : Boolean := False;
      Server_Auth      : Boolean := False;
      Client_Auth      : Boolean := False;
      Code_Signing     : Boolean := False;
      Email_Protection : Boolean := False;
      OCSP_Signing     : Boolean := False;
      Has_Unrecognised : Boolean := False;
   end record;

   --  Which kind of identity a subject alternative name carries.
   type General_Name_Kind is
     (DNS_Name,
      IP_Address,
      Email_Address,
      URI,
      Directory_Name,
      Other_Name);

   --  Read the basic constraints.
   --  @param Item the certificate to inspect
   --  @return the constraints; Present is False when the extension is absent
   function Get_Basic_Constraints (Item : Certificate) return Basic_Constraints;

   --  Read the key usage.
   --  @param Item the certificate to inspect
   --  @return the usage; Present is False when the extension is absent
   function Get_Key_Usage (Item : Certificate) return Key_Usage;

   --  Read the extended key usage.
   --  @param Item the certificate to inspect
   --  @return the purposes; Present is False when the extension is absent
   function Get_Extended_Key_Usage
     (Item : Certificate) return Extended_Key_Usage;

   --  How many names does the subject alternative name extension carry?
   --  @param Item the certificate to inspect
   --  @return the number of names, zero when the extension is absent
   function Subject_Alternative_Name_Count (Item : Certificate) return Natural;

   --  What kind of identity is this name?
   --  @param Item the certificate to inspect
   --  @param Index which name, one through Subject_Alternative_Name_Count
   --  @return the name's kind
   function Subject_Alternative_Name_Kind
     (Item : Certificate; Index : Positive) return General_Name_Kind;

   --  A textual subject alternative name.
   --
   --  Meaningful for DNS names, email addresses, and URIs. An IP address is
   --  octets, not text, and comes back empty here: rendering one would invite
   --  a caller to compare addresses as strings, where "10.0.0.1" and
   --  "10.000.000.001" differ and the addresses do not.
   --  @param Item the certificate to inspect
   --  @param Index which name, one through Subject_Alternative_Name_Count
   --  @return the name as text, "" when this name is not textual
   function Subject_Alternative_Name_Text
     (Item : Certificate; Index : Positive) return String;

   --  A subject alternative name's raw octets.
   --
   --  For an IP address these are the four or sixteen address bytes, which is
   --  what an address comparison must use.
   --  @param Item the certificate to inspect
   --  @param Index which name, one through Subject_Alternative_Name_Count
   --  @return the name's octets as encoded
   function Subject_Alternative_Name_Bytes
     (Item : Certificate; Index : Positive) return Octets;

   --  The subject key identifier, if present.
   --  @param Item the certificate to inspect
   --  @return the identifier octets, empty when the extension is absent
   function Subject_Key_Identifier (Item : Certificate) return Octets;

   --  The authority key identifier's keyIdentifier field, if present.
   --  @param Item the certificate to inspect
   --  @return the identifier octets, empty when absent
   function Authority_Key_Identifier (Item : Certificate) return Octets;

   --  Does this certificate carry a critical extension this crate cannot
   --  interpret?
   --
   --  A validator must refuse such a certificate. Marking an extension
   --  critical is the issuer saying that ignoring it changes what the
   --  certificate means, so proceeding without understanding it is proceeding
   --  on a different certificate than the one that was signed.
   --  @param Item the certificate to inspect
   --  @return True when an unrecognised critical extension is present
   function Has_Unsupported_Critical_Extension
     (Item : Certificate) return Boolean;

end CryptoLib.X509.Extensions;
