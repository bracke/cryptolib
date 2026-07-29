with Ada.Streams;
with Ada.Strings.Unbounded;

package CryptoLib.Certificates is
   subtype Unbounded_String is Ada.Strings.Unbounded.Unbounded_String;

   type Certificate_Status is
     (Ok,
      Invalid_Input,
      Unsupported_Profile,
      --  The algorithm is one this crate knows but cannot do on this path:
      --  an RSA CA handed to a path that generates and sizes keys from the
      --  algorithm's name. Distinct from Invalid_Input, which says the caller
      --  passed something wrong, and from Unsupported_Profile, which is about
      --  the profile.
      Unsupported_Key_Algorithm,
      Internal_Error);

   type Subject_Alternative_Name_List is array (Positive range <>) of Unbounded_String;

   --  Which key a certificate carries.
   --
   --  Ed25519 is compact and fast, and no browser will accept it: NSS refuses
   --  even to import such a certificate, so a CA built this way is trusted by
   --  nothing that speaks TLS to a person. P-384 is what a certificate meant
   --  for a browser has to be. The default stays Ed25519 so existing callers
   --  keep what they had; a caller that wants to be trusted asks for P-384.
   --
   --  Ed448 is a larger Edwards curve for a caller who wants one, and it is
   --  accepted by even less than Ed25519 is -- offered because this crate can
   --  verify it and check a key against it, and being unable to issue what it
   --  can verify was the odd part. Nothing about browsers changes here.
   --
   --  P-256 is the curve most TLS certificates in the world actually use, and
   --  it is here for the same reason Ed448 is: this crate could already verify
   --  a P-256 certificate and match a key to one, and not being able to issue
   --  one was the remaining half of that oddity. It is a smaller curve than
   --  P-384, which is the trade a caller makes for the wider deployment.
   --  RSA is last on purpose, so that the algorithms this crate will generate
   --  a key for form a contiguous range and the compiler can enforce it. RSA
   --  can sign a certificate and can be certified; it cannot be generated
   --  here, because an RSA private key is a structure of nine values whose
   --  width depends on a modulus size this enumeration does not carry. Use
   --  CryptoLib.RSA.Generate_Keypair_With_Primes and the RSA encoders below,
   --  then Issue_*_For_Key.
   type Key_Algorithm is
     (Ed25519_Key, P256_Key, P384_Key, Ed448_Key, RSA_Key);

   --  The algorithms this crate generates keys for.
   --
   --  A subtype rather than a runtime check: a path that generates a key takes
   --  this, so handing it RSA does not compile rather than failing at run
   --  time.
   subtype Generatable_Key_Algorithm is
     Key_Algorithm range Ed25519_Key .. Ed448_Key;

   --  How long an issued certificate is valid, in days, counted from the
   --  moment it is issued.
   --
   --  The window used to be a pair of literals in the source, which meant
   --  every certificate this crate ever issued claimed the same ten years
   --  and that issuing would silently start producing already-expired
   --  certificates once that decade ran out. It is computed from the clock
   --  now, and the caller says how long.
   --
   --  The leaf default is the CA/Browser Forum's ceiling for a TLS server
   --  certificate. A long-lived leaf is a long window in which a compromised
   --  key stays usable and nothing forces a rotation; a CA is granted longer
   --  because replacing one means redistributing trust.
   Default_Certificate_Days : constant := 397;
   Default_CA_Days          : constant := 3652;

   --  A certificate issued under a CA is cut short at the CA's own expiry
   --  when the requested window would run past it. Once the CA expires the
   --  chain stops verifying, so the extra time is validity the certificate
   --  states and does not have. Valid_Days is therefore a ceiling and not a
   --  promise; a caller that needs the full window issues under a CA with
   --  at least that long to live.

   --  Render a status as short diagnostic text.
   --  @param Status the status to describe
   --  @return lower-case text naming the status
   function Status_Image (Status : Certificate_Status) return String;

   --  Create a self-signed CA certificate and its private key.
   --  @param Common_Name the CA's subject common name
   --  @param Certificate_PEM receives the CA certificate in PEM form
   --  @param Private_Key_PEM receives the CA private key in PEM form
   --  @param Algorithm the key to issue the CA with; P384_Key for a CA a
   --  browser can be made to trust
   --  @param Valid_Days how long the CA is valid, counted from now
   --  @return Ok on success, otherwise a deterministic failure status
   function Create_Local_CA
     (Common_Name     : String;
      Certificate_PEM : out Unbounded_String;
      Private_Key_PEM : out Unbounded_String;
      Algorithm       : Generatable_Key_Algorithm := Ed25519_Key;
      Valid_Days      : Positive := Default_CA_Days)
      return Certificate_Status;

   --  Issue a server certificate under a CA, with a TLS server profile.
   --  @param CA_Certificate_PEM the issuing CA certificate in PEM form
   --  @param CA_Private_Key_PEM the issuing CA private key in PEM form
   --  @param Common_Name the subject common name
   --  @param Names subject alternative names; DNS names and IP addresses
   --  @param Certificate_PEM receives the issued certificate in PEM form
   --  @param Private_Key_PEM receives the issued private key in PEM form
   --  @param Valid_Days how long the certificate is valid, counted from now
   --  @return Ok on success, otherwise a deterministic failure status
   function Issue_Server_Certificate
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Names              : Subject_Alternative_Name_List;
      Certificate_PEM    : out Unbounded_String;
      Private_Key_PEM    : out Unbounded_String;
      Valid_Days         : Positive := Default_Certificate_Days)
      return Certificate_Status;

   --  Issue a client certificate under a CA, with a TLS client profile.
   --  @param CA_Certificate_PEM the issuing CA certificate in PEM form
   --  @param CA_Private_Key_PEM the issuing CA private key in PEM form
   --  @param Common_Name the subject common name
   --  @param Names subject alternative names; DNS names and IP addresses
   --  @param Certificate_PEM receives the issued certificate in PEM form
   --  @param Private_Key_PEM receives the issued private key in PEM form
   --  @param Valid_Days how long the certificate is valid, counted from now
   --  @return Ok on success, otherwise a deterministic failure status
   function Issue_Client_Certificate
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Names              : Subject_Alternative_Name_List;
      Certificate_PEM    : out Unbounded_String;
      Private_Key_PEM    : out Unbounded_String;
      Valid_Days         : Positive := Default_Certificate_Days)
      return Certificate_Status;

   --  Issue an email certificate under a CA, with an S/MIME profile.
   --  @param CA_Certificate_PEM the issuing CA certificate in PEM form
   --  @param CA_Private_Key_PEM the issuing CA private key in PEM form
   --  @param Common_Name the subject common name
   --  @param Emails subject alternative names; email addresses
   --  @param Certificate_PEM receives the issued certificate in PEM form
   --  @param Private_Key_PEM receives the issued private key in PEM form
   --  @param Valid_Days how long the certificate is valid, counted from now
   --  @return Ok on success, otherwise a deterministic failure status
   function Issue_Email_Certificate
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Emails             : Subject_Alternative_Name_List;
      Certificate_PEM    : out Unbounded_String;
      Private_Key_PEM    : out Unbounded_String;
      Valid_Days         : Positive := Default_Certificate_Days)
      return Certificate_Status;

   --  Sign a certificate signing request under a CA.
   --  @param CA_Certificate_PEM the issuing CA certificate in PEM form
   --  @param CA_Private_Key_PEM the issuing CA private key in PEM form
   --  @param CSR_PEM the certificate signing request in PEM form
   --  @param Certificate_PEM receives the issued certificate in PEM form
   --  @param Valid_Days how long the certificate is valid, counted from now
   --  @return Ok on success, otherwise a deterministic failure status
   function Sign_CSR
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      CSR_PEM            : String;
      Certificate_PEM    : out Unbounded_String;
      Valid_Days         : Positive := Default_Certificate_Days)
      return Certificate_Status;

   --  SubjectPublicKeyInfo for an RSA public key, as a certificate carries it.
   --
   --  What Issue_*_For_Key wants for an RSA subject. The BIT STRING wraps a
   --  SEQUENCE of two integers here, where an Edwards or EC key puts its
   --  point in directly -- which is why an RSA key cannot simply be handed to
   --  the paths that take a fixed-width public key.
   --  @param Modulus         the modulus n, unsigned big-endian
   --  @param Public_Exponent the public exponent e, unsigned big-endian
   --  @return the DER SubjectPublicKeyInfo, or "" if either value is empty
   function RSA_Public_Key_Info
     (Modulus         : Ada.Streams.Stream_Element_Array;
      Public_Exponent : Ada.Streams.Stream_Element_Array) return String;

   --  A PKCS#8 private key file for an RSA key, in PEM.
   --
   --  All nine values RFC 3447 requires, which is what any other
   --  implementation needs to read the key. Pass what
   --  CryptoLib.RSA.Generate_Keypair_With_Primes returned.
   --  @param Modulus          the modulus n
   --  @param Public_Exponent  the public exponent e
   --  @param Private_Exponent the private exponent d
   --  @param Prime_P          the first prime
   --  @param Prime_Q          the second prime
   --  @param Exponent_P       d mod (p-1)
   --  @param Exponent_Q       d mod (q-1)
   --  @param Coefficient      q inverse mod p
   --  @return the PEM private key, or "" if any value is empty
   function RSA_Private_Key_PEM
     (Modulus          : Ada.Streams.Stream_Element_Array;
      Public_Exponent  : Ada.Streams.Stream_Element_Array;
      Private_Exponent : Ada.Streams.Stream_Element_Array;
      Prime_P          : Ada.Streams.Stream_Element_Array;
      Prime_Q          : Ada.Streams.Stream_Element_Array;
      Exponent_P       : Ada.Streams.Stream_Element_Array;
      Exponent_Q       : Ada.Streams.Stream_Element_Array;
      Coefficient      : Ada.Streams.Stream_Element_Array) return String;

   --  Make a self-signed CA certificate for a key the caller already holds.
   --
   --  The counterpart of Create_Local_CA for a key that was not generated
   --  here. This is what an RSA CA needs: Create_Local_CA generates its key
   --  and cannot generate an RSA one, and the Issue_*_For_Key entry points
   --  deliberately refuse the CA profile, so without this a key you hold can
   --  be certified but can never become an issuer.
   --
   --  The certificate is signed by the key it certifies, so the private key
   --  must be the one whose public half goes in. Nothing is returned but the
   --  certificate: the caller already has the key.
   --  @param Common_Name        the CA's common name, used as issuer and
   --    subject
   --  @param CA_Private_Key_PEM the key to certify and sign with, PEM
   --  @param Certificate_PEM    receives the CA certificate in PEM form
   --  @param Valid_Days         how long the CA is valid, counted from now
   --  @return Ok on success, otherwise a deterministic failure status
   function Create_CA_For_Key
     (Common_Name        : String;
      CA_Private_Key_PEM : String;
      Certificate_PEM    : out Unbounded_String;
      Valid_Days         : Positive := Default_CA_Days)
      return Certificate_Status;

   --  Issue a certificate for a public key the caller already holds.
   --
   --  No key is generated and none is returned: the caller has the private
   --  half already. This is how an RSA certificate is issued, and it is also
   --  the way to certify a key this crate cannot generate at all -- one held
   --  in a token, or made by something else.
   --
   --  Subject_SPKI is the subject's SubjectPublicKeyInfo in DER, which is what
   --  RSA_Public_Key_Info returns for an RSA key and what a CSR carries for
   --  any other. It is passed through as given: whether it is a key this crate
   --  could have produced is not asked, and no proof that the caller holds the
   --  private half is required either. Sign_CSR is the entry point that
   --  demands that proof; this one certifies what it is told to.
   --  @param CA_Certificate_PEM the issuing CA certificate in PEM form
   --  @param CA_Private_Key_PEM the issuing CA private key in PEM form
   --  @param Common_Name        the subject common name
   --  @param Names              subject alternative names
   --  @param Subject_SPKI       the subject's SubjectPublicKeyInfo, DER
   --  @param Certificate_PEM    receives the issued certificate in PEM form
   --  @param Valid_Days         how long the certificate is valid, from now
   --  @return Ok on success, otherwise a deterministic failure status
   function Issue_Server_Certificate_For_Key
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Names              : Subject_Alternative_Name_List;
      Subject_SPKI       : Ada.Streams.Stream_Element_Array;
      Certificate_PEM    : out Unbounded_String;
      Valid_Days         : Positive := Default_Certificate_Days)
      return Certificate_Status;

   --  As Issue_Server_Certificate_For_Key, with the TLS client profile.
   --  @param CA_Certificate_PEM the issuing CA certificate in PEM form
   --  @param CA_Private_Key_PEM the issuing CA private key in PEM form
   --  @param Common_Name        the subject common name
   --  @param Names              subject alternative names
   --  @param Subject_SPKI       the subject's SubjectPublicKeyInfo, DER
   --  @param Certificate_PEM    receives the issued certificate in PEM form
   --  @param Valid_Days         how long the certificate is valid, from now
   --  @return Ok on success, otherwise a deterministic failure status
   function Issue_Client_Certificate_For_Key
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Names              : Subject_Alternative_Name_List;
      Subject_SPKI       : Ada.Streams.Stream_Element_Array;
      Certificate_PEM    : out Unbounded_String;
      Valid_Days         : Positive := Default_Certificate_Days)
      return Certificate_Status;

   --  As Issue_Server_Certificate_For_Key, with the email profile.
   --  @param CA_Certificate_PEM the issuing CA certificate in PEM form
   --  @param CA_Private_Key_PEM the issuing CA private key in PEM form
   --  @param Common_Name        the subject common name
   --  @param Names              subject alternative names
   --  @param Subject_SPKI       the subject's SubjectPublicKeyInfo, DER
   --  @param Certificate_PEM    receives the issued certificate in PEM form
   --  @param Valid_Days         how long the certificate is valid, from now
   --  @return Ok on success, otherwise a deterministic failure status
   function Issue_Email_Certificate_For_Key
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Names              : Subject_Alternative_Name_List;
      Subject_SPKI       : Ada.Streams.Stream_Element_Array;
      Certificate_PEM    : out Unbounded_String;
      Valid_Days         : Positive := Default_Certificate_Days)
      return Certificate_Status;

   --  Is this a DNS name, an IP address, an email address that may stand as a
   --  subject alternative name?
   --
   --  Here because this decides what a certificate may contain, and because a
   --  caller that validates for itself ends up with rules that disagree with
   --  these: it accepts an identity that then cannot be encoded, or refuses one
   --  that could have been. The encoders below answer the same question by
   --  succeeding or failing; these answer it before anything is built, so a
   --  caller can say which identity was wrong and why.
   --  @param Text the candidate DNS name
   --  @return True when Text may stand as a DNS subject alternative name
   function Valid_DNS_Name (Text : String) return Boolean;

   --  See Valid_DNS_Name.
   --  @param Text the candidate IP address
   --  @return True when Text may stand as an IP subject alternative name
   function Valid_IP_Address (Text : String) return Boolean;

   --  See Valid_DNS_Name.
   --  @param Text the candidate email address
   --  @return True when Text may stand as an email subject alternative name
   function Valid_Email_Address (Text : String) return Boolean;

   --  The certificate's SHA-256 fingerprint, lower-case hex in colon-separated
   --  pairs.
   --
   --  Over the certificate, which means over its DER: that is the value every
   --  other reader shows -- openssl, a browser's certificate manager, keytool
   --  -- and the only one a person can compare with. Hashing the armoured text
   --  instead gives a number that matches nothing, and that changes when the
   --  same certificate is re-wrapped.
   --  @param Certificate_PEM the certificate in PEM form
   --  @return "" when the text carries no certificate
   function Fingerprint (Certificate_PEM : String) return String;

   --  The same certificate's SHA-1 fingerprint, as plain lowercase hex.
   --
   --  Not an identity to prefer -- SHA-1 is not one to rely on for that -- but
   --  the one some stores index by, and a store that will only be told which
   --  certificate to remove in the hash it keeps has to be told in that hash.
   --  Windows is the case in hand: certutil matches "Cert Hash(sha1)", and
   --  handed a SHA-256 it exits zero having deleted nothing.
   --
   --  @param Certificate_PEM the certificate in PEM form
   --  @return "" when the text carries no certificate
   function SHA1_Fingerprint (Certificate_PEM : String) return String;

   --  Do these two PEM texts carry the same certificate?
   --
   --  Comparing the text does not answer it: the same certificate may be
   --  wrapped at a different width, carry different line endings, or be armoured
   --  with a different label. This compares what the armour holds.
   --  @param Left one PEM text
   --  @param Right the other PEM text
   --  @return True when both carry the same certificate
   function Same_Certificate (Left : String; Right : String) return Boolean;

   --  Does this PEM text carry a certificate?
   --
   --  Asked of the armour, which is what says which of the two a file is.
   --  @param Text the PEM text to inspect
   --  @return True when Text carries a certificate
   function Contains_Certificate (Text : String) return Boolean;

   --  Does this PEM text carry a private key?
   --  @param Text the PEM text to inspect
   --  @return True when Text carries a private key
   function Contains_Private_Key (Text : String) return Boolean;

   --  Does this private key belong to this certificate?
   --  @param Certificate_PEM the certificate in PEM form
   --  @param Private_Key_PEM the private key in PEM form
   --  @return Ok when the key matches, otherwise a deterministic failure status
   function Private_Key_Matches_Certificate
     (Certificate_PEM : String;
      Private_Key_PEM : String) return Certificate_Status;

   --  Bundle a certificate and its private key as PKCS#12.
   --  @param Certificate_PEM the certificate in PEM form
   --  @param Private_Key_PEM the private key in PEM form
   --  @param Friendly_Name the bundle's friendly name
   --  @param Password the password protecting the bundle
   --  @param Bundle_Data receives the PKCS#12 bundle
   --  @return Ok on success, otherwise a deterministic failure status
   --  How much work a password has to be put through to open a bundle.
   --
   --  A PKCS#12 file holds a private key, so a copy of it is an offline
   --  guessing target: the only thing between a weak password and the key is
   --  the cost of trying one. The old value was 2048, which is what
   --  `openssl pkcs12 -export` still writes and roughly three hundred times
   --  cheaper to attack than current guidance for PBKDF2-HMAC-SHA256.
   --
   --  It applies to the bundle's MAC as well as to its encryption, and that
   --  is not a detail: both derive from the password, so an attacker tests
   --  guesses against whichever is cheaper. Raising one and leaving the
   --  other is worth nothing at all.
   Default_PKCS12_Iterations : constant := 600_000;

   --  A floor, enforced where lowering it cannot be missed. A test could
   --  only say the constant is what it is, which the compiler already knows;
   --  this makes weakening the default fail the build instead.
   pragma Compile_Time_Error
     (Default_PKCS12_Iterations < 200_000,
      "the default PKCS#12 work factor must not be lowered: a bundle holds "
      & "a private key, and the count is what an offline guess costs");

   --  Write a PKCS#12 bundle holding a certificate and its private key.
   --  @param Certificate_PEM the certificate in PEM form
   --  @param Private_Key_PEM its private key in PEM form
   --  @param Friendly_Name the name to label the bundle's entries with
   --  @param Password the password protecting the bundle
   --  @param Bundle_Data receives the bundle
   --  @param Iterations how much work opening it costs; lower only where
   --  something other than the password's protection is being exercised
   --  @return Ok on success, otherwise a deterministic failure status
   function Generate_PKCS12
     (Certificate_PEM : String;
      Private_Key_PEM : String;
      Friendly_Name   : String;
      Password        : String;
      Bundle_Data     : out Unbounded_String;
      Iterations      : Positive := Default_PKCS12_Iterations)
      return Certificate_Status;
end CryptoLib.Certificates;
