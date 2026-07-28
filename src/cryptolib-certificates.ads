with Ada.Strings.Unbounded;

package CryptoLib.Certificates is
   subtype Unbounded_String is Ada.Strings.Unbounded.Unbounded_String;

   type Certificate_Status is
     (Ok,
      Invalid_Input,
      Unsupported_Profile,
      Internal_Error);

   type Subject_Alternative_Name_List is array (Positive range <>) of Unbounded_String;

   --  Which key a certificate carries.
   --
   --  Ed25519 is compact and fast, and no browser will accept it: NSS refuses
   --  even to import such a certificate, so a CA built this way is trusted by
   --  nothing that speaks TLS to a person. P-384 is what a certificate meant
   --  for a browser has to be. The default stays Ed25519 so existing callers
   --  keep what they had; a caller that wants to be trusted asks for P-384.
   type Key_Algorithm is (Ed25519_Key, P384_Key);

   function Status_Image (Status : Certificate_Status) return String;

   function Create_Local_CA
     (Common_Name     : String;
      Certificate_PEM : out Unbounded_String;
      Private_Key_PEM : out Unbounded_String;
      Algorithm       : Key_Algorithm := Ed25519_Key) return Certificate_Status;

   function Issue_Server_Certificate
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Names              : Subject_Alternative_Name_List;
      Certificate_PEM    : out Unbounded_String;
      Private_Key_PEM    : out Unbounded_String) return Certificate_Status;

   function Issue_Client_Certificate
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Names              : Subject_Alternative_Name_List;
      Certificate_PEM    : out Unbounded_String;
      Private_Key_PEM    : out Unbounded_String) return Certificate_Status;

   function Issue_Email_Certificate
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Emails             : Subject_Alternative_Name_List;
      Certificate_PEM    : out Unbounded_String;
      Private_Key_PEM    : out Unbounded_String) return Certificate_Status;

   function Sign_CSR
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      CSR_PEM            : String;
      Certificate_PEM    : out Unbounded_String) return Certificate_Status;

   --  Is this a DNS name, an IP address, an email address that may stand as a
   --  subject alternative name?
   --
   --  Here because this decides what a certificate may contain, and because a
   --  caller that validates for itself ends up with rules that disagree with
   --  these: it accepts an identity that then cannot be encoded, or refuses one
   --  that could have been. The encoders below answer the same question by
   --  succeeding or failing; these answer it before anything is built, so a
   --  caller can say which identity was wrong and why.
   function Valid_DNS_Name (Text : String) return Boolean;
   function Valid_IP_Address (Text : String) return Boolean;
   function Valid_Email_Address (Text : String) return Boolean;

   --  The certificate's SHA-256 fingerprint, lower-case hex in colon-separated
   --  pairs.
   --
   --  Over the certificate, which means over its DER: that is the value every
   --  other reader shows -- openssl, a browser's certificate manager, keytool
   --  -- and the only one a person can compare with. Hashing the armoured text
   --  instead gives a number that matches nothing, and that changes when the
   --  same certificate is re-wrapped.
   --  @return "" when the text carries no certificate
   function Fingerprint (Certificate_PEM : String) return String;

   --  Do these two PEM texts carry the same certificate?
   --
   --  Comparing the text does not answer it: the same certificate may be
   --  wrapped at a different width, carry different line endings, or be armoured
   --  with a different label. This compares what the armour holds.
   function Same_Certificate (Left : String; Right : String) return Boolean;

   --  Does this PEM text carry a certificate, or a private key?
   --
   --  Asked of the armour, which is what says which of the two a file is.
   function Contains_Certificate (Text : String) return Boolean;
   function Contains_Private_Key (Text : String) return Boolean;

   function Private_Key_Matches_Certificate
     (Certificate_PEM : String;
      Private_Key_PEM : String) return Certificate_Status;

   function Generate_PKCS12
     (Certificate_PEM : String;
      Private_Key_PEM : String;
      Friendly_Name   : String;
      Password        : String;
      Bundle_Data     : out Unbounded_String) return Certificate_Status;
end CryptoLib.Certificates;
