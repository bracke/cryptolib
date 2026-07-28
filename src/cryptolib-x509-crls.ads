with CryptoLib.ASN1;
with CryptoLib.ASN1.Errors;
with CryptoLib.X509.Certificates;
with CryptoLib.X509.Signatures;

--  @summary Reading and checking a certificate revocation list.
--
--  A CRL is a signed statement by an issuer that certain serial numbers it
--  issued are no longer to be trusted. This decodes one, checks that the
--  issuer really signed it, and answers whether a serial is on it.
--
--  Nothing here fetches anything. A CRL arrives from a file, a distribution
--  point the application chose to visit, or a protocol that carried it;
--  deciding to go and get one is a networking and policy question, and a
--  crypto library that opened sockets to answer it would be answering a
--  question nobody asked it.
--
--  The revoked list is not held in memory as a list. A CRL can carry hundreds
--  of thousands of entries, so an array of them would put a bound on what
--  could be read, and the bound would be the wrong one for somebody. The
--  encoding is walked on demand instead: Is_Revoked costs a pass over the
--  entries and nothing else costs anything.
package CryptoLib.X509.CRLs is

   subtype Decode_Status is CryptoLib.ASN1.Errors.Decode_Status;
   subtype Decode_Limits is CryptoLib.ASN1.Decode_Limits;
   subtype Certificate is CryptoLib.X509.Certificates.Certificate;

   type Revocation_List (Length : Offset) is private;

   --  Decode a CRL from DER.
   --  @param Data the DER encoding
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Status Ok on success, otherwise why the input was refused
   --  @return the decoded list, or an empty one on failure
   function Decode_DER
     (Data   : Octets;
      Limits : Decode_Limits;
      Status : out Decode_Status) return Revocation_List;

   --  Did this decode?
   --  @param Item the list to inspect
   --  @return True when the list holds a decoded encoding
   function Is_Present (Item : Revocation_List) return Boolean;

   --  The issuer name, as encoded.
   --
   --  Compare this against a candidate issuer's Subject_Bytes to decide
   --  whether the CRL is even about that issuer's certificates. A CRL signed
   --  by a key you trust but issued by somebody else says nothing about your
   --  certificates.
   --  @param Item the list to inspect
   --  @return the issuer's DER encoding, header included
   function Issuer_Bytes (Item : Revocation_List) return Octets;

   --  When the list was issued.
   --  @param Item the list to inspect
   --  @return the thisUpdate time
   function This_Update (Item : Revocation_List) return Certificate_Time;

   --  When the next list is due, if the CRL says.
   --
   --  Optional in the encoding. A CRL without it does not expire on its own
   --  terms, which is not the same as being fresh forever; what to do about
   --  that is the caller's policy.
   --  @param Item the list to inspect
   --  @return True when a nextUpdate is present
   function Has_Next_Update (Item : Revocation_List) return Boolean;

   --  See Has_Next_Update.
   --  @param Item the list to inspect
   --  @return the nextUpdate time, meaningless when absent
   function Next_Update (Item : Revocation_List) return Certificate_Time;

   --  The exact bytes the signature was computed over.
   --  @param Item the list to inspect
   --  @return the signed TBSCertList DER, header included
   function TBS_Bytes (Item : Revocation_List) return Octets;

   --  Is this serial number on the list?
   --
   --  Serial is the serial number's content octets, as
   --  CryptoLib.X509.Certificates.Serial_Number gives them. Compared as
   --  bytes after leading zeros are dropped from both, so that a serial
   --  written with a sign-preserving leading zero matches one written
   --  without: they are the same number, and a revocation missed on that
   --  account is a revoked certificate treated as good.
   --  @param Item the list to inspect
   --  @param Serial the serial number to look for
   --  @return True when the list revokes it
   function Is_Revoked
     (Item : Revocation_List; Serial : Octets) return Boolean;

   --  Look a serial up and report when it was revoked, and why.
   --
   --  Serial is matched as Is_Revoked matches it. Present is False when the
   --  serial is not on the list, in which case the other fields say nothing.
   --  @param Item the list to inspect
   --  @param Serial the serial number to look for
   --  @return what the entry says, or a record with Present False
   function Find_Revocation
     (Item : Revocation_List; Serial : Octets) return Revocation_Details;

   --  How many entries does the list carry?
   --
   --  Costs a walk of the entries; there is no stored count.
   --  @param Item the list to inspect
   --  @return the number of revoked entries
   function Entry_Count (Item : Revocation_List) return Natural;

   --  Is this CRL the one this issuer signed?
   --
   --  Answers only that. It does not check that the issuer is trusted, that
   --  the CRL is current, or that it covers the certificate you care about.
   --  @param Item the list to check
   --  @param Issuer the certificate whose key is proposed as signer
   --  @return Valid only when the signature verifies
   function Verify_Signature
     (Item   : Revocation_List;
      Issuer : Certificate)
      return CryptoLib.X509.Signatures.Verification_Result;

private

   type Span is record
      First : Offset := 1;
      Last  : Offset := 0;
   end record;

   type Revocation_List (Length : Offset) is record
      Present     : Boolean := False;
      Version     : Natural := 1;
      Issuer      : Span;
      TBS         : Span;
      Signature   : Span;
      Revoked     : Span;
      Has_Revoked : Boolean := False;
      Issued      : Certificate_Time;
      Due         : Certificate_Time;
      Due_Present : Boolean := False;
      Algorithm   : Signature_Algorithm := Unknown_Signature_Algorithm;
      DER         : Octets (1 .. Length) := [others => 0];
   end record;

end CryptoLib.X509.CRLs;
