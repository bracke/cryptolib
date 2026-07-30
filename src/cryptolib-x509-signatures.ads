with CryptoLib.ASN1;
with CryptoLib.RSA;
with CryptoLib.X509.Certificates;

--  @summary Checking that one certificate was signed by another's key.
--
--  This answers one question and refuses to imply any other. A Valid result
--  means the signature on the certificate is that issuer key's over that
--  certificate's signed bytes. It does not mean the issuer is trusted, that
--  the issuer is allowed to be a CA, that either certificate is current, that
--  the names line up, or that a chain built from them is valid. Every one of
--  those is a separate check with a separate answer.
--
--  The distinction is worth the awkwardness. A verifier that returned one
--  encouraging word for "the maths worked" is a verifier callers will read as
--  "this certificate is fine", and the gap between those two readings is
--  where trust bugs live.
package CryptoLib.X509.Signatures is

   --  No parameters, for the algorithms that carry none.
   Empty_Parameters : constant CryptoLib.ASN1.Octets (1 .. 0) :=
     [others => 0];

   type Verification_Result is
     (Valid,
      --  The signature is the issuer key's over the certificate's signed
      --  bytes. Nothing more than that.
      Invalid_Signature,
      --  The signature is well formed and does not verify. The certificate
      --  was not signed by this key, or has been altered since it was.
      Algorithm_Mismatch,
      --  The certificate's signature algorithm and the issuer's key type
      --  cannot go together -- an ECDSA signature under an Ed25519 key.
      --  Distinct from a bad signature: nothing was verified.
      Unsupported_Algorithm,
      --  A signature algorithm this crate cannot verify. Also not a bad
      --  signature. The certificate may be perfectly good; this cannot say.
      --  RSA PKCS#1 v1.5, RSA-PSS and ECDSA on P-256, P-384 and P-521 are
      --  all verified and do not land here. What still does: anything under
      --  SHA-1, and RSA-PSS whose parameters name a hash this crate does
      --  not implement -- the parameters are read, so the refusal is on
      --  what they say rather than on failing to read them.
      Malformed_Signature,
      --  The signature is not shaped like one for its algorithm: an ECDSA
      --  signature that is not a SEQUENCE of two integers, a component wider
      --  than the curve.
      Missing_Input);
      --  A certificate that did not decode was handed in.

   --  Render a verification result as short diagnostic text.
   --  @param Result the result to describe
   --  @return lower-case text naming the result
   function Result_Image (Result : Verification_Result) return String;

   --  Is this certificate's signature the issuer key's?
   --
   --  Uses the certificate's signed bytes exactly as they were decoded, not a
   --  re-encoding of the fields.
   --  @param Item the certificate whose signature is in question
   --  @param Issuer the certificate whose public key is proposed as signer
   --  @return Valid only when the signature verifies; see the type for what
   --  the other results mean and for what Valid does not mean
   function Verify_Certificate_Signature
     (Item   : CryptoLib.X509.Certificates.Certificate;
      Issuer : CryptoLib.X509.Certificates.Certificate)
      return Verification_Result;

   --  Is this signature over these bytes the issuer key's?
   --
   --  The primitive behind Verify_Certificate_Signature, exposed because a
   --  certificate is not the only thing an issuer signs: a CRL is signed the
   --  same way over its own body. Sharing this means the algorithm dispatch,
   --  the key checks and the ECDSA signature decoding cannot be right for one
   --  and wrong for the other.
   --  @param Signed the exact bytes that were signed
   --  @param Signature the signature value, without its BIT STRING wrapper
   --  @param Algorithm the algorithm the signature claims to be
   --  @param Issuer the certificate whose public key is proposed as signer
   --  @param Parameters the algorithm's own parameters, where it has them
   --  @return Valid only when the signature verifies; see the type for what
   --  the other results mean
   function Verify_Signed_Data
     (Signed    : CryptoLib.ASN1.Octets;
      Signature : CryptoLib.ASN1.Octets;
      Algorithm : Signature_Algorithm;
      Issuer    : CryptoLib.X509.Certificates.Certificate;
      Parameters : CryptoLib.ASN1.Octets := Empty_Parameters)
      return Verification_Result;

   --  Is this signature over these bytes that public key's?
   --
   --  Below Verify_Signed_Data, which finds the key in a certificate. A
   --  certification request is signed by the key inside it rather than by an
   --  issuer's, so there is no certificate to take the key from and this is
   --  what such a check needs.
   --  @param Signed the exact bytes that were signed
   --  @param Signature the signature value, without its BIT STRING wrapper
   --  @param Algorithm the algorithm the signature claims to be
   --  @param Key_Kind what kind of key Public_Key is
   --  @param Public_Key the key itself, as a SubjectPublicKeyInfo carries it
   --  @return Valid only when the signature verifies
   --  @param Parameters the algorithm's own parameters, for the algorithms
   --  that have them; RSASSA-PSS states its hash and salt length there and
   --  cannot be checked without them
   function Verify_With_Key
     (Signed     : CryptoLib.ASN1.Octets;
      Signature  : CryptoLib.ASN1.Octets;
      Algorithm  : Signature_Algorithm;
      Key_Kind   : Public_Key_Algorithm;
      Public_Key : CryptoLib.ASN1.Octets;
      Parameters : CryptoLib.ASN1.Octets := Empty_Parameters)
      return Verification_Result;

   --  Which hash an RSASSA-PSS signature was made with. Re-exported so a
   --  caller can name one without depending on CryptoLib.RSA directly.
   subtype PSS_Hash is CryptoLib.RSA.Hash_Algorithm;

   --  The digest length of a PSS hash, in octets: 32, 48 or 64.
   --
   --  Offered because the salt length below is a number a caller would
   --  otherwise write as a literal, and a wrong literal is a signature that
   --  verifies against the wrong thing.
   --  @param Hash which hash
   --  @return that hash's digest length in octets
   function Digest_Length (Hash : PSS_Hash) return Natural;

   --  Verify an RSASSA-PSS signature whose parameters the protocol fixes
   --  rather than carrying.
   --
   --  Verify_With_Key reads the hash and salt length out of a DER
   --  RSASSA-PSS-params, which is where a *certificate* keeps them. Several
   --  protocols do not keep them anywhere: TLS 1.3 fixes them per signature
   --  scheme in RFC 8446 section 4.2.3 -- MGF1 with the same hash, and a salt
   --  length equal to the digest length -- so a CertificateVerify carries a
   --  signature and no AlgorithmIdentifier at all.
   --
   --  Without this entry point such a caller has to encode an
   --  AlgorithmIdentifier purely so that this package can parse it straight
   --  back out, which is what SSL.Crypto was doing with three constant DER
   --  blobs. The parameters are arguments here instead.
   --
   --  For TLS 1.3 pass Salt_Length => Digest_Length (Hash).
   --  @param Signed      the bytes the signature covers
   --  @param Signature   the signature octets
   --  @param Hash        which digest, for both the message and MGF1
   --  @param Salt_Length the salt length in octets
   --  @param Public_Key  the signer's SubjectPublicKeyInfo
   --  @return Valid, Invalid_Signature when it does not verify,
   --    Malformed_Signature when the key or signature cannot be read
   function Verify_PSS_With_Key
     (Signed      : CryptoLib.ASN1.Octets;
      Signature   : CryptoLib.ASN1.Octets;
      Hash        : PSS_Hash;
      Salt_Length : Natural;
      Public_Key  : CryptoLib.ASN1.Octets)
      return Verification_Result;

   --  Can this crate verify signatures of this algorithm at all?
   --
   --  Offered so that a caller can tell "we did not check" from "we checked
   --  and it failed" before it starts, rather than inferring it from a
   --  result.
   --  @param Algorithm the signature algorithm in question
   --  @return True when Verify_Certificate_Signature can decide it
   function Is_Supported (Algorithm : Signature_Algorithm) return Boolean;

   --  How big the modulus of an RSA public key is.
   --
   --  RSA is the one key algorithm here whose strength is not fixed by which
   --  algorithm it is: the curves are named and Ed25519 is one size, but an
   --  RSA key is as strong as its modulus and a certificate may carry any
   --  size at all. A caller that wants to refuse a weak one has to be able
   --  to ask how weak it is.
   --
   --  The count is of significant bits, so it does not depend on whether the
   --  encoding carries a leading zero to keep the INTEGER positive.
   --  @param Key the subjectPublicKey bits of an RSA key
   --  @return the modulus size in bits, or zero if this is not an RSA key
   --    that parses
   function RSA_Modulus_Bits
     (Key : CryptoLib.ASN1.Octets) return Natural;

end CryptoLib.X509.Signatures;
