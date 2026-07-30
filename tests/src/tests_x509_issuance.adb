with Ada.Streams;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Interfaces;
with System;
with CryptoLib.ASN1;
with CryptoLib.PEM;
with CryptoLib.X509;
with CryptoLib.X509.Certificates;
with CryptoLib.X509.Extensions;
with CryptoLib.X509.Identity;
with CryptoLib.X509.Purposes;
with CryptoLib.X509.Names;
with Ada.Directories;
with Ada.Streams.Stream_IO;
with CryptoLib.X509.CRLs;
with CryptoLib.X509.Revocation;
with CryptoLib.OCSP;
with CryptoLib.PKCS10;
with CryptoLib.PKCS8;
with CryptoLib.PKCS12;
with CryptoLib.Identities;
with CryptoLib.X509.Policies;
with CryptoLib.HKDF;
with CryptoLib.TLS13_KDF;
with CryptoLib.ECDH;
with CryptoLib.Constant_Time_Proof;
with CryptoLib.Constant_Time_Assurance;
with CryptoLib.MLKEM768_Core;
with CryptoLib.EC_Curves;
with CryptoLib.Hybrid_PQ_Kex;
with CryptoLib.Fingerprints;
with CryptoLib.Constant_Time;
with CryptoLib.BCrypt_PBKDF;
with CryptoLib.X509.Times;
with CryptoLib.X509.Validation;
with CryptoLib.X509.Path_Building;
with CryptoLib.X509.Name_Constraints;
with CryptoLib.X509.Signatures;
with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.Errors;
with CryptoLib.ASN1.OIDs;
with CryptoLib.ChaCha20_Poly1305;
with CryptoLib.Certificates;
with OpenSSL_Interop;
with CryptoLib.Checksums;
with CryptoLib.Secure_Wipe;
with CryptoLib.Hashes;
with CryptoLib.Ciphers;
with CryptoLib.ECDSA;
with CryptoLib.Errors;
with CryptoLib.Macs;
with CryptoLib.UMAC;
with CryptoLib.MLKEM768;
with CryptoLib.SNTRUP761;
with CryptoLib.Curve25519;
with CryptoLib.Ed25519;
with CryptoLib.Ed448;
with CryptoLib.SHA3;
with CryptoLib.Buffers;
with CryptoLib.Diffie_Hellman;
with CryptoLib.Modexp;
with CryptoLib.Bignum;
with CryptoLib.Random;
with CryptoLib.RSA;
with Tests_Support; use Tests_Support;

package body Tests_X509_Issuance is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Certificates.Certificate_Status;
   use type Interfaces.Unsigned_32;

   procedure Check_Certificates is
      CA_Cert   : Ada.Strings.Unbounded.Unbounded_String;
      CA_Key    : Ada.Strings.Unbounded.Unbounded_String;
      Leaf_Cert : Ada.Strings.Unbounded.Unbounded_String;
      Leaf_Key  : Ada.Strings.Unbounded.Unbounded_String;
      CSR_Cert  : Ada.Strings.Unbounded.Unbounded_String;
      Bundle    : Ada.Strings.Unbounded.Unbounded_String;
      Client_Cert : Ada.Strings.Unbounded.Unbounded_String;
      Client_Key  : Ada.Strings.Unbounded.Unbounded_String;
      Email_Cert  : Ada.Strings.Unbounded.Unbounded_String;
      Email_Key   : Ada.Strings.Unbounded.Unbounded_String;
      Other_CA_Cert : Ada.Strings.Unbounded.Unbounded_String;
      Other_CA_Key  : Ada.Strings.Unbounded.Unbounded_String;
   begin
      Check
        (CryptoLib.Certificates.Create_Local_CA
           ("devcert-test-ca", CA_Cert, CA_Key) = CryptoLib.Certificates.Ok,
         "local CA creation succeeds");

      --  The issuer name has to come from the CA certificate, or the leaf
      --  cannot be chained to it: it was once a fixed string, so any CA not
      --  named that produced certificates no verifier would accept. Issuing
      --  without a readable CA certificate must fail rather than sign with a
      --  name of its own choosing.
      declare
         Orphan_Cert : Ada.Strings.Unbounded.Unbounded_String;
         Orphan_Key  : Ada.Strings.Unbounded.Unbounded_String;
      begin
         Check
           (CryptoLib.Certificates.Issue_Server_Certificate
              ("",
               Ada.Strings.Unbounded.To_String (CA_Key),
               "orphan.example",
               [1 => Ada.Strings.Unbounded.To_Unbounded_String
                       ("orphan.example")],
               Orphan_Cert, Orphan_Key)
            = CryptoLib.Certificates.Invalid_Input,
            "issuing without a CA certificate is refused");
         Check
           (CryptoLib.Certificates.Sign_CSR
              ("",
               Ada.Strings.Unbounded.To_String (CA_Key),
               "not a csr", Orphan_Cert)
            = CryptoLib.Certificates.Invalid_Input,
            "signing a CSR without a CA certificate is refused");
      end;

      --  Ask OpenSSL whether anybody else would accept what we issued. The CA
      --  names here are deliberately not the string the issuer field once
      --  carried: a leaf naming the wrong issuer parses perfectly and fails
      --  only when a verifier tries to build the chain.
      declare
         use type CryptoLib.Certificates.Key_Algorithm;

         procedure Check_Chain
           (Algorithm : CryptoLib.Certificates.Generatable_Key_Algorithm)
         is
            Label   : constant String :=
              (case Algorithm is
                  when CryptoLib.Certificates.P256_Key    => "p256",
                  when CryptoLib.Certificates.P384_Key    => "p384",
                  when CryptoLib.Certificates.Ed448_Key   => "ed448",
                  when CryptoLib.Certificates.Ed25519_Key => "ed25519");
            Root    : Ada.Strings.Unbounded.Unbounded_String;
            Root_Key : Ada.Strings.Unbounded.Unbounded_String;
            Leaf    : Ada.Strings.Unbounded.Unbounded_String;
            Leaf_K  : Ada.Strings.Unbounded.Unbounded_String;
         begin
            Check
              (CryptoLib.Certificates.Create_Local_CA
                 ("cryptolib-chain-check-" & Label, Root, Root_Key, Algorithm)
               = CryptoLib.Certificates.Ok,
               Label & " chain-check CA creation succeeds");
            Check
              (CryptoLib.Certificates.Issue_Server_Certificate
                 (Ada.Strings.Unbounded.To_String (Root),
                  Ada.Strings.Unbounded.To_String (Root_Key),
                  "chain.example",
                  [1 => Ada.Strings.Unbounded.To_Unbounded_String
                          ("chain.example")],
                  Leaf, Leaf_K)
               = CryptoLib.Certificates.Ok,
               Label & " chain-check leaf issuance succeeds");
            Check
              (OpenSSL_Interop.Chain_Verifies
                 (Ada.Strings.Unbounded.To_String (Root),
                  Ada.Strings.Unbounded.To_String (Leaf)),
               Label & " issued certificate verifies against its CA in OpenSSL");

            --  The key that comes back with it is the leaf's own. Issuing a
            --  certificate and a key that do not go together would be caught
            --  by nothing else here: both halves look well formed alone.
            Check
              (CryptoLib.Certificates.Private_Key_Matches_Certificate
                 (Ada.Strings.Unbounded.To_String (Leaf),
                  Ada.Strings.Unbounded.To_String (Leaf_K))
               = CryptoLib.Certificates.Ok,
               Label & " issued key belongs to the certificate issued with it");
         end Check_Chain;
      begin
         --  An RSA *CA*, signing a chain. The CA key is generated by
         --  CryptoLib.RSA, written as PKCS#8 by RSA_Private_Key_PEM, and
         --  handed back in as a CA -- so the whole loop closes: this crate
         --  makes the key, writes it, reads it, and signs with it.
         --
         --  Nothing here is sized from the algorithm's name. The CA's private
         --  exponent is 256 octets where an Ed25519 seed is 32, and the only
         --  way to know which is to have parsed the key.
         declare
            Rng : CryptoLib.Random.Random_Source;
            N   : Ada.Streams.Stream_Element_Array (1 .. 256);
            E   : Ada.Streams.Stream_Element_Array (1 .. 3);
            D   : Ada.Streams.Stream_Element_Array (1 .. 256);
            P, Q, DP, DQ, QI : Ada.Streams.Stream_Element_Array (1 .. 128);
            Root, Root_Key, Leaf, Leaf_Key : Ada.Strings.Unbounded.Unbounded_String;
         begin
            CryptoLib.Random.Initialize_Production (Rng);
            Check (CryptoLib.RSA.Generate_Keypair_With_Primes
                     (CryptoLib.RSA.RSA_2048, Rng, N, E, D, P, Q, DP, DQ, QI)
                     = CryptoLib.Errors.Ok,
                   "an RSA CA key is generated");

            --  A self-signed RSA CA, issued for its own key.
            declare
               CA_Key : constant String :=
                 CryptoLib.Certificates.RSA_Private_Key_PEM
                   (N, E, D, P, Q, DP, DQ, QI);
            begin
               Check (CA_Key /= "", "and written as a PKCS#8 key file");
               --  A self-signed CA certificate for the key. A server
               --  certificate would not do: without basicConstraints saying CA,
               --  OpenSSL refuses to build a chain through it, which is how
               --  the first version of this test failed.
               Check (CryptoLib.Certificates.Create_CA_For_Key
                        ("cryptolib-rsa-ca", CA_Key, Root)
                        = CryptoLib.Certificates.Ok,
                      "the RSA key becomes a CA");
               Root_Key := Ada.Strings.Unbounded.To_Unbounded_String (CA_Key);
            end;

            --  A 4096-bit CA key fits the slot; the ceiling is what stops a
            --  wider one being truncated into a key that signs and produces
            --  signatures nothing verifies. Checked here because Max_CA_Private
            --  is a constant that has to be right, and a truncating Place
            --  would be silent.
            declare
               Big_N  : Ada.Streams.Stream_Element_Array (1 .. 512);
               Big_E  : Ada.Streams.Stream_Element_Array (1 .. 3);
               Big_D  : Ada.Streams.Stream_Element_Array (1 .. 512);
               Big_P, Big_Q, Big_DP, Big_DQ, Big_QI :
                 Ada.Streams.Stream_Element_Array (1 .. 256);
               Big_CA : Ada.Strings.Unbounded.Unbounded_String;
            begin
               Check (CryptoLib.RSA.Generate_Keypair_With_Primes
                        (CryptoLib.RSA.RSA_4096, Rng, Big_N, Big_E, Big_D,
                         Big_P, Big_Q, Big_DP, Big_DQ, Big_QI)
                        = CryptoLib.Errors.Ok,
                      "a 4096-bit RSA key is generated");
               Check (CryptoLib.Certificates.Create_CA_For_Key
                        ("cryptolib-rsa-4096-ca",
                         CryptoLib.Certificates.RSA_Private_Key_PEM
                           (Big_N, Big_E, Big_D, Big_P, Big_Q, Big_DP, Big_DQ,
                            Big_QI),
                         Big_CA)
                        = CryptoLib.Certificates.Ok,
                      "and a 4096-bit RSA CA fits the material slot");
            end;

            --  Now sign a leaf with that RSA CA. The leaf is P-256, because
            --  this crate does not generate RSA keys -- an ordinary mixed
            --  chain, which is what most of the world runs.
            Check (CryptoLib.Certificates.Issue_Server_Certificate
                     (Ada.Strings.Unbounded.To_String (Root),
                      Ada.Strings.Unbounded.To_String (Root_Key),
                      "under-rsa-ca.example",
                      [1 => Ada.Strings.Unbounded.To_Unbounded_String
                              ("under-rsa-ca.example")],
                      Leaf, Leaf_Key)
                     = CryptoLib.Certificates.Ok,
                   "an RSA CA signs a leaf");
            Check (OpenSSL_Interop.Chain_Verifies
                     (Ada.Strings.Unbounded.To_String (Root),
                      Ada.Strings.Unbounded.To_String (Leaf)),
                   "and OpenSSL verifies the chain the RSA CA signed");
            Check (OpenSSL_Interop.Certificate_Key_Bits
                     (Ada.Strings.Unbounded.To_String (Leaf)) = 256,
                   "the leaf under an RSA CA carries a P-256 key");
            Check (CryptoLib.Certificates.Private_Key_Matches_Certificate
                     (Ada.Strings.Unbounded.To_String (Leaf),
                      Ada.Strings.Unbounded.To_String (Leaf_Key))
                     = CryptoLib.Certificates.Ok,
                   "and the key issued with it belongs to it");
         end;

         --  An RSA subject, which this crate cannot generate a key for and
         --  can now certify: the key comes from CryptoLib.RSA, the
         --  SubjectPublicKeyInfo from RSA_Public_Key_Info, and the
         --  certificate from the supplied-key entry point. OpenSSL verifying
         --  the chain is what says the rsaEncryption identifier, its explicit
         --  NULL parameters, and the two-integer BIT STRING are all right --
         --  none of which resembles the fixed-width keys the other arms use.
         declare
            Rng : CryptoLib.Random.Random_Source;
            N   : Ada.Streams.Stream_Element_Array (1 .. 256);
            E   : Ada.Streams.Stream_Element_Array (1 .. 3);
            D   : Ada.Streams.Stream_Element_Array (1 .. 256);
            P, Q, DP, DQ, QI : Ada.Streams.Stream_Element_Array (1 .. 128);
            Root, Root_Key, Leaf : Ada.Strings.Unbounded.Unbounded_String;
         begin
            CryptoLib.Random.Initialize_Production (Rng);
            Check (CryptoLib.RSA.Generate_Keypair_With_Primes
                     (CryptoLib.RSA.RSA_2048, Rng, N, E, D, P, Q, DP, DQ, QI)
                     = CryptoLib.Errors.Ok,
                   "an RSA subject key is generated");
            Check (CryptoLib.Certificates.Create_Local_CA
                     ("cryptolib-chain-check-rsa-subject", Root, Root_Key,
                      CryptoLib.Certificates.P256_Key)
                     = CryptoLib.Certificates.Ok,
                   "a P-256 CA to certify it with");

            declare
               SPKI : constant String :=
                 CryptoLib.Certificates.RSA_Public_Key_Info (N, E);
               SPKI_Bytes : Ada.Streams.Stream_Element_Array
                 (1 .. Ada.Streams.Stream_Element_Offset (SPKI'Length));
            begin
               Check (SPKI /= "", "the RSA SubjectPublicKeyInfo encodes");
               for I in SPKI_Bytes'Range loop
                  SPKI_Bytes (I) :=
                    Character'Pos (SPKI (SPKI'First + Natural (I - 1)));
               end loop;
               Check (CryptoLib.Certificates.Issue_Server_Certificate_For_Key
                        (Ada.Strings.Unbounded.To_String (Root),
                         Ada.Strings.Unbounded.To_String (Root_Key),
                         "rsa-subject.example",
                         [1 => Ada.Strings.Unbounded.To_Unbounded_String
                                 ("rsa-subject.example")],
                         SPKI_Bytes, Leaf)
                        = CryptoLib.Certificates.Ok,
                      "an RSA leaf is issued for a supplied key");
               Check (OpenSSL_Interop.Chain_Verifies
                        (Ada.Strings.Unbounded.To_String (Root),
                         Ada.Strings.Unbounded.To_String (Leaf)),
                      "the RSA leaf verifies against its CA in OpenSSL");

               --  Chaining is not enough, and this is the reason the two
               --  checks below exist. The chain check verifies the CA's
               --  signature; the subject's own key is only carried along, so
               --  a subject key encoded wrongly chains perfectly. Swapping
               --  the modulus and the exponent in the SubjectPublicKeyInfo
               --  passed the chain check -- OpenSSL has to be asked what key
               --  it thinks is in there before anything notices.
               Check (OpenSSL_Interop.Certificate_Key_Is_RSA
                        (Ada.Strings.Unbounded.To_String (Leaf)),
                      "OpenSSL reads the subject key as RSA");
               Check (OpenSSL_Interop.Certificate_Key_Bits
                        (Ada.Strings.Unbounded.To_String (Leaf)) = 2048,
                      "and as 2048 bits, which a swapped modulus and exponent"
                      & " would not be, got"
                      & Natural'Image (OpenSSL_Interop.Certificate_Key_Bits
                          (Ada.Strings.Unbounded.To_String (Leaf))));
            end;

            --  And the private key file this crate writes for that key is one
            --  anything else can read: nine values, all required.
            Check (CryptoLib.Certificates.RSA_Private_Key_PEM
                     (N, E, D, P, Q, DP, DQ, QI) /= "",
                   "the RSA private key writes as PKCS#8 PEM");
            Check (Ada.Strings.Fixed.Index
                     (CryptoLib.Certificates.RSA_Private_Key_PEM
                        (N, E, D, P, Q, DP, DQ, QI),
                      "-----BEGIN PRIVATE KEY-----") = 1,
                   "and it is armoured as a PKCS#8 private key");

            --  The client profile takes the same supplied key, and the
            --  certificate it produces must still chain and still carry the
            --  RSA key -- a profile that swapped the subject key for the CA's
            --  would chain just as well.
            declare
               SPKI : constant String :=
                 CryptoLib.Certificates.RSA_Public_Key_Info (N, E);
               SPKI_Bytes : Ada.Streams.Stream_Element_Array
                 (1 .. Ada.Streams.Stream_Element_Offset (SPKI'Length));
               Client : Ada.Strings.Unbounded.Unbounded_String;
            begin
               for I in SPKI_Bytes'Range loop
                  SPKI_Bytes (I) :=
                    Character'Pos (SPKI (SPKI'First + Natural (I - 1)));
               end loop;
               Check (CryptoLib.Certificates.Issue_Client_Certificate_For_Key
                        (Ada.Strings.Unbounded.To_String (Root),
                         Ada.Strings.Unbounded.To_String (Root_Key),
                         "rsa-client.example",
                         [1 => Ada.Strings.Unbounded.To_Unbounded_String
                                 ("rsa-client.example")],
                         SPKI_Bytes, Client)
                        = CryptoLib.Certificates.Ok,
                      "an RSA client certificate is issued for a supplied key");
               Check (OpenSSL_Interop.Chain_Verifies
                        (Ada.Strings.Unbounded.To_String (Root),
                         Ada.Strings.Unbounded.To_String (Client))
                      and then OpenSSL_Interop.Certificate_Key_Bits
                        (Ada.Strings.Unbounded.To_String (Client)) = 2048,
                      "and it chains carrying the same 2048-bit RSA key");
            end;

            --  The key issued alongside an RSA certificate belongs to it.
            --  This used to be refused for RSA while CryptoLib.Identities
            --  matched RSA keys perfectly well -- two answers to one question.
            declare
               CA_Key : constant String :=
                 CryptoLib.Certificates.RSA_Private_Key_PEM
                   (N, E, D, P, Q, DP, DQ, QI);
               Own_CA : Ada.Strings.Unbounded.Unbounded_String;
            begin
               Check (CryptoLib.Certificates.Create_CA_For_Key
                        ("cryptolib-rsa-match", CA_Key, Own_CA)
                        = CryptoLib.Certificates.Ok,
                      "a CA certificate for the RSA key");
               Check (CryptoLib.Certificates.Private_Key_Matches_Certificate
                        (Ada.Strings.Unbounded.To_String (Own_CA), CA_Key)
                        = CryptoLib.Certificates.Ok,
                      "an RSA key is matched to its own certificate");

               --  And a different RSA key is not matched to it, which is the
               --  half that would pass if the check simply always said yes.
               declare
                  N2 : Ada.Streams.Stream_Element_Array (1 .. 256);
                  E2 : Ada.Streams.Stream_Element_Array (1 .. 3);
                  D2 : Ada.Streams.Stream_Element_Array (1 .. 256);
                  P2, Q2, DP2, DQ2, QI2 :
                    Ada.Streams.Stream_Element_Array (1 .. 128);
               begin
                  Check (CryptoLib.RSA.Generate_Keypair_With_Primes
                           (CryptoLib.RSA.RSA_2048, Rng, N2, E2, D2, P2, Q2,
                            DP2, DQ2, QI2) = CryptoLib.Errors.Ok,
                         "a second RSA key");
                  Check (CryptoLib.Certificates.Private_Key_Matches_Certificate
                           (Ada.Strings.Unbounded.To_String (Own_CA),
                            CryptoLib.Certificates.RSA_Private_Key_PEM
                              (N2, E2, D2, P2, Q2, DP2, DQ2, QI2))
                           /= CryptoLib.Certificates.Ok,
                         "and it is not matched to the first key's certificate");
               end;
            end;

            --  The email profile, so all three supplied-key entry points are
            --  exercised rather than two of them.
            declare
               SPKI : constant String :=
                 CryptoLib.Certificates.RSA_Public_Key_Info (N, E);
               SPKI_Bytes : Ada.Streams.Stream_Element_Array
                 (1 .. Ada.Streams.Stream_Element_Offset (SPKI'Length));
               Mail : Ada.Strings.Unbounded.Unbounded_String;
            begin
               for I in SPKI_Bytes'Range loop
                  SPKI_Bytes (I) :=
                    Character'Pos (SPKI (SPKI'First + Natural (I - 1)));
               end loop;
               Check (CryptoLib.Certificates.Issue_Email_Certificate_For_Key
                        (Ada.Strings.Unbounded.To_String (Root),
                         Ada.Strings.Unbounded.To_String (Root_Key),
                         "rsa@example.com",
                         [1 => Ada.Strings.Unbounded.To_Unbounded_String
                                 ("rsa@example.com")],
                         SPKI_Bytes, Mail)
                        = CryptoLib.Certificates.Ok,
                      "an RSA email certificate is issued for a supplied key");
               Check (OpenSSL_Interop.Chain_Verifies
                        (Ada.Strings.Unbounded.To_String (Root),
                         Ada.Strings.Unbounded.To_String (Mail)),
                      "and it chains");
            end;

            --  RSASSA-PSS as a certificate signature. This crate could
            --  verify a PSS-signed certificate long before it could make one,
            --  which was the last algorithm it could check and not produce.
            --
            --  PSS states its hash, mask function and salt length in the
            --  algorithm identifier rather than in its name, and the same
            --  block has to appear in the signed body and beside the
            --  signature. Two verifiers are asked: this crate's own, and
            --  OpenSSL, because agreeing with itself would prove nothing about
            --  a parameter block assembled wrongly.
            declare
               CA_Key : constant String :=
                 CryptoLib.Certificates.RSA_Private_Key_PEM
                   (N, E, D, P, Q, DP, DQ, QI);
               PSS_CA, PSS_Leaf : Ada.Strings.Unbounded.Unbounded_String;
               SPKI : constant String :=
                 CryptoLib.Certificates.RSA_Public_Key_Info (N, E);
               SPKI_Bytes : Ada.Streams.Stream_Element_Array
                 (1 .. Ada.Streams.Stream_Element_Offset (SPKI'Length));
            begin
               for I in SPKI_Bytes'Range loop
                  SPKI_Bytes (I) :=
                    Character'Pos (SPKI (SPKI'First + Natural (I - 1)));
               end loop;
               Check (CryptoLib.Certificates.Create_CA_For_Key
                        ("cryptolib-pss-ca", CA_Key, PSS_CA,
                         Use_PSS => True)
                        = CryptoLib.Certificates.Ok,
                      "a PSS-signed CA certificate is issued");
               Check (CryptoLib.Certificates.Issue_Server_Certificate_For_Key
                        (Ada.Strings.Unbounded.To_String (PSS_CA), CA_Key,
                         "pss-leaf.example",
                         [1 => Ada.Strings.Unbounded.To_Unbounded_String
                                 ("pss-leaf.example")],
                         SPKI_Bytes, PSS_Leaf, Use_PSS => True)
                        = CryptoLib.Certificates.Ok,
                      "and a PSS-signed leaf under it");
               Check (OpenSSL_Interop.Chain_Verifies
                        (Ada.Strings.Unbounded.To_String (PSS_CA),
                         Ada.Strings.Unbounded.To_String (PSS_Leaf)),
                      "OpenSSL verifies the PSS chain");

               --  Both directions are already covered without asking this
               --  crate to read what it just wrote, which would be the weaker
               --  check: Check_RSA_PSS verifies PSS certificates OpenSSL made,
               --  and OpenSSL verifies the ones made here. Reading our own
               --  output would only show the writer and reader agree with each
               --  other.
            end;

            --  A supplied key that is not a key is refused rather than
            --  certified. This crate already declines to certify a name that
            --  is not a name; a public key it cannot recognise as one deserves
            --  the same answer, because the certificate that comes out is
            --  useless and the caller was told it succeeded.
            declare
               Garbage : constant Ada.Streams.Stream_Element_Array :=
                 [16#DE#, 16#AD#, 16#BE#, 16#EF#];
               Truncated : constant Ada.Streams.Stream_Element_Array :=
                 [16#30#, 16#82#, 16#01#, 16#22#];   --  a SEQUENCE header only
               Ignored : Ada.Strings.Unbounded.Unbounded_String;
            begin
               Check (CryptoLib.Certificates.Issue_Server_Certificate_For_Key
                        (Ada.Strings.Unbounded.To_String (Root),
                         Ada.Strings.Unbounded.To_String (Root_Key),
                         "not-a-key.example",
                         [1 => Ada.Strings.Unbounded.To_Unbounded_String
                                 ("not-a-key.example")],
                         Garbage, Ignored)
                        /= CryptoLib.Certificates.Ok,
                      "a subject key that is not DER at all is refused");
               Check (CryptoLib.Certificates.Issue_Server_Certificate_For_Key
                        (Ada.Strings.Unbounded.To_String (Root),
                         Ada.Strings.Unbounded.To_String (Root_Key),
                         "not-a-key.example",
                         [1 => Ada.Strings.Unbounded.To_Unbounded_String
                                 ("not-a-key.example")],
                         Truncated, Ignored)
                        /= CryptoLib.Certificates.Ok,
                      "and one whose length runs past what it carries");

               --  A real key with an octet stuck on the end. The SEQUENCE
               --  parses; what makes this wrong is that it is not the whole of
               --  what was handed over, and only the spans-exactly check
               --  notices -- neither case above has anything trailing.
               declare
                  Good : constant String :=
                    CryptoLib.Certificates.RSA_Public_Key_Info (N, E);
                  Trailing : Ada.Streams.Stream_Element_Array
                    (1 .. Ada.Streams.Stream_Element_Offset (Good'Length) + 1);
               begin
                  for I in 1 .. Ada.Streams.Stream_Element_Offset
                                  (Good'Length)
                  loop
                     Trailing (I) :=
                       Character'Pos (Good (Good'First + Natural (I - 1)));
                  end loop;
                  Trailing (Trailing'Last) := 16#00#;
                  Check (CryptoLib.Certificates
                           .Issue_Server_Certificate_For_Key
                             (Ada.Strings.Unbounded.To_String (Root),
                              Ada.Strings.Unbounded.To_String (Root_Key),
                              "not-a-key.example",
                              [1 => Ada.Strings.Unbounded
                                      .To_Unbounded_String
                                        ("not-a-key.example")],
                              Trailing, Ignored)
                           /= CryptoLib.Certificates.Ok,
                         "and a valid key with an octet after it is refused");
               end;
            end;

            --  A supplied key with an empty SPKI is refused rather than
            --  certified as nothing.
            declare
               Nothing : Ada.Streams.Stream_Element_Array (1 .. 0);
               Ignored : Ada.Strings.Unbounded.Unbounded_String;
            begin
               Check (CryptoLib.Certificates.Issue_Server_Certificate_For_Key
                        (Ada.Strings.Unbounded.To_String (Root),
                         Ada.Strings.Unbounded.To_String (Root_Key),
                         "rsa-subject.example",
                         [1 => Ada.Strings.Unbounded.To_Unbounded_String
                                 ("rsa-subject.example")],
                         Nothing, Ignored)
                        /= CryptoLib.Certificates.Ok,
                      "an empty subject key is refused");
            end;
         end;

         Check_Chain (CryptoLib.Certificates.Ed25519_Key);
         --  P-256 last of the curves to arrive, and the one most certificates
         --  in the world actually use. OpenSSL verifying the chain is what
         --  says the curve OID, the signature OID, the scalar width and the
         --  point encoding all agree with the rest of the world rather than
         --  only with each other.
         Check_Chain (CryptoLib.Certificates.P256_Key);
         Check_Chain (CryptoLib.Certificates.P384_Key);
         Check_Chain (CryptoLib.Certificates.Ed448_Key);
      end;
      Check
        (Ada.Strings.Unbounded.Index
           (CA_Cert, "BEGIN CERTIFICATE") /= 0,
         "local CA certificate is PEM encoded");
      Check
        (Ada.Strings.Unbounded.Index
           (CA_Key, "BEGIN PRIVATE KEY") /= 0,
         "local CA private key is PKCS#8 PEM");
      Check
        (CryptoLib.Certificates.Create_Local_CA
           ("devcert-other-ca", Other_CA_Cert, Other_CA_Key)
         = CryptoLib.Certificates.Ok,
         "second local CA creation succeeds");
      Check
        (CryptoLib.Certificates.Private_Key_Matches_Certificate
           (To_String (CA_Cert), To_String (CA_Key))
         = CryptoLib.Certificates.Ok,
         "certificate/private-key match is detected");
      Check
        (CryptoLib.Certificates.Private_Key_Matches_Certificate
           (To_String (CA_Cert), To_String (Other_CA_Key))
         = CryptoLib.Certificates.Invalid_Input,
         "certificate/private-key mismatch is rejected");

      Check
        (CryptoLib.Certificates.Issue_Server_Certificate
           (To_String (CA_Cert),
            To_String (CA_Key),
            "localhost",
            [1 => To_Unbounded_String ("localhost")],
            Leaf_Cert,
            Leaf_Key) = CryptoLib.Certificates.Ok,
         "server certificate creation succeeds");
      Check
        (Ada.Strings.Unbounded.Index
           (Leaf_Cert, "BEGIN CERTIFICATE") /= 0,
         "server certificate is PEM encoded");
      Check
        (Ada.Strings.Unbounded.Index
           (Leaf_Key, "BEGIN PRIVATE KEY") /= 0,
         "server private key is PKCS#8 PEM");

      Check
        (CryptoLib.Certificates.Issue_Server_Certificate
           (To_String (CA_Cert),
            To_String (CA_Key),
            "127.0.0.1",
            [1 => To_Unbounded_String ("127.0.0.1"),
             2 => To_Unbounded_String ("::1")],
            Leaf_Cert,
            Leaf_Key) = CryptoLib.Certificates.Ok,
         "IP SAN certificate creation succeeds");

      Check
        (CryptoLib.Certificates.Issue_Client_Certificate
           (To_String (CA_Cert),
            To_String (CA_Key),
            "client",
            [1 => To_Unbounded_String ("client")],
            Client_Cert,
            Client_Key) = CryptoLib.Certificates.Ok,
         "client certificate creation succeeds");
      Check
        (Ada.Strings.Unbounded.Index
           (Client_Cert, "BEGIN CERTIFICATE") /= 0,
         "client certificate is PEM encoded");
      Check
        (Ada.Strings.Unbounded.Index
           (Client_Key, "BEGIN PRIVATE KEY") /= 0,
         "client private key is PKCS#8 PEM");

      Check
        (CryptoLib.Certificates.Issue_Email_Certificate
           (To_String (CA_Cert),
            To_String (CA_Key),
            "user@example.test",
            [1 => To_Unbounded_String ("user@example.test")],
            Email_Cert,
            Email_Key) = CryptoLib.Certificates.Ok,
         "email certificate creation succeeds");
      Check
        (Ada.Strings.Unbounded.Index
           (Email_Cert, "BEGIN CERTIFICATE") /= 0,
         "email certificate is PEM encoded");
      Check
        (Ada.Strings.Unbounded.Index
           (Email_Key, "BEGIN PRIVATE KEY") /= 0,
         "email private key is PKCS#8 PEM");

      Check
        (CryptoLib.Certificates.Sign_CSR
           (To_String (CA_Cert),
            To_String (CA_Key),
            "-----BEGIN CERTIFICATE REQUEST-----",
            CSR_Cert) = CryptoLib.Certificates.Invalid_Input,
         "malformed CSR is rejected");
      Check
        (Ada.Strings.Unbounded.Length (CSR_Cert) = 0,
         "malformed CSR does not produce a certificate");

      Check
        (CryptoLib.Certificates.Generate_PKCS12
           (To_String (Leaf_Cert),
            To_String (Leaf_Key),
            "localhost",
            "secret",
            Bundle,
            --  Cheap on purpose: this checks that a bundle comes out, not
            --  how hard it is to open. Check_PKCS12_Work_Factor covers that.
            Iterations => 4_096) = CryptoLib.Certificates.Ok,
         "PKCS#12 generation succeeds");
      Check
        (Ada.Strings.Unbounded.Element (Bundle, 1) = Character'Val (16#30#),
         "PKCS#12 bundle is DER sequence");
   end Check_Certificates;

   procedure Check_P384_Local_CA is
      Cert, Key : Ada.Strings.Unbounded.Unbounded_String;
      Status    : CryptoLib.Certificates.Certificate_Status;

      Secp384r1 : constant String :=
        Character'Val (16#2B#) & Character'Val (16#81#) & Character'Val (16#04#)
        & Character'Val (16#00#) & Character'Val (16#22#);
      Ecdsa_SHA384 : constant String :=
        Character'Val (16#2A#) & Character'Val (16#86#) & Character'Val (16#48#)
        & Character'Val (16#CE#) & Character'Val (16#3D#) & Character'Val (16#04#)
        & Character'Val (16#03#) & Character'Val (16#03#);

   begin
      Status :=
        CryptoLib.Certificates.Create_Local_CA
          ("cryptolib-p384-ca", Cert, Key, CryptoLib.Certificates.P384_Key);
      Check (Status = CryptoLib.Certificates.Ok, "P-384 local CA status");
      Check
        (Ada.Strings.Unbounded.Length (Cert) > 0
         and then Ada.Strings.Unbounded.Length (Key) > 0,
         "P-384 local CA emits both PEMs");

      declare
         DER : constant String :=
           Decode_PEM_Body (Ada.Strings.Unbounded.To_String (Cert));
      begin
         Check
           (Index_Of (DER, Secp384r1) > 0,
            "P-384 certificate names secp384r1");
         Check
           (Index_Of (DER, Ecdsa_SHA384) > 0,
            "P-384 certificate is signed with ecdsa-with-SHA384");
      end;

      declare
         DER : constant String :=
           Decode_PEM_Body (Ada.Strings.Unbounded.To_String (Key));
      begin
         Check
           (Index_Of (DER, Secp384r1) > 0,
            "P-384 private key names secp384r1");
      end;
   end Check_P384_Local_CA;

   --  An Ed448 certificate, which is the point of having the primitive.
   --
   --  OpenSSL issued this chain; the signature this checks is one an
   --  independent implementation produced over bytes it chose.
   procedure Check_Ed448_Certificate is
      package X509C renames CryptoLib.X509.Certificates;
      package XV renames CryptoLib.X509.Validation;
      package XS renames CryptoLib.X509.Signatures;
      package ID renames CryptoLib.Identities;
      use type XS.Verification_Result;
      use type CryptoLib.X509.Public_Key_Algorithm;
      use type ID.Identity_Status;

      E448_Leaf_PEM : constant String :=
        "-----BEGIN CERTIFICATE-----" & ASCII.LF &
        "MIIBpDCCASSgAwIBAgIUQLczDWL7WwuZoYVM4WsLqa7MwWIwBQYDK2VxMBUxEzAR" & ASCII.LF &
        "BgNVBAMMCkVkNDQ4IFJvb3QwHhcNMjYwNzI5MDk1NDQ4WhcNMzIwMTE5MDk1NDQ4" & ASCII.LF &
        "WjAYMRYwFAYDVQQDDA1lZDQ0OC5leGFtcGxlMEMwBQYDK2VxAzoANsYQp79ULh3d" & ASCII.LF &
        "SjdMmNmFUG1+o2Q5SSCXICPq8UUqzOYBYHeJ7hNF32pZzaGPBjzs2Z+SamfvyS0A" & ASCII.LF &
        "o2owaDAMBgNVHRMBAf8EAjAAMBgGA1UdEQQRMA+CDWVkNDQ4LmV4YW1wbGUwHQYD" & ASCII.LF &
        "VR0OBBYEFNb187dyLV9qCvIGD4F3TJR0WLUqMB8GA1UdIwQYMBaAFMbdgp4UBnjX" & ASCII.LF &
        "ERu+ekkzVsgRgRsVMAUGAytlcQNzAJMzV/lMPoEHUcr1PaG6vEbABaXpt5YnsLan" & ASCII.LF &
        "6gdTjwBoGMzeoSJNgElR+VgnUzhMFksq9RbPy3KFgPsA1OPP3RxrFlAhuBi4cmPR" & ASCII.LF &
        "jsn91H3D6FErtsx6azAZ9tTrESyu0MCqMMmGyNuLdEKBFNJO+XIKAA==" & ASCII.LF &
        "-----END CERTIFICATE-----";
      E448_Key_PEM : constant String :=
        "-----BEGIN PRIVATE KEY-----" & ASCII.LF &
        "MEcCAQAwBQYDK2VxBDsEOYyTXKOV7SfQx6zlvUpFDYciMQ6W+mNHXbEDe8xPX6kz" & ASCII.LF &
        "OCUb0dKHgHnuElzHtXQCKo9TeCtrBOQFOg==" & ASCII.LF &
        "-----END PRIVATE KEY-----";
      E448_Other_Key_PEM : constant String :=
        "-----BEGIN PRIVATE KEY-----" & ASCII.LF &
        "MEcCAQAwBQYDK2VxBDsEOZEzccND4JxGmKYY52TJ9TBSiT5dO9S6x5f97ovYOgNO" & ASCII.LF &
        "INbtgil2L/8dqEoW1wfU5o8SWe9sFGpciQ==" & ASCII.LF &
        "-----END PRIVATE KEY-----";

      E448_Root_DER : constant String :=
        "308201783081f9a00302010202145772562f5003d8e4686dca2c57baa102163cd987300506032b6571301531" &
        "13301106035504030c0a456434343820526f6f74301e170d3236303732393039353434385a170d3334313031" &
        "353039353434385a30153113301106035504030c0a456434343820526f6f743043300506032b6571033a0045" &
        "d2095f56d2bea5572d69c011ed8de923301a8f561ea57ed3e13ed04bd8000dc36b78dea17a1f6e9e2d854971" &
        "4bc9fe07179d46c3f6b56180a3423040300f0603551d130101ff040530030101ff300e0603551d0f0101ff04" &
        "0403020204301d0603551d0e04160414c6dd829e140678d7111bbe7a493356c811811b15300506032b657103" &
        "7300f3c873adf2a0a171f80f20e5b47bef9bc07a1cfe0991ab570b7ddeec0628e5f8afc1857ddfce5e0945c1" &
        "e448d20f9694e9fd8c0c385c0cbb802352d13e94faa9108b4115e884137593d9b2919ce27a9325fae140a584" &
        "ac987ec46919dbc1889cde500a9af25c7bc3ef52dfb6263d6d182f00";

      E448_Leaf_DER : constant String :=
        "308201a430820124a003020102021440b7330d62fb5b0b99a1854ce16b0ba9aeccc162300506032b65713015" &
        "3113301106035504030c0a456434343820526f6f74301e170d3236303732393039353434385a170d33323031" &
        "31393039353434385a30183116301406035504030c0d65643434382e6578616d706c653043300506032b6571" &
        "033a0036c610a7bf542e1ddd4a374c98d985506d7ea364394920972023eaf1452acce601607789ee1345df6a" &
        "59cda18f063cecd99f926a67efc92d00a36a3068300c0603551d130101ff0402300030180603551d11041130" &
        "0f820d65643434382e6578616d706c65301d0603551d0e04160414d6f5f3b7722d5f6a0af2060f81774c9474" &
        "58b52a301f0603551d23041830168014c6dd829e140678d7111bbe7a493356c811811b15300506032b657103" &
        "7300933357f94c3e810751caf53da1babc46c005a5e9b79627b0b6a7ea07538f006818ccdea1224d804951f9" &
        "582753384c164b2af516cfcb728580fb00d4e3cfdd1c6b165021b818b87263d18ec9fdd47dc3e8512bb6cc7a" &
        "6b3019f6d4eb112caed0c0aa30c986c8db8b74428114d24ef9720a00";

      Status : CryptoLib.ASN1.Errors.Decode_Status;

      function From_Hex
        (Text : String) return Ada.Streams.Stream_Element_Array
      is
         Result : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Text'Length / 2));
         function Nibble (C : Character) return Natural
         is (case C is
                when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
                when others     => Character'Pos (C) - Character'Pos ('a') + 10);
      begin
         for I in Result'Range loop
            Result (I) :=
              Ada.Streams.Stream_Element
                (Nibble (Text (Text'First + 2 * Natural (I - 1))) * 16
                 + Nibble (Text (Text'First + 2 * Natural (I - 1) + 1)));
         end loop;
         return Result;
      end From_Hex;

      function Decoded (Hex : String) return X509C.Certificate
      is (X509C.Decode_DER
            (From_Hex (Hex), CryptoLib.ASN1.Default_Limits, Status));

      type Ed448_Chain is limited new XV.Path_Source with null record;

      overriding function Length (Source : Ed448_Chain) return Positive is (2);

      overriding function Certificate_At
        (Source : Ed448_Chain; Index : Positive) return X509C.Certificate
      is (if Index = 1 then Decoded (E448_Leaf_DER) else Decoded (E448_Root_DER));

      overriding function Is_Trust_Anchor
        (Source : Ed448_Chain; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Bytes (Item)
          = X509C.Subject_Bytes (Decoded (E448_Root_DER)));

      At_Time : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 9, Day => 1,
         Hour => 12, Minute => 0, Second => 0);
   begin
      Check (X509C.Public_Key_Algorithm_Of (Decoded (E448_Leaf_DER))
             = CryptoLib.X509.Ed448,
             "the certificate names an Ed448 key");
      Check (XS.Is_Supported (CryptoLib.X509.Ed448_Signature),
             "and Ed448 counts as an algorithm this can decide, which is "
             & "what tells a caller it was checked rather than skipped");
      Check (XS.Verify_Certificate_Signature
               (Decoded (E448_Leaf_DER), Decoded (E448_Root_DER)) = XS.Valid,
             "the issuer's signature over it verifies");

      declare
         Verdict : constant XV.Validation_Result :=
           XV.Validate_Path (Ed448_Chain'(null record), At_Time);
      begin
         Check (Verdict.Valid,
                "and the chain validates, got "
                & XV.Failure_Image (Verdict.Failure));
      end;

      --  An Ed448 key is now checked against its certificate rather than
      --  shrugged at. The difference that matters is the second answer
      --  below: "these do not go together" is a finding, where
      --  Unsupported_Key was only ever an admission of not looking.
      declare
         Item : ID.Local_Identity;
         St   : ID.Identity_Status;
      begin
         ID.Decode (E448_Leaf_PEM, E448_Key_PEM, Item, St);
         Check (St = ID.Ok and then ID.Is_Present (Item),
                "an Ed448 key is recognised as belonging to its leaf, got "
                & ID.Status_Image (St));
      end;

      declare
         Item : ID.Local_Identity;
         St   : ID.Identity_Status;
      begin
         ID.Decode (E448_Leaf_PEM, E448_Other_Key_PEM, Item, St);
         Check (St = ID.Key_Mismatch,
                "and another Ed448 key is reported as not belonging to it, "
                & "not as one that could not be checked, got "
                & ID.Status_Image (St));
         Check (not ID.Is_Present (Item), "with nothing handed back");
      end;
   end Check_Ed448_Certificate;

   --  AUnit routine wrappers. Each check is a test of its own, so a
   --  failure reports the check that failed and the rest still run.
   procedure Run_Check_P384_Local_CA (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Ed448_Certificate (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Certificates (Item : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Check_P384_Local_CA (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_P384_Local_CA;
   end Run_Check_P384_Local_CA;

   procedure Run_Check_Ed448_Certificate (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Ed448_Certificate;
   end Run_Check_Ed448_Certificate;

   procedure Run_Check_Certificates (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Certificates;
   end Run_Check_Certificates;

   overriding procedure Register_Tests (Item : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (Item, Run_Check_P384_Local_CA'Access, "p384 local ca");
      Register_Routine (Item, Run_Check_Ed448_Certificate'Access, "ed448 certificate");
      Register_Routine (Item, Run_Check_Certificates'Access, "certificates");
   end Register_Tests;

   overriding function Name (Item : Test_Case) return AUnit.Message_String is
      pragma Unreferenced (Item);
   begin
      return AUnit.Format ("cryptolib X.509 issuance");
   end Name;

end Tests_X509_Issuance;
