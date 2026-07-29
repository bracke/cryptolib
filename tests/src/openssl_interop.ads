--  Chain verification through OpenSSL, for the test harness only.
--
--  The library itself links nothing beyond the Ada runtime. This exists so the
--  suite can ask an independent implementation the one question its own code
--  cannot answer about itself: would anybody else accept what we issued? A
--  certificate whose issuer name does not match its CA parses perfectly and
--  fails only here.
package OpenSSL_Interop is

   --  Does Leaf_PEM chain to CA_PEM, as OpenSSL builds and checks it?
   --  @param CA_PEM the issuing CA certificate in PEM form
   --  @param Leaf_PEM the issued certificate in PEM form
   --  @return True when OpenSSL verifies the chain
   function Chain_Verifies (CA_PEM : String; Leaf_PEM : String) return Boolean;

   --  What key does OpenSSL think this certificate carries?
   --
   --  Chain verification does not answer this: it checks the issuer's
   --  signature, and the subject's own key is only carried along. A subject
   --  key encoded wrongly -- the wrong structure, or the modulus and exponent
   --  the wrong way round -- chains perfectly and is still useless to anyone
   --  who tries to use it. This asks the question that notices.
   --  @param Leaf_PEM the certificate to inspect
   --  @return the subject key's size in bits as OpenSSL reads it, or 0
   function Certificate_Key_Bits (Leaf_PEM : String) return Natural;

   --  Is the subject key an RSA key, as OpenSSL reads it?
   --  @param Leaf_PEM the certificate to inspect
   --  @return True when OpenSSL identifies the subject key as RSA
   function Certificate_Key_Is_RSA (Leaf_PEM : String) return Boolean;

end OpenSSL_Interop;
