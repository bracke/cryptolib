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

end OpenSSL_Interop;
