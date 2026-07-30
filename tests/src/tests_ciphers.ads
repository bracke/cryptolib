--  Block and stream ciphers, AEAD constructions, and MAC negotiation.
--
--  Each procedure is one group of known-answer or negative tests, and
--  is called from the Tests driver. Splitting the suite by topic is
--  what keeps any one file readable; the driver keeps the order.
package Tests_Ciphers is

   procedure Check_ZIP_AES_CTR_Roundtrip;

   procedure Check_RC2_40_CBC_Decrypt;

   procedure Check_AES_256_CBC_Raw_Roundtrip;

   procedure Check_AES_CBC_Raw_Rejects_Bad_Sizes;

   procedure Check_Cipher_Names;

   procedure Check_UMAC_Sequence_Nonce;

   procedure Check_Chacha_Length_Agreement;

   procedure Check_CBC_Paths_Agree;

   procedure Check_UMAC_Negotiation_Guard;

   procedure Check_ChaCha20_Poly1305_RFC8439;

end Tests_Ciphers;
