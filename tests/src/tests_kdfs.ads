--  Password- and key-derivation functions, including HKDF and the TLS 1.3 schedule.
--
--  Each procedure is one group of known-answer or negative tests, and
--  is called from the Tests driver. Splitting the suite by topic is
--  what keeps any one file readable; the driver keeps the order.
package Tests_KDFs is

   procedure Check_PBKDF2_SHA1;

   procedure Check_PBKDF2_SHA2;

   procedure Check_PBKDF1;

   procedure Check_PKCS12_KDF_SHA1;

   procedure Check_Scrypt_SHA256;

   procedure Check_Seven_Zip_AES_SHA256_KDF;

   procedure Check_EVP_Bytes_To_Key_MD5;

   procedure Check_PKCS12_Mac_Key;

   procedure Check_PKCS12_Work_Factor;

   procedure Check_PKCS12_Work_Ceiling;

   procedure Check_Bcrypt_PBKDF;

   procedure Check_TLS13_KDF;

   procedure Check_HKDF;

end Tests_KDFs;
