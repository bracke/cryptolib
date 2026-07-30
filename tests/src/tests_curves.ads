--  Elliptic-curve signatures and key agreement: ECDSA, Ed25519, Ed448, X25519, ECDH.
--
--  Each procedure is one group of known-answer or negative tests, and
--  is called from the Tests driver. Splitting the suite by topic is
--  what keeps any one file readable; the driver keeps the order.
package Tests_Curves is

   procedure Check_ECDSA_P384_Public_Key;

   procedure Check_ECDSA_P384_Verify;

   procedure Check_ECDSA_P384_P521_Signing;

   procedure Check_Off_Curve_Key;

   procedure Check_Ed25519_Encoding;

   procedure Check_Ed448;

   procedure Check_X25519_Shared_Secret;

   procedure Check_ECDSA_Raw_Entry_Points;

   procedure Check_ECDH;

   procedure Check_ECDSA_Curves;

   procedure Check_ECDSA_Scalar_Encodings;

end Tests_Curves;
