with CryptoLib.Errors;

--  @summary Policy and wire-length metadata for OpenSSH hybrid post-quantum key
--  exchange, which combines x25519 with a PQ KEM (ML-KEM-768 or SNTRUP761).
--
--  Recognizes the four OpenSSH-compatible hybrid KEX names, reports the hash
--  combiner (SHA-256 vs SHA-512), the KEM public-key / ciphertext byte lengths
--  and the concatenated client-init and server-reply payload sizes (KEM part +
--  32-byte x25519 part), and exposes the selectability / fail-closed policy.
package CryptoLib.Hybrid_PQ_Kex
  with SPARK_Mode => On
is

   type Hybrid_PQ_Kind is
     (Not_Hybrid_PQ,
      MLKEM768_X25519_SHA256,
      MLKEM768_X25519_SHA512,
      SNTRUP761_X25519_SHA512_OpenSSH,
      SNTRUP761_X25519_SHA512);

   type Hybrid_PQ_Readiness is
     (Unknown_Algorithm,
      KEM_Boundary_Present,
      External_KAT_Gate_Pending,
      Live_OpenSSH_Interop_Gate_Pending,
      Advertised_And_Selectable);

   --  Classify an SSH KEX algorithm name into a hybrid-PQ kind.
   --  @param Name_Text the KEX method name from the SSH name-list
   --  @return the matching Hybrid_PQ_Kind, or Not_Hybrid_PQ if unrecognized
   function Kind_Of (Name_Text : String) return Hybrid_PQ_Kind;

   --  Test whether the name is one of the recognized OpenSSH hybrid-PQ methods.
   --  @param Name_Text the KEX method name
   --  @return True if Name_Text names a supported hybrid-PQ KEX
   function Is_OpenSSH_Hybrid_PQ_Kex_Name
     (Name_Text : String)
      return Boolean;

   --  Test whether the name is an ML-KEM-768 + x25519 hybrid method.
   --  @param Name_Text the KEX method name
   --  @return True if Name_Text names an ML-KEM-768 hybrid KEX
   function Is_MLKEM768_Hybrid_PQ_Kex_Name
     (Name_Text : String)
      return Boolean;

   --  Test whether the name is an SNTRUP761 + x25519 hybrid method.
   --  @param Name_Text the KEX method name
   --  @return True if Name_Text names an SNTRUP761 hybrid KEX
   function Is_SNTRUP761_Hybrid_PQ_Kex_Name
     (Name_Text : String)
      return Boolean;

   --  Report whether the method's shared-secret combiner hashes with SHA-512
   --  (as opposed to SHA-256).
   --  @param Name_Text the KEX method name
   --  @return True if the method uses the SHA-512 combiner
   function Uses_SHA512_Combiner
     (Name_Text : String)
      return Boolean;

   --  KEM public-key length carried in the client init (0 if not hybrid-PQ).
   --  @param Name_Text the KEX method name
   --  @return the KEM public-key length in bytes, or 0
   function Client_Init_PQ_Length
     (Name_Text : String)
      return Natural;

   --  KEM ciphertext length carried in the server reply (0 if not hybrid-PQ).
   --  @param Name_Text the KEX method name
   --  @return the KEM ciphertext length in bytes, or 0
   function Server_Reply_PQ_Length
     (Name_Text : String)
      return Natural;

   --  Total client-init payload length: the KEM public key plus the 32-byte
   --  x25519 public value (0 if not hybrid-PQ).
   --  @param Name_Text the KEX method name
   --  @return the concatenated client-init length in bytes, or 0
   function Client_Init_Total_Length
     (Name_Text : String)
      return Natural;

   --  Total server-reply payload length: the KEM ciphertext plus the 32-byte
   --  x25519 public value (0 if not hybrid-PQ).
   --  @param Name_Text the KEX method name
   --  @return the concatenated server-reply length in bytes, or 0
   function Server_Reply_Total_Length
     (Name_Text : String)
      return Natural;

   --  Report the deployment readiness state for the named method.
   --  @param Name_Text the KEX method name
   --  @return the Hybrid_PQ_Readiness, or Unknown_Algorithm if unrecognized
   function Readiness_Of
     (Name_Text : String)
      return Hybrid_PQ_Readiness;

   --  Render a readiness value as its stable lower-case string form.
   --  @param Value the readiness state to render
   --  @return the textual image of Value
   function Readiness_Image
     (Value : Hybrid_PQ_Readiness)
      return String;

   --  Test whether the named method is fully implemented and selectable.
   --  @param Name_Text the KEX method name
   --  @return True if the method is implemented and may be negotiated
   function Is_Implemented
     (Name_Text : String)
      return Boolean;

   --  Fail-closed negotiation status for the named method: Ok if implemented,
   --  Unsupported_Feature for a known-but-unimplemented name, else
   --  Handshake_Failed.
   --  @param Name_Text the KEX method name
   --  @return the negotiation Status per the fail-closed policy
   function Fail_Closed_Status
     (Name_Text : String)
      return CryptoLib.Errors.Status;
end CryptoLib.Hybrid_PQ_Kex;
