with Ada.Streams;
with CryptoLib.Errors;
with CryptoLib.HKDF;

--  @summary The TLS 1.3 key-schedule derivations, RFC 8446 section 7.1:
--  HKDF-Expand-Label and Derive-Secret.
--
--  TLS 1.3 never calls HKDF-Expand directly. It wraps the info string in a
--  structure that names the length, the purpose and the handshake transcript
--  the key belongs to, so two keys derived from one secret for different
--  purposes cannot collide even if a caller passes the same context. This
--  package builds that structure; CryptoLib.HKDF does the derivation.
--
--  What is here is the pair of primitives, not the schedule. Composing them
--  into the early/handshake/master chain is the protocol's job and needs its
--  state -- the PSK, the ECDHE shared secret, the running transcript. The
--  chain is three alternating steps and each is these two calls plus
--  HKDF.Extract:
--
--     Early     := HKDF.Extract (salt => empty, ikm => PSK or zeros)
--     Handshake := HKDF.Extract (salt => Derive_Secret (Early, "derived", ""),
--                                ikm  => ECDHE shared secret)
--     Master    := HKDF.Extract (salt => Derive_Secret (Handshake, "derived",
--                                                       ""),
--                                ikm  => zeros)
--
--  Nothing here speaks the record layer, the handshake, or the transcript.
--  This crate has no TLS implementation; these are the derivations a TLS
--  implementation would need.
package CryptoLib.TLS13_KDF is

   --  The hash the key schedule runs on, which the cipher suite fixes:
   --  SHA-256 for TLS_AES_128_GCM_SHA256 and TLS_CHACHA20_POLY1305_SHA256,
   --  SHA-384 for TLS_AES_256_GCM_SHA384.
   subtype Hash_Algorithm is CryptoLib.HKDF.Hash_Algorithm;

   --  The longest Label this will accept, in characters.
   --
   --  RFC 8446 gives the label field 7 .. 255 octets and requires the
   --  "tls13 " prefix, which spends 6 of them. Every label the RFC defines is
   --  far shorter; the bound is here so an over-long one is refused rather
   --  than truncated into a different label.
   Maximum_Label_Length : constant Natural := 249;

   --  The longest Context this will accept, in octets: the field is
   --  length-prefixed with a single octet.
   Maximum_Context_Length : constant Natural := 255;

   --  RFC 8446 section 7.1: HKDF-Expand-Label.
   --
   --  Expands Secret into Output, bound to Label and Context. The label is
   --  written into the info string as "tls13 " & Label -- the prefix is added
   --  here, so pass the label as the RFC writes it ("key", "iv", "finished",
   --  "derived", "c hs traffic"), not with the prefix already on it.
   --
   --  Secret is a pseudorandom key of the hash's own width, which is what
   --  every step of the schedule produces.
   --  @param Hash    the hash the cipher suite fixes
   --  @param Secret  the secret to expand, the hash's output length
   --  @param Label   the label, without the "tls13 " prefix, 1 ..
   --    Maximum_Label_Length characters
   --  @param Context the context octets; empty is normal and legal
   --  @param Output  out: the derived key material, zeroed on failure
   --  @return Ok, Handshake_Failed on a secret, label or context that cannot
   --    be used, or Unsupported_Feature when more output is asked for than
   --    the length field or HKDF can express
   function Expand_Label
     (Hash    : Hash_Algorithm;
      Secret  : Ada.Streams.Stream_Element_Array;
      Label   : String;
      Context : Ada.Streams.Stream_Element_Array;
      Output  : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  RFC 8446 section 7.1: Derive-Secret.
   --
   --  Expand_Label with the transcript hash as the context and the hash's own
   --  width as the length. Messages is the handshake transcript, hashed here.
   --
   --  A caller that already keeps a running transcript hash -- which every
   --  real implementation does, since the transcript grows message by message
   --  -- should use Derive_Secret_From_Transcript rather than re-hashing the
   --  whole transcript for each derivation.
   --  @param Hash     the hash the cipher suite fixes
   --  @param Secret   the secret to derive from, the hash's output length
   --  @param Label    the label, without the "tls13 " prefix
   --  @param Messages the handshake transcript, hashed here; may be empty
   --  @param Output   out: the derived secret, which must be the hash's
   --    output length, zeroed on failure
   --  @return Ok, or the status Expand_Label refused with
   function Derive_Secret
     (Hash     : Hash_Algorithm;
      Secret   : Ada.Streams.Stream_Element_Array;
      Label    : String;
      Messages : Ada.Streams.Stream_Element_Array;
      Output   : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Derive-Secret where the caller already has the transcript hash.
   --
   --  Identical to Derive_Secret but takes the digest instead of the messages
   --  that produced it, which is what an implementation carrying a running
   --  hash context has to hand.
   --  @param Hash            the hash the cipher suite fixes
   --  @param Secret          the secret to derive from
   --  @param Label           the label, without the "tls13 " prefix
   --  @param Transcript_Hash the transcript digest, the hash's output length
   --  @param Output          out: the derived secret, the hash's output
   --    length, zeroed on failure
   --  @return Ok, or the status Expand_Label refused with
   function Derive_Secret_From_Transcript
     (Hash            : Hash_Algorithm;
      Secret          : Ada.Streams.Stream_Element_Array;
      Label           : String;
      Transcript_Hash : Ada.Streams.Stream_Element_Array;
      Output          : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

end CryptoLib.TLS13_KDF;
