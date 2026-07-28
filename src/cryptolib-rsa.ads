with Ada.Streams;

with CryptoLib.Errors;

--  @summary RSA signature verification, RSASSA-PKCS1-v1_5.
--
--  Verification only. There is no signing here and no private-key operation
--  of any kind, which is what makes this package unusually simple: every
--  value it touches -- the modulus, the public exponent, the signature, the
--  message -- is public. There is nothing to leak, so nothing here needs to
--  be constant-time, and saying so plainly is better than leaving a reader to
--  wonder whether it was overlooked. (CryptoLib.Constant_Time.Equal is still
--  used for the final comparison, because it costs nothing and keeps the
--  habit intact.)
--
--  The verification is done by constructing the block the signature should
--  have decrypted to and comparing it, rather than by taking the decrypted
--  block apart and checking the pieces. That is deliberate and it is the
--  whole security argument of this package. A parser that scans forward for
--  the 16#00# separator and then reads whatever follows will accept
--  signatures with too little padding or with data after the digest -- the
--  Bleichenbacher forgery against low public exponents is exactly that
--  mistake. A comparison against a fully determined expected block cannot
--  make it: there is no scan, no optional part, and nothing after the digest
--  to ignore.
package CryptoLib.RSA is

   type Hash_Algorithm is (SHA256, SHA384, SHA512);

   --  Is this signature the given RSA public key's over this message?
   --
   --  Message is hashed here; pass what was signed, not its digest. Modulus
   --  and Exponent are unsigned big-endian and may carry leading zero octets,
   --  as they do when taken straight from a DER INTEGER.
   --  @param Modulus the public modulus n, unsigned big-endian
   --  @param Exponent the public exponent e, unsigned big-endian
   --  @param Hash which digest the signature was made with
   --  @param Message the signed message
   --  @param Signature the signature, which must be exactly as long as the
   --  modulus
   --  @return Ok when the signature verifies, Authentication_Failed when it
   --          does not, Handshake_Failed when an argument cannot be used --
   --          an even or zero modulus, an empty exponent, a signature of the
   --          wrong length or one not less than the modulus, or a modulus too
   --          small to hold the padded digest
   function Verify_PKCS1_V1_5
     (Modulus   : Ada.Streams.Stream_Element_Array;
      Exponent  : Ada.Streams.Stream_Element_Array;
      Hash      : Hash_Algorithm;
      Message   : Ada.Streams.Stream_Element_Array;
      Signature : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Is this signature the given RSA public key's, under RSASSA-PSS?
   --
   --  PSS carries its own parameters -- which hash, which mask generation
   --  function, how long the salt -- in the algorithm identifier rather than
   --  in the algorithm's name, so a caller has to supply them. Getting them
   --  from anywhere but the signature's own parameters is guessing, and a
   --  guess that happens to be right proves nothing about the next one.
   --
   --  Salt_Length is the length the parameters state. The recovered salt is
   --  required to be exactly that: accepting whatever length turns up would
   --  let a signature be reinterpreted with a shorter salt than its issuer
   --  chose.
   --  @param Modulus the public modulus n, unsigned big-endian
   --  @param Exponent the public exponent e, unsigned big-endian
   --  @param Hash which digest the signature was made with, used for the
   --  message digest and for the mask generation function alike
   --  @param Salt_Length the salt length the parameters state, in octets
   --  @param Message the signed message
   --  @param Signature the signature, exactly as long as the modulus
   --  @return Ok when the signature verifies, Authentication_Failed when it
   --          does not, Handshake_Failed when an argument cannot be used
   function Verify_PSS
     (Modulus     : Ada.Streams.Stream_Element_Array;
      Exponent    : Ada.Streams.Stream_Element_Array;
      Hash        : Hash_Algorithm;
      Salt_Length : Natural;
      Message     : Ada.Streams.Stream_Element_Array;
      Signature   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  How many bits wide is this modulus?
   --
   --  For a caller enforcing a minimum key size. No minimum is imposed here:
   --  what counts as too small is policy, it changes over time, and a
   --  primitive that decided it would have to be edited to change it.
   --  @param Modulus the public modulus, unsigned big-endian
   --  @return the modulus's bit length, zero when it is zero
   function Modulus_Bits
     (Modulus : Ada.Streams.Stream_Element_Array) return Natural;

end CryptoLib.RSA;
