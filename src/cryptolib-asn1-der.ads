with CryptoLib.ASN1.Errors;

--  @summary A defensive DER reader.
--
--  The reader holds no state. Every operation takes the buffer, the position
--  within it, the end of the region being read, and the depth it is being
--  called at. Nesting is therefore something the caller passes rather than
--  something the reader remembers, which means a caller cannot descend
--  without saying so and a lost or reused parser object cannot carry a stale
--  depth into a fresh parse.
--
--  Positions are in/out: a successful read advances Position past the
--  element, so a sequence is read by calling repeatedly until Position passes
--  the sequence's Last. A failed read leaves Position where it was.
--
--  DER, not BER. Encodings that BER allows and DER does not -- the
--  indefinite-length form, a length or integer in other than its shortest
--  form -- are refused rather than accepted. See Non_Canonical_DER for why
--  that matters for certificates specifically.
package CryptoLib.ASN1.DER is
   pragma Preelaborate;

   subtype Decode_Status is CryptoLib.ASN1.Errors.Decode_Status;

   --  Read one element beginning at Position.
   --
   --  Last bounds the region being read, which for nested content is the
   --  enclosing element's Last rather than the buffer's. Passing the buffer's
   --  end instead would let a truncated inner element read into its sibling.
   --  @param Data the buffer to read from
   --  @param Position where to read; advanced past the element on success
   --  @param Last the last offset the element may occupy
   --  @param Depth the nesting depth this call is made at, zero at the top
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Item receives the decoded element on success
   --  @param Status Ok on success, otherwise why the element was refused
   procedure Read
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Item     : out Element;
      Status   : out Decode_Status);

   --  Read one element and require it to have the given tag.
   --  @param Data the buffer to read from
   --  @param Position where to read; advanced past the element on success
   --  @param Last the last offset the element may occupy
   --  @param Depth the nesting depth this call is made at
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Class the tag class required
   --  @param Number the tag number required
   --  @param Constructed whether the element must be constructed
   --  @param Item receives the decoded element on success
   --  @param Status Ok on success, Invalid_Tag when the tag differs
   procedure Read_Expected
     (Data        : Octets;
      Position    : in out Offset;
      Last        : Offset;
      Depth       : Natural;
      Limits      : Decode_Limits;
      Class       : Tag_Class;
      Number      : Tag_Number;
      Constructed : Boolean;
      Item        : out Element;
      Status      : out Decode_Status);

   --  Read a SEQUENCE header. The content is Item.First .. Item.Last, to be
   --  read at Depth + 1.
   --  @param Data the buffer to read from
   --  @param Position where to read; advanced past the sequence on success
   --  @param Last the last offset the sequence may occupy
   --  @param Depth the nesting depth this call is made at
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Item receives the sequence on success
   --  @param Status Ok on success, otherwise why it was refused
   procedure Read_Sequence
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Item     : out Element;
      Status   : out Decode_Status);

   --  Read a SET header. See Read_Sequence.
   --  @param Data the buffer to read from
   --  @param Position where to read; advanced past the set on success
   --  @param Last the last offset the set may occupy
   --  @param Depth the nesting depth this call is made at
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Item receives the set on success
   --  @param Status Ok on success, otherwise why it was refused
   procedure Read_Set
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Item     : out Element;
      Status   : out Decode_Status);

   --  Read an INTEGER, leaving the value as content octets.
   --
   --  A serial number is up to twenty octets and has no business being turned
   --  into a machine integer, so the value is handed back as the octets it
   --  was encoded as. Minimal-form and sign rules are enforced here.
   --  @param Data the buffer to read from
   --  @param Position where to read; advanced past the integer on success
   --  @param Last the last offset the integer may occupy
   --  @param Depth the nesting depth this call is made at
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Item receives the integer's content range on success
   --  @param Negative True when the encoded value is negative
   --  @param Status Ok on success, otherwise why it was refused
   procedure Read_Integer
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Item     : out Element;
      Negative : out Boolean;
      Status   : out Decode_Status);

   --  Read a small non-negative INTEGER, such as a version number.
   --  @param Data the buffer to read from
   --  @param Position where to read; advanced past the integer on success
   --  @param Last the last offset the integer may occupy
   --  @param Depth the nesting depth this call is made at
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Value receives the value on success
   --  @param Status Ok on success, Invalid_Value when negative or too large
   procedure Read_Small_Integer
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Value    : out Natural;
      Status   : out Decode_Status);

   --  Read a BOOLEAN. DER permits only 0 and 255 as the encoded octet.
   --  @param Data the buffer to read from
   --  @param Position where to read; advanced past the boolean on success
   --  @param Last the last offset the boolean may occupy
   --  @param Depth the nesting depth this call is made at
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Value receives the value on success
   --  @param Status Ok on success, Invalid_Value for any other octet
   procedure Read_Boolean
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Value    : out Boolean;
      Status   : out Decode_Status);

   --  Read an OBJECT IDENTIFIER, leaving the value as content octets.
   --
   --  The arcs are not decoded into numbers. Every use here is a comparison
   --  against a known identifier, and comparing encoded octets answers that
   --  without a decoder to get wrong. The encoding is still validated.
   --  @param Data the buffer to read from
   --  @param Position where to read; advanced past the identifier on success
   --  @param Last the last offset the identifier may occupy
   --  @param Depth the nesting depth this call is made at
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Item receives the identifier's content range on success
   --  @param Status Ok on success, otherwise why it was refused
   procedure Read_Object_Identifier
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Item     : out Element;
      Status   : out Decode_Status);

   --  Read a BIT STRING.
   --
   --  Item covers the value octets only: the leading unused-bit count is
   --  consumed and reported separately, so a caller reading a public key gets
   --  the key rather than the key behind a count.
   --  @param Data the buffer to read from
   --  @param Position where to read; advanced past the bit string on success
   --  @param Last the last offset the bit string may occupy
   --  @param Depth the nesting depth this call is made at
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Item receives the value octets on success
   --  @param Unused_Bits receives how many trailing bits are not part of the
   --  value, zero through seven
   --  @param Status Ok on success, otherwise why it was refused
   procedure Read_Bit_String
     (Data        : Octets;
      Position    : in out Offset;
      Last        : Offset;
      Depth       : Natural;
      Limits      : Decode_Limits;
      Item        : out Element;
      Unused_Bits : out Natural;
      Status      : out Decode_Status);

   --  Read an OCTET STRING.
   --  @param Data the buffer to read from
   --  @param Position where to read; advanced past the string on success
   --  @param Last the last offset the string may occupy
   --  @param Depth the nesting depth this call is made at
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Item receives the string's content range on success
   --  @param Status Ok on success, otherwise why it was refused
   procedure Read_Octet_String
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Item     : out Element;
      Status   : out Decode_Status);

   --  Read a NULL, which DER requires to be empty.
   --  @param Data the buffer to read from
   --  @param Position where to read; advanced past the null on success
   --  @param Last the last offset the null may occupy
   --  @param Depth the nesting depth this call is made at
   --  @param Limits the bounds the caller is willing to decode within
   --  @param Status Ok on success, Invalid_Value when it carries content
   procedure Read_Null
     (Data     : Octets;
      Position : in out Offset;
      Last     : Offset;
      Depth    : Natural;
      Limits   : Decode_Limits;
      Status   : out Decode_Status);

   --  Is the region fully consumed?
   --  @param Position the current position
   --  @param Last the last offset of the region
   --  @return True when nothing remains to be read
   function At_End (Position : Offset; Last : Offset) return Boolean
   is (Position > Last);

end CryptoLib.ASN1.DER;
