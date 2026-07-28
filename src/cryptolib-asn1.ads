with Ada.Streams;

--  @summary ASN.1 types shared by the DER reader and the X.509 layer above it.
--
--  Everything here describes an encoding that has already been received, so
--  the types are deliberately inert: an Element names a region of a caller's
--  buffer and carries no storage of its own. Nothing in this hierarchy copies
--  input. That is not only an allocation choice -- a certificate signature is
--  computed over the exact bytes that were signed, and a parser that rebuilt
--  its input would have to be trusted to rebuild it identically. Naming a
--  slice cannot get that wrong.
package CryptoLib.ASN1 is
   pragma Preelaborate;

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;

   subtype Octet is Ada.Streams.Stream_Element;
   subtype Octets is Ada.Streams.Stream_Element_Array;
   subtype Offset is Ada.Streams.Stream_Element_Offset;

   type Tag_Class is (Universal, Application, Context_Specific, Private_Class);

   --  Bounded because a tag number is read from the input. The cap is far
   --  above anything X.509 uses and exists so that a hostile high-tag-number
   --  form cannot be made to run long or overflow.
   subtype Tag_Number is Natural range 0 .. 16#FF_FFFF#;

   Tag_Boolean           : constant Tag_Number := 1;
   Tag_Integer           : constant Tag_Number := 2;
   Tag_Bit_String        : constant Tag_Number := 3;
   Tag_Octet_String      : constant Tag_Number := 4;
   Tag_Null              : constant Tag_Number := 5;
   Tag_Object_Identifier : constant Tag_Number := 6;
   Tag_UTF8_String       : constant Tag_Number := 12;
   Tag_Sequence          : constant Tag_Number := 16;
   Tag_Set               : constant Tag_Number := 17;
   Tag_Printable_String  : constant Tag_Number := 19;
   Tag_T61_String        : constant Tag_Number := 20;
   Tag_IA5_String        : constant Tag_Number := 22;
   Tag_UTC_Time          : constant Tag_Number := 23;
   Tag_Generalized_Time  : constant Tag_Number := 24;
   Tag_BMP_String        : constant Tag_Number := 30;

   --  One decoded TLV, as offsets into the buffer it was read from.
   --
   --  First .. Last is the content. An empty content is represented by
   --  Last < First, which is why Content_Length exists rather than callers
   --  subtracting. Header_First .. Last is the whole encoding, which is what a
   --  signature is computed over.
   type Element is record
      Class        : Tag_Class := Universal;
      Constructed  : Boolean   := False;
      Number       : Tag_Number := 0;
      Header_First : Offset    := 1;
      First        : Offset    := 1;
      Last         : Offset    := 0;
   end record;

   --  Does this element have no content octets?
   --  @param Item the element to inspect
   --  @return True when the element's content is empty
   function Is_Empty (Item : Element) return Boolean
   is (Item.Last < Item.First);

   --  How many content octets does this element have?
   --  @param Item the element to inspect
   --  @return the number of content octets, zero for an empty element
   function Content_Length (Item : Element) return Natural
   is (if Item.Last < Item.First then 0 else Natural (Item.Last - Item.First + 1));

   --  The whole encoding, header included.
   --
   --  This is the range to hash when verifying a signature: the signature was
   --  computed over the tag and length as well as the content.
   --  @param Item the element to inspect
   --  @return the first offset of the element's encoding
   function Encoded_First (Item : Element) return Offset
   is (Item.Header_First);

   --  See Encoded_First.
   --  @param Item the element to inspect
   --  @return the last offset of the element's encoding
   function Encoded_Last (Item : Element) return Offset
   is (Item.Last);

   --  Bounds a caller places on what it is willing to decode.
   --
   --  A certificate arrives from whoever offered it, so every one of these is
   --  a defence rather than a tuning knob. They are passed in rather than
   --  fixed here because the right bound differs between a TLS peer chain and
   --  a locally issued certificate.
   type Decode_Limits is record
      Maximum_Input_Size     : Natural;
      Maximum_Nesting_Depth  : Natural;
      Maximum_Sequence_Items : Natural;
      Maximum_String_Length  : Natural;
   end record;

   --  Bounds that comfortably admit real certificates and nothing else.
   --
   --  The nesting depth is the interesting one: a certificate with all its
   --  extensions nests around a dozen deep, so sixteen is room to spare while
   --  still refusing a structure built only to be deep.
   Default_Limits : constant Decode_Limits :=
     (Maximum_Input_Size     => 1024 * 1024,
      Maximum_Nesting_Depth  => 16,
      Maximum_Sequence_Items => 1024,
      Maximum_String_Length  => 64 * 1024);

end CryptoLib.ASN1;
