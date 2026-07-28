--  @summary Why a DER decode failed.
--
--  Kept apart from CryptoLib.Errors, whose statuses describe a cryptographic
--  operation rather than a parse. The distinction that matters most here is
--  between input this reader could not make sense of and input it understood
--  but declined to accept: a caller diagnosing interoperability needs to know
--  which of the two it is looking at, and "invalid" alone never says.
package CryptoLib.ASN1.Errors is
   pragma Preelaborate;

   type Decode_Status is
     (Ok,
      --  The element was decoded.
      Truncated_Input,
      --  The encoding claims more octets than the buffer holds.
      Invalid_Tag,
      --  A tag was read where a different one was required.
      Invalid_Length,
      --  The length octets are not a length.
      Non_Canonical_DER,
      --  A valid BER encoding that DER does not permit: a length or an
      --  integer that is not in its shortest form. Refused rather than
      --  accepted, because a certificate's identity is its bytes, and two
      --  encodings of one value give one certificate two identities.
      Excessive_Nesting,
      --  Deeper than the caller's limit allows.
      Size_Limit_Exceeded,
      --  Larger than the caller's limit allows.
      Unsupported_Encoding,
      --  A well-formed encoding this reader does not implement, such as the
      --  indefinite-length form. Distinct from malformed input.
      Invalid_Value,
      --  The encoding is structurally sound but the value is not one the type
      --  permits: a BOOLEAN outside {0, 255}, an OID that ends mid-arc.
      Trailing_Data);
      --  Decoding finished with octets left over where none were allowed.

   --  Render a decode status as short diagnostic text.
   --  @param Status the status to describe
   --  @return lower-case text naming the status
   function Status_Image (Status : Decode_Status) return String;

end CryptoLib.ASN1.Errors;
