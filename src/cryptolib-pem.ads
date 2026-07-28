with Ada.Streams;

--  @summary Decoding PEM armour into the DER it wraps.
--
--  Strict about what may appear between the armour lines: the base64
--  alphabet, padding, and whitespace, and nothing else. A decoder that
--  silently drops whatever it does not recognise will happily absorb a
--  preamble -- "keytool -rfc" names the alias first, "openssl x509 -text"
--  prints the whole certificate before the armour -- and hand back bytes that
--  decode to a different certificate, or to something that is not one. That
--  is a real failure this crate has already had once. Here it is a status
--  rather than a silent substitution.
--
--  Blocks are found by label and can be walked, so a chain in one file is
--  read by calling until No_Block_Found.
package CryptoLib.PEM is
   pragma Preelaborate;

   subtype Octets is Ada.Streams.Stream_Element_Array;
   subtype Offset is Ada.Streams.Stream_Element_Offset;

   type Decode_Status is
     (Ok,
      No_Block_Found,
      --  No block with the requested label begins at or after the position
      --  given. Not an error when walking a chain: it is how the walk ends.
      Malformed_Armour,
      --  A BEGIN line with no matching END line, or an END line naming a
      --  different label than the BEGIN it closes.
      Invalid_Base64,
      --  A character that is not base64, padding, or whitespace; or padding
      --  in a position where the encoding does not allow it.
      Buffer_Too_Small,
      --  The output buffer cannot hold the decoded block. Ask
      --  Maximum_Decoded_Length first.
      Empty_Block);
      --  The armour is well formed and encloses nothing.

   Certificate_Label : constant String := "CERTIFICATE";
   CSR_Label         : constant String := "CERTIFICATE REQUEST";
   Private_Key_Label : constant String := "PRIVATE KEY";
   Public_Key_Label  : constant String := "PUBLIC KEY";

   --  Render a decode status as short diagnostic text.
   --  @param Status the status to describe
   --  @return lower-case text naming the status
   function Status_Image (Status : Decode_Status) return String;

   --  An upper bound on the octets Text could decode to.
   --
   --  For sizing an output buffer before decoding. Deliberately generous: it
   --  counts every character, because counting exactly would mean scanning
   --  for the armour twice.
   --  @param Text the PEM text
   --  @return the largest number of octets a block within Text can yield
   function Maximum_Decoded_Length (Text : String) return Natural
   is (Text'Length / 4 * 3 + 3);

   --  Decode the next block carrying Label.
   --
   --  From is advanced past the block that was decoded, so the same call
   --  repeated walks every block in the text. On failure it is left where it
   --  was.
   --  @param Text the PEM text to read
   --  @param Label the armour label to look for, such as Certificate_Label
   --  @param From where to start looking; advanced past the block on success
   --  @param Output receives the decoded octets
   --  @param Last the last index of Output written, Output'First - 1 if none
   --  @param Status Ok on success, otherwise why the block was refused
   procedure Decode_Block
     (Text   : String;
      Label  : String;
      From   : in out Positive;
      Output : out Octets;
      Last   : out Offset;
      Status : out Decode_Status);

   --  How many blocks carrying Label does this text hold?
   --
   --  Counts armour only; it does not decode, so a well-formed BEGIN/END pair
   --  around invalid base64 still counts. For sizing a chain before reading it.
   --  @param Text the PEM text to inspect
   --  @param Label the armour label to count
   --  @return the number of blocks found
   function Block_Count (Text : String; Label : String) return Natural;

end CryptoLib.PEM;
