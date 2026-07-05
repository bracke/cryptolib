with Ada.Streams;
with Interfaces;
with CryptoLib.Errors;

--  @summary RFC 4418 UMAC-64/128 message authentication as used by OpenSSH
--  (umac-64/umac-128, plain and encrypt-then-MAC variants).
package CryptoLib.UMAC is

   UMAC_Key_Length : constant Natural := 16;
   UMAC_64_Length  : constant Natural := 8;
   UMAC_128_Length : constant Natural := 16;

   subtype UMAC_Key_Index is Ada.Streams.Stream_Element_Offset range 1 ..
     Ada.Streams.Stream_Element_Offset (UMAC_Key_Length);
   subtype UMAC_Key is Ada.Streams.Stream_Element_Array (UMAC_Key_Index);

   --  Report whether Name_Text is one of the four OpenSSH UMAC MAC names.
   --  @param Name_Text the SSH MAC algorithm name to test
   --  @return True for umac-64/umac-128 (plain or -etm) @openssh.com names
   function Is_OpenSSH_UMAC_Name
     (Name_Text : String)
      return Boolean
      with SPARK_Mode => On;

   --  Report whether the named MAC is actually implemented by this package
   --  (currently identical to the set of recognized OpenSSH UMAC names).
   --  @param Name_Text the SSH MAC algorithm name to test
   --  @return True if Generate can produce a tag for this name
   function Is_Implemented
     (Name_Text : String)
      return Boolean
      with SPARK_Mode => On;

   --  Report whether the named MAC uses the encrypt-then-MAC (-etm) framing.
   --  @param Name_Text the SSH MAC algorithm name to test
   --  @return True for the umac-*-etm@openssh.com names
   function Is_EtM_Name
     (Name_Text : String)
      return Boolean
      with SPARK_Mode => On;

   --  Return the output tag length in bytes for the named UMAC algorithm.
   --  @param Name_Text the SSH MAC algorithm name to test
   --  @return 8 for umac-64, 16 for umac-128, 0 for an unrecognized name
   function Tag_Length
     (Name_Text : String)
      return Natural
      with SPARK_Mode => On;

   --  Compute a UMAC tag for Message_Data, building the 8-byte nonce from the
   --  big-endian SSH packet Sequence_Value (upper four bytes zero).
   --  @param Name_Text      the UMAC algorithm name (selects tag length)
   --  @param Key_Data       the 16-byte UMAC key
   --  @param Sequence_Value the SSH packet sequence number used as the nonce
   --  @param Message_Data   the message to authenticate
   --  @return the tag (8 or 16 bytes), or empty on invalid name/inputs
   function Generate
     (Name_Text       : String;
      Key_Data        : UMAC_Key;
      Sequence_Value  : Interfaces.Unsigned_32;
      Message_Data    : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array;

   --  As Generate, but with an explicit 8-byte nonce instead of a sequence
   --  number. Exposed for RFC 4418 known-answer testing (whose vectors use an
   --  arbitrary 8-byte nonce); Generate builds the nonce from Sequence_Value.
   --  @param Name_Text    the UMAC algorithm name (selects tag length)
   --  @param Key_Data     the 16-byte UMAC key
   --  @param Nonce        the 8-byte nonce; any other length yields empty output
   --  @param Message_Data the message to authenticate
   --  @return the tag (8 or 16 bytes), or empty on invalid name/inputs
   function Generate_With_Nonce
     (Name_Text    : String;
      Key_Data     : UMAC_Key;
      Nonce        : Ada.Streams.Stream_Element_Array;
      Message_Data : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array;

   --  Map a MAC name to the fail-closed negotiation status: unsupported for a
   --  recognized-but-unimplemented UMAC name, Ok for a usable UMAC name, and
   --  Handshake_Failed for any non-UMAC name.
   --  @param Name_Text the SSH MAC algorithm name to classify
   --  @return Ok, Unsupported_Feature, or Handshake_Failed as above
   function Fail_Closed_Status
     (Name_Text : String)
      return CryptoLib.Errors.Status
      with SPARK_Mode => On;
end CryptoLib.UMAC;
