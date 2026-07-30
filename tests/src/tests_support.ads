with Ada.Streams;

--  Shared helpers for the cryptolib test suite: the assertion the
--  whole suite is built on, and the literal-to-octets conversions the
--  known-answer vectors are written with.
package Tests_Support is

   procedure Check (Condition : Boolean; Message : String);

   function Bytes_From_String
     (Value : String) return Ada.Streams.Stream_Element_Array;

   function Bytes_From_Hex
     (Value : String)
      return Ada.Streams.Stream_Element_Array;

   function Sequence_Data
     (Length : Natural)
      return Ada.Streams.Stream_Element_Array;

   function Decode_PEM_Body (Text : String) return String;

   function Index_Of (Haystack : String; Needle : String) return Natural;

end Tests_Support;
