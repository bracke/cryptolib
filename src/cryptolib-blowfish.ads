with Ada.Streams;
with Interfaces;

--  @summary The Blowfish cipher and the expensive key schedule that bcrypt is
--  built on.
--
--  This is machinery, not an interface anyone should reach for to encrypt
--  something. Blowfish has a 64-bit block, which puts a birthday bound at
--  about 32 GiB under one key, and there is no reason to choose it for new
--  work over AES or ChaCha20. It is here because bcrypt and OpenBSD's
--  bcrypt_pbkdf are both defined on it, and because two copies of a cipher in
--  one library is one copy more than anybody will keep correct.
--
--  Extracted from CryptoLib.BCrypt_PBKDF, which had it privately, when
--  CryptoLib.Bcrypt needed the same routines. Neither of those packages
--  should be understood as endorsing Blowfish as a cipher; they use its key
--  schedule because being slow is the point.
package CryptoLib.Blowfish is

   subtype Word_32 is Interfaces.Unsigned_32;

   P_Count : constant Natural := 18;
   S_Count : constant Natural := 1024;

   type P_Array is array (Natural range 0 .. P_Count - 1) of Word_32;
   type S_Array is array (Natural range 0 .. S_Count - 1) of Word_32;

   --  A key schedule in progress: the P array and the four S boxes.
   type Blowfish_State is record
      P_Data : P_Array := [others => 0];
      S_Data : S_Array := [others => 0];
   end record;

   --  Load the state with the constants Blowfish starts from.
   --  @param State_Item out: the state
   procedure Init_State (State_Item : out Blowfish_State)
     with SPARK_Mode => On;

   --  The expensive key schedule's keyed step: fold key and salt into the
   --  state, which is what makes bcrypt cost what it costs.
   --  @param State_Item in out: the state
   --  @param Salt_Data  the salt
   --  @param Key_Data   the key
   procedure Expand_State
     (State_Item : in out Blowfish_State;
      Salt_Data  : Ada.Streams.Stream_Element_Array;
      Key_Data   : Ada.Streams.Stream_Element_Array);

   --  The same step against a zero salt, which is the loop bcrypt repeats
   --  2**cost times.
   --  @param State_Item in out: the state
   --  @param Key_Data   the key
   procedure Expand_Zero_State
     (State_Item : in out Blowfish_State;
      Key_Data   : Ada.Streams.Stream_Element_Array);

   --  Encrypt words in place, in ECB, as a sequence of 64-bit blocks.
   --  @param State_Item the key schedule
   --  @param Data_Words in out: the words, two per block
   --  @param Pair_Count how many 64-bit blocks to encrypt
   procedure Encrypt_Words
     (State_Item : Blowfish_State;
      Data_Words : in out P_Array;
      Pair_Count : Natural);

   --  Read four octets as a big-endian word, wrapping around the end of the
   --  buffer, which is how both key schedules consume their material.
   --  @param Data   the octets
   --  @param Offset_Value in out: the cursor, advanced and wrapped
   --  @return the word
   function Stream_To_Word
     (Data : Ada.Streams.Stream_Element_Array; Offset_Value : in out Natural)
      return Word_32;

   --  Scrub a key schedule.
   --  @param Item out: the state, zeroed
   procedure Clear_State (Item : out Blowfish_State)
     with SPARK_Mode => On;

   --  Scrub a word array.
   --  @param Item out: the array, zeroed
   procedure Clear_P_Array (Item : out P_Array)
     with SPARK_Mode => On;

   --  Scrub an octet buffer.
   --  @param Item out: the buffer, zeroed
   procedure Clear_Stream_Array (Item : out Ada.Streams.Stream_Element_Array)
     with SPARK_Mode => On;

end CryptoLib.Blowfish;
