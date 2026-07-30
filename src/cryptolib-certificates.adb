with Ada.Characters.Handling;
with Ada.Strings.Fixed;

with CryptoLib.Ciphers;
with CryptoLib.ECDSA;
with CryptoLib.Ed25519;
with CryptoLib.Ed448;
with CryptoLib.RSA;
with CryptoLib.Errors;
with CryptoLib.Hashes;
with CryptoLib.Macs;
with CryptoLib.ASN1;
with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.Errors;
with CryptoLib.PEM;
with CryptoLib.PKCS10;
with CryptoLib.PKCS8;
with CryptoLib.X509.Signatures;
with CryptoLib.X509.Certificates;
with Ada.Calendar;
with Ada.Calendar.Formatting;
with CryptoLib.Random;

with CryptoLib.Secure_Wipe;

package body CryptoLib.Certificates is
   use Ada.Strings.Unbounded;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.Errors.Status;

   Hex : constant String := "0123456789abcdef";
   B64 : constant String :=
     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

   type Certificate_Profile is (CA_Profile, Server_Profile, Client_Profile,
                                Email_Profile);

   function Status_Image (Status : Certificate_Status) return String is
   begin
      case Status is
         when Ok =>
            return "ok";
         when Invalid_Input =>
            return "invalid input";
         when Unsupported_Profile =>
            return "unsupported profile";
         when Unsupported_Key_Algorithm =>
            return "unsupported key algorithm";
         when Internal_Error =>
            return "internal error";
      end case;
   end Status_Image;

   function Byte (Value : Natural) return Character is
   begin
      return Character'Val (Value mod 256);
   end Byte;

   function To_Bytes (Text : String) return Ada.Streams.Stream_Element_Array is
      Result : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Text'Length));
      Pos : Ada.Streams.Stream_Element_Offset := Result'First;
   begin
      for C of Text loop
         Result (Pos) := Ada.Streams.Stream_Element (Character'Pos (C));
         Pos := Pos + 1;
      end loop;
      return Result;
   end To_Bytes;

   function To_String
     (Data : Ada.Streams.Stream_Element_Array) return String
   is
      Result : String (1 .. Natural (Data'Length));
      Pos    : Positive := Result'First;
   begin
      for B of Data loop
         Result (Pos) := Byte (Natural (B));
         Pos := Pos + 1;
      end loop;
      return Result;
   end To_String;

   procedure Append_Line (Target : in out Unbounded_String; Line : String) is
   begin
      Append (Target, Line);
      Append (Target, ASCII.LF);
   end Append_Line;

   function Hex_Image
     (Data : Ada.Streams.Stream_Element_Array) return String
   is
      Result : String (1 .. Data'Length * 2);
      Pos    : Positive := Result'First;
   begin
      for B of Data loop
         Result (Pos) := Hex (Natural (B) / 16 + 1);
         Result (Pos + 1) := Hex (Natural (B) mod 16 + 1);
         Pos := Pos + 2;
      end loop;
      return Result;
   end Hex_Image;

   function Digest_Hex (Text : String) return String is
   begin
      return Hex_Image
        (Ada.Streams.Stream_Element_Array
           (CryptoLib.Hashes.SHA256 (To_Bytes (Text))));
   end Digest_Hex;

   --  A DER length, in the shortest form that holds it.
   --
   --  The long form used to stop at two octets, and Byte truncates rather
   --  than complains, so a structure longer than 65_535 was given a length
   --  with its high bits quietly dropped. Nothing rejected it: issuance
   --  reported Ok and handed back a certificate no parser could read. A
   --  subject alternative name list is unbounded, so reaching that size takes
   --  a caller with a lot of names and no warning that anything is wrong.
   function DER_Length (Length : Natural) return String is
   begin
      if Length < 128 then
         return "" & Byte (Length);
      end if;

      declare
         Digits_Out : String (1 .. 4);
         First      : Natural := Digits_Out'Last;
         Rest       : Natural := Length;
      begin
         Digits_Out (First) := Byte (Rest mod 256);
         Rest := Rest / 256;
         while Rest > 0 loop
            First := First - 1;
            Digits_Out (First) := Byte (Rest mod 256);
            Rest := Rest / 256;
         end loop;

         return Byte (16#80# + (Digits_Out'Last - First + 1))
                & Digits_Out (First .. Digits_Out'Last);
      end;
   end DER_Length;

   function TLV (Tag : Natural; Content : String) return String is
   begin
      return Byte (Tag) & DER_Length (Content'Length) & Content;
   end TLV;

   function Seq (Content : String) return String is (TLV (16#30#, Content));
   function Set_Of (Content : String) return String is (TLV (16#31#, Content));
   function Octets (Content : String) return String is (TLV (16#04#, Content));
   function Bits (Content : String) return String is (TLV (16#03#, Byte (0) & Content));
   function Explicit (Tag : Natural; Content : String) return String is
     (TLV (16#A0# + Tag, Content));
   function Bool (Value : Boolean) return String is
     (TLV (16#01#, "" & (if Value then Byte (16#FF#) else Byte (0))));
   function UTF8 (Value : String) return String is (TLV (16#0C#, Value));
   function UTC (Value : String) return String is (TLV (16#17#, Value));

   --  A non-negative INTEGER in the shortest form DER permits.
   --
   --  The previous shape emitted a fixed four octets for anything at or
   --  above 16#8000#, so 600_000 came out as 00 09 27 C0 -- a leading zero
   --  octet that DER allows only when the next one would otherwise read as
   --  negative. Nothing encoded a value in that range until something did,
   --  and then this crate wrote a bundle its own reader refused. The bound
   --  is the same one the decoder enforces, so the two now agree by
   --  construction rather than by luck.
   function Integer_DER (Value : Natural) return String is
      Content : String (1 .. 5);
      First   : Natural := Content'Last;
      Rest    : Natural := Value;
   begin
      --  Least significant octet first, keeping at least one.
      Content (First) := Byte (Rest mod 256);
      Rest := Rest / 256;
      while Rest > 0 loop
         First := First - 1;
         Content (First) := Byte (Rest mod 256);
         Rest := Rest / 256;
      end loop;

      --  A leading octet at or above 16#80# would read as a negative
      --  number, so a zero goes in front of it -- and only then.
      if Character'Pos (Content (First)) >= 16#80# then
         First := First - 1;
         Content (First) := Byte (0);
      end if;

      return TLV (16#02#, Content (First .. Content'Last));
   end Integer_DER;

   function OID (Content : String) return String is
   begin
      return TLV (16#06#, Content);
   end OID;

   function OID_Data return String is
   begin
      return OID
        (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#86#)
         & Byte (16#F7#) & Byte (16#0D#) & Byte (16#01#) & Byte (16#07#)
         & Byte (16#01#));
   end OID_Data;

   function OID_Shrouded_Key_Bag return String is
   begin
      return OID
        (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#86#)
         & Byte (16#F7#) & Byte (16#0D#) & Byte (16#01#) & Byte (16#0C#)
         & Byte (16#0A#) & Byte (16#01#) & Byte (16#02#));
   end OID_Shrouded_Key_Bag;

   function OID_Cert_Bag return String is
   begin
      return OID
        (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#86#)
         & Byte (16#F7#) & Byte (16#0D#) & Byte (16#01#) & Byte (16#0C#)
         & Byte (16#0A#) & Byte (16#01#) & Byte (16#03#));
   end OID_Cert_Bag;

   function OID_X509_Certificate return String is
   begin
      return OID
        (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#86#)
         & Byte (16#F7#) & Byte (16#0D#) & Byte (16#01#) & Byte (16#09#)
         & Byte (16#16#) & Byte (16#01#));
   end OID_X509_Certificate;

   function OID_SHA1 return String is
   begin
      return OID
        (Byte (16#2B#) & Byte (16#0E#) & Byte (16#03#) & Byte (16#02#)
         & Byte (16#1A#));
   end OID_SHA1;

   function OID_PBES2 return String is
   begin
      return OID
        (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#86#)
         & Byte (16#F7#) & Byte (16#0D#) & Byte (16#01#) & Byte (16#05#)
         & Byte (16#0D#));
   end OID_PBES2;

   function OID_PBKDF2 return String is
   begin
      return OID
        (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#86#)
         & Byte (16#F7#) & Byte (16#0D#) & Byte (16#01#) & Byte (16#05#)
         & Byte (16#0C#));
   end OID_PBKDF2;

   function OID_HMAC_SHA256 return String is
   begin
      return OID
        (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#86#)
         & Byte (16#F7#) & Byte (16#0D#) & Byte (16#02#) & Byte (16#09#));
   end OID_HMAC_SHA256;

   function OID_AES_256_CBC return String is
   begin
      return OID
        (Byte (16#60#) & Byte (16#86#) & Byte (16#48#) & Byte (16#01#)
         & Byte (16#65#) & Byte (16#03#) & Byte (16#04#) & Byte (16#01#)
         & Byte (16#2A#));
   end OID_AES_256_CBC;

   --  1.3.101.112 id-Ed25519
   function Ed25519_Algorithm return String is
   begin
      return Seq (OID (Byte (16#2B#) & Byte (16#65#) & Byte (16#70#)));
   end Ed25519_Algorithm;

   --  1.2.840.10045.2.1 id-ecPublicKey with 1.3.132.0.34 secp384r1: an EC key
   --  states its curve, where an Ed25519 key is only ever one thing.
   function P384_Algorithm return String is
   begin
      return Seq
        (OID (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#CE#)
              & Byte (16#3D#) & Byte (16#02#) & Byte (16#01#))
         & OID (Byte (16#2B#) & Byte (16#81#) & Byte (16#04#) & Byte (16#00#)
                & Byte (16#22#)));
   end P384_Algorithm;

   --  1.2.840.10045.4.3.3 ecdsa-with-SHA384. The signature algorithm is its
   --  own identifier here: Ed25519 names the hash inside the scheme, ECDSA
   --  pairs a curve with a digest and has to say which.
   function P384_Signature_Algorithm return String is
   begin
      return Seq
        (OID (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#CE#)
              & Byte (16#3D#) & Byte (16#04#) & Byte (16#03#) & Byte (16#03#)));
   end P384_Signature_Algorithm;

   --  1.2.840.10045.2.1 id-ecPublicKey with 1.2.840.10045.3.1.7 prime256v1.
   function P256_Algorithm return String is
   begin
      return Seq
        (OID (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#CE#)
              & Byte (16#3D#) & Byte (16#02#) & Byte (16#01#))
         & OID (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#CE#)
                & Byte (16#3D#) & Byte (16#03#) & Byte (16#01#)
                & Byte (16#07#)));
   end P256_Algorithm;

   --  1.2.840.10045.4.3.2 ecdsa-with-SHA256.
   function P256_Signature_Algorithm return String is
   begin
      return Seq
        (OID (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#CE#)
              & Byte (16#3D#) & Byte (16#04#) & Byte (16#03#) & Byte (16#02#)));
   end P256_Signature_Algorithm;

   --  The salt length PSS signatures here use, matching the digest's own
   --  length as everything in practice does.
   RSA_PSS_Salt_Length : constant := 32;

   --  1.2.840.113549.1.1.1 rsaEncryption, with the explicit NULL parameters
   --  RFC 3279 requires.
   --
   --  Included because the RFC says so, not because anything here proves it
   --  matters: dropping the NULL and re-running the suite changes nothing,
   --  because OpenSSL accepts a certificate whose rsaEncryption identifier
   --  omits it. So no test guards this, and saying so beats implying one does.
   function RSA_Algorithm return String is
   begin
      return Seq
        (OID (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#86#)
              & Byte (16#F7#) & Byte (16#0D#) & Byte (16#01#) & Byte (16#01#)
              & Byte (16#01#))
         & Byte (16#05#) & Byte (16#00#));
   end RSA_Algorithm;

   --  1.2.840.113549.1.1.11 sha256WithRSAEncryption, also with NULL params.
   function RSA_Signature_Algorithm return String is
   begin
      return Seq
        (OID (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#86#)
              & Byte (16#F7#) & Byte (16#0D#) & Byte (16#01#) & Byte (16#01#)
              & Byte (16#0B#))
         & Byte (16#05#) & Byte (16#00#));
   end RSA_Signature_Algorithm;

   --  1.2.840.113549.1.1.10 id-RSASSA-PSS, with the parameters spelled out.
   --
   --  PSS carries which hash, which mask generation function and how long a
   --  salt in the algorithm identifier rather than in its name, so the whole
   --  block has to be built and has to appear identically in the signed body
   --  and beside the signature -- a verifier that finds them differing refuses
   --  the certificate.
   --
   --  These bytes were taken from a certificate OpenSSL signed with
   --  -sigopt rsa_padding_mode:pss and compared octet for octet, rather than
   --  assembled from the RFC and hoped over. RFC 4055 permits the hash's own
   --  parameters to be absent; OpenSSL writes an explicit NULL, and matching
   --  what it writes is what keeps the two agreeing. The trailer field is left
   --  out because its only legal value is the default.
   function RSA_PSS_Signature_Algorithm return String is
      SHA256_Identifier : constant String :=
        Seq (OID (Byte (16#60#) & Byte (16#86#) & Byte (16#48#)
                  & Byte (16#01#) & Byte (16#65#) & Byte (16#03#)
                  & Byte (16#04#) & Byte (16#02#) & Byte (16#01#))
             & Byte (16#05#) & Byte (16#00#));
      MGF1_Identifier : constant String :=
        Seq (OID (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#)
                  & Byte (16#86#) & Byte (16#F7#) & Byte (16#0D#)
                  & Byte (16#01#) & Byte (16#01#) & Byte (16#08#))
             & SHA256_Identifier);
   begin
      return Seq
        (OID (Byte (16#2A#) & Byte (16#86#) & Byte (16#48#) & Byte (16#86#)
              & Byte (16#F7#) & Byte (16#0D#) & Byte (16#01#) & Byte (16#01#)
              & Byte (16#0A#))
         & Seq (Explicit (0, SHA256_Identifier)
                & Explicit (1, MGF1_Identifier)
                & Explicit (2, Integer_DER (RSA_PSS_Salt_Length))));
   end RSA_PSS_Signature_Algorithm;

   --  1.3.101.113 id-Ed448. Like Ed25519 it names the hash inside the
   --  scheme, so the key and the signature share one identifier.
   function Ed448_Algorithm return String is
   begin
      return Seq (OID (Byte (16#2B#) & Byte (16#65#) & Byte (16#71#)));
   end Ed448_Algorithm;

   function Algorithm_Identifier
     (Algorithm : Key_Algorithm := Ed25519_Key) return String is
   begin
      return (case Algorithm is
                 when Ed25519_Key => Ed25519_Algorithm,
                 when P256_Key    => P256_Algorithm,
                 when P384_Key    => P384_Algorithm,
                 when Ed448_Key   => Ed448_Algorithm,
                 when RSA_Key     => RSA_Algorithm);
   end Algorithm_Identifier;

   --  Use_PSS only means anything for RSA: every other algorithm here has one
   --  signature scheme, and PSS is a second way to sign with an RSA key rather
   --  than a second kind of key.
   function Signature_Algorithm
     (Algorithm : Key_Algorithm; Use_PSS : Boolean := False) return String is
   begin
      return (case Algorithm is
                 when Ed25519_Key => Ed25519_Algorithm,
                 when P256_Key    => P256_Signature_Algorithm,
                 when P384_Key    => P384_Signature_Algorithm,
                 when Ed448_Key   => Ed448_Algorithm,
                 when RSA_Key     =>
                   (if Use_PSS
                    then RSA_PSS_Signature_Algorithm
                    else RSA_Signature_Algorithm));
   end Signature_Algorithm;

   --  How wide the private and public halves are for each algorithm, in one
   --  place, so that adding a third did not mean finding every "if it is EC
   --  then 48 else 32" scattered through the issuing paths.
   function Seed_Length_For
     (Algorithm : Generatable_Key_Algorithm) return Positive
   is (case Algorithm is
          when Ed25519_Key => 32,
          when P256_Key    => 32,
          when P384_Key    => 48,
          when Ed448_Key   => 57);

   function Public_Length_For
     (Algorithm : Generatable_Key_Algorithm) return Positive
   is (case Algorithm is
          when Ed25519_Key => 32,
          when P256_Key    => 65,
          when P384_Key    => 97,
          when Ed448_Key   => 57);

   --  DER INTEGER from a big-endian magnitude: leading zeros are not part of
   --  the value, and a top bit that is set needs a zero byte in front or the
   --  integer reads as negative.
   function Integer_From_Bytes (Value : String) return String is
      First : Natural := Value'First;
   begin
      while First < Value'Last and then Value (First) = Character'Val (0) loop
         First := First + 1;
      end loop;

      if Character'Pos (Value (First)) >= 16#80# then
         return TLV (16#02#, Byte (0) & Value (First .. Value'Last));
      end if;
      return TLV (16#02#, Value (First .. Value'Last));
   end Integer_From_Bytes;

   --  How many octets of randomness a serial number carries.
   --
   --  A serial has to be unique per issuer, because a revocation names a
   --  certificate by issuer and serial and by nothing else: two certificates
   --  sharing one cannot be revoked apart. Uniqueness by counting would mean
   --  keeping state across calls, which this has nowhere to put, so it is
   --  bought with entropy instead -- at this width a collision is not
   --  something that happens. The width also puts the serial out of reach of
   --  an attacker who wants to predict it, which is what a chosen-prefix
   --  collision against the signature hash would need.
   Serial_Octets : constant := 16;

   --  Draw a serial. Empty when the source could not supply bytes, which the
   --  caller must treat as a failure rather than fall back on something
   --  predictable.
   function Random_Serial
     (Source : in out CryptoLib.Random.Random_Source) return String
   is
      Bytes : Ada.Streams.Stream_Element_Array (1 .. Serial_Octets);
      Text  : String (1 .. Serial_Octets);
   begin
      if CryptoLib.Random.Fill (Source, Bytes) /= CryptoLib.Errors.Ok then
         return "";
      end if;

      --  Positive, and with no leading zero octet to strip: RFC 5280 requires
      --  a positive serial, and clearing the top bit gives one without the
      --  encoder having to pad. Forcing the low bit keeps the first octet
      --  non-zero so the encoding stays minimal at its full width.
      Bytes (Bytes'First) :=
        Ada.Streams."or"
          (Ada.Streams."and" (Bytes (Bytes'First), 16#7F#), 16#01#);

      for I in Text'Range loop
         Text (I) :=
           Character'Val
             (Bytes (Bytes'First + Ada.Streams.Stream_Element_Offset (I - 1)));
      end loop;
      return Text;
   end Random_Serial;

   function Name_DER (Common_Name : String) return String is
   begin
      return Seq
        (Set_Of
           (Seq
              (OID (Byte (16#55#) & Byte (16#04#) & Byte (16#03#))
               & UTF8 (Common_Name))));
   end Name_DER;

   --  A time as X.509 writes it.
   --
   --  UTCTime carries a two-digit year and is only unambiguous through 2049,
   --  so anything at or beyond 2050 goes out as GeneralizedTime. RFC 5280
   --  requires exactly that switch, and hardcoding one form is how a
   --  certificate generator acquires an expiry date of its own.
   function Time_DER (Value : Ada.Calendar.Time) return String is
      Year   : Ada.Calendar.Year_Number;
      Month  : Ada.Calendar.Month_Number;
      Day    : Ada.Calendar.Day_Number;
      Hour   : Ada.Calendar.Formatting.Hour_Number;
      Minute : Ada.Calendar.Formatting.Minute_Number;
      Second : Ada.Calendar.Formatting.Second_Number;
      Sub    : Ada.Calendar.Formatting.Second_Duration;
      Leap   : Boolean;

      function Pair (Number : Natural) return String is
         Text : constant String := Natural'Image (Number mod 100);
      begin
         return
           (if Number mod 100 < 10 then "0" & Text (Text'Last)
            else Text (Text'Last - 1 .. Text'Last));
      end Pair;
   begin
      --  Split in UTC: a certificate's times carry no zone, so writing local
      --  time would state an instant the certificate does not mean.
      Ada.Calendar.Formatting.Split
        (Value, Year, Month, Day, Hour, Minute, Second, Sub, Leap,
         Time_Zone => 0);

      declare
         Body_Text : constant String :=
           Pair (Month) & Pair (Day) & Pair (Hour) & Pair (Minute)
           & Pair (Second) & "Z";
      begin
         if Year < 2050 then
            return UTC (Pair (Year) & Body_Text);
         end if;

         --  GeneralizedTime, tag 24, with the full year.
         declare
            Full : constant String := Natural'Image (Year);
         begin
            return TLV
              (16#18#,
               Full (Full'Last - 3 .. Full'Last) & Body_Text);
         end;
      end;
   end Time_DER;

   --  The validity window of a certificate being issued now.
   --
   --  Backdated slightly because the issuer's clock and the verifier's are
   --  not the same clock: a certificate stamped to the second is not yet
   --  valid for anyone running a little behind.
   Clock_Skew_Allowance : constant Duration := 3600.0;

   --  Not_After_Limit is the issuer's own expiry, when there is an issuer.
   --
   --  A certificate must not claim to be valid past the certificate that
   --  signed it: the moment the issuer expires the chain stops verifying, so
   --  the extra time is time the certificate says it has and does not. This
   --  crate already computes the window from the clock rather than writing a
   --  fixed decade into the source, for the same reason -- a certificate
   --  should not state a validity it will not have.
   function Validity_DER
     (Valid_Days      : Positive;
      Limit_Present   : Boolean := False;
      Not_After_Limit : Ada.Calendar.Time := Ada.Calendar.Clock)
      return String
   is
      use type Ada.Calendar.Time;
      Now  : constant Ada.Calendar.Time := Ada.Calendar.Clock;
      From : constant Ada.Calendar.Time := Now - Clock_Skew_Allowance;
      Want : constant Ada.Calendar.Time :=
        Now + Duration (Valid_Days) * 86_400.0;
      Till : constant Ada.Calendar.Time :=
        (if Limit_Present and then Not_After_Limit < Want
         then Not_After_Limit else Want);
   begin
      return Seq (Time_DER (From) & Time_DER (Till));
   end Validity_DER;

   function SPKI_DER
     (Public_Key : Ada.Streams.Stream_Element_Array;
      Algorithm  : Key_Algorithm := Ed25519_Key) return String is
   begin
      return Seq
        (Algorithm_Identifier (Algorithm) & Bits (To_String (Public_Key)));
   end SPKI_DER;

   function Private_Key_DER
     (Seed      : Ada.Streams.Stream_Element_Array;
      Algorithm : Key_Algorithm := Ed25519_Key) return String
   is
   begin
      return Seq
        (Integer_DER (0)
         & Algorithm_Identifier (Algorithm)
         & Octets (Octets (To_String (Seed))));
   end Private_Key_DER;

   --  PKCS#8 around an RFC 5915 ECPrivateKey. The inner structure carries the
   --  public point as well: a reader that has only the scalar would otherwise
   --  have to multiply to learn the key it belongs to.
   function EC_Private_Key_DER
     (Scalar       : Ada.Streams.Stream_Element_Array;
      Public       : Ada.Streams.Stream_Element_Array;
      Algorithm_ID : String) return String
   is
      Inner : constant String :=
        Seq
          (Integer_DER (1)
           & Octets (To_String (Scalar))
           & Explicit (1, Bits (To_String (Public))));
   begin
      return Seq
        (Integer_DER (0) & Algorithm_ID & Octets (Inner));
   end EC_Private_Key_DER;

   function Mac_Data
     (Authenticated_Safe : String;
      Password           : String;
      Salt               : Ada.Streams.Stream_Element_Array;
      Iterations         : Positive) return String
   is
      Key        : constant Ada.Streams.Stream_Element_Array :=
        CryptoLib.Macs.PKCS12_KDF_SHA1
          --  The plain password: PKCS12_KDF_SHA1 widens it to a BMPString
          --  itself, and handing it one already widened produced a key for a
          --  password nobody typed -- so every bundle failed its own MAC check.
          (Password_Data => To_Bytes (Password),
           Salt_Data     => Salt,
           Iterations    => Iterations,
           Id_Byte       => 3,
           Output_Length => 20);
      Tag        : constant CryptoLib.Macs.HMAC_SHA1_Digest :=
        CryptoLib.Macs.HMAC_SHA1 (Key, To_Bytes (Authenticated_Safe));
      Digest_Info : constant String :=
        Seq
          (Seq (OID_SHA1 & TLV (16#05#, ""))
           & Octets (To_String (Ada.Streams.Stream_Element_Array (Tag))));
   begin
      return Seq
        (Digest_Info & Octets (To_String (Salt)) & Integer_DER (Iterations));
   end Mac_Data;

   function PKCS7_Pad
     (Data       : String;
      Block_Size : Positive) return Ada.Streams.Stream_Element_Array
   is
      Pad_Length : constant Positive :=
        (if Data'Length mod Block_Size = 0
         then Block_Size
         else Block_Size - (Data'Length mod Block_Size));
      Result : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Data'Length + Pad_Length));
      Pos : Ada.Streams.Stream_Element_Offset := Result'First;
   begin
      for C of Data loop
         Result (Pos) := Ada.Streams.Stream_Element (Character'Pos (C));
         Pos := Pos + 1;
      end loop;
      for Index_Value in 1 .. Pad_Length loop
         pragma Unreferenced (Index_Value);
         Result (Pos) := Ada.Streams.Stream_Element (Pad_Length);
         Pos := Pos + 1;
      end loop;
      return Result;
   end PKCS7_Pad;

   function PBES2_AES_256_CBC_Algorithm
     (Salt       : Ada.Streams.Stream_Element_Array;
      Iterations : Positive;
      IV_Data    : Ada.Streams.Stream_Element_Array) return String
   is
      PBKDF2_Params : constant String :=
        Seq
          (Octets (To_String (Salt))
           & Integer_DER (Iterations)
           & Integer_DER (32)
           & Seq (OID_HMAC_SHA256 & TLV (16#05#, "")));
      KDF_Algorithm : constant String := Seq (OID_PBKDF2 & PBKDF2_Params);
      Enc_Algorithm : constant String :=
        Seq (OID_AES_256_CBC & Octets (To_String (IV_Data)));
   begin
      return Seq (OID_PBES2 & Seq (KDF_Algorithm & Enc_Algorithm));
   end PBES2_AES_256_CBC_Algorithm;

   function Base64_Encode (Data : String) return String is
      Result : Unbounded_String;
      I      : Natural := Data'First;
      B1     : Natural;
      B2     : Natural;
      B3     : Natural;
      Count  : Natural;
   begin
      while I <= Data'Last loop
         B1 := Character'Pos (Data (I));
         B2 := 0;
         B3 := 0;
         Count := 1;
         if I + 1 <= Data'Last then
            B2 := Character'Pos (Data (I + 1));
            Count := 2;
         end if;
         if I + 2 <= Data'Last then
            B3 := Character'Pos (Data (I + 2));
            Count := 3;
         end if;
         Append (Result, B64 (B1 / 4 + 1));
         Append (Result, B64 (((B1 mod 4) * 16) + (B2 / 16) + 1));
         Append
           (Result,
            (if Count >= 2 then B64 (((B2 mod 16) * 4) + (B3 / 64) + 1)
             else '='));
         Append (Result, (if Count = 3 then B64 (B3 mod 64 + 1) else '='));
         I := I + 3;
      end loop;
      return To_String (Result);
   end Base64_Encode;

   function PEM (Label : String; DER : String) return Unbounded_String is
      Encoded : constant String := Base64_Encode (DER);
      Result  : Unbounded_String;
      I       : Natural := Encoded'First;
      Last    : Natural;
   begin
      Append_Line (Result, "-----BEGIN " & Label & "-----");
      while I <= Encoded'Last loop
         Last := Natural'Min (Encoded'Last, I + 63);
         Append_Line (Result, Encoded (I .. Last));
         I := Last + 1;
      end loop;
      Append_Line (Result, "-----END " & Label & "-----");
      return Result;
   end PEM;

   function Base64_Value (C : Character) return Integer is
   begin
      if C in 'A' .. 'Z' then
         return Character'Pos (C) - Character'Pos ('A');
      elsif C in 'a' .. 'z' then
         return Character'Pos (C) - Character'Pos ('a') + 26;
      elsif C in '0' .. '9' then
         return Character'Pos (C) - Character'Pos ('0') + 52;
      elsif C = '+' then
         return 62;
      elsif C = '/' then
         return 63;
      else
         return -1;
      end if;
   end Base64_Value;

   --  Decode the first armoured block in Text.
   --
   --  Delegates to CryptoLib.PEM, which permits only base64, padding and
   --  whitespace between the armour lines. The decoder this replaced skipped
   --  anything it did not recognise, so a preamble -- keytool naming the
   --  alias, openssl -text printing the certificate first -- was swept into
   --  the payload and decoded to something else entirely. That was a real
   --  failure here, fixed once by moving where the scan started; this removes
   --  the class of it rather than the instance.
   --
   --  Which block is chosen is unchanged: the first one, whatever its label.
   --  The label is read from the armour and required to close the block, so a
   --  BEGIN CERTIFICATE ending in END PRIVATE KEY is now refused rather than
   --  quietly decoded.
   function Base64_Decode (Text : String) return String is
      use type CryptoLib.PEM.Decode_Status;

      Opening : constant String := "-----BEGIN ";
      Head    : constant Natural :=
        Ada.Strings.Fixed.Index (Text, Opening);
      Tail    : Natural;
   begin
      if Head = 0 then
         return "";
      end if;

      Tail :=
        Ada.Strings.Fixed.Index
          (Text (Head + Opening'Length .. Text'Last), "-----");
      if Tail = 0 then
         return "";
      end if;

      declare
         Label  : constant String :=
           Text (Head + Opening'Length .. Tail - 1);
         Buffer : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CryptoLib.PEM.Maximum_Decoded_Length (Text)));
         Last   : Ada.Streams.Stream_Element_Offset;
         From   : Positive := Text'First;
         Status : CryptoLib.PEM.Decode_Status;
      begin
         if Label'Length = 0 then
            return "";
         end if;

         CryptoLib.PEM.Decode_Block
           (Text, Label, From, Buffer, Last, Status);
         if Status /= CryptoLib.PEM.Ok then
            return "";
         end if;

         declare
            Result : String (1 .. Natural (Last - Buffer'First + 1));
         begin
            for I in Result'Range loop
               Result (I) :=
                 Character'Val
                   (Buffer (Buffer'First
                            + Ada.Streams.Stream_Element_Offset (I - 1)));
            end loop;
            return Result;
         end;
      end;
   end Base64_Decode;

   function Contains (Data : String; Needle : String) return Boolean;

   --  Which algorithm a private key PEM carries. An Ed25519 key is only ever
   --  one thing; an EC key names its curve, so the curve OID in the DER is the
   --  discriminator.
   --  Decode a private key from its armour, once, for the three questions
   --  below to share.
   --
   --  These used to scan the encoding for the two bytes that introduce an
   --  octet string of the right length and take what followed. What that
   --  finds depends on what the key happens to contain, so valid keys were
   --  read wrongly or refused according to their own bytes -- a P-384 key
   --  generated by OpenSSL failed more often than it worked. This decodes the
   --  structure instead.
   procedure Decode_Private_Key
     (Private_Key_PEM : String;
      Item            : out CryptoLib.PKCS8.Private_Key;
      Ok_Out          : out Boolean)
   is
      use type CryptoLib.ASN1.Errors.Decode_Status;

      DER : constant String := Base64_Decode (Private_Key_PEM);
   begin
      Ok_Out := False;
      if DER'Length = 0 then
         return;
      end if;

      declare
         Raw : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (DER'Length));
         Status : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         for I in DER'Range loop
            Raw (Ada.Streams.Stream_Element_Offset (I - DER'First + 1)) :=
              Character'Pos (DER (I));
         end loop;

         CryptoLib.PKCS8.Decode_DER
           (Raw, CryptoLib.ASN1.Default_Limits, Item, Status);
         Ok_Out := Status = CryptoLib.ASN1.Errors.Ok
           and then CryptoLib.PKCS8.Is_Present (Item);
      end;
   end Decode_Private_Key;

   function Algorithm_Of_Private_Key (Private_Key_PEM : String) return Key_Algorithm is
      use type CryptoLib.X509.Public_Key_Algorithm;

      Item   : CryptoLib.PKCS8.Private_Key;
      Parsed : Boolean;
   begin
      Decode_Private_Key (Private_Key_PEM, Item, Parsed);
      if not Parsed then
         return Ed25519_Key;
      end if;

      return (if CryptoLib.PKCS8.Algorithm_Of (Item)
                   = CryptoLib.X509.ECDSA_P256
              then P256_Key
              elsif CryptoLib.PKCS8.Algorithm_Of (Item)
                   = CryptoLib.X509.ECDSA_P384
              then P384_Key
              elsif CryptoLib.PKCS8.Algorithm_Of (Item)
                   = CryptoLib.X509.Ed448
              then Ed448_Key
              elsif CryptoLib.PKCS8.Algorithm_Of (Item) = CryptoLib.X509.RSA
              then RSA_Key
              else Ed25519_Key);
   end Algorithm_Of_Private_Key;

   --  A CA's key material, held in a slot wide enough for any of them with the
   --  used length attached.
   --
   --  The widths here do not come from the algorithm's name. An Ed25519 seed is
   --  32 octets and a 4096-bit RSA private exponent is 512, and the only way to
   --  know which is to have parsed the key. CryptoLib.EC_Curves does the same
   --  thing for the three prime curves, whose moduli share one 66-octet slot
   --  with a length beside them.
   --
   --  The length lives in the record rather than in a separate variable
   --  because a slot and a loose length invite reading the whole slot where
   --  only a prefix means anything, and that class of mistake has cost real
   --  time in this crate. Value is the only way to read it.
   Max_CA_Private : constant := 512;   --  d for a 4096-bit modulus
   Max_CA_Public  : constant := 600;   --  RSAPublicKey DER at that size

   type CA_Private_Material is record
      Slot : Ada.Streams.Stream_Element_Array (1 .. Max_CA_Private) :=
        [others => 0];
      Used : Ada.Streams.Stream_Element_Offset := 0;
   end record;

   --  An RSA CA's CRT parameters, when its key file carries them. All five or
   --  none: signing with a partial set is not a thing.
   type CA_CRT_Material is record
      P, Q, DP, DQ, QI :
        Ada.Streams.Stream_Element_Array (1 .. Max_CA_Private) :=
          [others => 0];
      Used  : Ada.Streams.Stream_Element_Offset := 0;
      Ready : Boolean := False;
   end record;

   type CA_Public_Material is record
      Slot : Ada.Streams.Stream_Element_Array (1 .. Max_CA_Public) :=
        [others => 0];
      Used : Ada.Streams.Stream_Element_Offset := 0;
   end record;

   function Value (Item : CA_Private_Material)
     return Ada.Streams.Stream_Element_Array
   is (Item.Slot (1 .. Item.Used));

   function Value (Item : CA_Public_Material)
     return Ada.Streams.Stream_Element_Array
   is (Item.Slot (1 .. Item.Used));

   --  Each CRT value at the width they share, which is half the modulus.
   function CRT_P (Item : CA_CRT_Material)
     return Ada.Streams.Stream_Element_Array
   is (if Item.Ready then Item.P (1 .. Item.Used) else [1 .. 0 => 0]);
   function CRT_Q (Item : CA_CRT_Material)
     return Ada.Streams.Stream_Element_Array
   is (if Item.Ready then Item.Q (1 .. Item.Used) else [1 .. 0 => 0]);
   function CRT_DP (Item : CA_CRT_Material)
     return Ada.Streams.Stream_Element_Array
   is (if Item.Ready then Item.DP (1 .. Item.Used) else [1 .. 0 => 0]);
   function CRT_DQ (Item : CA_CRT_Material)
     return Ada.Streams.Stream_Element_Array
   is (if Item.Ready then Item.DQ (1 .. Item.Used) else [1 .. 0 => 0]);
   function CRT_QI (Item : CA_CRT_Material)
     return Ada.Streams.Stream_Element_Array
   is (if Item.Ready then Item.QI (1 .. Item.Used) else [1 .. 0 => 0]);

   --  Drop leading zero octets, which a DER INTEGER's contents may carry and
   --  which are not part of the value.
   function Significant (Bytes : Ada.Streams.Stream_Element_Array)
     return Ada.Streams.Stream_Element_Array
   is
      use type Ada.Streams.Stream_Element;
      First : Ada.Streams.Stream_Element_Offset := Bytes'First;
   begin
      while First <= Bytes'Last
        and then Bytes (First) = 0
      loop
         First := First + 1;
      end loop;
      return Bytes (First .. Bytes'Last);
   end Significant;

   --  Place a value in a slot, refusing one too wide rather than truncating it.
   --  A truncated private exponent would sign, and produce signatures nothing
   --  verifies.
   function Place
     (Item  : out CA_Private_Material;
      Bytes : Ada.Streams.Stream_Element_Array) return Boolean is
   begin
      Item.Slot := [others => 0];
      Item.Used := 0;
      if Bytes'Length = 0 or else Bytes'Length > Max_CA_Private then
         return False;
      end if;
      Item.Slot (1 .. Bytes'Length) := Bytes;
      Item.Used := Bytes'Length;
      return True;
   end Place;

   function Place
     (Item  : out CA_Public_Material;
      Bytes : Ada.Streams.Stream_Element_Array) return Boolean is
   begin
      Item.Slot := [others => 0];
      Item.Used := 0;
      if Bytes'Length = 0 or else Bytes'Length > Max_CA_Public then
         return False;
      end if;
      Item.Slot (1 .. Bytes'Length) := Bytes;
      Item.Used := Bytes'Length;
      return True;
   end Place;

   --  The private scalar or seed, at the width the caller is prepared for.
   function Value_From_Private_Key_PEM
     (Private_Key_PEM : String;
      Wanted          : CryptoLib.X509.Public_Key_Algorithm;
      Value           : out Ada.Streams.Stream_Element_Array) return Boolean
   is
      use type CryptoLib.X509.Public_Key_Algorithm;

      Item   : CryptoLib.PKCS8.Private_Key;
      Parsed : Boolean;
   begin
      Value := [others => 0];
      Decode_Private_Key (Private_Key_PEM, Item, Parsed);
      if not Parsed or else CryptoLib.PKCS8.Algorithm_Of (Item) /= Wanted then
         return False;
      end if;

      declare
         Held : constant Ada.Streams.Stream_Element_Array :=
           CryptoLib.PKCS8.Private_Value (Item);
      begin
         if Held'Length /= Value'Length then
            return False;
         end if;
         Value := Held;
         return True;
      end;
   end Value_From_Private_Key_PEM;

   --  Which curve the scalar is expected to be on. Reading a P-256 key as a
   --  P-384 one would take a 32-octet scalar for a 48-octet one.
   function Scalar_From_Private_Key_PEM
     (Private_Key_PEM : String;
      Scalar          : out Ada.Streams.Stream_Element_Array;
      Algorithm       : Key_Algorithm := P384_Key) return Boolean
   is (Value_From_Private_Key_PEM
         (Private_Key_PEM,
          (if Algorithm = P256_Key
           then CryptoLib.X509.ECDSA_P256
           else CryptoLib.X509.ECDSA_P384),
          Scalar));

   function Seed_From_Private_Key_PEM
     (Private_Key_PEM : String;
      Seed            : out Ada.Streams.Stream_Element_Array;
      Algorithm       : Key_Algorithm := Ed25519_Key) return Boolean
   is (Value_From_Private_Key_PEM
         (Private_Key_PEM,
          (case Algorithm is
              when Ed448_Key   => CryptoLib.X509.Ed448,
              when Ed25519_Key => CryptoLib.X509.Ed25519,
              when P256_Key    => CryptoLib.X509.ECDSA_P256,
              --  RSA has no single private value to read; the length check
              --  below refuses it, and nothing calls this for an RSA key.
              when RSA_Key     => CryptoLib.X509.RSA,
              when P384_Key    => CryptoLib.X509.ECDSA_P384),
          Seed));

   function Valid_Name (Text : String) return Boolean is
   begin
      if Text = "" then
         return False;
      end if;

      for C of Text loop
         if not (C in 'a' .. 'z'
                 or else C in 'A' .. 'Z'
                 or else C in '0' .. '9'
                 or else C = '.'
                 or else C = '-'
                 or else C = '_'
                 or else C = '*')
         then
            return False;
         end if;
      end loop;
      return True;
   end Valid_Name;

   function Valid_Email (Text : String) return Boolean is
      At_Pos : Natural := 0;
      Dot_Pos : Natural := 0;
   begin
      if Text'Length < 3 then
         return False;
      end if;

      for I in Text'Range loop
         if Text (I) = '@' then
            if At_Pos /= 0 or else I = Text'First or else I = Text'Last then
               return False;
            end if;
            At_Pos := I;
         elsif Text (I) = '.' and then At_Pos /= 0 and then I > At_Pos + 1 then
            Dot_Pos := I;
         elsif not (Text (I) in 'a' .. 'z'
                    or else Text (I) in 'A' .. 'Z'
                    or else Text (I) in '0' .. '9'
                    or else Text (I) = '.'
                    or else Text (I) = '-'
                    or else Text (I) = '_'
                    or else Text (I) = '+')
         then
            return False;
         end if;
      end loop;

      return At_Pos /= 0 and then Dot_Pos /= 0 and then Dot_Pos < Text'Last;
   end Valid_Email;

   function IPv4_Bytes (Text : String) return String is
      Result      : String (1 .. 4);
      Part        : Natural := 0;
      Value       : Natural := 0;
      Digit_Count : Natural := 0;

      procedure Finish (Ok : in out Boolean) is
      begin
         if Digit_Count = 0 or else Value > 255 or else Part = 4 then
            Ok := False;
         else
            Part := Part + 1;
            Result (Part) := Byte (Value);
            Value := 0;
            Digit_Count := 0;
         end if;
      end Finish;

      Ok : Boolean := True;
   begin
      if Text = "" then
         return "";
      end if;

      for C of Text loop
         if C in '0' .. '9' then
            Value := Value * 10 + Character'Pos (C) - Character'Pos ('0');
            Digit_Count := Digit_Count + 1;
         elsif C = '.' then
            Finish (Ok);
            if not Ok then
               return "";
            end if;
         else
            return "";
         end if;
      end loop;

      Finish (Ok);
      if Ok and then Part = 4 then
         return Result;
      else
         return "";
      end if;
   end IPv4_Bytes;

   function Hex_Value (C : Character) return Integer is
   begin
      if C in '0' .. '9' then
         return Character'Pos (C) - Character'Pos ('0');
      elsif C in 'a' .. 'f' then
         return Character'Pos (C) - Character'Pos ('a') + 10;
      elsif C in 'A' .. 'F' then
         return Character'Pos (C) - Character'Pos ('A') + 10;
      else
         return -1;
      end if;
   end Hex_Value;

   function IPv6_Bytes (Text : String) return String is
      Groups          : array (1 .. 8) of Natural := [others => 0];
      Group_Count     : Natural := 0;
      Compress_Index  : Natural := 0;
      I               : Natural := Text'First;

      function Read_Group
        (Pos   : in out Natural;
         Value : out Natural) return Boolean
      is
         Digit_Total : Natural := 0;
         V      : Natural := 0;
         H      : Integer;
      begin
         Value := 0;
         while Pos <= Text'Last loop
            exit when Text (Pos) = ':';
            H := Hex_Value (Text (Pos));
            if H < 0 or else Digit_Total = 4 then
               return False;
            end if;
            V := V * 16 + Natural (H);
            Digit_Total := Digit_Total + 1;
            Pos := Pos + 1;
         end loop;
         if Digit_Total = 0 then
            return False;
         end if;
         Value := V;
         return True;
      end Read_Group;
   begin
      if Text'Length < 2 then
         return "";
      end if;

      while I <= Text'Last loop
         if Text (I) = ':' then
            if I = Text'Last or else Text (I + 1) /= ':' or else Compress_Index /= 0
            then
               return "";
            end if;
            Compress_Index := Group_Count + 1;
            I := I + 2;
            if I > Text'Last then
               exit;
            end if;
         else
            if Group_Count = 8 then
               return "";
            end if;
            Group_Count := Group_Count + 1;
            if not Read_Group (I, Groups (Group_Count)) then
               return "";
            end if;
            if I <= Text'Last then
               if Text (I) /= ':' then
                  return "";
               end if;
               I := I + 1;
            end if;
         end if;
      end loop;

      if Compress_Index = 0 and then Group_Count /= 8 then
         return "";
      elsif Compress_Index /= 0 then
         declare
            Missing : constant Natural := 8 - Group_Count;
         begin
            if Missing = 0 then
               return "";
            end if;
            for J in reverse Compress_Index .. Group_Count loop
               Groups (J + Missing) := Groups (J);
            end loop;
            for J in Compress_Index .. Compress_Index + Missing - 1 loop
               Groups (J) := 0;
            end loop;
         end;
      end if;

      declare
         Result : String (1 .. 16);
         Pos    : Positive := Result'First;
      begin
         for G of Groups loop
            Result (Pos) := Byte (G / 256);
            Result (Pos + 1) := Byte (G mod 256);
            Pos := Pos + 2;
         end loop;
         return Result;
      end;
   end IPv6_Bytes;

   function IP_Bytes (Text : String) return String is
      V4 : constant String := IPv4_Bytes (Text);
   begin
      if V4 /= "" then
         return V4;
      else
         return IPv6_Bytes (Text);
      end if;
   end IP_Bytes;

   function Valid_Profile_Name
     (Profile : Certificate_Profile;
      Text    : String) return Boolean
   is
   begin
      if Profile = Email_Profile then
         return Valid_Email (Text);
      else
         return Valid_Name (Text) or else IP_Bytes (Text) /= "";
      end if;
   end Valid_Profile_Name;

   --  A key identifier, RFC 5280 method 1: SHA-1 over the public key bits,
   --  which is what 38 of the 40 system roots carrying one were checked to
   --  use. It is an identifier, not a security claim -- SHA-1's weakness
   --  costs nothing here, because the value only has to tell one key from
   --  another and a verifier that follows it still checks the signature.
   function Key_Identifier
     (Public_Key : Ada.Streams.Stream_Element_Array) return String
   is (To_String
         (Ada.Streams.Stream_Element_Array
            (CryptoLib.Hashes.SHA1 (Public_Key))));

   function Extensions_DER
     (Profile     : Certificate_Profile;
      Names       : Subject_Alternative_Name_List;
      Subject_Key : Ada.Streams.Stream_Element_Array;
      Issuer_Key  : Ada.Streams.Stream_Element_Array) return String
   is
      Items : Unbounded_String;
      SANs  : Unbounded_String;
   begin
      if Profile = CA_Profile then
         Append
           (Items,
            Seq
              (OID (Byte (16#55#) & Byte (16#1D#) & Byte (16#13#))
               & Bool (True)
               & Octets (Seq (Bool (True)))));
         Append
           (Items,
            Seq
              (OID (Byte (16#55#) & Byte (16#1D#) & Byte (16#0F#))
               & Bool (True)
               & Octets (TLV (16#03#, Byte (1) & Byte (16#06#)))));
      else
         for Name of Names loop
            declare
               Name_Text : constant String := To_String (Name);
               IP_Data   : constant String := IP_Bytes (Name_Text);
            begin
               if IP_Data /= "" then
                  Append (SANs, TLV (16#87#, IP_Data));
               else
                  Append
                    (SANs,
                     TLV
                       ((if Profile = Email_Profile then 16#81# else 16#82#),
                        Name_Text));
               end if;
            end;
         end loop;
         Append
           (Items,
            Seq
              (OID (Byte (16#55#) & Byte (16#1D#) & Byte (16#13#))
               & Bool (True)
               & Octets (Seq (""))));
         Append
           (Items,
            Seq
              (OID (Byte (16#55#) & Byte (16#1D#) & Byte (16#0F#))
               & Bool (True)
               & Octets (TLV (16#03#, Byte (7) & Byte (16#80#)))));
         Append
           (Items,
            Seq
              (OID (Byte (16#55#) & Byte (16#1D#) & Byte (16#11#))
               & Octets (Seq (To_String (SANs)))));
         Append
           (Items,
            Seq
              (OID (Byte (16#55#) & Byte (16#1D#) & Byte (16#25#))
               & Octets
                   (Seq
                      (OID
                         (Byte (16#2B#) & Byte (16#06#) & Byte (16#01#)
                          & Byte (16#05#) & Byte (16#05#) & Byte (16#07#)
                          & Byte (16#03#)
                          & (case Profile is
                               when Server_Profile => Byte (16#01#),
                               when Client_Profile => Byte (16#02#),
                               when Email_Profile => Byte (16#04#),
                               when CA_Profile => Byte (16#01#)))))));
      end if;
      --  subjectKeyIdentifier names this certificate's key, and
      --  authorityKeyIdentifier names the key that signed it. RFC 5280
      --  requires both -- SKI in every CA certificate, AKI in everything but
      --  a self-signed root -- because a name alone does not pick out a
      --  certificate once a CA has more than one: after a re-key, or under a
      --  cross-signature, several certificates share a subject name and
      --  differ only by key. A verifier with no identifier to go on has to
      --  try them all, and one that gives up early fails to build a chain
      --  that exists. Both are non-critical, as the RFC requires: they help
      --  a verifier find the issuer, they do not constrain what it may
      --  conclude.
      Append
        (Items,
         Seq
           (OID (Byte (16#55#) & Byte (16#1D#) & Byte (16#0E#))
            & Octets (Octets (Key_Identifier (Subject_Key)))));
      Append
        (Items,
         Seq
           (OID (Byte (16#55#) & Byte (16#1D#) & Byte (16#23#))
            & Octets
                (Seq (TLV (16#80#, Key_Identifier (Issuer_Key))))));

      return Explicit (3, Seq (To_String (Items)));
   end Extensions_DER;

   --  Read a CA's signing material, whatever kind of key it is.
   --
   --  One reader for every algorithm, so a path that signs does not need to
   --  know which. For RSA the public part is the RSAPublicKey DER, because
   --  that is what a certificate's BIT STRING holds and what the authority key
   --  identifier is a hash of; the modulus and exponent come back separately
   --  as well, because signing needs them as numbers rather than as an
   --  encoding.
   function Read_CA_Material
     (CA_Private_Key_PEM : String;
      Algorithm          : Key_Algorithm;
      Private_Part       : out CA_Private_Material;
      Public_Part        : out CA_Public_Material;
      Modulus            : out CA_Public_Material;
      Exponent           : out CA_Public_Material;
      CRT                : out CA_CRT_Material) return Boolean
   is
      --  All five CRT values or none, at one shared width. A partial set is
      --  treated as absent, and signing falls back to the plain
      --  exponentiation rather than doing something halfway.
      function Take_CRT
        (Item : CryptoLib.PKCS8.Private_Key) return CA_CRT_Material
      is
         P_Val  : constant Ada.Streams.Stream_Element_Array :=
           Significant (CryptoLib.PKCS8.RSA_Prime_P (Item));
         Q_Val  : constant Ada.Streams.Stream_Element_Array :=
           Significant (CryptoLib.PKCS8.RSA_Prime_Q (Item));
         DP_Val : constant Ada.Streams.Stream_Element_Array :=
           Significant (CryptoLib.PKCS8.RSA_Exponent_P (Item));
         DQ_Val : constant Ada.Streams.Stream_Element_Array :=
           Significant (CryptoLib.PKCS8.RSA_Exponent_Q (Item));
         QI_Val : constant Ada.Streams.Stream_Element_Array :=
           Significant (CryptoLib.PKCS8.RSA_Coefficient (Item));
         Width  : constant Ada.Streams.Stream_Element_Offset := P_Val'Length;
         Result : CA_CRT_Material;
      begin
         if Width = 0 or else Width > Max_CA_Private
           or else Q_Val'Length /= Width
           or else DP_Val'Length > Width or else DQ_Val'Length > Width
           or else QI_Val'Length > Width
         then
            return Result;                --  not ready
         end if;
         Result.Used := Width;
         Result.P (1 .. Width) := P_Val;
         Result.Q (1 .. Width) := Q_Val;
         --  These are each below their prime, so they may be shorter; the
         --  exponentiation wants them at the prime's width.
         Result.DP (Width - DP_Val'Length + 1 .. Width) := DP_Val;
         Result.DQ (Width - DQ_Val'Length + 1 .. Width) := DQ_Val;
         Result.QI (Width - QI_Val'Length + 1 .. Width) := QI_Val;
         Result.Ready := True;
         return Result;
      end Take_CRT;
   begin
      CRT := (others => <>);
      Private_Part := (Slot => [others => 0], Used => 0);
      Public_Part := (Slot => [others => 0], Used => 0);
      Modulus := (Slot => [others => 0], Used => 0);
      Exponent := (Slot => [others => 0], Used => 0);

      case Algorithm is
         when RSA_Key =>
            declare
               Item   : CryptoLib.PKCS8.Private_Key;
               Parsed : Boolean;
            begin
               Decode_Private_Key (CA_Private_Key_PEM, Item, Parsed);
               if not Parsed then
                  return False;
               end if;
               --  These come out of the key as DER INTEGER contents, so a
               --  modulus whose top bit is set carries a leading zero octet --
               --  257 for a 2048-bit modulus, not 256. Signing sizes the
               --  signature from the modulus, so the padding has to come off
               --  here or every signature is one octet too wide and refused.
               --  Integer_From_Bytes puts it back when the key is re-encoded.
               CRT := Take_CRT (Item);
               if not Place (Private_Part,
                             Significant
                               (CryptoLib.PKCS8.RSA_Private_Exponent (Item)))
                 or else not Place (Modulus,
                                    Significant
                                      (CryptoLib.PKCS8.RSA_Modulus (Item)))
                 or else not Place (Exponent,
                                    Significant
                                      (CryptoLib.PKCS8.RSA_Exponent (Item)))
               then
                  return False;
               end if;
               --  The BIT STRING contents of an RSA subjectPublicKey.
               declare
                  Info : constant String :=
                    Seq (Integer_From_Bytes (To_String (Value (Modulus)))
                         & Integer_From_Bytes
                             (To_String (Value (Exponent))));
                  Bytes : Ada.Streams.Stream_Element_Array
                    (1 .. Ada.Streams.Stream_Element_Offset (Info'Length));
               begin
                  for I in Bytes'Range loop
                     Bytes (I) :=
                       Character'Pos (Info (Info'First + Natural (I - 1)));
                  end loop;
                  return Place (Public_Part, Bytes);
               end;
            end;

         when P256_Key | P384_Key =>
            declare
               Width : constant Ada.Streams.Stream_Element_Offset :=
                 Ada.Streams.Stream_Element_Offset
                   (Seed_Length_For (if Algorithm = P256_Key
                                     then P256_Key else P384_Key));
               Scalar : Ada.Streams.Stream_Element_Array (1 .. Width);
               Point  : Ada.Streams.Stream_Element_Array
                 (1 .. Ada.Streams.Stream_Element_Offset
                         (Public_Length_For (if Algorithm = P256_Key
                                             then P256_Key else P384_Key)));
               Curve  : constant CryptoLib.ECDSA.Curve_Id :=
                 (if Algorithm = P256_Key
                  then CryptoLib.ECDSA.Nistp256
                  else CryptoLib.ECDSA.Nistp384);
            begin
               if not Scalar_From_Private_Key_PEM
                        (CA_Private_Key_PEM, Scalar,
                         (if Algorithm = P256_Key then P256_Key else P384_Key))
                 or else CryptoLib.ECDSA.Public_Key_Raw (Curve, Scalar, Point)
                           /= CryptoLib.Errors.Ok
               then
                  CryptoLib.Secure_Wipe.Wipe (Scalar'Address, Scalar'Length);
                  return False;
               end if;
               if not Place (Private_Part, Scalar)
                 or else not Place (Public_Part, Point)
               then
                  CryptoLib.Secure_Wipe.Wipe (Scalar'Address, Scalar'Length);
                  return False;
               end if;
               CryptoLib.Secure_Wipe.Wipe (Scalar'Address, Scalar'Length);
               return True;
            end;

         when Ed25519_Key | Ed448_Key =>
            declare
               Kind : constant Generatable_Key_Algorithm :=
                 (if Algorithm = Ed448_Key then Ed448_Key else Ed25519_Key);
               Seed : Ada.Streams.Stream_Element_Array
                 (1 .. Ada.Streams.Stream_Element_Offset
                         (Seed_Length_For (Kind)));
               Point : Ada.Streams.Stream_Element_Array
                 (1 .. Ada.Streams.Stream_Element_Offset
                         (Public_Length_For (Kind)));
               Fine : Boolean;
            begin
               if not Seed_From_Private_Key_PEM
                        (CA_Private_Key_PEM, Seed, Kind)
               then
                  CryptoLib.Secure_Wipe.Wipe (Seed'Address, Seed'Length);
                  return False;
               end if;
               Fine :=
                 (if Kind = Ed448_Key
                  then CryptoLib.Ed448.Public_Key_From_Seed (Seed, Point)
                         = CryptoLib.Errors.Ok
                  else CryptoLib.Ed25519.Public_Key_From_Seed (Seed, Point)
                         = CryptoLib.Errors.Ok);
               if not Fine
                 or else not Place (Private_Part, Seed)
                 or else not Place (Public_Part, Point)
               then
                  CryptoLib.Secure_Wipe.Wipe (Seed'Address, Seed'Length);
                  return False;
               end if;
               CryptoLib.Secure_Wipe.Wipe (Seed'Address, Seed'Length);
               return True;
            end;
      end case;
   end Read_CA_Material;

   function Sign_Certificate
     (Serial      : String;
      Issuer_CN   : String;
      Subject_CN  : String;
      Subject_Key : Ada.Streams.Stream_Element_Array;
      Sign_Seed   : Ada.Streams.Stream_Element_Array;
      Sign_Public : Ada.Streams.Stream_Element_Array;
      Profile     : Certificate_Profile;
      Names       : Subject_Alternative_Name_List;
      Algorithm   : Key_Algorithm := Ed25519_Key;
      Subject_Algorithm : Key_Algorithm := Ed25519_Key;
      Valid_Days  : Positive := Default_Certificate_Days;
      Limit_Present   : Boolean := False;
      Not_After_Limit : Ada.Calendar.Time := Ada.Calendar.Clock;
      Subject_SPKI    : String := "";
      Sign_Modulus    : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Sign_Exponent   : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Use_PSS         : Boolean := False;
      Sign_P          : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Sign_Q          : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Sign_DP         : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Sign_DQ         : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0];
      Sign_QI         : Ada.Streams.Stream_Element_Array := [1 .. 0 => 0])
      return String
   is
      --  The signer's algorithm and the subject's need not agree: a CSR brings
      --  its own key, and the CA signs whatever it was handed.
      TBS : constant String :=
        Seq
          (Explicit (0, Integer_DER (2))
           & Integer_From_Bytes (Serial)
           & Signature_Algorithm (Algorithm, Use_PSS)
           & Name_DER (Issuer_CN)
           & Validity_DER (Valid_Days, Limit_Present, Not_After_Limit)
           & Name_DER (Subject_CN)
           & (if Subject_SPKI /= "" then Subject_SPKI
              else SPKI_DER (Subject_Key, Subject_Algorithm))
           & Extensions_DER (Profile, Names, Subject_Key, Sign_Public));
   begin
      case Algorithm is
         when RSA_Key =>
            --  Signing with RSA needs the modulus and public exponent as
            --  numbers; Sign_Seed is d. The signature is a single block, not
            --  two integers the way ECDSA's is.
            if Sign_Modulus'Length = 0 or else Sign_Exponent'Length = 0 then
               return "";
            end if;
            declare
               Rng : CryptoLib.Random.Random_Source;
               Sig : Ada.Streams.Stream_Element_Array
                 (1 .. Sign_Modulus'Length);
            begin
               CryptoLib.Random.Initialize_Production (Rng);
               --  The identifier beside the signature has to be the same one
               --  the signed body carries, PSS parameters included, or a
               --  verifier refuses the certificate.
               if Use_PSS then
                  if CryptoLib.RSA.Sign_PSS
                       (Sign_Modulus, Sign_Exponent, Sign_Seed,
                        CryptoLib.RSA.SHA256, RSA_PSS_Salt_Length,
                        To_Bytes (TBS), Rng, Sig,
                        Sign_P, Sign_Q, Sign_DP, Sign_DQ, Sign_QI)
                       /= CryptoLib.Errors.Ok
                  then
                     return "";
                  end if;
               elsif CryptoLib.RSA.Sign_PKCS1_V1_5
                       (Sign_Modulus, Sign_Exponent, Sign_Seed,
                        CryptoLib.RSA.SHA256, To_Bytes (TBS), Rng, Sig,
                        Sign_P, Sign_Q, Sign_DP, Sign_DQ, Sign_QI)
                       /= CryptoLib.Errors.Ok
               then
                  return "";
               end if;
               return Seq
                 (TBS & Signature_Algorithm (Algorithm, Use_PSS)
                  & Bits (To_String (Sig)));
            end;

         when Ed25519_Key =>
            declare
               Sig : Ada.Streams.Stream_Element_Array (1 .. 64);
               St  : constant CryptoLib.Errors.Status :=
                 CryptoLib.Ed25519.Sign
                   (Sign_Seed, Sign_Public, To_Bytes (TBS), Sig);
            begin
               if St /= CryptoLib.Errors.Ok then
                  return "";
               end if;
               return Seq
                 (TBS & Signature_Algorithm (Algorithm)
                  & Bits (To_String (Sig)));
            end;

         when Ed448_Key =>
            declare
               Sig : Ada.Streams.Stream_Element_Array (1 .. 114);
               St  : constant CryptoLib.Errors.Status :=
                 CryptoLib.Ed448.Sign
                   (Sign_Seed, Sign_Public, To_Bytes (TBS), Sig);
            begin
               if St /= CryptoLib.Errors.Ok then
                  return "";
               end if;
               return Seq
                 (TBS & Signature_Algorithm (Algorithm)
                  & Bits (To_String (Sig)));
            end;

         when P256_Key =>
            declare
               R  : Ada.Streams.Stream_Element_Array (1 .. 32);
               S2 : Ada.Streams.Stream_Element_Array (1 .. 32);
               St : constant CryptoLib.Errors.Status :=
                 CryptoLib.ECDSA.Sign_Nistp256_Raw
                   (Sign_Seed, To_Bytes (TBS), R, S2);
            begin
               if St /= CryptoLib.Errors.Ok then
                  return "";
               end if;
               return Seq
                 (TBS & Signature_Algorithm (Algorithm)
                  & Bits (Seq (Integer_From_Bytes (To_String (R))
                               & Integer_From_Bytes (To_String (S2)))));
            end;

         when P384_Key =>
            --  ECDSA signs as two integers, not one fixed block, and DER wants
            --  each of them minimally encoded.
            declare
               R  : Ada.Streams.Stream_Element_Array (1 .. 48);
               S2 : Ada.Streams.Stream_Element_Array (1 .. 48);
               St : constant CryptoLib.Errors.Status :=
                 CryptoLib.ECDSA.Sign_Nistp384_Raw
                   (Sign_Seed, To_Bytes (TBS), R, S2);
            begin
               if St /= CryptoLib.Errors.Ok then
                  return "";
               end if;
               return Seq
                 (TBS & Signature_Algorithm (Algorithm)
                  & Bits
                      (Seq
                         (Integer_From_Bytes (To_String (R))
                          & Integer_From_Bytes (To_String (S2)))));
            end;
      end case;
   end Sign_Certificate;

   function Contains (Data : String; Needle : String) return Boolean is
   begin
      return Ada.Strings.Fixed.Index (Data, Needle) /= 0;
   end Contains;

   --  A DER INTEGER carries no leading zeros and may have gained a sign byte;
   --  the verifier wants a fixed-width big-endian value.
   function Fixed_Width
     (Value : String;
      Out_Bytes : out Ada.Streams.Stream_Element_Array) return Boolean
   is
      First : Natural := Value'First;
   begin
      Out_Bytes := [others => 0];
      while First <= Value'Last and then Value (First) = Character'Val (0) loop
         First := First + 1;
      end loop;
      if First > Value'Last
        or else Natural (Value'Last - First + 1) > Natural (Out_Bytes'Length)
      then
         return False;
      end if;

      declare
         Width : constant Natural := Value'Last - First + 1;
         Start : constant Ada.Streams.Stream_Element_Offset :=
           Out_Bytes'Last - Ada.Streams.Stream_Element_Offset (Width) + 1;
      begin
         for I in 0 .. Width - 1 loop
            Out_Bytes (Start + Ada.Streams.Stream_Element_Offset (I)) :=
              Ada.Streams.Stream_Element (Character'Pos (Value (First + I)));
         end loop;
      end;
      return True;
   end Fixed_Width;

   --  Read a certification request and check the asker holds the key.
   --
   --  Two hundred lines of hand-written DER walking until there was a parsed
   --  request to ask instead. The contract is unchanged: True only when the
   --  request carries a key of exactly the size the caller is prepared for
   --  and its own signature verifies under that key.
   --
   --  What is new is what the parse itself refuses -- non-canonical lengths
   --  and integers, trailing data, unbounded nesting -- and that the
   --  signature check now covers every algorithm the crate can verify rather
   --  than the two this walked by hand.
   --  The subject name and the whole SubjectPublicKeyInfo of a request.
   --
   --  Taking the key's own encoding rather than rebuilding it from raw bytes
   --  is what lets a request name a key this crate cannot generate -- RSA,
   --  most of the time. Nothing here has to know the algorithm: the request
   --  is signed with the key it names, so a request whose signature this can
   --  check is one whose key it can carry, and a request whose signature it
   --  cannot check is refused below whatever the key is.
   function Extract_CSR_Info
     (CSR_PEM    : String;
      Subject_CN : out Unbounded_String;
      Key_Info   : out Unbounded_String) return Boolean
   is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.X509.Signatures.Verification_Result;

      DER : constant String := Base64_Decode (CSR_PEM);
   begin
      Subject_CN := Null_Unbounded_String;
      Key_Info := Null_Unbounded_String;

      if DER'Length = 0 then
         return False;
      end if;

      declare
         Raw : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (DER'Length));
      begin
         for I in DER'Range loop
            Raw (Ada.Streams.Stream_Element_Offset (I - DER'First + 1)) :=
              Character'Pos (DER (I));
         end loop;

         declare
            Status : CryptoLib.ASN1.Errors.Decode_Status;
            Item   : constant CryptoLib.PKCS10.Request :=
              CryptoLib.PKCS10.Decode_DER
                (Raw, CryptoLib.ASN1.Default_Limits, Status);
         begin
            if Status /= CryptoLib.ASN1.Errors.Ok
              or else not CryptoLib.PKCS10.Is_Present (Item)
            then
               return False;
            end if;

            --  Proof of possession, as before: a request whose signature
            --  does not check is somebody claiming a key without showing
            --  they hold it.
            if CryptoLib.PKCS10.Verify_Signature (Item)
              /= CryptoLib.X509.Signatures.Valid
            then
               return False;
            end if;

            declare
               Info : constant Ada.Streams.Stream_Element_Array :=
                 CryptoLib.PKCS10.Public_Key_Info_Bytes (Item);
               Text : String (1 .. Natural (Info'Length));
            begin
               if Info'Length = 0 then
                  return False;
               end if;
               for I in Text'Range loop
                  Text (I) :=
                    Character'Val
                      (Info (Info'First
                             + Ada.Streams.Stream_Element_Offset (I - 1)));
               end loop;
               Key_Info := To_Unbounded_String (Text);
            end;

            Subject_CN :=
              To_Unbounded_String
                (CryptoLib.PKCS10.Subject_Common_Name (Item));
            return Length (Subject_CN) > 0;
         end;
      end;
   end Extract_CSR_Info;

   function Extract_CSR
     (CSR_PEM    : String;
      Subject_CN : out Unbounded_String;
      Public_Key : out Ada.Streams.Stream_Element_Array) return Boolean
   is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.X509.Signatures.Verification_Result;

      DER : constant String := Base64_Decode (CSR_PEM);
   begin
      Subject_CN := Null_Unbounded_String;
      Public_Key := [others => 0];

      if DER'Length = 0 then
         return False;
      end if;

      declare
         Raw : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (DER'Length));
      begin
         for I in DER'Range loop
            Raw (Ada.Streams.Stream_Element_Offset (I - DER'First + 1)) :=
              Character'Pos (DER (I));
         end loop;

         declare
            Status : CryptoLib.ASN1.Errors.Decode_Status;
            Item   : constant CryptoLib.PKCS10.Request :=
              CryptoLib.PKCS10.Decode_DER
                (Raw, CryptoLib.ASN1.Default_Limits, Status);
         begin
            if Status /= CryptoLib.ASN1.Errors.Ok
              or else not CryptoLib.PKCS10.Is_Present (Item)
            then
               return False;
            end if;

            --  Proof of possession. A request whose signature does not check
            --  is an assertion that somebody holds a key, made by somebody
            --  who has not shown that they do.
            if CryptoLib.PKCS10.Verify_Signature (Item)
              /= CryptoLib.X509.Signatures.Valid
            then
               return False;
            end if;

            declare
               Key : constant Ada.Streams.Stream_Element_Array :=
                 CryptoLib.PKCS10.Public_Key (Item);
            begin
               if Key'Length /= Public_Key'Length then
                  --  Not the shape this caller is prepared for; it will try
                  --  another.
                  return False;
               end if;

               Public_Key := Key;
               Subject_CN :=
                 To_Unbounded_String
                   (CryptoLib.PKCS10.Subject_Common_Name (Item));
               return Length (Subject_CN) > 0;
            end;
         end;
      end;
   end Extract_CSR;

   function Create_Local_CA
     (Common_Name     : String;
      Certificate_PEM : out Unbounded_String;
      Private_Key_PEM : out Unbounded_String;
      Algorithm       : Generatable_Key_Algorithm := Ed25519_Key;
      Valid_Days      : Positive := Default_CA_Days)
      return Certificate_Status
   is
      Rng  : CryptoLib.Random.Random_Source;
      Cert : Unbounded_String;

      Seed   : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Seed_Length_For (Algorithm)));
      Public : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset
                (Public_Length_For (Algorithm)));

      --  The seed is the CA's private key. It leaves this subprogram only
      --  inside Private_Key_PEM, so the copy on the stack is scrubbed on every
      --  exit; an assignment of zeros would be a dead store and removed.
      procedure Scrub is
      begin
         CryptoLib.Secure_Wipe.Wipe (Seed'Address, Seed'Length);
      end Scrub;
   begin
      Certificate_PEM := Null_Unbounded_String;
      Private_Key_PEM := Null_Unbounded_String;

      if not Valid_Name (Common_Name) then
         Scrub;
         return Invalid_Input;
      end if;

      CryptoLib.Random.Initialize_Production (Rng);
      case Algorithm is
         when Ed25519_Key =>
            if CryptoLib.Ed25519.Generate_Keypair (Rng, Seed, Public)
              /= CryptoLib.Errors.Ok
            then
               Scrub;
               return Internal_Error;
            end if;
         when P256_Key =>
            if CryptoLib.ECDSA.Generate_Nistp256_Keypair (Rng, Seed, Public)
              /= CryptoLib.Errors.Ok
            then
               Scrub;
               return Internal_Error;
            end if;
         when P384_Key =>
            if CryptoLib.ECDSA.Generate_Nistp384_Keypair (Rng, Seed, Public)
              /= CryptoLib.Errors.Ok
            then
               Scrub;
               return Internal_Error;
            end if;
         when Ed448_Key =>
            if CryptoLib.Ed448.Generate_Keypair (Rng, Seed, Public)
              /= CryptoLib.Errors.Ok
            then
               Scrub;
               return Internal_Error;
            end if;
      end case;

      declare
         Serial_Value : constant String := Random_Serial (Rng);
      begin
         if Serial_Value = "" then
            Scrub;
            return Internal_Error;
         end if;

         Cert :=
           To_Unbounded_String
             (Sign_Certificate
                (Serial      => Serial_Value,
                 Issuer_CN   => Common_Name,
                 Subject_CN  => Common_Name,
                 Subject_Key => Public,
                 Sign_Seed   => Seed,
                 Sign_Public => Public,
                 Profile     => CA_Profile,
                 Names       => [1 => To_Unbounded_String (Common_Name)],
                 Algorithm   => Algorithm,
                 Subject_Algorithm => Algorithm,
                 Valid_Days  => Valid_Days));
      end;

      if Length (Cert) = 0 then
         Scrub;
         return Internal_Error;
      end if;

      Certificate_PEM := PEM ("CERTIFICATE", To_String (Cert));
      Private_Key_PEM :=
        PEM ("PRIVATE KEY",
             (case Algorithm is
                 when Ed25519_Key => Private_Key_DER (Seed),
                 when Ed448_Key   => Private_Key_DER (Seed, Ed448_Key),
                 when P256_Key    =>
                   EC_Private_Key_DER (Seed, Public, P256_Algorithm),
                 when P384_Key    =>
                   EC_Private_Key_DER (Seed, Public, P384_Algorithm)));
      Scrub;
      return Ok;
   end Create_Local_CA;

   --  The subject common name of a certificate, read from its DER.
   --
   --  A leaf's issuer name has to be the CA's subject name exactly, or no
   --  verifier can build the chain: OpenSSL looks the issuer up by subject and
   --  reports "unable to get local issuer certificate" when they differ. Taking
   --  it from the CA certificate is the only way to be sure they match, which
   --  is what CA_Certificate_PEM is for.
   --  The subject common name of a certificate, used to name the issuer on
   --  certificates issued under it.
   --
   --  This walked the TBSCertificate by hand until there was a parsed
   --  certificate to ask instead. The hand-written walk and the one in
   --  CryptoLib.X509.Certificates read the same structure, and two readers of
   --  one structure drift: the parsed one enforces canonical DER, bounds what
   --  it will decode, and refuses trailing data, none of which the walk here
   --  did.
   --  When the certificate that will sign this one runs out, as a clock
   --  time. Absent when the PEM does not decode -- the caller is issuing
   --  under it either way, and a limit that cannot be read is not a licence
   --  to ignore one.
   function Issuer_Expiry
     (CA_Certificate_PEM : String; Found : out Boolean)
      return Ada.Calendar.Time
   is
      DER : constant String := Base64_Decode (CA_Certificate_PEM);
   begin
      Found := False;
      if DER'Length = 0 then
         return Ada.Calendar.Clock;
      end if;

      declare
         Raw : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (DER'Length));
         Status : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         for I in DER'Range loop
            Raw (Ada.Streams.Stream_Element_Offset (I - DER'First + 1)) :=
              Character'Pos (DER (I));
         end loop;

         declare
            use type CryptoLib.ASN1.Errors.Decode_Status;
            Item : constant CryptoLib.X509.Certificates.Certificate :=
              CryptoLib.X509.Certificates.Decode_DER
                (Raw, CryptoLib.ASN1.Default_Limits, Status);
         begin
            if Status /= CryptoLib.ASN1.Errors.Ok
              or else not CryptoLib.X509.Certificates.Is_Present (Item)
            then
               return Ada.Calendar.Clock;
            end if;

            declare
               When_Over : constant CryptoLib.X509.Certificate_Time :=
                 CryptoLib.X509.Certificates.Not_After (Item);
            begin
               Found := True;
               return Ada.Calendar.Formatting.Time_Of
                        (Year    => When_Over.Year,
                         Month   => When_Over.Month,
                         Day     => When_Over.Day,
                         Hour    => When_Over.Hour,
                         Minute  => When_Over.Minute,
                         Second  => Natural'Min (When_Over.Second, 59),
                         Time_Zone => 0);
            end;
         end;
      end;
   exception
      when others =>
         Found := False;
         return Ada.Calendar.Clock;
   end Issuer_Expiry;

   function Certificate_Subject_CN
     (Certificate_PEM : String;
      Common_Name     : out Unbounded_String) return Boolean
   is
      use type CryptoLib.ASN1.Errors.Decode_Status;

      DER : constant String := Base64_Decode (Certificate_PEM);
   begin
      Common_Name := Null_Unbounded_String;
      if DER'Length = 0 then
         return False;
      end if;

      declare
         Raw : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (DER'Length));
      begin
         for I in DER'Range loop
            Raw (Ada.Streams.Stream_Element_Offset (I - DER'First + 1)) :=
              Character'Pos (DER (I));
         end loop;

         declare
            Status : CryptoLib.ASN1.Errors.Decode_Status;
            Item   : constant CryptoLib.X509.Certificates.Certificate :=
              CryptoLib.X509.Certificates.Decode_DER
                (Raw, CryptoLib.ASN1.Default_Limits, Status);
         begin
            if Status /= CryptoLib.ASN1.Errors.Ok then
               return False;
            end if;

            declare
               Text : constant String :=
                 CryptoLib.X509.Certificates.Subject_Common_Name (Item);
            begin
               if Text'Length = 0 then
                  return False;
               end if;
               Common_Name := To_Unbounded_String (Text);
               return True;
            end;
         end;
      end;
   end Certificate_Subject_CN;

   function Issue_Profile_Certificate
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Names              : Subject_Alternative_Name_List;
      Profile            : Certificate_Profile;
      Certificate_PEM    : out Unbounded_String;
      Private_Key_PEM    : out Unbounded_String;
      Valid_Days         : Positive := Default_Certificate_Days)
      return Certificate_Status
   is
      Rng : CryptoLib.Random.Random_Source;

      --  The issuer name must equal the CA's subject name exactly.
      Issuer_Name : Unbounded_String;
      Have_Issuer : constant Boolean :=
        Certificate_Subject_CN (CA_Certificate_PEM, Issuer_Name);

      --  What the CA itself runs out of. A certificate issued here must
      --  not outlast it: past that instant the chain stops verifying, and
      --  the remaining time is validity the certificate claims and does not
      --  have.
      CA_Ends_Known : Boolean;
      CA_Ends       : constant Ada.Calendar.Time :=
        Issuer_Expiry (CA_Certificate_PEM, CA_Ends_Known);

      --  A leaf is signed by the CA and has to be verifiable by whatever
      --  accepts the CA, so it carries the same kind of key. Nothing asks the
      --  caller: the CA's own key already says which.
      Algorithm : constant Key_Algorithm :=
        Algorithm_Of_Private_Key (CA_Private_Key_PEM);

      --  The leaf carries the same kind of key as the CA where this crate can
      --  generate that kind. An RSA CA cannot have an RSA leaf generated here,
      --  so it gets a P-256 one -- an ordinary mixed chain, and the curve most
      --  certificates use. A caller wanting an RSA leaf under an RSA CA brings
      --  the key to Issue_*_For_Key.
      Signing : constant Generatable_Key_Algorithm :=
        (if Algorithm in Generatable_Key_Algorithm then Algorithm
         else P256_Key);
      CA_Priv : CA_Private_Material;
      CA_Pub  : CA_Public_Material;
      CA_N    : CA_Public_Material;
      CA_E    : CA_Public_Material;
      CA_CRT  : CA_CRT_Material;
      Seed      : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Seed_Length_For (Signing)));
      Public    : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset
                (Public_Length_For (Signing)));
      Cert      : Unbounded_String;

      --  Both private keys are secrets: the CA's, recovered from its PEM, and
      --  the leaf's, generated here. Only the leaf's leaves this subprogram,
      --  and only inside Private_Key_PEM.
      procedure Scrub is
      begin
         CryptoLib.Secure_Wipe.Wipe
           (CA_Priv.Slot'Address, CA_Priv.Slot'Length);
         CryptoLib.Secure_Wipe.Wipe (Seed'Address, Seed'Length);
      end Scrub;
   begin
      Certificate_PEM := Null_Unbounded_String;
      Private_Key_PEM := Null_Unbounded_String;

      --  Without the CA's certificate there is no issuer name to sign with,
      --  and a certificate carrying the wrong one cannot be chained to it.
      if not Have_Issuer
        or else CA_Private_Key_PEM = ""
        or else not Valid_Profile_Name (Profile, Common_Name)
        or else Names'Length = 0
        or else Profile = CA_Profile
      then
         Scrub;
         return Invalid_Input;
      end if;

      for Name of Names loop
         if not Valid_Profile_Name (Profile, To_String (Name)) then
            Scrub;
            return Invalid_Input;
         end if;
      end loop;

      --  One reader for every kind of CA key, RSA included: the material comes
      --  back in slots wide enough for any of them with the used length
      --  attached, so nothing here is sized from the algorithm's name.
      if not Read_CA_Material
               (CA_Private_Key_PEM, Algorithm, CA_Priv, CA_Pub, CA_N, CA_E,
                CA_CRT)
      then
         Scrub;
         return Invalid_Input;
      end if;

      CryptoLib.Random.Initialize_Production (Rng);
      --  A case rather than an if-chain, so the compiler names every
      --  algorithm. This was an if-chain whose else branch generated an
      --  Ed25519 key: adding P-256 made it issue a certificate that said
      --  P-256 and carried an Ed25519 key, and nothing in the type system
      --  objected. A case cannot acquire that kind of silent default.
      case Signing is
         when P256_Key =>
            if CryptoLib.ECDSA.Generate_Nistp256_Keypair (Rng, Seed, Public)
              /= CryptoLib.Errors.Ok
            then
               Scrub;
               return Internal_Error;
            end if;
         when P384_Key =>
            if CryptoLib.ECDSA.Generate_Nistp384_Keypair (Rng, Seed, Public)
              /= CryptoLib.Errors.Ok
            then
               Scrub;
               return Internal_Error;
            end if;
         when Ed448_Key =>
            if CryptoLib.Ed448.Generate_Keypair (Rng, Seed, Public)
              /= CryptoLib.Errors.Ok
            then
               Scrub;
               return Internal_Error;
            end if;
         when Ed25519_Key =>
            if CryptoLib.Ed25519.Generate_Keypair (Rng, Seed, Public)
              /= CryptoLib.Errors.Ok
            then
               Scrub;
               return Internal_Error;
            end if;
      end case;

      declare
         Serial_Value : constant String := Random_Serial (Rng);
      begin
         if Serial_Value = "" then
            Scrub;
            return Internal_Error;
         end if;

         Cert :=
           To_Unbounded_String
             (Sign_Certificate
                (Serial      => Serial_Value,
                 Issuer_CN   => To_String (Issuer_Name),
                 Subject_CN  => Common_Name,
                 Subject_Key => Public,
                 Sign_Seed   => Value (CA_Priv),
                 Sign_Public => Value (CA_Pub),
                 Profile     => Profile,
                 Names       => Names,
                 --  The signer is the CA's algorithm, which may be RSA; the
                 --  subject's is the leaf's, which never is.
                 Algorithm   => Algorithm,
                 Subject_Algorithm => Signing,
                 Valid_Days  => Valid_Days,
                 Limit_Present   => CA_Ends_Known,
                 Not_After_Limit => CA_Ends,
                 Sign_Modulus    => Value (CA_N),
                 Sign_Exponent   => Value (CA_E),
                 Sign_P          => CRT_P (CA_CRT),
                 Sign_Q          => CRT_Q (CA_CRT),
                 Sign_DP         => CRT_DP (CA_CRT),
                 Sign_DQ         => CRT_DQ (CA_CRT),
                 Sign_QI         => CRT_QI (CA_CRT)));
      end;

      if Length (Cert) = 0 then
         Scrub;
         return Internal_Error;
      end if;

      Certificate_PEM := PEM ("CERTIFICATE", To_String (Cert));
      Private_Key_PEM :=
        PEM ("PRIVATE KEY",
             (case Signing is
                 when P256_Key    =>
                   EC_Private_Key_DER (Seed, Public, P256_Algorithm),
                 when P384_Key    =>
                   EC_Private_Key_DER (Seed, Public, P384_Algorithm),
                 when Ed448_Key   => Private_Key_DER (Seed, Ed448_Key),
                 when Ed25519_Key => Private_Key_DER (Seed)));
      Scrub;
      return Ok;
   exception
      when others =>
         Certificate_PEM := Null_Unbounded_String;
         Private_Key_PEM := Null_Unbounded_String;
         Scrub;
         return Internal_Error;
   end Issue_Profile_Certificate;

   function Issue_Server_Certificate
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Names              : Subject_Alternative_Name_List;
      Certificate_PEM    : out Unbounded_String;
      Private_Key_PEM    : out Unbounded_String;
      Valid_Days         : Positive := Default_Certificate_Days)
      return Certificate_Status is
   begin
      return Issue_Profile_Certificate
        (CA_Certificate_PEM, CA_Private_Key_PEM, Common_Name, Names,
         Server_Profile, Certificate_PEM, Private_Key_PEM, Valid_Days);
   end Issue_Server_Certificate;

   function Issue_Client_Certificate
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Names              : Subject_Alternative_Name_List;
      Certificate_PEM    : out Unbounded_String;
      Private_Key_PEM    : out Unbounded_String;
      Valid_Days         : Positive := Default_Certificate_Days)
      return Certificate_Status is
   begin
      return Issue_Profile_Certificate
        (CA_Certificate_PEM, CA_Private_Key_PEM, Common_Name, Names,
         Client_Profile, Certificate_PEM, Private_Key_PEM, Valid_Days);
   end Issue_Client_Certificate;

   function Issue_Email_Certificate
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Emails             : Subject_Alternative_Name_List;
      Certificate_PEM    : out Unbounded_String;
      Private_Key_PEM    : out Unbounded_String;
      Valid_Days         : Positive := Default_Certificate_Days)
      return Certificate_Status is
   begin
      return Issue_Profile_Certificate
        (CA_Certificate_PEM, CA_Private_Key_PEM, Common_Name, Emails,
         Email_Profile, Certificate_PEM, Private_Key_PEM, Valid_Days);
   end Issue_Email_Certificate;

   function Sign_CSR
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      CSR_PEM            : String;
      Certificate_PEM    : out Unbounded_String;
      Valid_Days         : Positive := Default_Certificate_Days)
      return Certificate_Status
   is
      Algorithm : constant Key_Algorithm :=
        Algorithm_Of_Private_Key (CA_Private_Key_PEM);

      --  What the CA itself runs out of. A certificate issued here must
      --  not outlast it: past that instant the chain stops verifying, and
      --  the remaining time is validity the certificate claims and does not
      --  have.
      CA_Ends_Known : Boolean;
      CA_Ends       : constant Ada.Calendar.Time :=
        Issuer_Expiry (CA_Certificate_PEM, CA_Ends_Known);

      --  The issuer name must equal the CA's subject name exactly.
      Issuer_Name : Unbounded_String;
      Have_Issuer : constant Boolean :=
        Certificate_Subject_CN (CA_Certificate_PEM, Issuer_Name);
      CA_Priv : CA_Private_Material;
      CA_Pub  : CA_Public_Material;
      CA_N    : CA_Public_Material;
      CA_E    : CA_Public_Material;
      CA_CRT  : CA_CRT_Material;

      --  The CA's private key, recovered from its PEM to sign with.
      procedure Scrub is
      begin
         CryptoLib.Secure_Wipe.Wipe
           (CA_Priv.Slot'Address, CA_Priv.Slot'Length);
      end Scrub;

      Subject   : Unbounded_String;
      Empty_Key : constant Ada.Streams.Stream_Element_Array (1 .. 0) :=
        [others => 0];
      Cert      : Unbounded_String;
      Rng       : CryptoLib.Random.Random_Source;
   begin
      CryptoLib.Random.Initialize_Production (Rng);
      Certificate_PEM := Null_Unbounded_String;
      --  Without the CA's certificate there is no issuer name to sign with.
      if not Have_Issuer or else CA_Private_Key_PEM = "" or else CSR_PEM = ""
      then
         Scrub;
         return Invalid_Input;
      end if;
      if not Read_CA_Material
               (CA_Private_Key_PEM, Algorithm, CA_Priv, CA_Pub, CA_N, CA_E,
                CA_CRT)
      then
         Scrub;
         return Invalid_Input;
      end if;

      --  One path for every request. The subject's key goes in exactly as
      --  the request encoded it, so nothing here needs to recognise the
      --  algorithm or its width -- which is what used to be tried in turn,
      --  97 bytes then 57 then 32, and is why an RSA request was refused
      --  whatever the CA was.
      declare
         Key_Info : Unbounded_String;
      begin
         if not Extract_CSR_Info (CSR_PEM, Subject, Key_Info) then
            Scrub;
            return Invalid_Input;
         end if;

         --  The request's common name becomes this certificate's subject
         --  alternative name, so it has to be a name of the kind the profile
         --  admits. Without this a request could ask for "evil.test
         --  attacker" and be handed a certificate carrying it as a dNSName
         --  -- not a domain name at all, and the sort of thing two readers
         --  disagree about, which is the whole reason this crate refuses a
         --  name with a NUL in it elsewhere. The profile paths have always
         --  checked; this one did not.
         if not Valid_Profile_Name (Server_Profile, To_String (Subject)) then
            Scrub;
            return Invalid_Input;
         end if;

         declare
            Serial_Value : constant String := Random_Serial (Rng);
         begin
            if Serial_Value = "" then
               Scrub;
               return Internal_Error;
            end if;

            Cert :=
              To_Unbounded_String
                (Sign_Certificate
                   (Serial      => Serial_Value,
                    Issuer_CN   => To_String (Issuer_Name),
                    Subject_CN  => To_String (Subject),
                    Subject_Key => Empty_Key,
                    Sign_Seed   => Value (CA_Priv),
                    Sign_Public => Value (CA_Pub),
                    Profile     => Server_Profile,
                    Names       => [1 => Subject],
                    Algorithm   => Algorithm,
                    Valid_Days  => Valid_Days,
                    Limit_Present   => CA_Ends_Known,
                    Not_After_Limit => CA_Ends,
                    Subject_SPKI    => To_String (Key_Info),
                    Sign_Modulus    => Value (CA_N),
                    Sign_Exponent   => Value (CA_E),
                    Sign_P          => CRT_P (CA_CRT),
                    Sign_Q          => CRT_Q (CA_CRT),
                    Sign_DP         => CRT_DP (CA_CRT),
                    Sign_DQ         => CRT_DQ (CA_CRT),
                    Sign_QI         => CRT_QI (CA_CRT)));
         end;
      end;

      if Length (Cert) = 0 then
         Scrub;
         return Internal_Error;
      end if;
      Certificate_PEM := PEM ("CERTIFICATE", To_String (Cert));
      Scrub;
      return Ok;
   end Sign_CSR;

   --  Label rules, not a character set: a DNS label is 1 to 63 characters, may
   --  hold hyphens inside but not at either end, and the name may not be one
   --  long label of dots. A charset check accepts "-.-" and a trailing dot,
   --  which no resolver will.
   function Valid_DNS_Name (Text : String) return Boolean is
      Label_Start : Positive;
      Label_Len   : Natural := 0;

      function Alpha_Num (C : Character) return Boolean is
        (C in 'a' .. 'z' or else C in 'A' .. 'Z' or else C in '0' .. '9');

      function Valid_Label (First : Positive; Last : Natural) return Boolean is
      begin
         if Last < First or else Last - First + 1 > 63 then
            return False;
         elsif not Alpha_Num (Text (First)) or else not Alpha_Num (Text (Last))
         then
            return False;
         end if;

         for I in First .. Last loop
            if not Alpha_Num (Text (I)) and then Text (I) /= '-' then
               return False;
            end if;
         end loop;
         return True;
      end Valid_Label;
   begin
      if Text'Length = 0 or else Text'Length > 253 then
         return False;
      end if;

      --  A wildcard stands for one label and only the leftmost, and only where
      --  something remains for it to qualify: "*.example.test" names hosts in a
      --  domain, "*" and "*.test" name far too much, and "a*b" is not a
      --  wildcard at all.
      if Text = "*" then
         return False;
      elsif Text'Length > 2
        and then Text (Text'First) = '*'
        and then Text (Text'First + 1) = '.'
      then
         return Ada.Strings.Fixed.Index
                  (Text (Text'First + 2 .. Text'Last), ".") /= 0
           and then Valid_DNS_Name (Text (Text'First + 2 .. Text'Last));
      elsif Ada.Strings.Fixed.Index (Text, "*") /= 0 then
         return False;
      end if;

      Label_Start := Text'First;
      for I in Text'Range loop
         if Text (I) = '.' then
            if not Valid_Label (Label_Start, I - 1) then
               return False;
            end if;
            Label_Start := I + 1;
            Label_Len := 0;
         else
            Label_Len := Label_Len + 1;
         end if;
      end loop;

      return Label_Len > 0 and then Valid_Label (Label_Start, Text'Last);
   end Valid_DNS_Name;

   --  The encoder is the authority: an address is valid exactly when it can be
   --  turned into the bytes a certificate carries.
   function Valid_IP_Address (Text : String) return Boolean is
   begin
      return IP_Bytes (Text) /= "";
   end Valid_IP_Address;

   function Valid_Email_Address (Text : String) return Boolean is
   begin
      return Valid_Email (Text);
   end Valid_Email_Address;

   function Fingerprint (Certificate_PEM : String) return String is
      DER : constant String := Base64_Decode (Certificate_PEM);
   begin
      if DER = "" then
         return "";
      end if;

      declare
         Digest : constant String := Digest_Hex (DER);
         Result : Unbounded_String;
      begin
         for I in 1 .. Digest'Length / 2 loop
            if I > 1 then
               Append (Result, ":");
            end if;
            Append
              (Result,
               Digest (Digest'First + (I - 1) * 2 .. Digest'First + (I - 1) * 2 + 1));
         end loop;
         return To_String (Result);
      end;
   end Fingerprint;

   function SHA1_Fingerprint (Certificate_PEM : String) return String is
      DER : constant String := Base64_Decode (Certificate_PEM);
   begin
      if DER = "" then
         return "";
      end if;

      return Ada.Characters.Handling.To_Lower
        (Hex_Image
           (Ada.Streams.Stream_Element_Array
              (CryptoLib.Hashes.SHA1 (To_Bytes (DER)))));
   end SHA1_Fingerprint;

   function Same_Certificate (Left : String; Right : String) return Boolean is
      Left_DER  : constant String := Base64_Decode (Left);
      Right_DER : constant String := Base64_Decode (Right);
   begin
      return Left_DER /= "" and then Left_DER = Right_DER;
   end Same_Certificate;

   function Contains_Certificate (Text : String) return Boolean is
   begin
      return Contains (Text, "BEGIN CERTIFICATE")
        and then Contains (Text, "END CERTIFICATE");
   end Contains_Certificate;

   function Contains_Private_Key (Text : String) return Boolean is
   begin
      return Contains (Text, "BEGIN PRIVATE KEY")
        and then Contains (Text, "END PRIVATE KEY");
   end Contains_Private_Key;

   function Private_Key_Matches_Certificate
     (Certificate_PEM : String;
      Private_Key_PEM : String) return Certificate_Status
   is
      DER       : constant String := Base64_Decode (Certificate_PEM);
      Algorithm : constant Key_Algorithm :=
        Algorithm_Of_Private_Key (Private_Key_PEM);

      Priv : CA_Private_Material;
      Pub  : CA_Public_Material;
      N, E : CA_Public_Material;
      CRT  : CA_CRT_Material;

      procedure Scrub is
      begin
         CryptoLib.Secure_Wipe.Wipe (Priv.Slot'Address, Priv.Slot'Length);
      end Scrub;
   begin
      if DER = "" or else Private_Key_PEM = "" then
         return Invalid_Input;
      end if;

      --  Derive the public key the private one implies and look for it in the
      --  certificate: a key that belongs to another certificate cannot produce
      --  a subject public key that matches this one.
      --
      --  This used to be a case over four algorithms that each derived a
      --  public value its own way, with RSA refused because it is matched by
      --  its modulus rather than by a point derived from a scalar. Read_CA_
      --  Material already produces the public half of every kind of key,
      --  including RSA, so there is one path and RSA is no longer the
      --  exception. CryptoLib.Identities has always matched RSA keys; this
      --  refusing them was the two answering the same question differently.
      if not Read_CA_Material
               (Private_Key_PEM, Algorithm, Priv, Pub, N, E, CRT)
      then
         Scrub;
         return Invalid_Input;
      end if;
      Scrub;

      if Contains (DER, SPKI_DER (Value (Pub), Algorithm)) then
         return Ok;
      else
         return Invalid_Input;
      end if;
   exception
      when others =>
         Scrub;
         return Internal_Error;
   end Private_Key_Matches_Certificate;

   function Generate_PKCS12
     (Certificate_PEM : String;
      Private_Key_PEM : String;
      Friendly_Name   : String;
      Password        : String;
      Bundle_Data     : out Unbounded_String;
      Iterations      : Positive := Default_PKCS12_Iterations)
      return Certificate_Status
   is
      Cert_DER        : constant String := Base64_Decode (Certificate_PEM);
      Key_DER         : constant String := Base64_Decode (Private_Key_PEM);
      Padded_Key      : constant Ada.Streams.Stream_Element_Array :=
        PKCS7_Pad (Key_DER, 16);
      Rng             : CryptoLib.Random.Random_Source;
      Mac_Salt        : Ada.Streams.Stream_Element_Array (1 .. 8);
      Encryption_Salt : Ada.Streams.Stream_Element_Array (1 .. 16);
      IV_Data         : Ada.Streams.Stream_Element_Array (1 .. 16);
   begin
      Bundle_Data := Null_Unbounded_String;
      if Certificate_PEM = "" or else Private_Key_PEM = "" or else Friendly_Name = "" then
         return Invalid_Input;
      end if;
      if Cert_DER = "" or else Key_DER = "" then
         return Invalid_Input;
      end if;

      CryptoLib.Random.Initialize_Production (Rng);
      if CryptoLib.Random.Fill (Rng, Mac_Salt) /= CryptoLib.Errors.Ok
        or else CryptoLib.Random.Fill (Rng, Encryption_Salt) /= CryptoLib.Errors.Ok
        or else CryptoLib.Random.Fill (Rng, IV_Data) /= CryptoLib.Errors.Ok
      then
         return Internal_Error;
      end if;

      declare
         Key_Data : constant Ada.Streams.Stream_Element_Array :=
           CryptoLib.Macs.PBKDF2_HMAC_SHA256
             (Password_Data => To_Bytes (Password),
              Salt_Data     => Encryption_Salt,
              Iterations    => Iterations,
              Output_Length => 32);
         Encrypted_Key : Ada.Streams.Stream_Element_Array (Padded_Key'Range);
         Status        : CryptoLib.Errors.Status;
      begin
         Status :=
           CryptoLib.Ciphers.Encrypt_CBC_Raw
             ("aes256-cbc", Key_Data, IV_Data, Padded_Key, Encrypted_Key);
         if Status /= CryptoLib.Errors.Ok then
            return Internal_Error;
         end if;

         declare
            Encrypted_Private_Key_Info : constant String :=
              Seq
                (PBES2_AES_256_CBC_Algorithm
                   (Encryption_Salt, Iterations, IV_Data)
                 & Octets (To_String (Encrypted_Key)));
            Key_Bag : constant String :=
              Seq
                (OID_Shrouded_Key_Bag
                 & Explicit (0, Encrypted_Private_Key_Info));
            Cert_Bag : constant String :=
              Seq
                (OID_Cert_Bag
                 & Explicit
                     (0,
                      Seq
                        (OID_X509_Certificate
                         & Explicit (0, Octets (Cert_DER)))));
            Safe_Contents : constant String := Seq (Key_Bag & Cert_Bag);
            Inner_Content : constant String :=
              Seq (OID_Data & Explicit (0, Octets (Safe_Contents)));
            Authenticated_Safe : constant String := Seq (Inner_Content);
            Auth_Safe : constant String :=
              Seq (OID_Data & Explicit (0, Octets (Authenticated_Safe)));
         begin
            Bundle_Data :=
              To_Unbounded_String
                (Seq
                   (Integer_DER (3)
                    & Auth_Safe
                    & Mac_Data
                        (Authenticated_Safe, Password, Mac_Salt,
                         Iterations)));
            return Ok;
         end;
      end;
   end Generate_PKCS12;

   function RSA_Public_Key_Info
     (Modulus         : Ada.Streams.Stream_Element_Array;
      Public_Exponent : Ada.Streams.Stream_Element_Array) return String is
   begin
      if Modulus'Length = 0 or else Public_Exponent'Length = 0 then
         return "";
      end if;
      --  The BIT STRING holds a SEQUENCE of two integers, where an Edwards or
      --  EC key holds its point directly. Every reader of a certificate knows
      --  that; it is the reason an RSA key cannot be handed to the paths here
      --  that take a fixed-width public key.
      return Seq
        (RSA_Algorithm
         & Bits (Seq (Integer_From_Bytes (To_String (Modulus))
                      & Integer_From_Bytes (To_String (Public_Exponent)))));
   end RSA_Public_Key_Info;

   function RSA_Private_Key_PEM
     (Modulus          : Ada.Streams.Stream_Element_Array;
      Public_Exponent  : Ada.Streams.Stream_Element_Array;
      Private_Exponent : Ada.Streams.Stream_Element_Array;
      Prime_P          : Ada.Streams.Stream_Element_Array;
      Prime_Q          : Ada.Streams.Stream_Element_Array;
      Exponent_P       : Ada.Streams.Stream_Element_Array;
      Exponent_Q       : Ada.Streams.Stream_Element_Array;
      Coefficient      : Ada.Streams.Stream_Element_Array) return String
   is
      --  RFC 3447 RSAPrivateKey: version, then the nine values in this order.
      --  All of them are required -- a key file missing the primes or the CRT
      --  parameters is not one any other implementation will read.
      Inner : constant String :=
        Seq
          (Integer_DER (0)
           & Integer_From_Bytes (To_String (Modulus))
           & Integer_From_Bytes (To_String (Public_Exponent))
           & Integer_From_Bytes (To_String (Private_Exponent))
           & Integer_From_Bytes (To_String (Prime_P))
           & Integer_From_Bytes (To_String (Prime_Q))
           & Integer_From_Bytes (To_String (Exponent_P))
           & Integer_From_Bytes (To_String (Exponent_Q))
           & Integer_From_Bytes (To_String (Coefficient)));
   begin
      if Modulus'Length = 0 or else Private_Exponent'Length = 0
        or else Prime_P'Length = 0 or else Prime_Q'Length = 0
        or else Exponent_P'Length = 0 or else Exponent_Q'Length = 0
        or else Coefficient'Length = 0
      then
         return "";
      end if;
      return To_String
        (PEM ("PRIVATE KEY",
              Seq (Integer_DER (0) & RSA_Algorithm & Octets (Inner))));
   end RSA_Private_Key_PEM;

   --  Issue for a public key the caller brought. No key generation, so none of
   --  the fixed-width sizing that keeps RSA out of the other paths applies to
   --  the subject here; the CA still has to be one this crate can read.
   function Create_CA_For_Key
     (Common_Name        : String;
      CA_Private_Key_PEM : String;
      Certificate_PEM    : out Unbounded_String;
      Valid_Days         : Positive := Default_CA_Days;
      Use_PSS            : Boolean := False)
      return Certificate_Status
   is
      Rng  : CryptoLib.Random.Random_Source;
      Cert : Unbounded_String;

      Algorithm : constant Key_Algorithm :=
        Algorithm_Of_Private_Key (CA_Private_Key_PEM);
      CA_Priv : CA_Private_Material;
      CA_Pub  : CA_Public_Material;
      CA_N    : CA_Public_Material;
      CA_E    : CA_Public_Material;
      CA_CRT  : CA_CRT_Material;

      procedure Scrub is
      begin
         CryptoLib.Secure_Wipe.Wipe
           (CA_Priv.Slot'Address, CA_Priv.Slot'Length);
      end Scrub;
   begin
      Certificate_PEM := Null_Unbounded_String;

      if not Valid_Name (Common_Name) or else CA_Private_Key_PEM = "" then
         Scrub;
         return Invalid_Input;
      end if;
      if not Read_CA_Material
               (CA_Private_Key_PEM, Algorithm, CA_Priv, CA_Pub, CA_N, CA_E,
                CA_CRT)
      then
         Scrub;
         return Invalid_Input;
      end if;

      CryptoLib.Random.Initialize_Production (Rng);
      declare
         Serial_Value : constant String := Random_Serial (Rng);
      begin
         if Serial_Value = "" then
            Scrub;
            return Internal_Error;
         end if;
         --  Signed by the key it certifies, so issuer and subject are the
         --  same name and the same key.
         Cert :=
           To_Unbounded_String
             (Sign_Certificate
                (Serial      => Serial_Value,
                 Issuer_CN   => Common_Name,
                 Subject_CN  => Common_Name,
                 Subject_Key => Value (CA_Pub),
                 Sign_Seed   => Value (CA_Priv),
                 Sign_Public => Value (CA_Pub),
                 Profile     => CA_Profile,
                 Names       => [1 => To_Unbounded_String (Common_Name)],
                 Algorithm   => Algorithm,
                 Subject_Algorithm => Algorithm,
                 Valid_Days  => Valid_Days,
                 Sign_Modulus    => Value (CA_N),
                 Sign_Exponent   => Value (CA_E),
                 Use_PSS         => Use_PSS,
                 Sign_P          => CRT_P (CA_CRT),
                 Sign_Q          => CRT_Q (CA_CRT),
                 Sign_DP         => CRT_DP (CA_CRT),
                 Sign_DQ         => CRT_DQ (CA_CRT),
                 Sign_QI         => CRT_QI (CA_CRT)));
      end;

      if Length (Cert) = 0 then
         Scrub;
         return Internal_Error;
      end if;
      Certificate_PEM := PEM ("CERTIFICATE", To_String (Cert));
      Scrub;
      return Ok;
   exception
      when others =>
         Certificate_PEM := Null_Unbounded_String;
         Scrub;
         return Internal_Error;
   end Create_CA_For_Key;

   --  Is this a SubjectPublicKeyInfo?
   --
   --  Issue_*_For_Key takes the subject's key as bytes and does not ask whether
   --  it is a key this crate could have produced -- a token's key, or one made
   --  elsewhere, is the point of that entry point. It does ask whether it is a
   --  key at all. Certifying four octets of nothing produces a certificate that
   --  parses as broken and is useless to everyone, while telling the caller it
   --  worked; this crate already declines to certify a name that is not a name,
   --  and a public key deserves the same answer.
   --
   --  The shape checked is the whole of RFC 5280's definition: a SEQUENCE
   --  spanning exactly these octets, holding an AlgorithmIdentifier SEQUENCE
   --  and then a BIT STRING, with nothing after either. What algorithm the
   --  identifier names is deliberately not checked.
   function Valid_Public_Key_Info
     (Info : Ada.Streams.Stream_Element_Array) return Boolean
   is
      package DER_Reader renames CryptoLib.ASN1.DER;
      use type CryptoLib.ASN1.Errors.Decode_Status;

      Limits : constant CryptoLib.ASN1.Decode_Limits :=
        CryptoLib.ASN1.Default_Limits;
      Cursor : CryptoLib.ASN1.Offset := Info'First;
      Outer, Algorithm_Item, Key_Item : CryptoLib.ASN1.Element;
      Unused : Natural;
      Status : CryptoLib.ASN1.Errors.Decode_Status;
   begin
      if Info'Length = 0 then
         return False;
      end if;

      DER_Reader.Read_Sequence
        (Info, Cursor, Info'Last, 0, Limits, Outer, Status);
      if Status /= CryptoLib.ASN1.Errors.Ok
        or else not DER_Reader.At_End (Cursor, Info'Last)
      then
         --  Either it is not a SEQUENCE, or there are octets after it: a
         --  SubjectPublicKeyInfo is the whole of what it is given.
         return False;
      end if;

      Cursor := Outer.First;
      DER_Reader.Read_Sequence
        (Info, Cursor, Outer.Last, 1, Limits,
         Algorithm_Item, Status);
      if Status /= CryptoLib.ASN1.Errors.Ok then
         return False;
      end if;

      Cursor := Algorithm_Item.Last + 1;
      DER_Reader.Read_Bit_String
        (Info, Cursor, Outer.Last, 1, Limits,
         Key_Item, Unused, Status);
      if Status /= CryptoLib.ASN1.Errors.Ok then
         return False;
      end if;

      return DER_Reader.At_End
               (Cursor, Outer.Last);
   exception
      when others =>
         return False;
   end Valid_Public_Key_Info;

   function Issue_For_Supplied_Key
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Names              : Subject_Alternative_Name_List;
      Subject_SPKI       : Ada.Streams.Stream_Element_Array;
      Profile            : Certificate_Profile;
      Certificate_PEM    : out Unbounded_String;
      Valid_Days         : Positive;
      Use_PSS            : Boolean) return Certificate_Status
   is
      Rng : CryptoLib.Random.Random_Source;

      Issuer_Name : Unbounded_String;
      Have_Issuer : constant Boolean :=
        Certificate_Subject_CN (CA_Certificate_PEM, Issuer_Name);

      CA_Ends_Known : Boolean;
      CA_Ends       : constant Ada.Calendar.Time :=
        Issuer_Expiry (CA_Certificate_PEM, CA_Ends_Known);

      Algorithm : constant Key_Algorithm :=
        Algorithm_Of_Private_Key (CA_Private_Key_PEM);
      CA_Priv : CA_Private_Material;
      CA_Pub  : CA_Public_Material;
      CA_N    : CA_Public_Material;
      CA_E    : CA_Public_Material;
      CA_CRT  : CA_CRT_Material;
      Cert : Unbounded_String;

      procedure Scrub is
      begin
         CryptoLib.Secure_Wipe.Wipe
           (CA_Priv.Slot'Address, CA_Priv.Slot'Length);
      end Scrub;
   begin
      Certificate_PEM := Null_Unbounded_String;

      if not Have_Issuer
        or else CA_Private_Key_PEM = ""
        or else not Valid_Public_Key_Info (Subject_SPKI)
        or else not Valid_Profile_Name (Profile, Common_Name)
        or else Names'Length = 0
        or else Profile = CA_Profile
      then
         Scrub;
         return Invalid_Input;
      end if;
      for Name of Names loop
         if not Valid_Profile_Name (Profile, To_String (Name)) then
            Scrub;
            return Invalid_Input;
         end if;
      end loop;
      if not Read_CA_Material
               (CA_Private_Key_PEM, Algorithm, CA_Priv, CA_Pub, CA_N, CA_E,
                CA_CRT)
      then
         Scrub;
         return Invalid_Input;
      end if;

      CryptoLib.Random.Initialize_Production (Rng);
      declare
         Serial_Value : constant String := Random_Serial (Rng);
      begin
         if Serial_Value = "" then
            Scrub;
            return Internal_Error;
         end if;
         Cert :=
           To_Unbounded_String
             (Sign_Certificate
                (Serial      => Serial_Value,
                 Issuer_CN   => To_String (Issuer_Name),
                 Subject_CN  => Common_Name,
                 Subject_Key => Subject_SPKI,
                 Sign_Seed   => Value (CA_Priv),
                 Sign_Public => Value (CA_Pub),
                 Profile     => Profile,
                 Names       => Names,
                 Algorithm   => Algorithm,
                 Subject_Algorithm => Algorithm,
                 Valid_Days  => Valid_Days,
                 Limit_Present   => CA_Ends_Known,
                 Not_After_Limit => CA_Ends,
                 Subject_SPKI    => To_String (Subject_SPKI),
                 Sign_Modulus    => Value (CA_N),
                 Sign_Exponent   => Value (CA_E),
                 Use_PSS         => Use_PSS,
                 Sign_P          => CRT_P (CA_CRT),
                 Sign_Q          => CRT_Q (CA_CRT),
                 Sign_DP         => CRT_DP (CA_CRT),
                 Sign_DQ         => CRT_DQ (CA_CRT),
                 Sign_QI         => CRT_QI (CA_CRT)));
      end;

      if Length (Cert) = 0 then
         Scrub;
         return Internal_Error;
      end if;
      Certificate_PEM := PEM ("CERTIFICATE", To_String (Cert));
      Scrub;
      return Ok;
   exception
      when others =>
         Certificate_PEM := Null_Unbounded_String;
         Scrub;
         return Internal_Error;
   end Issue_For_Supplied_Key;

   function Issue_Server_Certificate_For_Key
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Names              : Subject_Alternative_Name_List;
      Subject_SPKI       : Ada.Streams.Stream_Element_Array;
      Certificate_PEM    : out Unbounded_String;
      Valid_Days         : Positive := Default_Certificate_Days;
      Use_PSS            : Boolean := False)
      return Certificate_Status is
   begin
      return Issue_For_Supplied_Key
        (CA_Certificate_PEM, CA_Private_Key_PEM, Common_Name, Names,
         Subject_SPKI, Server_Profile, Certificate_PEM, Valid_Days, Use_PSS);
   end Issue_Server_Certificate_For_Key;

   function Issue_Email_Certificate_For_Key
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Names              : Subject_Alternative_Name_List;
      Subject_SPKI       : Ada.Streams.Stream_Element_Array;
      Certificate_PEM    : out Unbounded_String;
      Valid_Days         : Positive := Default_Certificate_Days;
      Use_PSS            : Boolean := False)
      return Certificate_Status is
   begin
      return Issue_For_Supplied_Key
        (CA_Certificate_PEM, CA_Private_Key_PEM, Common_Name, Names,
         Subject_SPKI, Email_Profile, Certificate_PEM, Valid_Days, Use_PSS);
   end Issue_Email_Certificate_For_Key;

   function Issue_Client_Certificate_For_Key
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Names              : Subject_Alternative_Name_List;
      Subject_SPKI       : Ada.Streams.Stream_Element_Array;
      Certificate_PEM    : out Unbounded_String;
      Valid_Days         : Positive := Default_Certificate_Days;
      Use_PSS            : Boolean := False)
      return Certificate_Status is
   begin
      return Issue_For_Supplied_Key
        (CA_Certificate_PEM, CA_Private_Key_PEM, Common_Name, Names,
         Subject_SPKI, Client_Profile, Certificate_PEM, Valid_Days, Use_PSS);
   end Issue_Client_Certificate_For_Key;

end CryptoLib.Certificates;
