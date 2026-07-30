with Ada.Streams;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Interfaces;
with System;
with CryptoLib.ASN1;
with CryptoLib.PEM;
with CryptoLib.X509;
with CryptoLib.X509.Certificates;
with CryptoLib.X509.Extensions;
with CryptoLib.X509.Identity;
with CryptoLib.X509.Purposes;
with CryptoLib.X509.Names;
with Ada.Directories;
with Ada.Streams.Stream_IO;
with CryptoLib.X509.CRLs;
with CryptoLib.X509.Revocation;
with CryptoLib.OCSP;
with CryptoLib.PKCS10;
with CryptoLib.PKCS8;
with CryptoLib.PKCS12;
with CryptoLib.Identities;
with CryptoLib.X509.Policies;
with CryptoLib.HKDF;
with CryptoLib.TLS13_KDF;
with CryptoLib.ECDH;
with CryptoLib.Constant_Time_Proof;
with CryptoLib.Constant_Time_Assurance;
with CryptoLib.MLKEM768_Core;
with CryptoLib.EC_Curves;
with CryptoLib.Hybrid_PQ_Kex;
with CryptoLib.Fingerprints;
with CryptoLib.Constant_Time;
with CryptoLib.BCrypt_PBKDF;
with CryptoLib.X509.Times;
with CryptoLib.X509.Validation;
with CryptoLib.X509.Path_Building;
with CryptoLib.X509.Name_Constraints;
with CryptoLib.X509.Signatures;
with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.Errors;
with CryptoLib.ASN1.OIDs;
with CryptoLib.ChaCha20_Poly1305;
with CryptoLib.Certificates;
with OpenSSL_Interop;
with CryptoLib.Checksums;
with CryptoLib.Secure_Wipe;
with CryptoLib.Hashes;
with CryptoLib.Ciphers;
with CryptoLib.ECDSA;
with CryptoLib.Errors;
with CryptoLib.Macs;
with CryptoLib.UMAC;
with CryptoLib.MLKEM768;
with CryptoLib.SNTRUP761;
with CryptoLib.Curve25519;
with CryptoLib.Ed25519;
with CryptoLib.Ed448;
with CryptoLib.SHA3;
with CryptoLib.Buffers;
with CryptoLib.Diffie_Hellman;
with CryptoLib.Modexp;
with CryptoLib.Bignum;
with CryptoLib.Random;
with CryptoLib.RSA;
with Tests_Support; use Tests_Support;

package body Tests_Runtime is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Certificates.Certificate_Status;
   use type Interfaces.Unsigned_32;


   --  What happens when there is no randomness.
   --
   --  The RNG is documented to fail closed: no OS source means
   --  Internal_Error and a zeroed buffer, never weak bytes. Nothing tested
   --  that, and the regression it invites is quiet -- somebody making a
   --  failing source "work" by falling back to something deterministic
   --  leaves no trace, and every key generated afterwards is predictable
   --  while every status still reads Ok.
   --
   --  So this checks the failure at the source and then that it propagates:
   --  a key generator handed a source that cannot deliver must refuse rather
   --  than build a key out of whatever the buffer happened to hold.
   procedure Check_Random_Fails_Closed is
      Rng    : CryptoLib.Random.Random_Source;
      Buffer : Ada.Streams.Stream_Element_Array (1 .. 32) := [others => 16#AA#];
   begin
      CryptoLib.Random.Initialize_Failing (Rng);

      Check (CryptoLib.Random.Fill (Rng, Buffer) /= CryptoLib.Errors.Ok,
             "a source that cannot deliver says so");

      --  Zeroed, not left as it was: a caller that ignores the status must
      --  not find the bytes it supplied looking like fresh randomness.
      declare
         Untouched : Boolean := False;
      begin
         for B of Buffer loop
            if B /= 0 then
               Untouched := True;
            end if;
         end loop;
         Check (not Untouched,
                "and leaves nothing behind that could pass for randomness");
      end;

      --  The failure has to reach the caller of a key generator, not be
      --  swallowed into a key made of zeros.
      declare
         Seed   : Ada.Streams.Stream_Element_Array (1 .. 48) :=
           [others => 16#BB#];
         Public : Ada.Streams.Stream_Element_Array (1 .. 97) :=
           [others => 16#CC#];
      begin
         Check (CryptoLib.ECDSA.Generate_Nistp384_Keypair (Rng, Seed, Public)
                /= CryptoLib.Errors.Ok,
                "a P-384 key pair is not generated without randomness");
      end;

      declare
         Seed_25519   : Ada.Streams.Stream_Element_Array (1 .. 32) :=
           [others => 16#BB#];
         Public_25519 : Ada.Streams.Stream_Element_Array (1 .. 32) :=
           [others => 16#CC#];
      begin
         Check (CryptoLib.Ed25519.Generate_Keypair
                  (Rng, Seed_25519, Public_25519)
                /= CryptoLib.Errors.Ok,
                "nor an Ed25519 one");
      end;

      --  And the production source still works, so the checks above are
      --  about the failing mode rather than about these calls always failing.
      declare
         Live   : CryptoLib.Random.Random_Source;
         Sample : Ada.Streams.Stream_Element_Array (1 .. 32) := [others => 0];
         Any    : Boolean := False;
      begin
         CryptoLib.Random.Initialize_Production (Live);
         Check (CryptoLib.Random.Fill (Live, Sample) = CryptoLib.Errors.Ok,
                "the production source delivers");
         for B of Sample loop
            if B /= 0 then
               Any := True;
            end if;
         end loop;
         Check (Any, "and delivers something other than zeros");
      end;
   end Check_Random_Fails_Closed;


   --  The comparison every tag check goes through.
   --
   --  Its shape is held to a jump budget by check_constant_time, so it
   --  cannot quietly acquire an early return; that says nothing about
   --  whether it answers correctly, and nothing named it. A tamper test on
   --  an AEAD reaches it, but only for the byte that test happens to
   --  disturb.
   procedure Check_Constant_Time_Equal is
      A : constant Ada.Streams.Stream_Element_Array (1 .. 8) :=
        [1, 2, 3, 4, 5, 6, 7, 8];
      Empty : constant Ada.Streams.Stream_Element_Array (1 .. 0) :=
        [others => 0];

      function Differing_At (Where : Positive) return Boolean is
         B : Ada.Streams.Stream_Element_Array (1 .. 8) := A;
      begin
         B (Ada.Streams.Stream_Element_Offset (Where)) :=
           B (Ada.Streams.Stream_Element_Offset (Where)) xor 16#80#;
         return CryptoLib.Constant_Time.Equal (A, B);
      end Differing_At;
   begin
      Check (CryptoLib.Constant_Time.Equal (A, A),
             "a value equals itself");

      --  Every position, because a comparison that stops early or runs one
      --  short is right about all the others.
      for Where in 1 .. 8 loop
         Check (not Differing_At (Where),
                "a difference at byte" & Natural'Image (Where) & " is seen");
      end loop;

      Check (not CryptoLib.Constant_Time.Equal (A, A (1 .. 7)),
             "a shorter value is not equal to a longer one");
      Check (not CryptoLib.Constant_Time.Equal (A (1 .. 7), A),
             "nor the other way round");
      Check (CryptoLib.Constant_Time.Equal (Empty, Empty),
             "two empty values are equal, which is what the contract says");
   end Check_Constant_Time_Equal;


   --  The packet buffer's ceiling, one byte at a time.
   --
   --  Append_Byte is what ssh_lib fills a buffer with when it is building
   --  from something it read, and the ceiling is the only thing between a
   --  peer's idea of how much to send and this crate's storage. The bound is
   --  written down and was never exercised.
   --
   --  What matters as much as the refusal is that the refusal changes
   --  nothing: a buffer that grew by one past its limit and then reported
   --  failure would have written somewhere it should not.
   --
   --  Two things enforce it, which is worth knowing before someone tidies
   --  one away. Append_Byte tests the ceiling itself, and Last is of a
   --  subtype that stops at it, so the assignment would raise and the
   --  handler would return a status regardless. Deleting the explicit test
   --  changes nothing observable here -- I tried it -- so this pins the
   --  behaviour rather than either mechanism, and a change that removed
   --  both would fail it.
   procedure Check_Buffer_Ceiling is
      Item   : CryptoLib.Buffers.Packet_Buffer;
      Status : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
   begin
      CryptoLib.Buffers.Clear (Item);
      Check (CryptoLib.Buffers.Is_Empty (Item), "a cleared buffer is empty");

      --  Right up to the ceiling.
      for Count in 1 .. CryptoLib.Buffers.Max_Packet_Length loop
         Status := CryptoLib.Buffers.Append_Byte (Item, 16#5A#);
         exit when Status /= CryptoLib.Errors.Ok;
      end loop;
      Check (Status = CryptoLib.Errors.Ok,
             "a buffer fills to its stated capacity a byte at a time");
      Check (CryptoLib.Buffers.Length (Item)
             = CryptoLib.Buffers.Max_Packet_Length,
             "and holds exactly that many, got"
             & Natural'Image (CryptoLib.Buffers.Length (Item)));

      --  One past it.
      Status := CryptoLib.Buffers.Append_Byte (Item, 16#5A#);
      Check (Status /= CryptoLib.Errors.Ok,
             "the byte after the last is refused rather than written");
      Check (CryptoLib.Buffers.Length (Item)
             = CryptoLib.Buffers.Max_Packet_Length,
             "and the refusal leaves the buffer the length it already was");

      --  Set starts over rather than appending to what was there.
      Status := CryptoLib.Buffers.Set (Item, [1 => 16#01#, 2 => 16#02#]);
      Check (Status = CryptoLib.Errors.Ok
             and then CryptoLib.Buffers.Length (Item) = 2,
             "and Set replaces the contents rather than adding to them, got"
             & Natural'Image (CryptoLib.Buffers.Length (Item)));
   end Check_Buffer_Ceiling;


   --  HKDF (RFC 5869).
   --
   --  Written from the RFC in Python and checked against pyca before any of
   --  the Ada existed, which is the order that catches a transcription error
   --  rather than enshrining it. The SHA-256 vectors are the RFC's own A.1,
   --  A.2 and A.3 -- basic, long inputs, and the empty salt and info the
   --  specification treats as meaningful rather than as an error. The
   --  SHA-384 and SHA-512 ones were produced by the same reference and
   --  agreed with pyca.
   --  Every out buffer in the cipher, AEAD, ECDSA and KDF entry points is
   --  documented as zero when the status is not Ok. Nothing checked that, so
   --  it could have decayed into a comment. Each case here pre-fills the
   --  buffer with a pattern that is not zero, forces the failure, and looks
   --  at what is left: a partial plaintext, half a signature, or the caller's
   --  own stale bytes would all survive a status check that a caller forgot
   --  to make.
   --  Six public entry points that a shipping consumer calls and this suite
   --  never did: sshlib uses AES_GCM_Key_Length, Encrypt_GCM_Length,
   --  Is_OpenSSH_Hybrid_PQ_Kex_Name and Policies.Encoded_Value; versionlib
   --  uses Ciphers.Is_Active and Errors.Is_Success. Each is checked against
   --  the code that consumes its answer rather than against a restatement of
   --  its body, so a wrong answer has to disagree with something real.
   procedure Check_Consumer_Entry_Points is
      package HP renames CryptoLib.Hybrid_PQ_Kex;
      package PO renames CryptoLib.X509.Policies;

      --  The GCM key length has to be the length Seal_GCM will accept: a
      --  number that is merely self-consistent would still break the caller
      --  sizing a key from it.
      procedure Check_GCM_Width (Text : String; Want : Natural) is
         Width : constant Natural :=
           CryptoLib.Ciphers.AES_GCM_Key_Length (Text);
         Nonce : constant Ada.Streams.Stream_Element_Array (1 .. 12) :=
           [others => 1];
         Plain : constant Ada.Streams.Stream_Element_Array (1 .. 8) :=
           [others => 16#5A#];
         Wire  : Ada.Streams.Stream_Element_Array (1 .. 24);
      begin
         Check (Width = Want, "AES_GCM_Key_Length names " & Text);
         declare
            Key : constant Ada.Streams.Stream_Element_Array
              (1 .. Ada.Streams.Stream_Element_Offset (Width)) := [others => 3];
            Short : constant Ada.Streams.Stream_Element_Array
              (1 .. Ada.Streams.Stream_Element_Offset (Width) - 1) :=
                [others => 3];
         begin
            Check (CryptoLib.Ciphers.Seal_GCM (Text, Key, Nonce, 0, Plain, Wire)
                     = CryptoLib.Errors.Ok,
                   "a key of that length is the length Seal_GCM wants");
            Check (CryptoLib.Ciphers.Seal_GCM
                     (Text, Short, Nonce, 0, Plain, Wire)
                     /= CryptoLib.Errors.Ok,
                   "one octet short is refused, so " & Text
                   & "'s length is not merely a lower bound");
         end;
      end Check_GCM_Width;

      --  The predicate must agree with the table it reads, in both
      --  directions, and a hybrid name must carry lengths where a classic
      --  one must not.
      procedure Check_Hybrid_Name (Text : String) is
         use type HP.Hybrid_PQ_Kind;
         Shown  : constant String :=
           (if Text = "" then "the empty name" else Text);
         Hybrid : constant Boolean := HP.Is_OpenSSH_Hybrid_PQ_Kex_Name (Text);
      begin
         Check (Hybrid = (HP.Kind_Of (Text) /= HP.Not_Hybrid_PQ),
                "Is_OpenSSH_Hybrid_PQ_Kex_Name agrees with Kind_Of on " & Shown);
         Check ((HP.Client_Init_Total_Length (Text) > 0) = Hybrid,
                "the client-init length is present exactly when hybrid: "
                & Shown);
      end Check_Hybrid_Name;
   begin
      --  The GCM key length has to be the length Seal_GCM will accept: a
      --  number that is merely self-consistent would still break the caller
      --  sizing a key from it.
      Check_GCM_Width ("aes128-gcm@openssh.com", 16);
      Check_GCM_Width ("aes256-gcm@openssh.com", 32);
      Check (CryptoLib.Ciphers.AES_GCM_Key_Length ("aes192-gcm@openssh.com") = 0
             and then CryptoLib.Ciphers.AES_GCM_Key_Length ("aes256-ctr") = 0
             and then CryptoLib.Ciphers.AES_GCM_Key_Length ("") = 0,
             "AES_GCM_Key_Length answers zero for a name it does not know");

      --  The GCM length step is the identity, but it is a seam the caller
      --  goes through every packet, so its refusals matter as much.
      declare
         Key    : constant Ada.Streams.Stream_Element_Array (1 .. 32) :=
           [others => 7];
         Nonce  : constant Ada.Streams.Stream_Element_Array (1 .. 12) :=
           [others => 2];
         Header : constant Ada.Streams.Stream_Element_Array (1 .. 4) :=
           [16#00#, 16#00#, 16#01#, 16#2C#];
         Out4   : Ada.Streams.Stream_Element_Array (1 .. 4) :=
           [others => 16#A5#];
         Out3   : Ada.Streams.Stream_Element_Array (1 .. 3) :=
           [others => 16#A5#];
         St     : CryptoLib.Errors.Status;
      begin
         St := CryptoLib.Ciphers.Encrypt_GCM_Length
           ("aes256-gcm@openssh.com", Key, Nonce, 0, Header, Out4);
         Check (St = CryptoLib.Errors.Ok and then Out4 = Header,
                "Encrypt_GCM_Length passes the cleartext length through");

         St := CryptoLib.Ciphers.Encrypt_GCM_Length
           ("aes256-gcm@openssh.com", Key, Nonce, 0, Header, Out3);
         Check (St /= CryptoLib.Errors.Ok,
                "Encrypt_GCM_Length refuses an output that is not four octets");
         Check (Out3 = [Out3'Range => 0],
                "and zeroes it, like every other out buffer here");
      end;

      --  A context is inactive until it is keyed, and inactive again after a
      --  Reset -- which is what versionlib asks it.
      declare
         Item : CryptoLib.Ciphers.Cipher_State;
         Key  : constant Ada.Streams.Stream_Element_Array (1 .. 32) :=
           [others => 4];
         IV   : constant Ada.Streams.Stream_Element_Array (1 .. 16) :=
           [others => 5];
      begin
         CryptoLib.Ciphers.Reset (Item);
         Check (not CryptoLib.Ciphers.Is_Active (Item),
                "a reset cipher context is inactive");
         Check (CryptoLib.Ciphers.Initialize
                  (Item, "aes256-ctr", CryptoLib.Ciphers.Client_To_Server,
                   Key, IV) = CryptoLib.Errors.Ok,
                "the context keys");
         Check (CryptoLib.Ciphers.Is_Active (Item),
                "a keyed cipher context is active");
         CryptoLib.Ciphers.Reset (Item);
         Check (not CryptoLib.Ciphers.Is_Active (Item),
                "Reset makes it inactive again");
      end;

      --  Is_Success must be true for exactly one value. Written as a sweep of
      --  the whole enumeration rather than a couple of spot checks, so a
      --  status added later cannot quietly join the success side.
      declare
         Successes : Natural := 0;
      begin
         for St in CryptoLib.Errors.Status loop
            if CryptoLib.Errors.Is_Success (St) then
               Successes := Successes + 1;
               Check (St = CryptoLib.Errors.Ok,
                      "Is_Success is true only for Ok, not " & St'Image);
            end if;
         end loop;
         Check (Successes = 1, "exactly one status counts as success");
      end;

      --  The hybrid-PQ predicate must agree with the table it reads, in both
      --  directions, for every name the table knows and for one it does not.
      Check_Hybrid_Name ("mlkem768x25519-sha256");
      Check_Hybrid_Name ("mlkem768x25519-sha512");
      Check_Hybrid_Name ("sntrup761x25519-sha512");
      Check_Hybrid_Name ("sntrup761x25519-sha512@openssh.com");
      Check_Hybrid_Name ("curve25519-sha256");
      Check_Hybrid_Name ("diffie-hellman-group14-sha256");
      Check_Hybrid_Name ("");

      --  A policy OID must survive the round trip it is put through whenever
      --  one is reported back to a caller.
      declare
         Encoded : constant PO.Octets := [16#2A#, 16#86#, 16#48#, 16#86#,
                                          16#F7#, 16#0D#, 16#01#, 16#07#];
         Value   : constant PO.Policy_Value := PO.To_Policy (Encoded);
         Any     : constant PO.Policy_Value := PO.Any_Policy;
      begin
         Check (PO.Is_Present (Value), "an OID becomes a policy value");
         Check (PO.Encoded_Value (Value) = Encoded,
                "Encoded_Value returns the octets it was given");
         Check (PO.Encoded_Value (Any)
                  = PO.Octets'[16#55#, 16#1D#, 16#20#, 16#00#],
                "anyPolicy encodes as 2.5.29.32.0");
         Check (PO.Is_Any (Any) and then not PO.Is_Any (Value),
                "Is_Any tells anyPolicy from an ordinary policy");
      end;
   end Check_Consumer_Entry_Points;


   --  The manifests this crate publishes about itself, and a handful of small
   --  public helpers that nothing else in the suite reached.
   procedure Check_Manifests_And_Helpers is
      package CA renames CryptoLib.Constant_Time_Assurance;
      package CP renames CryptoLib.Constant_Time_Proof;
      package HP renames CryptoLib.Hybrid_PQ_Kex;
      use type CA.Assurance_Level;
      use type CA.Crypto_Primitive;
      use type CP.Proof_Status;
      use type HP.Hybrid_PQ_Readiness;
   begin
      --  A manifest that claims coverage it does not have is worse than no
      --  manifest, so these check the claims against each other.
      Check (CA.Manifest_Version /= "", "the assurance manifest is versioned");
      Check (CA.All_Primitives_Assessed,
             "every primitive in the manifest has been assessed");
      for Item in CA.Crypto_Primitive loop
         declare
            Label : constant String := CA.Primitive_Label (Item);
         begin
            Check (Label /= "",
                   "every primitive has a label: " & Item'Image);
            Check (CA.Level (Item) /= CA.Not_Assessed,
                   "no primitive is left unassessed: " & Label);
            --  Gated and review-required are recorded facts, not opinions;
            --  each must follow from the level rather than float free.
            Check (CA.Is_Assurance_Gated (Item)
                     = (CA.Level (Item) in CA.Fixed_Iteration_Audited
                          | CA.Source_Gated_Formal_Assurance),
                   "gating follows from the level for " & Label);
            --  True for every primitive, by design and not by omission: the
            --  in-tree gate is a source-evidence gate and does not stand in
            --  for independent leakage tooling, compiler inspection or
            --  third-party review. Pinned so that a primitive cannot quietly
            --  start claiming it needs none.
            Check (CA.Requires_External_Review (Item),
                   "external review is still required for " & Label);
         end;
      end loop;

      --  Labels have to be distinct or the manifest cannot be read.
      for Left in CA.Crypto_Primitive loop
         for Right in CA.Crypto_Primitive loop
            if Left /= Right then
               Check (CA.Primitive_Label (Left) /= CA.Primitive_Label (Right),
                      "two primitives share a label: "
                      & CA.Primitive_Label (Left));
            end if;
         end loop;
      end loop;

      Check (CP.Formal_Proof_Manifest_Version /= "",
             "the proof manifest is versioned");
      for Item in CP.Proof_Obligation loop
         Check (CP.Obligation_Label (Item) /= "",
                "every proof obligation has a label: " & Item'Image);
      end loop;
      for Item in CA.Crypto_Primitive loop
         declare
            Discharged : constant Boolean :=
              CP.Source_Obligations_Discharged (Item);
            External : constant Boolean :=
              CP.External_Proof_Remains_Required (Item);
            Any_Missing : Boolean := False;
            Any_External : Boolean := False;
         begin
            for Obligation in CP.Proof_Obligation loop
               case CP.Status (Item, Obligation) is
                  when CP.Missing => Any_Missing := True;
                  when CP.External_Evidence_Required => Any_External := True;
                  when CP.Source_Obligation_Discharged => null;
               end case;
            end loop;
            Check (Discharged = not Any_Missing,
                   "source obligations are discharged exactly when none is "
                   & "missing: " & CA.Primitive_Label (Item));
            Check (External = Any_External,
                   "external proof is required exactly when some obligation "
                   & "says so: " & CA.Primitive_Label (Item));
         end;
      end loop;
      Check (CP.All_Source_Obligations_Discharged
               = (for all Item in CA.Crypto_Primitive =>
                    CP.Source_Obligations_Discharged (Item)),
             "the summary agrees with the primitives it summarizes");

      --  Hybrid-PQ wire lengths must be the KEM's own, not a second copy.
      Check (HP.Client_Init_PQ_Length ("mlkem768x25519-sha256")
               = CryptoLib.MLKEM768.Public_Key_Length
             and then HP.Server_Reply_PQ_Length ("mlkem768x25519-sha256")
               = CryptoLib.MLKEM768.Ciphertext_Length,
             "ML-KEM hybrid lengths are the KEM's own");
      Check (HP.Client_Init_PQ_Length ("sntrup761x25519-sha512@openssh.com")
               = CryptoLib.SNTRUP761.Public_Key_Length
             and then HP.Server_Reply_PQ_Length
               ("sntrup761x25519-sha512@openssh.com")
               = CryptoLib.SNTRUP761.Ciphertext_Length,
             "sntrup761 hybrid lengths are the KEM's own");
      Check (HP.Server_Reply_Total_Length ("mlkem768x25519-sha256")
               = HP.Server_Reply_PQ_Length ("mlkem768x25519-sha256") + 32,
             "the server reply carries the KEM ciphertext plus x25519");
      Check (HP.Client_Init_PQ_Length ("curve25519-sha256") = 0
             and then HP.Server_Reply_PQ_Length ("curve25519-sha256") = 0
             and then HP.Server_Reply_Total_Length ("curve25519-sha256") = 0,
             "a classic method carries no post-quantum length");

      --  Readiness has a stable rendering, and an unknown name is unknown
      --  rather than accidentally ready.
      for Value in HP.Hybrid_PQ_Readiness loop
         Check (HP.Readiness_Image (Value) /= "",
                "every readiness state renders: " & Value'Image);
      end loop;
      Check (HP.Readiness_Of ("not-a-kex-method")
               = HP.Unknown_Algorithm,
             "an unrecognized method is reported unknown");
      Check (HP.Readiness_Image (HP.Readiness_Of ("mlkem768x25519-sha256"))
               /= HP.Readiness_Image (HP.Unknown_Algorithm),
             "a method this crate implements is not reported unknown");

      --  The raw CRC-32 step must agree with the state-based one it underlies.
      declare
         Data : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String ("123456789");
         Raw  : Interfaces.Unsigned_32 := 16#FFFF_FFFF#;
      begin
         for B of Data loop
            CryptoLib.Checksums.CRC32_Update_Raw (Raw, B);
         end loop;
         Check ((Raw xor 16#FFFF_FFFF#) = CryptoLib.Checksums.CRC32 (Data),
                "the raw CRC-32 step finalizes to the same value as CRC32");
         --  And that value is the published check word for this input.
         Check (CryptoLib.Checksums.CRC32 (Data) = 16#CBF4_3926#,
                "CRC-32 of the standard check string");
      end;

      --  UMAC's encrypt-then-MAC names.
      Check (CryptoLib.UMAC.Is_EtM_Name ("umac-64-etm@openssh.com")
             and then CryptoLib.UMAC.Is_EtM_Name ("umac-128-etm@openssh.com"),
             "the -etm names are recognized as encrypt-then-MAC");
      Check (not CryptoLib.UMAC.Is_EtM_Name ("umac-64@openssh.com")
             and then not CryptoLib.UMAC.Is_EtM_Name ("hmac-sha2-256")
             and then not CryptoLib.UMAC.Is_EtM_Name (""),
             "the plain names are not, and neither is anything else");

      --  Name-constraint verdicts render distinctly, so a diagnostic cannot
      --  say "permitted" when it means "excluded".
      declare
         package NC renames CryptoLib.X509.Name_Constraints;
         use type NC.Verdict;
      begin
         for Left in NC.Verdict loop
            Check (NC.Verdict_Image (Left) /= "",
                   "every name-constraint verdict renders: " & Left'Image);
            for Right in NC.Verdict loop
               if Left /= Right then
                  Check (NC.Verdict_Image (Left) /= NC.Verdict_Image (Right),
                         "two verdicts render alike: "
                         & NC.Verdict_Image (Left));
               end if;
            end loop;
         end loop;
      end;

      --  DH group 14 client value: it must be one the consuming side accepts.
      declare
         Rng    : CryptoLib.Random.Random_Source;
         Public : CryptoLib.Buffers.Packet_Buffer;
      begin
         CryptoLib.Random.Initialize_Production (Rng);
         Check (CryptoLib.Diffie_Hellman.Generate_Group14_Client_Value
                  (Rng, Public) = CryptoLib.Errors.Ok,
                "a group-14 client value is generated");
         Check (CryptoLib.Buffers.Length (Public) > 0,
                "and it is not empty");
      end;
   end Check_Manifests_And_Helpers;


   procedure Check_Zero_On_Failure is
      Pattern : constant Ada.Streams.Stream_Element := 16#A5#;

      function All_Zero (Item : Ada.Streams.Stream_Element_Array) return Boolean is
      begin
         for B of Item loop
            if B /= 0 then
               return False;
            end if;
         end loop;
         return True;
      end All_Zero;
   begin
      --  AES-GCM, SSH framing: a flipped tag bit must leave nothing behind.
      declare
         Key    : constant Ada.Streams.Stream_Element_Array (1 .. 32) := [others => 7];
         Nonce  : constant Ada.Streams.Stream_Element_Array (1 .. 12) := [others => 3];
         Plain  : constant Ada.Streams.Stream_Element_Array (1 .. 20) := [others => 16#5C#];
         Sealed : Ada.Streams.Stream_Element_Array (1 .. 36) := [others => 0];
         Out_Buf : Ada.Streams.Stream_Element_Array (1 .. 20) := [others => Pattern];
         Result : CryptoLib.Errors.Status;
      begin
         Result := CryptoLib.Ciphers.Seal_GCM
           ("aes256-gcm@openssh.com", Key, Nonce, 0, Plain, Sealed);
         Check (Result = CryptoLib.Errors.Ok, "Seal_GCM seals for the zeroing test");
         Sealed (Sealed'Last) := Sealed (Sealed'Last) xor 1;
         Result := CryptoLib.Ciphers.Open_GCM
           ("aes256-gcm@openssh.com", Key, Nonce, 0, Sealed, Out_Buf);
         Check (Result /= CryptoLib.Errors.Ok, "Open_GCM rejects a flipped tag");
         Check (All_Zero (Out_Buf), "Open_GCM zeroes its output on a bad tag");
      end;

      --  AES-GCM, general purpose.
      declare
         Key    : constant Ada.Streams.Stream_Element_Array (1 .. 32) := [others => 9];
         Nonce  : constant Ada.Streams.Stream_Element_Array (1 .. 12) := [others => 4];
         Aad    : constant Ada.Streams.Stream_Element_Array (1 .. 5)  := [others => 1];
         Plain  : constant Ada.Streams.Stream_Element_Array (1 .. 12) := [others => 16#3B#];
         Sealed : Ada.Streams.Stream_Element_Array (1 .. 28) := [others => 0];
         Out_Buf : Ada.Streams.Stream_Element_Array (1 .. 12) := [others => Pattern];
         Result : CryptoLib.Errors.Status;
      begin
         Result := CryptoLib.Ciphers.Seal_AEAD
           ("aes256-gcm@openssh.com", Key, Nonce, Aad, Plain, Sealed);
         Check (Result = CryptoLib.Errors.Ok, "Seal_AEAD seals for the zeroing test");
         Sealed (Sealed'First) := Sealed (Sealed'First) xor 16#80#;
         Result := CryptoLib.Ciphers.Open_AEAD
           ("aes256-gcm@openssh.com", Key, Nonce, Aad, Sealed, Out_Buf);
         Check (Result /= CryptoLib.Errors.Ok, "Open_AEAD rejects tampered ciphertext");
         Check (All_Zero (Out_Buf), "Open_AEAD zeroes its output on a bad tag");
      end;

      --  ChaCha20-Poly1305.
      declare
         Key    : constant Ada.Streams.Stream_Element_Array (1 .. 64) := [others => 16#2A#];
         Plain  : constant Ada.Streams.Stream_Element_Array (1 .. 16) := [others => 16#77#];
         Sealed : Ada.Streams.Stream_Element_Array (1 .. 32) := [others => 0];
         Out_Buf : Ada.Streams.Stream_Element_Array (1 .. 16) := [others => Pattern];
         Result : CryptoLib.Errors.Status;
      begin
         Result := CryptoLib.ChaCha20_Poly1305.Seal (Key, 1, Plain, Sealed);
         Check (Result = CryptoLib.Errors.Ok, "ChaCha Seal seals for the zeroing test");
         Sealed (Sealed'Last) := Sealed (Sealed'Last) xor 1;
         Result := CryptoLib.ChaCha20_Poly1305.Open (Key, 1, Sealed, Out_Buf);
         Check (Result /= CryptoLib.Errors.Ok, "ChaCha Open rejects a flipped tag");
         Check (All_Zero (Out_Buf), "ChaCha Open zeroes its output on a bad tag");
      end;

      --  An unknown cipher name is refused before any key schedule exists.
      declare
         Key    : constant Ada.Streams.Stream_Element_Array (1 .. 16) := [others => 2];
         IV     : constant Ada.Streams.Stream_Element_Array (1 .. 16) := [others => 5];
         Cipher : constant Ada.Streams.Stream_Element_Array (1 .. 16) := [others => 6];
         Out_Buf : Ada.Streams.Stream_Element_Array (1 .. 16) := [others => Pattern];
         Result : CryptoLib.Errors.Status;
      begin
         Result := CryptoLib.Ciphers.Decrypt_CBC_Raw
           ("not-a-cipher", Key, IV, Cipher, Out_Buf);
         Check (Result /= CryptoLib.Errors.Ok, "Decrypt_CBC_Raw refuses an unknown name");
         Check (All_Zero (Out_Buf), "Decrypt_CBC_Raw zeroes its output on an unknown name");
      end;

      --  A streaming context that was never initialized must not pass input
      --  through to the output.
      declare
         Item    : CryptoLib.Ciphers.Cipher_State;
         Plain   : constant Ada.Streams.Stream_Element_Array (1 .. 16) := [others => 16#11#];
         Out_Buf : Ada.Streams.Stream_Element_Array (1 .. 16) := [others => Pattern];
         Result  : CryptoLib.Errors.Status;
      begin
         CryptoLib.Ciphers.Reset (Item);
         Result := CryptoLib.Ciphers.Encrypt (Item, Plain, Out_Buf);
         Check (Result /= CryptoLib.Errors.Ok, "Encrypt refuses an inactive context");
         Check (All_Zero (Out_Buf), "Encrypt zeroes its output for an inactive context");
      end;

      --  ECDSA: a wrong-width output is refused with nothing written.
      declare
         Scalar  : constant Ada.Streams.Stream_Element_Array (1 .. 48) := [others => 16#41#];
         Message : constant Ada.Streams.Stream_Element_Array (1 .. 8)  := [others => 16#22#];
         R_Buf   : Ada.Streams.Stream_Element_Array (1 .. 32) := [others => Pattern];
         S_Buf   : Ada.Streams.Stream_Element_Array (1 .. 32) := [others => Pattern];
         Result  : CryptoLib.Errors.Status;
      begin
         Result := CryptoLib.ECDSA.Sign_Nistp384_Raw
           (Scalar, Message, R_Buf, S_Buf);
         Check (Result /= CryptoLib.Errors.Ok,
                "Sign_Nistp384_Raw refuses a 32-byte r and s");
         Check (All_Zero (R_Buf) and then All_Zero (S_Buf),
                "Sign_Nistp384_Raw zeroes both halves on refusal");
      end;

      --  ECDSA public key derivation, same shape.
      declare
         Scalar  : constant Ada.Streams.Stream_Element_Array (1 .. 48) := [others => 16#41#];
         Out_Buf : Ada.Streams.Stream_Element_Array (1 .. 64) := [others => Pattern];
         Result  : CryptoLib.Errors.Status;
      begin
         Result := CryptoLib.ECDSA.Public_Key_Raw
           (CryptoLib.ECDSA.Nistp384, Scalar, Out_Buf);
         Check (Result /= CryptoLib.Errors.Ok,
                "Public_Key_Raw refuses a 64-byte point");
         Check (All_Zero (Out_Buf), "Public_Key_Raw zeroes its output on refusal");
      end;

      --  bcrypt_pbkdf with no rounds to run.
      declare
         Salt    : constant Ada.Streams.Stream_Element_Array (1 .. 16) := [others => 8];
         Out_Buf : Ada.Streams.Stream_Element_Array (1 .. 32) := [others => Pattern];
         Result  : CryptoLib.Errors.Status;
      begin
         Result := CryptoLib.BCrypt_PBKDF.Derive ("password", Salt, 0, Out_Buf);
         Check (Result /= CryptoLib.Errors.Ok, "bcrypt_pbkdf refuses zero rounds");
         Check (All_Zero (Out_Buf), "bcrypt_pbkdf zeroes its output on refusal");
      end;

      --  HKDF past the 255-block ceiling, the one case already reachable.
      declare
         PRK     : constant Ada.Streams.Stream_Element_Array (1 .. 32) := [others => 16#0B#];
         Info    : constant Ada.Streams.Stream_Element_Array (1 .. 4)  := [others => 1];
         Out_Buf : Ada.Streams.Stream_Element_Array (1 .. 255 * 32 + 1) := [others => Pattern];
         Result  : CryptoLib.Errors.Status;
      begin
         Result := CryptoLib.HKDF.Expand
           (CryptoLib.HKDF.SHA256, PRK, Info, Out_Buf);
         Check (Result /= CryptoLib.Errors.Ok, "HKDF refuses one octet past the ceiling");
         Check (All_Zero (Out_Buf), "HKDF zeroes its output past the ceiling");
      end;
   end Check_Zero_On_Failure;

end Tests_Runtime;
