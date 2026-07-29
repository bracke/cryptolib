with Ada.Streams;

with CryptoLib.ASN1.OIDs;
with CryptoLib.X509.Extensions;
with CryptoLib.X509.Name_Constraints;
with CryptoLib.X509.Signatures;

package body CryptoLib.X509.Validation is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.X509.Signatures.Verification_Result;

   package X509C renames CryptoLib.X509.Certificates;
   package XE renames CryptoLib.X509.Extensions;
   package PP renames CryptoLib.X509.Policies;
   package NC renames CryptoLib.X509.Name_Constraints;
   package XS renames CryptoLib.X509.Signatures;

   function Failure_Image (Failure : Validation_Failure) return String is
   begin
      case Failure is
         when None                       => return "none";
         when Malformed_Certificate      => return "malformed certificate";
         when Empty_Path                 => return "empty path";
         when Path_Too_Long              => return "path too long";
         when Invalid_Signature          => return "invalid signature";
         when Unsupported_Signature_Algorithm =>
            return "unsupported signature algorithm";
         when Issuer_Mismatch            => return "issuer mismatch";
         when Certificate_Expired        => return "certificate expired";
         when Certificate_Not_Yet_Valid  => return "certificate not yet valid";
         when Invalid_Basic_Constraints  => return "invalid basic constraints";
         when Path_Length_Exceeded       => return "path length exceeded";
         when Invalid_Key_Usage          => return "invalid key usage";
         when Policy_Not_Established     => return "policy not established";
         when Weak_Key                   => return "key too weak";
         when Name_Constraint_Violation  =>
            return "name constraint violation";
         when Unsupported_Name_Constraint =>
            return "unsupported name constraint";
         when Unknown_Critical_Extension =>
            return "unknown critical extension";
         when Duplicate_Certificate      => return "duplicate certificate";
         when No_Trust_Anchor            => return "no trust anchor";
      end case;
   end Failure_Image;

   function Fail
     (Failure : Validation_Failure; Index : Natural) return Validation_Result
   is ((Valid    => False,
        Failure  => Failure,
        Index    => Index,
        Policies => (others => <>)));

   --  Do these two encoded names match?
   --
   --  Compared as bytes. RFC 5280 defines a name comparison that folds case
   --  and whitespace in some string types, which this does not do: a byte
   --  comparison can only be too strict, never too lax, and being too strict
   --  costs a chain that could have been built rather than trusting one that
   --  should not have been.
   function Same_Name (Left : Octets; Right : Octets) return Boolean is
   begin
      if Left'Length /= Right'Length or else Left'Length = 0 then
         return False;
      end if;

      for I in 0 .. Left'Length - 1 loop
         if Left (Left'First + Offset (I)) /= Right (Right'First + Offset (I))
         then
            return False;
         end if;
      end loop;

      return True;
   end Same_Name;

   --  Are these the same certificate?
   function Same_Certificate (Left : Certificate; Right : Certificate)
     return Boolean
   is (Same_Name (X509C.DER_Bytes (Left), X509C.DER_Bytes (Right)));

   function Validate_Path
     (Source          : Path_Source'Class;
      Validation_Time : Certificate_Time;
      Policy          : Validation_Policy := Default_Policy)
      return Validation_Result
   is
      Path_Length : constant Positive := Length (Source);

      function Get (Index : Positive) return Certificate
      is (Certificate_At (Source, Index));
   begin
      if Path_Length > Policy.Maximum_Path_Length then
         --  Refused before any signature is checked, so a long path costs
         --  nothing to reject.
         return Fail (Path_Too_Long, 0);
      end if;

      --  Every certificate must decode, be current, and carry nothing
      --  critical this crate cannot interpret.
      for I in 1 .. Path_Length loop
         declare
            Item : constant Certificate := Get (I);
         begin
            if not X509C.Is_Present (Item) then
               return Fail (Malformed_Certificate, I);
            end if;

            if Policy.Reject_Unknown_Critical
              and then XE.Has_Unsupported_Critical_Extension (Item)
            then
               return Fail (Unknown_Critical_Extension, I);
            end if;

            if not Is_Not_After (X509C.Not_Before (Item), Validation_Time) then
               return Fail (Certificate_Not_Yet_Valid, I);
            end if;

            if not Is_Not_After (Validation_Time, X509C.Not_After (Item)) then
               return Fail (Certificate_Expired, I);
            end if;

            --  Every certificate, not only the leaf: a chain is no stronger
            --  than the weakest key that signed a link of it, and a CA whose
            --  modulus can be factored is a CA anyone can sign as.
            if Policy.Minimum_RSA_Bits > 0
              and then X509C.Public_Key_Algorithm_Of (Item) = RSA
              and then CryptoLib.X509.Signatures.RSA_Modulus_Bits
                         (X509C.Public_Key (Item))
                       < Policy.Minimum_RSA_Bits
            then
               return Fail (Weak_Key, I);
            end if;
         end;
      end loop;

      --  A certificate must not appear twice: that is a loop, and a loop is
      --  how a path can be made to look longer than it is.
      for I in 1 .. Path_Length loop
         for J in I + 1 .. Path_Length loop
            if Same_Certificate (Get (I), Get (J)) then
               return Fail (Duplicate_Certificate, J);
            end if;
         end loop;
      end loop;

      --  Each link: the certificate below is issued by the one above.
      for I in 1 .. Path_Length - 1 loop
         declare
            Subject_Cert : constant Certificate := Get (I);
            Issuer_Cert  : constant Certificate := Get (I + 1);
         begin
            if not Same_Name
                     (X509C.Issuer_Bytes (Subject_Cert),
                      X509C.Subject_Bytes (Issuer_Cert))
            then
               return Fail (Issuer_Mismatch, I);
            end if;

            --  The issuer must be entitled to have issued it. Checked before
            --  the signature so that a certificate signed by something that
            --  was never a CA is reported as what it is.
            declare
               Constraints : constant XE.Basic_Constraints :=
                 XE.Get_Basic_Constraints (Issuer_Cert);
               Usage       : constant XE.Key_Usage :=
                 XE.Get_Key_Usage (Issuer_Cert);
               Below       : constant Natural := I - 1;
            begin
               if Policy.Require_Basic_Constraints
                 and then not (Constraints.Present and then Constraints.Is_CA)
               then
                  return Fail (Invalid_Basic_Constraints, I + 1);
               end if;

               --  pathLenConstraint counts the intermediates between this
               --  issuer and the leaf, not the whole path.
               if Constraints.Has_Path_Length
                 and then Below > Constraints.Path_Length
               then
                  return Fail (Path_Length_Exceeded, I + 1);
               end if;

               --  A key usage that is present and omits keyCertSign forbids
               --  signing certificates, whatever the basic constraints say.
               --  An absent key usage does not constrain it.
               if Policy.Require_Key_Cert_Sign
                 and then Usage.Present
                 and then not Usage.Certificate_Sign
               then
                  return Fail (Invalid_Key_Usage, I + 1);
               end if;
            end;

            if not XS.Is_Supported
                     (X509C.Signature_Algorithm_Of (Subject_Cert))
            then
               return Fail (Unsupported_Signature_Algorithm, I);
            end if;

            if XS.Verify_Certificate_Signature (Subject_Cert, Issuer_Cert)
              /= XS.Valid
            then
               return Fail (Invalid_Signature, I);
            end if;
         end;
      end loop;

      --  Name constraints, applied by every CA above each certificate rather
      --  than only by its immediate issuer: a constraint on a root binds
      --  everything beneath it, and checking only one link would let an
      --  intermediate certify outside what the root allowed.
      for Subject_Index in 1 .. Path_Length - 1 loop
         for Issuer_Index in Subject_Index + 1 .. Path_Length loop
            declare
               Above : constant Certificate := Get (Issuer_Index);
               Where : constant Natural :=
                 X509C.Find_Extension
                   (Above, CryptoLib.ASN1.OIDs.Name_Constraints);
            begin
               if Where > 0 then
                  declare
                     Answer : constant NC.Verdict :=
                       NC.Check
                         (X509C.Extension_Value (Above, Where),
                          Get (Subject_Index));
                  begin
                     case Answer is
                        when NC.Permitted =>
                           null;
                        when NC.Excluded =>
                           return Fail
                             (Name_Constraint_Violation, Subject_Index);
                        when NC.Unsupported_Constraint =>
                           return Fail
                             (Unsupported_Name_Constraint, Issuer_Index);
                        when NC.Malformed =>
                           return Fail
                             (Malformed_Certificate, Issuer_Index);
                     end case;
                  end;
               end if;
            end;
         end loop;
      end loop;

      --  The path must end somewhere the caller trusts. Asked last, so that a
      --  path which is both untrusted and malformed is reported as malformed:
      --  that is the more actionable of the two.
      if not Is_Trust_Anchor (Source, Get (Path_Length)) then
         return Fail (No_Trust_Anchor, Path_Length);
      end if;

      --  RFC 5280 section 6.1 policy processing, last because it is the only
      --  check that can succeed on a path nothing else would accept: it says
      --  which policies hold, not whether the chain does.
      --
      --  Driven from the anchor downwards. The RFC numbers certificates in
      --  issuing order and this path is held leaf-first, so the two run
      --  opposite ways -- certificate i of the RFC is Get (Path_Length - i)
      --  here, and the anchor itself is not one of them.
      declare
         Below  : constant Natural := Path_Length - 1;
         Engine : PP.Engine (Path_Length => Natural'Max (Below, 1));
         Ok     : Boolean;
         Wanted : constant PP.Policy_Array :=
           Policy.Accepted_Policies.Values
             (1 .. Policy.Accepted_Policies.Count);
      begin
         if Below = 0 then
            --  A path of the anchor alone establishes no policies and needs
            --  none; there is no certificate to process.
            return (Valid => True, Failure => None, Index => 0,
                    Policies => (others => <>));
         end if;

         PP.Start (Engine, Policy.Policy_Options);

         for I in reverse 1 .. Below loop
            declare
               Subject : constant Certificate := Get (I);
               Issuer  : constant Certificate := Get (I + 1);

               --  A self-issued certificate is one a CA wrote for itself,
               --  typically to change keys. It does not lengthen the path,
               --  so it does not spend any of the policy allowances.
               --
               --  Asked of the certificate rather than reconstructed here:
               --  the predicate is named, documented and tested, and a
               --  second copy of it is a second thing to keep true.
               Self_Issued : constant Boolean :=
                 X509C.Is_Self_Issued (Subject);
            begin
               pragma Unreferenced (Issuer);
               PP.Step (Engine, Subject, Self_Issued, Ok);
               if not Ok then
                  --  Carrying the exhaustion flag out with the failure: a
                  --  path refused for establishing no acceptable policy and
                  --  one refused because the tree would not fit are both
                  --  Policy_Not_Established, and they are not the same
                  --  problem to go and look at.
                  return (Valid    => False,
                          Failure  => Policy_Not_Established,
                          Index    => I,
                          Policies =>
                            (Acceptable => False,
                             Exhausted  => PP.Exhausted (Engine),
                             Count      => 0,
                             Values     => [others => <>]));
               end if;
            end;
         end loop;

         declare
            Outcome : constant PP.Policy_Outcome :=
              PP.Finish (Engine, Wanted);
         begin
            if not Outcome.Acceptable then
               return Fail (Policy_Not_Established, 1);
            end if;
            return (Valid => True, Failure => None, Index => 0,
                    Policies => Outcome);
         end;
      end;
   end Validate_Path;

end CryptoLib.X509.Validation;
