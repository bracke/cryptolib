with Ada.Streams;

with CryptoLib.X509.Signatures;

package body CryptoLib.X509.Revocation is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.OCSP.Certificate_Status;
   use type CryptoLib.OCSP.Response_Status;
   use type CryptoLib.OCSP.Verification_Result;
   use type CryptoLib.X509.Signatures.Verification_Result;

   package X509C renames CryptoLib.X509.Certificates;
   package XC renames CryptoLib.X509.CRLs;
   package CO renames CryptoLib.OCSP;

   function Answer_Image (Answer : Revocation_Answer) return String is
   begin
      case Answer is
         when Not_Revoked         => return "not revoked";
         when Revoked             => return "revoked";
         when Unknown             => return "unknown";
         when Stale               => return "stale";
         when Wrong_Issuer        => return "wrong issuer";
         when Untrusted_Signature => return "untrusted signature";
         when Malformed           => return "malformed";
      end case;
   end Answer_Image;

   function Same_Bytes (Left : Octets; Right : Octets) return Boolean is
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
   end Same_Bytes;

   function Check_Against_CRL
     (Item    : Certificate;
      Issuer  : Certificate;
      List    : XC.Revocation_List;
      At_Time : Certificate_Time) return Revocation_Answer
   is
   begin
      if not X509C.Is_Present (Item)
        or else not X509C.Is_Present (Issuer)
        or else not XC.Is_Present (List)
      then
         return Malformed;
      end if;

      --  About this issuer's certificates, and about this certificate's
      --  issuer. Both, because a list that satisfies only one is a list about
      --  somebody else.
      if not Same_Bytes (XC.Issuer_Bytes (List), X509C.Subject_Bytes (Issuer))
        or else not Same_Bytes
                      (X509C.Issuer_Bytes (Item),
                       X509C.Subject_Bytes (Issuer))
      then
         return Wrong_Issuer;
      end if;

      if XC.Verify_Signature (List, Issuer)
        /= CryptoLib.X509.Signatures.Valid
      then
         return Untrusted_Signature;
      end if;

      --  Issued in the past, and not yet superseded. A list from before the
      --  time being asked about has not happened yet; one past its nextUpdate
      --  has been replaced, and reading it as current is how a certificate
      --  revoked since keeps working.
      if not Is_Not_After (XC.This_Update (List), At_Time) then
         return Stale;
      end if;

      if XC.Has_Next_Update (List)
        and then not Is_Not_After (At_Time, XC.Next_Update (List))
      then
         return Stale;
      end if;

      if XC.Is_Revoked (List, X509C.Serial_Number (Item)) then
         return Revoked;
      end if;

      return Not_Revoked;
   end Check_Against_CRL;

   function Check_Against_OCSP
     (Item     : Certificate;
      Issuer   : Certificate;
      Response : in out CO.Response;
      At_Time  : Certificate_Time) return Revocation_Answer
   is
      Verdict : CO.Verification_Result;
   begin
      if not X509C.Is_Present (Item)
        or else not X509C.Is_Present (Issuer)
        or else not CO.Is_Present (Response)
      then
         return Malformed;
      end if;

      if CO.Status_Of (Response) /= CO.Successful then
         --  The responder declined to answer, which is not an answer about
         --  the certificate.
         return Unknown;
      end if;

      Verdict := CO.Verify (Response, Item, Issuer);
      case Verdict is
         when CO.Accepted =>
            null;
         when CO.Wrong_Certificate =>
            return Wrong_Issuer;
         when CO.Unknown_Responder | CO.Delegate_Not_Authorized
            | CO.Invalid_Signature =>
            return Untrusted_Signature;
         when others =>
            return Malformed;
      end case;

      if not Is_Not_After (CO.This_Update (Response), At_Time) then
         return Stale;
      end if;

      if CO.Has_Next_Update (Response)
        and then not Is_Not_After (At_Time, CO.Next_Update (Response))
      then
         return Stale;
      end if;

      case CO.Certificate_Status_Of (Response) is
         when CO.Good    => return Not_Revoked;
         when CO.Revoked => return Revoked;
         when CO.Unknown => return Unknown;
      end case;
   end Check_Against_OCSP;

end CryptoLib.X509.Revocation;
