with CryptoLib.X509.Extensions;

package body CryptoLib.X509.Purposes is

   package X509C renames CryptoLib.X509.Certificates;
   package XE renames CryptoLib.X509.Extensions;

   function Result_Image (Result : Purpose_Result) return String is
   begin
      case Result is
         when Permitted                  => return "permitted";
         when Not_A_CA                   => return "not a ca";
         when Key_Usage_Forbids          => return "key usage forbids";
         when Extended_Key_Usage_Forbids =>
            return "extended key usage forbids";
         when Missing_Input              => return "missing input";
      end case;
   end Result_Image;

   --  Does the extended key usage admit this purpose?
   --
   --  Absent admits everything. Present admits what it names, plus everything
   --  if it names anyExtendedKeyUsage. A purpose this crate does not
   --  recognise cannot be asked about, so Has_Unrecognised does not enter
   --  into it: the question is always about one of the purposes named here.
   function EKU_Admits
     (Usage : XE.Extended_Key_Usage; Purpose : Certificate_Purpose)
      return Boolean
   is
   begin
      if not Usage.Present then
         return True;
      end if;

      if Usage.Any_Purpose then
         return True;
      end if;

      case Purpose is
         when TLS_Server            => return Usage.Server_Auth;
         when TLS_Client            => return Usage.Client_Auth;
         when Code_Signing          => return Usage.Code_Signing;
         when Email_Protection      => return Usage.Email_Protection;
         when OCSP_Signing          => return Usage.OCSP_Signing;
         when Certificate_Authority =>
            --  Issuing certificates is governed by basic constraints and
            --  keyCertSign, not by an extended key usage. A CA that names
            --  purposes is naming what its issued certificates may be used
            --  for, not what it may do.
            return True;
      end case;
   end EKU_Admits;

   --  Does the key usage admit this purpose?
   function KU_Admits
     (Usage : XE.Key_Usage; Purpose : Certificate_Purpose) return Boolean
   is
   begin
      if not Usage.Present then
         return True;
      end if;

      case Purpose is
         when TLS_Server | TLS_Client =>
            --  Which of these is needed depends on the key exchange the
            --  handshake settles on, which is not knowable here. Any one of
            --  them leaves the certificate usable for some negotiation, and
            --  refusing on that basis would reject certificates a handshake
            --  would have accepted.
            return Usage.Digital_Signature
              or else Usage.Key_Encipherment
              or else Usage.Key_Agreement;

         when Code_Signing =>
            return Usage.Digital_Signature or else Usage.Non_Repudiation;

         when Email_Protection =>
            return Usage.Digital_Signature
              or else Usage.Non_Repudiation
              or else Usage.Key_Encipherment
              or else Usage.Key_Agreement;

         when OCSP_Signing =>
            return Usage.Digital_Signature or else Usage.Non_Repudiation;

         when Certificate_Authority =>
            return Usage.Certificate_Sign;
      end case;
   end KU_Admits;

   function Check_Purpose
     (Item    : Certificate;
      Purpose : Certificate_Purpose) return Purpose_Result
   is
   begin
      if not X509C.Is_Present (Item) then
         return Missing_Input;
      end if;

      declare
         Constraints : constant XE.Basic_Constraints :=
           XE.Get_Basic_Constraints (Item);
         Usage       : constant XE.Key_Usage := XE.Get_Key_Usage (Item);
         Extended    : constant XE.Extended_Key_Usage :=
           XE.Get_Extended_Key_Usage (Item);
      begin
         if Purpose = Certificate_Authority
           and then not (Constraints.Present and then Constraints.Is_CA)
         then
            return Not_A_CA;
         end if;

         if not KU_Admits (Usage, Purpose) then
            return Key_Usage_Forbids;
         end if;

         if not EKU_Admits (Extended, Purpose) then
            return Extended_Key_Usage_Forbids;
         end if;

         return Permitted;
      end;
   end Check_Purpose;

end CryptoLib.X509.Purposes;
