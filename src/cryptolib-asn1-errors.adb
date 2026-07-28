package body CryptoLib.ASN1.Errors is

   function Status_Image (Status : Decode_Status) return String is
   begin
      case Status is
         when Ok                   => return "ok";
         when Truncated_Input      => return "truncated input";
         when Invalid_Tag          => return "invalid tag";
         when Invalid_Length       => return "invalid length";
         when Non_Canonical_DER    => return "non-canonical der";
         when Excessive_Nesting    => return "excessive nesting";
         when Size_Limit_Exceeded  => return "size limit exceeded";
         when Unsupported_Encoding => return "unsupported encoding";
         when Invalid_Value        => return "invalid value";
         when Trailing_Data        => return "trailing data";
      end case;
   end Status_Image;

end CryptoLib.ASN1.Errors;
