package body CryptoLib.Errors
  with SPARK_Mode => On
is
   function Is_Success (Value : Status) return Boolean
     with SPARK_Mode => On
   is
   begin
      return Value = Ok;
   end Is_Success;
end CryptoLib.Errors;
