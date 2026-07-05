--  @summary Shared result enumeration returned across CryptoLib and the SSH
--  transport, where Ok denotes success and every other value a specific
--  failure.
--
--  Values range from generic conditions (End_Of_Stream, Internal_Error) through
--  connection/handshake/authentication failures to remote and I/O errors; use
--  Is_Success to test the outcome rather than comparing against Ok directly.
package CryptoLib.Errors
  with SPARK_Mode => On
is
   type Status is
     (Ok,
      End_Of_Stream,
      Invalid_Host,
      Invalid_Port,
      Invalid_User,
      Invalid_Command,
      DNS_Failed,
      Connection_Failed,
      Timeout,
      Handshake_Failed,
      Host_Key_Unknown,
      Host_Key_Mismatch,
      Authentication_Failed,
      Channel_Open_Failed,
      Channel_Request_Failed,
      Read_Failed,
      Write_Failed,
      No_Such_File,
      Permission_Denied,
      Remote_Failure,
      Remote_Exit_Nonzero,
      Cancelled,
      Unsupported_Feature,
      Internal_Error);

   --  Report whether a status denotes success.
   --  @param Value the status to test
   --  @return True when Value is Ok, False for any error value
   function Is_Success (Value : Status) return Boolean
     with SPARK_Mode => On;
end CryptoLib.Errors;
