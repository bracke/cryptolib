with Ada.Strings.Unbounded;

package CryptoLib.Certificates is
   subtype Unbounded_String is Ada.Strings.Unbounded.Unbounded_String;

   type Certificate_Status is
     (Ok,
      Invalid_Input,
      Unsupported_Profile,
      Internal_Error);

   type Subject_Alternative_Name_List is array (Positive range <>) of Unbounded_String;

   function Status_Image (Status : Certificate_Status) return String;

   function Create_Local_CA
     (Common_Name     : String;
      Certificate_PEM : out Unbounded_String;
      Private_Key_PEM : out Unbounded_String) return Certificate_Status;

   function Issue_Server_Certificate
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Names              : Subject_Alternative_Name_List;
      Certificate_PEM    : out Unbounded_String;
      Private_Key_PEM    : out Unbounded_String) return Certificate_Status;

   function Issue_Client_Certificate
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Names              : Subject_Alternative_Name_List;
      Certificate_PEM    : out Unbounded_String;
      Private_Key_PEM    : out Unbounded_String) return Certificate_Status;

   function Issue_Email_Certificate
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      Common_Name        : String;
      Emails             : Subject_Alternative_Name_List;
      Certificate_PEM    : out Unbounded_String;
      Private_Key_PEM    : out Unbounded_String) return Certificate_Status;

   function Sign_CSR
     (CA_Certificate_PEM : String;
      CA_Private_Key_PEM : String;
      CSR_PEM            : String;
      Certificate_PEM    : out Unbounded_String) return Certificate_Status;

   function Generate_PKCS12
     (Certificate_PEM : String;
      Private_Key_PEM : String;
      Friendly_Name   : String;
      Password        : String;
      Bundle_Data     : out Unbounded_String) return Certificate_Status;
end CryptoLib.Certificates;
