with Ada.Strings.Unbounded;
with Ada.Text_IO;
with CryptoLib.Certificates;

--  Make a local CA and issue a server certificate under it, the counterpart to
--  the README's certificate fragment.
procedure Example_Certificates is
   use type CryptoLib.Certificates.Certificate_Status;
   use Ada.Strings.Unbounded;

   CA_Cert, CA_Key   : Unbounded_String;
   Leaf_Cert, Leaf_Key : Unbounded_String;
   Status : CryptoLib.Certificates.Certificate_Status;
begin
   --  P-256 because it is what most certificates use; Ed25519 is the default
   --  and no browser will accept it.
   Status := CryptoLib.Certificates.Create_Local_CA
     --  A CA's common name has to be a name the profile admits -- spaces and
     --  punctuation are refused rather than certified, which the first draft
     --  of this example ran into by calling it "example local CA".
     ("example-local-ca", CA_Cert, CA_Key,
      CryptoLib.Certificates.P256_Key);
   if Status /= CryptoLib.Certificates.Ok then
      Ada.Text_IO.Put_Line
        ("CA creation failed: "
         & CryptoLib.Certificates.Status_Image (Status));
      return;
   end if;

   --  The leaf's key is generated here and returned beside its certificate.
   --  Its validity is cut short at the CA's own expiry rather than claiming
   --  time the chain will not have.
   Status := CryptoLib.Certificates.Issue_Server_Certificate
     (To_String (CA_Cert), To_String (CA_Key),
      "service.example",
      [1 => To_Unbounded_String ("service.example")],
      Leaf_Cert, Leaf_Key);
   if Status /= CryptoLib.Certificates.Ok then
      Ada.Text_IO.Put_Line
        ("issuance failed: " & CryptoLib.Certificates.Status_Image (Status));
      return;
   end if;

   Ada.Text_IO.Put_Line
     ("issued a certificate of" & Natural'Image (Length (Leaf_Cert))
      & " PEM characters");

   --  The key that came back belongs to the certificate it came with.
   Status := CryptoLib.Certificates.Private_Key_Matches_Certificate
     (To_String (Leaf_Cert), To_String (Leaf_Key));
   Ada.Text_IO.Put_Line
     ("the issued key matches its certificate: "
      & Boolean'Image (Status = CryptoLib.Certificates.Ok));
end Example_Certificates;
