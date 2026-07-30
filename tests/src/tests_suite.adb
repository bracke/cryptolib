with Tests_KDFs;
with Tests_Ciphers;
with Tests_Curves;
with Tests_X509_Issuance;
with Tests_Encodings;
with Tests_X509_Decoding;
with Tests_X509_Validation;
with Tests_X509_Policies;
with Tests_X509_Name_Constraints;
with Tests_RSA;
with Tests_Runtime;
with Tests_Key_Exchange;
with Tests_Hashes;
with Tests_X509_Revocation;

package body Tests_Suite is

   type Tests_KDFs_Access is access all Tests_KDFs.Test_Case;
   type Tests_Ciphers_Access is access all Tests_Ciphers.Test_Case;
   type Tests_Curves_Access is access all Tests_Curves.Test_Case;
   type Tests_X509_Issuance_Access is access all Tests_X509_Issuance.Test_Case;
   type Tests_Encodings_Access is access all Tests_Encodings.Test_Case;
   type Tests_X509_Decoding_Access is access all Tests_X509_Decoding.Test_Case;
   type Tests_X509_Validation_Access is access all Tests_X509_Validation.Test_Case;
   type Tests_X509_Policies_Access is access all Tests_X509_Policies.Test_Case;
   type Tests_X509_Name_Constraints_Access is access all Tests_X509_Name_Constraints.Test_Case;
   type Tests_RSA_Access is access all Tests_RSA.Test_Case;
   type Tests_Runtime_Access is access all Tests_Runtime.Test_Case;
   type Tests_Key_Exchange_Access is access all Tests_Key_Exchange.Test_Case;
   type Tests_Hashes_Access is access all Tests_Hashes.Test_Case;
   type Tests_X509_Revocation_Access is access all Tests_X509_Revocation.Test_Case;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
      Result : constant AUnit.Test_Suites.Access_Test_Suite :=
        AUnit.Test_Suites.New_Suite;
   begin
      declare
         Item : constant Tests_KDFs_Access := new Tests_KDFs.Test_Case;
      begin
         AUnit.Test_Suites.Add_Test (Result, Item);
      end;
      declare
         Item : constant Tests_Ciphers_Access := new Tests_Ciphers.Test_Case;
      begin
         AUnit.Test_Suites.Add_Test (Result, Item);
      end;
      declare
         Item : constant Tests_Curves_Access := new Tests_Curves.Test_Case;
      begin
         AUnit.Test_Suites.Add_Test (Result, Item);
      end;
      declare
         Item : constant Tests_X509_Issuance_Access := new Tests_X509_Issuance.Test_Case;
      begin
         AUnit.Test_Suites.Add_Test (Result, Item);
      end;
      declare
         Item : constant Tests_Encodings_Access := new Tests_Encodings.Test_Case;
      begin
         AUnit.Test_Suites.Add_Test (Result, Item);
      end;
      declare
         Item : constant Tests_X509_Decoding_Access := new Tests_X509_Decoding.Test_Case;
      begin
         AUnit.Test_Suites.Add_Test (Result, Item);
      end;
      declare
         Item : constant Tests_X509_Validation_Access := new Tests_X509_Validation.Test_Case;
      begin
         AUnit.Test_Suites.Add_Test (Result, Item);
      end;
      declare
         Item : constant Tests_X509_Policies_Access := new Tests_X509_Policies.Test_Case;
      begin
         AUnit.Test_Suites.Add_Test (Result, Item);
      end;
      declare
         Item : constant Tests_X509_Name_Constraints_Access := new Tests_X509_Name_Constraints.Test_Case;
      begin
         AUnit.Test_Suites.Add_Test (Result, Item);
      end;
      declare
         Item : constant Tests_RSA_Access := new Tests_RSA.Test_Case;
      begin
         AUnit.Test_Suites.Add_Test (Result, Item);
      end;
      declare
         Item : constant Tests_Runtime_Access := new Tests_Runtime.Test_Case;
      begin
         AUnit.Test_Suites.Add_Test (Result, Item);
      end;
      declare
         Item : constant Tests_Key_Exchange_Access := new Tests_Key_Exchange.Test_Case;
      begin
         AUnit.Test_Suites.Add_Test (Result, Item);
      end;
      declare
         Item : constant Tests_Hashes_Access := new Tests_Hashes.Test_Case;
      begin
         AUnit.Test_Suites.Add_Test (Result, Item);
      end;
      declare
         Item : constant Tests_X509_Revocation_Access := new Tests_X509_Revocation.Test_Case;
      begin
         AUnit.Test_Suites.Add_Test (Result, Item);
      end;
      return Result;
   end Suite;

end Tests_Suite;
