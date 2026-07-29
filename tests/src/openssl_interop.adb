with Interfaces.C;
with Interfaces.C.Strings;
with System;

package body OpenSSL_Interop is

   use type System.Address;
   use type Interfaces.C.int;

   subtype Handle is System.Address;
   Null_Handle : constant Handle := System.Null_Address;

   function BIO_new_mem_buf
     (Buffer : Interfaces.C.Strings.chars_ptr;
      Length : Interfaces.C.int) return Handle
     with Import, Convention => C, External_Name => "BIO_new_mem_buf";

   function BIO_free (Item : Handle) return Interfaces.C.int
     with Import, Convention => C, External_Name => "BIO_free";

   function PEM_read_bio_X509
     (Source   : Handle;
      Target   : Handle;
      Callback : Handle;
      User     : Handle) return Handle
     with Import, Convention => C, External_Name => "PEM_read_bio_X509";

   procedure X509_free (Item : Handle)
     with Import, Convention => C, External_Name => "X509_free";

   function X509_STORE_new return Handle
     with Import, Convention => C, External_Name => "X509_STORE_new";

   procedure X509_STORE_free (Item : Handle)
     with Import, Convention => C, External_Name => "X509_STORE_free";

   function X509_STORE_add_cert
     (Store : Handle; Cert : Handle) return Interfaces.C.int
     with Import, Convention => C, External_Name => "X509_STORE_add_cert";

   function X509_STORE_CTX_new return Handle
     with Import, Convention => C, External_Name => "X509_STORE_CTX_new";

   procedure X509_STORE_CTX_free (Item : Handle)
     with Import, Convention => C, External_Name => "X509_STORE_CTX_free";

   function X509_STORE_CTX_init
     (Context : Handle;
      Store   : Handle;
      Cert    : Handle;
      Chain   : Handle) return Interfaces.C.int
     with Import, Convention => C, External_Name => "X509_STORE_CTX_init";

   function X509_verify_cert (Context : Handle) return Interfaces.C.int
     with Import, Convention => C, External_Name => "X509_verify_cert";

   function Read_Certificate (PEM_Text : String) return Handle is
      Buffer : Interfaces.C.Strings.chars_ptr :=
        Interfaces.C.Strings.New_String (PEM_Text);
      Source : constant Handle :=
        BIO_new_mem_buf (Buffer, Interfaces.C.int (PEM_Text'Length));
      Cert   : Handle := Null_Handle;
      Ignored : Interfaces.C.int;
   begin
      if Source /= Null_Handle then
         Cert := PEM_read_bio_X509
           (Source, Null_Handle, Null_Handle, Null_Handle);
         Ignored := BIO_free (Source);
      end if;
      Interfaces.C.Strings.Free (Buffer);
      return Cert;
   end Read_Certificate;

   function Chain_Verifies (CA_PEM : String; Leaf_PEM : String) return Boolean
   is
      CA      : constant Handle := Read_Certificate (CA_PEM);
      Leaf    : constant Handle := Read_Certificate (Leaf_PEM);
      Store   : Handle := Null_Handle;
      Context : Handle := Null_Handle;
      Result  : Boolean := False;
      Ignored : Interfaces.C.int;
   begin
      if CA /= Null_Handle and then Leaf /= Null_Handle then
         Store := X509_STORE_new;
         if Store /= Null_Handle then
            Ignored := X509_STORE_add_cert (Store, CA);
            Context := X509_STORE_CTX_new;
            if Context /= Null_Handle then
               if X509_STORE_CTX_init (Context, Store, Leaf, Null_Handle) = 1
               then
                  Result := X509_verify_cert (Context) = 1;
               end if;
               X509_STORE_CTX_free (Context);
            end if;
            X509_STORE_free (Store);
         end if;
      end if;

      if Leaf /= Null_Handle then
         X509_free (Leaf);
      end if;
      if CA /= Null_Handle then
         X509_free (CA);
      end if;
      return Result;
   end Chain_Verifies;

end OpenSSL_Interop;
