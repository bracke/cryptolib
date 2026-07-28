with Ada.Streams;

with CryptoLib.X509.Signatures;

package body CryptoLib.X509.Path_Building is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.X509.Signatures.Verification_Result;

   package X509C renames CryptoLib.X509.Certificates;
   package XS renames CryptoLib.X509.Signatures;

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

   function Build_Path
     (Leaf   : Certificate;
      Source : Candidate_Source'Class;
      Limits : Search_Limits := Default_Limits) return Build_Result
   is
      Total   : constant Natural := Count (Source);
      Ceiling : constant Natural :=
        Natural'Min (Limits.Maximum_Depth, Maximum_Path);

      Result : Build_Result;
      Chosen : Path_Indices := [others => 1];
      Used   : array (1 .. Maximum_Path) of Natural := [others => 0];

      --  Is this candidate already somewhere in the path being built?
      --
      --  Guards against a loop, which cross-certification makes ordinary
      --  rather than exotic: two CAs signing each other is a legitimate
      --  arrangement and an endless path if followed naively.
      function Already_Used (Index : Positive; Depth : Natural) return Boolean
      is
      begin
         for I in 1 .. Depth loop
            if Used (I) = Index then
               return True;
            end if;
         end loop;
         return False;
      end Already_Used;

      --  Extend the path above Current, which sits at Depth certificates
      --  above the leaf.
      function Extend (Current : Certificate; Depth : Natural) return Boolean
      is
      begin
         if Depth >= Ceiling then
            Result.Exhausted := True;
            return False;
         end if;

         for I in 1 .. Total loop
            if Result.Examined >= Limits.Maximum_Links then
               Result.Exhausted := True;
               return False;
            end if;

            if not Already_Used (I, Depth) then
               declare
                  Issuer : constant Certificate := Candidate (Source, I);
               begin
                  if X509C.Is_Present (Issuer)
                    and then Same_Name
                               (X509C.Issuer_Bytes (Current),
                                X509C.Subject_Bytes (Issuer))
                  then
                     Result.Examined := Result.Examined + 1;

                     --  The name matching only proposes; the signature
                     --  decides. Two certificates can share a subject name
                     --  and not share a key, which is what cross-signing is,
                     --  so stopping at the first name match would miss paths
                     --  that exist.
                     if XS.Verify_Certificate_Signature (Current, Issuer)
                       = XS.Valid
                     then
                        Used (Depth + 1) := I;
                        Chosen (Depth + 1) := I;

                        if Is_Trust_Anchor (Source, Issuer) then
                           Result.Found := True;
                           Result.Length := Depth + 1;
                           Result.Indices := Chosen;
                           return True;
                        end if;

                        if Extend (Issuer, Depth + 1) then
                           return True;
                        end if;

                        --  That branch led nowhere. Put the slot back and go
                        --  on to the next candidate rather than concluding
                        --  there is no path.
                        Used (Depth + 1) := 0;
                     end if;
                  end if;
               end;
            end if;
         end loop;

         return False;
      end Extend;
   begin
      if not X509C.Is_Present (Leaf) or else Total = 0 then
         return Result;
      end if;

      --  A leaf the caller already trusts is a path of no length at all.
      if Is_Trust_Anchor (Source, Leaf) then
         Result.Found := True;
         Result.Length := 0;
         return Result;
      end if;

      if Extend (Leaf, 0) then
         --  A path was found, so whatever bound was brushed along the way no
         --  longer matters.
         Result.Exhausted := False;
      end if;

      return Result;
   end Build_Path;

end CryptoLib.X509.Path_Building;
