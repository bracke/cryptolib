with Ada.Streams;

with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.Errors;
with CryptoLib.ASN1.OIDs;

package body CryptoLib.X509.Policies is

   use CryptoLib.ASN1;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.ASN1.Errors.Decode_Status;

   package DER_Reader renames CryptoLib.ASN1.DER;
   package OID_Table renames CryptoLib.ASN1.OIDs;
   package X509C renames CryptoLib.X509.Certificates;

   Empty_Octets : constant Octets (1 .. 0) := [others => 0];

   Limits : constant Decode_Limits := Default_Limits;

   --  2.5.29.32.0.
   Any_Policy_Encoded : constant Octets :=
     [16#55#, 16#1D#, 16#20#, 16#00#];

   function Any_Policy return Policy_Value
   is (To_Policy (Any_Policy_Encoded));

   function To_Policy (Encoded : Octets) return Policy_Value is
      Result : Policy_Value;
   begin
      if Encoded'Length = 0
        or else Natural (Encoded'Length) > Maximum_Policy_Length
      then
         return Result;
      end if;

      Result.Length := Natural (Encoded'Length);
      for I in 1 .. Result.Length loop
         Result.Data (I) := Encoded (Encoded'First + Offset (I - 1));
      end loop;
      return Result;
   end To_Policy;

   function Is_Present (Item : Policy_Value) return Boolean
   is (Item.Length > 0);

   function Is_Any (Item : Policy_Value) return Boolean
   is (Same (Item, To_Policy (Any_Policy_Encoded)));

   function Same (Left : Policy_Value; Right : Policy_Value) return Boolean is
   begin
      if Left.Length /= Right.Length or else Left.Length = 0 then
         return False;
      end if;
      for I in 1 .. Left.Length loop
         if Left.Data (I) /= Right.Data (I) then
            return False;
         end if;
      end loop;
      return True;
   end Same;

   function Encoded_Value (Item : Policy_Value) return Octets is
      Result : Octets (1 .. Offset (Item.Length));
   begin
      if Item.Length = 0 then
         return Empty_Octets;
      end if;
      for I in 1 .. Item.Length loop
         Result (Offset (I)) := Item.Data (I);
      end loop;
      return Result;
   end Encoded_Value;

   --  One extension's value octets by identifier.
   function Value_Of
     (Item       : Certificate;
      Identifier : Octets;
      Found      : out Boolean) return Octets
   is
      Index : constant Natural := X509C.Find_Extension (Item, Identifier);
   begin
      Found := Index > 0;
      if not Found then
         return Empty_Octets;
      end if;
      return X509C.Extension_Value (Item, Index);
   end Value_Of;

   function Policies_Of (Item : Certificate) return Policy_Set is
      Found  : Boolean;
      Data   : constant Octets :=
        Value_Of (Item, OID_Table.Certificate_Policies, Found);
      Result : Policy_Set;
      Cursor : Offset;
      Seq    : Element;
      Status : Errors.Decode_Status;
   begin
      if not Found then
         return Result;
      end if;

      Result.Present := True;

      Cursor := Data'First;
      DER_Reader.Read_Sequence
        (Data, Cursor, Data'Last, 0, Limits, Seq, Status);
      if Status /= Errors.Ok
        or else not DER_Reader.At_End (Cursor, Data'Last)
      then
         return Result;
      end if;

      --  PolicyInformation ::= SEQUENCE { policyIdentifier OBJECT IDENTIFIER,
      --                                   policyQualifiers SEQUENCE OPTIONAL }
      --  The qualifiers are text for humans -- a CPS pointer, a notice -- and
      --  say nothing about whether a policy applies, so they are stepped over
      --  rather than read.
      Cursor := Seq.First;
      while not DER_Reader.At_End (Cursor, Seq.Last) loop
         declare
            Info : Element;
            Part : Offset;
            OID  : Element;
         begin
            DER_Reader.Read_Sequence
              (Data, Cursor, Seq.Last, 1, Limits, Info, Status);
            exit when Status /= Errors.Ok;

            Part := Info.First;
            DER_Reader.Read_Object_Identifier
              (Data, Part, Info.Last, 2, Limits, OID, Status);
            exit when Status /= Errors.Ok;

            if Result.Count = Maximum_Policies then
               --  More than this can hold. Refusing to record them is not
               --  the same as there being none, so the set stays not
               --  well-formed and the caller treats the certificate as one
               --  whose policies cannot be established.
               return Result;
            end if;

            declare
               Value : constant Policy_Value :=
                 To_Policy (Data (OID.First .. OID.Last));
            begin
               if not Is_Present (Value) then
                  return Result;
               end if;

               Result.Count := Result.Count + 1;
               Result.Values (Result.Count) := Value;
               if Is_Any (Value) then
                  Result.Has_Any := True;
               end if;
            end;
         end;
      end loop;

      if Status = Errors.Ok and then Result.Count > 0 then
         Result.Well_Formed := True;
      end if;
      return Result;
   end Policies_Of;

   function Mappings_Of (Item : Certificate) return Mapping_Set is
      Found  : Boolean;
      Data   : constant Octets :=
        Value_Of (Item, OID_Table.Policy_Mappings, Found);
      Result : Mapping_Set;
      Cursor : Offset;
      Seq    : Element;
      Status : Errors.Decode_Status;
   begin
      if not Found then
         return Result;
      end if;

      Result.Present := True;

      Cursor := Data'First;
      DER_Reader.Read_Sequence
        (Data, Cursor, Data'Last, 0, Limits, Seq, Status);
      if Status /= Errors.Ok
        or else not DER_Reader.At_End (Cursor, Data'Last)
      then
         return Result;
      end if;

      Cursor := Seq.First;
      while not DER_Reader.At_End (Cursor, Seq.Last) loop
         declare
            Pair    : Element;
            Part    : Offset;
            Issuer  : Element;
            Subject : Element;
         begin
            DER_Reader.Read_Sequence
              (Data, Cursor, Seq.Last, 1, Limits, Pair, Status);
            exit when Status /= Errors.Ok;

            Part := Pair.First;
            DER_Reader.Read_Object_Identifier
              (Data, Part, Pair.Last, 2, Limits, Issuer, Status);
            exit when Status /= Errors.Ok;
            DER_Reader.Read_Object_Identifier
              (Data, Part, Pair.Last, 2, Limits, Subject, Status);
            exit when Status /= Errors.Ok;

            if Result.Count = Maximum_Mappings then
               return Result;
            end if;

            declare
               From_Policy : constant Policy_Value :=
                 To_Policy (Data (Issuer.First .. Issuer.Last));
               To_Value    : constant Policy_Value :=
                 To_Policy (Data (Subject.First .. Subject.Last));
            begin
               --  RFC 5280 6.1.4 (a): a mapping to or from anyPolicy is not
               --  permitted, and a certificate carrying one is refused
               --  rather than having the entry quietly dropped.
               if not Is_Present (From_Policy)
                 or else not Is_Present (To_Value)
                 or else Is_Any (From_Policy)
                 or else Is_Any (To_Value)
               then
                  return Result;
               end if;

               Result.Count := Result.Count + 1;
               Result.Values (Result.Count) :=
                 (Issuer_Policy => From_Policy, Subject_Policy => To_Value);
            end;
         end;
      end loop;

      if Status = Errors.Ok and then Result.Count > 0 then
         Result.Well_Formed := True;
      end if;
      return Result;
   end Mappings_Of;

   function Constraints_Of (Item : Certificate) return Policy_Constraints is
      Found  : Boolean;
      Data   : constant Octets :=
        Value_Of (Item, OID_Table.Policy_Constraints, Found);
      Result : Policy_Constraints;
      Cursor : Offset;
      Seq    : Element;
      Status : Errors.Decode_Status;
   begin
      if not Found then
         return Result;
      end if;

      Result.Present := True;

      Cursor := Data'First;
      DER_Reader.Read_Sequence
        (Data, Cursor, Data'Last, 0, Limits, Seq, Status);
      if Status /= Errors.Ok
        or else not DER_Reader.At_End (Cursor, Data'Last)
      then
         return Result;
      end if;

      --  Both fields are context-tagged INTEGERs, implicit, and both are
      --  optional -- but a policyConstraints with neither is meaningless and
      --  RFC 5280 forbids it.
      Cursor := Seq.First;
      while not DER_Reader.At_End (Cursor, Seq.Last) loop
         declare
            Field : Element;
            Value : Natural := 0;
         begin
            DER_Reader.Read (Data, Cursor, Seq.Last, 1, Limits, Field, Status);
            exit when Status /= Errors.Ok;

            if Field.Class /= Context_Specific or else Field.Constructed then
               return Result;
            end if;

            --  The content is an INTEGER's, without its own tag.
            if Content_Length (Field) = 0
              or else Content_Length (Field) > 4
            then
               return Result;
            end if;
            for I in Field.First .. Field.Last loop
               Value := Value * 256 + Natural (Data (I));
            end loop;

            case Field.Number is
               when 0 =>
                  if Result.Has_Require_Explicit then
                     return Result;
                  end if;
                  Result.Has_Require_Explicit := True;
                  Result.Require_Explicit := Value;
               when 1 =>
                  if Result.Has_Inhibit_Mapping then
                     return Result;
                  end if;
                  Result.Has_Inhibit_Mapping := True;
                  Result.Inhibit_Mapping := Value;
               when others =>
                  return Result;
            end case;
         end;
      end loop;

      if Status = Errors.Ok
        and then (Result.Has_Require_Explicit or else Result.Has_Inhibit_Mapping)
      then
         Result.Well_Formed := True;
      end if;
      return Result;
   end Constraints_Of;

   function Inhibit_Of (Item : Certificate) return Inhibit_Any_Policy is
      Found  : Boolean;
      Data   : constant Octets :=
        Value_Of (Item, OID_Table.Inhibit_Any_Policy, Found);
      Result : Inhibit_Any_Policy;
      Cursor : Offset;
      Value  : Natural;
      Status : Errors.Decode_Status;
   begin
      if not Found then
         return Result;
      end if;

      Result.Present := True;

      Cursor := Data'First;
      DER_Reader.Read_Small_Integer
        (Data, Cursor, Data'Last, 0, Limits, Value, Status);
      if Status /= Errors.Ok
        or else not DER_Reader.At_End (Cursor, Data'Last)
      then
         return Result;
      end if;

      Result.Value := Value;
      Result.Well_Formed := True;
      return Result;
   end Inhibit_Of;

   -----------------------------------------------------------------------
   --  RFC 5280 section 6.1 policy processing
   -----------------------------------------------------------------------

   --  Is this policy in the node's expected set?
   function Expects
     (Node : Tree_Node; Value : Policy_Value) return Boolean is
   begin
      for I in 1 .. Node.Expected_Count loop
         if Same (Node.Expected (I), Value) then
            return True;
         end if;
      end loop;
      return False;
   end Expects;

   --  Does this node already have a child naming this policy?
   function Has_Child
     (Item   : Engine;
      Parent : Natural;
      Value  : Policy_Value;
      Depth  : Natural) return Boolean is
   begin
      for I in Item.Nodes'Range loop
         if Item.Nodes (I).In_Use
           and then Item.Nodes (I).Parent = Parent
           and then Item.Nodes (I).Depth = Depth
           and then Same (Item.Nodes (I).Valid, Value)
         then
            return True;
         end if;
      end loop;
      return False;
   end Has_Child;

   --  Add a node. Running out of room is recorded rather than ignored: a
   --  tree that stopped growing is missing exactly the nodes that pruning
   --  would have removed, so continuing would answer from a tree that is too
   --  permissive rather than too strict.
   procedure Add_Node
     (Item     : in out Engine;
      Depth    : Natural;
      Parent   : Natural;
      Valid    : Policy_Value;
      Expected : Policy_Array;
      Count    : Natural)
   is
   begin
      for I in Item.Nodes'Range loop
         if not Item.Nodes (I).In_Use then
            Item.Nodes (I).In_Use := True;
            Item.Nodes (I).Depth := Depth;
            Item.Nodes (I).Parent := Parent;
            Item.Nodes (I).Valid := Valid;
            Item.Nodes (I).Expected_Count := 0;
            for J in 1 .. Natural'Min (Count, Maximum_Policies) loop
               Item.Nodes (I).Expected_Count :=
                 Item.Nodes (I).Expected_Count + 1;
               Item.Nodes (I).Expected (Item.Nodes (I).Expected_Count) :=
                 Expected (Expected'First + J - 1);
            end loop;
            return;
         end if;
      end loop;
      Item.Exhausted := True;
   end Add_Node;

   function Has_Node_At (Item : Engine; Depth : Natural) return Boolean is
   begin
      for I in Item.Nodes'Range loop
         if Item.Nodes (I).In_Use and then Item.Nodes (I).Depth = Depth then
            return True;
         end if;
      end loop;
      return False;
   end Has_Node_At;

   --  Section 6.1.3 (d)(3): a node with no children says nothing, and once
   --  it goes its own parent may have none either.
   procedure Prune (Item : in out Engine; Below : Natural) is
      Changed : Boolean := True;
   begin
      while Changed loop
         Changed := False;
         for I in Item.Nodes'Range loop
            if Item.Nodes (I).In_Use
              and then Item.Nodes (I).Depth <= Below
            then
               declare
                  Any_Child : Boolean := False;
               begin
                  for J in Item.Nodes'Range loop
                     if Item.Nodes (J).In_Use and then Item.Nodes (J).Parent = I
                     then
                        Any_Child := True;
                     end if;
                  end loop;
                  if not Any_Child then
                     Item.Nodes (I).In_Use := False;
                     Changed := True;
                  end if;
               end;
            end if;
         end loop;
      end loop;
   end Prune;

   procedure Start (Item : out Engine; Options : Policy_Options) is
      Root_Expected : constant Policy_Array (1 .. 1) := [1 => Any_Policy];
   begin
      Item.Nodes := [others => <>];
      Item.Depth := 0;
      Item.Tree_Empty := False;
      Item.Exhausted := False;
      Item.Last_Constraints := (others => <>);

      --  Each counter is a number of certificates that may still pass before
      --  the permission it guards is withdrawn. Starting at n + 1 means
      --  "never" for a path of n certificates; starting at zero means the
      --  caller withdrew it before processing began.
      Item.Explicit_Policy :=
        (if Options.Require_Explicit_Policy then 0 else Item.Path_Length + 1);
      Item.Policy_Mapping :=
        (if Options.Inhibit_Policy_Mapping then 0 else Item.Path_Length + 1);
      Item.Inhibit_Any :=
        (if Options.Inhibit_Any_Policy then 0 else Item.Path_Length + 1);

      --  The root: anyPolicy, expecting anyPolicy.
      Add_Node (Item, 0, 0, Any_Policy, Root_Expected, 1);
   end Start;

   procedure Step
     (Item        : in out Engine;
      Subject     : Certificate;
      Self_Issued : Boolean;
      Accepted    : out Boolean)
   is
      Level : constant Natural := Item.Depth + 1;
      Last  : constant Natural := Item.Path_Length;
      Named : constant Policy_Set := Policies_Of (Subject);
   begin
      Accepted := False;
      Item.Depth := Level;

      --  6.1.3 (d): grow the tree by what this certificate asserts.
      if not Item.Tree_Empty then
         if Named.Present and then Named.Well_Formed then
            for P in 1 .. Named.Count loop
               if not Is_Any (Named.Values (P)) then
                  declare
                     Value   : constant Policy_Value := Named.Values (P);
                     Single  : constant Policy_Array (1 .. 1) := [1 => Value];
                     Matched : Boolean := False;
                  begin
                     --  (1)(i) under every parent that expected it.
                     for I in Item.Nodes'Range loop
                        if Item.Nodes (I).In_Use
                          and then Item.Nodes (I).Depth = Level - 1
                          and then Expects (Item.Nodes (I), Value)
                        then
                           Add_Node (Item, Level, I, Value, Single, 1);
                           Matched := True;
                        end if;
                     end loop;

                     --  (1)(ii) otherwise under anyPolicy, if one is there.
                     if not Matched then
                        for I in Item.Nodes'Range loop
                           if Item.Nodes (I).In_Use
                             and then Item.Nodes (I).Depth = Level - 1
                             and then Is_Any (Item.Nodes (I).Valid)
                           then
                              Add_Node (Item, Level, I, Value, Single, 1);
                           end if;
                        end loop;
                     end if;
                  end;
               end if;
            end loop;

            --  (2) anyPolicy propagates whatever each parent still expects,
            --  but only while the wildcard is permitted.
            if Named.Has_Any
              and then (Item.Inhibit_Any > 0
                        or else (Level < Last and then Self_Issued))
            then
               for I in Item.Nodes'Range loop
                  if Item.Nodes (I).In_Use
                    and then Item.Nodes (I).Depth = Level - 1
                  then
                     for E in 1 .. Item.Nodes (I).Expected_Count loop
                        declare
                           Value  : constant Policy_Value :=
                             Item.Nodes (I).Expected (E);
                           Single : constant Policy_Array (1 .. 1) :=
                             [1 => Value];
                        begin
                           if not Has_Child (Item, I, Value, Level) then
                              Add_Node (Item, Level, I, Value, Single, 1);
                           end if;
                        end;
                     end loop;
                  end if;
               end loop;
            end if;

            --  (3)
            Prune (Item, Level - 1);
            if not Has_Node_At (Item, Level) then
               Item.Tree_Empty := True;
            end if;
         else
            --  (e) no policies here, so nothing below can be established.
            --  A malformed extension is treated the same: it does not say
            --  which policies apply, and guessing would be the permissive
            --  reading.
            Item.Tree_Empty := True;
         end if;
      end if;

      --  (f) the moment both the tree and the allowance are gone.
      if Item.Explicit_Policy = 0 and then Item.Tree_Empty then
         return;
      end if;

      if Level < Last then
         --  6.1.4 (a)(b): policy mapping.
         declare
            Maps : constant Mapping_Set := Mappings_Of (Subject);
         begin
            if Maps.Present then
               if not Maps.Well_Formed then
                  return;
               end if;

               if Item.Policy_Mapping > 0 then
                  for M in 1 .. Maps.Count loop
                     declare
                        From_P : constant Policy_Value :=
                          Maps.Values (M).Issuer_Policy;
                        Subjects : Policy_Array (1 .. Maximum_Policies);
                        Count    : Natural := 0;
                        Found    : Boolean := False;
                     begin
                        --  Every subject policy this issuer policy maps to.
                        for K in 1 .. Maps.Count loop
                           if Same (Maps.Values (K).Issuer_Policy, From_P)
                             and then Count < Maximum_Policies
                           then
                              Count := Count + 1;
                              Subjects (Count) :=
                                Maps.Values (K).Subject_Policy;
                           end if;
                        end loop;

                        for I in Item.Nodes'Range loop
                           if Item.Nodes (I).In_Use
                             and then Item.Nodes (I).Depth = Level
                             and then Same (Item.Nodes (I).Valid, From_P)
                           then
                              Item.Nodes (I).Expected_Count := 0;
                              for C in 1 .. Count loop
                                 Item.Nodes (I).Expected_Count := C;
                                 Item.Nodes (I).Expected (C) := Subjects (C);
                              end loop;
                              Found := True;
                           end if;
                        end loop;

                        --  No node names it, but anyPolicy stands in.
                        if not Found then
                           for I in Item.Nodes'Range loop
                              if Item.Nodes (I).In_Use
                                and then Item.Nodes (I).Depth = Level
                                and then Is_Any (Item.Nodes (I).Valid)
                              then
                                 Add_Node
                                   (Item, Level, Item.Nodes (I).Parent,
                                    From_P, Subjects, Count);
                              end if;
                           end loop;
                        end if;
                     end;
                  end loop;
               else
                  --  Mapping is inhibited: a mapped policy is struck out
                  --  rather than followed.
                  for M in 1 .. Maps.Count loop
                     for I in Item.Nodes'Range loop
                        if Item.Nodes (I).In_Use
                          and then Item.Nodes (I).Depth = Level
                          and then Same (Item.Nodes (I).Valid,
                                         Maps.Values (M).Issuer_Policy)
                        then
                           Item.Nodes (I).In_Use := False;
                        end if;
                     end loop;
                  end loop;
                  Prune (Item, Level - 1);
                  if not Has_Node_At (Item, Level) then
                     Item.Tree_Empty := True;
                  end if;
               end if;
            end if;
         end;

         --  (h) a self-issued certificate does not lengthen the path, so it
         --  does not spend any of the allowances.
         if not Self_Issued then
            if Item.Explicit_Policy > 0 then
               Item.Explicit_Policy := Item.Explicit_Policy - 1;
            end if;
            if Item.Policy_Mapping > 0 then
               Item.Policy_Mapping := Item.Policy_Mapping - 1;
            end if;
            if Item.Inhibit_Any > 0 then
               Item.Inhibit_Any := Item.Inhibit_Any - 1;
            end if;
         end if;

         --  (i)(j) a constraint only ever tightens.
         declare
            Con : constant Policy_Constraints := Constraints_Of (Subject);
            Inh : constant Inhibit_Any_Policy := Inhibit_Of (Subject);
         begin
            if Con.Present then
               if not Con.Well_Formed then
                  return;
               end if;
               if Con.Has_Require_Explicit
                 and then Con.Require_Explicit < Item.Explicit_Policy
               then
                  Item.Explicit_Policy := Con.Require_Explicit;
               end if;
               if Con.Has_Inhibit_Mapping
                 and then Con.Inhibit_Mapping < Item.Policy_Mapping
               then
                  Item.Policy_Mapping := Con.Inhibit_Mapping;
               end if;
            end if;

            if Inh.Present then
               if not Inh.Well_Formed then
                  return;
               end if;
               if Inh.Value < Item.Inhibit_Any then
                  Item.Inhibit_Any := Inh.Value;
               end if;
            end if;
         end;
      else
         --  The last certificate's constraints are read in the wrap-up.
         Item.Last_Constraints := Constraints_Of (Subject);
         if Item.Last_Constraints.Present
           and then not Item.Last_Constraints.Well_Formed
         then
            return;
         end if;
      end if;

      Accepted := not Item.Exhausted;
   end Step;

   function Finish
     (Item : in out Engine; Wanted : Policy_Array) return Policy_Outcome
   is
      Result : Policy_Outcome;
      Depth  : constant Natural := Item.Path_Length;
   begin
      --  6.1.5 (a)
      if Item.Explicit_Policy /= 0 then
         Item.Explicit_Policy := Item.Explicit_Policy - 1;
      end if;

      --  (b) the leaf may demand an explicit policy of itself.
      if Item.Last_Constraints.Present
        and then Item.Last_Constraints.Has_Require_Explicit
        and then Item.Last_Constraints.Require_Explicit = 0
      then
         Item.Explicit_Policy := 0;
      end if;

      --  (g) intersect with what the caller will accept. An empty Wanted is
      --  the RFC's any-policy, and intersecting with it is the whole tree.
      if Wanted'Length > 0 and then not Item.Tree_Empty then
         declare
            Wildcard : Natural := 0;
         begin
            for I in Item.Nodes'Range loop
               if Item.Nodes (I).In_Use
                 and then Item.Nodes (I).Depth = Depth
               then
                  if Is_Any (Item.Nodes (I).Valid) then
                     Wildcard := I;
                  else
                     declare
                        Kept : Boolean := False;
                     begin
                        for W in Wanted'Range loop
                           if Same (Item.Nodes (I).Valid, Wanted (W)) then
                              Kept := True;
                           end if;
                        end loop;
                        if not Kept then
                           Item.Nodes (I).In_Use := False;
                        end if;
                     end;
                  end if;
               end if;
            end loop;

            --  A surviving anyPolicy at the bottom stands for each policy
            --  the caller asked for that nothing else already provides.
            if Wildcard /= 0 then
               for W in Wanted'Range loop
                  declare
                     Single : constant Policy_Array (1 .. 1) :=
                       [1 => Wanted (W)];
                     Present_Already : Boolean := False;
                  begin
                     for I in Item.Nodes'Range loop
                        if Item.Nodes (I).In_Use
                          and then Item.Nodes (I).Depth = Depth
                          and then Same (Item.Nodes (I).Valid, Wanted (W))
                        then
                           Present_Already := True;
                        end if;
                     end loop;
                     if not Present_Already then
                        Add_Node
                          (Item, Depth, Item.Nodes (Wildcard).Parent,
                           Wanted (W), Single, 1);
                     end if;
                  end;
               end loop;
               Item.Nodes (Wildcard).In_Use := False;
            end if;

            Prune (Item, Depth - 1);
            if not Has_Node_At (Item, Depth) then
               Item.Tree_Empty := True;
            end if;
         end;
      end if;

      for I in Item.Nodes'Range loop
         if Item.Nodes (I).In_Use
           and then Item.Nodes (I).Depth = Depth
           and then Result.Count < Maximum_Policies
         then
            Result.Count := Result.Count + 1;
            Result.Values (Result.Count) := Item.Nodes (I).Valid;
         end if;
      end loop;

      Result.Exhausted := Item.Exhausted;
      Result.Acceptable :=
        not Item.Exhausted
        and then (Item.Explicit_Policy > 0 or else not Item.Tree_Empty);
      return Result;
   end Finish;

end CryptoLib.X509.Policies;
