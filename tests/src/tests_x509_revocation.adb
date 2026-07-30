with Ada.Streams;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Interfaces;
with System;
with CryptoLib.ASN1;
with CryptoLib.PEM;
with CryptoLib.X509;
with CryptoLib.X509.Certificates;
with CryptoLib.X509.Extensions;
with CryptoLib.X509.Identity;
with CryptoLib.X509.Purposes;
with CryptoLib.X509.Names;
with Ada.Directories;
with Ada.Streams.Stream_IO;
with CryptoLib.X509.CRLs;
with CryptoLib.X509.Revocation;
with CryptoLib.OCSP;
with CryptoLib.PKCS10;
with CryptoLib.PKCS8;
with CryptoLib.PKCS12;
with CryptoLib.Identities;
with CryptoLib.X509.Policies;
with CryptoLib.HKDF;
with CryptoLib.TLS13_KDF;
with CryptoLib.ECDH;
with CryptoLib.Constant_Time_Proof;
with CryptoLib.Constant_Time_Assurance;
with CryptoLib.MLKEM768_Core;
with CryptoLib.EC_Curves;
with CryptoLib.Hybrid_PQ_Kex;
with CryptoLib.Fingerprints;
with CryptoLib.Constant_Time;
with CryptoLib.BCrypt_PBKDF;
with CryptoLib.X509.Times;
with CryptoLib.X509.Validation;
with CryptoLib.X509.Path_Building;
with CryptoLib.X509.Name_Constraints;
with CryptoLib.X509.Signatures;
with CryptoLib.ASN1.DER;
with CryptoLib.ASN1.Errors;
with CryptoLib.ASN1.OIDs;
with CryptoLib.ChaCha20_Poly1305;
with CryptoLib.Certificates;
with OpenSSL_Interop;
with CryptoLib.Checksums;
with CryptoLib.Secure_Wipe;
with CryptoLib.Hashes;
with CryptoLib.Ciphers;
with CryptoLib.ECDSA;
with CryptoLib.Errors;
with CryptoLib.Macs;
with CryptoLib.UMAC;
with CryptoLib.MLKEM768;
with CryptoLib.SNTRUP761;
with CryptoLib.Curve25519;
with CryptoLib.Ed25519;
with CryptoLib.Ed448;
with CryptoLib.SHA3;
with CryptoLib.Buffers;
with CryptoLib.Diffie_Hellman;
with CryptoLib.Modexp;
with CryptoLib.Bignum;
with CryptoLib.Random;
with CryptoLib.RSA;
with Tests_Support; use Tests_Support;

package body Tests_X509_Revocation is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Certificates.Certificate_Status;
   use type Interfaces.Unsigned_32;



   --  A revocation list made by OpenSSL, with a certificate genuinely
   --  revoked through "openssl ca -revoke".
   --  When a certificate was revoked, and why -- from a CRL and from an OCSP
   --  response about the same certificates, which must agree.
   --
   --  The time matters on its own: a signature made before the revocation
   --  took effect may still stand, and a caller judging one needs that time
   --  rather than the moment the statement was published. The reason matters
   --  because Key_Compromise discredits every signature the key ever made,
   --  while Superseded or Cessation_Of_Operation leave earlier ones alone.
   procedure Check_Revocation_Details is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.OCSP.Verification_Result;
      use type CryptoLib.X509.Certificate_Time;
      use type CryptoLib.X509.Revocation_Reason;
      use type CryptoLib.X509.Revocation.Revocation_Answer;
      use type CryptoLib.X509.Signatures.Verification_Result;

      package X509C renames CryptoLib.X509.Certificates;
      package XC renames CryptoLib.X509.CRLs;
      package XR renames CryptoLib.X509.Revocation;
      package CO renames CryptoLib.OCSP;

      Reason_CA_DER : constant String :=
        "3082030d308201f5a0030201020214695a2eb222fd6509af65d97b7099306d68b399eb300d06092a864886f70d" &
        "01010b050030163114301206035504030c0b63726c2d746573742d6361301e170d323630373238323031353437" &
        "5a170d3336303732353230313534375a30163114301206035504030c0b63726c2d746573742d63613082012230" &
        "0d06092a864886f70d01010105000382010f003082010a0282010100b5e60ee7058f7f9e991a038feeac5eb95d" &
        "99b6b52f543a4cf379d9b84ab68125a82424b27f07a1f6a39f6f6e5ac4df194a06d3683fafc31123427f768f60" &
        "24aa6b2d5f759d0629a578497370038d70020ea20e261a913c332504d70327b2cd747a2ae0f415764976ae21d8" &
        "c34874405cfabefd83ffc5b03de5c6521a611c333189ead8755a0bf56113ad088deb953cf1febb465a377d256b" &
        "ad055bf627727ccfffa616cfe8edc009a49f318a6c1e935dc42b69ab1d2aa9ee2173defdf45fbb595b99aced52" &
        "9fca129587fac967025980f7617070edde4748fa62cd395a608475ba22bd65c29f1fabdefe5e8aeed28baa1703" &
        "88bca8bb6490db6bacea3473ed8f0203010001a3533051301d0603551d0e04160414a1f6d41f7e7b24380aa8a0" &
        "cd33926e4452de852f301f0603551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300f06" &
        "03551d130101ff040530030101ff300d06092a864886f70d01010b050003820101005f484fd12f7d522aa3787c" &
        "0ee05c3e06067d91b3f51a3747e1ffcd7d57e839f17a9bfcf878faa9c4af435426aa06ed4907dfb9c29ca36c6b" &
        "53af27ce22516b5bd4cb19e9d912893e3800a1f7acc3abefbc18a6c899793b6ff9d378f2a77e0feb03659f8a24" &
        "09bee7a4804773be1f8428608fb9041ac74581b1943d0d90dd2939be1b74015bcd676cf483167988523fba452b" &
        "255b49146d3c5be21408d8c9848f6794a4fa588ab2d6d326bc7d92920c3547d3f4d9270c01ec4d368c98e11a61" &
        "1f40cd6672de148b3bf435f812eda7e9e5d383ff2eefcf1384d136c45b1c062f731fc3414a237cf1b971994cce" &
        "d2b6852b3f4314e9335fc96ba21fd8949c58f5c5";

      Reason_Leaf_DER : constant String :=
        "308202a53082018d02021000300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d74" &
        "6573742d6361301e170d3236303732383230313534375a170d3237303732383230313534375a301a3118301606" &
        "035504030c0f7265766f6b65642e6578616d706c6530820122300d06092a864886f70d01010105000382010f00" &
        "3082010a0282010100c0ed219d3150260bb4a5a976fd93941636a1dcdc8976321a5c82e468c74ff7e755f29a69" &
        "40524606cf7e70308e8c3ed01c6954e7e7a45fdedd1d914b6cf2459cbba0b0a2f3a248771f69301ac2735a408a" &
        "f830e03b7c3941648de0810c102c79f17da1d486a3b676993fd30102ed86ee4d4cde770d3abf8dd4b178885132" &
        "f79e8799c63595af16af350d94207d96a5d830c19e2eff9edb43607e7c8e5ba3e737b82f71937a7ca59ffcac9d" &
        "fc633aa69ce1e08aabf84a068c4e1dfa9f7ca28f959062408140c1c8cf63d66761609bc2dff8b3d4bd3250ee0a" &
        "86b507023e9f9aee80b2184c01758ffaf3c280eeeff0fb0926de9c83cfc2f327c4dcd6254a0447150203010001" &
        "300d06092a864886f70d01010b0500038201010080e42f4484be128c22efd3e63c0ea74f0efc8937b0a9529a0d" &
        "90efd502c75e3647fa117adca923af965a184fa141d74ce910ad9fbed2fb1f1eb295f9cd28ebff73c6b8ea6ace" &
        "a4d54009be31e34a52fa63c4277ebe37865d16ce20d7776ff9dbfee953305678b1dc967f59f836b6fc5ce4f166" &
        "c3e4d20a992bbdb0b2ac53f8c8a23b9176097ae12e84bcebe9e81b77da3571a2f2bcf77d7e516102c37352c1e0" &
        "fba2439d98a01280abcefe8a91b5857a2f515e6ae71c14f10fa56fb4710798b987f0a0b89a2510995a6f6cfa27" &
        "2f10d60bcd56e3add0eb664aaa565ee2471a1f5b00eae79e62e58b987db98503855bb0bd82b803d2b7ee27f40c" &
        "f62c878f5876";

      Reason_Second_DER : constant String :=
        "308202a43082018c02021001300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d74" &
        "6573742d6361301e170d3236303732383232313431375a170d3237303732383232313431375a30193117301506" &
        "035504030c0e7365636f6e642e6578616d706c6530820122300d06092a864886f70d01010105000382010f0030" &
        "82010a0282010100a169fd82209088be49800f464b442f6e1d1fdd823084ff0a76bfbc7ec44287274a752dba1d" &
        "1926442087bff21dd051ce99fdf42f8cb4b30426d8240f922287b089d4e37a4add7ba8181dfc701369be8291e5" &
        "7166ba7922d556eed539d1c2627b160cdd7c71ba8598319435dc4c2087d062ed23a84313fae6666f45b3050b88" &
        "46c8b8fc2fca5b4e5018545e10a3cb8c7cdfbfa133cadb29acd896362cafb931bdfb31b4be226ba91567d38499" &
        "84b6fc1f6f9211550ea01e522aeaf7523e23c59e22ed3fc55bbdcd1e4a7019ad93f5c2c8cb603d849af6c0c0d6" &
        "99147c7c0073baaf455e0259cf099305383c5bebcf32113e1d82db30e615de58a0eed56dbb5b37020301000130" &
        "0d06092a864886f70d01010b050003820101006066b5357a33b4941a2fd365f2792c297d6e82829fc3ac6bdd8c" &
        "fc5efe3861139b38592af36fd731af2ee9f4a09689f01604097636072dac2cb00a319eded804527a0631c7ef52" &
        "1f610c466cc33d8bdc9aaaf3e77b13b5ff004a51f837af3c6cba3ba6bf882e293e2d23a35c5654b4827341e1fd" &
        "3afd7be93bb546b93bdf0983a8cbdde40b23ffd240220362c028f824e44fa2792a6a5fee2af6878df9c401ffba" &
        "c2681e43effd2c225cc03b7bbb09affc9e1b962feef1da1dbc1f23597487d936c21e712fd4085290cc5f5eef03" &
        "237d417b683db649c246f384d9190d16873cb75c50abe79b62e349772306da7e154bc2655aa9306c63ea33ce84" &
        "0832a2c904";

      Reason_CRL_DER : constant String :=
        "308201aa308193020101300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d746573" &
        "742d6361170d3236303732383232333530315a170d3236303832373232333530315a3038301302021000170d32" &
        "36303732383230313534375a302102021001170d3236303732383232333530315a300c300a0603551d1504030a" &
        "0101a00f300d300b0603551d14040402021001300d06092a864886f70d01010b050003820101007a95fd172721" &
        "41f2fb843e9bca2032f064e9fc48a1a09e47042bf2acf47f6c704776cb513d6991b0b9f08966af640a5be77c75" &
        "c497905b1087b1114a0ebab6616ddd0740085ae706dc9095b3596928ea9353484d4a07867174a3e17e745d61fe" &
        "3e3038fbe8e365e370ae1b989da8d11cd3cb2aa46ebdbad1b0af01581925c221270b488651bdfd13574ca3b91c" &
        "feb81e99c5d3d450de6cc66d93a1bf42f22683d81597a58be41fc8bf78cc038b73e30b3226bb5e4b8ee8f06a09" &
        "b8463b8bcb6095eff4dc439313f5834791ae09b92d169059b6d08af52d1ac727d373a3bd52e38dae47120addd9" &
        "dd397ac90f72edbc0b651c50b149f9c9a989029b3419a7d65e";

      Reason_Response_DER : constant String :=
        "308204f60a0100a08204ef308204eb06092b0601050507300101048204dc308204d83081a8a118301631143012" &
        "06035504030c0b63726c2d746573742d6361180f32303236303732383232333535325a307b3079303b30090605" &
        "2b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b24380aa8a0cd3392" &
        "6e4452de852f02021001a116180f32303236303732383232333530315aa0030a0101180f323032363037323832" &
        "32333535325aa011180f32303236303832373232333535325a300d06092a864886f70d01010b05000382010100" &
        "80a8a22a0fdfd1ad318eab14f12e354c63021234ae50e3b4b1ca9f7102dc9df6327c8f7df5b5ccc2e3c5afdb6c" &
        "c94cf1dbfd7c1f46d86d3a95dc2eb2668b0d3a2eadfeeaed734da38c84dbd94dfe8acf0458adcb48fcec6d970b" &
        "39e55f6a27bfe3838f5edc746c2a6c9ffa785066e68540e89124f7a44e27b4fdecf86a59b41f9b3ec3b5663687" &
        "348a1f4b4a13a5c3f2156429037d67f55e39846ccc07432f3f0bff4bf84517ddf3994fc61c72b6d1f9a7d0a36f" &
        "a331d3eaad39c6cc6f2845801461af6bd4a0152e9731fd4b39d25f66a394cc6a24b38db2cc5b5dd77acc620233" &
        "14469b08e952941688585c1788af20ecd72ac1db95c69944b073cabf27d188a0820315308203113082030d3082" &
        "01f5a0030201020214695a2eb222fd6509af65d97b7099306d68b399eb300d06092a864886f70d01010b050030" &
        "163114301206035504030c0b63726c2d746573742d6361301e170d3236303732383230313534375a170d333630" &
        "3732353230313534375a30163114301206035504030c0b63726c2d746573742d636130820122300d06092a8648" &
        "86f70d01010105000382010f003082010a0282010100b5e60ee7058f7f9e991a038feeac5eb95d99b6b52f543a" &
        "4cf379d9b84ab68125a82424b27f07a1f6a39f6f6e5ac4df194a06d3683fafc31123427f768f6024aa6b2d5f75" &
        "9d0629a578497370038d70020ea20e261a913c332504d70327b2cd747a2ae0f415764976ae21d8c34874405cfa" &
        "befd83ffc5b03de5c6521a611c333189ead8755a0bf56113ad088deb953cf1febb465a377d256bad055bf62772" &
        "7ccfffa616cfe8edc009a49f318a6c1e935dc42b69ab1d2aa9ee2173defdf45fbb595b99aced529fca129587fa" &
        "c967025980f7617070edde4748fa62cd395a608475ba22bd65c29f1fabdefe5e8aeed28baa170388bca8bb6490" &
        "db6bacea3473ed8f0203010001a3533051301d0603551d0e04160414a1f6d41f7e7b24380aa8a0cd33926e4452" &
        "de852f301f0603551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300f0603551d130101" &
        "ff040530030101ff300d06092a864886f70d01010b050003820101005f484fd12f7d522aa3787c0ee05c3e0606" &
        "7d91b3f51a3747e1ffcd7d57e839f17a9bfcf878faa9c4af435426aa06ed4907dfb9c29ca36c6b53af27ce2251" &
        "6b5bd4cb19e9d912893e3800a1f7acc3abefbc18a6c899793b6ff9d378f2a77e0feb03659f8a2409bee7a48047" &
        "73be1f8428608fb9041ac74581b1943d0d90dd2939be1b74015bcd676cf483167988523fba452b255b49146d3c" &
        "5be21408d8c9848f6794a4fa588ab2d6d326bc7d92920c3547d3f4d9270c01ec4d368c98e11a611f40cd6672de" &
        "148b3bf435f812eda7e9e5d383ff2eefcf1384d136c45b1c062f731fc3414a237cf1b971994cced2b6852b3f43" &
        "14e9335fc96ba21fd8949c58f5c5";

      function From_Hex
        (Text : String) return Ada.Streams.Stream_Element_Array
      is
         Result : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Text'Length / 2));
         function Nibble (C : Character) return Natural
         is (case C is
                when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
                when others     => Character'Pos (C) - Character'Pos ('a') + 10);
      begin
         for I in Result'Range loop
            Result (I) :=
              Ada.Streams.Stream_Element
                (Nibble (Text (Text'First + 2 * Natural (I - 1))) * 16
                 + Nibble (Text (Text'First + 2 * Natural (I - 1) + 1)));
         end loop;
         return Result;
      end From_Hex;

      Status : CryptoLib.ASN1.Errors.Decode_Status;
      CA     : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (Reason_CA_DER), CryptoLib.ASN1.Default_Limits, Status);
      Leaf   : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (Reason_Leaf_DER), CryptoLib.ASN1.Default_Limits, Status);
      Second : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (Reason_Second_DER), CryptoLib.ASN1.Default_Limits,
           Status);
      List   : constant XC.Revocation_List :=
        XC.Decode_DER
          (From_Hex (Reason_CRL_DER), CryptoLib.ASN1.Default_Limits, Status);

      --  Inside the CRL's window: thisUpdate 2026-07-28, nextUpdate
      --  2026-08-27, both as OpenSSL wrote them.
      Inside : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 8, Day => 1,
         Hour => 12, Minute => 0, Second => 0);

      Scoped_CRL_DER : constant String :=
        "30820180306a020101300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d74657374" &
        "2d6361170d3236303732383232353330385a170d3236303832373232353330385aa020301e300f0603551d1c01" &
        "01ff040530038201ff300b0603551d14040402022000300d06092a864886f70d01010b050003820101003fdb81" &
        "9f241451c144f655f468651da90a1e5009fc9564925c5849a2d061025e1511cd0eddcbfa07b325b352dd79d06a" &
        "20fd8b3135aeea4cb32f879ac49a9bd23a21626bfe06baa9bd96a037245980741f4d66affe4b4319b0ed467b2e" &
        "32615986c25ff8c0b295df910e640ac08b7d2d5035120640265597f73dd1891f8895fe626b0fac8dbca132286b" &
        "e2a62e85e190d1e7d0d1bbaedf217a6494ed1efe86aea9953d900d2c08635fa8e027306c08a6da815215135f64" &
        "18bc8d84542ad6f12a7fe9d3488b5c0f1ef8746e062ce93d0a6add3ddeb512773690a347b59d05a18ecd0ea465" &
        "695e35231c67a5e38f5e24560a02d031f92143ce973aa48a0b41648a";

      From_List : CryptoLib.X509.Revocation_Details;
      From_OCSP : CryptoLib.X509.Revocation_Details;
   begin
      Check (Status = CryptoLib.ASN1.Errors.Ok and then XC.Is_Present (List),
             "fixture: the two-entry CRL decodes");
      Check (XC.Entry_Count (List) = 2,
             "the list revokes two certificates, got"
             & Natural'Image (XC.Entry_Count (List)));

      --  An entry that gives no reason. Has_Reason must stay False: an
      --  issuer that said nothing did not say "unspecified", and reading the
      --  default as a statement puts words in its mouth.
      declare
         Info : constant CryptoLib.X509.Revocation_Details :=
           XC.Find_Revocation (List, X509C.Serial_Number (Leaf));
      begin
         Check (Info.Present, "the first certificate is on the list");
         Check (Info.Revoked_At.Year = 2026
                and then Info.Revoked_At.Month = 7
                and then Info.Revoked_At.Day = 28
                and then Info.Revoked_At.Hour = 20
                and then Info.Revoked_At.Minute = 15
                and then Info.Revoked_At.Second = 47,
                "its revocation time is the one OpenSSL wrote");
         Check (not Info.Has_Reason,
                "it gives no reason, and none is invented");
      end;

      --  An entry that does give one.
      From_List := XC.Find_Revocation (List, X509C.Serial_Number (Second));
      Check (From_List.Present, "the second certificate is on the list too");
      Check (From_List.Revoked_At.Year = 2026
             and then From_List.Revoked_At.Month = 7
             and then From_List.Revoked_At.Day = 28
             and then From_List.Revoked_At.Hour = 22
             and then From_List.Revoked_At.Minute = 35
             and then From_List.Revoked_At.Second = 1,
             "with its own revocation time, not the other entry's");
      Check (From_List.Has_Reason
             and then From_List.Reason = CryptoLib.X509.Key_Compromise,
             "and the reason the issuer gave, "
             & CryptoLib.X509.Reason_Image (From_List.Reason));

      --  A serial the list says nothing about must not come back carrying
      --  some other entry's time.
      declare
         Info : constant CryptoLib.X509.Revocation_Details :=
           XC.Find_Revocation (List, X509C.Serial_Number (CA));
      begin
         Check (not Info.Present,
                "a certificate not on the list is not revoked");
         Check (Info.Revoked_At.Year = 0 and then not Info.Has_Reason,
                "and carries no time or reason from anyone else");
      end;

      --  The same two facts from an OCSP response about the same
      --  certificate. The two sources are parsed by different code and must
      --  land on the same answer; if they can disagree, one of them is wrong
      --  and a caller has no way to tell which.
      declare
         Reply : CO.Response :=
           CO.Decode_Response
             (From_Hex (Reason_Response_DER), CryptoLib.ASN1.Default_Limits,
              Status);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok,
                "fixture: the response decodes");
         Check (CO.Verify (Reply, Second, CA) = CO.Accepted,
                "the response is accepted before its contents are read");

         From_OCSP := CO.Revocation_Of (Reply);
         Check (From_OCSP.Present,
                "the response says when the revocation took effect");
         Check (From_OCSP.Revoked_At = From_List.Revoked_At,
                "and it is the time the CRL gave");
         Check (From_OCSP.Has_Reason = From_List.Has_Reason
                and then From_OCSP.Reason = From_List.Reason,
                "and the reason the CRL gave, "
                & CryptoLib.X509.Reason_Image (From_OCSP.Reason));
      end;

      --  The same, through the front door, which is where a caller lands.
      declare
         Reply  : CO.Response :=
           CO.Decode_Response
             (From_Hex (Reason_Response_DER), CryptoLib.ASN1.Default_Limits,
              Status);
         Detail : CryptoLib.X509.Revocation_Details;
         Answer : XR.Revocation_Answer;
      begin
         Answer :=
           XR.Check_Against_CRL (Second, CA, List, Inside, Detail);
         Check (Answer = XR.Revoked,
                "the list revokes it: " & XR.Answer_Image (Answer));
         Check (Detail.Present
                and then Detail.Reason = CryptoLib.X509.Key_Compromise,
                "and says why without a second lookup");

         Answer :=
           XR.Check_Against_OCSP (Second, CA, Reply, Inside, Detail);
         Check (Answer = XR.Revoked,
                "the response revokes it: " & XR.Answer_Image (Answer));
         Check (Detail.Present
                and then Detail.Reason = CryptoLib.X509.Key_Compromise,
                "and says why too");

         --  A certificate the statement does not revoke must leave the
         --  details empty rather than keep the last certificate's.
         Answer := XR.Check_Against_CRL (CA, CA, List, Inside, Detail);
         Check (Answer /= XR.Revoked,
                "the CA is not revoked by its own list");
         Check (not Detail.Present,
                "and no revocation details are left behind from the last "
                & "question");
      end;

      --  A CRL that says, critically, that it covers only part of what its
      --  issuer signed. It is properly signed, in its own window, and lists
      --  nothing -- so every other check passes and an absent serial reads
      --  as "not revoked". It is not: the list never covered end-entity
      --  certificates, and reading silence as absolution is how a revoked
      --  certificate keeps working.
      declare
         Scoped : constant XC.Revocation_List :=
           XC.Decode_DER
             (From_Hex (Scoped_CRL_DER), CryptoLib.ASN1.Default_Limits,
              Status);
         Detail : CryptoLib.X509.Revocation_Details;
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok
                and then XC.Is_Present (Scoped),
                "a scoped CRL still decodes -- it is well formed");
         Check (XC.Verify_Signature (Scoped, CA)
                = CryptoLib.X509.Signatures.Valid,
                "and its issuer really signed it");
         Check (XC.Entry_Count (Scoped) = 0,
                "and it lists nothing, which is the trap");

         Check (XC.Has_Unsupported_Critical_Extension (Scoped),
                "its critical scoping extension is noticed");

         --  The certificate this asks about is revoked on the real list.
         declare
            Answer : constant XR.Revocation_Answer :=
              XR.Check_Against_CRL (Leaf, CA, Scoped, Inside, Detail);
         begin
            Check (Answer = XR.Unsupported_Statement,
                   "so the list answers nothing rather than 'not revoked', "
                   & "got " & XR.Answer_Image (Answer));
            Check (not Detail.Present,
                   "and carries no revocation details either");
         end;

         --  The ordinary list is unaffected: this must refuse scoped CRLs,
         --  not CRLs.
         Check (not XC.Has_Unsupported_Critical_Extension (List),
                "an ordinary CRL carries nothing critical this cannot read");
         Check (XR.Check_Against_CRL (Leaf, CA, List, Inside, Detail)
                = XR.Revoked,
                "and still answers");
      end;
   end Check_Revocation_Details;


   procedure Check_X509_CRL is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.X509.Signatures.Verification_Result;

      package X509C renames CryptoLib.X509.Certificates;
      package XC renames CryptoLib.X509.CRLs;

      CRL_DER : constant String :=
        "308201863070020101300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d74657374" &
        "2d6361170d3236303732383230313534375a170d3236303832373230313534375a3015301302021000170d3236" &
        "303732383230313534375aa00f300d300b0603551d14040402021000300d06092a864886f70d01010b05000382" &
        "0101006658640fbac6a1af6d6ae781e8565bde72e4d010700077d31961e4927583013585ed7dbe4fc3a86e1a5f" &
        "ad9bfd07334f077af62093de31acb5c1d137d1a25e67ba5d7faa7330cb422947461d2a395068594ddde4f739be" &
        "3bd345e04807299af988b58413704b2227863de0cfdfc8eb4090620bb5f299a7952a194ba4d273d6453c7cb9d0" &
        "d5ddab9a0365ebe032d1abfb3a10bed8a02d52aff966391e0bef4601150fccf121628bdbf5302e155cbc492ced" &
        "d9b07a9d8faf65476f1e3494ca0835eaaa97ea86bd0e0c4aa0f63584a3829891fc7a8b9d79522ed10c8d627a69" &
        "a018f0630976bf890136c61568406f615df99b62cd3db8eb62fbe778914516b4d902";

      CRL_CA_DER : constant String :=
        "3082030d308201f5a0030201020214695a2eb222fd6509af65d97b7099306d68b399eb300d06092a864886f70d" &
        "01010b050030163114301206035504030c0b63726c2d746573742d6361301e170d323630373238323031353437" &
        "5a170d3336303732353230313534375a30163114301206035504030c0b63726c2d746573742d63613082012230" &
        "0d06092a864886f70d01010105000382010f003082010a0282010100b5e60ee7058f7f9e991a038feeac5eb95d" &
        "99b6b52f543a4cf379d9b84ab68125a82424b27f07a1f6a39f6f6e5ac4df194a06d3683fafc31123427f768f60" &
        "24aa6b2d5f759d0629a578497370038d70020ea20e261a913c332504d70327b2cd747a2ae0f415764976ae21d8" &
        "c34874405cfabefd83ffc5b03de5c6521a611c333189ead8755a0bf56113ad088deb953cf1febb465a377d256b" &
        "ad055bf627727ccfffa616cfe8edc009a49f318a6c1e935dc42b69ab1d2aa9ee2173defdf45fbb595b99aced52" &
        "9fca129587fac967025980f7617070edde4748fa62cd395a608475ba22bd65c29f1fabdefe5e8aeed28baa1703" &
        "88bca8bb6490db6bacea3473ed8f0203010001a3533051301d0603551d0e04160414a1f6d41f7e7b24380aa8a0" &
        "cd33926e4452de852f301f0603551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300f06" &
        "03551d130101ff040530030101ff300d06092a864886f70d01010b050003820101005f484fd12f7d522aa3787c" &
        "0ee05c3e06067d91b3f51a3747e1ffcd7d57e839f17a9bfcf878faa9c4af435426aa06ed4907dfb9c29ca36c6b" &
        "53af27ce22516b5bd4cb19e9d912893e3800a1f7acc3abefbc18a6c899793b6ff9d378f2a77e0feb03659f8a24" &
        "09bee7a4804773be1f8428608fb9041ac74581b1943d0d90dd2939be1b74015bcd676cf483167988523fba452b" &
        "255b49146d3c5be21408d8c9848f6794a4fa588ab2d6d326bc7d92920c3547d3f4d9270c01ec4d368c98e11a61" &
        "1f40cd6672de148b3bf435f812eda7e9e5d383ff2eefcf1384d136c45b1c062f731fc3414a237cf1b971994cce" &
        "d2b6852b3f4314e9335fc96ba21fd8949c58f5c5";

      CRL_Leaf_DER : constant String :=
        "308202a53082018d02021000300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d74" &
        "6573742d6361301e170d3236303732383230313534375a170d3237303732383230313534375a301a3118301606" &
        "035504030c0f7265766f6b65642e6578616d706c6530820122300d06092a864886f70d01010105000382010f00" &
        "3082010a0282010100c0ed219d3150260bb4a5a976fd93941636a1dcdc8976321a5c82e468c74ff7e755f29a69" &
        "40524606cf7e70308e8c3ed01c6954e7e7a45fdedd1d914b6cf2459cbba0b0a2f3a248771f69301ac2735a408a" &
        "f830e03b7c3941648de0810c102c79f17da1d486a3b676993fd30102ed86ee4d4cde770d3abf8dd4b178885132" &
        "f79e8799c63595af16af350d94207d96a5d830c19e2eff9edb43607e7c8e5ba3e737b82f71937a7ca59ffcac9d" &
        "fc633aa69ce1e08aabf84a068c4e1dfa9f7ca28f959062408140c1c8cf63d66761609bc2dff8b3d4bd3250ee0a" &
        "86b507023e9f9aee80b2184c01758ffaf3c280eeeff0fb0926de9c83cfc2f327c4dcd6254a0447150203010001" &
        "300d06092a864886f70d01010b0500038201010080e42f4484be128c22efd3e63c0ea74f0efc8937b0a9529a0d" &
        "90efd502c75e3647fa117adca923af965a184fa141d74ce910ad9fbed2fb1f1eb295f9cd28ebff73c6b8ea6ace" &
        "a4d54009be31e34a52fa63c4277ebe37865d16ce20d7776ff9dbfee953305678b1dc967f59f836b6fc5ce4f166" &
        "c3e4d20a992bbdb0b2ac53f8c8a23b9176097ae12e84bcebe9e81b77da3571a2f2bcf77d7e516102c37352c1e0" &
        "fba2439d98a01280abcefe8a91b5857a2f515e6ae71c14f10fa56fb4710798b987f0a0b89a2510995a6f6cfa27" &
        "2f10d60bcd56e3add0eb664aaa565ee2471a1f5b00eae79e62e58b987db98503855bb0bd82b803d2b7ee27f40c" &
        "f62c878f5876";

      function From_Hex
        (Text : String) return Ada.Streams.Stream_Element_Array
      is
         Result : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Text'Length / 2));
         function Nibble (C : Character) return Natural
         is (case C is
                when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
                when others     => Character'Pos (C) - Character'Pos ('a') + 10);
      begin
         for I in Result'Range loop
            Result (I) :=
              Ada.Streams.Stream_Element
                (Nibble (Text (Text'First + 2 * Natural (I - 1))) * 16
                 + Nibble (Text (Text'First + 2 * Natural (I - 1) + 1)));
         end loop;
         return Result;
      end From_Hex;

      Status : CryptoLib.ASN1.Errors.Decode_Status;

      CA : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (CRL_CA_DER), CryptoLib.ASN1.Default_Limits, Status);
      Leaf : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (CRL_Leaf_DER), CryptoLib.ASN1.Default_Limits, Status);
      List : constant XC.Revocation_List :=
        XC.Decode_DER
          (From_Hex (CRL_DER), CryptoLib.ASN1.Default_Limits, Status);

      --  For the separation check at the end.
      package XV renames CryptoLib.X509.Validation;

      type Revoked_Path is limited new XV.Path_Source with null record;

      overriding function Length (Source : Revoked_Path) return Positive
      is (2);

      overriding function Certificate_At
        (Source : Revoked_Path; Index : Positive) return X509C.Certificate
      is (if Index = 1
          then X509C.Decode_DER
                 (From_Hex (CRL_Leaf_DER), CryptoLib.ASN1.Default_Limits,
                  Status)
          else X509C.Decode_DER
                 (From_Hex (CRL_CA_DER), CryptoLib.ASN1.Default_Limits,
                  Status));

      overriding function Is_Trust_Anchor
        (Source : Revoked_Path; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Bytes (Item)
          = X509C.Subject_Bytes
              (X509C.Decode_DER
                 (From_Hex (CRL_CA_DER), CryptoLib.ASN1.Default_Limits,
                  Status)));
   begin
      Check (Status = CryptoLib.ASN1.Errors.Ok and then XC.Is_Present (List),
             "the CRL decodes: "
             & CryptoLib.ASN1.Errors.Status_Image (Status));
      Check (X509C.Is_Present (CA) and then X509C.Is_Present (Leaf),
             "fixture: the CA and the revoked certificate decode");

      --  Issued by the CA it claims, which is what makes it about these
      --  certificates at all.
      Check (XC.Issuer_Bytes (List) = X509C.Subject_Bytes (CA),
             "the CRL's issuer is the CA's subject");

      Check (XC.This_Update (List).Year = 2026,
             "thisUpdate decodes to the year OpenSSL wrote");
      Check (XC.Has_Next_Update (List),
             "this CRL states when the next one is due");
      Check (CryptoLib.X509.Is_Not_After
               (XC.This_Update (List), XC.Next_Update (List)),
             "the update window is not inverted");

      Check (XC.Entry_Count (List) = 1,
             "the list carries one revoked certificate, got"
             & Natural'Image (XC.Entry_Count (List)));

      --  The certificate that was revoked, looked up by the serial its own
      --  encoding carries.
      Check (XC.Is_Revoked (List, X509C.Serial_Number (Leaf)),
             "the revoked certificate is on the list");

      --  One that was not.
      Check (not XC.Is_Revoked (List, [16#7F#, 16#FF#]),
             "a serial that was never issued is not on the list");

      --  A serial written with a sign-preserving leading zero is the same
      --  number. Missing that would treat a revoked certificate as good.
      declare
         Serial : constant Ada.Streams.Stream_Element_Array :=
           X509C.Serial_Number (Leaf);
         Padded : constant Ada.Streams.Stream_Element_Array :=
           [0] & Serial;
      begin
         Check (XC.Is_Revoked (List, Padded),
                "a serial with a leading zero is the same serial");
      end;

      --  The CA really signed it.
      Check (XC.Verify_Signature (List, CA)
               = CryptoLib.X509.Signatures.Valid,
             "the CRL verifies under its issuer's key");

      --  And the leaf did not.
      Check (XC.Verify_Signature (List, Leaf)
               /= CryptoLib.X509.Signatures.Valid,
             "the CRL does not verify under an unrelated key");

      --  A CRL with a byte changed inside the signed body must not verify.
      declare
         Damaged : Ada.Streams.Stream_Element_Array := From_Hex (CRL_DER);
         Broken  : CryptoLib.ASN1.Errors.Decode_Status;
      begin
         --  Inside the TBSCertList rather than in the signature: this is the
         --  alteration a signature exists to detect.
         Damaged (Damaged'First + 30) := Damaged (Damaged'First + 30) xor 1;
         declare
            Altered : constant XC.Revocation_List :=
              XC.Decode_DER
                (Damaged, CryptoLib.ASN1.Default_Limits, Broken);
         begin
            if Broken = CryptoLib.ASN1.Errors.Ok then
               Check (XC.Verify_Signature (Altered, CA)
                        /= CryptoLib.X509.Signatures.Valid,
                      "an altered CRL does not verify");
            end if;
         end;
      end;
      --  Path validation does not consult revocation, and that is a
      --  decision rather than an oversight: the material has to come from
      --  somewhere, fetching it is the application's, and a validator that
      --  went to the network would make every validation a request that can
      --  hang. What it must not do is imply otherwise.
      --
      --  So: a certificate this very CRL revokes still passes Validate_Path.
      --  A caller reading a valid result as "not revoked" is reading
      --  something that was never checked, and the day Validate_Path starts
      --  consulting a CRL it did not receive, this check is what says so.
      declare
         use type XV.Validation_Failure;
         use type CryptoLib.X509.Revocation.Revocation_Answer;

         Inside : constant CryptoLib.X509.Certificate_Time :=
           (Year => 2026, Month => 8, Day => 1,
            Hour => 0, Minute => 0, Second => 0);

         Verdict : constant XV.Validation_Result :=
           XV.Validate_Path (Revoked_Path'(null record), Inside);
      begin
         --  The premise: the CRL really does revoke this certificate.
         Check (CryptoLib.X509.Revocation.Check_Against_CRL
                  (Leaf, CA, List, Inside)
                = CryptoLib.X509.Revocation.Revoked,
                "fixture: the list revokes the leaf");

         Check (Verdict.Valid,
                "and path validation still accepts it, because revocation "
                & "is not among the things it checks: "
                & XV.Failure_Image (Verdict.Failure));
      end;
   end Check_X509_CRL;



   --  OCSP, against requests and responses OpenSSL produced.
   --
   --  The two delegated cases are the reason this package is careful: a
   --  responder answering for somebody else's certificates is the whole
   --  attack, and the only thing standing between the two responses below is
   --  one extended key usage.
   procedure Check_OCSP is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.OCSP.Verification_Result;
      use type CryptoLib.OCSP.Response_Status;
      use type CryptoLib.OCSP.Certificate_Status;
      use type CryptoLib.OCSP.Responder_Kind;

      package X509C renames CryptoLib.X509.Certificates;
      package CO renames CryptoLib.OCSP;

      OCSP_Request : constant String :=
        "30433041303f303d303b300906052b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414" &
        "a1f6d41f7e7b24380aa8a0cd33926e4452de852f02021000";

      OCSP_Direct : constant String :=
        "308204de0a0100a08204d7308204d306092b0601050507300101048204c4308204c0308190a118301631143012" &
        "06035504030c0b63726c2d746573742d6361180f32303236303732383230323335385a30633061303b30090605" &
        "2b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b24380aa8a0cd3392" &
        "6e4452de852f02021000a111180f32303236303732383230313534375a180f3230323630373238323032333538" &
        "5a300d06092a864886f70d01010b05000382010100862fd17f69d414772feb68610edde88340d444547f7e017a" &
        "efab65e16849a6bd80267d5e624d5bdc87f5d6434ab54062c31f42ecaa312ad9a748c695c0d9d2e347dc540697" &
        "5ec19765aa29f2c3ba9376a21127c69294df5eb7adf737ebe67b2d68f7902a3e52a9853dcc3ef610046bf4a501" &
        "0d68c20b943c3dd04347b08a14be4b4e41c768e86784909e0d6bc36f09472ef4fb68025e5f92eecb0e9f816386" &
        "55c57d49f1b8b4931eccf246a8e342a83dd8b52ea209524956c4f3ab3ed05ca51d25fb648fb3218ee3516653d1" &
        "cf10b640ac0c3b561087977344d0a7ad93f276f89a19a8b667fd389b3650b83fe4183cf51ae996640d687a40b4" &
        "2faf4d10f5619ea0820315308203113082030d308201f5a0030201020214695a2eb222fd6509af65d97b709930" &
        "6d68b399eb300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d746573742d636130" &
        "1e170d3236303732383230313534375a170d3336303732353230313534375a30163114301206035504030c0b63" &
        "726c2d746573742d636130820122300d06092a864886f70d01010105000382010f003082010a0282010100b5e6" &
        "0ee7058f7f9e991a038feeac5eb95d99b6b52f543a4cf379d9b84ab68125a82424b27f07a1f6a39f6f6e5ac4df" &
        "194a06d3683fafc31123427f768f6024aa6b2d5f759d0629a578497370038d70020ea20e261a913c332504d703" &
        "27b2cd747a2ae0f415764976ae21d8c34874405cfabefd83ffc5b03de5c6521a611c333189ead8755a0bf56113" &
        "ad088deb953cf1febb465a377d256bad055bf627727ccfffa616cfe8edc009a49f318a6c1e935dc42b69ab1d2a" &
        "a9ee2173defdf45fbb595b99aced529fca129587fac967025980f7617070edde4748fa62cd395a608475ba22bd" &
        "65c29f1fabdefe5e8aeed28baa170388bca8bb6490db6bacea3473ed8f0203010001a3533051301d0603551d0e" &
        "04160414a1f6d41f7e7b24380aa8a0cd33926e4452de852f301f0603551d23041830168014a1f6d41f7e7b2438" &
        "0aa8a0cd33926e4452de852f300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003" &
        "820101005f484fd12f7d522aa3787c0ee05c3e06067d91b3f51a3747e1ffcd7d57e839f17a9bfcf878faa9c4af" &
        "435426aa06ed4907dfb9c29ca36c6b53af27ce22516b5bd4cb19e9d912893e3800a1f7acc3abefbc18a6c89979" &
        "3b6ff9d378f2a77e0feb03659f8a2409bee7a4804773be1f8428608fb9041ac74581b1943d0d90dd2939be1b74" &
        "015bcd676cf483167988523fba452b255b49146d3c5be21408d8c9848f6794a4fa588ab2d6d326bc7d92920c35" &
        "47d3f4d9270c01ec4d368c98e11a611f40cd6672de148b3bf435f812eda7e9e5d383ff2eefcf1384d136c45b1c" &
        "062f731fc3414a237cf1b971994cced2b6852b3f4314e9335fc96ba21fd8949c58f5c5";

      OCSP_Delegated : constant String :=
        "308205060a0100a08204ff308204fb06092b0601050507300101048204ec308204e8308193a11b301931173015" &
        "06035504030c0e6f6373702d726573706f6e646572180f32303236303732383230323431345a30633061303b30" &
        "0906052b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b24380aa8a0" &
        "cd33926e4452de852f02021000a111180f32303236303732383230313534375a180f3230323630373238323032" &
        "3431345a300d06092a864886f70d01010b05000382010100743a3e5445a00169dbfac8f1d889ae13523335e534" &
        "cfe136842b5316d626794304f602bee55c287bf8d5ebb02eadeb2ccf21392ab83aafb07de20fb8365ba7a7f180" &
        "91973241ef823100826a8a5da50ce96bd5d2c09095ded007e05038c8974e4d6d24df3ae3fe9088cc5c8719ba21" &
        "86933f61cd4657ba32b0885504597dcc45c8295fc478250f12ffe9398432f3d547017920b59880e05a2d7a320a" &
        "7e207b5b30354b3540a69256b623a3abf06200155e43dc9b347d0a184bdb0dddf431cec3ad1d76b8fcac3174ff" &
        "55a1e9590225d17eade87430acc731a02f0b936e675ad4ea2831530ec05ce57c917f47e57f8ffcdaba3fab5e31" &
        "6604116d938c1f4cd958a082033a30820336308203323082021aa003020102021444aab1aa260bfa011e9556a8" &
        "1fcac713d43514b6300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d746573742d" &
        "6361301e170d3236303732383230323431345a170d3237303732383230323431345a3019311730150603550403" &
        "0c0e6f6373702d726573706f6e64657230820122300d06092a864886f70d01010105000382010f003082010a02" &
        "82010100f51a4c10fd2b7b59f399fd3f6f2cd2f3b2f0ca1e94b48c7aa86fd4389e857ab7dc515e1de5debeeca2" &
        "10baa228975c38d7580b62b1e8e0e7b94030a79d3c572c2b5ed916a48c354bfec591c7685e8802e8be5789eb86" &
        "b2b209ece387c0ab75246ec81af3e7194b0e79c6238841da91497cffd00dc470027b242664f870511af713de07" &
        "50032a3e3cc73f83ca64d0e2f50e0137e74f0bae16eadb203e23907f9a7ee72a2069e095e9a3fb17be25d07557" &
        "32feaafe7e76e2b560086d6575a3b681f69347ce78aa56f8f9d13ad9b08813cb0f3d9397c403a5d943a85854c0" &
        "9657ab024e9dece7a5f6c0d81eb2a078fb8842cba426ee93e6c279c2cd0ebf86e0197f0203010001a375307330" &
        "090603551d1304023000300e0603551d0f0101ff04040302078030160603551d250101ff040c300a06082b0601" &
        "0505070309301d0603551d0e04160414d2f9e7ddf12388f9a8660ebd49decec3c844e664301f0603551d230418" &
        "30168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300d06092a864886f70d01010b050003820101007a" &
        "21aa45f4758c6a4ed14ffd336edfa0fa154e11b040e19d400bc6b95c4887cd2a6903eaf7b6e74e907df6bfb1fd" &
        "d1012b697abee6ab86946130e5bd37e65510e5728443c717bec4bb0986e97956903e25cdabbea19b60aab68588" &
        "d80be5e44eaf53c4f36f076124ad56a48c46abfb7eb806303d87b96b6bd7416192f5072d8536f53bbaf5087390" &
        "ce561548386d645695b8293bf35486124bfbca35ce0ff1892b7b697570033dae46b40b870c0fe0069fd153f6ba" &
        "6222b02f13b0a8a6cee43751a074c55dc7e0445117a02ae476d349bc164c136518fe15bbb3c9578baaeccee905" &
        "1cf77a0bb0b44ed31349a77fc4353a468cb1f1fc3555515f67c4c530a75e";

      OCSP_Multi : constant String :=
        "308205310a0100a082052a3082052606092b060105050730010104820517308205133081e3a118301631143012" &
        "06035504030c0b63726c2d746573742d6361180f32303236303732383232313431375a3081b53061303b300906" &
        "052b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b24380aa8a0cd33" &
        "926e4452de852f02021000a111180f32303236303732383230313534375a180f32303236303732383232313431" &
        "375a3050303b300906052b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f" &
        "7e7b24380aa8a0cd33926e4452de852f020210018000180f32303236303732383232313431375a300d06092a86" &
        "4886f70d01010b0500038201010066d7702b438d1c953ceff5ac8fde94cdce5a59909635095ff97bc3ab45bfbd" &
        "9763ac36de742e8514e2ab4acd9f3e91fde41c95cf47a7ac51ece4d9b9ded05de39a5b5a2e1192414362342c9e" &
        "2f2e563f4750185010bcbaefc6836a83a2a23d1d9f6e6c863a26744dbb9447978d60825d4dfc3e87ab600cebb9" &
        "aeb2abd34fa64ebff72537c083d6f72d170ba198be581b430caabbc4b4b8d511044c41126cc632e1727d0ce983" &
        "11cf07b2cbacc47739b24ac76fc8f264a75bf7250139fc380e7e571c111a1c5f556576a65872cd7dfc0a9e973a" &
        "211551470034f4a01df0896f64e37a68031d8253755c2ef26ed4dc6598f3021e1fdd0cbe9214765e856736c0b2" &
        "a0820315308203113082030d308201f5a0030201020214695a2eb222fd6509af65d97b7099306d68b399eb300d" &
        "06092a864886f70d01010b050030163114301206035504030c0b63726c2d746573742d6361301e170d32363037" &
        "32383230313534375a170d3336303732353230313534375a30163114301206035504030c0b63726c2d74657374" &
        "2d636130820122300d06092a864886f70d01010105000382010f003082010a0282010100b5e60ee7058f7f9e99" &
        "1a038feeac5eb95d99b6b52f543a4cf379d9b84ab68125a82424b27f07a1f6a39f6f6e5ac4df194a06d3683faf" &
        "c31123427f768f6024aa6b2d5f759d0629a578497370038d70020ea20e261a913c332504d70327b2cd747a2ae0" &
        "f415764976ae21d8c34874405cfabefd83ffc5b03de5c6521a611c333189ead8755a0bf56113ad088deb953cf1" &
        "febb465a377d256bad055bf627727ccfffa616cfe8edc009a49f318a6c1e935dc42b69ab1d2aa9ee2173defdf4" &
        "5fbb595b99aced529fca129587fac967025980f7617070edde4748fa62cd395a608475ba22bd65c29f1fabdefe" &
        "5e8aeed28baa170388bca8bb6490db6bacea3473ed8f0203010001a3533051301d0603551d0e04160414a1f6d4" &
        "1f7e7b24380aa8a0cd33926e4452de852f301f0603551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e" &
        "4452de852f300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003820101005f484f" &
        "d12f7d522aa3787c0ee05c3e06067d91b3f51a3747e1ffcd7d57e839f17a9bfcf878faa9c4af435426aa06ed49" &
        "07dfb9c29ca36c6b53af27ce22516b5bd4cb19e9d912893e3800a1f7acc3abefbc18a6c899793b6ff9d378f2a7" &
        "7e0feb03659f8a2409bee7a4804773be1f8428608fb9041ac74581b1943d0d90dd2939be1b74015bcd676cf483" &
        "167988523fba452b255b49146d3c5be21408d8c9848f6794a4fa588ab2d6d326bc7d92920c3547d3f4d9270c01" &
        "ec4d368c98e11a611f40cd6672de148b3bf435f812eda7e9e5d383ff2eefcf1384d136c45b1c062f731fc3414a" &
        "237cf1b971994cced2b6852b3f4314e9335fc96ba21fd8949c58f5c5";

      OCSP_Second_DER : constant String :=
        "308202a43082018c02021001300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d74" &
        "6573742d6361301e170d3236303732383232313431375a170d3237303732383232313431375a30193117301506" &
        "035504030c0e7365636f6e642e6578616d706c6530820122300d06092a864886f70d01010105000382010f0030" &
        "82010a0282010100a169fd82209088be49800f464b442f6e1d1fdd823084ff0a76bfbc7ec44287274a752dba1d" &
        "1926442087bff21dd051ce99fdf42f8cb4b30426d8240f922287b089d4e37a4add7ba8181dfc701369be8291e5" &
        "7166ba7922d556eed539d1c2627b160cdd7c71ba8598319435dc4c2087d062ed23a84313fae6666f45b3050b88" &
        "46c8b8fc2fca5b4e5018545e10a3cb8c7cdfbfa133cadb29acd896362cafb931bdfb31b4be226ba91567d38499" &
        "84b6fc1f6f9211550ea01e522aeaf7523e23c59e22ed3fc55bbdcd1e4a7019ad93f5c2c8cb603d849af6c0c0d6" &
        "99147c7c0073baaf455e0259cf099305383c5bebcf32113e1d82db30e615de58a0eed56dbb5b37020301000130" &
        "0d06092a864886f70d01010b050003820101006066b5357a33b4941a2fd365f2792c297d6e82829fc3ac6bdd8c" &
        "fc5efe3861139b38592af36fd731af2ee9f4a09689f01604097636072dac2cb00a319eded804527a0631c7ef52" &
        "1f610c466cc33d8bdc9aaaf3e77b13b5ff004a51f837af3c6cba3ba6bf882e293e2d23a35c5654b4827341e1fd" &
        "3afd7be93bb546b93bdf0983a8cbdde40b23ffd240220362c028f824e44fa2792a6a5fee2af6878df9c401ffba" &
        "c2681e43effd2c225cc03b7bbb09affc9e1b962feef1da1dbc1f23597487d936c21e712fd4085290cc5f5eef03" &
        "237d417b683db649c246f384d9190d16873cb75c50abe79b62e349772306da7e154bc2655aa9306c63ea33ce84" &
        "0832a2c904";

      OCSP_Unauthorized : constant String :=
        "3082050c0a0100a08205053082050106092b0601050507300101048204f2308204ee308196a11e301c311a3018" &
        "06035504030c116e6f746f6373702d726573706f6e646572180f32303236303732383230323431345a30633061" &
        "303b300906052b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b2438" &
        "0aa8a0cd33926e4452de852f02021000a111180f32303236303732383230313534375a180f3230323630373238" &
        "3230323431345a300d06092a864886f70d01010b050003820101003efd3a59e9a03c2805dfbdcf26a8cd69030b" &
        "f0b8ce62077c1a1bb41fa48a7a057fce3a66620e77c8d4b94c900d60e1d571fdbe63885930bdc90c57cd70c27a" &
        "8ebf532a48e349f9815238bed4ae6c74e91c12b5d1a46b2597e88ac38b844bebbfb80e10542e0f054a74f39720" &
        "05b9161b2ce6d81e5013f0c4526695d228983d426b74771432b1407cb26e7f517ff6742a562c884c5aad5d5162" &
        "21adc1f9a277ae81b718ad0a10a55b2cbce9d76bde99f6dc9d386701574cb9273a1b1a708ca7d09eb20eea15ec" &
        "2d71b2f0abe87b2bd8ea5642cbf88fdd89d91b757bced088d1e4bca01dd9aad9fa99c8ab3d5c4c5fe2fc505360" &
        "458c7e4237a2c11f15ed7f6075a082033d30820339308203353082021da003020102021444aab1aa260bfa011e" &
        "9556a81fcac713d43514b7300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d7465" &
        "73742d6361301e170d3236303732383230323431345a170d3237303732383230323431345a301c311a30180603" &
        "5504030c116e6f746f6373702d726573706f6e64657230820122300d06092a864886f70d01010105000382010f" &
        "003082010a0282010100c491c573ae839cb45ecb75d47f2ee41bc065ae9ac39fd7afd4f5cd4d7e89b400a7a79e" &
        "a43a2c43a05cb58e21d352370dc4d2956c4a709881048aafcd9e3d9c6a72aa007f6a259f43df29f8266532ae82" &
        "7cda39eeeafd679d1ceb61decd7bf001ba1678361cd24a53ce9173af7998f0498c73cf279ed10996c9bee9350b" &
        "c4137886fd8147c3402fc31447f03bffde66f34846635843750384edeeaa53aeb8b838fa8ab77f60a1f5a3e0e0" &
        "57991dd329172f19bc27db6a197ca7dd0b6ecb9b3c3455bd4c961ddb9d96ec27ee13367135de9567f041ea418f" &
        "bdb7df415504cabedbffa399a9f3a044bb9f1c0e473df09b22386d1cf2258a9b78ee21800ece10801502030100" &
        "01a375307330090603551d1304023000300e0603551d0f0101ff04040302078030160603551d250101ff040c30" &
        "0a06082b06010505070301301d0603551d0e041604146ad1ce7fdde3bfe17e9475437ce287f6a1b1f787301f06" &
        "03551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300d06092a864886f70d01010b0500" &
        "038201010064cf0f298af11571ae94fed30d1d5d06dacd42eea12c67ff6314a8ce09022033055285288afdbe17" &
        "4c219b8353b4cf08474ad7b98d0cfe39b89786822a712cf5bcfac43ea9469c0764d8d855fd8c0e433a478f9fbf" &
        "bc44a4ae55765959d634b2049200d96b4583d4815987808a8fed6a00fd9c4bca8bbaa94b35866393bc56238e5b" &
        "e6cc4b57faf9318df531ed1ac623f546f05fc72b168174b6211f65564bebccdeb3a87332bc76c84fffe8722525" &
        "e90a24602ea7bb0c5ccc21d5190bf9ddbeee2603064d2d4f18be78400151956112375b19f87a5a09eb4a63cd12" &
        "8dc20797b0fcf9cd0ab02d7b3aa89591c00bfd50b2006b51bd6aab88bd9eebc1f91109b0";

      CRL_CA_DER : constant String :=
        "3082030d308201f5a0030201020214695a2eb222fd6509af65d97b7099306d68b399eb300d06092a864886f70d" &
        "01010b050030163114301206035504030c0b63726c2d746573742d6361301e170d323630373238323031353437" &
        "5a170d3336303732353230313534375a30163114301206035504030c0b63726c2d746573742d63613082012230" &
        "0d06092a864886f70d01010105000382010f003082010a0282010100b5e60ee7058f7f9e991a038feeac5eb95d" &
        "99b6b52f543a4cf379d9b84ab68125a82424b27f07a1f6a39f6f6e5ac4df194a06d3683fafc31123427f768f60" &
        "24aa6b2d5f759d0629a578497370038d70020ea20e261a913c332504d70327b2cd747a2ae0f415764976ae21d8" &
        "c34874405cfabefd83ffc5b03de5c6521a611c333189ead8755a0bf56113ad088deb953cf1febb465a377d256b" &
        "ad055bf627727ccfffa616cfe8edc009a49f318a6c1e935dc42b69ab1d2aa9ee2173defdf45fbb595b99aced52" &
        "9fca129587fac967025980f7617070edde4748fa62cd395a608475ba22bd65c29f1fabdefe5e8aeed28baa1703" &
        "88bca8bb6490db6bacea3473ed8f0203010001a3533051301d0603551d0e04160414a1f6d41f7e7b24380aa8a0" &
        "cd33926e4452de852f301f0603551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300f06" &
        "03551d130101ff040530030101ff300d06092a864886f70d01010b050003820101005f484fd12f7d522aa3787c" &
        "0ee05c3e06067d91b3f51a3747e1ffcd7d57e839f17a9bfcf878faa9c4af435426aa06ed4907dfb9c29ca36c6b" &
        "53af27ce22516b5bd4cb19e9d912893e3800a1f7acc3abefbc18a6c899793b6ff9d378f2a77e0feb03659f8a24" &
        "09bee7a4804773be1f8428608fb9041ac74581b1943d0d90dd2939be1b74015bcd676cf483167988523fba452b" &
        "255b49146d3c5be21408d8c9848f6794a4fa588ab2d6d326bc7d92920c3547d3f4d9270c01ec4d368c98e11a61" &
        "1f40cd6672de148b3bf435f812eda7e9e5d383ff2eefcf1384d136c45b1c062f731fc3414a237cf1b971994cce" &
        "d2b6852b3f4314e9335fc96ba21fd8949c58f5c5";

      CRL_Leaf_DER : constant String :=
        "308202a53082018d02021000300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d74" &
        "6573742d6361301e170d3236303732383230313534375a170d3237303732383230313534375a301a3118301606" &
        "035504030c0f7265766f6b65642e6578616d706c6530820122300d06092a864886f70d01010105000382010f00" &
        "3082010a0282010100c0ed219d3150260bb4a5a976fd93941636a1dcdc8976321a5c82e468c74ff7e755f29a69" &
        "40524606cf7e70308e8c3ed01c6954e7e7a45fdedd1d914b6cf2459cbba0b0a2f3a248771f69301ac2735a408a" &
        "f830e03b7c3941648de0810c102c79f17da1d486a3b676993fd30102ed86ee4d4cde770d3abf8dd4b178885132" &
        "f79e8799c63595af16af350d94207d96a5d830c19e2eff9edb43607e7c8e5ba3e737b82f71937a7ca59ffcac9d" &
        "fc633aa69ce1e08aabf84a068c4e1dfa9f7ca28f959062408140c1c8cf63d66761609bc2dff8b3d4bd3250ee0a" &
        "86b507023e9f9aee80b2184c01758ffaf3c280eeeff0fb0926de9c83cfc2f327c4dcd6254a0447150203010001" &
        "300d06092a864886f70d01010b0500038201010080e42f4484be128c22efd3e63c0ea74f0efc8937b0a9529a0d" &
        "90efd502c75e3647fa117adca923af965a184fa141d74ce910ad9fbed2fb1f1eb295f9cd28ebff73c6b8ea6ace" &
        "a4d54009be31e34a52fa63c4277ebe37865d16ce20d7776ff9dbfee953305678b1dc967f59f836b6fc5ce4f166" &
        "c3e4d20a992bbdb0b2ac53f8c8a23b9176097ae12e84bcebe9e81b77da3571a2f2bcf77d7e516102c37352c1e0" &
        "fba2439d98a01280abcefe8a91b5857a2f515e6ae71c14f10fa56fb4710798b987f0a0b89a2510995a6f6cfa27" &
        "2f10d60bcd56e3add0eb664aaa565ee2471a1f5b00eae79e62e58b987db98503855bb0bd82b803d2b7ee27f40c" &
        "f62c878f5876";

      function From_Hex
        (Text : String) return Ada.Streams.Stream_Element_Array
      is
         Result : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Text'Length / 2));
         function Nibble (C : Character) return Natural
         is (case C is
                when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
                when others     => Character'Pos (C) - Character'Pos ('a') + 10);
      begin
         for I in Result'Range loop
            Result (I) :=
              Ada.Streams.Stream_Element
                (Nibble (Text (Text'First + 2 * Natural (I - 1))) * 16
                 + Nibble (Text (Text'First + 2 * Natural (I - 1) + 1)));
         end loop;
         return Result;
      end From_Hex;

      OCSP_Nonce_Request : constant String :=
        "30683066303f303d303b300906052b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414" &
        "a1f6d41f7e7b24380aa8a0cd33926e4452de852f02021000a2233021301f06092b060105050730010204120410" &
        "7fd8286787dd2b097e24bc1c0437e57b";

      OCSP_Nonce_Response : constant String :=
        "308205160a0100a082050f3082050b06092b0601050507300101048204fc308204f83081c8a118301631143012" &
        "06035504030c0b63726c2d746573742d6361180f32303236303732383232343130395a30763074303b30090605" &
        "2b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b24380aa8a0cd3392" &
        "6e4452de852f02021000a111180f32303236303732383230313534375a180f3230323630373238323234313039" &
        "5aa011180f32303236303832373232343130395aa1233021301f06092b0601050507300102041204107fd82867" &
        "87dd2b097e24bc1c0437e57b300d06092a864886f70d01010b0500038201010068b3c8fa8dde21a743f5eedd73" &
        "3a681dcbc6e188f739590f30dd2dc495cf9ead37f99b1f31ad0185ccb38fbf752de366d5b06a9c7dfbb3d75718" &
        "017343e06f71af78054f98fce4585277957e193cee24fe98c0417807d349efc09993533dd0b3daf47a73e63176" &
        "9b066f08e812af0ca47ac1630390166cb8120be2c1dc6a9f801e92495a1c44110fdd39524a72f7920ec2ecfa9e" &
        "459b7e0a774c87d8968e294acf799db314f391a612942210f53172d79367826822eb7d60db5c362a507aefd935" &
        "59913c5bc91e1a37e08cd5c258ed13166778accab6dd4d10b6de573acff07ac70b0b571845f7552b75fd924c38" &
        "02414f14b9e83fc0fd862856ee49a8db8c1aa0820315308203113082030d308201f5a0030201020214695a2eb2" &
        "22fd6509af65d97b7099306d68b399eb300d06092a864886f70d01010b050030163114301206035504030c0b63" &
        "726c2d746573742d6361301e170d3236303732383230313534375a170d3336303732353230313534375a301631" &
        "14301206035504030c0b63726c2d746573742d636130820122300d06092a864886f70d01010105000382010f00" &
        "3082010a0282010100b5e60ee7058f7f9e991a038feeac5eb95d99b6b52f543a4cf379d9b84ab68125a82424b2" &
        "7f07a1f6a39f6f6e5ac4df194a06d3683fafc31123427f768f6024aa6b2d5f759d0629a578497370038d70020e" &
        "a20e261a913c332504d70327b2cd747a2ae0f415764976ae21d8c34874405cfabefd83ffc5b03de5c6521a611c" &
        "333189ead8755a0bf56113ad088deb953cf1febb465a377d256bad055bf627727ccfffa616cfe8edc009a49f31" &
        "8a6c1e935dc42b69ab1d2aa9ee2173defdf45fbb595b99aced529fca129587fac967025980f7617070edde4748" &
        "fa62cd395a608475ba22bd65c29f1fabdefe5e8aeed28baa170388bca8bb6490db6bacea3473ed8f0203010001" &
        "a3533051301d0603551d0e04160414a1f6d41f7e7b24380aa8a0cd33926e4452de852f301f0603551d23041830" &
        "168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300f0603551d130101ff040530030101ff300d06092a" &
        "864886f70d01010b050003820101005f484fd12f7d522aa3787c0ee05c3e06067d91b3f51a3747e1ffcd7d57e8" &
        "39f17a9bfcf878faa9c4af435426aa06ed4907dfb9c29ca36c6b53af27ce22516b5bd4cb19e9d912893e3800a1" &
        "f7acc3abefbc18a6c899793b6ff9d378f2a77e0feb03659f8a2409bee7a4804773be1f8428608fb9041ac74581" &
        "b1943d0d90dd2939be1b74015bcd676cf483167988523fba452b255b49146d3c5be21408d8c9848f6794a4fa58" &
        "8ab2d6d326bc7d92920c3547d3f4d9270c01ec4d368c98e11a611f40cd6672de148b3bf435f812eda7e9e5d383" &
        "ff2eefcf1384d136c45b1c062f731fc3414a237cf1b971994cced2b6852b3f4314e9335fc96ba21fd8949c58f5" &
        "c5";

      OCSP_Critical_Response : constant String :=
        "308205280a0100a08205213082051d06092b06010505073001010482050e3082050a3081daa118301631143012" &
        "06035504030c0b63726c2d746573742d6361180f32303236303732383232343130395a30763074303b30090605" &
        "2b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b24380aa8a0cd3392" &
        "6e4452de852f02021000a111180f32303236303732383230313534375a180f3230323630373238323234313039" &
        "5aa011180f32303236303832373232343130395aa1353033301f06092b0601050507300102041204107fd82867" &
        "87dd2b097e24bc1c0437e57b301006092b06010505073001630101ff0400300d06092a864886f70d01010b0500" &
        "03820101003829713f5834725861c9a813a729eb5d4f91bf175b0f9b9611c4638e749525a353a9d0827a5c8333" &
        "09b7bb9cf75266a4a780b7d714d278705e1ff85014ae083a8bdf55064d0951684cbc3362473663c3c01d8d70d4" &
        "6ede6b058933f8d112baa790cf4c2ebe41636538e07edeec0ea0895b65de3dcbbe5204ec0baef590fb2a2a70be" &
        "4c914261d40f3db0df8d05a3d3c841cf4e47d77acd4d724c0c73a0e3486454b7253ef2239a57337c3f1bdab14f" &
        "3e6a4fc7d5182b9b17ef6946302e9ecca58c3fa2a37aff28d87d1948762ad60f0bc94f1e3fb09573250f7c7895" &
        "3eded381b7f7d81c968e32255a2809580349421faf29cbe3eb26ce784e5e9e3a62d469ada08203153082031130" &
        "82030d308201f5a0030201020214695a2eb222fd6509af65d97b7099306d68b399eb300d06092a864886f70d01" &
        "010b050030163114301206035504030c0b63726c2d746573742d6361301e170d3236303732383230313534375a" &
        "170d3336303732353230313534375a30163114301206035504030c0b63726c2d746573742d636130820122300d" &
        "06092a864886f70d01010105000382010f003082010a0282010100b5e60ee7058f7f9e991a038feeac5eb95d99" &
        "b6b52f543a4cf379d9b84ab68125a82424b27f07a1f6a39f6f6e5ac4df194a06d3683fafc31123427f768f6024" &
        "aa6b2d5f759d0629a578497370038d70020ea20e261a913c332504d70327b2cd747a2ae0f415764976ae21d8c3" &
        "4874405cfabefd83ffc5b03de5c6521a611c333189ead8755a0bf56113ad088deb953cf1febb465a377d256bad" &
        "055bf627727ccfffa616cfe8edc009a49f318a6c1e935dc42b69ab1d2aa9ee2173defdf45fbb595b99aced529f" &
        "ca129587fac967025980f7617070edde4748fa62cd395a608475ba22bd65c29f1fabdefe5e8aeed28baa170388" &
        "bca8bb6490db6bacea3473ed8f0203010001a3533051301d0603551d0e04160414a1f6d41f7e7b24380aa8a0cd" &
        "33926e4452de852f301f0603551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300f0603" &
        "551d130101ff040530030101ff300d06092a864886f70d01010b050003820101005f484fd12f7d522aa3787c0e" &
        "e05c3e06067d91b3f51a3747e1ffcd7d57e839f17a9bfcf878faa9c4af435426aa06ed4907dfb9c29ca36c6b53" &
        "af27ce22516b5bd4cb19e9d912893e3800a1f7acc3abefbc18a6c899793b6ff9d378f2a77e0feb03659f8a2409" &
        "bee7a4804773be1f8428608fb9041ac74581b1943d0d90dd2939be1b74015bcd676cf483167988523fba452b25" &
        "5b49146d3c5be21408d8c9848f6794a4fa588ab2d6d326bc7d92920c3547d3f4d9270c01ec4d368c98e11a611f" &
        "40cd6672de148b3bf435f812eda7e9e5d383ff2eefcf1384d136c45b1c062f731fc3414a237cf1b971994cced2" &
        "b6852b3f4314e9335fc96ba21fd8949c58f5c5";

      OCSP_Critical_Single : constant String :=
        "3082052e0a0100a08205273082052306092b060105050730010104820514308205103081e0a118301631143012" &
        "06035504030c0b63726c2d746573742d6361180f32303236303732383232343130395a30818d30818a303b3009" &
        "06052b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b24380aa8a0cd" &
        "33926e4452de852f02021000a111180f32303236303732383230313534375a180f323032363037323832323431" &
        "30395aa011180f32303236303832373232343130395aa1143012301006092b06010505073001630101ff0400a1" &
        "233021301f06092b0601050507300102041204107fd8286787dd2b097e24bc1c0437e57b300d06092a864886f7" &
        "0d01010b050003820101006a2c78c204cb36d61eac84655d9d60c9276097853ed6298d3eb8c2850703fc5365de" &
        "acc2dbfaa02fa9b31ab5e868c6456d59e243a9ab558e6adeaabc7ac53c92ce56b249b89fd6a6ff6e7bb4ad23e2" &
        "f4332605251d744da2efc49a06abb62b91ae75acd78f1a597ada5c62988b9871de7d995787a5212e32a75221ed" &
        "08dbb8b4723db228d2df8d85700acb7cca6019d43c4f0230f9081ae2c1771c455e7eaa4fdc846e9a5b7a668ba3" &
        "0bf6944c643aa854d239419b1c917cbc874f7b9f4aed7e670fece44acde038281f0150bf981519062f1e2ddcbd" &
        "a0187d55c26e4fbe8ed5950f46597969b82d6f85d39de60074f19fb262e424d728db7a3bf76d6053f17ca08203" &
        "15308203113082030d308201f5a0030201020214695a2eb222fd6509af65d97b7099306d68b399eb300d06092a" &
        "864886f70d01010b050030163114301206035504030c0b63726c2d746573742d6361301e170d32363037323832" &
        "30313534375a170d3336303732353230313534375a30163114301206035504030c0b63726c2d746573742d6361" &
        "30820122300d06092a864886f70d01010105000382010f003082010a0282010100b5e60ee7058f7f9e991a038f" &
        "eeac5eb95d99b6b52f543a4cf379d9b84ab68125a82424b27f07a1f6a39f6f6e5ac4df194a06d3683fafc31123" &
        "427f768f6024aa6b2d5f759d0629a578497370038d70020ea20e261a913c332504d70327b2cd747a2ae0f41576" &
        "4976ae21d8c34874405cfabefd83ffc5b03de5c6521a611c333189ead8755a0bf56113ad088deb953cf1febb46" &
        "5a377d256bad055bf627727ccfffa616cfe8edc009a49f318a6c1e935dc42b69ab1d2aa9ee2173defdf45fbb59" &
        "5b99aced529fca129587fac967025980f7617070edde4748fa62cd395a608475ba22bd65c29f1fabdefe5e8aee" &
        "d28baa170388bca8bb6490db6bacea3473ed8f0203010001a3533051301d0603551d0e04160414a1f6d41f7e7b" &
        "24380aa8a0cd33926e4452de852f301f0603551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de" &
        "852f300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003820101005f484fd12f7d" &
        "522aa3787c0ee05c3e06067d91b3f51a3747e1ffcd7d57e839f17a9bfcf878faa9c4af435426aa06ed4907dfb9" &
        "c29ca36c6b53af27ce22516b5bd4cb19e9d912893e3800a1f7acc3abefbc18a6c899793b6ff9d378f2a77e0feb" &
        "03659f8a2409bee7a4804773be1f8428608fb9041ac74581b1943d0d90dd2939be1b74015bcd676cf483167988" &
        "523fba452b255b49146d3c5be21408d8c9848f6794a4fa588ab2d6d326bc7d92920c3547d3f4d9270c01ec4d36" &
        "8c98e11a611f40cd6672de148b3bf435f812eda7e9e5d383ff2eefcf1384d136c45b1c062f731fc3414a237cf1" &
        "b971994cced2b6852b3f4314e9335fc96ba21fd8949c58f5c5";

      Status : CryptoLib.ASN1.Errors.Decode_Status;

      --  The same CA and revoked certificate the CRL fixtures come from.
      CA : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (CRL_CA_DER), CryptoLib.ASN1.Default_Limits, Status);
      Leaf : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (CRL_Leaf_DER), CryptoLib.ASN1.Default_Limits, Status);
   begin
      --  A request built here is the request OpenSSL builds, byte for byte.
      --  Anything less and the responder is being asked a question about a
      --  certificate it cannot recognise.
      declare
         Built : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CO.Maximum_Request_Length));
         Last  : Ada.Streams.Stream_Element_Offset;
         St    : CryptoLib.ASN1.Errors.Decode_Status;
         Want  : constant Ada.Streams.Stream_Element_Array :=
           From_Hex (OCSP_Request);
      begin
         CO.Build_Request (Leaf, CA, Built, Last, St);
         Check (St = CryptoLib.ASN1.Errors.Ok, "the request is built");
         Check (Built (Built'First .. Last) = Want,
                "the request is byte-identical to OpenSSL's");
      end;

      --  Signed by the issuer itself.
      declare
         Item : CO.Response :=
           CO.Decode_Response
             (From_Hex (OCSP_Direct), CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok and then CO.Is_Present (Item),
                "the direct response decodes: "
                & CryptoLib.ASN1.Errors.Status_Image (Status));
         Check (CO.Status_Of (Item) = CO.Successful,
                "the responder answered");
         Check (CO.Verify (Item, Leaf, CA) = CO.Accepted,
                "a response signed by the issuer is accepted");
         Check (CO.Responder (Item) = CO.Issuer_Signed,
                "and is recorded as issuer-signed");
         Check (CO.Certificate_Status_Of (Item) = CO.Revoked,
                "the certificate is reported revoked, which is what "
                & "openssl ca -revoke made it");
      end;

      --  Signed by a responder the issuer delegated to.
      declare
         Item : CO.Response :=
           CO.Decode_Response
             (From_Hex (OCSP_Delegated), CryptoLib.ASN1.Default_Limits,
              Status);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok, "the delegated response "
                & "decodes");
         Check (CO.Verify (Item, Leaf, CA) = CO.Accepted,
                "a response from an authorized delegate is accepted");
         Check (CO.Responder (Item) = CO.Delegate_Signed,
                "and is recorded as delegate-signed, not confused with the "
                & "issuer answering directly");
      end;

      --  Signed by a certificate the issuer really did issue, which is not
      --  authorized to answer. Without the extended key usage check any
      --  server certificate could speak for its CA's revocation state.
      declare
         Item : CO.Response :=
           CO.Decode_Response
             (From_Hex (OCSP_Unauthorized), CryptoLib.ASN1.Default_Limits,
              Status);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok,
                "the unauthorized response decodes -- it is well formed");
         Check (CO.Verify (Item, Leaf, CA) = CO.Delegate_Not_Authorized,
                "a delegate without OCSP signing authority is refused, got "
                & CO.Result_Image (CO.Verify (Item, Leaf, CA)));
         Check (CO.Responder (Item) = CO.Not_Established,
                "and no responder is established for it");
      end;

      --  A responder may answer about several certificates at once, so the
      --  reply has to be searched rather than its first entry taken. Asking
      --  about the second certificate in this reply used to give
      --  Wrong_Certificate -- fail-closed, but an answer that was there and
      --  was not found.
      declare
         Second : constant X509C.Certificate :=
           X509C.Decode_DER
             (From_Hex (OCSP_Second_DER), CryptoLib.ASN1.Default_Limits,
              Status);
         First_Item : CO.Response :=
           CO.Decode_Response
             (From_Hex (OCSP_Multi), CryptoLib.ASN1.Default_Limits, Status);
         Second_Item : CO.Response :=
           CO.Decode_Response
             (From_Hex (OCSP_Multi), CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok,
                "a reply covering two certificates decodes");

         Check (CO.Verify (First_Item, Leaf, CA) = CO.Accepted,
                "the first certificate is answered, got "
                & CO.Result_Image (CO.Verify (First_Item, Leaf, CA)));
         Check (CO.Certificate_Status_Of (First_Item) = CO.Revoked,
                "and it is the revoked one");

         Check (CO.Verify (Second_Item, Second, CA) = CO.Accepted,
                "the second certificate is answered too, got "
                & CO.Result_Image (CO.Verify (Second_Item, Second, CA)));
         Check (CO.Certificate_Status_Of (Second_Item) = CO.Good,
                "and it is good -- the status is its own rather than the "
                & "first entry's");
      end;

      --  A response about somebody else's certificate. Verified against the
      --  CA as if it were the subject, so the CertID cannot match.
      declare
         Item : CO.Response :=
           CO.Decode_Response
             (From_Hex (OCSP_Direct), CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (CO.Verify (Item, CA, CA) = CO.Wrong_Certificate,
                "a response about a different certificate is refused, got "
                & CO.Result_Image (CO.Verify (Item, CA, CA)));
      end;

      --  A nonce ties a response to the question that was asked. Without one
      --  a response stands on its own for as long as it is current, so an
      --  answer captured before a certificate was revoked can be presented
      --  again afterwards and still check out.
      declare
         Sent : constant Ada.Streams.Stream_Element_Array :=
           From_Hex ("7fd8286787dd2b097e24bc1c0437e57b");
         Other : constant Ada.Streams.Stream_Element_Array :=
           From_Hex ("00112233445566778899aabbccddeeff");
         Built : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset
                   (CO.Maximum_Request_Length));
         Last  : Ada.Streams.Stream_Element_Offset;
         St    : CryptoLib.ASN1.Errors.Decode_Status;
         Want  : constant Ada.Streams.Stream_Element_Array :=
           From_Hex (OCSP_Nonce_Request);
      begin
         --  Same certificate, same nonce, same bytes OpenSSL writes. The
         --  nonce sits in requestExtensions with its value wrapped twice --
         --  an OCTET STRING inside the extension's OCTET STRING -- and
         --  getting that nesting wrong produces a request a responder reads
         --  as carrying no nonce at all.
         CO.Build_Request (Leaf, CA, Built, Last, St, Sent);
         Check (St = CryptoLib.ASN1.Errors.Ok,
                "a request carrying a nonce is built");
         Check (Built (Built'First .. Last) = Want,
                "and is byte-identical to the one OpenSSL builds");

         --  RFC 8954 bounds the nonce at 32 octets. A longer one is refused
         --  rather than truncated: a truncated nonce is a different nonce,
         --  and the caller would compare against what it meant to send.
         declare
            Too_Long : constant Ada.Streams.Stream_Element_Array
              (1 .. CO.Maximum_Nonce_Length + 1) := [others => 16#41#];
         begin
            CO.Build_Request (Leaf, CA, Built, Last, St, Too_Long);
            Check (St /= CryptoLib.ASN1.Errors.Ok,
                   "an over-long nonce is refused rather than trimmed");
         end;

         declare
            Reply : CO.Response :=
              CO.Decode_Response
                (From_Hex (OCSP_Nonce_Response),
                 CryptoLib.ASN1.Default_Limits, Status);
            Plain : CO.Response :=
              CO.Decode_Response
                (From_Hex (OCSP_Direct), CryptoLib.ASN1.Default_Limits,
                 Status);
         begin
            Check (Status = CryptoLib.ASN1.Errors.Ok,
                   "fixture: the response decodes");
            Check (CO.Has_Nonce (Reply),
                   "the responder echoed a nonce");
            Check (CO.Nonce (Reply) = Sent,
                   "and it is the nonce that was sent");

            Check (CO.Verify (Reply, Leaf, CA, Sent) = CO.Accepted,
                   "a response carrying the nonce sent is accepted, got "
                   & CO.Result_Image (CO.Verify (Reply, Leaf, CA, Sent)));

            --  The whole point: a well-formed, correctly signed, current
            --  response that answers the wrong question is refused.
            Check (CO.Verify (Reply, Leaf, CA, Other) = CO.Nonce_Mismatch,
                   "a response carrying a different nonce is refused, got "
                   & CO.Result_Image (CO.Verify (Reply, Leaf, CA, Other)));

            --  Missing is reported apart from mismatched, because a
            --  responder serving pre-signed answers omits the nonce as a
            --  matter of course and a caller may decide to live with that.
            Check (CO.Verify (Plain, Leaf, CA, Sent) = CO.Nonce_Missing,
                   "a response carrying no nonce is reported as missing, got "
                   & CO.Result_Image (CO.Verify (Plain, Leaf, CA, Sent)));

            --  A caller that sent no nonce has nothing to compare against,
            --  and demanding one anyway would refuse every stapled response.
            Check (CO.Verify (Reply, Leaf, CA) = CO.Accepted,
                   "checking no nonce still accepts a response that has one");
            Check (CO.Verify (Plain, Leaf, CA) = CO.Accepted,
                   "and one that has none");
         end;
      end;

      --  A critical extension is the responder saying that ignoring it
      --  changes what the response means. Both fixtures are genuinely
      --  signed -- OpenSSL reports "Response verify OK" on each -- and
      --  differ from the accepted response above only by carrying one
      --  unrecognised critical extension, so nothing but this check stands
      --  between them and being read as ordinary answers.
      declare
         In_Response : CO.Response :=
           CO.Decode_Response
             (From_Hex (OCSP_Critical_Response),
              CryptoLib.ASN1.Default_Limits, Status);
         In_Entry : CO.Response :=
           CO.Decode_Response
             (From_Hex (OCSP_Critical_Single),
              CryptoLib.ASN1.Default_Limits, Status);
         Clean : CO.Response :=
           CO.Decode_Response
             (From_Hex (OCSP_Nonce_Response), CryptoLib.ASN1.Default_Limits,
              Status);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok,
                "fixtures carrying critical extensions still decode");

         --  In the response's own extensions.
         Check (CO.Has_Unsupported_Critical_Extension (In_Response),
                "a critical extension on the response is noticed");
         Check (CO.Verify (In_Response, Leaf, CA) = CO.Unsupported_Extension,
                "and the response is refused, got "
                & CO.Result_Image (CO.Verify (In_Response, Leaf, CA)));

         --  And in the entry about this certificate. These sit behind an
         --  optional nextUpdate, so a reader that peeks at nextUpdate
         --  without stepping over it never reaches them at all.
         Check (CO.Has_Unsupported_Critical_Extension (In_Entry),
                "a critical extension on the entry is noticed too");
         Check (CO.Verify (In_Entry, Leaf, CA) = CO.Unsupported_Extension,
                "and that response is refused as well, got "
                & CO.Result_Image (CO.Verify (In_Entry, Leaf, CA)));

         --  This must refuse those responses, not responses.
         Check (not CO.Has_Unsupported_Critical_Extension (Clean),
                "an ordinary response carries nothing critical this cannot "
                & "read");
         Check (CO.Verify (Clean, Leaf, CA) = CO.Accepted,
                "and is still accepted");
      end;
   end Check_OCSP;



   --  Revocation answered from material the caller already has, and judged
   --  for freshness -- which nothing was doing before. A statement made years
   --  ago saying a certificate was fine says nothing about now, and reading
   --  it as though it did is how a revoked certificate keeps working.
   procedure Check_Revocation is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.X509.Revocation.Revocation_Answer;

      package X509C renames CryptoLib.X509.Certificates;
      package XR renames CryptoLib.X509.Revocation;

      --  The same CA, revoked leaf, CRL and OCSP responses the earlier tests
      --  use, all made by OpenSSL through "openssl ca -revoke".
      CRL_DER : constant String :=
        "308201863070020101300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d74657374" &
        "2d6361170d3236303732383230313534375a170d3236303832373230313534375a3015301302021000170d3236" &
        "303732383230313534375aa00f300d300b0603551d14040402021000300d06092a864886f70d01010b05000382" &
        "0101006658640fbac6a1af6d6ae781e8565bde72e4d010700077d31961e4927583013585ed7dbe4fc3a86e1a5f" &
        "ad9bfd07334f077af62093de31acb5c1d137d1a25e67ba5d7faa7330cb422947461d2a395068594ddde4f739be" &
        "3bd345e04807299af988b58413704b2227863de0cfdfc8eb4090620bb5f299a7952a194ba4d273d6453c7cb9d0" &
        "d5ddab9a0365ebe032d1abfb3a10bed8a02d52aff966391e0bef4601150fccf121628bdbf5302e155cbc492ced" &
        "d9b07a9d8faf65476f1e3494ca0835eaaa97ea86bd0e0c4aa0f63584a3829891fc7a8b9d79522ed10c8d627a69" &
        "a018f0630976bf890136c61568406f615df99b62cd3db8eb62fbe778914516b4d902";

      CRL_CA_DER : constant String :=
        "3082030d308201f5a0030201020214695a2eb222fd6509af65d97b7099306d68b399eb300d06092a864886f70d" &
        "01010b050030163114301206035504030c0b63726c2d746573742d6361301e170d323630373238323031353437" &
        "5a170d3336303732353230313534375a30163114301206035504030c0b63726c2d746573742d63613082012230" &
        "0d06092a864886f70d01010105000382010f003082010a0282010100b5e60ee7058f7f9e991a038feeac5eb95d" &
        "99b6b52f543a4cf379d9b84ab68125a82424b27f07a1f6a39f6f6e5ac4df194a06d3683fafc31123427f768f60" &
        "24aa6b2d5f759d0629a578497370038d70020ea20e261a913c332504d70327b2cd747a2ae0f415764976ae21d8" &
        "c34874405cfabefd83ffc5b03de5c6521a611c333189ead8755a0bf56113ad088deb953cf1febb465a377d256b" &
        "ad055bf627727ccfffa616cfe8edc009a49f318a6c1e935dc42b69ab1d2aa9ee2173defdf45fbb595b99aced52" &
        "9fca129587fac967025980f7617070edde4748fa62cd395a608475ba22bd65c29f1fabdefe5e8aeed28baa1703" &
        "88bca8bb6490db6bacea3473ed8f0203010001a3533051301d0603551d0e04160414a1f6d41f7e7b24380aa8a0" &
        "cd33926e4452de852f301f0603551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300f06" &
        "03551d130101ff040530030101ff300d06092a864886f70d01010b050003820101005f484fd12f7d522aa3787c" &
        "0ee05c3e06067d91b3f51a3747e1ffcd7d57e839f17a9bfcf878faa9c4af435426aa06ed4907dfb9c29ca36c6b" &
        "53af27ce22516b5bd4cb19e9d912893e3800a1f7acc3abefbc18a6c899793b6ff9d378f2a77e0feb03659f8a24" &
        "09bee7a4804773be1f8428608fb9041ac74581b1943d0d90dd2939be1b74015bcd676cf483167988523fba452b" &
        "255b49146d3c5be21408d8c9848f6794a4fa588ab2d6d326bc7d92920c3547d3f4d9270c01ec4d368c98e11a61" &
        "1f40cd6672de148b3bf435f812eda7e9e5d383ff2eefcf1384d136c45b1c062f731fc3414a237cf1b971994cce" &
        "d2b6852b3f4314e9335fc96ba21fd8949c58f5c5";

      CRL_Leaf_DER : constant String :=
        "308202a53082018d02021000300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d74" &
        "6573742d6361301e170d3236303732383230313534375a170d3237303732383230313534375a301a3118301606" &
        "035504030c0f7265766f6b65642e6578616d706c6530820122300d06092a864886f70d01010105000382010f00" &
        "3082010a0282010100c0ed219d3150260bb4a5a976fd93941636a1dcdc8976321a5c82e468c74ff7e755f29a69" &
        "40524606cf7e70308e8c3ed01c6954e7e7a45fdedd1d914b6cf2459cbba0b0a2f3a248771f69301ac2735a408a" &
        "f830e03b7c3941648de0810c102c79f17da1d486a3b676993fd30102ed86ee4d4cde770d3abf8dd4b178885132" &
        "f79e8799c63595af16af350d94207d96a5d830c19e2eff9edb43607e7c8e5ba3e737b82f71937a7ca59ffcac9d" &
        "fc633aa69ce1e08aabf84a068c4e1dfa9f7ca28f959062408140c1c8cf63d66761609bc2dff8b3d4bd3250ee0a" &
        "86b507023e9f9aee80b2184c01758ffaf3c280eeeff0fb0926de9c83cfc2f327c4dcd6254a0447150203010001" &
        "300d06092a864886f70d01010b0500038201010080e42f4484be128c22efd3e63c0ea74f0efc8937b0a9529a0d" &
        "90efd502c75e3647fa117adca923af965a184fa141d74ce910ad9fbed2fb1f1eb295f9cd28ebff73c6b8ea6ace" &
        "a4d54009be31e34a52fa63c4277ebe37865d16ce20d7776ff9dbfee953305678b1dc967f59f836b6fc5ce4f166" &
        "c3e4d20a992bbdb0b2ac53f8c8a23b9176097ae12e84bcebe9e81b77da3571a2f2bcf77d7e516102c37352c1e0" &
        "fba2439d98a01280abcefe8a91b5857a2f515e6ae71c14f10fa56fb4710798b987f0a0b89a2510995a6f6cfa27" &
        "2f10d60bcd56e3add0eb664aaa565ee2471a1f5b00eae79e62e58b987db98503855bb0bd82b803d2b7ee27f40c" &
        "f62c878f5876";

      OCSP_Direct : constant String :=
        "308204de0a0100a08204d7308204d306092b0601050507300101048204c4308204c0308190a118301631143012" &
        "06035504030c0b63726c2d746573742d6361180f32303236303732383230323335385a30633061303b30090605" &
        "2b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b24380aa8a0cd3392" &
        "6e4452de852f02021000a111180f32303236303732383230313534375a180f3230323630373238323032333538" &
        "5a300d06092a864886f70d01010b05000382010100862fd17f69d414772feb68610edde88340d444547f7e017a" &
        "efab65e16849a6bd80267d5e624d5bdc87f5d6434ab54062c31f42ecaa312ad9a748c695c0d9d2e347dc540697" &
        "5ec19765aa29f2c3ba9376a21127c69294df5eb7adf737ebe67b2d68f7902a3e52a9853dcc3ef610046bf4a501" &
        "0d68c20b943c3dd04347b08a14be4b4e41c768e86784909e0d6bc36f09472ef4fb68025e5f92eecb0e9f816386" &
        "55c57d49f1b8b4931eccf246a8e342a83dd8b52ea209524956c4f3ab3ed05ca51d25fb648fb3218ee3516653d1" &
        "cf10b640ac0c3b561087977344d0a7ad93f276f89a19a8b667fd389b3650b83fe4183cf51ae996640d687a40b4" &
        "2faf4d10f5619ea0820315308203113082030d308201f5a0030201020214695a2eb222fd6509af65d97b709930" &
        "6d68b399eb300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d746573742d636130" &
        "1e170d3236303732383230313534375a170d3336303732353230313534375a30163114301206035504030c0b63" &
        "726c2d746573742d636130820122300d06092a864886f70d01010105000382010f003082010a0282010100b5e6" &
        "0ee7058f7f9e991a038feeac5eb95d99b6b52f543a4cf379d9b84ab68125a82424b27f07a1f6a39f6f6e5ac4df" &
        "194a06d3683fafc31123427f768f6024aa6b2d5f759d0629a578497370038d70020ea20e261a913c332504d703" &
        "27b2cd747a2ae0f415764976ae21d8c34874405cfabefd83ffc5b03de5c6521a611c333189ead8755a0bf56113" &
        "ad088deb953cf1febb465a377d256bad055bf627727ccfffa616cfe8edc009a49f318a6c1e935dc42b69ab1d2a" &
        "a9ee2173defdf45fbb595b99aced529fca129587fac967025980f7617070edde4748fa62cd395a608475ba22bd" &
        "65c29f1fabdefe5e8aeed28baa170388bca8bb6490db6bacea3473ed8f0203010001a3533051301d0603551d0e" &
        "04160414a1f6d41f7e7b24380aa8a0cd33926e4452de852f301f0603551d23041830168014a1f6d41f7e7b2438" &
        "0aa8a0cd33926e4452de852f300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003" &
        "820101005f484fd12f7d522aa3787c0ee05c3e06067d91b3f51a3747e1ffcd7d57e839f17a9bfcf878faa9c4af" &
        "435426aa06ed4907dfb9c29ca36c6b53af27ce22516b5bd4cb19e9d912893e3800a1f7acc3abefbc18a6c89979" &
        "3b6ff9d378f2a77e0feb03659f8a2409bee7a4804773be1f8428608fb9041ac74581b1943d0d90dd2939be1b74" &
        "015bcd676cf483167988523fba452b255b49146d3c5be21408d8c9848f6794a4fa588ab2d6d326bc7d92920c35" &
        "47d3f4d9270c01ec4d368c98e11a611f40cd6672de148b3bf435f812eda7e9e5d383ff2eefcf1384d136c45b1c" &
        "062f731fc3414a237cf1b971994cced2b6852b3f4314e9335fc96ba21fd8949c58f5c5";

      OCSP_Unauthorized : constant String :=
        "3082050c0a0100a08205053082050106092b0601050507300101048204f2308204ee308196a11e301c311a3018" &
        "06035504030c116e6f746f6373702d726573706f6e646572180f32303236303732383230323431345a30633061" &
        "303b300906052b0e03021a05000414c62b1a2f4dac7a6728a9d9bcec42380ae44dbd360414a1f6d41f7e7b2438" &
        "0aa8a0cd33926e4452de852f02021000a111180f32303236303732383230313534375a180f3230323630373238" &
        "3230323431345a300d06092a864886f70d01010b050003820101003efd3a59e9a03c2805dfbdcf26a8cd69030b" &
        "f0b8ce62077c1a1bb41fa48a7a057fce3a66620e77c8d4b94c900d60e1d571fdbe63885930bdc90c57cd70c27a" &
        "8ebf532a48e349f9815238bed4ae6c74e91c12b5d1a46b2597e88ac38b844bebbfb80e10542e0f054a74f39720" &
        "05b9161b2ce6d81e5013f0c4526695d228983d426b74771432b1407cb26e7f517ff6742a562c884c5aad5d5162" &
        "21adc1f9a277ae81b718ad0a10a55b2cbce9d76bde99f6dc9d386701574cb9273a1b1a708ca7d09eb20eea15ec" &
        "2d71b2f0abe87b2bd8ea5642cbf88fdd89d91b757bced088d1e4bca01dd9aad9fa99c8ab3d5c4c5fe2fc505360" &
        "458c7e4237a2c11f15ed7f6075a082033d30820339308203353082021da003020102021444aab1aa260bfa011e" &
        "9556a81fcac713d43514b7300d06092a864886f70d01010b050030163114301206035504030c0b63726c2d7465" &
        "73742d6361301e170d3236303732383230323431345a170d3237303732383230323431345a301c311a30180603" &
        "5504030c116e6f746f6373702d726573706f6e64657230820122300d06092a864886f70d01010105000382010f" &
        "003082010a0282010100c491c573ae839cb45ecb75d47f2ee41bc065ae9ac39fd7afd4f5cd4d7e89b400a7a79e" &
        "a43a2c43a05cb58e21d352370dc4d2956c4a709881048aafcd9e3d9c6a72aa007f6a259f43df29f8266532ae82" &
        "7cda39eeeafd679d1ceb61decd7bf001ba1678361cd24a53ce9173af7998f0498c73cf279ed10996c9bee9350b" &
        "c4137886fd8147c3402fc31447f03bffde66f34846635843750384edeeaa53aeb8b838fa8ab77f60a1f5a3e0e0" &
        "57991dd329172f19bc27db6a197ca7dd0b6ecb9b3c3455bd4c961ddb9d96ec27ee13367135de9567f041ea418f" &
        "bdb7df415504cabedbffa399a9f3a044bb9f1c0e473df09b22386d1cf2258a9b78ee21800ece10801502030100" &
        "01a375307330090603551d1304023000300e0603551d0f0101ff04040302078030160603551d250101ff040c30" &
        "0a06082b06010505070301301d0603551d0e041604146ad1ce7fdde3bfe17e9475437ce287f6a1b1f787301f06" &
        "03551d23041830168014a1f6d41f7e7b24380aa8a0cd33926e4452de852f300d06092a864886f70d01010b0500" &
        "038201010064cf0f298af11571ae94fed30d1d5d06dacd42eea12c67ff6314a8ce09022033055285288afdbe17" &
        "4c219b8353b4cf08474ad7b98d0cfe39b89786822a712cf5bcfac43ea9469c0764d8d855fd8c0e433a478f9fbf" &
        "bc44a4ae55765959d634b2049200d96b4583d4815987808a8fed6a00fd9c4bca8bbaa94b35866393bc56238e5b" &
        "e6cc4b57faf9318df531ed1ac623f546f05fc72b168174b6211f65564bebccdeb3a87332bc76c84fffe8722525" &
        "e90a24602ea7bb0c5ccc21d5190bf9ddbeee2603064d2d4f18be78400151956112375b19f87a5a09eb4a63cd12" &
        "8dc20797b0fcf9cd0ab02d7b3aa89591c00bfd50b2006b51bd6aab88bd9eebc1f91109b0";

      function From_Hex
        (Text : String) return Ada.Streams.Stream_Element_Array
      is
         Result : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Text'Length / 2));
         function Nibble (C : Character) return Natural
         is (case C is
                when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
                when others     => Character'Pos (C) - Character'Pos ('a') + 10);
      begin
         for I in Result'Range loop
            Result (I) :=
              Ada.Streams.Stream_Element
                (Nibble (Text (Text'First + 2 * Natural (I - 1))) * 16
                 + Nibble (Text (Text'First + 2 * Natural (I - 1) + 1)));
         end loop;
         return Result;
      end From_Hex;

      Status : CryptoLib.ASN1.Errors.Decode_Status;

      CA : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (CRL_CA_DER), CryptoLib.ASN1.Default_Limits, Status);
      Leaf : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (CRL_Leaf_DER), CryptoLib.ASN1.Default_Limits, Status);
      List : constant CryptoLib.X509.CRLs.Revocation_List :=
        CryptoLib.X509.CRLs.Decode_DER
          (From_Hex (CRL_DER), CryptoLib.ASN1.Default_Limits, Status);

      --  The CRL was issued in July 2026 and is due to be replaced a month
      --  later, so these three times sit before, inside and after its window.
      Before : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 1, Day => 1,
         Hour => 0, Minute => 0, Second => 0);
      Inside : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 8, Day => 1,
         Hour => 0, Minute => 0, Second => 0);
      After  : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2027, Month => 1, Day => 1,
         Hour => 0, Minute => 0, Second => 0);
   begin
      Check (X509C.Is_Present (CA) and then X509C.Is_Present (Leaf),
             "fixture: the certificates decode");

      --  Inside the window, the list revokes the certificate it revoked.
      Check (XR.Check_Against_CRL (Leaf, CA, List, Inside) = XR.Revoked,
             "a current list reports the revoked certificate, got "
             & XR.Answer_Image (XR.Check_Against_CRL (Leaf, CA, List, Inside)));

      --  Outside it, the list says nothing about now -- in either direction.
      Check (XR.Check_Against_CRL (Leaf, CA, List, Before) = XR.Stale,
             "a list issued after the time asked about is stale, got "
             & XR.Answer_Image (XR.Check_Against_CRL (Leaf, CA, List, Before)));
      Check (XR.Check_Against_CRL (Leaf, CA, List, After) = XR.Stale,
             "a list past its nextUpdate is stale, got "
             & XR.Answer_Image (XR.Check_Against_CRL (Leaf, CA, List, After)));

      --  A list about another issuer's certificates says nothing about this
      --  one, however well it is signed.
      Check (XR.Check_Against_CRL (CA, Leaf, List, Inside) = XR.Wrong_Issuer,
             "a list is refused for a certificate whose issuer it is not "
             & "about, got "
             & XR.Answer_Image (XR.Check_Against_CRL (CA, Leaf, List, Inside)));

      --  And the OCSP responses, which carry their own window.
      declare
         Direct : CryptoLib.OCSP.Response :=
           CryptoLib.OCSP.Decode_Response
             (From_Hex (OCSP_Direct), CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (XR.Check_Against_OCSP (Leaf, CA, Direct, Inside) = XR.Revoked,
                "a current response reports the revoked certificate, got "
                & XR.Answer_Image
                    (XR.Check_Against_OCSP (Leaf, CA, Direct, Inside)));
      end;

      declare
         Direct : CryptoLib.OCSP.Response :=
           CryptoLib.OCSP.Decode_Response
             (From_Hex (OCSP_Direct), CryptoLib.ASN1.Default_Limits, Status);
      begin
         Check (XR.Check_Against_OCSP (Leaf, CA, Direct, Before) = XR.Stale,
                "a response from after the time asked about is stale");
      end;

      --  A responder the issuer never authorised is not an answer at all.
      declare
         Rogue : CryptoLib.OCSP.Response :=
           CryptoLib.OCSP.Decode_Response
             (From_Hex (OCSP_Unauthorized), CryptoLib.ASN1.Default_Limits,
              Status);
      begin
         Check (XR.Check_Against_OCSP (Leaf, CA, Rogue, Inside)
                  = XR.Untrusted_Signature,
                "an unauthorized responder's answer is not trusted, got "
                & XR.Answer_Image
                    (XR.Check_Against_OCSP (Leaf, CA, Rogue, Inside)));
      end;
   end Check_Revocation;

   --  AUnit routine wrappers. Each check is a test of its own, so a
   --  failure reports the check that failed and the rest still run.
   procedure Run_Check_X509_CRL (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Revocation_Details (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_OCSP (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Revocation (Item : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Check_X509_CRL (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_X509_CRL;
   end Run_Check_X509_CRL;

   procedure Run_Check_Revocation_Details (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Revocation_Details;
   end Run_Check_Revocation_Details;

   procedure Run_Check_OCSP (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_OCSP;
   end Run_Check_OCSP;

   procedure Run_Check_Revocation (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Revocation;
   end Run_Check_Revocation;

   overriding procedure Register_Tests (Item : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (Item, Run_Check_X509_CRL'Access, "x509 crl");
      Register_Routine (Item, Run_Check_Revocation_Details'Access, "revocation details");
      Register_Routine (Item, Run_Check_OCSP'Access, "ocsp");
      Register_Routine (Item, Run_Check_Revocation'Access, "revocation");
   end Register_Tests;

   overriding function Name (Item : Test_Case) return AUnit.Message_String is
      pragma Unreferenced (Item);
   begin
      return AUnit.Format ("cryptolib X.509 revocation");
   end Name;

end Tests_X509_Revocation;
