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

package body Tests_X509_Policies is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Certificates.Certificate_Status;
   use type Interfaces.Unsigned_32;

   --  RFC 5280 section 6.1 policy processing.
   --
   --  A policy identifier on its own asserts something and restricts nothing.
   --  What gives it teeth is policyConstraints, which can demand that every
   --  certificate below it name an acceptable policy; policyMappings, which
   --  lets one CA declare its policy equivalent to another's; and
   --  inhibitAnyPolicy, which withdraws the wildcard. This crate used to
   --  refuse any chain carrying the first or third of those, which was
   --  correct and useless.
   --
   --  Every verdict below was taken from OpenSSL first, with
   --  `openssl verify -policy_check -policy 1.3.6.1.4.1.99999.1`, and this
   --  agrees with it on all of them.
   procedure Check_Policy_Processing is
      package X509C renames CryptoLib.X509.Certificates;
      package XV renames CryptoLib.X509.Validation;
      use type XV.Validation_Failure;

      Pol_Root_DER : constant String :=
        "308201c63082014ba00302010202145727441835ad76033727ea6b84f515747f3320c2300a06082a8648ce3d04" &
        "030230163114301206035504030c0b706f6c6963792d726f6f74301e170d3236303732393033343234335a170d" &
        "3237303532353033343234335a30163114301206035504030c0b706f6c6963792d726f6f743076301006072a86" &
        "48ce3d020106052b8104002203620004fab57ef5a1788133397062176d5925a43cd8595df917f6743c6323355d" &
        "2658e3173fce28a87905f80b9ba83ee1aab697a7bb599368c751864a56fbaa711e5b2726530bc20c83714e3ce3" &
        "718536a74005d731b1489eb8e166434548c44d69b0cfa35a3058300f0603551d130101ff040530030101ff300e" &
        "0603551d0f0101ff04040302010630160603551d20040f300d300b06092b06010401868d1f01301d0603551d0e" &
        "04160414208a7da7f801c4b3c24c5dea13986578cbec0ed6300a06082a8648ce3d040302036900306602310093" &
        "4dbbfa5f698b9aaa2a6349fed0bae3572c3a3fcf09da057a05046c6724f4d40d3e1c36dccecaab036b60672925" &
        "bced023100d96d24eef7e88ed6c3c434743d79d0619f1b54a3bf01ef831d4bef08264efa2a9d989132170c7443" &
        "fcacbe2bb70aee19";

      Pol_Inter_Req_DER : constant String :=
        "308201e53082016ca003020102020111300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343234335a170d3237303532353033343234335a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b8104002203620004e15b58" &
        "46a5c5aa4118c74841b2a4d1cac4c19fcf8b7a326c793b925c6b3e812064cfc41d80da3fe58efa95f36268c9e4" &
        "92ce3f8cd6ad4c07c73320b34b892361a8182b17e63dbc1f53b9b51c559e6730b855011c68eeaa084cac7a4ed5" &
        "2fd898a3818d30818a300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301606" &
        "03551d20040f300d300b06092b06010401868d1f01300f0603551d240101ff04053003800100301d0603551d0e" &
        "041604144a97461dd73c54c4d02a3f0b416a6afc6d0f8e32301f0603551d23041830168014208a7da7f801c4b3" &
        "c24c5dea13986578cbec0ed6300a06082a8648ce3d040302036700306402300a2dfefe083b5e9d75967003b81a" &
        "ba7d546b7834cc7c300881cabe6fe8dec7fece25dcae0366c2f70b9222c290603f70023059ec3865ccd17af7a8" &
        "bc2af98ea4e35513ea24490494f49cc110096c3a8bee972151c7e4d17a7387329f33890c9c02eb";

      Pol_Inter_Plain_DER : constant String :=
        "308201d330820159a003020102020112300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343234335a170d3237303532353033343234335a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b8104002203620004e15b58" &
        "46a5c5aa4118c74841b2a4d1cac4c19fcf8b7a326c793b925c6b3e812064cfc41d80da3fe58efa95f36268c9e4" &
        "92ce3f8cd6ad4c07c73320b34b892361a8182b17e63dbc1f53b9b51c559e6730b855011c68eeaa084cac7a4ed5" &
        "2fd898a37b3079300f0603551d130101ff040530030101ff300e0603551d0f0101ff0404030201063016060355" &
        "1d20040f300d300b06092b06010401868d1f01301d0603551d0e041604144a97461dd73c54c4d02a3f0b416a6a" &
        "fc6d0f8e32301f0603551d23041830168014208a7da7f801c4b3c24c5dea13986578cbec0ed6300a06082a8648" &
        "ce3d040302036800306502307145f1818ae7ef3193b94efdd67dd25ed927f59caa1e8b35e903c94d57318782f6" &
        "89872eb16daba58026fb82533bca3d023100dd8dcffad0f4b8fee4cf608dc1329619253245e550556568450970" &
        "d2a72a37fb798b9b773a0346ede88c91839bc4e712";

      Pol_Inter_Inhibit_DER : constant String :=
        "308201f53082017ba003020102020113300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343432395a170d3237303532353033343432395a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b8104002203620004e15b58" &
        "46a5c5aa4118c74841b2a4d1cac4c19fcf8b7a326c793b925c6b3e812064cfc41d80da3fe58efa95f36268c9e4" &
        "92ce3f8cd6ad4c07c73320b34b892361a8182b17e63dbc1f53b9b51c559e6730b855011c68eeaa084cac7a4ed5" &
        "2fd898a3819c308199300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301606" &
        "03551d20040f300d300b06092b06010401868d1f01300f0603551d240101ff04053003800100300d0603551d36" &
        "0101ff0403020100301d0603551d0e041604144a97461dd73c54c4d02a3f0b416a6afc6d0f8e32301f0603551d" &
        "23041830168014208a7da7f801c4b3c24c5dea13986578cbec0ed6300a06082a8648ce3d040302036800306502" &
        "3100c3b2fb9c7bd0488f4356ba5761f3a79b98e533779f8c2014d0c62891393eda71ed5d84e3e7565bd889fb85" &
        "cfddfd320302307dc6d4f4d3254b9276b1a0459729f6bd6eb558083b79d0c9a8a9b71c56d794078ea20685dc68" &
        "fd87c10ed979f527a6e5";

      Pol_Inter_Map_DER : constant String :=
        "308202093082018fa003020102020114300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343432395a170d3237303532353033343432395a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b8104002203620004e15b58" &
        "46a5c5aa4118c74841b2a4d1cac4c19fcf8b7a326c793b925c6b3e812064cfc41d80da3fe58efa95f36268c9e4" &
        "92ce3f8cd6ad4c07c73320b34b892361a8182b17e63dbc1f53b9b51c559e6730b855011c68eeaa084cac7a4ed5" &
        "2fd898a381b03081ad300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301606" &
        "03551d20040f300d300b06092b06010401868d1f01300f0603551d240101ff0405300380010030210603551d21" &
        "041a3018301606092b06010401868d1f0106092b0601040185b63801301d0603551d0e041604144a97461dd73c" &
        "54c4d02a3f0b416a6afc6d0f8e32301f0603551d23041830168014208a7da7f801c4b3c24c5dea13986578cbec" &
        "0ed6300a06082a8648ce3d0403020368003065023100de613a955ab42e1fb759f2cd1aec7951a15bc5aa8a8744" &
        "3cee4921af808dbe73a7661d0a5f668e02f1ff650d68cc319d023071f25589438e722d60ebddc7d72430ebc2fe" &
        "aa6719b84bc9929fdeb215be9168a99e4421eab72e6dd4de561b20532856";

      Pol_Inter_Map_Crit_DER : constant String :=
        "3082020c30820192a003020102020116300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393037333131365a170d3237303532353037333131365a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b8104002203620004e15b58" &
        "46a5c5aa4118c74841b2a4d1cac4c19fcf8b7a326c793b925c6b3e812064cfc41d80da3fe58efa95f36268c9e4" &
        "92ce3f8cd6ad4c07c73320b34b892361a8182b17e63dbc1f53b9b51c559e6730b855011c68eeaa084cac7a4ed5" &
        "2fd898a381b33081b0300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301606" &
        "03551d20040f300d300b06092b06010401868d1f01300f0603551d240101ff0405300380010030240603551d21" &
        "0101ff041a3018301606092b06010401868d1f0106092b0601040185b63801301d0603551d0e041604144a9746" &
        "1dd73c54c4d02a3f0b416a6afc6d0f8e32301f0603551d23041830168014208a7da7f801c4b3c24c5dea139865" &
        "78cbec0ed6300a06082a8648ce3d0403020368003065023100a076113b47ae93935aa562ab406922d6abed781f" &
        "f0a9ae4c1e2f3d60b23918186f034cba5cbae52ef78df2ace923903b023072e20017edaaa6a03f68413faf7639" &
        "5e4feb6edd171fe0b30f75d112a2fbbd552cd293496d4cb53b5416643392c50c98";

      Pol_Leaf_Policy_DER : constant String :=
        "308201c130820146a003020102020121300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343234335a170d3237303532353033343234335a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b81040022036200043402ce" &
        "6ccea70ea36eb8521e2007faa5beb6e7c3806e6fa37fa5327cb5d3f557feca8c0d8d241091a0ea74e4c0732957" &
        "40bfbfc075897e4da948d1cc6c167840e84238120e8cb80affde05c989c869103e6b1baa065634d40307e610b8" &
        "593fe8a3683066300c0603551d130101ff0402300030160603551d20040f300d300b06092b06010401868d1f01" &
        "301d0603551d0e04160414384bc3b7f08c0a2ad3fc513ff2bec55b1ba8efb2301f0603551d230418301680144a" &
        "97461dd73c54c4d02a3f0b416a6afc6d0f8e32300a06082a8648ce3d04030203690030660231009cf61f07f09c" &
        "8bacb47ca0be767c341452c2032533a6b22b3efc9e002c7d2d11e85eff4d166d392b9f1b6d38db1b7f71023100" &
        "fc4f717bc35b622f8c94e6b6fcea42adf6867f73f35cc262ebe57ed5790e3f42d8daea529862214ec14392f312" &
        "e30b28";

      Pol_Leaf_Other_DER : constant String :=
        "308201c130820146a003020102020121300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343234335a170d3237303532353033343234335a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b81040022036200043402ce" &
        "6ccea70ea36eb8521e2007faa5beb6e7c3806e6fa37fa5327cb5d3f557feca8c0d8d241091a0ea74e4c0732957" &
        "40bfbfc075897e4da948d1cc6c167840e84238120e8cb80affde05c989c869103e6b1baa065634d40307e610b8" &
        "593fe8a3683066300c0603551d130101ff0402300030160603551d20040f300d300b06092b0601040184df5109" &
        "301d0603551d0e04160414384bc3b7f08c0a2ad3fc513ff2bec55b1ba8efb2301f0603551d230418301680144a" &
        "97461dd73c54c4d02a3f0b416a6afc6d0f8e32300a06082a8648ce3d04030203690030660231009968df9936d9" &
        "412143d1b60b2b6b971a6aafc2ae3beeb1065590e1a6b2a5052448ca815b7e798b4eb80f95cb0db95afa023100" &
        "93358650650df7b7736b87dee1ff633b891fba4cfd35193edec3b902299b1fe03eb6e3de21044c271ed4a66766" &
        "d78bac";

      Pol_Leaf_None_DER : constant String :=
        "308201a83082012ea003020102020121300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343234335a170d3237303532353033343234335a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b81040022036200043402ce" &
        "6ccea70ea36eb8521e2007faa5beb6e7c3806e6fa37fa5327cb5d3f557feca8c0d8d241091a0ea74e4c0732957" &
        "40bfbfc075897e4da948d1cc6c167840e84238120e8cb80affde05c989c869103e6b1baa065634d40307e610b8" &
        "593fe8a350304e300c0603551d130101ff04023000301d0603551d0e04160414384bc3b7f08c0a2ad3fc513ff2" &
        "bec55b1ba8efb2301f0603551d230418301680144a97461dd73c54c4d02a3f0b416a6afc6d0f8e32300a06082a" &
        "8648ce3d040302036800306502310086e66099b0cda06383ed72776cb553ec367361e5cc528ca35c7018aedad7" &
        "11f8ce39e5d4d6cf42b1d6f3ae94b327562e023068e4d658e2b643601e5682fad634ae5b82df926e3c7ed1f89e" &
        "c31f435721d06ac80296c50dc5c9b3135dd1863d35d48a";

      Pol_Leaf_Any_DER : constant String :=
        "308201bb30820141a003020102020141300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343432395a170d3237303532353033343432395a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b81040022036200043402ce" &
        "6ccea70ea36eb8521e2007faa5beb6e7c3806e6fa37fa5327cb5d3f557feca8c0d8d241091a0ea74e4c0732957" &
        "40bfbfc075897e4da948d1cc6c167840e84238120e8cb80affde05c989c869103e6b1baa065634d40307e610b8" &
        "593fe8a3633061300c0603551d130101ff0402300030110603551d20040a300830060604551d2000301d060355" &
        "1d0e04160414384bc3b7f08c0a2ad3fc513ff2bec55b1ba8efb2301f0603551d230418301680144a97461dd73c" &
        "54c4d02a3f0b416a6afc6d0f8e32300a06082a8648ce3d0403020368003065023100ce186b844eba08a3db51bc" &
        "0941f289c9dfa619b402d4bd67dfc3520a95c21da82d347292ebddb3c1a6b5e336aa5f3956023048372cefb703" &
        "f4314103946d7bf88e48a26a926adb447bee23e45c2ecb0af47fdae1467e3f0379160167a585854db4ba";

      Pol_Leaf_Mapped_DER : constant String :=
        "308201c130820146a003020102020141300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343432395a170d3237303532353033343432395a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b81040022036200043402ce" &
        "6ccea70ea36eb8521e2007faa5beb6e7c3806e6fa37fa5327cb5d3f557feca8c0d8d241091a0ea74e4c0732957" &
        "40bfbfc075897e4da948d1cc6c167840e84238120e8cb80affde05c989c869103e6b1baa065634d40307e610b8" &
        "593fe8a3683066300c0603551d130101ff0402300030160603551d20040f300d300b06092b0601040185b63801" &
        "301d0603551d0e04160414384bc3b7f08c0a2ad3fc513ff2bec55b1ba8efb2301f0603551d230418301680144a" &
        "97461dd73c54c4d02a3f0b416a6afc6d0f8e32300a06082a8648ce3d0403020369003066023100ee90c48ae9b6" &
        "5209c5242f56cd53e58e17e11ddefd40199f52ded1f32134f53b11ba13ca407435b5e520245043a5f931023100" &
        "cc68368691849c6e3e5dc53902fd817f79a2b95e2bf1546184f1c80b71b6b74fe800fcaecbb79a20f4cf22f6e8" &
        "e725b7";

      Pol_Leaf_None_Plain_DER : constant String :=
        "308201a83082012ea003020102020131300a06082a8648ce3d04030230163114301206035504030c0b706f6c69" &
        "63792d726f6f74301e170d3236303732393033343331325a170d3237303532353033343331325a301631143012" &
        "06035504030c0b706f6c6963792d726f6f743076301006072a8648ce3d020106052b81040022036200043402ce" &
        "6ccea70ea36eb8521e2007faa5beb6e7c3806e6fa37fa5327cb5d3f557feca8c0d8d241091a0ea74e4c0732957" &
        "40bfbfc075897e4da948d1cc6c167840e84238120e8cb80affde05c989c869103e6b1baa065634d40307e610b8" &
        "593fe8a350304e300c0603551d130101ff04023000301d0603551d0e04160414384bc3b7f08c0a2ad3fc513ff2" &
        "bec55b1ba8efb2301f0603551d230418301680144a97461dd73c54c4d02a3f0b416a6afc6d0f8e32300a06082a" &
        "8648ce3d04030203680030650230036d5757d235d4fe32e612750bbeb248c84f198aa1cba7b6356ab90f967813" &
        "f34484c5623e35449db518c535d2ba387f02310082d568ddeb7909e66d44ff7f1f000079835b0cb96226ecd19b" &
        "fef5c1977bf5ffb01f82ab7ef3b5a9149431a0d21f1b4b";

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

      function Decoded (Hex : String) return X509C.Certificate
      is (X509C.Decode_DER
            (From_Hex (Hex), CryptoLib.ASN1.Default_Limits, Status));

      type Which_Inter is (Req, Plain, Inhibit, Map, Map_Critical);
      type Which_Leaf is (With_Policy, Other_Policy, No_Policy, Any, Mapped,
                          None_Plain);

      type Chain (Inter : Which_Inter; Leaf : Which_Leaf) is
        limited new XV.Path_Source with null record;

      overriding function Length (Source : Chain) return Positive is (3);

      overriding function Certificate_At
        (Source : Chain; Index : Positive) return X509C.Certificate
      is (case Index is
             when 1 =>
               (case Source.Leaf is
                   when With_Policy  => Decoded (Pol_Leaf_Policy_DER),
                   when Other_Policy => Decoded (Pol_Leaf_Other_DER),
                   when No_Policy    => Decoded (Pol_Leaf_None_DER),
                   when Any          => Decoded (Pol_Leaf_Any_DER),
                   when Mapped       => Decoded (Pol_Leaf_Mapped_DER),
                   when None_Plain   => Decoded (Pol_Leaf_None_Plain_DER)),
             when 2 =>
               (case Source.Inter is
                   when Req     => Decoded (Pol_Inter_Req_DER),
                   when Plain   => Decoded (Pol_Inter_Plain_DER),
                   when Inhibit => Decoded (Pol_Inter_Inhibit_DER),
                   when Map     => Decoded (Pol_Inter_Map_DER),
                   when Map_Critical =>
                     Decoded (Pol_Inter_Map_Crit_DER)),
             when others => Decoded (Pol_Root_DER));

      overriding function Is_Trust_Anchor
        (Source : Chain; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Bytes (Item)
          = X509C.Subject_Bytes (Decoded (Pol_Root_DER)));

      At_Time : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 9, Day => 1,
         Hour => 12, Minute => 0, Second => 0);

      function Verdict (Inter : Which_Inter; Leaf : Which_Leaf)
        return XV.Validation_Result
      is (XV.Validate_Path (Chain'(Inter => Inter, Leaf => Leaf), At_Time));
   begin
      --  The control: a chain whose intermediate demands nothing, and a leaf
      --  that names no policy. Without it the refusals below would be
      --  consistent with the chain being broken for some other reason.
      Check (Verdict (Plain, None_Plain).Valid,
             "a chain that demands no policy validates: "
             & XV.Failure_Image (Verdict (Plain, None_Plain).Failure));

      --  requireExplicitPolicy on the intermediate: from here down, every
      --  certificate must name a policy that survives to the leaf.
      Check (Verdict (Req, With_Policy).Valid,
             "a leaf naming the policy its issuer granted validates: "
             & XV.Failure_Image (Verdict (Req, With_Policy).Failure));
      Check (Verdict (Req, With_Policy).Policies.Count = 1,
             "and the policy it establishes is reported, got"
             & Natural'Image (Verdict (Req, With_Policy).Policies.Count));

      --  A policy nobody above it granted is not a policy. This is the
      --  check: the leaf asserts something, and the assertion is worth
      --  nothing because no issuer in the path allowed it.
      Check (not Verdict (Req, Other_Policy).Valid
             and then Verdict (Req, Other_Policy).Failure
                      = XV.Policy_Not_Established,
             "a leaf naming a policy its issuers never granted is refused, "
             & "got " & XV.Failure_Image (Verdict (Req, Other_Policy).Failure));
      Check (not Verdict (Req, No_Policy).Valid,
             "and so is one naming none at all");

      --  anyPolicy satisfies the demand, until a certificate withdraws it.
      Check (Verdict (Req, Any).Valid,
             "anyPolicy satisfies an explicit-policy requirement: "
             & XV.Failure_Image (Verdict (Req, Any).Failure));
      Check (not Verdict (Inhibit, Any).Valid
             and then Verdict (Inhibit, Any).Failure
                      = XV.Policy_Not_Established,
             "unless inhibitAnyPolicy withdrew it, got "
             & XV.Failure_Image (Verdict (Inhibit, Any).Failure));

      --  policyMappings: the intermediate declares its issuer's policy
      --  equivalent to one of its own, and a leaf naming the mapped policy
      --  is then reachable from the root's.
      Check (Verdict (Map, Mapped).Valid,
             "a mapped policy carries through: "
             & XV.Failure_Image (Verdict (Map, Mapped).Failure));
      Check (not Verdict (Map, With_Policy).Valid,
             "and the unmapped one no longer does, because mapping replaced "
             & "what the issuer expects rather than adding to it");

      --  RFC 5280 4.2.1.5 says a conforming CA SHOULD mark policyMappings
      --  critical, so refusing a certificate that does is refusing what the
      --  specification asks for. This crate processes the extension, which
      --  is what entitles it to recognise it: the rule is that an extension
      --  is honoured or the certificate is refused, and honouring it while
      --  leaving it off the recognised list fails certificates for carrying
      --  something that was acted on anyway.
      Check (Verdict (Map_Critical, Mapped).Valid,
             "a critical policyMappings is honoured rather than refused: "
             & XV.Failure_Image (Verdict (Map_Critical, Mapped).Failure));
      Check (not Verdict (Map_Critical, With_Policy).Valid,
             "and it maps, so the unmapped policy no longer reaches the leaf");

      --  The caller's own policy set: RFC 5280's user-initial-policy-set.
      declare
         package PP renames CryptoLib.X509.Policies;

         function Only (Encoded : String) return PP.Accepted_Policies is
            Result : PP.Accepted_Policies := PP.Accept_Any;
         begin
            Result.Count := 1;
            Result.Values (1) := PP.To_Policy (From_Hex (Encoded));
            return Result;
         end Only;

         function Asking (Encoded : String; Leaf : Which_Leaf)
           return XV.Validation_Result
         is (XV.Validate_Path
               (Chain'(Inter => Req, Leaf => Leaf), At_Time,
                (XV.Default_Policy with delta
                   Accepted_Policies => Only (Encoded))));

         Wanted : constant String := "2b06010401868d1f01";
         Other  : constant String := "2b0601040184df5109";
      begin
         Check (Asking (Wanted, With_Policy).Valid,
                "a caller asking for the policy the chain establishes is "
                & "satisfied: "
                & XV.Failure_Image (Asking (Wanted, With_Policy).Failure));

         --  The chain is exactly as valid as before; what changed is what
         --  the caller will accept from it.
         Check (not Asking (Other, With_Policy).Valid
                and then Asking (Other, With_Policy).Failure
                         = XV.Policy_Not_Established,
                "and one asking for a policy it does not is refused, got "
                & XV.Failure_Image (Asking (Other, With_Policy).Failure));

         --  The caller's set is read in the trust anchor's policy domain,
         --  not the leaf's, and a mapping is what connects the two. Asking
         --  for the policy the anchor granted must therefore be satisfied by
         --  a leaf asserting what that policy was mapped to.
         --
         --  Filtering every node against the caller's set breaks exactly
         --  this: the leaf's node names the subject-domain policy, which is
         --  not what was asked for, and deleting it rejects the chain that
         --  policy mapping exists to allow. Section 6.1.5 (g)(iii) matches
         --  only nodes whose parent is anyPolicy for that reason.
         declare
            function Through_Map (Encoded : String)
              return XV.Validation_Result
            is (XV.Validate_Path
                  (Chain'(Inter => Map, Leaf => Mapped), At_Time,
                   (XV.Default_Policy with delta
                      Accepted_Policies => Only (Encoded))));

            Anchor_Policy  : constant String := "2b06010401868d1f01";
            Subject_Policy : constant String := "2b0601040185b63801";
         begin
            Check (Through_Map (Anchor_Policy).Valid,
                   "a mapped chain satisfies a caller asking for the policy "
                   & "the anchor granted, got "
                   & XV.Failure_Image (Through_Map (Anchor_Policy).Failure));

            --  And not the other way round: what the leaf asserts is in the
            --  subject's domain, which is not the domain the caller spoke in.
            Check (not Through_Map (Subject_Policy).Valid,
                   "and not one asking for the policy it was mapped to");
         end;
      end;
   end Check_Policy_Processing;

   --  What a policy says to a person reading it.
   --
   --  RFC 5280 4.2.1.4 defines two qualifiers: a pointer to the issuer's
   --  certification practice statement, and a notice meant to be displayed.
   --  Neither changes whether a policy applies -- section 6.1 never consults
   --  them -- so they are read for a caller that wants to show why a
   --  certificate claims what it claims. They were parsed past and dropped.
   procedure Check_Policy_Qualifiers is
      use type CryptoLib.ASN1.Errors.Decode_Status;
      use type CryptoLib.X509.Policies.Qualifier_Kind;

      package X509C renames CryptoLib.X509.Certificates;
      package PP renames CryptoLib.X509.Policies;

      Long_Qualifier_DER : constant String :=
        "308203083082028fa00302010202147772a1c377955a4de366da5b5b9c5d8ecc91244a300a06082a8648ce3d04" &
        "030230163114301206035504030c0b706f6c6963792d726f6f74301e170d3236303732393038303635335a170d" &
        "3237303532353038303635335a30163114301206035504030c0b706f6c6963792d726f6f743076301006072a86" &
        "48ce3d020106052b8104002203620004fab57ef5a1788133397062176d5925a43cd8595df917f6743c6323355d" &
        "2658e3173fce28a87905f80b9ba83ee1aab697a7bb599368c751864a56fbaa711e5b2726530bc20c83714e3ce3" &
        "718536a74005d731b1489eb8e166434548c44d69b0cfa382019c30820198300f0603551d130101ff0405300301" &
        "01ff300e0603551d0f0101ff040403020106308201540603551d200482014b308201473082014306092b060104" &
        "01868d1f01308201343082013006082b060105050702011682012268747470733a2f2f6578616d706c652e7465" &
        "73742f6370732f6161616161616161616161616161616161616161616161616161616161616161616161616161" &
        "616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" &
        "616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" &
        "616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" &
        "616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" &
        "6161616161616161616161616161616161616161616161616161616161616161616161616161616161612e6874" &
        "6d6c301d0603551d0e04160414208a7da7f801c4b3c24c5dea13986578cbec0ed6300a06082a8648ce3d040302" &
        "0367003064023060ce4e4b4f493390e21e8e77d05a9860bd3ffd028886b585b10c6b39ddced4e8f20d3d19b9fe" &
        "d21c19c041fe9f3bcda202307bccdcf85917ebc87ebdbcbfa60266b0604aa61ea0bbd8af9035b72e6d3e1b9996" &
        "2e1a61953c62a96fdbd0d07dbaf9f2";

      Qualified_DER : constant String :=
        "30820249308201cea003020102021457dc68c06a8727f75fca6853854da359d207b6fc300a06082a8648ce3d04" &
        "030230163114301206035504030c0b706f6c6963792d726f6f74301e170d3236303732393037343631385a170d" &
        "3237303532353037343631385a30163114301206035504030c0b706f6c6963792d726f6f743076301006072a86" &
        "48ce3d020106052b8104002203620004fab57ef5a1788133397062176d5925a43cd8595df917f6743c6323355d" &
        "2658e3173fce28a87905f80b9ba83ee1aab697a7bb599368c751864a56fbaa711e5b2726530bc20c83714e3ce3" &
        "718536a74005d731b1489eb8e166434548c44d69b0cfa381dc3081d9300f0603551d130101ff040530030101ff" &
        "300e0603551d0f0101ff0404030201063081960603551d2004818e30818b30818806092b06010401868d1f0130" &
        "7b302906082b06010505070201161d68747470733a2f2f6578616d706c652e746573742f6370732e68746d6c30" &
        "4e06082b060105050702023042301a1a104578616d706c652054657374204f726730060201010201021a244973" &
        "7375656420756e64657220746865206578616d706c65207465737420706f6c696379301d0603551d0e04160414" &
        "208a7da7f801c4b3c24c5dea13986578cbec0ed6300a06082a8648ce3d0403020369003066023100d3a5eb9ed0" &
        "6bc532ebf2da5d489183d0d4f082690d1e888f8ea954e0594b77d2a9d2494c620bc7665fec33b9f48809510231" &
        "00e86ff2b3713b9ba9a632c6a0fa424829c0548fee20becea5932b0f3e759885375e1feb99b0a882cd62789cfe" &
        "ea02f666";

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
      Item   : constant X509C.Certificate :=
        X509C.Decode_DER
          (From_Hex (Qualified_DER), CryptoLib.ASN1.Default_Limits, Status);
      Named  : constant PP.Policy_Set := PP.Policies_Of (Item);
   begin
      Check (Status = CryptoLib.ASN1.Errors.Ok
             and then Named.Well_Formed
             and then Named.Count = 1,
             "a certificate with a qualified policy decodes");

      --  Both kinds, in the order the certificate carries them.
      Check (Named.Entries (1).Qualifier_Count = 2,
             "both qualifiers are read, got"
             & Natural'Image (Named.Entries (1).Qualifier_Count));

      Check (Named.Entries (1).Qualifiers (1).Kind = PP.CPS_Uri,
             "the first is a practice-statement pointer");
      Check (Named.Entries (1).Qualifiers (1).Text
               (1 .. Named.Entries (1).Qualifiers (1).Length)
             = "https://example.test/cps.html",
             "and it is the URI the certificate carries, got ["
             & Named.Entries (1).Qualifiers (1).Text
                 (1 .. Named.Entries (1).Qualifiers (1).Length) & "]");

      --  A user notice holds an organisation and a list of numbers as well
      --  as the text. The numbers mean something only to whoever published
      --  them; the explicit text is the part written to be read, and it is
      --  the part taken.
      Check (Named.Entries (1).Qualifiers (2).Kind = PP.User_Notice,
             "the second is a notice");
      Check (Named.Entries (1).Qualifiers (2).Text
               (1 .. Named.Entries (1).Qualifiers (2).Length)
             = "Issued under the example test policy",
             "and its explicit text is taken rather than its notice "
             & "reference, got ["
             & Named.Entries (1).Qualifiers (2).Text
                 (1 .. Named.Entries (1).Qualifiers (2).Length) & "]");

      Check (not Named.Entries (1).Qualifiers (1).Truncated
             and then not Named.Entries (1).Qualifiers (2).Truncated,
             "neither was truncated");

      --  A qualifier longer than this can hold. RFC 5280 bounds DisplayText
      --  at 200 characters and says nothing about the length of a CPS URI,
      --  so a certificate carrying a long one is not malformed and must not
      --  be read as though the bound were a promise about the input.
      declare
         Long_Item : constant X509C.Certificate :=
           X509C.Decode_DER
             (From_Hex (Long_Qualifier_DER), CryptoLib.ASN1.Default_Limits,
              Status);
         Long_Set  : constant PP.Policy_Set := PP.Policies_Of (Long_Item);
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok
                and then Long_Set.Well_Formed
                and then Long_Set.Entries (1).Qualifier_Count = 1,
                "a certificate with an over-long qualifier still decodes");
         Check (Long_Set.Entries (1).Qualifiers (1).Truncated,
                "and says the text was cut rather than pretending it fit");
         Check (Long_Set.Entries (1).Qualifiers (1).Length
                = PP.Maximum_Qualifier_Text,
                "keeping what it can, got"
                & Natural'Image (Long_Set.Entries (1).Qualifiers (1).Length));
      end;
   end Check_Policy_Qualifiers;

   --  The search skips a path that cannot carry the policies.
   --
   --  Path building already verifies signatures as it goes rather than
   --  trusting a name match, because two certificates can share a subject
   --  name and not a key. Policies are the same shape of problem one level
   --  up: two certificates can share a subject name AND a key, and grant
   --  different policies, which is what cross-signing produces. Taking the
   --  first anchor reached proposes a path the validator then refuses, while
   --  a path that works sits unexamined in the pool.
   --
   --  Both intermediates here have the same subject and the same key, so
   --  both verify the leaf and neither can be told from the other by
   --  signature. They differ only in the policy they grant.
   procedure Check_Policy_Aware_Path_Building is
      package X509C renames CryptoLib.X509.Certificates;
      package PB renames CryptoLib.X509.Path_Building;
      package XV renames CryptoLib.X509.Validation;

      PB_Leaf_DER : constant String :=
        "308201c93082014fa003020102020161300a06082a8648ce3d040302301e311c301a06035504030c1373686172" &
        "65642d696e7465726d656469617465301e170d3236303732393037353430385a170d3237303532353037353430" &
        "385a30173115301306035504030c0c686f73742e6578616d706c653076301006072a8648ce3d020106052b8104" &
        "002203620004f87d3963719d77f4c81524657c92199180906b54fc56ff2c848be3b67a0481de7db8684546488b" &
        "03763c375c507a6cfa64daa5f9f515b82bc6547f955e03f5956d009ea28554beb05e2f85417f91b96fd1b7566f" &
        "8f92c02e82ac82f0e20a64c0a3683066300c0603551d130101ff0402300030160603551d20040f300d300b0609" &
        "2b06010401868d1f01301d0603551d0e041604143e80a30384dc81214a81498674ba57783db8ef85301f060355" &
        "1d2304183016801467499f0fa03b44804b13d5a5c720a449cb6491b4300a06082a8648ce3d0403020368003065" &
        "0230509701daa9f5a45e57494fdecd832333b175af38018267496392437ef78c0f31f8c43a76ab243e0fb3de3b" &
        "bd370e61d5023100f07cb804905a423b25c50694034ff8a84f5d750b29c1b9fcbae179ca179c4ed293563050e2" &
        "bf54d6205769ffcae0e852";

      PB_Inter_Bad_DER : constant String :=
        "308201e93082016fa003020102020152300a06082a8648ce3d0403023011310f300d06035504030c06726f6f74" &
        "2d62301e170d3236303732393037353430385a170d3237303532353037353430385a301e311c301a0603550403" &
        "0c137368617265642d696e7465726d6564696174653076301006072a8648ce3d020106052b8104002203620004" &
        "56750ad1e24e2bbfd349d09ec008ec4506edadee48ed1af3575025622d583de813ad1ef329f4a374f7a1a8c4ac" &
        "ac11604e414a6f51da9fb7ecf34adc160806ca4e6670b08309a3e5d08eebd2256d4a3afe7cfbb818b315a0b0ef" &
        "f0afe4dcd8a7a3818d30818a300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106" &
        "30160603551d20040f300d300b06092b0601040184df5109300f0603551d240101ff04053003800100301d0603" &
        "551d0e0416041467499f0fa03b44804b13d5a5c720a449cb6491b4301f0603551d230418301680145aeb3a2a00" &
        "26debc836959f1a6b2fa00df56e19c300a06082a8648ce3d040302036800306502306714225aba6cdff783b990" &
        "e8c6369c2d7ca531628b2ff65e8ce1246a3379c2aedc6df3fc086038802c67317edd0b28c8023100df0758270b" &
        "6b633c5e27c27acd6bf5e0ee4a5245ddcb9e609e5011a7a9a1836cf2744b8404f5b48b9dd0140470d48243";

      PB_Inter_Good_DER : constant String :=
        "308201e83082016fa003020102020151300a06082a8648ce3d0403023011310f300d06035504030c06726f6f74" &
        "2d61301e170d3236303732393037353430385a170d3237303532353037353430385a301e311c301a0603550403" &
        "0c137368617265642d696e7465726d6564696174653076301006072a8648ce3d020106052b8104002203620004" &
        "56750ad1e24e2bbfd349d09ec008ec4506edadee48ed1af3575025622d583de813ad1ef329f4a374f7a1a8c4ac" &
        "ac11604e414a6f51da9fb7ecf34adc160806ca4e6670b08309a3e5d08eebd2256d4a3afe7cfbb818b315a0b0ef" &
        "f0afe4dcd8a7a3818d30818a300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106" &
        "30160603551d20040f300d300b06092b06010401868d1f01300f0603551d240101ff04053003800100301d0603" &
        "551d0e0416041467499f0fa03b44804b13d5a5c720a449cb6491b4301f0603551d2304183016801473a50636f7" &
        "dc3b6b3e4c411184e7b5a13b9c100d300a06082a8648ce3d0403020367003064023030b37a1d2b20a9e38507cd" &
        "9217deb780c5a192de41b193b1ea4a798da13329226cc396a2908b85aaddf8cb728c1eaae00230525c5b69e632" &
        "1645a8b37d0e348bad381c8d3671975067958d5bf935347aca5bb8633e16ae4d607eb4934a15d0158514";

      PB_Root_A_DER : constant String :=
        "308201bc30820141a003020102021421ea63a70614babf12043ff3fd4bdc41048c4cc1300a06082a8648ce3d04" &
        "03023011310f300d06035504030c06726f6f742d61301e170d3236303732393037353430385a170d3237303532" &
        "353037353430385a3011310f300d06035504030c06726f6f742d613076301006072a8648ce3d020106052b8104" &
        "0022036200045876f37066dba6cc53105ef20479a3c2d895a138f4f807f817e20a836058af4243a7dd42d6898b" &
        "a8753fce34d928f1c6b782c3af94f16020564ada84880c31087f34d527242c8bba1c2342666e6a95fc9ffb610c" &
        "b660ecf8438057489fd7e50fa35a3058300f0603551d130101ff040530030101ff300e0603551d0f0101ff0404" &
        "0302010630160603551d20040f300d300b06092b06010401868d1f01301d0603551d0e0416041473a50636f7dc" &
        "3b6b3e4c411184e7b5a13b9c100d300a06082a8648ce3d0403020369003066023100a4f9d741fe62998fa48577" &
        "2c25d75d47c81781fce06439937676dcef371917871aa705f6d74d20ac782f1f1211e9444a023100c7c4830f99" &
        "df1d17e663ac7c62b7f5c145d5f1e5320dfe54161bd6b5b453efbbaa3201025c068621045d37f35486a94d";

      PB_Root_B_DER : constant String :=
        "308201bc30820141a0030201020214528b48a4bc34c3d22e407d9102994b89fe991205300a06082a8648ce3d04" &
        "03023011310f300d06035504030c06726f6f742d62301e170d3236303732393037353430385a170d3237303532" &
        "353037353430385a3011310f300d06035504030c06726f6f742d623076301006072a8648ce3d020106052b8104" &
        "002203620004aba3973bbdd01cf0db3f15e268007c7793948acf49742f641407bd1fe91e4bb7fc0cd00d7504fd" &
        "767169e6484f549e1cb05d61bbbe1652211f04732e488e1c74f82c25593a9fb2eb341c5c2b04e020d64178179b" &
        "173900ce76fe679e946247d4a35a3058300f0603551d130101ff040530030101ff300e0603551d0f0101ff0404" &
        "0302010630160603551d20040f300d300b06092b06010401868d1f01301d0603551d0e041604145aeb3a2a0026" &
        "debc836959f1a6b2fa00df56e19c300a06082a8648ce3d0403020369003066023100b525ff73e032612f337e21" &
        "ccb7a41434d7705f4f427ce849aaf177d5eb36d0cc5eb2a51b0ced490256eb3d7799807a4802310089ad6f07e8" &
        "1ac21b9bd7ca6e4368609b7cc42bcc1e81092fb67f90603386bfee276e0c30851485358de5c76575e0d6f2";

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

      function Decoded (Hex : String) return X509C.Certificate
      is (X509C.Decode_DER
            (From_Hex (Hex), CryptoLib.ASN1.Default_Limits, Status));

      --  The one that cannot carry the policy comes first, so taking the
      --  first path found is the wrong answer.
      type Pool is limited new PB.Candidate_Source with null record;

      overriding function Count (Source : Pool) return Natural is (4);

      overriding function Candidate
        (Source : Pool; Index : Positive) return X509C.Certificate
      is (case Index is
             when 1      => Decoded (PB_Inter_Bad_DER),
             when 2      => Decoded (PB_Inter_Good_DER),
             when 3      => Decoded (PB_Root_A_DER),
             when others => Decoded (PB_Root_B_DER));

      overriding function Is_Trust_Anchor
        (Source : Pool; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Bytes (Item)
          = X509C.Subject_Bytes (Decoded (PB_Root_A_DER))
          or else X509C.Subject_Bytes (Item)
                  = X509C.Subject_Bytes (Decoded (PB_Root_B_DER)));

      Search : constant PB.Build_Result :=
        PB.Build_Path (Decoded (PB_Leaf_DER), Pool'(null record));
   begin
      --  The premise: both intermediates really are indistinguishable by
      --  key, so the search cannot be picking between them on signatures.
      Check (X509C.Public_Key (Decoded (PB_Inter_Bad_DER))
             = X509C.Public_Key (Decoded (PB_Inter_Good_DER)),
             "fixture: the two intermediates share a key");
      Check (X509C.Subject_Bytes (Decoded (PB_Inter_Bad_DER))
             = X509C.Subject_Bytes (Decoded (PB_Inter_Good_DER)),
             "fixture: and a subject name");

      Check (Search.Found, "a path is found");
      Check (Search.Length = 2,
             "of the leaf, an intermediate and an anchor, got"
             & Natural'Image (Search.Length));

      --  The point: not the first one reached.
      Check (Search.Indices (1) = 2,
             "and it goes through the intermediate that grants the policy "
             & "the leaf asserts, not the one listed first, got"
             & Natural'Image (Search.Indices (1)));

      --  What it proposed has to survive the validator, which is the only
      --  thing entitled to conclude anything.
      declare
         type Found_Path is limited new XV.Path_Source with null record;

         overriding function Length (Source : Found_Path) return Positive
         is (3);

         overriding function Certificate_At
           (Source : Found_Path; Index : Positive) return X509C.Certificate
         is (case Index is
                when 1      => Decoded (PB_Leaf_DER),
                when 2      => Decoded (PB_Inter_Good_DER),
                when others => Decoded (PB_Root_A_DER));

         overriding function Is_Trust_Anchor
           (Source : Found_Path; Item : X509C.Certificate) return Boolean
         is (X509C.Subject_Bytes (Item)
             = X509C.Subject_Bytes (Decoded (PB_Root_A_DER)));

         At_Time : constant CryptoLib.X509.Certificate_Time :=
           (Year => 2026, Month => 9, Day => 1,
            Hour => 12, Minute => 0, Second => 0);

         Verdict : constant XV.Validation_Result :=
           XV.Validate_Path (Found_Path'(null record), At_Time);
      begin
         Check (Verdict.Valid,
                "and the path it proposes validates: "
                & XV.Failure_Image (Verdict.Failure));
      end;
   end Check_Policy_Aware_Path_Building;

   --  A self-issued certificate does not spend the policy allowances.
   --
   --  RFC 5280 6.1.4 (h) decrements explicit_policy, policy_mapping and
   --  inhibit_anyPolicy once per certificate -- unless that certificate is
   --  self-issued, because one a CA wrote for itself does not lengthen the
   --  path. It is the rule that lets a CA change keys without spending the
   --  budget its own policyConstraints handed out.
   --
   --  Constructing a chain whose verdict turns on it takes some care, since
   --  6.1.4 applies the constraint after the decrement and the constraint
   --  value overrides the count. With the tree empty, success needs
   --  explicit_policy to still be at least two entering the wrap-up, which
   --  decrements once more. So: a constraint of two, then one middle
   --  certificate, then a leaf naming no policy. If the middle one is
   --  self-issued the allowance survives; if it is not, it does not.
   --
   --  The two middle certificates differ in nothing but their subject name.
   --  Same key, same extensions, same issuer.
   procedure Check_Self_Issued_Policy_Allowance is
      package X509C renames CryptoLib.X509.Certificates;
      package XV renames CryptoLib.X509.Validation;
      use type XV.Validation_Failure;

      SI_Root_DER : constant String :=
        "308201be30820143a00302010202145472b1d2cdae935174a69f43b7d24d7a0cded637300a06082a8648ce3d04" &
        "030230123110300e06035504030c0773692d726f6f74301e170d3236303732393038313030365a170d32373035" &
        "32353038313030365a30123110300e06035504030c0773692d726f6f743076301006072a8648ce3d020106052b" &
        "8104002203620004c5f1b14fee380c1fa7f26dcf7c1a7445f56686fc578b775dcbb4a86c9e09388931022a69b8" &
        "9019636fd90851eed38b0209e46379f93d7a694b3b1900b11c619f7ee6d0a8726733ab50dd0f5cff7d0644a1ab" &
        "810b543bf6d08838d61b9f010c8fa35a3058300f0603551d130101ff040530030101ff300e0603551d0f0101ff" &
        "04040302010630160603551d20040f300d300b06092b06010401868d1f01301d0603551d0e04160414e4adfd6a" &
        "929eec316667b49362ab4b7cd848021c300a06082a8648ce3d0403020369003066023100f5bd22151a750f679c" &
        "8bccfac5ac798d1871320e49942eafcac76c91da7cd74fd00c20cbe590c5f87be52d800e501cf1023100d10c3c" &
        "0939f57755b78eeb115a51f5e01382c3bf480e0f51da0e2f7bfd3373abbd11fb132ba6f222fb0068545949078b";

      SI_Inter_DER : constant String :=
        "308201df30820165a003020102020171300a06082a8648ce3d04030230123110300e06035504030c0773692d72" &
        "6f6f74301e170d3236303732393038313030365a170d3237303532353038313030365a30133111300f06035504" &
        "030c0873692d696e7465723076301006072a8648ce3d020106052b81040022036200048d820adcf2775e7065ad" &
        "d15b168345189fdddbade134616d11a9b2ff4031a2a9f4fd86a18dca3dca4993318671747d837f912c3df48120" &
        "77448ace4e8bf46d55d97adb98bdb02f6f66740c016037d02497b759e06cf52e6c863041a007007351a3818d30" &
        "818a300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630160603551d20040f30" &
        "0d300b06092b06010401868d1f01300f0603551d240101ff04053003800102301d0603551d0e041604147a0638" &
        "a9b61e586eacf75a52776968f6f801c493301f0603551d23041830168014e4adfd6a929eec316667b49362ab4b" &
        "7cd848021c300a06082a8648ce3d0403020368003065023100863f69f21783c279f19df4aba3049851b8e05c44" &
        "c0a36eb3801d8f339cd34450aeb3e4b2930cbd98623baf79ad14385502306893a3d34e9335203337d8deaf2f12" &
        "4c7dca27ecc00aa0d11a02a757f293dbd1cce1c49c4cca4b4875aea981c46401d2";

      SI_Mid_Self_DER : constant String :=
        "308201b73082013ca00302010202020081300a06082a8648ce3d04030230133111300f06035504030c0873692d" &
        "696e746572301e170d3236303732393038313030365a170d3237303532353038313030365a30133111300f0603" &
        "5504030c0873692d696e7465723076301006072a8648ce3d020106052b81040022036200044d51021871860ab8" &
        "e06affcc44f94af2ead588163ee47c3a925c482aec1c13ec95579fd14f4756e35ebe1a7cfb4077ad849aa1fe83" &
        "51a4b83868c936a4e18e2a38bb540616c7e07a87e34378c2ba3e8c2f79a206758fed5680c8158a7b987c0fa363" &
        "3061300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301d0603551d0e041604" &
        "146d50e83c3aa909d04158d66863af9986458c1307301f0603551d230418301680147a0638a9b61e586eacf75a" &
        "52776968f6f801c493300a06082a8648ce3d0403020369003066023100b1e5538a8c151966ec2e26be905655cf" &
        "b24e82c232d588482018aec16235de375f905ce6f3b187317bb0441c13f90c3d023100f9f497e92d81de6a3c57" &
        "188c267fbc5a95fb07ca65e1ec6af9dcf339230aef20634446dd0dbfa9d512871e292c20716e";

      SI_Mid_Other_DER : constant String :=
        "308201b53082013ca00302010202020082300a06082a8648ce3d04030230133111300f06035504030c0873692d" &
        "696e746572301e170d3236303732393038313030365a170d3237303532353038313030365a30133111300f0603" &
        "5504030c0873692d6f746865723076301006072a8648ce3d020106052b81040022036200044d51021871860ab8" &
        "e06affcc44f94af2ead588163ee47c3a925c482aec1c13ec95579fd14f4756e35ebe1a7cfb4077ad849aa1fe83" &
        "51a4b83868c936a4e18e2a38bb540616c7e07a87e34378c2ba3e8c2f79a206758fed5680c8158a7b987c0fa363" &
        "3061300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301d0603551d0e041604" &
        "146d50e83c3aa909d04158d66863af9986458c1307301f0603551d230418301680147a0638a9b61e586eacf75a" &
        "52776968f6f801c493300a06082a8648ce3d04030203670030640230028880c0cacc17aeada041639e20f4cfe6" &
        "3d5b4194a2554ad27a728831b637a3e65ae23465d87fdb50dca1987f97bc2b023060c8cb52332bcd97ad15f52c" &
        "a4885e743d52d3495d8c6258d22cfc3621b7f9c3b6af40c65d88d2ebc607f3d86e1d6ecd";

      SI_Inter_NoAny_DER : constant String :=
        "308201ed30820174a003020102020172300a06082a8648ce3d04030230123110300e06035504030c0773692d72" &
        "6f6f74301e170d3236303732393038313334335a170d3237303532353038313334335a30133111300f06035504" &
        "030c0873692d696e7465723076301006072a8648ce3d020106052b81040022036200048d820adcf2775e7065ad" &
        "d15b168345189fdddbade134616d11a9b2ff4031a2a9f4fd86a18dca3dca4993318671747d837f912c3df48120" &
        "77448ace4e8bf46d55d97adb98bdb02f6f66740c016037d02497b759e06cf52e6c863041a007007351a3819c30" &
        "8199300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630160603551d20040f30" &
        "0d300b06092b06010401868d1f01300f0603551d240101ff04053003800100300d0603551d360101ff04030201" &
        "00301d0603551d0e041604147a0638a9b61e586eacf75a52776968f6f801c493301f0603551d23041830168014" &
        "e4adfd6a929eec316667b49362ab4b7cd848021c300a06082a8648ce3d0403020367003064023074ceec09e8e5" &
        "888826f130fc7ca86786c103d5b27ea4205015b61a70a645fe9574a609804e369a599b3285c815146d8d023075" &
        "4a2a30b2d5511d5a1e4a06cd5fafcf50da59616d460442c263813b7cf8f5ab468b085d2abbfc720e00d75ed058" &
        "49ff";

      SI_MidAny_Self_DER : constant String :=
        "308201c93082014fa00302010202020083300a06082a8648ce3d04030230133111300f06035504030c0873692d" &
        "696e746572301e170d3236303732393038313334335a170d3237303532353038313334335a30133111300f0603" &
        "5504030c0873692d696e7465723076301006072a8648ce3d020106052b81040022036200044d51021871860ab8" &
        "e06affcc44f94af2ead588163ee47c3a925c482aec1c13ec95579fd14f4756e35ebe1a7cfb4077ad849aa1fe83" &
        "51a4b83868c936a4e18e2a38bb540616c7e07a87e34378c2ba3e8c2f79a206758fed5680c8158a7b987c0fa376" &
        "3074300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630110603551d20040a30" &
        "0830060604551d2000301d0603551d0e041604146d50e83c3aa909d04158d66863af9986458c1307301f060355" &
        "1d230418301680147a0638a9b61e586eacf75a52776968f6f801c493300a06082a8648ce3d0403020368003065" &
        "023100db90d2118496b871a7d41e94869e024f62db758962b477ef63067460f75eee2da89698fe349b7ead75d5" &
        "89f2a97ccdca02307af04b39675a429ee3ba5a0de4d9eed5a9e7e5439aceb164c23fe627035712e696acbc0d15" &
        "b21fae567137b4eb7bf15f";

      SI_MidAny_Other_DER : constant String :=
        "308201ca3082014fa00302010202020084300a06082a8648ce3d04030230133111300f06035504030c0873692d" &
        "696e746572301e170d3236303732393038313334335a170d3237303532353038313334335a30133111300f0603" &
        "5504030c0873692d6f746865723076301006072a8648ce3d020106052b81040022036200044d51021871860ab8" &
        "e06affcc44f94af2ead588163ee47c3a925c482aec1c13ec95579fd14f4756e35ebe1a7cfb4077ad849aa1fe83" &
        "51a4b83868c936a4e18e2a38bb540616c7e07a87e34378c2ba3e8c2f79a206758fed5680c8158a7b987c0fa376" &
        "3074300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630110603551d20040a30" &
        "0830060604551d2000301d0603551d0e041604146d50e83c3aa909d04158d66863af9986458c1307301f060355" &
        "1d230418301680147a0638a9b61e586eacf75a52776968f6f801c493300a06082a8648ce3d0403020369003066" &
        "02310089abe10f6e6457d34be715571171f4241f0229a83ff84b22671ee70296b5910866bec983e16c69d0185d" &
        "591123c295b6023100c662dbd27f6321ada0f347660821d2018e895c150368beda50044c1cfa0ba116cf5cc2ab" &
        "4beff2f219a7473cbb98870c";

      SI_LeafAny_Self_DER : constant String :=
        "308201be30820145a00302010202020092300a06082a8648ce3d04030230133111300f06035504030c0873692d" &
        "696e746572301e170d3236303732393038313334335a170d3237303532353038313334335a3017311530130603" &
        "5504030c0c686f73742e6578616d706c653076301006072a8648ce3d020106052b81040022036200043533ae65" &
        "6cce864ebe5ec01abcd8be7da1900054dddbca9abfb51811f8f627686cfb5ef640120b25abb03ffc64ca4e1a25" &
        "230a35a74b76ee5c38326e61982a54201701b3659857b9f29e875a758ba8456d2a0de90e1c47eba92bc0b70994" &
        "e1e6a3683066300c0603551d130101ff0402300030160603551d20040f300d300b06092b06010401868d1f0130" &
        "1d0603551d0e041604142318475bea76beeb0af07d63a5ac5fcf840c4bb1301f0603551d230418301680146d50" &
        "e83c3aa909d04158d66863af9986458c1307300a06082a8648ce3d040302036700306402302585ffdc3cc6f971" &
        "b8f05bfc16526721500ebea572700f30c1b2d73cb52cdfd60e6aa939f952a0b4c10c198957431c860230402d69" &
        "0bc1ccdf6cbc8add97c5e4364be32d0432103314a1ab1ecd7642de909dea3cf72789185d0a72c788f83088955f";

      SI_LeafAny_Other_DER : constant String :=
        "308201c030820145a00302010202020092300a06082a8648ce3d04030230133111300f06035504030c0873692d" &
        "6f74686572301e170d3236303732393038313334335a170d3237303532353038313334335a3017311530130603" &
        "5504030c0c686f73742e6578616d706c653076301006072a8648ce3d020106052b81040022036200043533ae65" &
        "6cce864ebe5ec01abcd8be7da1900054dddbca9abfb51811f8f627686cfb5ef640120b25abb03ffc64ca4e1a25" &
        "230a35a74b76ee5c38326e61982a54201701b3659857b9f29e875a758ba8456d2a0de90e1c47eba92bc0b70994" &
        "e1e6a3683066300c0603551d130101ff0402300030160603551d20040f300d300b06092b06010401868d1f0130" &
        "1d0603551d0e041604142318475bea76beeb0af07d63a5ac5fcf840c4bb1301f0603551d230418301680146d50" &
        "e83c3aa909d04158d66863af9986458c1307300a06082a8648ce3d0403020369003066023100b298db0acf51c2" &
        "ff1b8d23465e1cc0c82597ae1a3e100b3cc0e8b3772592b737a698869b9ffe01bf1bd5d81de8e979cf023100fd" &
        "acd518e6bf8c242be13abc2a5b833acec2cf97a2ed3b0344cc2baa5cb5458f20d81495b9998e4ef34183c557b7" &
        "5963";

      SI_Leaf_Self_DER : constant String :=
        "308201a73082012da00302010202020091300a06082a8648ce3d04030230133111300f06035504030c0873692d" &
        "696e746572301e170d3236303732393038313030365a170d3237303532353038313030365a3017311530130603" &
        "5504030c0c686f73742e6578616d706c653076301006072a8648ce3d020106052b81040022036200043533ae65" &
        "6cce864ebe5ec01abcd8be7da1900054dddbca9abfb51811f8f627686cfb5ef640120b25abb03ffc64ca4e1a25" &
        "230a35a74b76ee5c38326e61982a54201701b3659857b9f29e875a758ba8456d2a0de90e1c47eba92bc0b70994" &
        "e1e6a350304e300c0603551d130101ff04023000301d0603551d0e041604142318475bea76beeb0af07d63a5ac" &
        "5fcf840c4bb1301f0603551d230418301680146d50e83c3aa909d04158d66863af9986458c1307300a06082a86" &
        "48ce3d04030203680030650230248d46c68e75e3e512d3324b483943fa1d627ea99925e6d5cd576ccf667c5779" &
        "8745b20c2387871cbc6393b108e0f9b5023100953d386784f3bc27fe4a1653413a1de3ffe2af72a24ed68b3723" &
        "32a79876fcbfb6aed73ccc0383eafdd83cc673d8b4ea";

      SI_Leaf_Other_DER : constant String :=
        "308201a63082012da00302010202020091300a06082a8648ce3d04030230133111300f06035504030c0873692d" &
        "6f74686572301e170d3236303732393038313030365a170d3237303532353038313030365a3017311530130603" &
        "5504030c0c686f73742e6578616d706c653076301006072a8648ce3d020106052b81040022036200043533ae65" &
        "6cce864ebe5ec01abcd8be7da1900054dddbca9abfb51811f8f627686cfb5ef640120b25abb03ffc64ca4e1a25" &
        "230a35a74b76ee5c38326e61982a54201701b3659857b9f29e875a758ba8456d2a0de90e1c47eba92bc0b70994" &
        "e1e6a350304e300c0603551d130101ff04023000301d0603551d0e041604142318475bea76beeb0af07d63a5ac" &
        "5fcf840c4bb1301f0603551d230418301680146d50e83c3aa909d04158d66863af9986458c1307300a06082a86" &
        "48ce3d04030203670030640230545d57151e1dcb206ee398b91e4cbdc5a0fe6c4ed465e35a5bf37f6e85ba99aa" &
        "62bdb12fa3e631659c22676bc2502e5e02305380e6a691e72b7c456e5157ed153231abcd50ea8d5d4154cf719c" &
        "acdcb2928c0b6f327de6f3f7a8046e2dfb30fedfb4";

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

      function Decoded (Hex : String) return X509C.Certificate
      is (X509C.Decode_DER
            (From_Hex (Hex), CryptoLib.ASN1.Default_Limits, Status));

      --  Two scenarios, each with a self-issued and a plain middle
      --  certificate. Allowance: does a self-issued certificate spend the
      --  explicit-policy countdown. Wildcard: may it still use anyPolicy
      --  after inhibitAnyPolicy reached zero.
      type Which is (Self, Other);
      type Scenario is (Allowance, Wildcard);

      type Four (Case_Kind : Scenario; Kind : Which) is
        limited new XV.Path_Source with null record;

      overriding function Length (Source : Four) return Positive is (4);

      overriding function Certificate_At
        (Source : Four; Index : Positive) return X509C.Certificate
      is (case Index is
             when 1 =>
               (case Source.Case_Kind is
                   when Allowance =>
                     (if Source.Kind = Self then Decoded (SI_Leaf_Self_DER)
                      else Decoded (SI_Leaf_Other_DER)),
                   when Wildcard =>
                     (if Source.Kind = Self
                      then Decoded (SI_LeafAny_Self_DER)
                      else Decoded (SI_LeafAny_Other_DER))),
             when 2 =>
               (case Source.Case_Kind is
                   when Allowance =>
                     (if Source.Kind = Self then Decoded (SI_Mid_Self_DER)
                      else Decoded (SI_Mid_Other_DER)),
                   when Wildcard =>
                     (if Source.Kind = Self
                      then Decoded (SI_MidAny_Self_DER)
                      else Decoded (SI_MidAny_Other_DER))),
             when 3 =>
               (case Source.Case_Kind is
                   when Allowance => Decoded (SI_Inter_DER),
                   when Wildcard  => Decoded (SI_Inter_NoAny_DER)),
             when others => Decoded (SI_Root_DER));

      overriding function Is_Trust_Anchor
        (Source : Four; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Bytes (Item)
          = X509C.Subject_Bytes (Decoded (SI_Root_DER)));

      At_Time : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 9, Day => 1,
         Hour => 12, Minute => 0, Second => 0);

      function Verdict
        (Case_Kind : Scenario; Kind : Which) return XV.Validation_Result
      is (XV.Validate_Path
            (Four'(Case_Kind => Case_Kind, Kind => Kind), At_Time));
   begin
      --  The premises, asserted rather than assumed: one middle certificate
      --  is self-issued and the other is not, and they are otherwise the
      --  same certificate.
      Check (X509C.Is_Self_Issued (Decoded (SI_Mid_Self_DER)),
             "fixture: the one middle certificate is self-issued");
      Check (not X509C.Is_Self_Issued (Decoded (SI_Mid_Other_DER)),
             "fixture: and the other is not");
      Check (X509C.Public_Key (Decoded (SI_Mid_Self_DER))
             = X509C.Public_Key (Decoded (SI_Mid_Other_DER)),
             "fixture: they carry the same key");

      --  The allowance survives a certificate that did not lengthen the
      --  path.
      Check (Verdict (Allowance, Self).Valid,
             "a self-issued certificate does not spend the explicit-policy "
             & "allowance: "
             & XV.Failure_Image (Verdict (Allowance, Self).Failure));

      --  And is spent by one that did. OpenSSL agrees on both, with
      --  openssl verify -policy_check over the same two chains.
      Check (not Verdict (Allowance, Other).Valid
             and then Verdict (Allowance, Other).Failure
                      = XV.Policy_Not_Established,
             "and one that is not self-issued does spend it, got "
             & XV.Failure_Image (Verdict (Allowance, Other).Failure));

      --  The other half of the rule, 6.1.3 (d)(2): a self-issued
      --  certificate may still assert anyPolicy after inhibitAnyPolicy has
      --  reached zero, because it is the same CA rather than a step further
      --  down the path. Here the intermediate withdraws the wildcard and the
      --  middle certificate uses it anyway.
      Check (Verdict (Wildcard, Self).Valid,
             "a self-issued certificate may still use anyPolicy after it "
             & "was inhibited: "
             & XV.Failure_Image (Verdict (Wildcard, Self).Failure));
      Check (not Verdict (Wildcard, Other).Valid
             and then Verdict (Wildcard, Other).Failure
                      = XV.Policy_Not_Established,
             "and one that is not self-issued may not, got "
             & XV.Failure_Image (Verdict (Wildcard, Other).Failure));
   end Check_Self_Issued_Policy_Allowance;

   --  A policy tree wider than this crate will hold.
   --
   --  The bound exists because the tree is built from certificates somebody
   --  else wrote and must not grow without end. Reaching it is reported and
   --  refused rather than truncated: a partial tree is missing exactly the
   --  nodes that pruning would have removed, so answering from one can only
   --  ever be too permissive.
   --
   --  This is a real divergence and worth stating as one. OpenSSL accepts
   --  the chain below; this refuses it. Exhausted is how a caller tells that
   --  apart from the certificates failing on their own merits -- the first
   --  is this implementation's limit, the second is not, and they call for
   --  different things to be done about them.
   procedure Check_Policy_Tree_Bound is
      package X509C renames CryptoLib.X509.Certificates;
      package XV renames CryptoLib.X509.Validation;
      use type XV.Validation_Failure;

      EX_Root_DER : constant String :=
        "308201693082010ea0030201020214258aa8101cb678c72721299bd717e683a715057a300a06082a8648ce3d04" &
        "030230123110300e06035504030c0765782d726f6f74301e170d3236303732393038333334315a170d32373035" &
        "32353038333334315a30123110300e06035504030c0765782d726f6f743059301306072a8648ce3d020106082a" &
        "8648ce3d0301070342000423f87ab29ecf1e6cbe382570602a675d04e31cd3e7a33351f75c266537312873dc77" &
        "ae00b968e993ea0eecc3d07551ea64d539ca88810b7c5b1d9758807493e5a3423040300f0603551d130101ff04" &
        "0530030101ff300e0603551d0f0101ff040403020106301d0603551d0e04160414137a5ce002458b4a02a927d3" &
        "379fb533e8f980f4300a06082a8648ce3d0403020349003046022100dc19551b600487325853796e2ee38b741f" &
        "7e3c9d49ef67cb47fa6eb45c33feb10221009a53ca584544b77b244fa1c2481b1bb16a0ffdf555c1007bb017c9" &
        "2c2c580a38";

      EX_C1_DER : constant String :=
        "30820247308201eda003020102020200a1300a06082a8648ce3d04030230123110300e06035504030c0765782d" &
        "726f6f74301e170d3236303732393038333334315a170d3237303532353038333334315a3010310e300c060355" &
        "04030c0565782d63313059301306072a8648ce3d020106082a8648ce3d030107034200041d8a2619a23951a09a" &
        "00dc1bed7c4c59047f1e8fa693792c989983ca371c6210fc5182095e4a15d5cf3808435b125d1e946d90f5c206" &
        "f479b663383a38191a63a38201333082012f300f0603551d130101ff040530030101ff300e0603551d0f0101ff" &
        "0404030201063081cb0603551d200481c33081c0300a06082b06010401a70801300a06082b06010401a7090130" &
        "0a06082b06010401a70a01300a06082b06010401a70b01300a06082b06010401a70c01300a06082b06010401a7" &
        "0d01300a06082b06010401a70e01300a06082b06010401a70f01300a06082b06010401a71001300a06082b0601" &
        "0401a71101300a06082b06010401a71201300a06082b06010401a71301300a06082b06010401a71401300a0608" &
        "2b06010401a71501300a06082b06010401a71601300a06082b06010401a71701301d0603551d0e04160414b1b8" &
        "23bd89082af24e093638e614da17ce2ab875301f0603551d23041830168014137a5ce002458b4a02a927d3379f" &
        "b533e8f980f4300a06082a8648ce3d0403020348003045022041c1e75429a7c3c05ca8475f9f88b4c7f5598c3e" &
        "7431860a425f33ea0a61404e022100a7fc6c3d0901714ac2734364557b32dfc4218e25be804f85f243dac368ca" &
        "bae6";

      EX_C2_DER : constant String :=
        "308201863082012ca003020102020200a2300a06082a8648ce3d0403023010310e300c06035504030c0565782d" &
        "6331301e170d3236303732393038333334315a170d3237303532353038333334315a3010310e300c0603550403" &
        "0c0565782d63323059301306072a8648ce3d020106082a8648ce3d0301070342000451db26ea2e413733d7c6e9" &
        "d07b06b08f5df72df69b4e10d0ee49a4980f388ff02483861446fd20d518c3be5f05f1a27abfced023306fd500" &
        "8630749610138492a3763074300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106" &
        "30110603551d20040a300830060604551d2000301d0603551d0e041604141b2aac4c9eea97e063695b33838fdb" &
        "8be4a2d5cb301f0603551d23041830168014b1b823bd89082af24e093638e614da17ce2ab875300a06082a8648" &
        "ce3d0403020348003045022100dc141147ef634d4fbbe89af902deea720a917be8047350b642b8b4d0cfa8ae55" &
        "022049425ef4466ca029bc3419e20c535a97e65adbc07f49b46d2996b771bc0f8e36";

      EX_C3_DER : constant String :=
        "308201873082012ca003020102020200a3300a06082a8648ce3d0403023010310e300c06035504030c0565782d" &
        "6332301e170d3236303732393038333334315a170d3237303532353038333334315a3010310e300c0603550403" &
        "0c0565782d63333059301306072a8648ce3d020106082a8648ce3d030107034200048cddee079b2fefa50d3a68" &
        "9ff693bd9b81979ce7a5415b202cc7a77f1ad95002896c947821fa2559c62977aca714802f6426ce8e83669506" &
        "6244e6d8dc2d1cc7a3763074300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106" &
        "30110603551d20040a300830060604551d2000301d0603551d0e04160414a5db2091914df88362860a8eb50d77" &
        "d03d9de3b5301f0603551d230418301680141b2aac4c9eea97e063695b33838fdb8be4a2d5cb300a06082a8648" &
        "ce3d0403020349003046022100922be191dc6f1bf2034c76700a87851e4c69f009f9db2be9e0df2a770411f89b" &
        "022100ea59de8c1f19e253d2fa8bf341e83c39098f3330335e847c785e35585c6b6a35";

      EX_Leaf_DER : constant String :=
        "308201753082011ba003020102020200a4300a06082a8648ce3d0403023010310e300c06035504030c0565782d" &
        "6333301e170d3236303732393038333334315a170d3237303532353038333334315a30123110300e0603550403" &
        "0c0765782d6c6561663059301306072a8648ce3d020106082a8648ce3d0301070342000471fa7e6cdc9e7bed4f" &
        "e3448926d3af91e0bc41f6e01977b1c3546c38b984c5fe0e5f97e3cfdfc0c4c308dffe3858a74d74f26de0ad73" &
        "7b8048d56b312a6c592aa3633061300c0603551d130101ff0402300030110603551d20040a300830060604551d" &
        "2000301d0603551d0e04160414e3b8a5632e9979a915046d66332f2e33f3c47974301f0603551d230418301680" &
        "14a5db2091914df88362860a8eb50d77d03d9de3b5300a06082a8648ce3d0403020348003045022062f75565c1" &
        "48b13724cea67660270eabbd6db17952df724d6117b0c5bfc1718b022100b79a98c915ab8f100d541e2e7f0637" &
        "cc057fe1c7ab56ce8a111fd97158f98b19";

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

      function Decoded (Hex : String) return X509C.Certificate
      is (X509C.Decode_DER
            (From_Hex (Hex), CryptoLib.ASN1.Default_Limits, Status));

      --  Sixteen policies at the first level, widened by anyPolicy at each
      --  level below it: 1 + 16 + 16 + 16 + 16 nodes against a bound of 64.
      type Wide is limited new XV.Path_Source with null record;

      overriding function Length (Source : Wide) return Positive is (5);

      overriding function Certificate_At
        (Source : Wide; Index : Positive) return X509C.Certificate
      is (case Index is
             when 1      => Decoded (EX_Leaf_DER),
             when 2      => Decoded (EX_C3_DER),
             when 3      => Decoded (EX_C2_DER),
             when 4      => Decoded (EX_C1_DER),
             when others => Decoded (EX_Root_DER));

      overriding function Is_Trust_Anchor
        (Source : Wide; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Bytes (Item)
          = X509C.Subject_Bytes (Decoded (EX_Root_DER)));

      At_Time : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 9, Day => 1,
         Hour => 12, Minute => 0, Second => 0);

      Verdict : constant XV.Validation_Result :=
        XV.Validate_Path (Wide'(null record), At_Time);
   begin
      --  The premise: the first certificate really does carry enough
      --  policies to widen the tree past the bound. Sixteen is also the
      --  most one certificate may assert, so this is the widest a single
      --  level can get.
      declare
         Named : constant CryptoLib.X509.Policies.Policy_Set :=
           CryptoLib.X509.Policies.Policies_Of (Decoded (EX_C1_DER));
      begin
         Check (Named.Well_Formed
                and then Named.Count = CryptoLib.X509.Policies.Maximum_Policies,
                "fixture: the first certificate asserts a full set of "
                & "policies, got" & Natural'Image (Named.Count));
      end;

      --  Refused, and said to be refused for this reason rather than for
      --  anything the certificates did.
      Check (not Verdict.Valid,
             "a tree wider than the bound is refused rather than answered "
             & "from in part");
      Check (Verdict.Policies.Exhausted,
             "and the refusal says the bound was reached, not that the "
             & "chain establishes no policy");
      Check (Verdict.Failure = XV.Policy_Not_Established,
             "reported as a policy failure, got "
             & XV.Failure_Image (Verdict.Failure));
   end Check_Policy_Tree_Bound;

   --  A policy set is a set, at both ends.
   --
   --  Coming in: RFC 5280 4.2.1.4 says a policy OID must not appear twice
   --  in one extension, and OpenSSL refuses one that does (error 42,
   --  "invalid or inconsistent certificate policy extension"). Accepting
   --  it would leave this the more permissive of the two on input the RFC
   --  forbids outright, which is the wrong direction for this library to
   --  differ in.
   --
   --  Going out: two nodes can carry the same policy without anything
   --  being wrong -- two mappings converging on one subject policy is the
   --  ordinary way to arrive there -- and the reported set listed it once
   --  per node. Nothing was refused that should have been accepted, so
   --  this is not an unsound verdict; it is a caller counting the list and
   --  reading a repetition as breadth.
   procedure Check_Policy_Set_Is_A_Set is
      package X509C renames CryptoLib.X509.Certificates;
      package PP renames CryptoLib.X509.Policies;
      package XV renames CryptoLib.X509.Validation;
      use type CryptoLib.ASN1.Errors.Decode_Status;

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

      Dup_Policy_DER : constant String :=
        "308201a030820146a00302010202146f3c7cb756844c0a8daf62f2208802ba31ac25ac300a06082a8648ce3d04" &
        "03023011310f300d06035504030c065020526f6f74301e170d3236303732393038343531395a170d3334313031" &
        "353038343531395a3011310f300d06035504030c064475702043413059301306072a8648ce3d020106082a8648" &
        "ce3d030107034200048b245cf0e8e82860e05d6391e4747088bea4efe6894425cc78ea2598d7c60f5777a3eede" &
        "abf4bbcf66ce81a56ed8fde1207630ec6ea5b42e2af72d898ac5b0e7a37c307a300f0603551d130101ff040530" &
        "030101ff300e0603551d0f0101ff04040302020430170603551d200410300e300506032a0304300506032a0304" &
        "301d0603551d0e041604143aa5eb3b237e63b3f2a0710f36e2ee6d60625cc6301f0603551d2304183016801402" &
        "2ece54b366f27ede1b920700fb928139116f3f300a06082a8648ce3d04030203480030450220231e243cb54f35" &
        "131612fabafd2f527a87c66c5cbe31e9e224ae8aa24c5a1132022100d8931fda0f0bc878d3d8f9a4d88a015eac" &
        "589d43e60285c4282ce615d5a45068";

      CV_Root_DER : constant String :=
        "308201673082010ca003020102021438712a03489d5b69aefec58a74228f323acc452d300a06082a8648ce3d04" &
        "03023011310f300d06035504030c065020526f6f74301e170d3236303732393038343531395a170d3336303732" &
        "363038343531395a3011310f300d06035504030c065020526f6f743059301306072a8648ce3d020106082a8648" &
        "ce3d03010703420004456418d55e203fe65b9f8c38fb141be790aebcb087d03965a3e6f8f3e555aeb6a24623d5" &
        "aaf702768805759cbc5186201d8b054de710825cd2b80dc2ca9b6950a3423040300f0603551d130101ff040530" &
        "030101ff300e0603551d0f0101ff040403020204301d0603551d0e04160414022ece54b366f27ede1b920700fb" &
        "928139116f3f300a06082a8648ce3d0403020349003046022100f7618559ffeac694358047b4e91c751e63f9c8" &
        "a94cb85592c13596b05980ab5b02210097f23bcf1b16a617cf03076c9b638540ff7f1457a268770df533e00e2f" &
        "0ee7cd";

      CV_AB_DER : constant String :=
        "3082019f30820145a00302010202146f3c7cb756844c0a8daf62f2208802ba31ac25ad300a06082a8648ce3d04" &
        "03023011310f300d06035504030c065020526f6f74301e170d3236303732393038343531395a170d3334313031" &
        "353038343531395a3010310e300c06035504030c0541422043413059301306072a8648ce3d020106082a8648ce" &
        "3d030107034200048b245cf0e8e82860e05d6391e4747088bea4efe6894425cc78ea2598d7c60f5777a3eedeab" &
        "f4bbcf66ce81a56ed8fde1207630ec6ea5b42e2af72d898ac5b0e7a37c307a300f0603551d130101ff04053003" &
        "0101ff300e0603551d0f0101ff04040302020430170603551d200410300e300506032a0301300506032a030230" &
        "1d0603551d0e041604143aa5eb3b237e63b3f2a0710f36e2ee6d60625cc6301f0603551d23041830168014022e" &
        "ce54b366f27ede1b920700fb928139116f3f300a06082a8648ce3d040302034800304502205b1b6cea73d3c0e9" &
        "0684665b6b05f52c756b21594af01cf309dbe10f37fb4400022100b72a6346f917f03829b91c9b527f779a028b" &
        "42f0169017bd2a14a4039a9cceeb";

      CV_Map_DER : constant String :=
        "308201c53082016aa0030201020214140f080672287aeb0d12b20eca69618ad6ccb75a300a06082a8648ce3d04" &
        "03023010310e300c06035504030c054142204341301e170d3236303732393038343531395a170d333431303135" &
        "3038343531395a3011310f300d06035504030c064d61702043413059301306072a8648ce3d020106082a8648ce" &
        "3d03010703420004c57bfeab6876597b9837d11e2a014c5635b7ba4e23e656fc0fdef9102c24bb86510273b3ab" &
        "993e7ea30dd8d2abf6ef31ec6906ecece4b4936c3a6a446825caa1a381a030819d300f0603551d130101ff0405" &
        "30030101ff300e0603551d0f0101ff04040302020430170603551d200410300e300506032a0301300506032a03" &
        "0230210603551d21041a3018300a06032a030106032a0309300a06032a030206032a0309301d0603551d0e0416" &
        "04144213281531333a76ba243992cc9b3570024d80c9301f0603551d230418301680143aa5eb3b237e63b3f2a0" &
        "710f36e2ee6d60625cc6300a06082a8648ce3d0403020349003046022100b978f747358fef7b843c5951d2729f" &
        "e2157a9032234fab5054e0342c719e7ac6022100f173dc4da3833c5873004bbff6cae519f7855859d83e46ac6e" &
        "6ba2b79752e4c5";

      CV_Leaf_DER : constant String :=
        "308201883082012fa0030201020214793d3836dd484ab712ce6e5876bfb95ec73531a2300a06082a8648ce3d04" &
        "03023011310f300d06035504030c064d6170204341301e170d3236303732393038343533375a170d3334313031" &
        "353038343533375a30143112301006035504030c09782e6578616d706c653059301306072a8648ce3d02010608" &
        "2a8648ce3d03010703420004985fb7103ef3a20f32fa4ea636bbf614aff1c998e56410209b6882f4c19a7ce09d" &
        "a8e95ee119f295fccf4de59e46c8ff212667609ce4a4fa53ee6a20cef93f42a3623060300c0603551d130101ff" &
        "0402300030100603551d2004093007300506032a0309301d0603551d0e041604147471bbec40749113341508ee" &
        "601bd5dc5eb116a2301f0603551d230418301680144213281531333a76ba243992cc9b3570024d80c9300a0608" &
        "2a8648ce3d0403020347003044022100e31cbbf268a7036a8207c8cd98cae7c385741d59199e43b2d6670a9185" &
        "c7d747021f2d41fa8ca8245f053189b898a850d014d075387846b95be31ff57f3f8fa7c6";

      Status : CryptoLib.ASN1.Errors.Decode_Status;

      function Decoded (Hex : String) return X509C.Certificate
      is (X509C.Decode_DER
            (From_Hex (Hex), CryptoLib.ASN1.Default_Limits, Status));

      --  root -> {1.2.3.1, 1.2.3.2} -> both mapped to 1.2.3.9 -> 1.2.3.9
      type Converging is limited new XV.Path_Source with null record;

      overriding function Length (Source : Converging) return Positive is (4);

      overriding function Certificate_At
        (Source : Converging; Index : Positive) return X509C.Certificate
      is (case Index is
             when 1      => Decoded (CV_Leaf_DER),
             when 2      => Decoded (CV_Map_DER),
             when 3      => Decoded (CV_AB_DER),
             when others => Decoded (CV_Root_DER));

      overriding function Is_Trust_Anchor
        (Source : Converging; Item : X509C.Certificate) return Boolean
      is (X509C.Subject_Bytes (Item)
          = X509C.Subject_Bytes (Decoded (CV_Root_DER)));

      At_Time : constant CryptoLib.X509.Certificate_Time :=
        (Year => 2026, Month => 9, Day => 1,
         Hour => 12, Minute => 0, Second => 0);
   begin
      --  Coming in: 1.2.3.4 twice in one extension.
      declare
         Doubled : constant PP.Policy_Set :=
           PP.Policies_Of (Decoded (Dup_Policy_DER));
      begin
         Check (Status = CryptoLib.ASN1.Errors.Ok,
                "the certificate itself decodes -- the duplicate is a policy "
                & "question, not a DER one");
         Check (Doubled.Present,
                "and the extension is there to be judged");
         Check (not Doubled.Well_Formed,
                "a policy asserted twice makes the set unusable rather than "
                & "being folded down to one");
      end;

      --  Going out: two mappings, one destination, reported once.
      declare
         Verdict : constant XV.Validation_Result :=
           XV.Validate_Path (Converging'(null record), At_Time);
      begin
         Check (Verdict.Valid,
                "converging mappings are ordinary and the path holds, got "
                & XV.Failure_Image (Verdict.Failure));
         Check (Verdict.Policies.Count = 1,
                "the policy both mappings arrive at is reported once, got"
                & Natural'Image (Verdict.Policies.Count));
         Check (not Verdict.Policies.Exhausted,
                "and nothing about this reached a bound");
      end;
   end Check_Policy_Set_Is_A_Set;

   --  SkipCerts, read by hand and so read wrongly.
   --
   --  Both policyConstraints fields are context-tagged INTEGERs carrying an
   --  INTEGER's content without an INTEGER's tag, so the shared reader --
   --  which rejects a negative value, insists on the minimal form, and
   --  guards its own accumulation -- could not be called and the bytes were
   --  folded by hand instead. The hand-written loop did none of the three.
   --  A four-octet field reaches 4294967295 and Natural stops at
   --  2147483647, so a certificate could raise CONSTRAINT_ERROR out of a
   --  parser whose whole contract is that it does not: anyone can put four
   --  octets in an extension.
   --
   --  If any of this crashes rather than fails, the suite dies here, which
   --  is the outcome being guarded against.
   procedure Check_Policy_Constraint_Skipcerts is
      package X509C renames CryptoLib.X509.Certificates;
      package PP renames CryptoLib.X509.Policies;

      Skip_Negative_DER : constant String :=
        "3082016d30820114a003020102021411e4e06fd4d42c37f49055a01d0252baf2727c69300a06082a8648ce3d04" &
        "030230133111300f06035504030c084f766572666c6f77301e170d3236303732393038353135305a170d333431" &
        "3031353038353135305a30133111300f06035504030c084f766572666c6f773059301306072a8648ce3d020106" &
        "082a8648ce3d03010703420004616e1c07a40b382e5a6b6cbd16ccb32d1035c52f6c7cec204e75d6623d97aec4" &
        "f0d33d2af1e46da7b892fcf24489dab8f038c39218fba2ad11e06d3a9c0e6815a3463044300f0603551d130101" &
        "ff040530030101ff30120603551d240101ff04083006800480000000301d0603551d0e041604144d81fe58bc05" &
        "ce60d8225766eeb6c37877cfefc5300a06082a8648ce3d0403020347003044022002773f3c71a3b6a61f010cfc" &
        "f3fe352a2064f2d07e90f00e4b61a8e62105067d022060132cf2b1249bf79fcefdcac6f91f36e9269160446f6b" &
        "fafe780d559b5b4c4a";

      Skip_Huge_DER : constant String :=
        "3082016030820107a00302010202146c79d5de8ad1b36736a50ecd6ebead7486953767300a06082a8648ce3d04" &
        "0302300c310a300806035504030c0154301e170d3236303732393038353334345a170d33343130313530383533" &
        "34345a300c310a300806035504030c01543059301306072a8648ce3d020106082a8648ce3d0301070342000461" &
        "6e1c07a40b382e5a6b6cbd16ccb32d1035c52f6c7cec204e75d6623d97aec4f0d33d2af1e46da7b892fcf24489" &
        "dab8f038c39218fba2ad11e06d3a9c0e6815a3473045300f0603551d130101ff040530030101ff30130603551d" &
        "240101ff04093007800500ffffffff301d0603551d0e041604144d81fe58bc05ce60d8225766eeb6c37877cfef" &
        "c5300a06082a8648ce3d0403020347003044022014020108045a4a5523786cdde89c7b1e1abd491b38afc4b068" &
        "d7c7c0b5f9a61102204c8b942529e8a08dcb928717847c4fa6cd06f984798acfcb7abe1a33f54b2362";

      Skip_Non_Minimal_DER : constant String :=
        "3082015d30820104a00302010202141e0f9c28b63b2fb1d3312894e0320d449078be36300a06082a8648ce3d04" &
        "0302300c310a300806035504030c0154301e170d3236303732393038353430315a170d33343130313530383534" &
        "30315a300c310a300806035504030c01543059301306072a8648ce3d020106082a8648ce3d0301070342000461" &
        "6e1c07a40b382e5a6b6cbd16ccb32d1035c52f6c7cec204e75d6623d97aec4f0d33d2af1e46da7b892fcf24489" &
        "dab8f038c39218fba2ad11e06d3a9c0e6815a3443042300f0603551d130101ff040530030101ff30100603551d" &
        "240101ff0406300480020001301d0603551d0e041604144d81fe58bc05ce60d8225766eeb6c37877cfefc5300a" &
        "06082a8648ce3d040302034700304402207b9aea4da0777599d00a09fd972498aa6d4da5759ab3e4c428f0af00" &
        "a88250850220574018d1249aae8989915afb20ac01b0b3c384832dc0a4078f6f85327e67fc24";

      Skip_Plain_DER : constant String :=
        "3082015d30820103a0030201020214536596ec8bbf720a5e3a2db18d3ada585bfd7a75300a06082a8648ce3d04" &
        "0302300c310a300806035504030c0154301e170d3236303732393038353430315a170d33343130313530383534" &
        "30315a300c310a300806035504030c01543059301306072a8648ce3d020106082a8648ce3d0301070342000461" &
        "6e1c07a40b382e5a6b6cbd16ccb32d1035c52f6c7cec204e75d6623d97aec4f0d33d2af1e46da7b892fcf24489" &
        "dab8f038c39218fba2ad11e06d3a9c0e6815a3433041300f0603551d130101ff040530030101ff300f0603551d" &
        "240101ff04053003800105301d0603551d0e041604144d81fe58bc05ce60d8225766eeb6c37877cfefc5300a06" &
        "082a8648ce3d0403020348003045022100d428d89fdcd24eb41b89d438547fafcacdd4bceb5be1d41603fa25b7" &
        "3dcb1f850220205e3891d01c91ba2d35d5c82662fb4aa2d9b061c29677dc1cc2a42daad4170a";

      Status : CryptoLib.ASN1.Errors.Decode_Status;

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

      function Constraints (Hex : String) return PP.Policy_Constraints
      is (PP.Constraints_Of
            (X509C.Decode_DER
               (From_Hex (Hex), CryptoLib.ASN1.Default_Limits, Status)));
   begin
      --  0x80000000: one past what Natural holds, and with the top bit set
      --  it is a negative INTEGER, which SkipCerts (0..MAX) does not allow.
      --  Malformed, not merely large.
      declare
         Negative : constant PP.Policy_Constraints :=
           Constraints (Skip_Negative_DER);
      begin
         Check (Negative.Present, "the extension is there to be judged");
         Check (not Negative.Well_Formed,
                "a negative SkipCerts is refused rather than folded into a "
                & "positive one");
      end;

      --  4294967295, written the long way and genuinely positive. A CA
      --  meaning "never" this way is not writing a bad certificate, so it
      --  is clamped rather than refused -- any value at or past the length
      --  of the path counts down identically.
      declare
         Huge : constant PP.Policy_Constraints := Constraints (Skip_Huge_DER);
      begin
         Check (Huge.Well_Formed,
                "a large but valid SkipCerts is usable");
         Check (Huge.Has_Require_Explicit
                and then Huge.Require_Explicit = Natural'Last,
                "clamped to what Natural holds, got"
                & Natural'Image (Huge.Require_Explicit));
      end;

      --  A leading zero octet that clears no sign bit is not the minimal
      --  form, and DER has exactly one encoding per value.
      declare
         Padded : constant PP.Policy_Constraints :=
           Constraints (Skip_Non_Minimal_DER);
      begin
         Check (not Padded.Well_Formed,
                "a non-minimal SkipCerts is refused, as it would be with "
                & "its own INTEGER tag on it");
      end;

      --  And the ordinary case still reads as itself.
      declare
         Plain : constant PP.Policy_Constraints := Constraints (Skip_Plain_DER);
      begin
         Check (Plain.Well_Formed
                and then Plain.Has_Require_Explicit
                and then Plain.Require_Explicit = 5,
                "an ordinary SkipCerts is unaffected, got"
                & Natural'Image (Plain.Require_Explicit));
      end;
   end Check_Policy_Constraint_Skipcerts;

   --  AUnit routine wrappers. Each check is a test of its own, so a
   --  failure reports the check that failed and the rest still run.
   procedure Run_Check_Policy_Processing (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Policy_Qualifiers (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Policy_Aware_Path_Building (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Self_Issued_Policy_Allowance (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Policy_Tree_Bound (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Policy_Set_Is_A_Set (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Check_Policy_Constraint_Skipcerts (Item : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Check_Policy_Processing (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Policy_Processing;
   end Run_Check_Policy_Processing;

   procedure Run_Check_Policy_Qualifiers (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Policy_Qualifiers;
   end Run_Check_Policy_Qualifiers;

   procedure Run_Check_Policy_Aware_Path_Building (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Policy_Aware_Path_Building;
   end Run_Check_Policy_Aware_Path_Building;

   procedure Run_Check_Self_Issued_Policy_Allowance (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Self_Issued_Policy_Allowance;
   end Run_Check_Self_Issued_Policy_Allowance;

   procedure Run_Check_Policy_Tree_Bound (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Policy_Tree_Bound;
   end Run_Check_Policy_Tree_Bound;

   procedure Run_Check_Policy_Set_Is_A_Set (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Policy_Set_Is_A_Set;
   end Run_Check_Policy_Set_Is_A_Set;

   procedure Run_Check_Policy_Constraint_Skipcerts (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Check_Policy_Constraint_Skipcerts;
   end Run_Check_Policy_Constraint_Skipcerts;

   overriding procedure Register_Tests (Item : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (Item, Run_Check_Policy_Processing'Access, "policy processing");
      Register_Routine (Item, Run_Check_Policy_Qualifiers'Access, "policy qualifiers");
      Register_Routine (Item, Run_Check_Policy_Aware_Path_Building'Access, "policy aware path building");
      Register_Routine (Item, Run_Check_Self_Issued_Policy_Allowance'Access, "self issued policy allowance");
      Register_Routine (Item, Run_Check_Policy_Tree_Bound'Access, "policy tree bound");
      Register_Routine (Item, Run_Check_Policy_Set_Is_A_Set'Access, "policy set is a set");
      Register_Routine (Item, Run_Check_Policy_Constraint_Skipcerts'Access, "policy constraint skipcerts");
   end Register_Tests;

   overriding function Name (Item : Test_Case) return AUnit.Message_String is
      pragma Unreferenced (Item);
   begin
      return AUnit.Format ("cryptolib X.509 policies");
   end Name;

end Tests_X509_Policies;
