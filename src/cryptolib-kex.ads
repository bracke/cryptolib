--  @summary Root package for the SSH key-exchange (KEX) subsystem; a
--  preelaborable namespace parent for the concrete KEX method children.
package CryptoLib.Kex
  with SPARK_Mode => On
is
   pragma Preelaborate;
end CryptoLib.Kex;
