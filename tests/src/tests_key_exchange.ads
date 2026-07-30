--  Finite-field Diffie-Hellman and the post-quantum KEMs.
--
--  Each procedure is one group of known-answer or negative tests, and
--  is called from the Tests driver. Splitting the suite by topic is
--  what keeps any one file readable; the driver keeps the order.
package Tests_Key_Exchange is

   procedure Check_DH_Peer_Validation;

   procedure Check_DH_Group14;

   procedure Check_DH_Group1;

   procedure Check_DH_Generators;

   procedure Check_Gex_Group_Selection;

   procedure Check_Hybrid_PQ_Names;

   procedure Check_MLKEM_Core_Algebra;

end Tests_Key_Exchange;
