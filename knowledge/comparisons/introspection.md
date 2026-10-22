# Transaction introspection

These rows separate the reported full Binohash protocol, host-side mechanics,
and two reduced funded Core fixtures. Consensus acceptance does not establish
default relay acceptance.

| Construction | Boundary | Evidence | Execution | Main limitation |
| --- | --- | --- | --- | --- |
| Binohash transaction digest | Full two-round signature grinding, transaction mutation, and Script extraction | reported | unclassified | No complete local reproduction or Core regtest |
| Binohash legacy core | Opcode-boundary `FindAndDelete` plus legacy sighash | locally-reproduced | unclassified | No grinding, complete spend, or Script consumer |
| Binohash two-choice fixture | Two signed P2SH spends with selected embedded signatures and a wrong-selection control | differentially-validated | consensus-validated | Default policy rejects `CONST_SCRIPTCODE`; no grinding or Script consumer |
| Binohash 2-of-3 toy subset | `OP_ROLL` chooses two embedded signatures; size filter and selected-index preimage check | differentially-validated | consensus-validated | Toy nonce space, public preimages, no pinning/two-round grind; default policy rejects `CONST_SCRIPTCODE` |

The host-side core has no script, witness, stack, or validation-weight metric.
The funded fixture has a 23-byte P2SH locking scriptPubKey, a 220-byte
redeemScript, and complete transaction weights
of 1,744/1,740 WU; it has zero witness/hint items and no measured stack peak.
The 2-of-3 toy has a 23-byte P2SH locking scriptPubKey, a 493-byte redeemScript,
and two 2,908-WU complete spends, also with zero witness/hint items and no measured
stack peak. The 71-byte size filter is a toy condition, not a work estimate.
Full protocol costs remain [OP-011](../open-problems.md#op-011--reproduce-binohash).
