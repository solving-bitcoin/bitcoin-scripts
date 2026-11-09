# Transaction introspection

These rows separate the reported full Binohash protocol, host-side mechanics,
and two reduced funded Core fixtures. Consensus acceptance does not establish
default relay acceptance.

| Construction | Boundary | Evidence | Execution | Main limitation |
| --- | --- | --- | --- | --- |
| Binohash transaction digest | Full two-round signature grinding, transaction mutation, and Script extraction | reported | unclassified | No complete local reproduction or Core regtest |
| Binohash legacy core | Opcode-boundary `FindAndDelete` plus legacy sighash | locally-reproduced | unclassified | No grinding, complete spend, or Script consumer |
| Binohash six-mode mutation matrix | Eight field mutations per canonical legacy sighash mode on a fixed host template | locally-reproduced | unclassified | No signed spends or Core validation; out-of-range SINGLE is non-committing |
| Binohash exact DER-size nonce probe | Fixed-digest deterministic nonce-data search for one 70-byte signature, with size and ECDSA controls | differentially-validated | policy-validated | One P2SH signature, no subset, field pinning, two-round grind, or Script-readable digest |
| Binohash 10-choose-5 host probe | All 252 ascending subsets over one fixed template | locally-reproduced | unclassified | Dummy deletion targets; order/duplicate aliases need Script-side canonicalization |
| Binohash two-choice fixture | Two signed P2SH spends with selected embedded signatures and a wrong-selection control | differentially-validated | consensus-validated | Default policy rejects `CONST_SCRIPTCODE`; no grinding or Script consumer |
| Binohash 2-of-3 toy subset | `OP_ROLL` chooses two embedded signatures; size filter and selected-index preimage check | differentially-validated | consensus-validated | Toy nonce space, public preimages, no pinning/two-round grind; default policy rejects `CONST_SCRIPTCODE` |
| Binohash raw flag census | 256 disjoint signed P2SH spends plus fixed-template host digests | differentially-validated | consensus-validated | Only six canonical flags pass default policy; no subset grind or security bound |
| Binohash nine-byte SINGLE anchor | Hardcoded minimal DER signature verifies only under out-of-range `SIGHASH_SINGLE` in a funded P2SH spend | differentially-validated | consensus-validated | The bug digest commits to no transaction fields; default policy rejects `CONST_SCRIPTCODE` |
| Binohash CODESEPARATOR fixture | Executed/dead separator boundaries plus before/after-boundary `FindAndDelete` in two funded P2SH spends | differentially-validated | consensus-validated | Default policy rejects executed legacy `OP_CODESEPARATOR`; no grinding or full protocol |

The host-side core has no script, witness, stack, or validation-weight metric.
The funded fixture has a 23-byte P2SH locking scriptPubKey, a 220-byte
redeemScript, and complete transaction weights
of 1,744/1,740 WU; it has zero witness/hint items and no measured stack peak.
The 2-of-3 toy has a 23-byte P2SH locking scriptPubKey, a 493-byte redeemScript,
and two 2,908-WU complete spends, also with zero witness/hint items and no measured
stack peak. The 71-byte size filter is a toy condition, not a work estimate.
The raw-flag census uses a 23-byte P2SH locking scriptPubKey, a 35-byte
redeemScript, and complete spend weights of 804–812 WU. It has zero
witness/hint items and no measured stack peak. Its six canonical flag rows
are additionally `policy-validated` for the pinned node options.
The nine-byte anchor has a 23-byte P2SH scriptPubKey, a 45-byte redeemScript,
and a 732-WU complete valid spend, also with zero witness/hint items.
The CODESEPARATOR fixture has a 23-byte P2SH scriptPubKey, a 229-byte
redeemScript and two 1,780-WU complete transactions. It also has zero
witness/hint items and no measured stack peak.
Full protocol costs remain [OP-011](../open-problems.md#op-011--reproduce-binohash).
The [8-of-n planning report](../../research/binohash-parameters/README.md)
separately checks exact subset counts and applies the paper's approximate
resource formulas. Its modeled hit probabilities depend on independent uniform
trials; they are not a Core execution or security result.
