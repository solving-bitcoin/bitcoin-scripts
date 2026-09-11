# Transaction introspection

These rows separate the reported full Binohash protocol from the locally
reproduced deterministic legacy mechanics. Neither row is a deployability
claim.

| Construction | Boundary | Evidence | Execution | Main limitation |
| --- | --- | --- | --- | --- |
| Binohash transaction digest | Full two-round signature grinding, transaction mutation, and Script extraction | reported | unclassified | No complete local reproduction or Core regtest |
| Binohash legacy core | Opcode-boundary `FindAndDelete` plus legacy sighash | locally-reproduced | unclassified | No grinding, complete spend, or Script consumer |

The host-side core has no script, witness, stack, or validation-weight metric:
those quantities begin at the complete legacy transaction and Script boundary,
which remains [OP-011](../open-problems.md#op-011--reproduce-binohash).
