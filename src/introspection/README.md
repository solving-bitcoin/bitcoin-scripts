# Legacy transaction introspection

This module contains host-side research helpers for transaction-dependent
legacy Script behavior. They are not tapscript fragments and must not be
executed with the repository's default tapscript-only assumptions.

## Binohash core

`binohash::find_and_delete` removes selected serialized signature pushes only
when they occur at Script opcode boundaries. `binohash::binohash_digest` then
passes the mutated `scriptCode` to rust-bitcoin's legacy sighash implementation.
This reproduces the deterministic mutation boundary used by a Binohash-style
subset grind. A separate [funded Core fixture](../../research/binohash-legacy-core/README.md)
constructs fixed ECDSA signatures and executes two complete P2SH spends. The
proof-of-work search and digest extraction into Script remain outside this
helper.

The [2-of-3 subset fixture](../../research/binohash-subset/README.md) separately
uses `OP_ROLL` to choose two embedded signatures and consumes their canonical
indices in a later Script predicate. Its public preimages and small size
filter demonstrate execution only; the full protocol remains open.

The checked Core report fixes its complete-transaction measurement boundary:

| Pair | P2SH scriptPubKey | RedeemScript in scriptSig | Complete spend | First scriptSig | Selected scriptSig | Hint items |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `[0,1]` | <!-- metric:binohash_subset_lock -->23<!-- /metric:binohash_subset_lock --> bytes | <!-- metric:binohash_subset_redeem -->493<!-- /metric:binohash_subset_redeem --> bytes | <!-- metric:binohash_subset_first_weight -->2908<!-- /metric:binohash_subset_first_weight --> WU | <!-- metric:binohash_subset_first_easy_sig -->2<!-- /metric:binohash_subset_first_easy_sig --> bytes | <!-- metric:binohash_subset_first_main_sig -->588<!-- /metric:binohash_subset_first_main_sig --> bytes | 0 |
| `[0,2]` | 23 bytes | 493 bytes | <!-- metric:binohash_subset_second_weight -->2908<!-- /metric:binohash_subset_second_weight --> WU | <!-- metric:binohash_subset_second_easy_sig -->2<!-- /metric:binohash_subset_second_easy_sig --> bytes | <!-- metric:binohash_subset_second_main_sig -->588<!-- /metric:binohash_subset_second_main_sig --> bytes | 0 |

There are six scriptSig data pushes and zero witness items. The report does
not measure a combined stack peak or executed opcode count.

The focused tests cover opcode-boundary deletion, subset-dependent digests,
the legacy `SIGHASH_SINGLE` bug constant, invalid selections, and invalid input
indices. The host helper alone remains `unclassified`; the separate funded
configuration is `differentially-validated` against Core v30.3 and
`consensus-validated`, but fails default relay policy.
