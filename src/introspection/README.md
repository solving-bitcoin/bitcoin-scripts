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

The public digest API accepts a `u32` for compatibility but rejects values
above `0xff`: a legacy ECDSA signature appends one sighash byte. The focused
boundary test shows that rust-bitcoin's raw `0x00` and `0x100` digests differ
for one fixed template, although `0x100` cannot be selected by such a
signature. See [NR-111](../../knowledge/negative-results/index.md#nr-111-high-byte-legacy-sighash-types-are-host-only-digests).

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
the legacy `SIGHASH_SINGLE` bug constant, invalid selections, invalid input
indices, and out-of-byte-range sighash flags. The host helper alone remains `unclassified`; the separate funded
configuration is `differentially-validated` against Core v30.3 and
`consensus-validated`, but fails default relay policy.

The [six-mode mutation matrix](../../research/binohash-sighash-matrix/README.md)
checks which transaction-field changes affect the selected digest in a fixed
host-side template. It also isolates the non-committing out-of-range
`SIGHASH_SINGLE` case; this result alone remains `unclassified` for execution.

The [raw sighash-byte census](../../research/binohash-sighash-flags/README.md)
independently signs all 256 flag values in P2SH spends. Its canonical `01`
sample has this complete-transaction boundary:

| P2SH scriptPubKey | RedeemScript in scriptSig | Complete spend | scriptSig | Witness items | Hint items |
| ---: | ---: | ---: | ---: | ---: | ---: |
| <!-- metric:binohash_flag_lock -->23<!-- /metric:binohash_flag_lock --> bytes | <!-- metric:binohash_flag_redeem -->35<!-- /metric:binohash_flag_redeem --> bytes | <!-- metric:binohash_flag_weight -->808<!-- /metric:binohash_flag_weight --> WU | <!-- metric:binohash_flag_scriptsig -->108<!-- /metric:binohash_flag_scriptsig --> bytes | 0 | 0 |

The sample uses a plain `OP_CHECKSIG`, without Binohash subset selection or
grinding. Stack peak and executed opcode count remain unmeasured.

The [10-choose-5 host probe](../../research/binohash-ten-choose-five/README.md)
enumerates all 252 ascending subsets for one fixed transaction and scriptCode.
It finds distinct local digests for this fixture, while permutations and
duplicate index vectors alias unless a Script consumer validates them. It does
not execute ECDSA or Core consensus.

The [nine-byte SINGLE anchor](../../research/binohash-single-anchor/README.md)
is another raw legacy P2SH fixture. A recovered public key verifies an
embedded minimum-size ECDSA signature only when input index 1 exceeds the
one-output count. Pinned Core accepts that spend and rejects adding an output
or moving the anchor to input index 0. Its checked complete-transaction
boundary is:

| P2SH scriptPubKey | RedeemScript in scriptSig | Complete spend | Easy scriptSig | Anchor scriptSig | Witness items | Hint items |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| <!-- metric:binohash_anchor_lock -->23<!-- /metric:binohash_anchor_lock --> bytes | <!-- metric:binohash_anchor_redeem -->45<!-- /metric:binohash_anchor_redeem --> bytes | <!-- metric:binohash_anchor_weight -->732<!-- /metric:binohash_anchor_weight --> WU | <!-- metric:binohash_anchor_easy_sig -->2<!-- /metric:binohash_anchor_easy_sig --> bytes | <!-- metric:binohash_anchor_main_sig -->46<!-- /metric:binohash_anchor_main_sig --> bytes | 0 | 0 |

Combined stack peak and executed opcode count were not measured. The valid
spend is consensus-valid but fails default relay policy under
`CONST_SCRIPTCODE`.

The separate [CODESEPARATOR fixture](../../research/binohash-codesep/README.md)
requires its caller to identify the suffix after the last executed separator
and to omit all parsed separator opcodes before calling rust-bitcoin's legacy
sighash API. Two funded Core spends validate selected embedded signatures on
both sides of that boundary, plus an unexecuted separator. This does not turn
the host helper into a Script evaluator: arbitrary control flow still requires
an independently established execution path.
