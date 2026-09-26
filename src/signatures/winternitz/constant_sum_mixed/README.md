# Mixed-stage constant-sum Winternitz for 20-byte messages

This experimental terminal construction authenticates every unchanged 20-byte
message with a **1,491-byte verifier and an attained 844-byte maximum serialized
signature: 2,335 bytes combined**. A staged isolation check saves one further
byte, for **2,334 bytes**. This improves the earlier 2,400-byte
constant-composition result under the same fragment-plus-signature boundary.

These totals are bytes, not transaction vbytes. They include embedded public
endpoints, all relation checks, signature cleanup, and witness-vector framing.
They exclude the caller's terminal predicate, Taproot script/control-block
framing, and transaction overhead. Message decoding remains offchain.

## Code and capacity

The construction has 45 independent chains with maximum digit 45. Twelve keys
are assigned digit 45 and remain implicit. Three ordinary slots have fixed
digits 23, 38, and 44. Fifteen pair slots each permit

```text
(u, v) or (u - t, v + t)
```

for positive even `t`. Both choices preserve the pair sum. The exact tuples are
defined by `PAIRS` in [`mod.rs`](mod.rs). Every branch therefore has total digit
sum 1,566. All `2^15` branch masks produce distinct histograms, and the union of
their multinomial classes contains exactly

```text
1474534644173396013943101947755055475538944000000
```

words, approximately `2^160.012808`. A 20-byte big-endian rank selects a class
by cumulative capacity and then a lexicographic permutation within that class.
Exact ranking reverses the mapping. No message hash, padding search, or grinding
is used. Script authenticates the whole union; the host decoder additionally
rejects the unused suffix at ranks `>= 2^160`.

This is a compact feasible construction found by heuristic search, not a proof
of a global optimum over constant-sum codes or Script verifiers. The retained
candidate was recomputed with exact factorial arithmetic and distinct-histogram
deduplication.

## Alternating chains and pair inference

Each private chain starts with 16 bytes. Successive stages alternate SHA256 and
RIPEMD160 so every public endpoint is 20 bytes. From a 20-byte opening the
verifier uses `OP_HASH160`; a 32-byte opening first uses `OP_RIPEMD160` and then
`OP_HASH160`. The fixed geometry reveals 26 narrow nodes and seven wide nodes,
never a 16-byte start, and executes 233 hash opcodes.

For a pair `(u,v,t)`, the verifier first hashes the two openings to asymmetric
checkpoints. Exactly one opening needs another `t/2` HASH160 operations. It uses
equality at the first checkpoint to move that opening into place, hashes it,
and compares both results to their independently selected endpoints. The local
relation costs seven Script bytes beyond the ordinary slots and transmits no
branch bit. Removing each selected endpoint with `OP_ROLL` prevents one key
from satisfying two slots.

The three fixed slots, fifteen pair relations, and twelve implicit endpoints
jointly enforce the admitted constant-sum union. There is no omitted global
sum check.

## Witness and verifier contracts

The witness contains 33 selector/node pairs, 66 data items, and zero auxiliary
hints. Pair selectors are relative to the shrinking endpoint pool. The second
selector adds two because the first endpoint and opening remain on the main
stack until the pair relation has been checked.

Both verifier methods consume the signature, preserve caller-owned altstack
state, reject unrelated main-stack state, and leave no result. The caller must
append a terminal predicate.

| Method | Isolation check | Script | Maximum witness | Combined | Peak |
| --- | --- | ---: | ---: | ---: | ---: |
| `checksig_verify_isolated_and_clear` | Before staging | <!-- metric:w20_mixed_sum_isolated_script -->1491<!-- /metric:w20_mixed_sum_isolated_script --> | <!-- metric:w20_mixed_sum_isolated_witness_max -->844<!-- /metric:w20_mixed_sum_isolated_witness_max --> | <!-- metric:w20_mixed_sum_isolated_total_max -->2335<!-- /metric:w20_mixed_sum_isolated_total_max --> | <!-- metric:w20_mixed_sum_isolated_stack -->111<!-- /metric:w20_mixed_sum_isolated_stack --> |
| `checksig_verify_staged_and_clear` | After staging | <!-- metric:w20_mixed_sum_staged_script -->1490<!-- /metric:w20_mixed_sum_staged_script --> | <!-- metric:w20_mixed_sum_staged_witness_max -->844<!-- /metric:w20_mixed_sum_staged_witness_max --> | <!-- metric:w20_mixed_sum_staged_total_max -->2334<!-- /metric:w20_mixed_sum_staged_total_max --> | <!-- metric:w20_mixed_sum_staged_stack -->111<!-- /metric:w20_mixed_sum_staged_stack --> |

The maximum is attained by message
`000130275c86cf4a987ba62d99451e92b2800000`. For the original entry guard, the
Script breakdown is 945 endpoint-push bytes, 198 bytes for staging/routing and
comparisons, 233 hash opcodes, 105 pair-inference bytes, six cleanup bytes, and
four guard bytes. The serialized maximum witness is 546 bytes for narrow nodes,
231 for wide nodes, 66 for selectors, and one count prefix.

| Profile | Zero witness | `ff` witness | Varied witness | Entry items | Hints | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Entry guard | <!-- metric:w20_mixed_sum_isolated_witness_zero -->843<!-- /metric:w20_mixed_sum_isolated_witness_zero --> | <!-- metric:w20_mixed_sum_isolated_witness_ff -->844<!-- /metric:w20_mixed_sum_isolated_witness_ff --> | <!-- metric:w20_mixed_sum_isolated_witness_varied -->844<!-- /metric:w20_mixed_sum_isolated_witness_varied --> | <!-- metric:w20_mixed_sum_isolated_items -->66<!-- /metric:w20_mixed_sum_isolated_items --> | <!-- metric:w20_mixed_sum_isolated_hints -->0<!-- /metric:w20_mixed_sum_isolated_hints --> | <!-- metric:w20_mixed_sum_isolated_opcodes -->529<!-- /metric:w20_mixed_sum_isolated_opcodes --> |
| Staged guard | <!-- metric:w20_mixed_sum_staged_witness_zero -->843<!-- /metric:w20_mixed_sum_staged_witness_zero --> | <!-- metric:w20_mixed_sum_staged_witness_ff -->844<!-- /metric:w20_mixed_sum_staged_witness_ff --> | <!-- metric:w20_mixed_sum_staged_witness_varied -->844<!-- /metric:w20_mixed_sum_staged_witness_varied --> | <!-- metric:w20_mixed_sum_staged_items -->66<!-- /metric:w20_mixed_sum_staged_items --> | <!-- metric:w20_mixed_sum_staged_hints -->0<!-- /metric:w20_mixed_sum_staged_hints --> | <!-- metric:w20_mixed_sum_staged_opcodes -->529<!-- /metric:w20_mixed_sum_staged_opcodes --> |

The varied fixture has byte `i = (37*i) mod 256`. Metrics are
`locally-reproduced`, `research-unlimited`; separate strict local tests enforce
the 1,000-item stack limit and are `unclassified` for deployment. No Bitcoin
Core consensus or relay validation is claimed for this construction.

## Security boundary

The allowed code is an antichain: every accepted word has the same positive
coordinate sum, so a distinct word cannot be coordinatewise greater. With
independently derived chains, changing an authenticated assignment therefore
requires an earlier node on at least one chain, under the usual inversion and
collision assumptions. The verifier also enforces the smaller admitted union,
not merely its sum. This is a local argument for a custom unkeyed one-time
construction, not a WOTS+ reduction.

Keys are strictly one-time. Consuming the Rust key does not prevent restoring
or concurrently reusing its seed. Sixteen-byte starts cap generic single-target
preimage search at 128 bits before multi-target effects. The 20-byte endpoints
retain an 80-bit generic collision bound. Raw node widths are not checked;
every admitted opening is nevertheless hashed at least once.

## Reproduction

```sh
cargo test --locked signatures::winternitz::constant_sum_mixed
cargo test --locked --test primitive_metrics winternitz20_mixed_sum_metrics_are_current
python3 src/signatures/winternitz/constant_sum_mixed/tests/vectors.py
python3 tools/kb.py validate
```

Only intentional metric changes should use `UPDATE_PRIMITIVE_METRICS=1`.
