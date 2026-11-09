# Binary hash-path commitments

Authenticate a bit string with `F0(x) = RIPEMD160(x)` and
`F1(x) = RIPEMD160(SHA256(x))`. Every step produces 20 bytes; there is no
terminal hash. **This changes all commitments relative to the former
SHA256/RIPEMD160 branch construction.** No old-digest compatibility is implied.

## Parameters

`bit_width` is required (no default), positive for generic paths and `1..=31`
for integer adapters. Integers must fit that width. The host and script both
reject empty paths. `preimage` is caller-chosen and at most 520 bytes on-chain;
`commitment` is 20 bytes. No variant is selected implicitly.

## Script metrics

Metrics are fragment-only: input pushes and the caller's output predicate are
excluded; witness bytes include CompactSize item counts and lengths. Sizes use
`compile_with_policy()` with optimization enabled. Stack peaks combine main
and alt stacks. Metric execution uses bitcoin-scriptexec
`702544c9a045ac4fc14846da6da6559e2b7cd9d1` in tapscript mode with the stack
limit disabled (`research-unlimited`). The retained-bit row uses strict local
stack checks (`unclassified`); neither row is Core consensus or relay-policy
validation.

| Fragment | Locking script | Unlocking witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| `verify_hash_path_to_integer(31, commitment)` | <!-- metric:hash_path_integer_31 -->457<!-- /metric:hash_path_integer_31 --> bytes | <!-- metric:hash_path_integer_witness_31 -->78<!-- /metric:hash_path_integer_witness_31 --> bytes (32-byte nonce, 31 bits) | <!-- metric:hash_path_integer_stack_31 -->33<!-- /metric:hash_path_integer_stack_31 --> |
| `verify_hash_path_to_altstack(31, commitment)` | <!-- metric:hash_path_altstack_31 -->302<!-- /metric:hash_path_altstack_31 --> bytes | <!-- metric:hash_path_altstack_witness_31 -->78<!-- /metric:hash_path_altstack_witness_31 --> bytes, 32 data items, 0 hints (<!-- metric:hash_path_altstack_witness_max_31 -->96<!-- /metric:hash_path_altstack_witness_max_31 --> maximum) | <!-- metric:hash_path_altstack_stack_31 -->33<!-- /metric:hash_path_altstack_stack_31 --> |

The raw path uses exactly `5n` static legacy-counted opcodes. Retaining bits
uses `7n`; OP_0/OP_1 are pushes and do not count. The verification comparison
adds one counted opcode. Integer reconstruction adds five per bit. Static
counts include inactive branches and are distinct from executed opcodes.
For a hypothetical polyglot wrapper with exactly five additional counted
opcodes, `5n+5` fits 39 bits and `7n+5` fits 28. The hypothetical polyglot wrapper and signature/Lamport binding remain
unimplemented. The tapscript checkpoint pin is measured below.

## Security

**The starting preimage must be independently bound.** Otherwise `(x, 1)`
and `(SHA256(x), 0)` have identical first-step states, even when both preimages
are 32 bytes. Appending the same suffix preserves the equality. The verifier
alone therefore does not bind the integer for freely chosen preimages. See
[NR-056](../../../knowledge/negative-results/index.md#nr-056-optional-sha256-hash-paths-do-not-bind-a-free-starting-preimage).


The 160-bit state caps generic collision resistance at 80 bits and generic
preimage resistance at 160 bits; these are upper bounds, not a security proof
for this construction. Hiding depends on entropy in unrevealed preimages/bits.
Public preimages allow enumeration of small bit strings. Fix path lengths,
participant order and checkpoints externally. Nested paths equal the joined
bit path; boundaries carry no domain separation. No one-time key is used by
this primitive. A later Lamport/Binohash binding must use the **normalized
retained bits**, with its own one-time-key obligations.

## Script compatibility and standardness

Opcodes are available in bare script, P2SH, P2WSH and tapscript. Bare custom
outputs are non-standard; P2SH imposes a 520-byte redeem-script limit; legacy
and P2WSH impose the 201-opcode limit. The 31-bit integer adapter exceeds that
opcode limit. Tapscript requires canonical IF operands (`[]` or `[01]`). Legacy
accepts general Script truthiness; P2WSH accepts it at consensus but MINIMALIF
relay policy restricts it. Normalizing the output does not bypass MINIMALIF.
See [script types](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md).

## Witness and hints

Witness order is `bitN-1, ..., bit0, preimage` (top at right), processing least
significant first. The helper emits `[]` / `[01]`. There are **0 hint items**;
a path has `n+1` data items, all present at entry (32 for the measured case).
Selectors are hostile. Saved bits are created inside the selected branch,
never copied from selector bytes. Without unrelated state, retained paths
need at most `n+2` combined items; unrelated state counts toward 1,000 as well.

## Stack contract

`hash_path_script` consumes the opening and leaves a digest. `verify_hash_path`
leaves true. `verify_hash_path_to_altstack` leaves true and normalized bits
with bit `N-1` on top of the altstack. Integer verification consumes those
saved bits and leaves the integer; append a predicate to obtain clean truthy
success (zero is a valid committed integer). Pre-existing altstack entries are
preserved. Retained-bit consumers must manage their own cleanup.

## Operational notes

Tests cover all 256 eight-bit paths across consumed, retained and integer
forms; seven noncanonical selectors, negative zero, wrong openings/preimages,
empty paths, integer boundaries and nested composition. Opcode tests inspect
policy-produced bytecode. Direct Legacy tests enable the stack limit;
helper-based tapscript tests disable it. Neither proves cryptographic security.

The older hash function can also retain normalized bits using seven counted
opcodes per step (`SWAP IF RIPEMD160 1 ELSE 0 ENDIF TOALTSTACK`), plus its
terminal RIPEMD160. That is an alternative with different digests, not this API.

## Knowledge-base integration

See [the knowledge page](../../../knowledge/primitives/hash-path-integer.md),
[comparison](../../../knowledge/comparisons/commitments.md), catalog record
`commitment/hash-path-integer`, and OP-002/OP-003/OP-020.
Opcode counting, truthiness and MINIMALIF follow
[Bitcoin Core v29.0 interpreter.cpp](https://github.com/bitcoin/bitcoin/blob/v29.0/src/script/interpreter.cpp).

## Two-round composition

`verify_hash_path_chain` checks the first digest and feeds it into the second
path without serialization. The witness holds the second round's reversed bits,
then the first round's reversed bits and its preimage. The first preimage still
needs independent binding; the intermediate checkpoint does not repair NR-056.

| Configuration | Locking script | Serialized witness | Combined stack peak |
| --- | ---: | ---: | ---: |
| Two-round 4+3 bits | <!-- metric:hash_path_chain_4_3 -->80<!-- /metric:hash_path_chain_4_3 --> bytes | <!-- metric:hash_path_chain_4_3_witness -->45<!-- /metric:hash_path_chain_4_3_witness --> bytes | <!-- metric:hash_path_chain_4_3_stack -->8<!-- /metric:hash_path_chain_4_3_stack --> |

The complete chain predicate has <!-- metric:hash_path_chain_4_3_opcodes -->38<!-- /metric:hash_path_chain_4_3_opcodes --> static non-push opcodes,
eight input data items and **0 hints**, all coexisting at entry. Pinning the
initial state is excluded. Execution is `research-unlimited` via the tapscript
helper with stack checks disabled. The final predicate leaves one true item.

## Pinned starting state and streamed checkpoints

`pinned::verify(starting_sha256, checkpoints)` checks an independently committed
starting preimage before running the existing binary hash paths. The public
start pin is a 32-byte SHA-256 digest. Supply one or more `(width, digest)`
checkpoints in processing order, each with positive width and a 20-byte digest;
total width `k` is at most 997. There are no defaults. The nonce is an arbitrary
byte vector subject to the 520-byte consensus element limit. Tapscript enforces
canonical empty/01 selectors.

### Script metrics

`complete-transaction:` all rows include checkpoint verification, a final
Boolean and clean stack, a one-input Taproot script-path spend with a 33-byte
control block and no annex, and its P2WSH output. The three 4+3-bit rows use the
same opening (`[0x42;32]`, LSB-first values 13 and 3). The 997-bit rows use the
same nonce and separate all-zero/all-one commitments. Data and complete witness
bytes each include CompactSize counts and lengths. Complete witness bytes
already include the leaf. No row uses hints (0 items, 0 bytes). All measured
leaves use the optimizer through `compile_with_policy()`.

| Configuration | Script bytes | Data witness bytes | Complete witness bytes | Data items | Combined peak | Executed non-push ops | Initial / remaining budget (same) | Transaction weight |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Unbound control, 4+3 | <!-- metric:pinned_chain_unbound_4_3_script -->80<!-- /metric:pinned_chain_unbound_4_3_script --> | <!-- metric:pinned_chain_unbound_4_3_data -->46<!-- /metric:pinned_chain_unbound_4_3_data --> | <!-- metric:pinned_chain_unbound_4_3_witness -->161<!-- /metric:pinned_chain_unbound_4_3_witness --> | <!-- metric:pinned_chain_unbound_4_3_items -->8<!-- /metric:pinned_chain_unbound_4_3_items --> | <!-- metric:pinned_chain_unbound_4_3_stack -->8<!-- /metric:pinned_chain_unbound_4_3_stack --> | <!-- metric:pinned_chain_unbound_4_3_executed -->36<!-- /metric:pinned_chain_unbound_4_3_executed --> | <!-- metric:pinned_chain_unbound_4_3_budget -->211<!-- /metric:pinned_chain_unbound_4_3_budget --> | <!-- metric:pinned_chain_unbound_4_3_weight -->539<!-- /metric:pinned_chain_unbound_4_3_weight --> |
| Length-only control, 4+3 | <!-- metric:pinned_chain_length_4_3_script -->84<!-- /metric:pinned_chain_length_4_3_script --> | <!-- metric:pinned_chain_length_4_3_data -->46<!-- /metric:pinned_chain_length_4_3_data --> | <!-- metric:pinned_chain_length_4_3_witness -->165<!-- /metric:pinned_chain_length_4_3_witness --> | <!-- metric:pinned_chain_length_4_3_items -->8<!-- /metric:pinned_chain_length_4_3_items --> | <!-- metric:pinned_chain_length_4_3_stack -->10<!-- /metric:pinned_chain_length_4_3_stack --> | <!-- metric:pinned_chain_length_4_3_executed -->38<!-- /metric:pinned_chain_length_4_3_executed --> | <!-- metric:pinned_chain_length_4_3_budget -->215<!-- /metric:pinned_chain_length_4_3_budget --> | <!-- metric:pinned_chain_length_4_3_weight -->543<!-- /metric:pinned_chain_length_4_3_weight --> |
| Pinned start, 4+3 | <!-- metric:pinned_chain_4_3_script -->116<!-- /metric:pinned_chain_4_3_script --> | <!-- metric:pinned_chain_4_3_data -->46<!-- /metric:pinned_chain_4_3_data --> | <!-- metric:pinned_chain_4_3_witness -->197<!-- /metric:pinned_chain_4_3_witness --> | <!-- metric:pinned_chain_4_3_items -->8<!-- /metric:pinned_chain_4_3_items --> | <!-- metric:pinned_chain_4_3_stack -->10<!-- /metric:pinned_chain_4_3_stack --> | <!-- metric:pinned_chain_4_3_executed -->39<!-- /metric:pinned_chain_4_3_executed --> | <!-- metric:pinned_chain_4_3_budget -->247<!-- /metric:pinned_chain_4_3_budget --> | <!-- metric:pinned_chain_4_3_weight -->575<!-- /metric:pinned_chain_4_3_weight --> |
| Pinned, 997 zeroes | <!-- metric:pinned_chain_997_zeroes_script -->5043<!-- /metric:pinned_chain_997_zeroes_script --> | <!-- metric:pinned_chain_997_zeroes_data -->1033<!-- /metric:pinned_chain_997_zeroes_data --> | <!-- metric:pinned_chain_997_zeroes_witness -->6113<!-- /metric:pinned_chain_997_zeroes_witness --> | <!-- metric:pinned_chain_997_zeroes_items -->998<!-- /metric:pinned_chain_997_zeroes_items --> | <!-- metric:pinned_chain_997_zeroes_stack -->1000<!-- /metric:pinned_chain_997_zeroes_stack --> | <!-- metric:pinned_chain_997_zeroes_executed -->3992<!-- /metric:pinned_chain_997_zeroes_executed --> | <!-- metric:pinned_chain_997_zeroes_budget -->6163<!-- /metric:pinned_chain_997_zeroes_budget --> | <!-- metric:pinned_chain_997_zeroes_weight -->6491<!-- /metric:pinned_chain_997_zeroes_weight --> |
| Pinned, 997 ones | <!-- metric:pinned_chain_997_ones_script -->5043<!-- /metric:pinned_chain_997_ones_script --> | <!-- metric:pinned_chain_997_ones_data -->2030<!-- /metric:pinned_chain_997_ones_data --> | <!-- metric:pinned_chain_997_ones_witness -->7110<!-- /metric:pinned_chain_997_ones_witness --> | <!-- metric:pinned_chain_997_ones_items -->998<!-- /metric:pinned_chain_997_ones_items --> | <!-- metric:pinned_chain_997_ones_stack -->1000<!-- /metric:pinned_chain_997_ones_stack --> | <!-- metric:pinned_chain_997_ones_executed -->4989<!-- /metric:pinned_chain_997_ones_executed --> | <!-- metric:pinned_chain_997_ones_budget -->7160<!-- /metric:pinned_chain_997_ones_budget --> | <!-- metric:pinned_chain_997_ones_weight -->7488<!-- /metric:pinned_chain_997_ones_weight --> |

The metric test reconstructs the Core transactions, matches their txids,
wtxids and weights, and steps the exact policy-compiled leaf in local tapscript
with the combined stack limit enabled and global MINIMALDATA disabled. It counts
executed non-push operations including IF/ENDIF handlers, excluding skipped
hashes. The budget is initialized from the complete witness; no signature
opcode consumes any of it. Opcode and budget counters are local measurements.
The [Core report](../../../tests/data/pinned-hash-path-v30.3.json) records
interpreter `a09e87af444034698697f0a2267e755cf72f9aed`, compiler
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`, and Core v30.3
`49faec4f87f5cd19c88db01a82e5c68b087c8227`. The harness compares both
embedded Rust identities with `cargo metadata --locked` before the oracle.
Core checks mined regtest blocks and `testmempoolaccept` with
`-acceptnonstdtxn=0`. The recorded accepted spends are `policy-validated`;
the API in general remains `unclassified`.

### Security and composition

The controls accept the known substitution `(x, 1) -> (SHA256(x), 0)` even
with identical first and final checkpoints. A 32-byte length guard still
accepts it. The independent SHA-256 pin rejects it for the recorded opening.
This does not prove general binding for the mixed-hash code. The 160-bit state
caps generic collision security at 80 bits. Hiding requires adequate secret
entropy; public intermediate checkpoints can allow enumeration of short later
rounds. No one-time keys or participant signatures are supplied. Protocols
must fix widths, checkpoint order and session context externally.

Each invocation has `k+1` data items, all present at entry, and **0 hints**;
the complete witness adds two items. For repeated invocations the cumulative
hint count is still **0**. A single invocation with `p` unrelated live main/alt
items needs `k+3+p <= 1000`. The initial check duplicates the preimage and
pushes the digest; subsequent checkpoint comparisons have already consumed
selectors. Include all preloaded data groups and any retained results in `p`.
The 997-bit accepted cases have 998 data items and 1000 complete witness items.
A 999th data item reaches 1001 stack items during the pin and is rejected.

Stack contract: `preserved | reversed round/bit groups | preimage -> preserved |
Boolean`, with top at right. No altstack operations. Standalone tapscript
requires a clean truthy result. A caller composing the fragment must enforce
the Boolean; an incorrect final checkpoint returns false.

### Compatibility and reproduction

The opcodes exist in bare, P2SH, P2WSH and tapscript. The small measured
leaf fits P2SH's 520-byte and legacy/P2WSH's 201-opcode limits, but only
Taproot spends were tested; legacy does not enforce canonical IF selectors.
The 997-bit leaves exceed those legacy opcode and P2SH size limits. The exact
Core policy evidence applies only to the documented Taproot fixtures.

```sh
cargo test --locked commitments::hash_path::pinned --lib
cargo test --locked --example core_validation_fixtures
python3 tools/core_regtest.py --download-core --fixture-prefix pinned-chain- --output target/pinned-chain-core.json
cargo test --locked --test primitive_metrics pinned_chain_metrics_are_current -- --exact
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

See the [knowledge entry](../../../knowledge/primitives/pinned-hash-path-chain.md),
[comparison](../../../knowledge/comparisons/commitments.md), NR-056 and OP-020.
