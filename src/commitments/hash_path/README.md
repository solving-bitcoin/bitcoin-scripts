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
opcodes, `5n+5` fits 39 bits and `7n+5` fits 28. That wrapper, signature checks,
checkpoint pinning and Lamport binding are not implemented or measured here.

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
