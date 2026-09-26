# Four-way hash-path commitments

Authenticate base-4 digits using two-hash codewords: `0 -> SS`, `1 -> SR`,
`2 -> RS`, `3 -> RR`, with SHA-256 `S` and RIPEMD-160 `R`, followed by a final R.

## Parameters

Integer width is `1..=31` (required, no default), using ceil(width/2) digits.
For odd widths, the leading digit is restricted to 0 or 1. Generic digit paths
are nonempty with digits in 0..=3. Preimages must fit 520 bytes; digests are 20 bytes.

## Script metrics

Metrics are fragment-only: input pushes and the caller's output predicate are
excluded; witness bytes include CompactSize item counts and lengths. Sizes use
`compile_with_policy()` with optimization enabled. Stack peaks combine main
and alt stacks. Metric execution uses bitcoin-scriptexec
`702544c9a045ac4fc14846da6da6559e2b7cd9d1` in tapscript mode with the stack
limit disabled (`research-unlimited`). The retained-digit row uses strict local
stack checks (`unclassified`); neither row is Core consensus or relay-policy
validation.

| Fragment | Locking script | Unlocking witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| `verify_four_way_hash_path_to_integer(31, commitment)` | <!-- metric:four_way_hash_path_integer_31 -->438<!-- /metric:four_way_hash_path_integer_31 --> bytes | <!-- metric:four_way_hash_path_integer_witness_31 -->61<!-- /metric:four_way_hash_path_integer_witness_31 --> bytes (32-byte nonce, 16 digits) | <!-- metric:four_way_hash_path_integer_stack_31 -->19<!-- /metric:four_way_hash_path_integer_stack_31 --> |
| `verify_four_way_hash_path_to_altstack(16, commitment)` | <!-- metric:four_way_hash_path_altstack_16 -->360<!-- /metric:four_way_hash_path_altstack_16 --> bytes | <!-- metric:four_way_hash_path_altstack_witness_16 -->61<!-- /metric:four_way_hash_path_altstack_witness_16 --> bytes, 17 data items, 0 hints (<!-- metric:four_way_hash_path_altstack_witness_max_16 -->66<!-- /metric:four_way_hash_path_altstack_witness_max_16 --> maximum) | <!-- metric:four_way_hash_path_altstack_stack_16 -->20<!-- /metric:four_way_hash_path_altstack_stack_16 --> |

## Security

Generic collision resistance is at most 80 bits; preimage resistance at most
160 bits. Binding assumes the unconventional mixed-hash schedule. Hiding needs
unpredictable opening entropy. No one-time key is required. Do not replace the
fixed-length code with single SHA256/HASH256/RIPEMD160/HASH160 opcodes: those
have structural aliases (negative result NR-012).

## Script compatibility and standardness

Although the opcodes exist in bare script, P2SH and P2WSH, the compact range
check relies on tapscript consensus MINIMALIF and is unsafe in the other
contexts without explicit checks. The measured configuration is tapscript
research; consensus and policy have not been validated. See
[script types](../../../docs/script-types.md) and [standardness](../../../docs/standardness.md).

## Witness and hints

Integer witness order is least-significant digit through most-significant
digit, then preimage; processing is most-significant first. Generic paths use
reverse path order. Digits use minimal ScriptNum encodings. The script binds
digit values, not unique bytes absent MINIMALDATA. There are **0 hint items**,
17 data items for 31 bits, all present at entry. Peak 19 leaves room only for
981 unrelated live items under the combined 1,000-item limit.

## Stack contract

The raw script returns the digest; verification returns true, optionally
retaining the original digit bytes on altstack. The integer adapter returns the integer and
cleans up its accumulator. Append a terminal predicate for clean truthy
success. Generic retained digits leave the last digit on top of altstack.

## Operational notes

Tests cover every codeword, boundaries, odd-width restrictions, malformed
selectors, wrong openings and strict stack execution. Fixed-length scheduling
avoids the recorded aliases but has no dedicated cryptanalysis.

## Knowledge-base integration

See [the knowledge page](../../../knowledge/primitives/four-way-hash-path-integer.md),
[comparison](../../../knowledge/comparisons/commitments.md), catalog record
`commitment/four-way-hash-path-integer`, and NR-012.
