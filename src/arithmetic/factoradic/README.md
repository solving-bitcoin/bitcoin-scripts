# Checked factoradic (Lehmer code) decoding

Range-checked decoding of a width-`n` factoradic (Lehmer) code into the single
integer `v = c_0 (n-1)! + c_1 (n-2)! + ... + c_{n-1} 0!`, which is the
lexicographic rank of a permutation of `n` objects. Every witness digit is
hostile raw ScriptNum data: the fragment proves `0 <= c_i < n-i` per position
with `OP_WITHIN` before using it, so an out-of-bounds or negative digit fails
the fragment instead of corrupting the result. The `OP_MUL` opcode family
fails every script that executes it, so the Horner step `v <- v * (n-i) + c_i`
multiplies by the generation-time constant `n-i` with unrolled repeated
addition; all partial sums are at most `n! - 1`.

## Parameters

- `u4_lehmer_to_value(width)` and `u4_lehmer_to_value_canonical(width)` take a
  width in `1..=12` (`FACTORADIC_U4_MAX_WIDTH`). The digit carrier is a u4
  nibble, which would allow widths up to 16; the binding limit is the 4-byte
  consensus numeric-operand domain: the maximum codeword `13! - 1` exceeds
  `2^31 - 1`, which the Horner accumulator and the terminal `OP_WITHIN`
  self-check must fit.
- `u4_lehmer_to_value` proves only the numeric range. Under the local
  consensus profile, which does not apply MINIMALDATA to consumed numbers, a
  non-minimal ScriptNum alias of an in-range value is accepted and normalized
  by the arithmetic; a profile that applies MINIMALDATA (relay policy, also
  applied by the default local research helpers) rejects it at the interpreter
  before the fragment runs.
- `u4_lehmer_to_value_canonical` additionally proves each digit is a byte-
  unique canonical nibble (minimal ScriptNum encoding) before the same range
  check, giving a byte-unique witness encoding under every profile.
- `factorial(n)` computes `n!` for `n <= 20`; `lehmer_value`,
  `lehmer_of_permutation`, and `lexicographic_rank` are deterministic host
  references. There is no default width.

## Script metrics

The representative configuration is the maximum width `12` with the
all-maximum digit vector. Script size is the policy-compiled fragment;
witness size is the serialized witness of the twelve data items (no script,
control block, or annex item); the stack peak is the strict combined
main-plus-alt peak of the fragment with the fragment's single output dropped.
Hint items: `0 (none)` — the fragment takes no auxiliary items.

| Configuration | Locking script | Unlocking witness | Hint items | Maximum stack items |
| --- | ---: | ---: | ---: | ---: |
| Range-checked, width 12 | <!-- metric:factoradic_u4_width12 -->185<!-- /metric:factoradic_u4_width12 --> bytes | <!-- metric:factoradic_u4_width12_witness -->24<!-- /metric:factoradic_u4_width12_witness --> bytes over <!-- metric:factoradic_u4_width12_witness_items -->12<!-- /metric:factoradic_u4_width12_witness_items --> data items | 0 (none) | <!-- metric:factoradic_u4_width12_stack -->22<!-- /metric:factoradic_u4_width12_stack --> items |
| Canonical, width 12 | <!-- metric:factoradic_u4_canonical_width12 -->305<!-- /metric:factoradic_u4_canonical_width12 --> bytes | same as above | 0 (none) | same as above |

The range-checked fragment contains <!-- metric:factoradic_u4_width12_opcodes -->157<!-- /metric:factoradic_u4_width12_opcodes --> static non-push opcodes; that is a generated-code count, not an executed-opcode or validation-budget claim.

## Security

Classically the fragment is a checked mixed-radix decoder: each of the twelve
digits is proven inside its per-position domain before any arithmetic, the
Horner accumulation is exact over ScriptNum, and a terminal `OP_WITHIN`
re-proves `0 <= v < 12!`. There is no one-time-use, signature, or
cryptographic assumption. Witness items are hostile: a digit that is negative,
above its bound, oversized, or a non-minimal alias (in the canonical variant)
fails the fragment. The range-checked variant does not establish a byte-
unique witness encoding; use the canonical variant when the protocol requires
one.

## Script compatibility and standardness

The fragment uses only `OP_DUP`, `OP_0`, small-int pushes, `OP_WITHIN`,
`OP_VERIFY`, `OP_SWAP`, `OP_ADD`, and `OP_NUMEQUAL` (in wrappers): all are
consensus-valid in bare script, P2SH, P2WSH, and tapscript, and none is a
relay-discouraged opcode. The `OP_MUL` family is deliberately absent: those
opcodes fail scripts that execute them. No locktime, signature, or altstack
opcodes appear. See [`docs/script-types.md`](../../../docs/script-types.md) and
[`docs/standardness.md`](../../../docs/standardness.md).

## Witness and hints

The complete witness is exactly the `n` digit data items, pushed with the
most significant digit `c_0` last (on top): `c_{n-1} | ... | c_1 | c_0`.
Zero is the empty item; every nonzero digit is one byte, the minimal
ScriptNum encodings. A complete width-12 wrapper therefore has twelve witness
/data items and no hints; all twelve coexist at script entry. Serialized
witness bytes for the all-maximum vector are 24, as measured in the metrics
table above.
Because the fragment consumes all digit items and leaves one output, unrelated
live main-stack state simply stays below; the measured combined peak is 22
items, leaving a large margin under the 1,000-item combined limit even with
preserved state.

## Stack contract

- **Before:** `preserved | c_{n-1} | ... | c_1 | c_0`, with `c_0` on top and
  every `c_i` a ScriptNum in `0..=15`.
- **After:** `preserved | v`, with `0 <= v < n!`.
- Main-stack peak over the fragment: 22 items for width 12 with no preserved
  state; the repeated-addition window adds at most `n-2` temporary copies of
  the accumulator.
- No altstack use, no hints, no cleanup beyond consuming the digit items.
- The fragment is not a complete locking script: callers must add a terminal
  predicate (for example `OP_NUMEQUAL OP_VERIFY` against an expected rank) and
  any required clean-stack behavior.

## Operational notes

- Focused tests cover the zero and all-maximum codewords, every single-digit
  place value at width 12, exhaustive permutation ranks for widths 1-5,
  seeded random ranks for widths 6-8, out-of-bounds digits at every position,
  hostile encodings (negative, above-range, oversized, negative zero), the
  canonical-versus-alias split under the local consensus profile (rejection
  asserted to come from the fragment, not MINIMALDATA), unrelated-state
  preservation, and the width boundary.
- Width 13 is rejected by the generator, not by the script: `13! - 1` exceeds
  the 4-byte consensus numeric-operand domain, so the terminal self-check
  could not accept the maximum codeword. Wider factoradic domains need a wider
  numeric domain (for example a bigint or RNS carrier); that is a separate
  construction.

## Knowledge-base integration

See the catalog record `arithmetic/factoradic-u4` and the knowledge page
[checked factoradic decoding](../../../knowledge/primitives/factoradic-u4.md),
with the [arithmetic comparison](../../../knowledge/comparisons/arithmetic.md).
Run `python3 tools/kb.py validate` before committing.
