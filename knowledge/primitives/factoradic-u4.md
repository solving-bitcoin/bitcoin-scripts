# Checked factoradic (Lehmer code) decoding

`arithmetic::factoradic` decodes a width-`n` factoradic (Lehmer) code
`c_0 .. c_{n-1}` with the descending per-position domains `0 <= c_i < n-i`
into the single integer `v = c_0 (n-1)! + c_1 (n-2)! + ... + c_{n-1} 0!`,
the lexicographic rank of a permutation of `n` objects. It is the mixed-radix
staircase sibling of the fixed-radix decoders in this atlas: one digit per
witness item, one value out, checked per position. It exposes two distinct
APIs with the same stack contract:

| API | Input check | Width range | Standalone peak |
| --- | --- | --- | --- |
| `u4_lehmer_to_value(n)` | numeric range `0..=n-1-i` per position | `1..=12` | `22` at 12 |
| `u4_lehmer_to_value_canonical(n)` | numeric range plus canonical ScriptNum encoding | `1..=12` | `22` at 12 |

- **Input:** `preserved | c_{n-1} | ... | c_1 | c_0`, with `c_0` on top.
- **Output:** `preserved | v`, one item with `0 <= v < n!`.
- **Evidence:** `locally-reproduced` by exhaustive small-width rank tests,
  seeded random ranks, zero/max codewords, per-position out-of-bounds and
  hostile-encoding tests, and a strict metric fixture for the width-12
  configuration of both APIs.
- **Execution class:** `unclassified`. The local strict executor runs the
  fragments in tapscript context with the combined stack limit; no Bitcoin
  Core consensus or relay-policy transaction has been tested.

## Representation

The factoradic system represents every integer in `0..n!` with `n` digits of
a descending mixed radix `(n-1)!, (n-2)!, ..., 0!`. Because the top digit
bound is `n-1`, the u4 carrier admits widths up to 16; the binding ceiling is
the 4-byte consensus numeric-operand domain. The value accumulates in one
ScriptNum through the Horner ladder `v <- v * (n-i) + c_i`, whose largest
intermediate is the final value `n! - 1`. `12! - 1` is below `2^31 - 1`;
`13! - 1` exceeds it, and the terminal `OP_WITHIN` self-check would reject
the maximum codeword, so the generator accepts `1 <= n <= 12`
(`FACTORADIC_U4_MAX_WIDTH`).

The Horner step multiplies by the generation-time constant `n - i` with
unrolled repeated addition. The `OP_MUL` opcode family fails every script
that executes it, so it is not an implementation; every repeated-addition
partial sum is at most `n! - 1`, inside the operand domain. At width 12 the
ladder contributes the 157 static non-push opcodes behind the
185-byte range-checked fragment.

## Numeric-range API

`u4_lehmer_to_value` proves every digit with a per-position
`OP_DUP 0 (n-i) OP_WITHIN OP_VERIFY` before any arithmetic, so a negative,
above-bound, or oversized digit fails the fragment rather than corrupting the
result. The range check protects the accumulation but does not establish a
byte-unique ScriptNum encoding. Under the local consensus profile, which does
not apply MINIMALDATA to consumed numbers, a non-minimal alias of an in-range
value (for example `0x0100` for 1) is accepted and projected like the minimal
value; the policy profile and the default research helpers reject it only
because the interpreter enforces MINIMALDATA. Focused tests execute the exact
width-12 fragment with the all-maximum codeword under the strict profile:
185 policy-compiled script bytes, 24 serialized witness bytes over 12 data
items (zero is the empty item; every nonzero digit is one byte), 22 combined
stack items, and no hints. The fragment-only boundary includes the 12 range
checks, the Horner ladder, and the terminal self-check; it excludes witness
serialization, terminal predicates, unrelated live state, and transaction
context.

## Canonical-encoding API

The canonical variant answers whether the same accumulator can bind byte-
unique minimal ScriptNum encodings. It replaces only the per-digit check with
`verify_canonical_nibble()` followed by the same per-position range check,
rejecting redundant sign bytes and negative zero as well as negative and
out-of-range values. At width 12 it costs 305 bytes versus 185 for the
numeric-range form; the standalone peak stays at 22 items because the
canonical check reuses the range-check window. Focused tests execute the
alias `0x0100` under the local consensus profile: the numeric-range API
accepts it and the canonical API rejects it from the fragment, not from
MINIMALDATA (the test asserts the error class). The fragment-only boundary
includes the canonical checks, range checks, ladder, and self-check; it
excludes the same items as the numeric-range boundary.

## Composition

Both variants are decoder fragments, not complete locking scripts: callers
still need a terminal predicate (for example `OP_NUMEQUAL OP_VERIFY` against
an expected rank) and any required clean-stack behavior. Use the canonical
API whenever the protocol needs a byte-unique witness encoding; the
numeric-range API alone does not provide one. The fragment consumes every
digit item and leaves one output, so unrelated live main-stack state simply
stays below the digit items; the 22-item width-12 peak leaves a large margin
under the 1,000-item combined limit even with preserved state. Wider
factoradic domains (`n >= 13`) need a wider numeric domain, such as a bigint
or RNS carrier, and are a separate construction.

See the [implementation README](../../src/arithmetic/factoradic/README.md),
the [arithmetic comparison](../comparisons/arithmetic.md), and the catalog
record `arithmetic/factoradic-u4`.
