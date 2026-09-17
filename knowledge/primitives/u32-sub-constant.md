# Embedded-constant u32 subtraction

## Research question

Can a public u32 subtrahend be embedded in the locking script so a checked
byte-oriented u32 subtraction uses four witness items instead of the eight
items required by the generic two-word borrow chain?

## Construction and threat model

`u32_sub_constant(value)` consumes the top four canonical byte limbs, checks
each hostile limb with `verify_canonical_byte()`, pushes the public
compile-time `value`, and reuses `u32_sub_drop(0, 1)` for subtraction modulo
`2^32`. It returns the four most-significant-byte-first result limbs. The
constant is script data, not a secret. Temporary borrow values use the
altstack and are removed before return; unrelated main- and alt-stack items
are preserved.

The input witness is hostile. The checks reject negative values, values above
255, and non-minimal ScriptNum aliases before the borrow chain uses them.

## Comparison objective and boundary

The objective is witness width and entry-item count when the subtrahend is
public, compared with the existing `u32_sub_drop(0, 1)` under the same
byte-limb representation. The `fragment-with-memory` boundary includes the
four input canonicality checks, the embedded constant push, the modulo-`2^32`
borrow chain, and borrow cleanup. It excludes witness pushes, terminal
predicates, unrelated live state, and transaction framing.

| Construction | Locking script | Representative witness | Maximum witness | Data items | Hint items | Peak items | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Embedded constant `0x89abcdef` | 141 | 9 bytes | 13 bytes | 4 | 0 | 9 | 79 |
| Generic two-word subtract, same values | 77 | 21 bytes | — | 8 | 0 | 9 | — |

The embedded form saves 12 representative witness bytes and four entry items,
at the cost of 60 locking-script bytes. It is therefore a narrow witness
shape adapter, not a general byte-cost improvement. Its measured strict peak
is equal to the unvalidated generic subtraction because the
canonicality checks are part of this checked boundary.

## Evidence and execution class

Evidence is `locally-reproduced`; deployment is `unclassified`. The measured
fixture uses `value = 0x12345678` and `constant = 0x89abcdef`. Correctness
tests cover zero, maximum values, underflow, borrow propagation, wraparound,
and a mixed pair. Adversarial tests cover negative, out-of-range, and
non-minimal raw limb encodings, plus surrounding main- and alt-stack state.

The strict metric fixture executes through the repository's locked
`bitcoin-scriptexec` dependency in a tapscript context with the combined
main-plus-alt-stack limit. The executor does not provide a useful dynamic
opcode count, so 81 is a static non-push opcode count, not an execution or
validation-weight claim. No Bitcoin Core differential, complete-transaction,
relay-policy, or cryptographic claim is made.

## Parameters and witness

- `value` is any public `u32`; there is no default.
- The witness supplies four canonical numeric byte limbs in
  most-significant-byte-first order, with the least-significant limb on top.
- The complete measured input has four data items and zero hint items. No
  hints are required, and no hint items coexist at entry.
- The maximum 13-byte witness fixture uses four canonical `0x80` limbs. The
  1,000-item composition limit must still include any caller-owned state,
  outputs, tables, or other fragments.

## Script compatibility and standardness

The fragment uses ordinary arithmetic, stack, and altstack opcodes available
in legacy Script, P2SH, P2WSH, and tapscript. Its isolated static opcode count
is below the historical 201-opcode P2SH/P2WSH limit, but the complete locking
script and its transaction context determine consensus validity. Relay and
mining policy are separate questions; this primitive does not establish
standardness. See [`script-types.md`](../../docs/script-types.md) and
[`standardness.md`](../../docs/standardness.md).

## Stack contract

Before: `... | a3 | a2 | a1 | a0`, with four canonical byte-valued items at
the top of the main stack.

After: `... | (a - value)3 | (a - value)2 | (a - value)1 | (a - value)0`,
modulo `2^32`. The four input items are consumed. The function temporarily
uses the altstack for borrow propagation and restores its prior contents. It
does not provide a terminal predicate or clean-stack wrapper.

## Reproduction

```sh
cargo test --locked arithmetic::u32::sub_constant::tests --lib
cargo test --locked --test primitive_metrics u32_sub_constant_metrics_are_current -- --exact
python3 tools/kb.py validate
```

The full repository test suite is intentionally not included in this focused
contribution run.
