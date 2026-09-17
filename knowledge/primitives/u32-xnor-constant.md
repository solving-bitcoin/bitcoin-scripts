# Embedded-constant u32 XNOR

## Research question

Can a public u32 mask be embedded in the locking script so a checked,
byte-oriented bitwise XNOR uses four witness items instead of a second
witness-supplied word?

## Construction and threat model

`u32_xnor_constant(value)` consumes the top four canonical byte limbs, checks
each hostile limb, XORs them with the public compile-time mask through the
existing 256-entry Boolean table, complements each result byte, and removes
the table before returning. The mask is script data, not a secret.

The input witness is hostile. The checks reject negative values, values above
255, and non-minimal ScriptNum aliases before any table query. No cryptographic
security claim is made.

## Comparison objective and boundary

The objective is witness width and entry-item count when the mask is public,
compared with a generic two-word XNOR composition. The
`fragment-with-memory` boundary includes four canonical byte checks, table
setup and cleanup, four XOR queries, four byte complements, and output routing.
It excludes witness pushes, terminal predicates, unrelated live state, and
transaction framing.

| Construction | Locking script | Representative witness | Maximum witness | Data items | Hint items | Peak items | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Embedded mask `0x89abcdef` | 678 | 13 bytes | 13 bytes | 4 | 0 | 272 | 498 |
| Generic XNOR with runtime mask | 566 plus complement and table routing | 21 bytes | 21 bytes | 8 | 0 | table-dependent | not measured here |

The embedded form removes four witness data items and saves the second word's
serialized witness bytes, but retains the 256-item table and adds one
complement per output byte. It is useful only when the mask is public, fixed at
script-generation time, and witness width or item count matters more than
locking-script bytes.

## Evidence and execution class

The implementation and metric boundary are `locally-reproduced` by focused CI.
Deployment is `unclassified`. The fixture uses
mask `0x89abcdef` and four canonical `0xff` data limbs. Correctness tests cover
boundary masks, malformed and non-minimal limbs, and surrounding main- and
alt-stack state.

The 492 figure is a static non-push opcode count, not a dynamic execution or
validation-weight claim. No Bitcoin Core differential, complete-transaction,
relay-policy, or cryptographic claim is made.

## Parameters and witness

- `value` is any public `u32`; there is no default.
- The witness supplies four canonical numeric byte limbs in
  most-significant-byte-first order.
- The complete measured input has four data items and zero hint items. The
  generated Boolean table contributes 256 items while the fragment runs.
- Callers must account for the table and unrelated live state under the 1,000-
  item combined main-plus-alt-stack limit.

## Stack contract

Before: `... | a3 | a2 | a1 | a0`, with four canonical byte-valued items at
the top of the main stack.

After: `... | ~(a ^ value)3 | ~(a ^ value)2 | ~(a ^ value)1 | ~(a ^ value)0`.
The input items are consumed, temporary table and routing state are removed,
and unrelated caller-owned stack state is preserved. No terminal predicate or
clean-stack wrapper is provided.

## Reproduction

```sh
cargo test --locked arithmetic::u32::xnor_constant::tests --lib
cargo test --locked --test primitive_metrics u32_xnor_constant_metrics_are_current -- --exact
python3 tools/kb.py validate
```

The full repository test suite is intentionally not included in this focused
contribution run.
