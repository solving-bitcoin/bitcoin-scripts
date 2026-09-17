# Embedded-constant u32 AND

## Research question

Can a public u32 mask be embedded in the locking script so a checked,
byte-oriented bitwise AND uses four witness items instead of a second
witness-supplied word?

## Construction and threat model

`u32_and_constant(value)` consumes the top four canonical byte limbs, checks
each hostile limb with `verify_canonical_byte()`, loads the existing 256-entry
byte Boolean table, ANDs every byte with the public compile-time `value`, and
removes the table before returning. The mask is script data, not a secret.

The input witness is hostile. The checks reject negative values, values above
255, and non-minimal ScriptNum aliases before any table query. The table is
the repository's existing XOR/AND table and is generated afresh for this
fragment; it is not a witness hint.

## Comparison objective and boundary

The objective is witness width and entry-item count when the mask is public,
compared with the generic table-backed `u32_and` composition. The
`fragment-with-memory` boundary includes four canonical byte checks, table
setup and cleanup, all four byte queries, and output routing. It excludes
witness pushes, terminal predicates, unrelated live state, and transaction
framing.

| Construction | Locking script | Representative witness | Maximum witness | Data items | Hint items | Peak items | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Embedded mask `0x89abcdef` | 612 | 13 bytes | 13 bytes | 4 | 0 | 272 | 444 |
| Generic `u32_and` with runtime mask | 326 operation bytes plus table setup/cleanup | 21 bytes | 21 bytes | 8 | 0 | table-dependent | not measured here |

The embedded form removes four witness data items and saves the second word's
serialized witness bytes, but retains the 256-item table and costs a larger
per-use fragment than the raw operation. It is useful only when the mask is
public, fixed at script-generation time, and witness width or item count is
more important than locking-script bytes. Table sharing can make the generic
composition preferable for multiple operations.

## Evidence and execution class

The implementation and metric boundary are currently `inspected`; the
repository CI metric fixture is the executable reproduction gate. Deployment
is `unclassified`. The fixture uses mask `0x89abcdef` and four canonical
`0xff` data limbs. Correctness tests cover zero, all-zero/all-one masks,
boundary masks, malformed and non-minimal limbs, and surrounding main- and
alt-stack state.

The strict metric fixture is intended to execute through the repository's
locked `bitcoin-scriptexec` dependency in a tapscript context with the
combined main-plus-alt-stack limit. The 444 figure is a static non-push
opcode count, not a dynamic execution or validation-weight claim. No Bitcoin
Core differential, complete-transaction, relay-policy, or cryptographic
claim is made.

## Parameters and witness

- `value` is any public `u32`; there is no default.
- The witness supplies four canonical numeric byte limbs in
  most-significant-byte-first order, with the least-significant limb on top.
- The complete measured input has four data items and zero hint items. No
  hints coexist at entry; the generated Boolean table contributes 256 script
  items to the live stack during the operation.
- The 13-byte fixture uses four canonical `0xff` limbs. Callers must account
  for the table and all unrelated live state under the 1,000-item combined
  main-plus-alt-stack limit.

## Script compatibility and standardness

The fragment uses opcodes available in legacy Script, P2SH, P2WSH, and
tapscript, but its table-backed static opcode count exceeds the historical
201-opcode P2SH/P2WSH limit as a standalone fragment. That does not classify
the construction as deployable or non-deployable in a larger protocol; the
complete script and execution context must be checked separately. Relay and
mining policy are also separate questions. See
[`script-types.md`](../../docs/script-types.md) and
[`standardness.md`](../../docs/standardness.md).

## Stack contract

Before: `... | a3 | a2 | a1 | a0`, with four canonical byte-valued items at
the top of the main stack.

After: `... | (a & value)3 | (a & value)2 | (a & value)1 | (a & value)0`.
The four input items are consumed. The fragment temporarily uses both stacks
for table queries, carries, and output routing, then removes the table and
restores caller-owned alt-stack state. It does not provide a terminal
predicate or clean-stack wrapper.

## Reproduction

```sh
cargo test --locked arithmetic::u32::and_constant::tests --lib
cargo test --locked --test primitive_metrics u32_and_constant_metrics_are_current -- --exact
python3 tools/kb.py validate
```

The full repository test suite is intentionally not included in this focused
contribution run.
