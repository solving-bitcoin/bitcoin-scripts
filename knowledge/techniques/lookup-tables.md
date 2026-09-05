# Lookup-table strategies

Bitcoin Script lacks general multiplication and bitwise opcodes, but `OP_PICK`
can query values embedded on the stack. Local constructions use several forms:

- **Full direct table:** lowest query logic, highest persistent item count.
- **Half table:** recover symmetry with signs or negation to halve memory.
- **Log/exp table:** convert nonzero multiplication into log addition and an
  exponent lookup; zero and signs require explicit handling.
- **Signed-projective log:** encode the lower-half logarithm with a sign for
  the omitted half-cycle, allowing magnitude logs plus a half exponent table.
- **Affine log bias:** shift those projective coordinates and compensate in
  generated exponent entries, minimizing ScriptNum literal bytes without
  adding query opcodes.
- **Coordinate streaming:** install/query/drop one small table at a time to
  reduce both cumulative lookup depths and peak memory when reuse is absent.
- **Radix table:** decompose an operand into digits and query constant multiples.
- **Batch lookup:** place one table above a contiguous input batch, consume the
  next input from a fixed depth, and amortize setup and cleanup across all
  queries. The 61-item u4 bit table uses four equal indices whose changing
  stack offsets select four consecutive bits.
- **Branch-selected static map:** encode constants in mutually exclusive
  `OP_IF` branches and let witness-provided minimal booleans select a leaf. This
  avoids placing every map entry on the stack, at the cost of a larger locking
  script and branch-hint witness.
- **Addition chain:** embed no persistent table; unroll doubles and adds.
- **Key-specific fused rows:** combine a fixed XOR and S-box lookup into a
  unary table. Price row installation, frequency, address encodings and cleanup
  jointly, then derive all downstream addresses from the resulting packing.
  PRINCEv2 uses a bounded deterministic search for these rows. Its hot final-row
  selector is placed at depth 16 so each quartet's selector literal is `OP_15`;
  moving the S-box deeper trades lookup costs against 44 repeated core uses.

The crossover depends on reuse count, preserved stack depth, representation,
and whether setup can coexist with protocol state. See the checked F257 results
and the streamed affine-projective prime-RNS result in
[lookup comparisons](../comparisons/lookup-strategies.md).

## Batch nibble decomposition

The checked u4 batch installs a 61-item staggered table, range-checks each
nibble before using it as a depth, removes the table, and restores four output
bits per input. Its locking-script boundary is `92 + 26*n` bytes: 61 bytes of
setup, 31 bytes of cleanup, a 22-byte checked query, and four bytes of output
restoration per nibble. The existing branch splitter is `43*n` on the same
boundary, so the checked table wins from six inputs. For 32 nibbles the checked
batch is 924 bytes versus 1,374, while peak combined stack grows from 130 to
189 items.

Unchecked lookup removes five bytes per query and crosses over at five inputs,
but it is valid only after an independent range proof. An out-of-range value
can otherwise make `OP_PICK` address below the table. These figures are
`locally-reproduced` by the u4 source, exhaustive tests, and checked README
metrics.

The motivating upstream combined-table sketch is pinned as source
`coins-bitcoin-scripts-8f442e4b`. Its direct 64-entry layout does not compensate
for the three, two, and one equal indices that remain above the table during
successive `OP_PICK` operations. The local implementation corrects this with a
staggered 61-item layout; the as-published failure is retained as a negative
result.

## Branch-selected static maps

For the five-scalar example in the pinned source, inspected scratch ports
measured 29 locking-script bytes for the hinted branch tree and 35 for the
linear conditional form, excluding the index and branch-hint witness. A direct
`OP_PICK` table with destructive cleanup measured 18 bytes at the same
fragment boundary and needs no branch hint. Branch maps are therefore not a
byte optimization for a small scalar map. Their distinct use is stack-starved
composition: only the selected leaf's constants execute, so an `n`-entry map
does not require `n` persistent stack items. Tuple width, branch-hint witness
serialization, and tapscript `MINIMALIF` obligations must be included in any
consumer-specific comparison. These map figures remain `inspected` because no
permanent local generator or metric fixture is retained. Source:
[`maps.md`](https://github.com/coins/bitcoin-scripts/blob/8f442e4bf8a744dd9bf69b2937bdebcaed5cae77/maps.md).
