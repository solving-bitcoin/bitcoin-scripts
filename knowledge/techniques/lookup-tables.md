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

## Fixed-sum chain tables

The [20-byte constant-sum Winternitz verifier](../primitives/winternitz-constant-sum20.md)
uses conditional chain advancement and half tables for HASH160; SHA-256
profiles use a parity bit and tables advancing two hashes per row. It also
offers a terminal relation that omits individual upper bounds while retaining
each raw digit in the exact sum. An overflow lookup can read below its local
table, so it supplies no independent digit-authentication guarantee. The
whole-vector security inference requires a canonical one-time signature:
any different vector with the same sum must decrease another coordinate,
which remains in its own table and requires an earlier chain node.
The bounded API is available when local range rejection is required.

Default HASH160 verification has 82 coexisting entry data items, zero auxiliary
hints, and a 93-item combined main/alt-stack peak including its temporary
table and sum accumulator. These are `locally-reproduced`, `research-unlimited`
metrics; the security argument is `inspected`. Neither this argument nor the
strict local tests establish Bitcoin Core consensus or policy validation.

## Destructive public-key pools

[Constant-composition Winternitz](../primitives/winternitz-constant-composition20.md)
replaces chain lookup tables with a shrinking table of 49 trusted endpoint
commitments. Each of 35 fixed digit slots removes its selected key using
`OP_ROLL`, enforcing distinctness without an index set or sortedness check.
Fixed hash distances authenticate the selected key; the fourteen unselected
keys receive the maximum digit. This trades codebook capacity for removal
of dynamic digit lookup and checksum logic.

The composable method clamps each selector into the remaining key pool. The
isolated method first checks that all 70 main-stack items are its signature
and stages them to altstack; each `OP_ROLL` then sees only trusted keys and
supplies its own range bound. Omitting both the initial depth check and
per-selector bounds is not a safe composable fragment. All 70 data items
coexist at entry, there are zero auxiliary hints, and measured combined peaks
are 119 isolated and 120 composable. HASH160/Preimage16 costs 2,400 and 2,498
maximum script-plus-signer-witness bytes respectively. These measurements
are `locally-reproduced`, `research-unlimited`. The historical `ba96bc2`
executor panicked at the exact `OP_ROLL` upper boundary; that outcome is
recorded separately from successful strict tests. The lab now pins repaired
interpreter `4b7269a`; see
[adoption and scope](../negative-results/index.md#nr-048-minimal-push-policy-must-follow-execution).
The [v30.3 differential fixtures](../core-validation.md) now
confirm Core rejection of that boundary and validate one complete isolated
HASH160 leaf under consensus and policy; other table/fragment measurements
retain their original scope.
