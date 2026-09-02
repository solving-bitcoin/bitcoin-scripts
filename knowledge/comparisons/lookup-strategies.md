# Lookup strategies

## F257 measured frontier

| Strategy | Setup/memory bytes | Per operation bytes | Persistent/peak items | Suitable use |
| --- | ---: | ---: | ---: | --- |
| Centered constant chain | 0 | 132 | peak 4 | Isolated known constant |
| Half direct table, batch 8 | included in 573 | included | peak 139 | Repeated same constant |
| Full direct table, batch 8 | included in 809 | included | peak 266 | Larger same-constant batches |
| Log/exp | 1,196 | 44 constant / 60 variable | 385 memory; peak 900 at depth | Repeated mixed products |
| Exact square | 499 | 11 | 129 memory; peak 643 at depth | Repeated centered squares |

The implementation README estimates byte crossover near four uses for the half
table, fourteen constant uses or four variable uses for log/exp. Recalculate
for the actual live stack and cleanup boundary.

## Nibble-to-bit measured frontier

| Strategy, 32 inputs | Total script bytes | Peak items | Boundary and use |
| --- | ---: | ---: | --- |
| Existing four-bit branch splitter | 1,376 | 130 | Repeated split-to-altstack plus restoration |
| Staggered batch table, checked | 924 | 189 | Setup, numeric range checks, cleanup, and restoration |
| Staggered batch table, unchecked | 764 | 189 | Inputs must already be certified in `0..=15` |

The checked table costs `92 + 26*n` bytes and crosses the `43*n` branch
baseline at six nibbles. The unchecked form costs `92 + 21*n` and crosses at
five. Its saving is not free stack-wise: the 61-item table remains live while
the output expands to four items per input. With no unrelated state, the local
generator accepts at most 234 inputs and reaches a strict 997-item peak there.
Callers must lower that count for every preserved main- or altstack item.

The upstream direct 64-entry table that motivated this search is not on the
frontier because it is incorrect as published for multiple nibble values. The
local staggered layout is a corrected construction, not a verbatim port.

## Native secp256k1 field frontier

| Strategy | Total bytes | Table lifecycle | Computation | Peak items |
| --- | ---: | ---: | ---: | ---: |
| One ordinary normalized-Karatsuba multiply | 20,524 | 1,795 | 18,729 | 757 |
| One factor-16 folded multiply | 20,501 | 1,795 | 18,706 | 719 |
| Two preloaded ordinary multiplies | 39,400 | 1,795 | 37,605 | 882 |
| Three preloaded ordinary multiplies, destructive layout | 59,163 | 1,795 | 57,368 | 993 |
| One specialized square | 14,543 | 1,795 | 12,748 | 614 |
| Five preloaded squares | 65,074 | 1,914 | 63,160 | 998 |

The 513-entry quarter-square table represents about 8.7% of one multiplication,
so reuse gives a real but moderate byte saving. Stack coexistence selects the
three-gate ordinary algorithm: the 85-coefficient layout is smaller for one or two
products, while a 57-slot destructive recombination is needed for three
preloaded groups to remain below 1,000 items. The five-square endpoint leaves
only two items for all unrelated state. Neither row includes operand
certification, fan-out, or circuit-level witness routing.

The factor-16 row has the smallest one-shot byte count and lowest multiplication
peak, but represents logical `x` as `x/16 mod p`. It currently has no measured
table-resident or batch fragment, and the table lifecycle is not amortized in
that row. Conversion or mixing with ordinary-domain multiplication/squaring is
outside the metric.

## RNS measured frontier

| Strategy | One-shot bytes | Peak items | Reuse behavior |
| --- | ---: | ---: | --- |
| Legacy direct-table RNS | 1,564 | 903 | Includes full memory and cleanup |
| 256-bit-product prime hybrid | 15,628 | 183 | Per-coordinate shortest of streamed lookup and centered/plain binary Horner |
| Prime hybrid, six-product batch | 64,912 total / 10,819 amortized | 900 | Coordinate-major, one table lifecycle per selected coordinate |
| Conditional exact-carry modular verifier | 10,952 | 231 | Table-free; external global bindings excluded |
| Standalone-bound exact-carry modular verifier | 51,055 | 305 | Table-free; four global bindings and field bounds included |
| Composable exact-carry modular verifier | 31,281 | 267 | Table-free; q/r bound locally; requires two adjacent certified operand vectors |

The prime-hybrid row is not a smaller instance of the legacy row: it covers a
513-bit composite range with 75 canonical residues, versus 69,300 with five
mixed prime-power residues. For each coordinate, generation compares a
table-free binary Horner products, with and without a centered multiplier,
against the existing streamed log/exp query and emits the shortest compiled
fragment. Any selected table exists only for the active nonzero coordinate and
is destructively cleaned up.

For primes 23 and above, a selected table uses affine signed-projective
magnitude logs and only half of the exponent cycle. Historical all-table
searches measured a wholly canonical half-exponent profile at 38,996 bytes and
a wholly centered one at 37,832 bytes on their respective byte-optimal
73-prime bases. Both are now dominated by the checked 15,628-byte
per-coordinate hybrid.

The one-shot hybrid spends 392 bytes pushing its 12 selected tables and 153
bytes destructively cleaning them up; its remaining 15,083 bytes are
arithmetic, routing, and output restoration. `prime::batch` instead installs
one coordinate table, processes every product for that coordinate, and drops
the full table before advancing. Strategy selection is batch-specific: at six
products, 73 coordinates use tables. Pushes cost 25,510 bytes once, cleanup
costs 6,521, queries cost 30,229, routing costs 2,202, and restoring all 450
outputs costs 450. This exact locally executed fragment is 64,912 bytes total,
versus 93,768 for six independent fragments.

The batch assumes coordinate-major witness input and returns coordinate-major
state; any vector-major transposition is outside the metric. Six products peak
at 900 items. Seven products cannot enter the script because the 1,050 operand
items alone exceed the limit. A separately prototyped two-proof batch of the
five-vector no-carry modular verifier measured 52,048 bytes, 494 bytes larger
than two independent 25,777-byte proofs: deeper routing erased its 897-byte
ideal table-reuse saving.

The exact-carry rows remove lookup memory rather than amortize it. The compact
42-prime verifier assumes a surrounding protocol has already tied every
coordinate vector to one bounded integer. The standalone 47-prime verifier
performs that work from four shared 16-limb values: 38,801 of its 51,055 bytes
are residue binding, while its modular relations cost 10,794 bytes. Its table
setup and cleanup are both zero. These rows are therefore not like-for-like
lookup competitors, and repeating either full fragment exposes no static table
setup to share. A composed protocol can instead reuse the output of the
9,777-byte one-value binder when the same unsigned-256 value survives across
operations. That plain binder does not prove a field bound; the
`bind_value_below(N)` variant costs 9,864 bytes.

The 46-prime composable verifier makes certificate reuse a concrete fragment:
its matching 9,835-byte binder proves one field value and returns only its
residue certificate, while each 31,281-byte gate binds q/r and returns a new
certificate. Both have zero table push and cleanup bytes. This is not lookup
setup amortization, and the gate number is not a complete multi-gate circuit
cost: the two operand certificates and 170 hint items must already be adjacent.
All-witness-at-entry routing, certificate fan-out/reordering, and terminal
predicates remain unmeasured. A straightforward 46-residue duplicate costs 138
bytes before a square, illustrating why those circuit costs cannot be omitted
from an end-to-end recurrence.
