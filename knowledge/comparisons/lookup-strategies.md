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

## RNS measured frontier

| Strategy | One-shot bytes | Peak items | Reuse behavior |
| --- | ---: | ---: | --- |
| Legacy direct-table RNS | 1,564 | 903 | Includes full memory and cleanup |
| 256-bit-product prime-log streaming | 37,471 | 462 | Fresh conditional table per coordinate |

The prime-log row is not a smaller instance of the legacy row: it covers a
513-bit composite range with 75 canonical residues, versus 69,300 with five
mixed prime-power residues. Its streamed multiplier installs a table only for
the active nonzero coordinate, then destructively consumes the final log and
exponent entries before cleanup.

For primes 23 and above, the table uses affine signed-projective magnitude logs
and only half of the exponent cycle. Canonical exponent entries are shorter for
the middle primes; centered entries become smaller enough at prime 157 to pay
for canonical result normalization. A wholly canonical half-exponent profile
is 38,996 bytes and a wholly centered one is 37,832 bytes on their respective
byte-optimal 73-prime bases, so the measured hybrid is the one-shot frontier at
the required product range. These uniform alternatives are inspected search
results; only the selected 37,471-byte profile is checked into metric snapshots.

Resident-table reuse cannot keep all 75 tables live under the 1,000-item stack
limit. A prime-major batch can instead install one coordinate table, process
several products for that coordinate, and clean it up before advancing. Its
byte crossover and required operand-state layout remain open.
