# Extended Hamming (8,4) byte decoder

`arithmetic::hamming::decode_hamming84()` consumes a canonical numeric
byte and returns a canonical nibble if the byte is within distance one
of a codeword. It rejects other bytes. Every witness byte is hostile.

## Parameters

The layout is fixed. Bit positions are numbered from the least-significant
bit starting at one. Data positions 3, 5, 6 and 7 carry the nibble from low
bit to high bit. Position 8 is overall even parity.

## Script metrics

| Inputs | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items | Peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Syndrome | <!-- metric:hamming84_syndrome_one_script -->185<!-- /metric:hamming84_syndrome_one_script --> | <!-- metric:hamming84_syndrome_one_witness -->4<!-- /metric:hamming84_syndrome_one_witness --> | 1 | 0 (none) | <!-- metric:hamming84_syndrome_one_stack -->13<!-- /metric:hamming84_syndrome_one_stack --> | <!-- metric:hamming84_syndrome_one_executed -->121<!-- /metric:hamming84_syndrome_one_executed --> |
| 1 | Table | <!-- metric:hamming84_table_one_script -->408<!-- /metric:hamming84_table_one_script --> | <!-- metric:hamming84_table_one_witness -->4<!-- /metric:hamming84_table_one_witness --> | 1 | 0 (none) | <!-- metric:hamming84_table_one_stack -->259<!-- /metric:hamming84_table_one_stack --> | <!-- metric:hamming84_table_one_executed -->144<!-- /metric:hamming84_table_one_executed --> |
| 8 | Syndrome | <!-- metric:hamming84_syndrome_eight_script -->1473<!-- /metric:hamming84_syndrome_eight_script --> | <!-- metric:hamming84_syndrome_eight_witness -->20<!-- /metric:hamming84_syndrome_eight_witness --> | 8 | 0 (none) | <!-- metric:hamming84_syndrome_eight_stack -->20<!-- /metric:hamming84_syndrome_eight_stack --> | <!-- metric:hamming84_syndrome_eight_executed -->975<!-- /metric:hamming84_syndrome_eight_executed --> |
| 8 | Table | <!-- metric:hamming84_table_eight_script -->585<!-- /metric:hamming84_table_eight_script --> | <!-- metric:hamming84_table_eight_witness -->20<!-- /metric:hamming84_table_eight_witness --> | 8 | 0 (none) | <!-- metric:hamming84_table_eight_stack -->267<!-- /metric:hamming84_table_eight_stack --> | <!-- metric:hamming84_table_eight_executed -->248<!-- /metric:hamming84_table_eight_executed --> |

The single checked input is `0x83`, which decodes to one. The eight-input
fixture uses codeword `i` with bit `i` flipped, for nibble values zero
through seven. Both leaves check exact decoded bytes in the original order
and finish with one true item. Whole-leaf compilation uses optimizer `ALL`.
Witness serialization includes count and item lengths for every entry byte
and excludes script, control block, annex and transaction. All data items
coexist at entry. Executed counts include encountered branch delimiters.

## Security

The code corrects one flipped bit and rejects any two-bit corruption of
a valid codeword. Larger changes can yield another accepted message.
There is no authentication, key or cryptographic security parameter.

## Script compatibility and standardness

Bare, P2SH and P2WSH complete execution is unclassified. The measured
context is the local tapscript `Consensus` profile, enforcing MINIMALIF and
stack and element limits, with numeric minimality and experimental OP_CAT
disabled. Evidence is `locally-reproduced`; execution is `unclassified`.
See [script types](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md).

## Witness and hints

Each input byte uses one canonical nonnegative ScriptNum, including the
sign pad at 128 and above. No hints or hint bytes are required. Preloaded
future inputs count toward the combined limit.

## Stack contract

`caller | received -> caller | nibble`. The fragment preserves both caller
stacks for this exact suffix and uses temporary altstack entries. The
combined peak is 13 items plus caller state. Consume or check the nibble
before adding a terminal predicate.

## Operational notes and knowledge-base integration

See the [research note](../../../knowledge/primitives/hamming84-decoder.md)
for the state schedule, shared-table comparison, limitations and reproduction.
