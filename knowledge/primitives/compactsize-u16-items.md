# CompactSize through 65,535 from separate raw byte items

Can Script consume a canonical one- or three-byte CompactSize token
when the incoming stack already holds its exact raw byte items?
Compare raw and numeric byte encodings of the same logical token,
with the same unsigned output and minimal-encoding checks. The
hypothesis is that raw items save witness bytes for high bytes at
the cost of additional decoding work.

## Construction

The [pinned Bitcoin Core CompactSize reader](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/serialize.h)
uses the first byte as the value below 253, and uses a little-endian
16-bit payload after marker 253 only for values at least 253.
The experiment supports those two forms, represented on the stack
as individual items with the first wire byte on top.

Dispatch on the exact raw `fd` item, then decode each data byte.
Raw `00` and `80` are handled before any numeric operation. Other
raw bytes are canonical one-byte signed-magnitude ScriptNums.
For a negative ScriptNum `s`, the raw unsigned byte equals
`128-s`. In the long form combine low and high bytes into a
canonical ScriptNum and check that it is at least 253. The numeric
baseline shares the dispatch and range logic and uses the existing
canonical byte guard.

[PR #313](https://github.com/solving-bitcoin/bitcoin-scripts/pull/313)
materializes raw bytes from numeric inputs. [PR #317](https://github.com/solving-bitcoin/bitcoin-scripts/pull/317)
prices serialized witness data. This experiment parses a token in
the opposite direction and verifies its minimal wire form. It does
not read the transaction's native witness serialization.

## Evidence and limits

For value 65,535, raw items use seven serialized data-witness bytes
versus ten for numeric byte items. They use 142 leaf bytes and 72
executed non-push operations versus 80 and 42. Both use three
ordinary data items, zero hints, and peak at five. Raw zero uses
one more witness byte than numeric zero. The
[matched comparison](../comparisons/compactsize-encoding.md)
gives the different encodings and shared boundaries.

The [implementation README](../../src/support/compact_size/README.md)
includes all measured values and reproduction commands. All 65,536
supported values were compared with the host serializer. The
[negative results](../negative-results/compactsize-u16-items.md) record
why treating raw bytes as ScriptNums can change the wire value.

Evidence is `locally-reproduced`; execution is `unclassified`.
Both local profiles accept representative valid fixtures. The
complete leaves do not establish funded-spend or relay evidence.
