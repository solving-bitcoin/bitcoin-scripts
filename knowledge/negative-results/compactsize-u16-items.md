# CompactSize item decoding limits

Using a raw byte directly as a ScriptNum loses its unsigned value.
Raw `80` is a zero-magnitude signed ScriptNum. The focused test
normalizes it to zero under the local Consensus profile, while the
local Policy profile rejects that numeric use. The raw decoder
compares the byte before arithmetic and returns 128 in both profiles.
The builder uses explicit raw byte vectors for `00`, `80`, and
`fd`; inserting those as numeric pushes changes their bytes.

Accepting every `fd` payload would allow a second wire encoding for
values below 253. The decoder rejects `fd fc 00` as well as the
unsupported `fe` and `ff` prefixes and incomplete tokens. It accepts
the exact boundary `fd fd 00`.

On the measured encodings, raw input does not repay its script cost
in serialized witness bytes. At 65,535 the three-byte witness saving
costs 62 more leaf bytes and 30 more executed non-push operations.
At zero the raw witness is also one byte larger. The raw form serves
an input contract that already requires exact one-byte items. It
cannot split a single contiguous token without a separate operation.

The long-form peak is five combined items. With 995 preserved caller
items it reaches 1,000, and one further item fails the local check.
See the [matched fixtures](../../src/support/compact_size/README.md#script-metrics).
Evidence is `locally-reproduced` and execution is `unclassified`.
