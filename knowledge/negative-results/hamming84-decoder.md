# Extended-Hamming correction is limited to one bit

`0x07` differs from the all-zero codeword in three bits and from
`0x87` in one bit. The checked leaf decodes it to nibble one. The
decoder cannot infer that the zero word was sent. Double-error
detection from a valid codeword gives no adversarial integrity
guarantee. Any application requiring authenticated data needs a
separate binding.

For a single byte, the lookup schedule uses 408 script bytes and
peaks at 259, versus 185 and 13 for the syndrome path. At eight inputs,
sharing the table saves script bytes and executed non-push operations,
using 585 bytes and 248 operations versus 1,473 and 975. The table
still peaks at 267, against 20 for the syndrome schedule. All eight
ordinary items coexist at entry, with 20 witness bytes and zero hints.
These are `locally-reproduced`, `unclassified` complete leaves.
See the [cost boundary and tests](../primitives/hamming84-decoder.md).
