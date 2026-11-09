# Two small residues cannot bind a full u32

Both 42 and 105 pass the same checked modulo-7/modulo-9 output predicate.
Their difference is 63, a multiple of both moduli. The focused test
reproduces the alias with distinct canonical four-byte words. The pair
can check congruence modulo 63, but a whole-word or commitment
predicate needs independent binding.

The separate centered-weight comparator was correct on the same host
corpus but uses 248 checked-leaf bytes and peaks at ten items, versus
210 bytes and seven items with the shared modulo-63 reduction. It
executes 136 non-push operations for both measured words, versus 115
and 113. Each comparison has the same four ordinary items, zero hints
and a 9- or 13-byte serialized data witness. These results are
`locally-reproduced` and `unclassified`.
See the [matched boundary and reproduction](../primitives/u32-dual-residue.md).
