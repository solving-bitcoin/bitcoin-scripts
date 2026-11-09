# Two altered nibbles can cancel an erasure check

The vectors `[5,5,5]` and `[4,7,4]` have the same two public
residues `S=15` and `T=15` modulo 17. With index zero erased,
the two changes at surviving positions have weighted effects
`+2` and `-2`. The checker accepts the alternate surviving
witness and returns four. Both checked schedules reproduce this.

Distinct positions matter for single-change detection. At width
18, positions zero and 17 have equal coefficients modulo 17.
The host fixture starts with eighteen fives, changes position 17
to six and changes the erased position zero to four. Both checks
are unchanged. The
[constructor](../../src/arithmetic/u4/erasure/README.md) restricts
width to 17. Evidence is `locally-reproduced`.
Execution is `unclassified`.
