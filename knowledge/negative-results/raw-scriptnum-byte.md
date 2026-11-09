# Hashing a numeric byte can hash the wrong string

Canonical numeric zero is empty. Canonical numeric 128 and 255 serialize
as `80 00` and `ff 00`, respectively. Hashing those items directly fails
the digest checks for the one-byte strings `00`, `80` and `ff`. The focused
tests run both complete leaves with each of the same three numeric witnesses.
The sign-magnitude adapter passes all three checks.

A high-half lookup also produces the correct bytes. It increases the
matched hash-checking leaf from 72 to 391 script bytes and the `0xc8`
peak from four to 129. At zero the lookup's upper branch is inactive.
Both schedules peak at four and the lookup executes 19 non-push opcodes
versus 20. Each fixture has one ordinary item, zero hints and the same
serialized witness across both schedules. These local results are
`locally-reproduced` with `unclassified` execution. See the
[measured boundary](../primitives/raw-scriptnum-byte.md#cost-boundary).
