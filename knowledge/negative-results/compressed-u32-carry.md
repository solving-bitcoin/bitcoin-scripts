# Consecutive sign classes do not determine compressed carry

Use tags `0` for a nonnegative compressed value, `1` for an ordinary
negative value, and `2` for the five-byte sentinel. The pair
`0 + 0x80000000` and the pair `0xffffffff + 0xffffffff` both have
tag sum two. Their unsigned carry bits differ. That single class
sum cannot distinguish the sentinel/low case from two ordinary
high-half words.

The [checked fragment](../../src/arithmetic/u32/carry/README.md) uses
tags `0,2,3`, so sum two identifies an ordinary mixed pair, three
identifies the sentinel/low case, and sums at least four identify
two high-half words. The mixed case additionally checks the signed
sum. Evidence is `locally-reproduced`; execution is `unclassified`.
