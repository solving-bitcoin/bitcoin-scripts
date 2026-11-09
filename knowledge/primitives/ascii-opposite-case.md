# Opposite-case ASCII pair check

Can one shared alphabet interval and an absolute numeric gap verify a pair
of hostile raw ASCII items with fewer script bytes than validating both
letters independently? Compare the same two data items and complete leaf
predicate under the pinned local tapscript interpreter. The hypothesis is
that one interval test removes duplicated validation without weakening
the byte contract or increasing the combined stack peak.

[RFC 20 §2](https://www.rfc-editor.org/rfc/rfc20.html#section-2) defines the
code table. In its letter ranges, each uppercase value is 32 less than
its lowercase mate. Enforce exact byte shape before numeric operations.
For decoded operands `x` and `y`, the proof is
`min(x,y) in [65,91)` and `abs(x-y) = 32`. A successful pair therefore
contains the unique one-byte encodings of one uppercase letter and its
lowercase counterpart. Both orders are accepted and both items are
consumed.

The [matched comparison](../comparisons/ascii-pair-checks.md) measures
a raw mate schedule and independently validated folds. Hex text decoders
and encoders from [PR #268](https://github.com/solving-bitcoin/bitcoin-scripts/pull/268)
and [PR #280](https://github.com/solving-bitcoin/bitcoin-scripts/pull/280)
map a different alphabet and have different stack contracts.

The [implementation README](../../src/support/ascii_case/README.md)
records the exact metrics and reproduction. The tests check every ordered
pair of one-byte vectors with the host predicate, malformed encodings and
combined caller-state limits. See the
[punctuation counterexample](../negative-results/ascii-pair-checks.md).

At 128 pairs, the shared check uses 2,561 leaf bytes and 1,536 executed
non-push operations, versus 3,969 and 1,536 for raw mate synthesis and
5,761 and 3,328 for independent folds. All three use 515 serialized data
witness bytes and zero hints. The combined peaks are 259, 259 and 261.

Evidence is `locally-reproduced`. Execution is `unclassified`.
