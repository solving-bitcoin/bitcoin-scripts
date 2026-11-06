# Exact wide ScriptNum sum with two numeric outputs

Can an exact sum of two signed four-byte ScriptNums produce a canonical
two-item representation that supports numeric ordering, and what does
a post-add size dispatch cost compared with pre-add headroom? Compare
identical operand widths, output representation, leaf checks, and
stack-limited local tapscript assumptions. The hypothesis is that a
post-add size test makes the central case cheaper without reparsing a
wide result as a number.

The [pinned Bitcoin Core ScriptNum definition](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/script.h#L211)
permits an arithmetic result wider than the numeric input boundary.
For `M = 2147483647`, represent the exact sum as
`residual + class*M`, with class `-1`, `0` or `1` for the
negative overflow, central, and positive overflow bands. The
residual is canonical and fits in four bytes. Ordering generated
pairs by class then residual is equivalent to ordering the sums.

[PR #304](https://github.com/solving-bitcoin/bitcoin-scripts/pull/304)
compares raw wide sums for equality. [PR #305](https://github.com/solving-bitcoin/bitcoin-scripts/pull/305)
clips sums to the four-byte range using signed headroom. The split
retains the excess as another usable numeric item. It can distinguish
`M+1` from `M+2` using ordinary numeric comparison on the generated
residuals.

The [matched comparison](../comparisons/wide-scriptnum-sum.md) includes
a complete leaf ordering two generated descriptors. The
[negative result](../negative-results/wide-scriptnum-sum.md) gives
the failure of directly ordering the raw wide outputs. See the
[implementation README](../../src/arithmetic/wide_sum/README.md)
for parameters, exact fixtures, and reproduction.

The ordering fixture uses 106 leaf bytes and 63 executed non-push
operations with post-add size dispatch, versus 146 and 65 with
pre-add headroom. Both use 15 serialized data-witness bytes and
zero hints. The combined peaks are seven and six.

Evidence is `locally-reproduced`; execution is `unclassified`.
