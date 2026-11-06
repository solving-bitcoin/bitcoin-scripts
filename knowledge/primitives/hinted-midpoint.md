# Hinted floor midpoint of signed ScriptNums

Can raw equality on canonical wide sums verify a floor midpoint
with one proposed-result hint and no separate parity hint? Compare
the same signed operands and exact output with a two-hint baseline
that supplies the parity bit. The hypothesis is that deriving parity
from the two possible raw sums reduces witness bytes and extends the
preloaded batch frontier.

The [pinned Bitcoin Core ScriptNum definition](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/script.h#L211)
allows arithmetic results wider than numeric operands. Let `s=a+b`.
The fragment checks canonical byte equality with `2*q` or
`q+(q+1)`. The latter branch guards the width of `q+1`. The equality
conditions characterize floor division by two on signed integers,
including `-1/2` rounding down to `-1`.

[Hinted division](scriptnum-hinted-div.md) verifies a quotient for
one numeric operand and a public divisor. [PR #291](https://github.com/solving-bitcoin/bitcoin-scripts/pull/291)
studies bounded general division. The midpoint verifies a relation
on two signed inputs whose exact sum may be wider than the numeric
operand limit. [PR #304](https://github.com/solving-bitcoin/bitcoin-scripts/pull/304)
uses the same raw comparison technique for equality of independent sums.

See the [matched hint comparison](../comparisons/hinted-midpoint.md),
[implementation README](../../src/arithmetic/midpoint/README.md) and
[negative result](../negative-results/hinted-midpoint.md).

At 128 calls, implicit parity saves 128 hint items and 192
data-witness bytes. It adds 256 leaf bytes and 192 executed
operations. The implicit and explicit peaks are 387 and 515.
Evidence is `locally-reproduced`. Execution is `unclassified`.
