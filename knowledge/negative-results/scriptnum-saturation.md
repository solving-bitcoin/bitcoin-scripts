# Saturating addition shortcuts and regrouping

Adding and then passing the sum through numeric `OP_MIN` and `OP_MAX` fails
on the valid witness `(2³¹−1, 1)`. The computed sum is five bytes and the
first clamp tries to consume it as a four-byte number. The focused local test
gets `ScriptIntNumericOverflow` for that positive case.

`OP_SIZE` can inspect the raw computed width safely. The tested width schedule
returns the right value in all 225 boundary pairs, but loses one executed
non-push operation in the in-range fixture and two in each overflow fixture
against the headroom schedule. Both use 32 script bytes, an eight-byte
serialized data witness, two ordinary data items, zero hints and a four-item
combined peak in the matched checked leaves. This is a measured comparison of
the two schedules on three paths, with whole-leaf optimizer `ALL` under the
local stack-limited tapscript `Consensus` profile.

Independently, pairwise signed saturation cannot be regrouped like exact
addition. The focused test builds both parenthesizations over three ordinary
entry operands and zero hints. With `(2³¹−1, 1, −1)` the left fold yields
`2³¹−2` while the right fold yields `2³¹−1`. Preserve evaluation order when
using repeated saturating operations in a mixed-sign protocol.

See the [primitive note](../primitives/scriptnum-saturation.md) for boundaries
and commands. These results are `locally-reproduced` and `unclassified`.
