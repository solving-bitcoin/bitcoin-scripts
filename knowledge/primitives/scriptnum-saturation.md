# Signed saturating ScriptNum addition

Can Script return a usable numeric sum over its full four-byte operand
domain by clamping before overflow? The hypothesis was that inspecting the
encoded width after addition would match or beat a pre-addition headroom
check. Compare both schedules with the same signed operands, canonical output
and terminal predicate. All witness items are hostile. The fixed range is
`[-2,147,483,647, 2,147,483,647]`, with four-byte arithmetic operands, at
most 1,000 combined stack items, the central compilation policy and zero
external hints.

## Headroom schedule

Let `M = 2³¹−1`. For a negative right operand `y`, compute the lowest safe
left operand `−M − y`, then replace `x` with `max(x, −M − y)`. For
nonnegative `y`, compute `M − y` and use `min(x, M − y)`. Adding the
bounded left operand to `y` gives exactly `clamp(x+y, −M, M)`. All
subtractions, extrema and the final addition fit within four bytes. The
four-byte input limit and potentially wider arithmetic results follow the
pinned [Bitcoin Core CScriptNum implementation](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/script.h#L211-L250).

The width schedule adds first, preserving one operand on the main stack.
[OP_SIZE](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L805-L813)
observes the output length without parsing the sum as a number. If the
length exceeds four, the two original operands necessarily shared a sign.
The width schedule drops the sum and selects the signed endpoint from the
saved operand. It is correct under the same domain, but the headroom
schedule executes fewer operations in the measured cases.

The catalog, arithmetic comparisons, negative results, source tree and PR
searches revealed no exact signed addition contract. The nearest in-repo
primitive is the [u4 embedded-cap clamp](u4-clamp.md), which caps individual
already-bounded nibble values without adding two operands.

## Matched cost

| Schedule | Checked leaf bytes | Data witness bytes | Data / hint items | Combined peak | Executed ops, in range / positive / negative |
| --- | ---: | ---: | ---: | ---: | ---: |
| Pre-addition headroom (public) | 32 | 8 | 2 / 0 | 4 | 11 / 11 / 11 |
| Encoded-width detection | 32 | 8 | 2 / 0 | 4 | 12 / 13 / 13 |

Use `(M, −1)`, `(M, 1)` and `(−M, −1)`, respectively. The complete
leaves check the same expected canonical result byte-for-byte and finish
with true. Script size includes all computation and the output check.
The whole artifact uses optimizer `ALL`. The witness serializes both
ordinary entry operands and their prefixes, excluding script, control block,
annex and transaction serialization. There is no caller state. Executed
non-push operations include active operations and encountered branch
delimiters. Signature weight charged is zero.

Evidence is `locally-reproduced`; execution is `unclassified`. Measurements
use the local tapscript `Consensus` profile, a synthetic empty transaction,
stack limits and MINIMALIF on, numeric minimality and experimental OP_CAT
off. The compiler and interpreter are the lockfile pins
[`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`](https://github.com/BitVM/rust-bitcoin-script/tree/124b561ed75ac3ec4c6ad99207d8dcdd3bc67180)
and [`a09e87af444034698697f0a2267e755cf72f9aed`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/tree/a09e87af444034698697f0a2267e755cf72f9aed).
The 1,000-item test covers the public headroom implementation. Funded Core
transactions and relay policy for this primitive have not been measured.

## Composition

`saturating_add()` consumes two operands and returns one canonical ScriptNum.
It preserves both caller stacks given an exact two-item suffix. Add all
live caller items, including preloaded future inputs, to the four-item peak.
The frontier test preserves 995 main-stack items and one altstack item at
1,000 and observes rejection with one extra item. An enclosing protocol must
establish the input boundary and bind the operands when their values or
spelling carry meaning. Numeric input aliases follow the profile. There are
no hints. The result can feed later arithmetic, including a second saturation.

Regrouping can change a mixed-sign result. At `(M, 1, −1)`,
`sat(sat(M, 1), −1) = M − 1` but `sat(M, sat(1, −1)) = M`.
Both schedules are checked against a host exact-add-and-clamp oracle on a
15-by-15 boundary grid. Tests also cover overlong and oversized inputs,
numeric aliases, short and surplus standalone witnesses, and observable
caller state. See the [negative result](../negative-results/scriptnum-saturation.md)
and [implementation](../../src/arithmetic/saturating/README.md).

```sh
cargo test --locked --lib arithmetic::saturating::tests
cargo test --locked --test primitive_metrics scriptnum_saturating_add_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```
