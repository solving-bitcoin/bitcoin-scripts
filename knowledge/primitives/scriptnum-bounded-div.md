# Bounded ScriptNum division without quotient hints

## Research framing

- **Question:** can a canonical bounded payload encode two public choices
  without a quotient hint, using less live stack than the existing verifier?
- **Hypothesis:** computing the quotient trades locking bytes for fewer entry
  items, witness bytes and combined stack items.
- **Objective:** compare those separate costs at the same canonical dividend,
  quotient/remainder output, and terminal-check boundary.
- **Constraints:** divisor in `1..=2^31-1`, maximum in `0..=2^31-1`, four-byte
  arithmetic, enabled opcodes, the centralized compilation policy and the
  1,000-item combined stack limit. Both parameters are required, with no default.
- **Threat model:** hostile operands and baseline quotient hints, raw aliases,
  negative zero, overflow, range violations, missing/extra data and live caller
  state. No cryptographic authentication or security property is claimed.

`arithmetic::scriptint::bounded::div_rem(divisor, maximum)` consumes one
canonical nonnegative dividend `x<=maximum` and returns `quotient | remainder`,
with remainder on top. Both caller stacks are preserved; no altstack or
additional hints are needed. Negative dividends remain outside this API.

## Reused arithmetic and checked boundary

The binary quotient core is extracted from the existing permutation decoder
at immutable commit
[`f6624f6edcf52257811eec1fd3e1d05967385fca`](https://github.com/solving-bitcoin/bitcoin-scripts/blob/f6624f6edcf52257811eec1fd3e1d05967385fca/src/arithmetic/permutation/mod.rs).
That decoder now calls the shared crate-private core with its certified residual
bound; its width-4/8/12 metric snapshots remain unchanged. This is a reusable
checked arithmetic boundary, not a new division algorithm or a global optimum.

The wrapper checks canonical encoding and `0<=x<=maximum`, independently of
MINIMALDATA. Starting with `q=0, r=x`, the core visits descending bits of
`floor(maximum/divisor)`. If `r>=divisor*2^bit`, it subtracts that threshold
and adds `2^bit` to `q`. Each step preserves `x=q*divisor+r` and nonnegative
`r`; the bounded bit range makes the final remainder smaller than the divisor.
Every threshold is at most `maximum`, and the accumulated quotient is at most
`maximum/divisor`, so no numeric operand exceeds four bytes, even at the
31-bit boundary. Comparison results are minimal branch booleans. A maximum
below the divisor correctly needs zero quotient steps and returns `0 | x`.

Tests show that both guards matter: a canonicality bypass accepts an alias
after subtraction normalizes it, and an upper-bound bypass lets input 992 under
a 991 bound return invalid remainder 31 for divisor 31. Public checks reject
both. The unchecked core is safe only with its stated certified-input contract.

## Matched measurements

Boundary: `complete-leaf:` canonical dividend/range checks, division, the same
two exact output comparisons and clean `OP_TRUE`. Input pushes and transaction
context are excluded. The hinted baseline normalizes its quotient using
`0 OP_ADD` before the existing `hinted_div_rem`, preserving canonical outputs
while accepting harmless numeric hint aliases. This comparison uses the
existing binary multiplication helper, not an optimized addition-chain verifier.

Fragment figures exclude the output comparisons and terminal `OP_TRUE` on
both sides. Data-witness figures serialize every input item, count and length
prefix; script/control-block items are excluded. All input items coexist at entry.

| Divisor / maximum / x | Method | Fragment / leaf bytes | Data witness | Hints / entry items | Combined peak | Executed / static non-push ops (leaf) |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 31 / 991 / 991 | direct | 85 / 92 | 4 | 0 / 1 | 4 | 53 / 53 |
| same | hinted | 42 / 49 | 6 | 1 / 2 | 8 | 35 / 35 |
| 17 / 271 / 271 | direct | 70 / 75 | 4 | 0 / 1 | 4 | 45 / 45 |
| same | hinted | 36 / 41 | 6 | 1 / 2 | 5 | 29 / 29 |
| 31 / 2^31-1 / 2^31-1 | direct | 523 / 532 | 6 | 0 / 1 | 4 | 145 / 229 |
| same | hinted | 44 / 53 | 11 | 1 / 2 | 8 | 35 / 35 |

Terminal costs are 7, 5 and 9 bytes, with zero cross-component optimizer delta.
All scripts receive policy `ALL` below 32 KiB. Actual non-push counts trace
interpreter dispatch and conditional state, excluding skipped arithmetic.
The full-range row shows why the instruction-position counter is insufficient.

The binary reports compiler `124b561ed75ac3ec4c6ad99207d8dcdd3bc67180` and
interpreter `a09e87af444034698697f0a2267e755cf72f9aed` from its embedded lockfile.
Local tapscript uses stack enforcement, minimal-data off, minimal-if on and
experimental OP_CAT disabled,
with a synthetic empty transaction. No signature executes; complete transaction
validation budgets are unmeasured. Evidence is `locally-reproduced`, execution
`unclassified`; no Bitcoin Core consensus or relay-policy validation is claimed.

For each smaller direct row the maximum witness is 4 bytes; the hinted maximum
is 9 because its correct quotient can use four raw bytes before normalization.
The canonical hinted representative is 6 bytes. A small hint contributes 2
length-prefixed bytes (3 in its own witness vector), with maximum contribution 5.
Full-range witnesses attain 6 direct / 11 hinted bytes, with a 5-byte hint
contribution (6 as its own witness vector). There are no tables.

## Composition and negative result

`x=31*a+b` encodes domains `0<=a<32` and `0<=b<31` in one operand. If these
choices are auxiliary to a sorting protocol, that payload remains **one protocol
hint**. Zero auxiliary arithmetic hints does not remove protocol witness data.
No integrated sorting/routing cost is measured; OP-044 tracks that consumer.

The direct operation peaks at four combined items before caller state. A test
with 996 preserved items plus its one operand reaches exactly 1,000; one extra
preserved item rejects. Future inputs and retained outputs also count. Baseline
order is `quotient_hint | x`; it needs exactly one hint per invocation.

All three direct rows lose combined bytes: 96 versus 55, 79 versus 47 and
538 versus 64 for complete leaf plus data witness. They save one entry item,
one quotient hint and two or five witness bytes, with a lower peak than the
matched existing verifier. [NR-088](../negative-results/index.md#nr-088-hint-free-bounded-division-loses-combined-bytes)
retains this scoped byte loss. The full-range leaf also exceeds P2SH's 520-byte
element bound and the legacy/P2WSH 201-static-opcode cap: 229 static operations
count even though only 145 execute. Smaller rows fitting those particular bounds
still need full spend validation. Tapscript retains the combined stack limit.

```sh
CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked arithmetic::scriptint::bounded --lib
CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test primitive_metrics bounded_division_metrics_are_current -- --nocapture
CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test primitive_metrics permutation_rank_metrics_are_current
python3 tools/kb.py validate
CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked -- --skip fields::
```

Coverage exhausts dividends `0..=63` for divisors `1..=32`, all 992 encoded
32-by-31 pairs, boundary multiples and nearby values up to `2^31-1`, and an
LCG starting at `0x4449565f20261017`. Host `/` and `%` supply expected results.
Malformed-input, bypass and caller-state tests use global minimal-data off.
See the [README markers](../../src/arithmetic/scriptint/README.md#bounded-division-without-quotient-hints),
[comparison](../comparisons/arithmetic.md) and
[OP-044](../open-problems.md#op-044-packed-bounded-choice-consumers).
