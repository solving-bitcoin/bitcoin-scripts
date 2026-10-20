# Subset-sum verification with free canonical selectors

## Research question and hypothesis

Subset sum is the canonical NP witness: a prover selects items whose public weights
add up to a public target. What does it cost to verify such a witness in Script, and
how much of that cost is the canonical-selector check? The hypothesis is that
`OP_IF` plus an add costs a handful of bytes per weight and that, in tapscript,
MINIMALIF supplies the range and canonicality check for free, making explicit
checks a large overhead. This is a new local construction; no global novelty claim
is made.

## Contract and proof

`arithmetic::knapsack::subset_sum_verify(weights, target)`, `1..=998` weights:

```text
witness: s[0] ... s[n-1]   (each empty = not selected, or [1] = selected)
-> ok = 1  iff  sum of weights[i] over selected i  ==  target
```

The accumulator starts at zero and each weight is added under `OP_IF`; the top
selector belongs to the last weight. All weights, and so every partial sum, fit a
four-byte ScriptNum because the total is checked at generation time to be at most
`2^31 - 1`. Weights may be zero or repeated. With every weight equal to one it is a
cardinality check; number partitioning is the target `total / 2`. In tapscript
MINIMALIF (BIP 342) aborts any `OP_IF` argument other than the empty item or `[1]`,
so the selection is a canonical bit vector; the local executor reproduces this and
does not offer a switch to disable it. `subset_sum_verify_explicit` adds a numeric
`0..=1` range check and a reserialization check per selector for contexts where
MINIMALIF is only policy; those contexts are not exercised locally.

## Threat model and evidence

The selection is hostile. Tests cover: all 256 subsets of eight Fibonacci-like
weights against eight targets (every subset sum and off-by-one targets); zero,
duplicate and near-limit weights (a total of exactly `2^31 - 1`); selector encodings
`[2]`, `[0x81]`, `[1, 0]`, `[0, 0]`, `[0x80]` and `[2, 0]` aborting under both the
local consensus and policy tapscript profiles and under the explicit form;
generation-time rejection of an empty list, overflow, an oversized target and more
than 998 weights; preserved main/alt state; and an exact stack frontier. Evidence is
`locally-reproduced`; execution is `unclassified` (the claim that MINIMALIF is a
consensus rule in tapscript is from BIP 342 and has not been checked against
Bitcoin Core here).

## Measured comparison

Boundary: the policy-compiled fragment; input pushes and terminal predicate
excluded; zero hints beyond the selection. Weights `(37i + 11) mod 65535 + 1`.
Sizes pinned by `knapsack::tests::recorded_sizes_are_current`.

| Weights | Plain (tapscript) | Explicit canonical checks |
| ---: | ---: | ---: |
| 8 | 56 | 136 |
| 32 | 224 | 544 |
| 128 | 896 | 2,176 |

The plain form costs 7 script bytes per weight with 16-bit weights (4 plus the weight push: 6 for weights below 256 and 5 below 16) and a combined peak of
`n + 1`; the witness is 54 bytes for 32 selectors (an empty item is one byte, `[1]`
two). The explicit form costs 17 bytes per weight, 2.4 times as much, so MINIMALIF
saves 58% of the script in tapscript.

## Reproduction

```sh
cargo test --locked arithmetic::knapsack::tests --lib
cargo test --locked --test primitive_metrics subset_sum_metrics_are_current -- --exact
python3 tools/kb.py validate
```
