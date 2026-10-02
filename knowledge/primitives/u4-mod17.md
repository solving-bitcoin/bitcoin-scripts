# Checked base-16 integer residue modulo 17

## Research question and hypothesis

Can a hostile big-endian nibble vector be reduced to its integer value modulo
17 with no table or hints, bounded small arithmetic, and less script than a
forward Horner scheduler? The hypothesis is that `16 = -1 (mod17)` permits a
reverse fold that replaces depth-dependent input routing with `OP_SWAP`, even
after paying for the even-length sign correction. This is a new local Script
construction; no global novelty claim is made for the elementary identity.

## Contract and proof

`arithmetic::u4::mod17::u4_nibbles_to_mod17(n)` takes `1..=997` nibbles:

```text
preserved | x[0] ... x[n-1] -> preserved | (sum x[i]*16^(n-1-i)) mod17
```

Every input is checked as a canonical ScriptNum in `0..=15`. Starting with the
last nibble, set `r=x-r (mod17)` for each preceding nibble. The invariant after
processing a suffix is its alternating signed sum, with the newest nibble
positive. Each difference lies in `-16..=15`, so adding 17 iff negative gives
`0..=16`. The reverse result differs from the forward positional sum by
`(-1)^(n-1)`; even lengths therefore negate and normalize once. All numeric
operands fit the four-byte ScriptNum domain. This derivation is local algebra,
not an inference of consensus validity from a mathematical proof.

The altstack is untouched and unrelated main-stack state survives. The exact
fragment stack bound is `n+3+p<=1000`, where `p` includes both preserved stacks.
Tests at 1/2/32/500/997 inputs exercise the boundary and one additional item.
Surrounding state is supplied at runtime to prevent optimizer removal. The
frontier test checks the observable fragment output directly, without a terminal
consumer; complete leaves must separately budget cleanup and their predicate.

## Threat model and evidence

All witness items are hostile. The shared contract suite tests malformed items
at every position, negative/above-range values, numeric overflows, redundant
positive encodings, zero aliases, short input, asymmetric ordering and both
preserved stacks. Deliberate bytecode mutations remove all range checks or all
canonicality checks in each of three measured families; the same typed-error
assertion catches each mutation, with valid controls and clean output cleanup.
The local consensus profile disables minimal-number policy, so the canonicality
check is tested independently of that policy. The sibling modulo-16 reducer
passes this audit; no production fix is justified.

Exhaustive lengths 1/2/3 and deterministic longer vectors check results against
ordinary left-to-right base-16 Horner arithmetic in Rust. This establishes
`locally-reproduced` evidence, without an independent Script interpreter.
Deployment remains `unclassified`; local resource acceptance is separate from
Bitcoin Core consensus or policy evidence. Arithmetic/opcode rules are pinned
to [Core v30.0 source](https://github.com/bitcoin/bitcoin/blob/d0f6d9953a15d7c7111d46dcb76ab2bb18e5dee3/src/script/interpreter.cpp).

## Measured comparison

Boundary: fragment-only, all canonical checks and arithmetic; input pushes,
terminal predicate and transaction excluded. Both schedulers receive the same
witness `x[i]=(7*i+floor(i/3)) mod16`, leave one canonical residue, and preserve
state. Peaks use a separately compiled complete leaf ending in expected-residue
`OP_EQUAL`; fragment and leaf hashes are both recorded.

| Inputs | Reverse script | Forward script | Serialized data witness | Data items | Hint items | Combined peak, both |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 10 | 22 | 2 | 1 | 0 | 4 |
| 2 | 40 | 42 | 4 | 2 | 0 | 5 |
| 32 | 670 | 746 | 62 | 32 | 0 | 35 |
| 128 | 2,686 | 3,050 | 246 | 128 | 0 | 131 |
| 997 | 20,926 | 24,775 | 1,913 | 997 | 0 | 1,000 |

All measurements use the repository compilation policy and stay below the
unoptimized-size cutoff. The report records exact inputs via their generator
and serialized-witness hash, terminal result, final hashes, and embedded-lockfile
pins. Static non-push counts for 32 inputs are 478/509; executed-opcode counts
are unavailable and must not be inferred from tapscript's position statistic.
Complete transaction validation weight is also unavailable. Zero hints per
invocation and per measured batch means no hint coexistence burden, but all
`n` data items coexist at script entry. Data-only witness bytes exclude the
leaf and control block and are not a complete Taproot witness size.

The existing sum-mod16 and XOR reducers have different semantics: their
permutation-invariant results cannot replace the positional mod17 residue.
The sum's 32-input published costs (592 bytes / 66-item peak) and XOR's
16-input costs (740 bytes / 273-item peak) are navigation aids, not dominance
comparisons. In particular,
the XOR reducer has a numeric-range contract, whereas this primitive also
binds canonical encodings. The like-for-like forward schedule is dominated
for the measured objective; see [the negative result](../negative-results/u4-mod17-forward-routing.md).

## Security and composition limitations

This is a checksum, not a commitment or signature primitive. A single nibble
substitution has a nonzero residue change because its difference is in
`-15..=15` and its positional weight is ±1. An adjacent unequal swap changes
it by `±2*(a-b)`, also nonzero modulo17. Equal-parity permutations and cancelling
multi-symbol changes can collide. Vector length is public generation-time
state and leading zero insertion can preserve the integer residue. No protocol
is claimed to authenticate or bind data by this checksum; Winternitz's stronger
anti-forwarding obligations remain unchanged.

The 32-input configuration exceeds the 201-operation legacy/P2WSH ceiling.
Opcode compatibility alone does not establish small-profile validity or
standardness. No signature, Taproot commitment, policy or Core transaction
harness was run for this construction. Future complete-leaf validation is
tracked in [OP-031](../open-problems.md#op-031--positional-nibble-checksum-composition).

## Reproduction and artifacts

See [implementation documentation](../../src/arithmetic/u4/README.md#base-16-integer-residue-modulo-17),
[raw report](../../research/u4-mod17/metrics.json) and
[artifact manifest](../../research/u4-mod17/README.md). Compiler is
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`; interpreter is
`a09e87af444034698697f0a2267e755cf72f9aed`. The report reads those identities
from `support::provenance`, rather than copying historical pins.

```sh
cargo test --locked --lib arithmetic::u4::mod17
cargo test --locked --test u4_reduction_contract
cargo test --locked --test primitive_metrics u4_mod17_metrics_are_current
cargo run --locked --example u4_mod17_benchmark
python3 tools/kb.py validate
cargo fmt --all -- --check
cargo test --locked -- --skip fields::
```
