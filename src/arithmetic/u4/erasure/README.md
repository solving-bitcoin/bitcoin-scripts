# Checked recovery of one erased nibble

Recover one missing nibble from a hostile vector of surviving
nibbles and two public checks modulo 17. The second check detects
any single changed surviving nibble relative to the original vector.

## Parameters and stack contract

`recover_u4_erasure(width, erased, sum, weighted_sum)` takes
generation-time parameters. Width is in `2..=17`. The erased
zero-based position is in `0..width`. The public checks are
`sum = Σ x[i] mod 17` and `weighted_sum = Σ i*x[i] mod 17`.
Their values are in `0..=16`. There are no defaults.

Main starts with the surviving nibbles in original order, with the
last surviving item on top. Each item must be a canonical ScriptNum
nibble. Success consumes them and leaves the canonical missing nibble.
Both caller stacks survive. Zero is a valid result. The caller
binds or consumes the returned value and supplies any terminal predicate.

## Construction

The first residual yields the missing nibble modulo 17. Reject
residue 16. For erased index `e`, subtract `e` times the first check
from the second at generation time. The missing coordinate's new
coefficient is zero. The other coefficients are `i-e mod 17`,
represented in `[-8,8]` to keep the small constant products cheap.
The script accumulates both integer residuals and reduces them
once each after all surviving nibbles have been checked.

The [direct baseline](../../../../research/checked-u4-erasure/baseline.rs)
computes the second check over the original weights and inserts the
recovered value at its original coefficient. Both schedules share
canonical nibble validation, the constant multiplier and bounded
residue reduction.

## Script metrics

The [fixture](../../../../research/checked-u4-erasure/fixture.rs)
uses digit `(7*i + floor(i/3) + 5) mod 16` at index `i`.
The complete leaves include both checks, exact recovered-nibble
equality and terminal true. Data witness includes item count and
lengths and excludes leaf, control block, annex and transaction.
All surviving digits coexist at entry. Peak combines both stacks.
Executed non-push counts include processed control delimiters.

| Width | Erased index | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (bytes) | Combined peak | Executed non-push ops |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | 1 | Centered check | <!-- metric:u4_erasure_4_1_centered_script -->116<!-- /metric:u4_erasure_4_1_centered_script --> | <!-- metric:u4_erasure_4_1_centered_witness -->7<!-- /metric:u4_erasure_4_1_centered_witness --> | 3 | 0 (0 bytes) | <!-- metric:u4_erasure_4_1_centered_stack -->7<!-- /metric:u4_erasure_4_1_centered_stack --> | <!-- metric:u4_erasure_4_1_centered_executed -->74<!-- /metric:u4_erasure_4_1_centered_executed --> |
| 4 | 1 | Direct recomposition | <!-- metric:u4_erasure_4_1_direct_script -->116<!-- /metric:u4_erasure_4_1_direct_script --> | <!-- metric:u4_erasure_4_1_direct_witness -->7<!-- /metric:u4_erasure_4_1_direct_witness --> | 3 | 0 (0 bytes) | <!-- metric:u4_erasure_4_1_direct_stack -->7<!-- /metric:u4_erasure_4_1_direct_stack --> | <!-- metric:u4_erasure_4_1_direct_executed -->76<!-- /metric:u4_erasure_4_1_direct_executed --> |
| 17 | 0 | Centered check | <!-- metric:u4_erasure_17_0_centered_script -->479<!-- /metric:u4_erasure_17_0_centered_script --> | <!-- metric:u4_erasure_17_0_centered_witness -->33<!-- /metric:u4_erasure_17_0_centered_witness --> | 16 | 0 (0 bytes) | <!-- metric:u4_erasure_17_0_centered_stack -->20<!-- /metric:u4_erasure_17_0_centered_stack --> | <!-- metric:u4_erasure_17_0_centered_executed -->359<!-- /metric:u4_erasure_17_0_centered_executed --> |
| 17 | 0 | Direct recomposition | <!-- metric:u4_erasure_17_0_direct_script -->525<!-- /metric:u4_erasure_17_0_direct_script --> | <!-- metric:u4_erasure_17_0_direct_witness -->33<!-- /metric:u4_erasure_17_0_direct_witness --> | 16 | 0 (0 bytes) | <!-- metric:u4_erasure_17_0_direct_stack -->21<!-- /metric:u4_erasure_17_0_direct_stack --> | <!-- metric:u4_erasure_17_0_direct_executed -->408<!-- /metric:u4_erasure_17_0_direct_executed --> |
| 17 | 8 | Centered check | <!-- metric:u4_erasure_17_8_centered_script -->468<!-- /metric:u4_erasure_17_8_centered_script --> | <!-- metric:u4_erasure_17_8_centered_witness -->33<!-- /metric:u4_erasure_17_8_centered_witness --> | 16 | 0 (0 bytes) | <!-- metric:u4_erasure_17_8_centered_stack -->20<!-- /metric:u4_erasure_17_8_centered_stack --> | <!-- metric:u4_erasure_17_8_centered_executed -->357<!-- /metric:u4_erasure_17_8_centered_executed --> |
| 17 | 8 | Direct recomposition | <!-- metric:u4_erasure_17_8_direct_script -->522<!-- /metric:u4_erasure_17_8_direct_script --> | <!-- metric:u4_erasure_17_8_direct_witness -->33<!-- /metric:u4_erasure_17_8_direct_witness --> | 16 | 0 (0 bytes) | <!-- metric:u4_erasure_17_8_direct_stack -->21<!-- /metric:u4_erasure_17_8_direct_stack --> | <!-- metric:u4_erasure_17_8_direct_executed -->405<!-- /metric:u4_erasure_17_8_direct_executed --> |
| 17 | 16 | Centered check | <!-- metric:u4_erasure_17_16_centered_script -->468<!-- /metric:u4_erasure_17_16_centered_script --> | <!-- metric:u4_erasure_17_16_centered_witness -->33<!-- /metric:u4_erasure_17_16_centered_witness --> | 16 | 0 (0 bytes) | <!-- metric:u4_erasure_17_16_centered_stack -->20<!-- /metric:u4_erasure_17_16_centered_stack --> | <!-- metric:u4_erasure_17_16_centered_executed -->356<!-- /metric:u4_erasure_17_16_centered_executed --> |
| 17 | 16 | Direct recomposition | <!-- metric:u4_erasure_17_16_direct_script -->522<!-- /metric:u4_erasure_17_16_direct_script --> | <!-- metric:u4_erasure_17_16_direct_witness -->33<!-- /metric:u4_erasure_17_16_direct_witness --> | 16 | 0 (0 bytes) | <!-- metric:u4_erasure_17_16_direct_stack -->21<!-- /metric:u4_erasure_17_16_direct_stack --> | <!-- metric:u4_erasure_17_16_direct_executed -->405<!-- /metric:u4_erasure_17_16_direct_executed --> |

## Security, compatibility and composition

The public checks and erased index define the relation. If exactly
one supplied digit changes, its nonzero difference is multiplied
by a nonzero coefficient in the transformed check. This cannot
cancel modulo the prime 17. Width 18 would repeat a coefficient.
Two changed surviving digits can cancel, as the tests demonstrate.
This check makes no cryptographic authentication claim.

Each invocation starts with `width-1` ordinary items and zero
hints. The erased index and both check residues are script constants.
Caller state and every future preloaded input still count toward
the combined 1,000-item bound. The width-17 fixture with erased
index eight reaches exactly 1,000 with 980 caller items, and one
more fails.

All measured leaves compile with policy `ALL`. The trace uses
stack-limited local tapscript Consensus, a synthetic transaction,
experimental OP_CAT disabled and zero signature charge. The fixtures
also pass the local Policy profile. The opcodes exist in bare, P2SH,
P2WSH and tapscript, subject to their own
[script-type](../../../../docs/script-types.md) and
[standardness](../../../../docs/standardness.md) limits.
Evidence is `locally-reproduced`. Execution is `unclassified`.

## Reproduction

```sh
cargo test --locked --lib arithmetic::u4::erasure::tests
cargo test --locked --test primitive_metrics u4_erasure_recovery_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

Tests cover every width-two vector, all single substitutions
of a width-17 fixture at every erasure position, malformed
nibbles, incompatible residues, the two-error counterexample
and both caller stacks. See the
[knowledge page](../../../../knowledge/primitives/u4-erasure-recovery.md).
