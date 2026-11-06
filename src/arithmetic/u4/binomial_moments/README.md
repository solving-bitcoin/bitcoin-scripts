# Centered positional binomial moments over u4

Consume a fixed-width vector of canonical, adversarial nibble inputs.
After subtracting eight from each input, return the unweighted, linear,
and binomial quadratic sums. The fragment uses additions, bounded
ScriptNum arithmetic, and no hints.

## Parameters and stack contract

`u4_centered_binomial_moments(n)` requires a count in `0..=997`.
With stacks written bottom to top, it consumes the exact main-stack
suffix `x[0] ... x[n-1]` and returns `M0 M1 M2` as canonical signed
ScriptNums. With `c_i = x[i] - 8`, the outputs are
`M0 = sum(c_i)`, `M1 = sum(i*c_i)`, and
`M2 = sum(binomial(i,2)*c_i)`. This is an offset by eight, so raw zero
contributes -8. Empty input returns three zeros. The caller must
use or remove all outputs and satisfy the terminal predicate.

Consuming from the right, update `M2 += old M1` and
`M1 += old M0` before adding the next centered nibble to `M0`.
A value with original index `i` survives `i` later steps.
Pascal's recurrence gives exactly the three binomial weights.
The first three input guards run before creating accumulator slots
that are still unnecessary. The fragment holds the quadratic state
on the altstack and restores both caller stacks after consuming
the stated suffix. Each partial moment of order `k` has magnitude
at most `8 * binomial(n,k+1)`; the largest is 1,317,395,920 at
width 997, within the four-byte signed arithmetic range.

All `n` ordinary inputs coexist at entry. There are zero hint items
and zero hint bytes. The nonempty combined peak is at most `n + 3`
plus preserved caller state. Width 997 reaches exactly 1,000 items.
At width 995, two preserved items fit and a third fails. The eager
recurrence allocates all three accumulators before the first guard
and needs up to `n + 6` plus caller state.

## Script metrics

Each measured leaf includes canonical checks, setup, all three
moment calculations, identical output equality checks, and terminal
true. The [eager and direct baselines](../../../../research/u4-binomial-moments/baseline.rs)
respect the same output contract. The direct baseline uses the
repository's constant multiplier for the linear and quadratic terms.
Fixture input `i` is `(11*i + 3*floor(i/4)) mod 16`.
Serialized witness includes its CompactSize count and item prefixes
and excludes the leaf, control block, annex, and transaction.
The stack peak includes both stacks. Executed counts cover
non-push instructions in the complete leaf.

| Inputs | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (serialized bytes) | Combined peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | Staged initialization | <!-- metric:binomial_moments_2_seeded_script -->34<!-- /metric:binomial_moments_2_seeded_script --> | <!-- metric:binomial_moments_2_seeded_witness -->4<!-- /metric:binomial_moments_2_seeded_witness --> | 2 | 0 (0 bytes) | <!-- metric:binomial_moments_2_seeded_stack -->5<!-- /metric:binomial_moments_2_seeded_stack --> | <!-- metric:binomial_moments_2_seeded_executed -->22<!-- /metric:binomial_moments_2_seeded_executed --> |
| 2 | Eager initialization | <!-- metric:binomial_moments_2_eager_script -->55<!-- /metric:binomial_moments_2_eager_script --> | <!-- metric:binomial_moments_2_eager_witness -->4<!-- /metric:binomial_moments_2_eager_witness --> | 2 | 0 (0 bytes) | <!-- metric:binomial_moments_2_eager_stack -->8<!-- /metric:binomial_moments_2_eager_stack --> | <!-- metric:binomial_moments_2_eager_executed -->39<!-- /metric:binomial_moments_2_eager_executed --> |
| 2 | Direct weights | <!-- metric:binomial_moments_2_direct_script -->55<!-- /metric:binomial_moments_2_direct_script --> | <!-- metric:binomial_moments_2_direct_witness -->4<!-- /metric:binomial_moments_2_direct_witness --> | 2 | 0 (0 bytes) | <!-- metric:binomial_moments_2_direct_stack -->7<!-- /metric:binomial_moments_2_direct_stack --> | <!-- metric:binomial_moments_2_direct_executed -->37<!-- /metric:binomial_moments_2_direct_executed --> |
| 4 | Staged initialization | <!-- metric:binomial_moments_4_seeded_script -->83<!-- /metric:binomial_moments_4_seeded_script --> | <!-- metric:binomial_moments_4_seeded_witness -->8<!-- /metric:binomial_moments_4_seeded_witness --> | 4 | 0 (0 bytes) | <!-- metric:binomial_moments_4_seeded_stack -->7<!-- /metric:binomial_moments_4_seeded_stack --> | <!-- metric:binomial_moments_4_seeded_executed -->60<!-- /metric:binomial_moments_4_seeded_executed --> |
| 4 | Eager initialization | <!-- metric:binomial_moments_4_eager_script -->101<!-- /metric:binomial_moments_4_eager_script --> | <!-- metric:binomial_moments_4_eager_witness -->8<!-- /metric:binomial_moments_4_eager_witness --> | 4 | 0 (0 bytes) | <!-- metric:binomial_moments_4_eager_stack -->10<!-- /metric:binomial_moments_4_eager_stack --> | <!-- metric:binomial_moments_4_eager_executed -->75<!-- /metric:binomial_moments_4_eager_executed --> |
| 4 | Direct weights | <!-- metric:binomial_moments_4_direct_script -->113<!-- /metric:binomial_moments_4_direct_script --> | <!-- metric:binomial_moments_4_direct_witness -->8<!-- /metric:binomial_moments_4_direct_witness --> | 4 | 0 (0 bytes) | <!-- metric:binomial_moments_4_direct_stack -->10<!-- /metric:binomial_moments_4_direct_stack --> | <!-- metric:binomial_moments_4_direct_executed -->84<!-- /metric:binomial_moments_4_direct_executed --> |
| 32 | Staged initialization | <!-- metric:binomial_moments_32_seeded_script -->700<!-- /metric:binomial_moments_32_seeded_script --> | <!-- metric:binomial_moments_32_seeded_witness -->62<!-- /metric:binomial_moments_32_seeded_witness --> | 32 | 0 (0 bytes) | <!-- metric:binomial_moments_32_seeded_stack -->35<!-- /metric:binomial_moments_32_seeded_stack --> | <!-- metric:binomial_moments_32_seeded_executed -->564<!-- /metric:binomial_moments_32_seeded_executed --> |
| 32 | Eager initialization | <!-- metric:binomial_moments_32_eager_script -->718<!-- /metric:binomial_moments_32_eager_script --> | <!-- metric:binomial_moments_32_eager_witness -->62<!-- /metric:binomial_moments_32_eager_witness --> | 32 | 0 (0 bytes) | <!-- metric:binomial_moments_32_eager_stack -->38<!-- /metric:binomial_moments_32_eager_stack --> | <!-- metric:binomial_moments_32_eager_executed -->579<!-- /metric:binomial_moments_32_eager_executed --> |
| 32 | Direct weights | <!-- metric:binomial_moments_32_direct_script -->1546<!-- /metric:binomial_moments_32_direct_script --> | <!-- metric:binomial_moments_32_direct_witness -->62<!-- /metric:binomial_moments_32_direct_witness --> | 32 | 0 (0 bytes) | <!-- metric:binomial_moments_32_direct_stack -->41<!-- /metric:binomial_moments_32_direct_stack --> | <!-- metric:binomial_moments_32_direct_executed -->1404<!-- /metric:binomial_moments_32_direct_executed --> |
| 128 | Staged initialization | <!-- metric:binomial_moments_128_seeded_script -->2814<!-- /metric:binomial_moments_128_seeded_script --> | <!-- metric:binomial_moments_128_seeded_witness -->249<!-- /metric:binomial_moments_128_seeded_witness --> | 128 | 0 (0 bytes) | <!-- metric:binomial_moments_128_seeded_stack -->131<!-- /metric:binomial_moments_128_seeded_stack --> | <!-- metric:binomial_moments_128_seeded_executed -->2292<!-- /metric:binomial_moments_128_seeded_executed --> |
| 128 | Eager initialization | <!-- metric:binomial_moments_128_eager_script -->2832<!-- /metric:binomial_moments_128_eager_script --> | <!-- metric:binomial_moments_128_eager_witness -->249<!-- /metric:binomial_moments_128_eager_witness --> | 128 | 0 (0 bytes) | <!-- metric:binomial_moments_128_eager_stack -->134<!-- /metric:binomial_moments_128_eager_stack --> | <!-- metric:binomial_moments_128_eager_executed -->2307<!-- /metric:binomial_moments_128_eager_executed --> |
| 128 | Direct weights | <!-- metric:binomial_moments_128_direct_script -->8424<!-- /metric:binomial_moments_128_direct_script --> | <!-- metric:binomial_moments_128_direct_witness -->249<!-- /metric:binomial_moments_128_direct_witness --> | 128 | 0 (0 bytes) | <!-- metric:binomial_moments_128_direct_stack -->139<!-- /metric:binomial_moments_128_direct_stack --> | <!-- metric:binomial_moments_128_direct_executed -->7896<!-- /metric:binomial_moments_128_direct_executed --> |

## Security, compatibility and execution

Every input must be byte-canonical and lie in `0..=15`. The tuple
does not authenticate a vector. The inputs `[8,8,8,8]` and
`[9,5,11,7]` have the same three zero outputs. The difference
between them is a discrete third difference, which cancels all
three degree-at-most-two weights.

All measured leaves use `CompileOptions::ALL` through the central
policy, the pinned local tapscript Consensus profile with the
520-byte item and 1,000-item combined-stack limits, and zero
signature validation charge. Evidence is `locally-reproduced`
and execution is `unclassified`. The opcodes are available in
bare, P2SH, P2WSH and tapscript, with legacy script-size and
opcode-count limits requiring separate evaluation. See
[script types](../../../../docs/script-types.md) and
[standardness](../../../../docs/standardness.md).

## Reproduction

```sh
cargo test --locked --lib arithmetic::u4::binomial_moments::tests
cargo test --locked --test primitive_metrics binomial_moment_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

The tests check a direct host sum, exhaustive short restricted
vectors, impulses at every position of a 17-item vector, malformed
items, wrong outputs, a deliberate collision, and both stack and
signed arithmetic boundaries. See the
[knowledge entry](../../../../knowledge/primitives/u4-binomial-moments.md).
