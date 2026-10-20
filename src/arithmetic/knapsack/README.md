# Subset-sum verification

`knapsack::subset_sum_verify(weights, target)` checks a witness selection against
public weights: one selector item per weight, each the empty item (not selected) or
`[1]` (selected); the script adds the weight for every selected item with
`OP_IF` and compares the sum with the public target, returning one Boolean. The
sum of all weights must fit a four-byte ScriptNum (checked at generation time),
there are at most 998 weights, and no hints beyond the selection itself are used.
With all weights equal to one it is a cardinality check.

In tapscript, MINIMALIF makes `OP_IF` abort on any selector other than the empty
item or `[1]`, so the plain form checks canonical bits at no extra cost (BIP 342;
reproduced by the local executor, which does not allow switching it off).
`subset_sum_verify_explicit` adds a numeric range check and a reserialization check
per selector for contexts without consensus MINIMALIF (legacy and segwit v0);
that leniency could not be exercised locally.

## Script metrics

Fragment-only boundary: the selector tests and conditional additions plus the
target comparison; input pushes and terminal predicate excluded. Fixture: 32
weights `(37*i + 11) mod 65535 + 1`, selected where `i mod 3 != 0`, target equal to
the selected sum. Witness bytes serialize the count and every selector item.

| Configuration | Script bytes | Witness bytes | Witness items | Hint items | Combined peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Plain (tapscript MINIMALIF), 32 weights | <!-- metric:subset_sum_32 -->224<!-- /metric:subset_sum_32 --> | <!-- metric:subset_sum_32_witness -->54<!-- /metric:subset_sum_32_witness --> | <!-- metric:subset_sum_32_witness_items -->32<!-- /metric:subset_sum_32_witness_items --> | 0 | <!-- metric:subset_sum_32_stack -->33<!-- /metric:subset_sum_32_stack --> | <!-- metric:subset_sum_32_opcodes -->129<!-- /metric:subset_sum_32_opcodes --> |
| Explicit canonical checks, 32 weights | <!-- metric:subset_sum_explicit_32 -->544<!-- /metric:subset_sum_explicit_32 --> | same | same | 0 | <!-- metric:subset_sum_explicit_32_stack -->36<!-- /metric:subset_sum_explicit_32_stack --> | <!-- metric:subset_sum_explicit_32_opcodes -->353<!-- /metric:subset_sum_explicit_32_opcodes --> |

See the [knowledge page](../../../knowledge/primitives/subset-sum.md).
