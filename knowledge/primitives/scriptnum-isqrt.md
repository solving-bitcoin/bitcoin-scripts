# Integer floor root over four-byte ScriptNum

`arithmetic::integer_root::scriptnum_isqrt(bit_count)` consumes a hostile
numeric x in `0..=2^bit_count-1` for widths 1..=31, returns canonical floor
sqrt(x), and preserves both caller stacks. It tracks residual x-r*r and tries
root bits with differences `2*r*b+b*b`, using the existing constant multiplier.
One ordinary entry item, zero hints, no externally supplied state. Numeric
aliases are allowed when the profile permits them; the caller binds bytes,
input provenance and a terminal predicate where required.

Question: does a residual-difference schedule beat balanced constant square
threshold dispatch while staying inside four-byte arithmetic? Matched boundaries
include guards, complete calculation and residual cleanup; exclude witness
pushes. Leaves bind the exact root then TRUE. The original immutable prototype
preceded production changes; integer square root itself is established, not a
new algorithm claim. Catalog absence is only a coverage gap.

| Width | Restoring fragment / leaf | Threshold fragment / leaf | Peak restoring / threshold |
| --- | ---: | ---: | ---: |
| 1 | 27 / 30 | 18 / 21 | 5 / 3 |
| 6 | 72 / 75 | 70 / 73 | 5 / 3 |
| 7 | 98 / 101 | 106 / 109 | 5 / 3 |
| 8 | 99 / 102 | 147 / 150 | 5 / 3 |
| 16 | 232 / 237 | 2,989 / 2,994 | 5 / 3 |
| 24 | 405 / 410 | 54,109 / 54,114 | 5 / 3 |
| 31 | 614 / 620 | 659,112 / 659,118 | 5 / 3 |

Restoring is ALL everywhere; threshold at 24/31 is explicitly unoptimized NONE.
The measured crossover is seven bits: 98 versus 106 bytes, after a six-bit
loss (72 versus 70). This is not universal dominance. Max-input witness bytes at 8/16/31
are 4/5/6; all permitted numeric encodings have a six-byte allowed maximum per
one-item witness. Each invocation uses exactly zero hints and zero hint bytes.
Static counts are separate: 31-bit restoring has 503 non-push opcodes. Dynamic
executed counts and complete transaction-budget evidence are unavailable.

Two preloaded 31-bit roots measure 1,230/1,235 fragment/leaf bytes, four witness
bytes / two data items / zero hints / peak six. Thirty-two measure 19,710/19,803,
89 witness bytes / 32 data / zero hints / peak 36. Both use ALL; component sums
1,232/19,712 plus delta -2 equal the final fragments. At 996 roots, all 996
ordinary inputs coexist at entry, with zero total hints and witness 2,738;
peak is exactly 1,000. Fragment/leaf are explicitly unoptimized NONE at
615,528/618,389. Raw component sum equals the whole fragment; individually
ALL-compiled sum 613,536 plus policy delta +1,992 reconciles the different
optimization choice. Future inputs and accumulated roots count; 997 rejects
StackSize at 1,001. Allowed witness maxima are 11/161/4,983 at 2/32/996 inputs.

The finite arithmetic invariant and bounds are explained in the implementation
README. For the largest root width, every trial delta is <=1,342,177,280;
conditional subtraction preserves nonnegative residual. The shared suite tests
all 65,536 16-bit inputs for both schedules and their canonical-input
compositions, all 92,681 distinct 31-bit square endpoints for the public API,
deterministic interiors, malformed and short inputs at every live position,
allowed/rejected aliases, caller main/alt frontiers and all preloaded outputs.
Compiled guard/canonicality/terminal bypasses have unchanged valid controls and
are caught by the same typed assertion. Trial equality and ordering mutations
are caught by the same exact-result assertion.

Evidence is locally-reproduced; every configuration is unclassified. Explicit
local Consensus tapscript uses numeric minimality off, MINIMALIF on, stack checks
on, OP_CAT off, synthetic empty transaction/data-only budget and no signatures.
Local Policy alias/entry-size rejection is separate from complete relay evidence.
Root zero is correct data but a false bare predicate; the checked leaf returns
TRUE. Literal root checks admit entire root intervals and do not authenticate x.

See [implementation](../../src/arithmetic/integer_root/README.md),
[immutable prototype and integrated report](../../research/integer-root-bounds/README.md),
[arithmetic comparison](../comparisons/arithmetic.md),
[NR-080](../negative-results/integer-root-bounds.md) and OP-038.


The 53-root fragment has raw size 32,754 and final size 32,646 with ALL; its
exact-output leaf has raw/final size 32,903 with NONE, explicitly unoptimized.
Adding 149 raw predicate bytes therefore changes final size by 257 because the
whole compilation policy changes. Both use 53 ordinary data items, zero hints,
142 fixture witness bytes (allowed maximum 266), and peak 57. At 54 roots,
fragment/leaf are 33,372/33,525, both unoptimized NONE. Fragment compilation
options must not be inherited by a composed leaf.
