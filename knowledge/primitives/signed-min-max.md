# Paired signed ScriptNum extrema

Does the paired min/max comparison strategy save Script resources
after accounting for canonical checks, stack routing and conditional
swaps? Compare exact signed minima and maxima for the same hostile
vector, with shared initialization, output checks and local
tapscript assumptions. The hypothesis is that pairing reduces
value comparisons, with a possible branch cost in total execution.

[Pohl's min/max analysis](https://doi.org/10.1145/361405.361423)
provides the comparison-model context. A comparison between the
two members of each pair determines which can change the
running minimum and which can change the maximum. The Script
implementation checks all original numeric encodings before
those comparisons.

[PR #314](https://github.com/solving-bitcoin/bitcoin-scripts/pull/314)
finds an earliest nibble minimum index. [PR #279](https://github.com/solving-bitcoin/bitcoin-scripts/pull/279)
checks one nibble order statistic. This primitive returns both
signed extrema with no index or hint.

The [matched comparison](../comparisons/signed-min-max.md)
prices routing and branch execution. The
[negative result](../negative-results/signed-min-max.md) shows why
a minimum and the arithmetic sum cannot always recover the other
operand within the numeric width limit. See the
[implementation README](../../src/arithmetic/extrema/README.md).
Evidence is `locally-reproduced`. Execution is `unclassified`.
