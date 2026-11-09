# Stable bipartition of opaque stack items

Can a single live-width cursor route both stable groups of an opaque
payload/flag stream with fewer script bytes and a lower stack peak than
recomputing each roll depth? Compare identical input and output stack
contracts with the same deterministic raw data, terminal predicates and
local tapscript profile. The hypothesis is that carrying the live width
avoids per-record constant pushes and additions, allowing the 499-pair
configuration to fit under the 1,000-item combined limit.

The immutable [C++ draft `[alg.partitions]`](https://github.com/Eelis/draft/blob/c7015b485cc3db8efaa9dfb9ff0809c5394a4ed1/source/algorithms.tex#L9799)
provides semantic context for stable partition. This Script contract emits
the two groups on different stacks. It consumes all flags and keeps
every opaque payload. Tapscript MINIMALIF validates the flags, and the
caller retains responsibility for the exact input suffix and any
authentication or payload provenance.

The cursor equals the live main width below itself, excluding caller
state. Two rolls of that depth remove the oldest remaining payload/flag
pair. False payloads accumulate on main and true payloads accumulate on
alt, in original input order. The cursor decreases by one for false
or two for true and ends at the false count.

[Stable selection](stable-selection.md) and its sparse indexed variant
in [PR #303](https://github.com/solving-bitcoin/bitcoin-scripts/pull/303)
return one retained subsequence. This split preserves the complement
on main and places the selected subsequence on alt. Their script sizes
include different output contracts and are not directly comparable.
The [matched comparison](../comparisons/stack-bipartition.md)
uses two schedules with identical split outputs.

See the [implementation and measured configurations](../../src/support/split/README.md)
and [frontier failure](../negative-results/stable-bipartition.md).
Evidence is `locally-reproduced` and execution is `unclassified`.
