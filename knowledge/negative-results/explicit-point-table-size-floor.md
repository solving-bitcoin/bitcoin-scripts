# Explicit legacy point tables exceed the 100,000-vbyte target

Question: can lookup or subset-code optimization alone reduce the current
legacy sum-key publication of arbitrary 256-byte data below 100,000 vB,
including creation and spending?

For separately stored HASH160 key commitments, grant a 21-byte table entry,
a 34-byte selected public-key push, and a freely available 58-byte signature
plus its push. This costs at least `21N+93T` stripped bytes for N candidates
and T revelations. The current sum-key length guard does not accept shorter
signatures.

For a uniform 2,048-bit message, entropy subadditivity bounds the selection
information by `sum_j H2(p_j)`, where p_j is the probability of selecting
candidate j. Minimizing `(21+93p)/H2(p)` gives 54.479425 bytes per bit, or
**111,573.86 vB** before opcodes, selectors, transaction framing or wrappers.
This covers nonuniform and correlated subset codes within the stated
independent explicit-table representation. Exact fixed-weight integer
optimization gives 111,891 bytes. With the measured 71-byte signatures,
the corresponding continuous and exact bounds are 119,403.84 and 119,746.

These are `locally-reproduced` arithmetic and `inspected` structural bounds;
deployment is `unclassified`. They do not exclude implicit candidate sets,
witness discount, different primitives, or a smaller structured payload.
The [windowed small-R candidate](../../research/pointlocks-2026-09-17/windowed-publication.md)
explicitly changes the primitive and uses witness discount, so is outside
this bound. Its security assumptions are separate.

The [complete bare publication](../../research/pointlocks-2026-09-17/bare-publication.md)
now confirms 161,382 vB actual / 161,560 vB canonical maximum with Core block
validation. Its 553 scalar openings and 256-byte roundtrip do not alter the
representation-family bound. Default relay rejects the bare scripts.

The [Binohash HORS table comparison](../../research/pointlocks-2026-09-17/hors-lookup-comparison.md)
finds a 153,125-vB maximum serialization estimate with ten-of-57 pools. Its
local pool tests do not establish native complete-publication validity. Direct
stack lookup reduces opcode use but produces a slightly larger estimate;
neither layout changes the explicit-key representation behind this bound.

The [table-first selector](../../research/pointlocks-2026-09-17/clamped-lookup.md)
further reduces the estimated total to 151,176 vB. Its constituent pools have
native Core validation, while the mixed publication remains a sizing result.
Selecting a committed entry before loading operands saves verification work
but retains the representation behind this lower bound. Reusing one auxiliary
opening across targets with public offsets reveals all those targets at once;
it cannot replace independent candidate entries for a one-of-n choice.

Reproducible calculations and exact scope:

- [Entropy bound and compiled bare-script probe](../../research/pointlocks-2026-09-17/sub100-lookup.md).
- [Exact integer optimization and antichain argument](../../research/pointlocks-2026-09-17/sub100-encoding.md).
- [Endpoint-graph setup and density bounds](../../research/pointlocks-2026-09-17/endpoint-graph-search.md).
- [Witness setup and Taproot-tweak boundaries](../../research/pointlocks-2026-09-17/sub100-witness-algebra.md).

The last note also records why the equation `Q=P+T` with fixed NUMS P does
not alone certify a Taproot point lock under malicious setup: choosing a
known-secret output Q first passes that equation but permits a key-path spend
without revealing the scalar of T.
