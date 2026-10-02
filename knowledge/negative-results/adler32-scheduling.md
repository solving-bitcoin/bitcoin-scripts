# NR-077: Adler input validation overlapping accumulators loses stack capacity

As of 2026-10-02: `locally-reproduced`, `unclassified` local tapscript.

Question: can the canonical byte/two-state Adler recurrence safely process
997 all-at-entry inputs? The original experiment parked all inputs first,
allocated A/B, then validated each popped byte while both accumulators were
live. It peaks at n+5. Its n995 fragment/leaf are 19084/19094 bytes and accept
at 1,000 combined items, but n996 and n997 reject with typed `StackSize`
at the first 1,001-item state. Their partial peaks are rejected-execution
observations, not accepted resource configurations.

The measured repair validates before staging each input and initializes
the accumulators afterward. It peaks at n+3 for positive n. The n997
fragment/leaf remain 19122/19132 bytes, now accepted at exactly 1,000 items;
one caller item rejects. The data witness is 2,994 serialized bytes / 997
ordinary data items, **zero hint items**; all data coexist at entry. Both
caller stacks survive in the exact-boundary contract tests. No resource
check is disabled. The API rejects n998 at generation time; the retained
prevalidated streaming probe at n998 also rejects at peak 1,001.

The shared harness has an original n995 valid control, original n996/997
typed failures and repaired successes. Substituting the original schedule
causes the same clean-success assertion to fail. Removing range or raw
canonicality guards from actual compiled bytecode likewise defeats the
same typed rejection assertion at every operand position, with unchanged
output cleanup and clean valid controls. See
[`tests/adler32_contract.rs`](../../tests/adler32_contract.rs).

Naive per-byte normalization is additionally dominated by prefix-bounded
streaming at the measured n32 boundary: 1442 versus 740 fragment bytes at
the same 35-item peak, witness shape and zero hints. The public deferred
form reaches 636 bytes. The n728 naive raw fragment/leaf cross the optimizer
cutoff separately (32762/32773, ALL/NONE); costs and flags cannot be inherited
across those boundaries. The strongest measured streaming baseline's
n997 41253/41263 bytes are explicitly unoptimized.

Adler's easy collision `01 02 01` / `02 00 02` gives `(A,B)=(5,11)` in the
independent zlib oracle and both local Script schedules. This is a scope
boundary for an error-detection checksum, not an implementation bug or
an authentication construction. No global novelty, consensus or policy
claim follows from these experiments. All script costs, exact hashes,
pins, options, boundaries and counterexamples are reproducible from
the [artifact guide](../../research/adler32-delayed-reduction/README.md).
