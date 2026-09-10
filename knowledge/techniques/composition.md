# Composition and resource coexistence

Fragments that pass alone can fail when composed. Track at least:

- main plus altstack peak, including unrelated live state;
- table lifetime and cleanup ordering;
- item size and numeric encoding at each boundary;
- conversion between byte, nibble, limb, field, and RNS layouts;
- clean-stack terminal behavior;
- tapscript validation budget and transaction weight;
- whether relaxed execution was used.

A protocol map should annotate every edge with its stack representation and
trust status. Setup amortization is valid only if table memory can remain live
across all intervening operations.

Check the initial witness before any cleanup and the combined live depth after
every instruction: an immediate drop cannot repair a prior overflow. The
[resource regression suite](../../tests/execution_limits.rs) exercises these
cases after the shared helper repair documented in
[NR-043](../negative-results/index.md#nr-043-upstream-stack-limit-enforcement-misses-entry-and-data-pushes).
The helper's explicit stack-limit flag is local execution evidence, not a
complete consensus-validation result.

Certificate provenance is part of that edge trust status. The prime-RNS
composable multiplier, for example, is globally sound only when each operand
vector is a verified-path output of its shared-integer field binder or a prior
gate; a same-shaped raw witness vector is not interchangeable. Fragment-cost
sums also assume each operation already sees its inputs in the documented
adjacent layout. They do not include routing all witness groups that are present
at script entry, and fan-out or squaring requires explicit duplication of the
certified vector. Record those routing, reordering, and duplication bytes before
turning per-fragment costs into a circuit total.

The native secp256k1 backend amortizes a different resource: a 513-item
quarter-square table whose push/drop code is 1,795 bytes. Two preloaded
multiplications share it at an 882-item peak. Three require a destructive
57-slot recombination and peak at 993; the smaller isolated-gate layout would
exceed the stack limit when all three witness groups coexist. Five specialized
squares peak at 998. These are byte wins only for the documented adjacent,
all-groups-preloaded layout, and the three/five-operation endpoints leave
essentially no room for unrelated protocol state.

The factor-16 Montgomery profile reduces one multiplication to a 719-item peak
and 29 hint items, but currently exposes no resident-table or batch API. Its
stored values mean `E(x)=x/16`, so an ordinary-domain batch estimate cannot be
transferred to it without also specifying conversions and downstream domain
compatibility.

The checked [`prince_verify`](../../src/ciphers/prince/README.md#checked-computation-leaf)
illustrates a complete-leaf boundary: it accepts exactly 16 canonical nibble
items, consumes them, and returns one true item. Its 633/685-item measured peaks
include all 16 inputs, zero hints, tables and temporaries. Extra main-stack
state rejects at entry, so its unused stack capacity cannot be advertised as
composition capacity. The underlying `prince_encrypt` fragment preserves a
surrounding prefix but requires the caller to validate nibble encodings/ranges,
budget that live prefix, consume every ciphertext output and add authorization
where the protocol requires it. The three Core-validated complete spends do
not transfer their deployment class to a differently composed leaf.
