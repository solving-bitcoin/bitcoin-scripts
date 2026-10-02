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
[NR-056](../negative-results/index.md#nr-043-upstream-stack-limit-enforcement-misses-entry-and-data-pushes).
The helper's explicit stack-limit flag is local execution evidence, not a
complete consensus-validation result.

Budget repeated signature checks against the serialized complete witness,
including the leaf, control path, annex and CompactSize prefixes. Data-only
fragment accounting can falsely reject a valid complete spend; byte boundaries
can also change a repeated check from exact exhaustion to failure. The
[funded budget experiment](../tapscript-budget-validation.md) records these
boundaries with zero hints and all data items present at entry. Reusing a
signature in Script does not remove the 50-unit charge for each executed
nonempty check.

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

## Binary hash-path checkpoints

The [optional-SHA256 hash path](../primitives/hash-path-integer.md) finishes
each bit with RIPEMD-160, so nested paths equal the joined bit path. Checkpoints
fit in one 20-byte item but do not encode round boundaries. Independently bind
the initial preimage (NR-056), fix widths and ordering, and retain normalized
branch bits for downstream authentication. A path has zero hints and `n+1`
input data items; a retained path peaks at `n+2` combined items before unrelated
protocol state. This bound does not include a surrounding pinning/signature
wrapper (OP-020).

## Preloaded integer roots

The [root composition](../../research/integer-root-bounds/README.md) preloads
all ordinary inputs, consumes the top remaining input, parks each canonical
root above the caller's altstack and restores roots in original input order.
Every invocation has one ordinary data item and zero hints. Two/32/996 folds
therefore have 2/32/996 ordinary entry items, **zero total hint items and zero
hint bytes**, and combined peaks 6/36/1,000 including every future input and
already computed root. Caller main+alt state reduces capacity one item at a
time; 997 roots fail StackSize at 1,001.

Two/32 31-bit folds have ALL whole fragments 1,230/19,710 bytes and leaves
binding every output at 1,235/19,803. Serialized fixture witnesses are 4/89
bytes, allowed alias-inclusive maxima 11/161. Independent component sums
1,232/19,712 include park/restore; whole optimizer delta -2 reconciles final
fragments. At 996, raw component sum/whole fragment is 615,528 and compilation
is NONE, explicitly unoptimized; checked leaf 618,389, fixture witness 2,738,
allowed maximum 4,983. Individually ALL-compiled components sum to 613,536;
whole-policy delta +1,992 includes the change to NONE. It is not a measured
cross-component rewrite loss alone.

Every root result is checked, and order, short prefixes, aliases, malformed
positions and actual compiled validation bypasses are exercised with valid
controls. Root zero remains data, so dropping or returning it without a consumer
is not a terminal predicate. Evidence is locally-reproduced/unclassified;
complete transaction and relay claims need exact context validation. Ordinary
u32 values above the four-byte positive ScriptNum range require a different
representation (OP-038).

At the exact optimizer boundary, 53 preloaded roots give a 32,646-byte ALL
fragment (raw 32,754) but a 32,903-byte NONE leaf, explicitly unoptimized.
There are 53 ordinary entry items and zero hints, witness 142 (allowed max 266),
peak 57. Every artifact records its own policy choice: 149 raw checking bytes
increase final bytes by 257 when the leaf crosses the cutoff.
