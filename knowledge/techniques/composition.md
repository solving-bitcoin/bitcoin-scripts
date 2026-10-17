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

## Stable selection with native binary flags

[Opaque-item stable selection](../primitives/stable-selection.md) uses no hints
or table but starts with two ordinary data items per pair. All discarded
payloads and future preloaded invocations still count at entry. For n>=2 its
peak is `2n+1+caller_main+caller_alt`; budget 4 plus caller state at n=1, and
1 plus caller state at n=0. A 499-pair invocation leaves room for one caller
item, on either stack, before reaching exactly 1,000. The shared tests observe
every preserved caller and returned item after compilation; cleanup cannot
hide the resource boundary.

Native tapscript MINIMALIF provides exact empty/01 selectors. That guarantee
does not transfer to legacy truthy IF or the numeric word selector, whose
OP_0NOTEQUAL accepts at-most-four-byte numeric aliases when the profile allows
them. Bind selector meaning, retained vector/count and terminal predicate;
routing does not certify payload content. Discarding a payload also cannot
repair 521-byte consensus entry elements or the local policy's 80-byte cap.
Literal-checking whole leaves can cross the optimizer cutoff even when their
selection fragment uses ALL; report whole-artifact options separately.

These measurements are locally-reproduced / unclassified, with zero hints and
explicit stack-limited local tapscript profiles. Protocol/Core composition is
[OP-036](../open-problems.md#op-036--stable-selection-protocol-composition).

## Destructive sorting pools

The [u4 sorting certificate](../primitives/u4-sort.md) requires a contiguous
operand pool above its reversed hint vector. One call needs `n` operands and
`n-1` hints at entry; `2*n+2` combined items is the exact standalone peak for
`n>=2`. Every unrelated main/alt-stack item adds to that bound. Two preloaded
32-input calls carry 62 hints and 64 operands and peak at 129 items if the
first output is consumed before the second call. Keeping those outputs would
require additional explicit routing and a fresh measurement. The primitive
preserves surrounding state but does not authenticate operands or preserve
their original ordering in the sorted result.

## Binary hash-path checkpoints

The [optional-SHA256 hash path](../primitives/hash-path-integer.md) finishes
each bit with RIPEMD-160, so nested paths equal the joined bit path. Checkpoints
fit in one 20-byte item but do not encode round boundaries. Independently bind
the initial preimage (NR-056), fix widths and ordering, and retain normalized
branch bits for downstream authentication. A path has zero hints and `n+1`
input data items; a retained path peaks at `n+2` combined items before unrelated
protocol state. This bound does not include a surrounding pinning/signature
wrapper (OP-020).

## Reverse positional residue folds

When the input radix is `b` and the modulus is `b+1`, `b=-1` modulo that
modulus. A right-to-left `x-r` fold can therefore replace depth-dependent input
routing with swaps, provided even vector lengths apply a final modular negation.
The [u4 modulo-17 experiment](../primitives/u4-mod17.md) demonstrates this with
bounded `-16..=15` intermediates, canonical runtime inputs, no table or hints,
and exact fragment bound `n+3+preserved<=1000`. Preserved state must be supplied
at runtime in frontier tests: known altstack constants can move across the
fragment under compilation and erase the coexistence being tested. Complete-leaf
terminal consumers require their own resource accounting.

## Fold a checked u32 word through two native-width lanes

The [modulo-65,537 adapter](../primitives/u32-mod65537.md) avoids reconstructing
an unsigned 32-bit ScriptNum: two canonical 16-bit lanes are subtracted because
`65536=-1 (mod65537)`. All intermediates fit native numeric arithmetic, with
zero hints, no table and a seven-item fragment peak. The result can require
17 bits and is a single numeric ScriptNum, so it must not be mistaken for a
low-16-bit lane or the four-byte u32 representation. In contrast, expanding
all 32 bits for general binary Horner remainder uses 35 peak items in the
measured comparison. These are configuration-specific local resource results,
not consensus or authentication claims.


The [canonical prefix scan](../primitives/u4-prefix-sum.md) can reconstruct
forward deltas only with a retained initial value. Its round-trip wrapper
canonical-checks all original items because the existing delta encoder accepts
numeric aliases. Retaining, routing and binding initial state are real caller
costs; the standalone n+3 scan peak does not price the encoder's live outputs.


[Exact quarter-square nibble products](../primitives/u4-exact-product.md)
consume 2n canonical nibble operands and return n exact 0..225 ScriptNums. Their
2*n+34 peak includes private memory and output staging; all inputs are present
at entry. Product outputs 128..225 require two-byte numeric encoding, so a hash
consumer needs an explicit raw-byte conversion. Terminal binding and caller
live state remain part of the composed protocol cost.

## Independent decimal checksum folds

The [Damm composition report](../../research/damm-finite-state/README.md)
preloads independent 32-digit messages, consumes the top remaining message,
parks its checksum above the caller's altstack, and restores all checksum
outputs in original message order. Every fold uses **zero hint items**; two
folds use zero total hints and 64 ordinary entry data items, while 28 folds
use zero total hints and 896 ordinary entry data items. Future messages and
accumulated results are included in the combined main-plus-alt peak.

Two folds measure 1,532 fragment bytes, 1,537 bytes for a leaf binding both
outputs, 67 witness bytes and peak 168. Independently compiling two 766-byte
folds plus two park/restore pairs gives 1,536 bytes; the whole-policy delta is
-4. At 28 folds, 21,504 component bytes plus delta -56 give a 21,448-byte
fragment; the leaf binding all states is 21,505 bytes, witness 927 bytes,
peak exactly 1,000. All these scripts use ALL. The 29th fold rejects StackSize
at first peak 1,001. Four-byte numeric aliases remain admissible under the
Consensus profile, so allowed witness maxima are 321/4,483 bytes at the
two/28-fold boundaries, larger than the selected canonical fixtures.

Each invocation installs and removes its own table. The measured optimizer
delta is not table-sharing amortization. Fixed arity, output order and every
result are tested along with caller state, short inputs and compiled validation
bypasses. Evidence remains `locally-reproduced`/`unclassified`: a checksum-only
leaf is forgeable and does not bind message length or authorization (OP-037).

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

## Independent CRC-8 messages

The [CRC-8 repeated wrapper](../primitives/crc8-smbus.md) retains every future
message nibble, parks each canonical CRC on altstack, then restores CRCs
top first and binds every output. Each nine-byte invocation uses 18 ordinary
items and zero incremental hints; all 18R inputs are at entry and total hints
remain zero. Numeric feedback has measured peak 18R+188 plus both caller
stacks, so R=45 reaches 998 and leaves two caller slots; R=46 fails at
measured 1,001. Witness maxima including four-byte numeric aliases are
181/721/2,253/2,343/4,053 at R=2/8/25/26/45.

R=2 fragment/leaf are 2,524/2,532, witness 71, peak 224. R=8 gives
10,096/10,126, witness 280, peak 332. R=25 ALL versus R=26 unoptimized NONE
shows why individually optimized components cannot be summed without a
whole-policy delta. Tables are reinstalled per independent call; sharing them
would require a separately validated state/table lifecycle. Every malformed
position and short prefix is audited across these configurations and matched
serial/canonical siblings. Runtime caller bytes are observed at exact 1,000
boundaries; alt state is reduced when the configuration has fewer free slots.
These are locally-reproduced/unclassified fragment outcomes.

The [bounded permutation decoder](../primitives/factoradic-permutation.md)
is an example of entry compression without output compression. Width 8 enters
with one rank item but emits eight symbols, with a measured 12-item standalone
peak. Its separate-digit baseline enters with seven items and peaks at 18.
Both preserve main/alt caller state and require consuming the entire expanded
vector. Exact 1,000-item tests include that preserved state; preloaded subsequent
invocations and retained prior outputs must be added at their live boundaries.
Both use zero hints and remain locally `unclassified`.

The [reflection adapter](../primitives/u4-reflection.md) also separates compressed
entry from expanded output: width 32 enters with 16 data items but emits 32.
Its measured complete leaf peaks at 33 versus 36 for raw verification, before
unrelated state; all hints are zero. Exact frontier probes move a runtime witness
item into the altstack and verify runtime caller data, because known constants
checked against themselves can optimize away and understate live occupancy.
