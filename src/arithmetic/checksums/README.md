# Adler-32 state

`adler32::adler32_state(n)` consumes a fixed message of canonical byte-valued
ScriptNums and returns the two Adler-32 residues, A below B. It implements the
recurrence in [RFC 1950](https://www.rfc-editor.org/rfc/rfc1950.txt), May 1996,
version 3.3. Deferred reduction is established by that reference; this experiment
specializes its numeric bounds and stack schedule to Bitcoin Script. All input
witness items are hostile. The fragment validates their range and encoding.

## Parameters

`n` is the public generation-time byte count, `0..=997`, with no default.
The modulus is 65,521; A starts at 1, B at 0. The fragment returns canonical
ScriptNums in `0..=65520`. It preserves both caller stacks and consumes exactly
the top n message items. It neither checks entry depth nor authenticates data.

## Script metrics

The stable fixture is 32 copies of byte 255, all present at script entry,
with output `(8161,3630)`. Fragment bytes include canonical checks, staging,
accumulation and both reductions. They exclude input pushes and terminal
predicates. The complete test leaf checks B then A with `OP_EQUALVERIFY`, then
leaves `OP_TRUE`. Serialized data-witness bytes include item count and lengths,
but exclude leaf, control block, annex and transaction. Both artifacts use
`compile_with_policy()` with ALL. Fragment and leaf combined peaks are equal
for this fixture; neither is inferred from the other.

| Configuration | Script bytes | Data-witness bytes | Hint items | Combined peak |
| --- | ---: | ---: | ---: | ---: |
| 32-byte fragment | <!-- metric:adler32_state32 -->636<!-- /metric:adler32_state32 --> | <!-- metric:adler32_state32_witness -->97<!-- /metric:adler32_state32_witness --> | 0 (none) | <!-- metric:adler32_state32_stack -->35<!-- /metric:adler32_state32_stack --> |
| 32-byte complete test leaf | <!-- metric:adler32_state32_leaf -->645<!-- /metric:adler32_state32_leaf --> | Same 97 bytes / 32 data items | 0 (none) | 35 |

The fragment has <!-- metric:adler32_state32_static -->458<!-- /metric:adler32_state32_static --> static non-push opcodes; the leaf has 460.
Executed non-push opcode count is unknown: the pinned interpreter's tapscript
counter also counts data pushes and inactive branch instructions. No signature
checks execute, so local validation weight charged is zero. No complete
transaction budget is measured.

At n997, the fragment/leaf cost 19,122/19,132 bytes (ALL), the maximum data
witness is 2,994 bytes / 997 items, hints are zero and the combined peak is
1,000. At n0, the fragment is two bytes with peak two; the constant complete
test leaf optimizes to `OP_TRUE`, one byte with peak one. That leaf is a
constant assertion, not evidence that the reusable empty fragment uses one
stack item. Full hashes, raw sizes, policy options and source bindings are in
[`metrics.json`](../../../research/adler32-delayed-reduction/metrics.json).

## Security

This is a non-cryptographic corruption checksum with easy adversarial collisions.
For example, `01 02 01` and `02 00 02` both give packed checksum `0x000b0005`.
Do not use it for authentication, collision-resistant commitments or replacing
a protocol hash. There is no one-time-key or subgroup assumption and no secret
key. The output alone does not bind a unique message or its length.

## Script compatibility and standardness

The fragment uses ordinary enabled arithmetic/stack opcodes. The 32-byte leaf
has 460 static non-push opcodes, exceeding the legacy 201 limit for bare,
P2SH and P2WSH scripts; its 645-byte redeem script also exceeds P2SH's 520-byte
element bound. Larger measured leaves can exceed the legacy/SegWit-v0 10,000-byte
script bound. Small configurations have not been validated in those contexts.
Local tapscript tests enforce the combined 1,000-item limit and do not use
OP_CAT or relaxed resource checks. They do not validate a Taproot commitment,
funded transaction or relay policy. Evidence is `locally-reproduced`, deployment
`unclassified`; [script contexts](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md) explain those distinctions.

## Witness and hints

Bottom-to-top: caller main prefix, `byte[0] ... byte[n-1]`; each message item
is the minimal signed-magnitude ScriptNum for the integer byte. Zero is empty;
128..255 use two bytes with a zero sign byte. Raw `ff` is negative, not 255.
There are exactly n data items, **zero hint items per invocation and in every
measured configuration**; no table or auxiliary witness is needed. All data
items coexist at entry. Maximum serialized data witness is
`CompactSize(n) + 3*n` bytes. Preserved caller state is excluded from that
isolated witness boundary and included in composed stack tests.

Outputs are numeric residues, not raw network-order bytes. Residues 32768..65520
require three ScriptNum bytes. The packed Adler word `B*65536+A` need not fit
positive four-byte ScriptNum, so conversion to four wire bytes is a separate
caller obligation. A fragment returns two live outputs, not a terminal Boolean.
Bind/consume both outputs and all caller state before the final predicate.

## Algorithm and stack behavior

Validate each byte before moving it to the altstack; only then allocate A/B.
Popping that suffix restores message order and leaves existing altstack state
untouched. Each byte performs `A+=byte; B+=A`, followed by two terminal modular
reductions. Descending powers of two times 65,521 implement bounded greedy
subtraction without disabled `DIV`/`MOD`.

For n<=997, unreduced `A<=1+255n<=254236` and
`B<=n+255n(n+1)/2<=126864262`, safely below 2,147,483,647. Since the recurrence
is linear modulo the modulus, reducing only at the end yields the same residues.
The combined peak is `n+3+preserved_main+preserved_alt` for n>0, or
`2+preserved_main+preserved_alt` for n0; require this to be <=1,000.
The original interleaved validator held the accumulators during checking and
peaked at n+5. It rejects n996/997 at the first 1,001-item state; prevalidation
accepts n997 at 1,000 without increasing script size. These are observed runtime
frontiers, not input-count-only estimates.

## Comparison and reproduction

At the same 32-input/two-output boundary, prefix-bounded per-byte reduction
costs 740/749 fragment/leaf bytes at the same 35-item peak. Deferred reduction
saves 104 bytes. At n997, it costs 19,122 versus 41,253 fragment bytes; the
streaming result is explicitly **unoptimized** above the raw 32KiB cutoff.
See the [comparison](../../../knowledge/comparisons/checksums.md),
[negative scheduling result](../../../knowledge/negative-results/adler32-scheduling.md)
and [reproduction guide](../../../research/adler32-delayed-reduction/README.md).

`tests/adler32_contract.rs` shares malformed-every-position, aliases, short
inputs, ordering, both caller stacks, exact peaks and deliberate compiled
guard mutations across checksum schedules and canonical/numeric word adapters.
It checks 555 zlib oracle vectors and detects removal of either output predicate.
The report test recomputes every artifact, hash, option and catalog binding.

```sh
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test adler32_contract
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test primitive_metrics adler32_state_metrics_are_current
python3 tools/kb.py validate
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked -- --skip fields::
```
