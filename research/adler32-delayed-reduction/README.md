# Deferred Adler-32 state experiment

Question: can a fixed-length canonical byte ScriptNum message produce both
Adler residues with fewer script bytes than prefix-bounded per-byte reduction,
while preserving caller main/alt state under strict local tapscript limits?
The private seed suggested an order-sensitive two-sum accumulator. Searches
of the catalog, negative results and source tree found no recorded Adler/Fletcher
primitive. That is a coverage observation, not global novelty. RFC 1950 already
specifies delayed reductions; the ScriptNum bounds and stack schedule are the
local contribution.

The public API is the minimal deferred form in
[`adler32.rs`](../../src/arithmetic/checksums/adler32.rs). The independent
comparison schedules remain in `baseline.rs`, including the original
interleaving counterexample. No production API or sibling canonical-byte
implementation is changed to make a baseline lose.

## Boundaries and assumptions

A starts at 1, B at 0; each input adds to A and then A to B. For n<=997,
unreduced A<=254236 and B<=126864262, inside signed four-byte ScriptNum.
The outputs are canonical residues modulo 65521, A below B. Inputs are
canonical ScriptNums for bytes, not raw byte strings. Hostile values are
range/canonicality checked using the existing byte helper. Each invocation
has n ordinary data items and zero hint items, all at entry. No tables or
secret keys exist. Both residues need independent consumption/binding and a
terminal predicate. The checksum has easy adversarial collisions, including
010201 / 020002 -> 0x000b0005; it is unsuitable for authentication.

Each report fragment includes validation, input staging, two accumulators
and normalization, excluding input pushes and terminal checks. Each leaf
independently compiles the fragment plus fixed expected B/A EQUALVERIFY
predicates and TRUE. Data-witness bytes include item count and length
prefixes but exclude script/control block/annex and transaction. Every
report row is n copies of canonical ScriptNum 255 with zero caller items.
Composed resource tests separately add observable runtime caller state.

The profile is the explicit local Consensus profile: require_minimal=false,
verify_minimal_if/CLTV/CSV=true, combined stack limit=true, OP_CAT=false,
Tapscript with a synthetic empty transaction and data-only witness budget.
The fragment itself checks raw encoding, so aliases must reach its guards.
This is local execution, not a complete Bitcoin consensus or policy validator.
Evidence stays locally-reproduced and deployment unclassified. No signature
check occurs; weight charged is zero, while transaction validation budget
and executed non-push opcode count are unknown. The interpreter's tapscript
counter includes pushes and inactive branch instructions, so the artifact
reports static non-push counts separately instead of relabeling that counter.

Both raw and final policy-produced fragment/leaf sizes and hashes are bound
separately. Script.len() supplies raw serialization size. The only compile
path is compile_with_policy(): ALL at raw<=32768, NONE (unoptimized) above.
Deferred valid profiles all use ALL. Prefix-bounded streaming transitions
between n808 and n809. Naive n728 has raw fragment 32762 / leaf 32773 and follows
ALL/NONE respectively, even though their final lengths equal the raw lengths.

## Findings

At n32, deferred state uses 636/645 fragment/leaf bytes, 97 serialized witness
bytes / 32 data items / 0 hints, peak 35. Prefix-bounded streaming uses 740/749,
same witness/peak. Naive streaming costs 1442 fragment bytes and is not the
closest comparison. At n997, deferred is 19122/19132 (ALL), witness 2994 bytes /
997 data items / 0 hints, peak 1000. Streaming is 41253/41263, explicitly
unoptimized. These compare final bounded-policy sizes, not identical optimizer
paths at every size.

The original interleaved validator overlaps the two accumulator items and
peaks at n+5. Its n995 valid control accepts at 1000; n996/997 reject with
typed StackSize at the first 1001-item state. Checking each input before
staging it and initializing A/B afterward changes the peak to n+3 without
changing final script size. The shared suite observes both caller stacks
and every output at the exact 1000 frontier, then rejects one additional
item. Empty fragment peak 2 is separate from constant empty leaf peak 1.
The public API rejects n998; the retained prevalidated streaming n998 probe
also rejects at 1001. These failures are recorded in NR-077.

## Independent result oracle and shared contracts

oracle.py calls Python zlib.adler32, with no Script or local recurrence.
oracle.json preserves 555 vectors: every one-byte value, 256 asymmetric
pairs, empty/decimal-text/collision vectors, plus zero/max/pattern messages
at 13 deterministic lengths through997. oracle-provenance.json records the
measured Python version, zlib compile/runtime versions and extension SHA256.
Those versions are provenance for the recorded reference run, not a runtime
dependency pin or a Core/resource oracle. The JSON vectors can be reproduced
on compatible zlib installations without matching extension binary hashes.
The Rust suite independently also checks a closed-form weighted sum.

The shared suite covers deferred, bounded-streaming and original interleaved
schedules plus canonical/numeric u32 bit converters. Each malformed witness
position has a valid control, correct output cleanup and typed errors.
Numeric aliases are accepted only by the documented numeric converter.
Actual compiled range/canonicality guard mutations defeat the same rejection
assertions at every position. Removing either terminal residue predicate
also defeats its rejection assertion. The original stack schedule defeats
the same clean-success assertion that passes with prevalidation. Short
inputs, asymmetric ordering and exact composed main/alt peaks are tested.

## Source and reproduction

Source base: bf9ee0bb34987a9130ad9dc13a06e18fef137296.
Measured source revision: 250f23861a87ee10b2a7e1ea3de07dcf8569e820.
Compiler/interpreter identities are extracted from the binary's embedded
Cargo.lock; metrics.json binds source SHA256s, the immutable source revision,
all 31 comparison rows, options, witness hashes, final bytecode hashes and
cost boundaries. The artifact test recomputes the entire report, checks each
bound file against the named Git commit in full clones, and checks all seven
catalog rows. Shallow CI recomputes current-tree file/hash bindings without
fetching the historical source commit.
A documentation-only follow-up records that source pin; the delivered clean
tree must pass the required suite. Catalog record arithmetic/adler32-state
is added without editing or dropping the 122 existing records.

```sh
python3 research/adler32-delayed-reduction/oracle.py > /tmp/adler32-oracle.json
cmp /tmp/adler32-oracle.json research/adler32-delayed-reduction/oracle.json
CARGO_PROFILE_DEV_OPT_LEVEL=1 cargo run --locked --example adler32_delayed_probe -- 250f23861a87ee10b2a7e1ea3de07dcf8569e820 > /tmp/adler32-metrics.json
cmp /tmp/adler32-metrics.json research/adler32-delayed-reduction/metrics.json
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test adler32_contract
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test primitive_metrics adler32_state_metrics_are_current
python3 tools/kb.py validate
cargo fmt --all -- --check
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked -- --skip fields::
```

Host optimization keeps debug assertions and overflow checks; it does not
change Script compilation policy. No field tests are run. Source:
[RFC 1950](https://www.rfc-editor.org/rfc/rfc1950.txt), May 1996 version 3.3,
sections 2.2/8.2/9. Independent complete Core/relay-policy validation remains
OP-035, with an explicit non-authentication scope and no class inheritance.
