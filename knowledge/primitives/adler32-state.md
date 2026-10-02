# Canonical Adler-32 state

As of 2026-10-02: `locally-reproduced`, `unclassified`.
Implementation: [`arithmetic::checksums::adler32`](../../src/arithmetic/checksums/adler32.rs).
Contract, numeric proof and witness encoding: [implementation README](../../src/arithmetic/checksums/README.md).

Question: does deferred reduction improve script size over prefix-bounded
per-byte normalization while retaining hostile canonical byte inputs, two
canonical residues and both caller stacks under the strict 1,000-item limit?
The measured answer is yes at n32 and n997. This is a Script scheduling and
bounded reduction contribution; [RFC 1950](https://www.rfc-editor.org/rfc/rfc1950.txt)
already specifies Adler-32 and delayed reduction in May 1996, version 3.3.

The generator accepts n0..997 (no default). Bottom-to-top n canonical byte
ScriptNums become A/B residues with A below B, starting from A1/B0. Values are
range-checked and raw aliases rejected by the existing canonical-byte helper.
There are n ordinary data items and zero hint items at entry. Inputs are
consumed; neither output is a terminal predicate or unique message commitment.

Deferred normalization uses bounded descending power-of-two multiple
subtraction. Exact four-byte ScriptNum bounds follow from
`A<=1+255n`, `B<=n+255n(n+1)/2`. Check-and-stage the inputs before allocating the
accumulators; the combined peak is n+3 for n>0, versus n+5 for interleaved
validation. Existing main and alt state add to this bound. At n997 no spare
item remains, and one additional caller item rejects with typed `StackSize`.

| All-255 fixture | Fragment / complete leaf bytes | Maximum data-witness bytes / items | Hint items | Fragment / leaf peak |
| --- | ---: | ---: | ---: | ---: |
| n0 | 2 / 1 | 1 / 0 | 0 | 2 / 1 |
| n1 | 21 / 30 | 4 / 1 | 0 | 4 / 4 |
| n32 | 636 / 645 | 97 / 32 | 0 | 35 / 35 |
| n128 | 2512 / 2521 | 385 / 128 | 0 | 131 / 131 |
| n512 | 9864 / 9874 | 1539 / 512 | 0 | 515 / 515 |
| n997 | 19122 / 19132 | 2994 / 997 | 0 | 1000 / 1000 |

Each fragment includes validation, staging, arithmetic and normalization but
excludes input pushes and terminal checks. Each test leaf independently
compiles the fragment plus expected B/A equality checks and TRUE. Witness
serialization includes count/length prefixes but excludes script/control block,
annex and transaction. All primary fragments and leaves use ALL under the
central raw <=32KiB compilation policy. Static non-push opcodes at n32 are
458/460; executed opcode counts remain unknown. Local validation weight charged
is zero because there are no signatures, not a transaction budget assertion.

The empty leaf optimizes to a constant TRUE. Its peak cannot replace the empty
fragment's peak in a composition model. The closest streaming baseline has
the same witness and peak and costs 740/749 at n32; at n997 its 41253/41263
bytes are **unoptimized** above the cutoff. See the
[like-for-like comparison](../comparisons/checksums.md) and
[NR-077](../negative-results/adler32-scheduling.md).

Independent zlib outputs check 555 deterministic vectors, including every
one-byte value, 256 asymmetric pairs, the standard decimal-text vector,
empty input, collisions, zero/max/pattern long inputs and n997. Catalog
classification conservatively stays `locally-reproduced`: resource acceptance
and artifact costs are from the local interpreter, not Core or zlib. These
result checks do not upgrade siblings or establish transaction validity.

The [shared contract suite](../../tests/adler32_contract.rs) audits the delayed,
prefix-bounded streaming and original interleaved schedules plus canonical
and numeric u32 bit adapters. It tests each hostile witness position, typed
errors, allowed numeric aliases, output ordering, short inputs, observable
runtime caller stacks, exact peaks and rejected mutations of actual compiled
guards. Original n996/997 interleaving fails the same success assertion that
passes after scheduling repair. Mutating either terminal predicate also makes
the same rejection assertion fail with a clean valid control.

[Artifact report](../../research/adler32-delayed-reduction/metrics.json) binds
the source revision, source-file SHA256s, locked compiler/interpreter pins,
options, witness SHA256, input configuration, raw/final fragment and leaf sizes,
hashes, peaks, terminal predicate and static counts for all 31 comparison rows.
The reproduction test recomputes the report and every catalog configuration.
The [guide](../../research/adler32-delayed-reduction/README.md) gives commands.

This checksum detects accidental corruption and has easy deliberate collisions;
it has no cryptographic security claim. Residues are numeric ScriptNums,
not network-order byte strings; packed checksum serialization and protocol
authentication are outside this boundary. A complete funded/Core/policy
fixture remains [OP-035](../open-problems.md#op-035--complete-adler-state-leaf-validation).
