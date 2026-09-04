# BLAKE3 challenge transcripts for an Ed25519-style verifier

## Question and objective

How cheaply can the repository expose BLAKE3 challenge bits as arithmetic u4
items for a custom Ed25519-style signature equation? The objective is a
generation-measured hash fragment that can eventually feed a scalar schedule.
This is not RFC 8032 Ed25519, whose challenge hash is SHA-512.

## Constructions

The exact 96-byte form computes

```text
BLAKE3(R32 || A32 || M32).
```

It consumes three checked 64-nibble groups. The first compression processes
`R32 || A32`; the second processes the eight live words of `M32`. Zero padding
words are absent from the round schedule rather than supplied as ignored
witness data.

The key-specialized form computes ordinary unkeyed

```text
BLAKE3(D32 || A32 || R32 || M32)
```

for fixed `D32,A32`. The generator evaluates the first block with
`CHUNK_START`, embeds its non-root chaining value, and runs one on-chain
compression over `R32 || M32` with `CHUNK_END|ROOT`. `D32` is transcript data,
not BLAKE3 derive-key mode. A deterministic host test compares the decomposed
two-block calculation with the standard `blake3::hash` result.

## Generation metrics and hints

Run one mode at a time; neither mode executes the generated Script:

```sh
cargo run --locked --release --example ed25519_blake3_challenge_model -- --key-specialized
cargo run --locked --release --example ed25519_blake3_challenge_model -- --key-specialized-truncated-128
cargo run --locked --release --example ed25519_blake3_challenge_model -- --key-specialized-truncated-128-certified-inputs
cargo run --locked --release --example ed25519_blake3_challenge_model -- --key-specialized-truncated-128-certified-inputs-preserving-337
cargo run --locked --release --example ed25519_blake3_challenge_model -- --key-specialized-truncated-128-fixed-message-preserving-337
cargo run --locked --release --example ed25519_blake3_challenge_model -- --exact-96
```

The packed-R and canonical-u5 boundaries are separate focused strict
executions:

```sh
cargo run --locked --release --example ed25519_blake3_packed_r_probe
cargo run --locked --release --example ed25519_blake3_u5_r_hybrid_probe
```

Every complete wrapper in the table is larger than 32 KiB. It is compiled only
through the centralized policy and therefore receives `CompileOptions::NONE`;
the reported whole-fragment sizes are unoptimized by upstream fixpoint passes.
Smaller semantic children may still receive their policy-selected compilation.

| Configuration | Script bytes | Static non-push opcodes | Data input items | Hint items | Digest output | Analytic local peak |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| exact 96-byte transcript | 125,687 | 91,673 | 192 checked u4 | **0** | 64 u4 | <=655 |
| fixed-prefix 128-byte transcript | 65,208 | 47,307 | 128 checked u4 | **0** | 64 u4 | <=591 |
| fixed-prefix transcript, low 128 output bits | 64,760 | 46,955 | 128 checked u4 | **0** | 32 u4 | <=591 |
| low 128 bits, caller-certified u4 input | 63,764 | 46,279 | 128 certified u4 | **0** | 32 u4 | <=591 |
| caller-certified input with 337 preserved items | 65,123 | not separately recorded | 128 certified u4 + 337 preserved | **0** | 32 u4 above prefix | 928 combined, strict fixture |
| fixed-`M32` binder + specialized hash, 337 preserved items | 64,118 | not separately recorded | 128 certified u4 + 337 preserved at pair entry; 64 u4 + 337 at hash | **0** | 32 u4 above prefix | 864 combined, strict fixture |
| fixed-`M32` hash copied from later-certified packed R, 297 preserved items | 67,806 | not separately recorded | 297 preserved, including eight packed R words | **0** | 32 u4 above prefix | 824 combined, strict fixture |
| fixed-`M32` hash from canonical-u5 R, 391 preserved items | 67,137 | 45,452 | 391 preserved, including 51 radix-32 R digits | **0** | 32 u4 above prefix | 918 combined, strict fixture |

This is a `fragment-with-memory` boundary: exact input-count and numeric u4
checks, shared lookup-table setup, BLAKE3 compression, cleanup, and digest
restoration are included. Input pushes, serialized witness bytes, digest use or
comparison, point-encoding binding, and terminal truth are excluded. The hash
fragments require no auxiliary witness hints, so their per-invocation and batch
hint counts are exactly zero. Their data items still count against the 1,000-
item combined stack limit.

The truncated form computes the same standard BLAKE3 root and materializes
only output words zero through three. This is the first 16 digest bytes in
BLAKE3's standard little-endian byte encoding. It saves 448 bytes and 32
post-hash stack items; the conservative peak bound remains that of the shared
compression core.
When a preceding carrier decoder has already proved each nibble is in
`0..16`, the caller-certified form removes the duplicate range checks and
saves another 996 bytes. That interface must never receive raw hostile
witness items directly.

The H16 Montgomery composition instantiates that interface with 337 preserved
items: 288 future trace/hint packet items, the 41-item current slope state, and
eight retained packed `Rtilde` words. Its complete variable-message hash input
is 465 items. The packed-XOR lookup uses `OP_DEPTH`, so its 330 table items must
be below that prefix. Correctly parking and restoring the prefix around table
construction and cleanup makes the variable-message fragment 65,123 bytes;
the former 63,766-byte generator failed its first table lookup when executed
with a real prefix and must not be used as a composable metric.

The linked benchmark fixes `M32`. Its 128-byte binder verifies and consumes all
64 hostile message nibbles, after which a 63,990-byte compressor materializes
the eight fixed words at generation time. The hash frontier consequently falls
from 465 to 401 items. The complete pair is 64,118 bytes, 1,197 fewer than the
corrected 65,315-byte republish-and-variable-hash pair, and both fragments need
exactly zero hint items. A focused strict execution matches the ordinary host
`blake3` digest, preserves the exact 337-item-prefix/`R32` order, rejects an
out-of-range or reordered fixed-message nibble and extra hash input, and peaks
at 864 combined main-plus-altstack items. The corrected old pair also matches
the host digest and peaks at 928.

The G29 q-free H16 schedule avoids transcript carriers. After its response side,
the hash frontier is 256 untouched challenge-trace items plus a 41-item current
state. The packed-R helper copies the eight R words from word-zero depth 289,
derives the 64 u4 inputs, and leaves the complete 297-item prefix unchanged.
Its 67,806 bytes include the packed-word conversion. The focused strict probe
matches host BLAKE3, peaks at 824, preserves the prefix byte-for-byte, and
rejects extra input. The helper does not certify the copied packed words by
itself: sound composition requires the final derived slope transition to
certify and consume those exact untouched originals later in the leaf.

The G32 hybrid-u5 boundary instead keeps a 92-item arithmetic state and the
remaining fifteen challenge packets above the 51-digit `Rtilde` field. A
2,931-byte converter copies, digit-range-checks, rejects the 19 noncanonical
radix encodings, and repacks that field into 64 u4 items without consuming the
original. The 64,206-byte fixed-message hash then computes the low 128 bits,
for a 67,137-byte combined helper. Its focused strict execution preserves all
391 original items byte-for-byte, matches the host BLAKE3 digest, rejects an
out-of-range digit, the first canonical-gap value, and extra input, and peaks
at 918 combined main-plus-alt-stack items. It needs exactly zero auxiliary
hint items. The original R field remains for the fused terminal slope
transition.

The output is already decomposed because BLAKE3 itself is evaluated in u4
Script arithmetic. This does not provide a way to decompose the opaque result
of a native Bitcoin hash opcode.

## Evidence and security boundary

The script sizes and opcode counts are deterministic generation measurements.
The general transcript rows remain `inspected`: their generated scripts were
not executed. The fixed-message H16 pair, packed-R boundary, canonical-u5
boundary, and corrected variable-message comparison are `locally-reproduced`
for deterministic strict-stack fixtures against the independent `blake3`
crate, including their stated malformed/order checks. This does not validate
any surrounding multi-megabyte verifier. Deployment remains `unclassified`
for every row.

A caller must bind `A32` to the exact canonical public-key encoding used by the
curve verifier, `R32` to the exact encoded point in the signature equation, and
`M32` to the intended message or prehash source. Numeric u4 validation does not
by itself require unique raw ScriptNum byte encodings. The curve layer must
also define and enforce point validity, subgroup/cofactor handling, scalar
semantics, and final equation comparison.

The hinted Montgomery H16 component account composes the 64,118-byte fixed-message pair
with both scalar-multiplication sides, carrier routing, and a clean terminal
predicate. Its policy-compliant additive projection is 3,828,057 bytes; the exact entry is 792
items, including 88 quotient hints, and its strict peak-equivalent schedule
reaches 999 items. The separate quotient-derived account composes the
67,806-byte packed-R boundary into a 3,896,335-byte G29 projection with 712 data items,
exactly zero hints, and an analytical 912-item arithmetic frontier. Neither
complete multi-megabyte Script was regenerated after this policy correction or
executed, so both constructions remain `inspected` and `unclassified`. Their
superseded pre-policy whole serializations were 3,826,949 and 3,895,323 bytes.

The current G32 linker composes the 67,137-byte canonical-u5 helper into a
2,999,983-byte leaf with 803 coexisting entry-data items, exactly zero hints
per each of 47 transitions and in total, and an analytical 999-item maximum
that includes its script-authored power pools. The complete leaf was generated
but not executed. Its fixed `M32` is still not a transaction digest; this row
does not provide transaction authorization or an RFC 8032 verification claim.
See the
[linked slope candidate](ed25519-blake3-montgomery-slope.md),
[NR-032](../negative-results/index.md), and
[OP-018](../open-problems.md).
