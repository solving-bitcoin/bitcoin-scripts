# Conditional publication of a compressed BN254 proof

Question: if the requested 256 bytes are the uncompressed coordinates of a
BN254 Groth16 proof, can ordinary point compression reduce the point-lock
publication below 100,000 combined creation and spending vbytes?

**Conditionally yes: a 128-byte payload has a Core-validated publication at
92,706 vB, with a 92,853-vB conservative bound.** This does not encode an
arbitrary 256-byte value. The application must actually permit lossless
compression of its proof format and must process the compressed representation.
The main arbitrary-256-byte requirement remains separate.

## Why the conditional payload has 128 bytes

A Groth16 proof consists of `A in G1`, `B in G2`, and `C in G1`. On BN254,
uncompressed affine coordinates use `64 + 128 + 64 = 256` bytes. Ordinary
point compression retains each x-coordinate and the y-sign/infinity flags,
giving `32 + 64 + 32 = 128` bytes. The 254-bit base field leaves sufficient
unused bits in its 32-byte representation for the flags.

The repository's pinned ark-bn254 and ark-ec **0.5.0** implement this encoding.
The conditional Rust probe serializes and deserializes deterministic G1 and G2
generators in both modes and asserts the exact sizes and point equality.
This is a point-serialization round trip, not a generated or verified Groth16
proof. Its published 128-byte value is a separate synthetic seeded payload.

No new setup ZKP is introduced by point compression. The application still
needs canonical field encoding, curve and subgroup validation, and a specified
sign convention when decompressing. A BitVM verifier or garbled computation
that currently consumes 256 uncompressed bytes must be adapted to this input
representation; that integration and its additional computation have not been
implemented or included in the publication byte total.

Primary references: the [arkworks Groth16 proof structure](https://docs.rs/ark-groth16/latest/ark_groth16/data_structures/struct.Proof.html)
and [ark-ec v0.5.0 point serialization](https://github.com/arkworks-rs/algebra/blob/v0.5.0/ec/src/models/short_weierstrass/mod.rs).
The exact local field modulus and flags were inspected in the Cargo-locked
ark-bn254/ark-ec 0.5.0 sources. Serialization evidence is `locally-reproduced`.

## Fixed-cardinality profile and accounting

Use the existing common-G sum-key HASH160 lookup pools, with **89 four-of-seventeen
pools, two three-of-fourteen pools, and one three-of-fifteen pool**. This creates
**92 P2SH outputs**, commits **1,556 independent candidate points**, and requires
exactly **365 revelations**. The mixed-radix capacity is

```text
binomial(17,4)^89 * binomial(14,3)^2 * binomial(15,3)
    >= 2^1024
log2(capacity) = 1024.1356933948657.
```

[The calculator](conditional128-sizing.py) uses exact integer dynamic
programming over every combination of the currently measured fixed common-G
HASH160 lookup pools. It maximizes the integer product of radices for every
integer total pair weight. This gives the smallest conservative transaction
size within that recorded family; it is not an optimum over all Bitcoin
constructions. It also verifies complete serialization and eleven deterministic
codec round trips, including zero, one, and the maximum 1024-bit value.

| Transaction | Conservative weight | Conservative vB | Actual Core weight | Actual Core vB |
| --- | ---: | ---: | ---: | ---: |
| Create first P2TR helper and all 92 P2SH outputs | 12,220 | 3,055 | 12,220 | 3,055 |
| Spend helper and all 92 pools into one P2TR output | 359,192 | 89,798 | 358,604 | 89,651 |
| **Combined** | **371,412** | **92,853** | **370,824** | **92,706** |

The creation starts from one existing P2TR input. Every created P2SH output
costs 32 stripped bytes and every later P2SH input is included. Both P2TR
helper signatures, transaction headers, count/length prefixes, empty witness
vectors for legacy inputs, and per-transaction rounding are included. Test
funding grants, extra change, refunds, and full BitVM3 protocol transactions
are excluded. The point-lock openings remain legacy data without witness
discount. Shorter lookup-depth pushes explain the 147-vB difference between
the actual fixture and conservative bound. Assertion static sigop cost is 2,920.

| Pool | Count | Redeem bytes | Maximum scriptSig bytes | Entry data items | Hint items | Combined stack peak |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 4-of-17 | 89 | 505 | 938 | 12 | 4 | 33 |
| 3-of-14 | 2 | 410 | 734 | 9 | 3 | 27 |
| 3-of-15 | 1 | 434 | 758 | 9 | 3 | 28 |

There are **365 hint items** and **1,095 complete entry data items** across
the separate P2SH inputs, plus 92 redeem-script pushes. Each input's data
coexist at its own script entry; different inputs have independent stacks.
The measured maximum combined main-plus-alt-stack peak is 33, below 1,000.
The existing compiler policy is used for all scripts. Every candidate signature
is 71 bytes in these deterministically generated fixtures.

## Core evidence and reproducibility

[The conditional report](conditional128-publication_core_check.json) records
both actual transactions passing default mempool policy, being submitted, and
being mined under isolated Bitcoin Core 30.3, commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`. Evidence is
`differentially-validated`; the exact fixture is `policy-validated`.

Independent Python decoding reads the actual Core-decoded scriptSigs,
authenticates selected keys against the funded tables, extracts all 365 scalars,
checks each `tG=P+G`, and recovers the exact original 128 bytes. Payload SHA256:
`e07703fed92089aee4708503fb5e58e6064c4c863ca93119b4020cfac5caed2a`.
The [transaction artifact](conditional128-publication-transactions.json) and
[selection fixture](conditional128-publication-selection.json) preserve the
complete evidence. The [sizing artifact](conditional128-sizing.json) contains
the conservative calculation and source-metric hash.

```sh
python3 research/pointlocks-2026-09-17/conditional128-sizing.py
python3 research/pointlocks-2026-09-17/publication_core_check.py --profile 128
```

The transaction builder and Core harness retain their default 256-byte profile;
the smaller profile requires explicit `--profile 128`. The construction keeps
the same algebraic setup and HASH160 binding assumptions as the existing
sum-key primitive. Under malicious candidate setup, the inner HASH160 table
has the roughly 2^80 generic collision caveat. This conditional experiment does
not strengthen that assumption or validate complete BitVM3 challenge/refund
integration.
