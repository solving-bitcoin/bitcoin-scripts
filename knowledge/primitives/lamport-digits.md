# Multi-digit Lamport commitments

## Research question and hypothesis

The repository has a two-bit Lamport commitment and several Winternitz
constructions, but no measurement of how a Lamport commitment scales with message
width or digit width. Which digit width minimizes script-plus-witness bytes, and
how close does a multi-digit Lamport commitment come to Winternitz at 160 bits?
The hypothesis is that images cost `2^w` per digit, so the total is minimized
near two bits per digit and stays well above Winternitz at 160 bits. This is a
new local measurement of a standard construction; no novelty claim is made.

## Contract and proof

`signatures::lamport_digits::lamport_digits_commit(images)` opens `d` digits of
radix `r = 2^w`. For each digit the witness gives the claimed value and a
preimage, bottom to top, digit `0` first; the script range-checks the value in
`0..r`, pushes the digit's `r` images, rolls image `value` to the top, hashes the
preimage and requires equality, drops the other images and parks the value. It
returns the `d` values in order, last digit on top. Opening a different value
needs the preimage of a different image, so under HASH160 preimage resistance a
single opening fixes each digit; no checksum is needed because a Lamport
opening reveals exactly one preimage per digit. The commitment authenticates
only the value on the stack, not a transaction.

## Threat model and evidence

The prover chooses values and preimages. Tests cover: every value combination for
`(digits, radix)` in `(1,2) (3,2) (1,4) (2,4) (1,16) (2,16)`; a preimage of
another value of the same digit; a claimed value that differs from the value whose
preimage is revealed; swapped digit positions; a short arbitrary preimage; and
out-of-range values `-1`, 4, 7 and 255, which abort instead of being clamped (the
earlier two-bit helper clamps to the maximum). Evidence is `locally-reproduced`;
execution is `unclassified`; no Bitcoin Core validation is claimed. Strictly
one-time: a revealed preimage is public.

## Measured design space

Boundary: the policy-compiled fragment plus the serialized witness for the
fixture `v_d = (37d + 5) mod r` with 16-byte preimages; input pushes, terminal
predicate and transaction framing excluded; zero hints. Sizes pinned by
`lamport_digits::tests::recorded_sizes_are_current` where tabulated.

| Message bits | Bits per digit | Script bytes | Witness bytes | Script + witness |
| ---: | ---: | ---: | ---: | ---: |
| 8 | 1 | 463 | 149 | 612 |
| 8 | 2 | 403 | 76 | 479 |
| 8 | 4 | 717 | 39 | 756 |
| 16 | 2 | 807 | 151 | 958 |
| 32 | 1 | 1,855 | 593 | 2,448 |
| 32 | 2 | 1,615 | 301 | 1,916 |
| 32 | 4 | 2,871 | 153 | 3,024 |
| 160 | 1 | 9,279 | 2,961 | 12,240 |
| 160 | 2 | 8,079 | 1,501 | 9,580 |
| 160 | 4 | 14,359 | 759 | 15,118 |

Two bits per digit minimizes script plus witness at every width (the 8-bit,
8-bit-digit row costs 5,540 bytes and the 3-bit rows lie between). It halves the
witness of one-bit digits for the same image count, which is why radix four
beats radix two. At 160 bits the best Lamport total is 9,580 bytes (peak 165,
160 witness items), against **2,334** for the smallest tested Winternitz
construction, 3,809 for clamped base-16 Winternitz and 2,400 for constant
composition, all on the fragment-plus-signature boundary with 16-byte secrets
(see the [Winternitz comparison](../../src/signatures/winternitz/README.md)).
The Lamport commitment leaves 80 two-bit digits, not 20 bytes, so a consumer
would add a conversion; the Winternitz totals leave the message in their own
forms. The Lamport figure is therefore a lower bound on a like-for-like byte
comparison.

## Reproduction

```sh
cargo test --locked signatures::lamport_digits::tests --lib
cargo test --locked --test primitive_metrics lamport_digits_metrics_are_current -- --exact
python3 tools/kb.py validate
```
