# Joint HASH160 and HASH256 preimage verification

Can one witness opening satisfy a published HASH160 and HASH256 pair while
performing the first SHA-256 only once? The hypothesis is that explicit reuse
reduces SHA-256 work despite using one more Script opcode. Compare the shared
prefix with separate native `OP_HASH160` and `OP_HASH256`, using the same
raw preimages, digest constants, verification order and terminal predicate.
All openings are hostile. The hard constraints are the central compilation
policy, 520 bytes per opening, the 1,000-item combined limit, and zero hints.
Evidence is `locally-reproduced` and execution is `unclassified`.

`verify_hash160_hash256` consumes one raw byte vector from an exact suffix
and returns no items. It computes `h = SHA256(opening)`, duplicates `h`,
checks `RIPEMD160(h)`, and checks `SHA256(h)` from the retained copy.
Both checks use exact raw-byte equality against generation-time constants.
Both caller stacks are preserved. The source and PR search found hash paths
and SHA-256 lookup-table sharing, which have different cost boundaries.
The separate native opcodes are the direct comparator for this contract.

## Measured leaves and derived compression work

| Openings | Schedule | Script bytes | Data witness bytes | Data / hints | Combined peak | Executed non-push ops | SHA-256 blocks | RIPEMD-160 blocks |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Shared | 61 | 524 | 1 / 0 | 3 | 6 | 10 | 1 |
| 1 | Separate | 60 | 524 | 1 / 0 | 3 | 5 | 19 | 1 |
| 4 | Shared | 241 | 638 | 4 / 0 | 6 | 24 | 17 | 4 |
| 4 | Separate | 237 | 638 | 4 / 0 | 6 | 20 | 30 | 4 |

Single input length is 520. The four inputs have lengths 0, 55, 56 and
520, bottom to top. Opening byte `i` is `(17*i+5) mod 251`. Each checked
leaf verifies both digests per opening and finishes with one true item.
All script bytes use whole-artifact optimizer `ALL`. Witness serialization
includes all entry data and count/length prefixes, excluding script,
control block, annex and transaction. Every opening coexists at entry.
There are zero caller items and zero hints. Executed non-push opcodes
count actual operations. Signature weight charged is zero.

The SHA-256 and RIPEMD-160 block counts are derived. For `L` raw bytes,
SHA-256 padding gives `b(L) = ceil((L+9)/64)` blocks. The second SHA-256
and RIPEMD-160 each receive 32 bytes and use one block. The shared verifier
therefore uses `b(L)+1` SHA-256 blocks and the separate verifier uses
`2*b(L)+1`. Both use one RIPEMD-160 block. Sources are
[FIPS 180-4 §5.1.1](https://csrc.nist.gov/files/pubs/fips/180-4/final/docs/fips180-4.pdf),
the [1996 RIPEMD-160 specification](https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf)
and the pinned [Bitcoin Core v30.3 hash wrappers](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/hash.h#L22-L63).
These counts describe the computations on accepted inputs. The experiment
does not measure wall-clock speed or the cost of an early rejection.

## Composition and reproduction

The single verifier peaks at three items plus both caller stacks. With
`n` independent openings preloaded and processed top first, the combined
peak is `n+2` plus caller state. The tests observe one opening with 997
preserved caller items at exactly 1,000 and reject one more. The local
tapscript `Consensus` profile enforces entry item size, combined stack and
MINIMALIF rules, with numeric minimality and experimental OP_CAT disabled
and a synthetic transaction. Its local policy profile rejects inputs over
80 bytes. No funded-spend or relay validation was run for these scripts.

The tests generate digests with rust-bitcoin for 14 deterministic lengths,
including padding transitions at 55/56 and 119/120 bytes and element boundaries
at 520/521. Each mutated target digest rejects independently. Wrong preimages,
the internal SHA-256 digest used as an opening, absent and surplus items,
and an oversized correct-digest opening all reject. A collision in the
common SHA-256 intermediate would propagate to both public digests.
The [negative result](../negative-results/dual-digest-preimage.md) records
this limitation and the script-size tradeoff.

```sh
cargo test --locked --lib commitments::dual_digest::tests
cargo test --locked --test primitive_metrics dual_digest_preimage_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

The compiler and interpreter pins are
[`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`](https://github.com/BitVM/rust-bitcoin-script/tree/124b561ed75ac3ec4c6ad99207d8dcdd3bc67180)
and [`a09e87af444034698697f0a2267e755cf72f9aed`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/tree/a09e87af444034698697f0a2267e755cf72f9aed).
See the [implementation](../../src/commitments/dual_digest/README.md)
and catalog `commitment/dual-digest-preimage`.
