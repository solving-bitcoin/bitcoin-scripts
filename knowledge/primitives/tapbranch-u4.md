# TapBranch tagged hash over u4 nodes

This primitive computes the BIP341 `TapBranch` tagged hash for two 32-byte
nodes that are already in lexicographic order. It is a concrete, executable
composition of the repository's u4 SHA-256 circuit: the script embeds the two
copies of `SHA256("TapBranch")`, routes 128 witness nibbles below that prefix,
and hashes the resulting 128-byte message.

The question is whether the existing nibble SHA-256 implementation can bind a
TapBranch preimage without byte concatenation. The answer is locally-reproduced
for the fixed-prefix, ordered-input fragment. It is not a deployable Taproot
leaf: the generated script is over the consensus script-size limit.

## Contract and threat model

The witness contains `left || right` as 128 canonical u4 items, two items per
byte, in most-significant-nibble-first order. The script returns the digest as
64 u4 items in the same order. The witness is hostile, so short input, wrong
node order, and digest mismatches are tested. The caller must separately bind
`left <= right`; the fragment intentionally does not include a comparator.

The digest is

```text
SHA256(SHA256("TapBranch") || SHA256("TapBranch") || left || right)
```

which is the BIP341 tagged-hash construction for TapBranch. The implementation
uses the existing `sha2_u4::sha256(128)` generator and does not introduce a
new hash algorithm or table family.

## Measurement

The representative configuration is fragment-only with its complete fixed
prefix, routing, SHA-256 tables, cleanup, and 128-item witness boundary. It
excludes the ordering comparator, terminal digest check, Taproot control block,
and transaction context. It has zero hint items; the 128 witness items are
data, not hints, and all coexist at script entry. The strict local peak is 969
combined main/alt-stack items, leaving 31 items for surrounding composition.

| Configuration | Script | Witness | Items | Hints | Peak |
| --- | ---: | ---: | ---: | ---: | ---: |
| Two ordered 32-byte nodes | 1,106,745 bytes | 161 bytes | 128 | 0 (none) | 969 |

The script contains 671,107 static non-push opcodes. The local executor does
not expose the consensus validation budget. The script is larger than
Bitcoin's 10,000-byte script-size consensus limit, so its successful local
execution is `research-unlimited`, not consensus validation or deployability.

## Compatibility and limitations

The generated opcodes are available to tapscript and the older script
versions, but the measured fragment is consensus-incompatible in every
wrapper because of its serialized size. The strict stack measurement is still
useful: it shows that the u4 tables and digest state fit below 1,000 items with
only 31 items of headroom. A compact deployable construction needs a different
representation or a smaller SHA-256 circuit, plus an in-script ordering
check if the caller cannot establish the Taproot sort order elsewhere.

This result updates the TapBranch boundary: a full fixed-prefix circuit is
possible in the local language, while a compact byte-level adapter remains an
open problem. See [NR-050](../negative-results/index.md#nr-050-the-full-u4-tapbranch-circuit-is-not-deployable),
[OP-001](../open-problems.md#op-001--strict-execution-matrix),
[OP-002](../open-problems.md#op-002--bitcoin-core-differential-harness), and
[OP-020](../open-problems.md#op-020--compact-tapbranch-adapter).

## Reproduction

Focused checks:

```sh
cargo test --locked commitments::tapbranch
cargo test --locked --test primitive_metrics tapbranch_metrics_are_current
python3 tools/kb.py validate
```

The implementation and tests are in
[`src/commitments/tapbranch.rs`](../../src/commitments/tapbranch.rs). The
primary construction reference is [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki),
with the SHA-256 execution model covered by the repository's pinned FIPS-180-4
reference record.
