# Transaction introspection with Binohash

Binohash is an external reported construction whose primary source uses legacy
signature behavior and proof-of-work grinding to expose a collision-resistant
transaction digest to Script without a consensus change.

```text
Transaction mutations and legacy sighash
├── FindAndDelete / OP_CHECKMULTISIG behavior
├── subset and nonce grinding
├── two-round digest extraction
├── Script-readable digest
└── Lamport authentication into a later verification protocol
```

The repository has a [legacy core reproduction](../primitives/binohash-legacy-core.md)
for opcode-boundary deletion, subset-dependent legacy sighashes, and the
`SIGHASH_SINGLE` bug constant. A reduced two-choice fixture now validates two
complete funded P2SH spends against pinned Bitcoin Core v30.3. Both selected
spends satisfy consensus but fail default relay policy; flipping selection
without re-signing fails consensus. This is not the two-round grinding
protocol, ECDSA nonce search, or Script-readable digest. Do not model Binohash
with the default tapscript executor: its legacy signature context and
transaction template are essential semantics. Full reproduction still needs
grinding parameters, mutation constraints, Script extraction, and full costs.
If a consumer uses the HORS-like helper to authenticate extracted indices,
its upper-clamped openings do not bind the raw index sequence; see
[NR-110](../negative-results/index.md#nr-110-clamped-hors-openings-do-not-bind-raw-binohash-indices).
See `introspection/binohash` and `OP-011`.

A separate [2-of-3 toy subset](../primitives/binohash-subset-toy.md) now
exercises the paper's dynamic `OP_ROLL` selection, a small signature-size
condition, and a downstream Script predicate selected by the surviving
indices. Pinned Core accepts two disjoint funded P2SH spends selecting
`[0,1]` and `[0,2]` and rejects malformed selectors and mismatched preimages
for each. The preimages are public, and the
fixture has no transaction pinning, two-round grind, or meaningful security
parameter. Default policy still rejects both consensus-valid spends.

The [raw sighash-byte census](../primitives/binohash-sighash-flags.md)
confirms that 256 byte values can be signed under legacy consensus while
default relay policy accepts only six canonical values. This is an input to
grinding-space analysis, not a measurement of independent nonce entropy or a
full transaction-introspection protocol.

The [nine-byte SIGHASH_SINGLE anchor](../primitives/binohash-single-anchor.md)
confirms under pinned Core that a hardcoded legacy signature can use the
out-of-range constant digest. Adding an output or moving it to an earlier
input invalidates the same signature. This is an anchor primitive, not proof
that transaction fields are pinned or that a nonce is authenticated.
