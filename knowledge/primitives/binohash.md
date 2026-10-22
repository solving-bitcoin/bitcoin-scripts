# Binohash transaction digest

Binohash is a reported 2026 construction that combines the legacy
`FindAndDelete`/`OP_CHECKMULTISIG` behavior with signature grinding to create a
transaction-dependent digest that Bitcoin Script can extract and authenticate.

- **Position:** external state-of-the-art transaction introspection construction
  that requires no consensus change, according to its primary source.
- **Evidence:** the full protocol remains `reported`; the
  [deterministic legacy core](binohash-legacy-core.md) is locally reproduced,
  and a reduced two-choice funded P2SH configuration is differentially
  validated against pinned Core v30.3 under consensus but rejected by default
  relay policy. A [2-of-3 toy subset](binohash-subset-toy.md) additionally
  validates dynamic selection, a size filter, and downstream index consumption.
- **Reported profile:** the paper proposes a two-round nonce extraction design
  with tunable work/collision parameters and a Lamport-signable output.
- **Execution context:** relies on legacy signature semantics, not the local
  tapscript-only executor defaults.
- **Research need:** reproduce transaction pinning, the full two-round grind,
  and authenticated Script extraction,
  catalog its complete costs and mutation boundaries, and model grinding
  economics. The reduced Core fixtures do not establish these properties.

See source `binohash-paper`, the [transaction-introspection discussion](https://delvingbitcoin.org/t/binohash-transaction-introspection-without-softforks/2288),
and open problem `OP-011`.
