# Binohash transaction digest

Binohash is a reported 2026 construction that combines the legacy
`FindAndDelete`/`OP_CHECKMULTISIG` behavior with signature grinding to create a
transaction-dependent digest that Bitcoin Script can extract and authenticate.

- **Position:** external state-of-the-art transaction introspection construction
  that requires no consensus change, according to its primary source.
- **Evidence:** reported and inspected at the paper/discussion level; no local
  implementation or reproduction is present.
- **Reported profile:** the paper proposes a two-round nonce extraction design
  with tunable work/collision parameters and a Lamport-signable output.
- **Execution context:** relies on legacy signature semantics, not the local
  tapscript-only executor defaults.
- **Research need:** pin a reference implementation, reproduce Core regtest
  behavior, catalog full script/witness/work costs, and model grinding economics.

See source `binohash-paper`, the [transaction-introspection discussion](https://delvingbitcoin.org/t/binohash-transaction-introspection-without-softforks/2288),
and open problem `OP-011`.
