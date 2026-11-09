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
  A separate [raw sighash-byte census](binohash-sighash-flags.md) validates 256
  signed P2SH spends under pinned Core consensus; only the six canonical byte
  values pass default relay policy.
  A [CODESEPARATOR fixture](binohash-codesep-core.md) differentially validates
  selected signature pushes on both sides of the operative legacy boundary.
  A [fixed-digest nonce-size probe](binohash-der-size-grind.md) validates a
  70-byte ECDSA signature and two controls in a funded, default-policy-accepted
  P2SH spend.
- **Reported profile:** the paper proposes a two-round nonce extraction design
  with tunable work/collision parameters and a Lamport-signable output.
- **Execution context:** relies on legacy signature semantics, not the local
  tapscript-only executor defaults.
- **Research need:** reproduce transaction pinning, the full two-round grind,
  and authenticated Script extraction,
  catalog its complete costs and mutation boundaries, and model grinding
  economics. The reduced Core fixtures do not establish these properties.

The [8-of-n parameter frontier](../../research/binohash-parameters/README.md)
computes the exact subset counts for the paper's `n=120,t=8` example and
evaluates its byte/opcode formulas as **estimates**. It is host-side arithmetic,
not a measured full script, grind, or deployment result.

See source `binohash-paper`, the [transaction-introspection discussion](https://delvingbitcoin.org/t/binohash-transaction-introspection-without-softforks/2288),
and open problem `OP-011`.
