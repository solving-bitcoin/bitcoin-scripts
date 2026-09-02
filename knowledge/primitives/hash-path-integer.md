# Mixed-hash path commitment

The generic construction authenticates a bit string by selecting SHA-256 or
RIPEMD-160 at each step. Its interface is

```text
hash_path(preimage, bits) -> 20-byte digest
```

The integer variant interprets the authenticated bits as a 1–31-bit
non-negative Script integer. The fixed-size generic output has a second,
unusual property: it can become the preimage of a later path, providing an
ordered, append-like commitment interface in a language without general byte
concatenation.

## Construction

Let `S(x) = SHA256(x)`, `R(x) = RIPEMD160(x)`, `H(0, x) = S(x)`, and
`H(1, x) = R(x)`. For bits processed in the order `b[0], ..., b[n-1]`, define

```text
HP(x, b) = R(H(b[n-1], ... H(b[0], x)))
```

The terminal `R` normalizes either branch's output to a 20-byte digest. The
verifier also restricts every bit to the unique Script encodings `[]` and
`[01]`. Integer reconstruction stores the authenticated bits temporarily on
the altstack and folds them into a Script number after the digest comparison.

## Hash-state composition

Suppose Alice commits to `(x_A, a)` and Bob subsequently contributes `b`:

```text
h_A = HP(x_A, a)
h_B = HP(h_A, b)
```

Script can verify both paths as a stream. Bob's bit items begin below Alice's
opening. Alice's path consumes only `x_A` and `a`, leaving `h_A` on top; Script
duplicates and compares that checkpoint, then immediately uses the retained
digest as the starting item for Bob's path. The local test
`digest_can_seed_a_later_path` reproduces this stack composition.

This gives the construction several relatively unusual properties for Bitcoin
Script:

- **Constant-size checkpoints:** every round reduces its history to 20 bytes.
- **Ordered extension:** Bob's contribution is bound to the exact `h_A` used
  as its preimage, so changing Alice's opening changes Bob's starting state.
- **Incremental verification:** more participants can nest further paths, and
  Script does not need to materialize a concatenated transcript item.
- **Streaming stack layout:** a later round's selector bits can wait below the
  current opening and become active when the prior digest reaches the top.

This is not ordinary concatenation or an associative transcript hash. In
general, `HP(HP(x, a), b) != HP(x, a || b)`: the nested form contains the
inner call's terminal RIPEMD-160 step. The protocol must fix and check every
checkpoint, participant order, bit width, and round boundary. Script and
witness cost remain linear in the total path length despite the constant-size
published state.

## Joint-randomness protocols

Nested paths can authenticate a commit–reveal transcript for a game or
poker-like protocol:

1. Alice samples `a` and a hiding preimage `x_A`, then publishes `h_A`.
2. Bob samples `b` only after `h_A` is fixed, then publishes `h_B`.
3. After both openings verify, the protocol derives its joint value with a
   specified combiner, such as equal-width `a XOR b`.

The security conditions sit above the path primitive:

- Hiding comes from min-entropy in the unrevealed `(preimage, bits)` pair.
  Since Bob starts from the already-public `h_A`, his `b` must itself have
  enough entropy to resist enumeration. Alice can use a secret high-entropy
  `x_A` to hide even a short `a`.
- For XOR-based randomness, at least one contribution must be uniformly random
  and hidden until every other contribution is bound. The commitment cannot
  enforce honest sampling.
- Using `h_B` directly as the outcome lets Bob grind candidate `b` values after
  seeing `h_A`. A combiner whose result Bob cannot predict without Alice's
  opening avoids that particular bias.
- The last revealer can still abort after learning the result. Deadlines,
  penalties, or fallback outcomes must be provided by the transaction graph.
- Unique session context and checkpoint reuse rules are needed to prevent
  cross-game replay.

These properties make hash paths a useful building block, not by themselves a
complete fairness or poker protocol.

## Evidence and deployment

- **Position:** compact bit-string or integer authentication with a simple
  witness, non-standard mixed-hash security, and append-like hash-state
  composition.
- **Evidence:** `locally-reproduced` with canonical-bit, wrong-opening,
  boundary, and nested-composition tests.
- **Representative result:** 31 bits use a 520-byte fragment, 78-byte serialized
  witness, and 34 stack items.
- **Security:** the final 160-bit digest caps generic collision resistance at
  80 bits and generic preimage/second-preimage resistance at 160 bits. Binding
  additionally relies on the unconventional mixed SHA-256/RIPEMD-160 path.
- **Deployment:** wider variants exceed legacy opcode limits and are primarily
  tapscript research constructions. The local witness executor disables the
  stack limit, so these results are `research-unlimited`, not evidence of
  consensus validity or relay policy.

See the [implementation README](../../src/commitments/README.md) and catalog
record `commitment/hash-path-integer`.
