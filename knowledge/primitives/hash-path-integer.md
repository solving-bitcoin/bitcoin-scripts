# Mixed-hash path commitment

The generic construction authenticates a bit string from an independently bound starting state, using optional SHA-256
followed by RIPEMD-160 at each step. A free starting preimage does not bind
the first bit (NR-056). Its interface is

```text
hash_path(preimage, bits) -> 20-byte digest
```

The integer variant interprets the authenticated bits as a 1–31-bit
non-negative Script integer. The fixed-size generic output has a second,
unusual property: it can become the preimage of a later path, providing an
ordered, append-like commitment interface in a language without general byte
concatenation.

## Construction

Let `S(x) = SHA256(x)`, `R(x) = RIPEMD160(x)`, `H(0, x) = R(x)`, and
`H(1, x) = R(S(x))`. For bits processed in the order `b[0], ..., b[n-1]`, define

```text
HP(x, b) = H(b[n-1], ... H(b[0], x))
```

Every step produces 20 bytes, without a terminal hash. This deliberately
changes existing commitments. Nonempty paths are required. Consumed paths use
`5n` static counted opcodes; retained normalized bits use `7n`. Output bits are
created inside branches; tapscript still rejects noncanonical IF selectors.
Integer reconstruction folds those normalized bits after digest comparison.

**Binding obligation:** independently authenticate or pin the initial preimage.
Without this, `(x, 1)` and `(SHA256(x), 0)` produce exactly the same state, and
any shared suffix preserves the collision. A 32-byte length check does not fix
it. This is reproduced by `unbound_preimage_allows_first_bit_substitution`.
The generic verifier deliberately remains a fragment; it adds no pinning cost.

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

`HP(HP(x, a), b) = HP(x, a || b)`: round boundaries add no hash or domain
separation. Pin every checkpoint, initial state, participant order, bit width,
and round boundary externally. Script and witness cost remain linear.

## Merkle distinction

The path is deliberately unary. A conventional Bitcoin Merkle branch requires
`HASH256(left || right)` at each level, but current Script hashes one stack item
and has no enabled `OP_CAT` to build that 64-byte preimage from two items. The
existing `sha2_u32::sha256(64)` backend has a 1,060,200-byte unoptimized,
compile-only profile and 770,481 static non-push opcodes before double hashing
or branch routing. Its 129-byte one-byte fixture witness becomes 193 bytes for
64 canonical two-byte payloads; both have 64 data items and zero hints. This is
a backend-specific workaround profile, not a Merkle verifier or universal cost
lower bound. Ordinary Merkle branches also differ from BIP341 TapBranch's
tagged, ordered-node construction; see [NR-064](../negative-results/merkle-branch-composition.md),
[NR-057](../negative-results/index.md#nr-057-native-taproot-merkle-branch-adapter-is-not-available),
and [OP-021](../open-problems.md#op-021--taproot-merkle-path-verifier).

## Joint-randomness protocols

Nested paths can authenticate a commit–reveal transcript for a game or
poker-like protocol:

1. Alice samples `a` and a hiding preimage `x_A`, independently binds `x_A`,
   then publishes `h_A`. The preimage binding can remain hiding.
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
- **Representative result:** 31 bits use a 457-byte fragment, 78-byte serialized
  witness, and 33 stack items.
- **Security:** the final 160-bit digest caps generic collision resistance at
  80 bits and generic preimage/second-preimage resistance at 160 bits. Binding requires an independently bound starting preimage and
  additionally relies on the unconventional mixed SHA-256/RIPEMD-160 path.
- **Deployment:** wider variants exceed legacy opcode limits and are primarily
  tapscript research constructions. The local witness executor disables the
  stack limit, so these results are `research-unlimited`, not evidence of
  consensus validity or relay policy.

See the [implementation README](../../src/commitments/hash_path/README.md) and catalog
record `commitment/hash-path-integer`.

The representative witness has 32 data items and **0 hint items**, all at entry.
The local executor revision is `702544c9a045ac4fc14846da6da6559e2b7cd9d1`.
Legacy normalization tests enable stack checks; helper-based tapscript metrics
disable them. Neither is Bitcoin Core differential validation. See OP-020 for
complete pinning and Binohash/Lamport composition requirements.

The two-round 4+3-bit chain measures 80 script bytes, 45 witness bytes,
38 static non-push opcodes and eight combined stack items, with eight entry
data items and zero hints. Initial-state binding is excluded.
