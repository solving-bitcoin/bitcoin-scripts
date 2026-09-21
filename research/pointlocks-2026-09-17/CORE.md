# Exact point-lock execution against Bitcoin Core

Question: do the policy-compiled, unpadded 76-byte two-check and 79-byte
three-check legacy point-lock predicates execute in complete transactions,
including the rare high-S completeness case? The comparison separates
consensus execution, relay policy, and the cryptographic extraction claim.

The runner [core_check.py](core_check.py) consumes the Rust-generated
[vectors.json](vectors.json) byte-for-byte. It independently traces the small
opcode layouts and checks their ECDSA equations in Python, then compares those
results with an isolated Bitcoin Core 30.3 regtest node. The exact binary,
archive checksum, immutable source commit, node arguments, full funding and
spending transactions, native digest preimages, and verdicts are recorded in
[core_check.json](core_check.json).

The Rust generator compiles through `ScriptCompilation::compile_with_policy()`
using `bitcoin-script` commit `124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`.
Both scripts are below the 32 KiB optimization cutoff. The Rust digest and
extraction comparison uses rust-bitcoin 0.32.102 and secp256k1 0.29.1, as
resolved in `Cargo.lock`. Its legacy unit-test interpreter is pinned to
`702544c9a045ac4fc14846da6da6559e2b7cd9d1`; the Core harness does not depend on
that interpreter's execution or its historical NOP-padding workaround.

**Result: all 18 expected outcomes matched.** The representative low-S
two-check P2SH transaction is `differentially-validated` and
`policy-validated`. Its bare counterpart, both three-check forms, the high-S
fallbacks, and the undefined-flag positive fixtures are
`differentially-validated` and `consensus-validated`, with policy rejection.
The eight malformed or incompatible-context negative fixtures reject under
consensus and policy; their fixture deployment class is
`consensus-incompatible`, not a classification of the whole primitive.

The tested release is Bitcoin Core **30.3**, commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`, from
`bitcoin-30.3-arm64-apple-darwin.tar.gz`, archive SHA-256
`c42480fd26dd0b12c984e8063a1879165c94525c475162deb3ea2c3054dd5c2c`.
The extracted executable SHA-256 is
`fb6bbeb837fbaba84a0883602d718d749a4d739ee82ab326c3bc58094edddadb`.

The node uses a fresh temporary directory, disables its wallet and networking,
binds RPC only to localhost, and verifies zero peers and inactive networking.
No production datadir, funds, wallet, peer, or network is used. The cached
release archive is hash-verified; the runner does not download binaries.

## Reproduction

Generate `vectors.json` with the repository's point-lock fixture generator,
then run:

```sh
cargo run --locked --example pointlock_vectors > research/pointlocks-2026-09-17/vectors.json
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/core_check.py
cargo test --locked --test pointlock_core_vectors
```

The cache must contain the pinned archive under
`/private/tmp/covenant-core-30.3`. If local RPC binding requires sandbox
escalation, rerun this same bounded command with local-network permission;
do not connect to an existing node.

## Measurement boundary

Each complete spending transaction has two inputs: one ordinary `OP_TRUE`
P2WSH helper and one point-lock input. The helper supplies the extra input
needed to place the point lock at index one with only one output, invoking
the legacy SIGHASH_SINGLE constant. Both inputs spend actual outputs of a
locally mined funding transaction. Distinct fixtures use distinct funded
outpoints so previous acceptance cannot interfere through mempool conflicts.

The locked input has exactly **one signature data item and zero hint items**.
Its P2SH `scriptSig` has two pushes (signature and redeem script); its bare
`scriptSig` has one. The point-lock input itself has no witness items. The
helper has one witness item (`51`). Complete transaction witness-vector
serialization occupies four bytes, plus two marker/flag bytes; those bytes
are included in the reported transaction weight. Within each input, its data
coexist at entry; the helper and point-lock inputs execute separately. The
altstack is unused.

The two-check predicate has a combined stack peak of three and six executed
non-push opcodes; the three-check predicate peaks at five and executes nine.
P2SH adds its two wrapper operations. Script bytes exclude the 23-byte P2SH
funding wrapper, input pushes, transaction framing, optional payment
authorization and refund branches. The JSON also records those full
transaction sizes and the exact `scriptSig` sizes. These measurements use
the final policy-produced bytecode, not the NOP-padded legacy interpreter
workaround found in earlier unit tests.

## Recorded positive transactions

| Signature case | Predicate | Wrapper | Signature bytes | ScriptSig bytes | Complete weight | Consensus | Policy |
| --- | --- | --- | ---: | ---: | ---: | --- | --- |
| Representative low-S | Two-check, 76 B | P2SH | 60 | 139 | 1,054 WU | Accept | Accept |
| Representative low-S | Two-check, 76 B | Bare | 60 | 61 | 742 WU | Accept | Reject |
| Representative low-S | Three-check, 79 B | P2SH | 60 | 142 | 1,066 WU | Accept | Reject |
| Representative low-S | Three-check, 79 B | Bare | 60 | 61 | 742 WU | Accept | Reject |
| High-S fallback | Two-check, 76 B | P2SH | 61 | 140 | 1,058 WU | Accept | Reject |
| High-S fallback | Two-check, 76 B | Bare | 61 | 62 | 746 WU | Accept | Reject |
| High-S fallback | Three-check, 79 B | P2SH | 61 | 143 | 1,070 WU | Accept | Reject |
| High-S fallback | Three-check, 79 B | Bare | 61 | 62 | 746 WU | Accept | Reject |
| Undefined flag `23` | Two-check, 76 B | P2SH | 60 | 139 | 1,054 WU | Accept | Reject |
| Undefined flag `23` | Three-check, 79 B | P2SH | 60 | 142 | 1,066 WU | Accept | Reject |

All positive checks receive the exact digest bytes `01` followed by 31 zero
bytes, interpreted by ECDSA as `C=2^248`. The independent arithmetic check
accepts the original high-S value without normalizing it, agreeing with the
legacy consensus result. Each complete transaction includes both inputs and
the one intended output; the table is not a witness-only proxy.

The eight negative fixtures are the Cartesian product of both predicates
with four mutations: change the signature's final scalar byte, move the
locked input to index zero, add a second output, or supply a 57-byte item.
The two context changes compute ordinary native sighashes and fail ECDSA;
they do not invoke the SINGLE constant. The 57-byte item fails the size
guard before any signature opcode. Full first-failure traces and Core
rejection messages are in the JSON.

The Rust integration test deserializes these exact transactions and funding
outputs, verifies the actual signature/redeem-script pushes, recomputes every
reached native digest and scriptCode view, and compares serialization, txid,
and weight. It recovers the expected scalar from all ten Core-accepted
fixtures and rejects all eight negative fixtures. This also covers the
original high-S signature bytes and undefined sighash byte `0x23`.

## Scope

Successful Core execution proves the recorded transaction's applicable
consensus behavior. Acceptance by `testmempoolaccept` additionally establishes
the pinned node's relay-policy result for that transaction. High-S is valid
under legacy consensus but nonstandard under LOW_S; undefined sighash byte
`23` invokes the same SINGLE-bug path but is nonstandard; executed legacy
CODESEPARATOR is nonstandard under CONST_SCRIPTCODE. Exact rejection reasons
are preserved rather than inferred from these descriptions.

These tests do not establish arbitrary-target computational extractability
of the two-check construction. See the separate [algebra review](algebra.md)
for the exact invariant, constant-digest extraction, ordinary-digest
limitation, and additional assumption. Successful sample execution must not
be used as a proof of that assumption.
