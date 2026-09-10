# Checked PRINCEv2 complete Taproot leaves

Question: can the existing PRINCEv2 fragment become a complete computation leaf
that enforces its input contract under consensus, matches an independent cipher
reference, and spends a funded output under Bitcoin Core's default relay policy?
The objective is to establish that boundary and its cost; the existing
6,136-byte unchecked fragment and the sub-5,000-byte OP-019 goal are unchanged.

## Result and scope

On 2026-09-10, all **20 fixtures** matched their Core consensus/policy
expectations and rejection diagnostics. All **40 local profile comparisons**
agreed with Core, with zero panics. Three valid spends were accepted by both
consensus and policy; 17 invalid cases were rejected by both. Two fresh nodes
produced byte-identical [reports](../tests/data/prince-validation-v30.3.json),
SHA-256 `342185a424dbe85d4d2fbeef96f2fd7c00c9b25199c3d6b1c50b36a1f34d1878`.

Evidence is `differentially-validated`. The three exact valid complete spends
are `policy-validated`; each rejected fixture is `consensus-incompatible` as
submitted. These classes do not establish an arbitrary-key resource bound or
transfer to unchecked fragments or composed protocols. The public embedded
cipher key and disclosed plaintext provide a computation predicate, with no
transaction authorization or plaintext secrecy. The test Taproot internal key
is public as well.

## Construction and validation

[`prince_verify(key, ciphertext)`](../src/ciphers/prince/mod.rs) requires exactly
16 main-stack items. It checks each item's byte encoding before encryption:
zero must be the empty vector; nonzero nibbles must be one-byte values 1–15.
Thus consensus permission for nonminimal ScriptNums cannot bypass the contract.
Each validation copy is consumed, preserving the input ordering. Encryption
consumes those inputs; all 16 ciphertext nibbles are compared before leaving
one true item and an empty alt stack.

The whole leaf passes through `compile_with_policy()` once. Its unoptimized
input falls below 32 KiB, so `CompileOptions::ALL` applies. Local execution,
script metrics, hashes and the Taproot commitment use that exact `ScriptBuf`.
Runtime witness inputs and observable ciphertext checks preserve the encrypted
computation through optimization. Local consensus/policy profiles enforce the
combined 1,000-item stack limit. They check the leaf only; Core independently
validates its commitment and complete funded transaction.

The deterministic [fixture generator](../examples/prince_validation_fixtures.rs)
selects three existing independent upstream-C vectors (indices 0, 3, 4):

| Fixture | Key (hex) | Plaintext (hex) | Ciphertext (hex) |
| --- | --- | --- | --- |
| Zero | `00000000000000000000000000000000` | `0000000000000000` | `0125fc7359441690` |
| All-ones | `00000000000000000000000000000000` | `ffffffffffffffff` | `832bd46f108e7857` |
| Published | `0123456789abcdeffedcba9876543210` | `0123456789abcdef` | `603cd95fa72a8704` |

Two controls change the expected ciphertext. Three supply 0, 15 or 17 items.
Twelve mutate individual nibbles across the most-significant, interior and
least-significant positions: negative values, 16/127/128, negative zero,
explicit zero bytes, padded encodings, and a five-byte number. Missing/extra
inputs reject at the entry count. Malformed encodings reject before encryption.
For byte strings `00` and `80`, consensus reaches `VERIFY`, whereas policy
rejects the nonminimal ScriptNum first; the report checks both diagnostics
separately. Core v30.3 renders that policy error as “unknown error”, while the
local interpreter identifies `MinimalData`.

The broader [local checked-leaf tests](../tests/prince_checked.rs) mutate 11
invalid encodings at every one of the 16 positions under both profiles, and
also exercise valid boundaries, input counts and wrong plaintext/ciphertext.
The Core corpus is a bounded subset of those cases.

## Complete costs and composition

Boundary: **complete-leaf:** input-count/encoding/range checks, embedded key,
lookup setup, encryption, cleanup, ciphertext comparisons and terminal truth.
Input pushes are excluded. The complete witness includes all data, the final
leaf and 33-byte control block, with every CompactSize prefix. Transaction
weight is measured from the funded one-input/one-output spend and cross-checked
with Core's decoder; it is not a projection.

| Fixture | Leaf bytes | Data witness bytes | Complete witness bytes | Combined peak | Static non-push ops | Weight | vbytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Zero | 6,426 | 17 | 6,480 | 633 | 4,182 | 6,858 | 1,715 |
| All-ones | 6,426 | 33 | 6,496 | 633 | 4,182 | 6,874 | 1,719 |
| Published | 6,582 | 32 | 6,651 | 685 | 4,237 | 7,029 | 1,758 |

Each valid invocation supplies **16 data items, zero hint items and zero hint
bytes**; all 16 data items coexist at entry. The complete Taproot witness has
**18 items**. Main-plus-alt peaks include inputs, tables and temporaries. The
complete leaf rejects unrelated main-stack state and has no batched mode, so
the remaining stack capacity is not a measured composition allowance.

Executed non-push counts remain null: canonical zero and nonzero inputs take
different branches, and the interpreter's parsed-instruction counter is not
that metric. There are no signature opcodes, so signature-validation charge is
zero; this does not validate local full-witness budget initialization. Checked
metric markers are separate from the original fragment snapshots.

## Reproduction and provenance

- Bitcoin Core v30.3: [`49faec4f87f5cd19c88db01a82e5c68b087c8227`](https://github.com/bitcoin/bitcoin/tree/49faec4f87f5cd19c88db01a82e5c68b087c8227).
- Interpreter: [`702544c9a045ac4fc14846da6da6559e2b7cd9d1`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/tree/702544c9a045ac4fc14846da6da6559e2b7cd9d1).
- Compiler: [`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`](https://github.com/BitVM/rust-bitcoin-script/tree/124b561ed75ac3ec4c6ad99207d8dcdd3bc67180).
- Independent C reference: [`0c6172dcd85f1fe6a269519093a79c7350fe6e55`](https://github.com/rub-hgi/princev2/tree/0c6172dcd85f1fe6a269519093a79c7350fe6e55).

The committed report used the hash-verified macOS ARM64 Core archive. The shared
manifest also pins Linux x86_64 for CI. The generator embeds Cargo lockfile
provenance; the runner cross-checks it with locked Cargo metadata and verifies
the cipher fixture hash. The source vector corpus records seed
`0x5052494e43455632`; no new randomness selects this experiment's cases.
The Taproot internal key uses seed `[1; 32]`, and mock time starts at
`1800000000`. Fixture JSON SHA-256 is
`3a1781c1b72e7c4a7c236abeb73c515678ab38dcf83798710c50a21675d37f1b`.

```sh
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test prince_checked
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test primitive_metrics prince_checked_metrics_are_current
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --example prince_validation_fixtures
python3 -m unittest discover -s tools -p 'test_prince_regtest.py'
CARGO_PROFILE_DEV_OPT_LEVEL=1 python3 tools/prince_regtest.py --download-core --output target/prince-validation-v30.3.json
```

The [runner](../tools/prince_regtest.py) creates and cleans up its own isolated
regtest node, with networking and wallet disabled and `-acceptnonstdtxn=0`.
It checks policy with `testmempoolaccept`, then independent consensus with raw
transaction block generation and a connected-block transaction-id check.
No mainnet or testnet funds are used. Missing expectations, wrong diagnostics,
dependency mismatches, or infrastructure errors make the command fail. The
shared [Core validation guide](core-validation.md) describes the oracle boundary.
