# Complete bare-legacy sum-key publication

Question: does the sized 79-pool, seven-of-48 bare-legacy sum-key publication
work with real funding, real signatures, and every publication output consumed?
**The complete example passes Bitcoin Core block validation at 161,382 vB.**
Its canonical maximum is **161,560 vB**, attained by the all-zero message.
Default relay policy rejects both transactions.

The [opt-in mempool-policy follow-up](bare-nonstandard-policy.md) now accepts
and mines the identical transactions with `acceptnonstdtxn=1` plus a local
Core policy patch. All 15 invalid controls still fail consensus; the patched
default-policy control preserves standardness rejection. Size is unchanged.

Evidence: **differentially-validated**. Positive deployment:
**consensus-validated**, not policy-validated. Bitcoin Core 30.3 at commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227` runs in a disposable regtest with
wallets and external networking disabled. No consensus checks are disabled;
no tapscript/stack-unlimited helper is used.

[Rust generator](../../examples/pointlock_bare_publication_probe.rs),
[Core and independent-decoder harness](bare_publication_core_check.py),
[complete transactions](bare-publication-transactions.json),
[Core report](bare-publication-core-check.json),
[offline regression](../../tests/pointlock_bare_publication_vectors.rs).

## Parameters and complete cost

79 independent seven-of-48 pools contain 3,792 candidate points and require
553 scalar revelations. The public test fixture derives nonce candidates from
SHA256 of increasing big-endian u64 counters starting at one, retrying until
the low-S signature with SINGLE flag is 71 bytes. Production requires secret,
independent nonces; these test secrets and the helper key must never hold funds.
Setup uses the existing common-G sum-key algebra, without ZKP or interaction.

`binomial(48,7)^79` has approximately 2064.5680024187923 bits of capacity;
78 pools are insufficient. Lexicographic subset ranking and big-endian
base-`binomial(48,7)` conversion encode every 256-byte value. Reveal order is
not additional capacity. Candidate keys and HASH160 commitments are globally
distinct in the generated fixture.

| Transaction | Bytes | Weight | vB |
|---|---:|---:|---:|
| Existing P2TR input to first P2TR helper plus 79 bare outputs | 98,359 | 393,232 WU | 98,308 |
| Helper plus all 79 pools to final P2TR; message `00 01 ... ff` | 63,184 | 252,295 WU | 63,074 |
| **Combined** | **161,543** | **645,527 WU** | **161,382** |

The all-zero message selects the first seven candidates per pool: all hints
need two-byte pushes, giving 756-byte scriptSigs and a 63,252-vB spend. Hence
**161,560 vB** is the maximum for this canonical layout with 71-byte signatures
and minimal hints, not for every consensus-permitted malleated encoding.
The all-`ff` message costs 161,361 vB combined.

Included: creation and consumption of all 79 outputs, complete scripts,
scriptSigs, 64-byte helper signatures, count/length prefixes, empty legacy
witness vectors, marker/flag bytes, and per-transaction rounding. The assumed
initial P2TR UTXO's creation, change, refunds, and application-specific
authorization are excluded. The regtest grant is separately identified.
Bare pool value is 10,000 satoshis; remaining value stays in the helper.

## Script and resources

Each optimized locking script is **1,232 bytes**, with **140 static and executed
non-push opcodes**, including 14 CHECKSIGVERIFY operations. It stages incoming
records on the alt stack, loads G and 48 HASH160 commitments, then destructively
selects seven distinct entries. A record is `[signature, compressed key, depth]`.
The key must match the selected commitment, and the same signature longer than
57 bytes must verify under both that key and G. OP_TRUE terminates the script.

Each pool requires **seven index hints and 21 complete data items**, all present
at entry. Across 79 separate stacks: **553 hints and 1,659 entry items**.
There is no redeem-script push. Each bare input has zero witness items, but
contributes a one-byte empty vector beside the P2TR helper. Funding/spending
witness vectors total 66/145 bytes, plus each transaction's two-byte marker/flag.

Independent Python tracing measures combined main/alt-stack peak **73**, or
**74** for the extra-lower-item control. These are trace measurements, not Core
instrumentation. Different input stacks do not coexist. A canonical pool ends
with **43 main-stack items**: G, 41 unused hashes, and true. Bare legacy consensus
does not require CLEANSTACK; omitting table cleanup is intentional.

The sum-key theorem is unchanged: distinct P and G plus the signature length
guard force opposite verification nonce points, giving `log_G(P+G)=-2z/r`
for the actual common digest z. No CODESEPARATOR or signature-sized push occurs
in the locking script, so FindAndDelete does not alter either scriptCode.
Honest openings use input indices at least one and exactly one output.

The Python decoder reads actual Core-decoded inputs and funded scripts, traces
lookup operations, checks both native ECDSA equations, checks each extracted
scalar against P+G, and reconstructs the message. All 553 scalars and 256 bytes
recover. Main payload SHA256:
`40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880`.
The Rust regression independently recomputes native digests and extracts all
1,659 scalars across the three complete message fixtures.

## Validation and application boundaries

Funding passes `generateblock` but fails default `testmempoolaccept` with
`scriptpubkey`. Spending fails policy with `bad-txns-nonstandard-inputs` or,
for that control, `scriptsig-not-pushonly`. Each accepted spend is mined,
inspected, and rolled back before the next conflicting variant. They test
alternative uses of a one-time instance, not repeated publications in one chain.

There are **11 accepted and 15 rejected spending controls**, plus funding:

- Accepted complete messages: increasing bytes, all zero, all `ff`.
- Accepted encodings: reversed selection order, nonminimal four-byte hints,
  extra lower item, DUP DROP in scriptSig, high-S, undefined SINGLE flag. Each
  preserves recovery of the intended message.
- Rejected: short/changed signatures, wrong key, zero/one/outside/negative/
  oversized hints, missing hint, deleted frame, duplicate selection, wrong
  sighash, second output, point-lock input zero, invalid helper signature.
  The helper is re-signed for the output-count/input-index controls so those
  failures isolate the point lock.
- Accepted protocol-boundary controls: an unused codeword opens 553 scalars
  outside the canonical 256-byte range; a one-pool spend opens seven and leaves
  78 pools unspent. The report explicitly identifies both outcomes.

Native pools therefore enforce seven distinct openings locally, not full
participation or the global message range. Complete BitVM3 integration still
needs total decoding or a specified failure rule, mandatory participation or
safe-abort handling, garbling/label binding, and malleability/refund treatment.
The decoder supports the recorded scriptSig forms; it is not a universal
parser for every consensus-valid legacy scriptSig.

HASH160 key-table binding remains required: malicious setup can seek alternate
colliding keys at the generic approximately 2^80 birthday scale. Bare outputs
remove the outer P2SH hash, not the inner key commitments. Setup timing is
**not measured** here; neither the full-goal 100-ms target nor global byte
optimality is established.

## Reproduction

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/bare_publication_core_check.py
cargo test --locked --example pointlock_bare_publication_probe
cargo test --locked --test pointlock_bare_publication_vectors
python3 tools/kb.py validate
```

The native harness requires loopback RPC permission and uses an existing,
checksum-verified Core cache without downloading software. Source/binary hashes,
dependency identity, node options, raw transactions, rejection reasons and
extraction traces are recorded. Compilation uses `compile_with_policy()`;
scripts are below the 32-KiB optimizer cutoff.
