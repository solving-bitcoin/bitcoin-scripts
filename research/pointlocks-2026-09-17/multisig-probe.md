# CHECKMULTISIG for point-lock subsets

The comparison question is whether `CHECKMULTISIG` reduces the complete redeem
script or unlocking bytes of the existing HASH160-authenticated t-of-n subset
construction, while preserving the exact selected signature/key correspondence.
The measured substitutions do not improve either byte metric. Reordering each
opening from `(sigma,T,Q,index)` to `(T,Q,sigma,index)` saves one byte per
revelation with the existing `CHECKSIG` verifier.

## Measured 2-of-6 layouts

All rows use the same six deterministic candidate secrets `[7;32]` through
`[12;32]`, two selected signatures, four selected public keys, two ascending
indices, and the same candidate table of three HASH160 commitments per row.

| Verifier | Redeem script | Serialized P2SH scriptSig | Static non-push opcodes | Charged opcode count | P2SH fits |
|---|---:|---:|---:|---:|---|
| Existing two CHECKSIGs per selection | 514 B | 777 B | 106 | 106 | yes |
| Two CHECKSIGs, reordered opening | **512 B** | **775 B** | 104 | 104 | yes |
| Exact 2-of-2 CHECKMULTISIG per selection | 518 B | 781 B | 104 | 108 | yes |
| Exact 2-of-2, reordered opening | 516 B | 779 B | 102 | 106 | yes |
| Two exact t-of-t CHECKMULTISIG batches | 543 B | 806 B | 120 | 124 | no |
| One exact 2t-of-2t CHECKMULTISIG batch | 540 B | 803 B | 120 | 124 | no |

These are final policy-compiled bytes. The script boundary includes the candidate
table, all selection/authentication checks, signature length guards, signature
checks, table cleanup, and a clean truthy terminal result. The scriptSig column
includes minimal pushes of the eight opening items and the redeem script,
including its PUSHDATA2 prefix. It excludes transaction framing and the
CompactSize scriptSig length. For scripts exceeding 520 bytes that column is
only the serialization of a hypothetical P2SH spend; those scripts cannot be
used as P2SH redeem scripts. Their Core executions instead use bare outputs.

The dummy is generated as `OP_0` inside the script. Repeated signatures are
duplicated inside the script. Consequently every layout has **two index hint
items** and **eight complete unlocking data items** at redeem-script entry:
two signatures, four public keys, and two indices. The redeem-script push is
one additional scriptSig item consumed by P2SH evaluation. There is no
point-lock witness; in a transaction containing another SegWit input this
legacy input has an empty witness vector serialized as one byte.

The measured combined main-plus-alt-stack peak is **29 items** for both
CHECKSIG layouts. The Core harness enforces the consensus stack limit for the
multisig variants but does not instrument their exact stack peak. Their peak
is therefore unmeasured, rather than copied from the CHECKSIG result. All
opening items coexist at entry; individual P2SH inputs execute separately.

## Exact correspondence is necessary

Each selected index authenticates the exact `(sigma,T,Q)` tuple against one
candidate row. Indices are strictly ascending, so duplicate selections cannot
count twice. The signature item must be longer than 57 bytes before entering
any signature check.

For the reordered per-pair layout the verified stack starts as `T Q sigma`:

```text
OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
OP_0 OP_SWAP OP_DUP OP_2 OP_2ROT OP_2 OP_CHECKMULTISIGVERIFY
```

The final CHECKMULTISIG arguments are exactly:

```text
<empty dummy> <sigma> <sigma> 2 <T> <Q> 2
```

Because the signature count equals the key count, the check cannot skip any
key. The two-batch version likewise checks the exact selected ordered T list
and Q list with identical ordered signature lists. The one-batch version
checks `[sigma_1,sigma_1,...]` against `[T_1,Q_1,...]`, again with equal counts.
There are still four ECDSA verifications for two revelations. CHECKMULTISIG
adds its key-count surcharge to the legacy opcode budget; counting only its
single opcode byte understates the execution cost.

Replacing these exact lists with unconstrained t-of-n checks against the full
T and Q pools is not an equivalent optimization. The two checks can select
different candidate rows. The separate
[cross-pair experiment](../../examples/pointlock_multisig_cross_pair.rs) and
[Core report](multisig_core_check.json) demonstrate that missing binding.
The committed point-lock's ordinary-digest extraction question also remains
open; opcode substitution does not settle it.

## Reproduction and evidence

```sh
cargo run --locked --example pointlock_multisig_probe -- /private/tmp/pointlock-multisig-vectors.json
```

The [generator](../../examples/pointlock_multisig_probe.rs) enumerates every
subset for `n=2..7` and `t=1..min(3,n)`, plus signature/key mismatches,
out-of-range indices, duplicate indices, and descending indices. It performs
local legacy-interpreter checks on every P2SH-sized CHECKSIG configuration and
exports the exact byte vectors for all configurations. The CHECKMULTISIG arm
of the pinned local interpreter is unimplemented; no local interpreter success
is claimed for those opcodes.

Byte measurements are `locally-reproduced`. Compilation uses
`compile_with_policy()` and compiler commit
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`. The local CHECKSIG interpreter is
`702544c9a045ac4fc14846da6da6559e2b7cd9d1`, with `ExecCtx::Legacy` and
`Options::default()`; the lock is input 1 of a two-input, one-output transaction.
The shared tapscript execution helper is not used.

The final Core run passes **235/235 cases: 151 positive and 84 negative**.
It includes all 15 subsets of the 2-of-6 CHECKSIG and per-pair CHECKMULTISIG
layouts, plus mismatched signatures/keys, out-of-range indices, duplicate
indices, and descending indices. Selected fixtures are persisted in
[multisig-vectors.json](multisig-vectors.json); the harness runs with its
default arguments.

Independent transaction validation is recorded by
[the Core harness](multisig_core_check.py) in
[multisig_core_check.json](multisig_core_check.json), using Bitcoin Core 30.3
commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`. Its exact successful P2SH
fixtures are `differentially-validated` and `policy-validated`; the oversized
batch fixtures are only `consensus-validated` as bare scripts and
`consensus-incompatible` as P2SH scripts. Refer to the report's case list for
the independently exercised configurations; generator enumeration alone is
not a Core validation claim. Consensus acceptance checks block inclusion, and
policy acceptance is separately checked with `testmempoolaccept`.
