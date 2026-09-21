# A known-digest filter locks a prescribed nonce point

Question: can the correlated targets `A, B, A+B, A-B` of the
[DH quartet](dh-quartet-labels.md) receive native scalar openings without
storing a target and a separate companion key for every candidate?

**Yes, at the small legacy-script boundary.** Three checks under the known
key `G` force the legacy SINGLE-bug digest, unless the spender finds a
collision between distinct sighash preimages reduced modulo the curve order.
A fourth check under one publicly derived key then fixes the nonce point.
The resulting signature reveals the target scalar. No setup proof, adaptor
exchange or signature hash commitment is used.

This supplies a native adapter for the quartet. It does **not** meet the
full publication goal: the explicit candidate-key table alone exceeds
100,000 legacy vB, and publicly binding a composable garbled verifier remains
open. There is no full-instance setup benchmark or payment authorization in
this experiment.

[Rust generator](../../examples/pointlock_fixed_digest_nonce_probe.rs),
[native harness](fixed_digest_nonce_core_check.py),
[Core report](fixed-digest-nonce-core.json),
[host report](fixed-digest-nonce-host.json),
[independent Rust checks](../../tests/pointlock_fixed_digest_nonce_vectors.rs).

## Public setup and honest opening

Use secp256k1 field modulus `p`, group order `n` and generator `G`. The actual
32-byte legacy SINGLE-bug digest is `01` followed by 31 zero bytes. ECDSA
interprets these bytes as the scalar `C=2^248`, not the scalar one.

Given a finite public target `T=tG`, let `r0=x(T)` as a field integer and derive

```text
d = -2C/r0 - 1 mod n
P = dG.
```

Public validation requires `p-n < r0 < n` and `d` different from zero and one.
The reference also requires `bit_length(r0) >= 144`, which is a sufficient
completeness condition for the length guard below. It is not a claim of a
minimal threshold. Selection tables reject repeated x-coordinates, including
the alias pair `T,-T`. Their associated scalar openings would reveal each other.
The quartet additionally uses its existing public input-relation and
output-label-separation checks.

An honest opening computes

```text
r = r0
s = (C+r0)/t mod n
sigma = strict_DER(r,s) || 0x03.
```

Replacing `s` by `n-s` leaves a valid signature and reverses the nonce point.
Use a representation longer than 57 bytes. For every accepted target the
high-S representation satisfies that length; low-S is also usable when long
enough. `d != 1` excludes `r0=-C`, so this construction does not generate `s=0`.
These are modular arithmetic and ordinary point multiplication, with no
nonce search. Knowing the public scalar `d` does not supply a nonce with the
prescribed x-coordinate.

## Script and extraction argument

The complete single-target redeem script is 86 bytes after the repository
compilation policy. Its initial stack consists of exactly one signature.

```text
OP_DEPTH OP_1 OP_EQUALVERIFY
OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
<G>
OP_2DUP OP_CHECKSIGVERIFY OP_CODESEPARATOR
OP_2DUP OP_CHECKSIGVERIFY OP_CODESEPARATOR
OP_2DUP OP_CHECKSIGVERIFY OP_DROP
<P> OP_CHECKSIG
```

For strict DER, the signature item has `7 + len(r_DER) + len(s_DER)` bytes,
including the sighash byte. If `r <= p-n`, the first integer takes at most
17 bytes and the second at most 33, so the item is at most 57 bytes. The guard
therefore forces `r > p-n`. There can be only two curve points with
`x mod n = r`, namely `R` and `-R`; the second possible field coordinate
`r+n` is outside the field.

For each of the first three checks, ECDSA reconstructs

```text
R_j = s^-1 (z_j+r)G.
```

Three accepted checks choose three points from a two-element set. Two points
are equal, hence their reduced digests `z_j` are equal. In an ordinary legacy
spend, their sighash preimages are nevertheless different: the three
executed CODESEPARATOR positions produce distinct scriptCode suffixes.
All explicit data pushes are shorter than the accepted signature, so
FindAndDelete cannot remove its push at an opcode boundary. The same raw
sighash byte is used for all four checks, including noncanonical values.
ANYONECANPAY and the legacy base modes preserve the scriptCode distinction.

Thus an ordinary accepted spend supplies a collision of distinct preimages
under the legacy double-SHA256 digest reduced modulo `n`. Otherwise all three
checks must be on the out-of-range SINGLE branch, where all digests equal
`C`. The bug condition depends on the input index, output count and raw
sighash byte, so it cannot hold for only some of these checks.

The third `G` check and the `P` check share the final scriptCode and digest.
Their reconstructed nonce points cannot be equal because `P != G`. They
must be opposite. Consequently

```text
2C + r(1+d) = 0 mod n
r = r0.
```

The known private scalar of `G` now gives

```text
k = (C+r0)/s mod n
kG = T or -T.
```

Check the public target and negate `k` when required. The result is exactly
its prebound scalar `t`. This extraction uses public transaction/signature
data; retained setup secrets are unnecessary.

This is an extraction argument conditional on reduced-sighash collision
resistance, not a proof obtained by testing samples. A generic 128-bit
collision target is a design estimate, not an independently audited bound
for these structured inputs. Pre-opening scalar hiding additionally depends
on the target's discrete log being unknown. Public shape checks cannot
certify entropy or prevent deliberate disclosure by its creator.

The argument conditions on execution of the checked redeem script. P2SH
also needs binding of its HASH160 script commitment. In the malicious
creator model, generic chosen-pair script collisions have an approximately
80-bit birthday bound; the curve/hash extraction argument alone does not
give the complete P2SH construction a 128-bit binding claim. A hash of a
signature is not used here.

## Selecting the four correlated targets

The reference derives one key `P_i` for each of
`T_i = A, B, A+B, A-B`. A binary branch selects that key and saves it on
the alt stack before the common known-key checks:

```text
# Entry: sigma, low_bit, high_bit
OP_DEPTH OP_3 OP_EQUALVERIFY
OP_IF
    OP_IF <P3> OP_ELSE <P2> OP_ENDIF
OP_ELSE
    OP_IF <P1> OP_ELSE <P0> OP_ENDIF
OP_ENDIF
OP_TOALTSTACK
OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
<G>
OP_2DUP OP_CHECKSIGVERIFY OP_CODESEPARATOR
OP_2DUP OP_CHECKSIGVERIFY OP_CODESEPARATOR
OP_2DUP OP_CHECKSIGVERIFY OP_DROP
OP_FROMALTSTACK OP_CHECKSIG
```

The policy-produced redeem script is 199 bytes. The selector operands are
interpreted by Script truthiness; the selected branch gives the unique index.
Its target scalar is extracted as above. The host evaluator then computes
the quartet's two prescribed secret point labels. The points themselves,
not their discrete logs, are the output labels at that separate interface.
Public setup checking must compare all derived keys and the exact serialized
script with the funded commitment.

Unlike the existing [three-check lock](../../src/signatures/pointlocks/three_check/README.md),
this arrangement shares `G` and stores only one derived key per candidate.
It uses four checks and generally longer signatures. The three-check lock
stores the target plus a companion and uses a small known nonce. Neither
tradeoff changes the other construction's measured results or assumptions.

## Native evidence and resource boundary

Evidence for the small transaction cases is **differentially-validated**;
deployment is **consensus-validated**. Algebraic claims are **inspected**.
The harness uses Bitcoin Core 30.3 commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`, in a temporary regtest with wallet
and external networking disabled. It mines the funding transaction, tests
each spend against mempool policy and submits it through block validation.
No consensus resource limit is disabled. The custom host trace is a narrow
instrumentation aid; consensus validity comes from Core.

The primary execution rules are pinned in Core's
[interpreter.cpp](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp):
strict DER length checks, opcode-boundary FindAndDelete, CODESEPARATOR handling
and the legacy SINGLE return value.

There are 23 positive cases: four targets, each with low/high-S signatures
in standalone and quartet scripts, plus seven additional raw SINGLE flag
bytes. Eight negative cases cover wrong selection, changed `s`, a 57-byte
item, a non-bug input index, an extra output, an extra entry item, a missing
hint, and a freshly signed ordinary ALL signature. That last signature
succeeds at the first check under `G` and fails at the second context.
All expected consensus outcomes reproduce.

The separate Rust test independently deserializes and reserializes every
recorded spend, checks its txid and weight, recomputes 101 native sighashes
using rust-bitcoin and verifies their ECDSA outcomes with libsecp256k1. It
also checks that all 23 extracted scalars reproduce the public target points.
The host-only screen tries all 256 raw sighash bytes for one fixed opening;
exactly the eight bytes with `(flag & 31) == 3` accept. This screen is not
256 additional Core cases or a general extraction proof.

| Measured boundary | Standalone | 1-of-4 quartet |
| --- | ---: | ---: |
| Redeem-script bytes | 86 | 199 |
| Signature-item bytes across positive fixtures | 71–73 | 71–73 |
| Complete scriptSig bytes | 160–162 | 275–277 |
| Required auxiliary hint items | 0 | 2 |
| Initial data items, all coexisting | 1 | 3 |
| scriptSig pushes including redeem script | 2 | 4 |
| Combined main-plus-alt-stack peak | 4 | 5 |
| Processed non-push operations | 15 | 26 |
| Static non-push operations | 15 | 26 |
| ECDSA checks | 4 | 4 |
| Complete small spend weight | 1,138–1,146 WU | 1,606–1,614 WU |
| Complete small spend vsize | 285–287 vB | 402–404 vB |

Processed counts include flow-control operations in skipped branches. Each
locked legacy input has no witness items. Each fixture transaction has a
separate helper input with one witness item: the whole transaction's witness
serialization is four bytes, plus the two-byte marker/flag. The spend has
two inputs and one P2WPKH output; it supplies no independent owner signature.
Tapscript validation budget is N/A. Scripts are optimized through
`compile_with_policy()` below its 32-KiB cutoff; report metadata pins the
compiler, interpreter and source files.

All positive spends fail default relay policy. Executed legacy CODESEPARATOR
violates CONST_SCRIPTCODE; high-S and undefined sighash bytes can add policy
reasons. P2WSH has no constant SINGLE-bug digest and is not a drop-in wrapper.
Tapscript does not execute these ECDSA checks.

The recorded 2,421-vB funding transaction funds all 31 independent test
cases together. It is test infrastructure, not a complete 256-byte
publication. Its output creation costs must not be silently dropped from
any future full construction.

## Why this arrangement still exceeds the goal

One quartet carries two message bits. Using 1,024 independent copies covers
all 2^2048 messages but includes the following legacy costs:

```text
four explicit compressed-key pushes per quartet:
1024 * 4 * 34 = 139264 vB

whole measured redeem scripts, before even their push prefixes:
1024 * 199 = 203776 vB.
```

These restricted byte floors alone exceed 100,000 vB. Granting an ideal
HASH160 lookup instead, four 21-byte hash pushes plus one supplied 34-byte
key push per quartet already cost `1024*(4*21+34)=120832` legacy vB.
All three bounds omit signatures, selectors, authorization, output creation
and consumption, and transaction framing. They apply to these explicit
independent-table layouts, not every possible pointlock construction.
The scoped [negative-result record](../../knowledge/negative-results/explicit-dh-quartet-tables.md)
preserves this boundary independently of the positive native adapter.

At that hypothetical one-quartet-per-input boundary there would be 2,048
hint items and 3,072 data-entry items across 1,024 separate stacks, with
4,096 scriptSig pushes including redeem scripts. Each individual measured
quartet has peak five. This is not a measurement of a composed full-message
transaction; changing batching or table representation requires new resource
accounting rather than placing those items together on one stack.

The wrapper therefore closes one native-delivery question and identifies
where this layout fails. A successful continuation must change the table or
label interface and still provide a publicly bound verifier, exact complete
transactions, participation/authorization rules and a full setup benchmark.

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/fixed_digest_nonce_core_check.py --host-only
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/fixed_digest_nonce_core_check.py
cargo test --locked --test pointlock_fixed_digest_nonce_vectors
python3 tools/kb.py validate
```
