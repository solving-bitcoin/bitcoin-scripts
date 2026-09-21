# R11: a literal native-recovery table within the packed-root frontier

Date: 2026-09-17. Question: can a small public table bind the actual signature
and native transaction digest to an intended output reference within the
remaining R10 legacy opcode budget, including its commitment and funding
chronology?

**The table lookup and native binding fit. Its creation before funding remains
unsolved.** A two-row table combined with the 37-stage numeric root uses 170
counted operations and 487 raw script bytes. Each row authorizes the same exact
ordered output vector, with a different transaction locktime. Three native
ECDSA checks establish membership in the stored reference digest set. A
CODESEPARATOR excludes the whole table from the signature's scriptCode.
Nevertheless, committing the table changes the funding transaction's txid,
which changes the ALL digest from which the table's keys were generated.

This is a concrete native lookup, not a polynomial check on freely supplied
transaction numbers. It isolates a remaining commitment dependency after the
direct table-to-scriptCode dependency has been removed. It is not a general
impossibility theorem for compact verifiers, and no total setup bound below
2^64 has been established.

Evidence: `locally-reproduced`; deployment: `unclassified`. The
[Python](r11_lookup_reference.py) and [JSON](r11_lookup_reference.json) use a
raw host Script model and actual secp256k1 equations/native ALL hash
serialization for the standalone lookup. Combined numeric-root tests mock
CHECKSIG explicitly because no rare DER root was mined. No Bitcoin Core,
repository Script compiler/executor, library change, field-library test, or
primitive metric is involved. Resource counts are raw boundary measurements.

## 1. What a committed row means

A row is four literal stack items, each committed in the locking script:

```
alpha_j, P_j1, P_j2, P_j3.
```

Here alpha_j is a complete 32-byte, strict-DER, LOW_S signature including the
literal ALL flag 01. Each P_ji is a distinct canonical 33-byte compressed
secp256k1 key. For a chosen reference transaction T_j with intended outputs O,
let z_j be its actual ALL digest modulo n. For three distinct nonce roots R_i,
generate publicly

```
P_ji = (s_j R_i - z_j G) / r_j.
```

The row generation and audit check each native ECDSA equation. No signing key
or nonce discrete logarithm is assumed unavailable to the creator. Three
distinct keys require a signature whose r admits all four recovery roots,
including x=r+n. The [R9 three-key certificate](r9_recovery_audit.md) proves
that the same signature verifying under three distinct keys at both z and
z_j forces z=z_j modulo n, including all recovery branches. That result is
the native binding ingredient; no alleged digest supplied by the spender is
used.

The executable chooses r=2 and s=2^183+17, giving a 32-byte signature with all
four roots. This is an easily constructed native-lookup fixture. It is **not**
a found preimage of the R10 numeric root. For any different proposed root,
strict DER, LOW_S, the ALL flag, three usable recovery keys, and root witness
availability remain generation/audit obligations.

The script compares its actual computed alpha bytes with the selected literal
alpha_j before checking the three literal keys. This byte comparison matters:
recovery keys generated for some other signature do not establish the theorem's
premise. Key uniqueness and canonical encoding need no witness-time checks
here because the deposited literal table is audited. A depositor must reject
a table containing repeated or invalid keys.

## 2. A complete flat lookup and native suffix

At the lookup boundary the main stack is exactly `[alpha, j]`. The complete
combined numeric-root prefix enforces entry depth. A standalone lookup adds
its own `DEPTH 2 EQUALVERIFY`.

The lookup performs these operations:

1. Require `0 <= j < M`, using WITHIN and VERIFY with four-byte ScriptNum reads.
2. Compute `K=4j+3`, save it on altstack, and push all literal rows in reverse
   order so row zero is the top four-item group.
3. Retrieve K. Repeat `DUP TOALTSTACK ROLL FROMALTSTACK` three times and finish
   with ROLL. This extracts alpha_j, P_j1, P_j2, P_j3 in that order, leaving
   the unused table items below them.
4. `<4M> ROLL <4> PICK EQUALVERIFY` compares actual alpha with alpha_j.
5. Execute CODESEPARATOR and the following fixed suffix:

```
3 PICK SWAP CHECKSIGVERIFY
2 PICK SWAP CHECKSIGVERIFY
CHECKSIG
TOALTSTACK
2DROP repeated (2M-2) times
FROMALTSTACK
```

The suffix checks alpha_j under P_j3, P_j2, and P_j1, then removes every unused
row item and leaves one boolean with empty altstack. For M=2 its raw bytes are
`53797cad52797cadac6b6d6d6c`. All three native checks use this same suffix;
there is no signature literal or later CODESEPARATOR inside it, so legacy
signature FindAndDelete and separator removal do not change it.

Thus the table contents do **not** affect scriptCode. The native digest still
commits to the current input's funding outpoint and the exact ordered outputs.
The witness's small j only selects a row; it is not assumed to be a native
transaction field. Actual CHECKSIG results establish native membership.

## 3. Reproduced results and exact resource frontier

The two native fixture transactions spend the same synthetic outpoint, have
locktimes zero and one, and share these exact ordered outputs:

```
400000 sat -> script 51
590000 sat -> script 52.
```

The input sequence is final. Both selected rows pass all three actual ECDSA
equations and finish with a clean stack. Ten negative cases reject: the wrong
row, changed output amount, changed output order, changed output script,
negative/out-of-range/oversized index, different actual alpha, and extra or
missing entry item. The standalone script is **318 bytes, 40 counted ops,
2 entry data items, 0 hints, peak 11**. Its unlocking data needs 34 scriptSig
bytes. If packaged as P2SH, the redeem push adds 321 bytes, so the scriptSig
would be 355 bytes and contain three pushes including the redeem script.
The outpoint is synthetic; this is no funded-spend or relay-policy claim.

For n root stages, the combined prefix saves j and q, executes the existing
numeric root, checks `x=16q+7`, and restores j. It uses `3n+21` ops. The lookup
fragment uses `34+2M`, including table cleanup and CODESEPARATOR. Total:

```
counted_ops = 3n+55+2M.
```

At n=37, exact raw sizes are `213+137M` for M=1..4, `214+137M` for M=5..16,
and `215+137M` for M=17..31. Every row contributes 135 pushed literal bytes;
the extra two bytes per row come from unused-row cleanup. Small-integer push
encoding accounts for the two fixed-size transitions.

| Rows M | Raw script bytes | Counted ops | Combined stack peak bound | P2SH 520-byte element bound |
| ---: | ---: | ---: | ---: | --- |
| 1 | 350 | 168 | 42 | fits |
| 2 | 487 | 170 | 42 | fits |
| 3 | 624 | 172 | 42 | exceeds |
| 8 | 1310 | 182 | 42 | exceeds |
| 17 | 2544 | 200 | 71 | exceeds |
| 18 | 2681 | 202 | 75 | exceeds |

M=17 fits the numerical bare-legacy limits with clean stack; M=18 exceeds
201 counted ops. These are resource statements, not consensus validation.
The table replaces the R10 unbound affine checker and free-key gates; the
literal recovery-key commitment makes a separate H(P) DER pin unnecessary
for this particular membership predicate. Consequently R10's `N L p^2`
formula must not be applied unchanged to this different gate.

There are **39 entry data items** at the redeem-script boundary: 36 path
selectors, x, packing hint q, and row index j. The hint count is **37**
(36 path + 1 packing); all coexist at entry. Incremental lookup hints are
zero; j is a lookup operand. The table's 4M literal items are introduced by
the script, not supplied as witness hints. Peak main-plus-alt stack is
`max(42,4M+3)` for the displayed n=37 configurations. Including the redeem
script, a P2SH unlocking script contains 40 push items. No SegWit witness is
used; serialized witness bytes are zero.

For M=2, the unmined combined layout's unlocking data takes 39..47 scriptSig
bytes, of which 37..41 are serialized hint pushes. The 487-byte redeem script
adds a 490-byte PUSHDATA2 push: total scriptSig 529..537 bytes, excluding its
outer CompactSize length. Those bounds describe a witness shape, not an
existing valid rare-root spend.

Twenty-one structural vectors run the real hash routing and stack operations
at the packing domain endpoints and zero, with 1, 2, 17, and 18 rows. Their
signature checks are explicitly mocked to check byte/key routing only. The
M=18 case is measured despite its excessive opcode count, without a claim
that such a script would run under consensus rules.

## 4. Funding chronology: the precise remaining dependency

With a fixed native outpoint F, generating M reference rows is cheap: M ALL
hashes and O(M) public curve operations. For a common alpha, three sR_i/r
points can be shared; each new reference digest needs a scalar multiple
z_j G/r and three point subtractions. The persistent table occupies 135M
literal script bytes and O(M) host memory. No exponential table is hidden.

But F must be the transaction that commits this table. Let C be the fixed
suffix above and let S(table) be the full redeem script. The required public
construction must satisfy

```
F = funding_transaction(P2SH(S(table)))
z_j = ALL(spend(outpoint=txid(F), outputs=O, locktime=j), C) mod n
P_ji = (s_j R_i - z_j G) / r_j.
```

The table is needed to determine F; F is needed to determine the table. This
dependency is still present after excluding the table from C. The root x or
its path blinding does not supply a way to compute an authenticated later
table without changing the commitment.

The executable fills a table using a proposed synthetic outpoint, constructs
a concrete serialized funding transaction paying its P2SH hash, and then
recomputes the actual spend digest. The resulting txid and digest differ,
and the stale table rejects. Rebuilding the table for that new outpoint
changes the next funding txid again. Three successive steps reproduce this
failure. These are deterministic dependency witnesses, **not a proof that
every possible fixed-point search fails** or a generic curve lower bound.

Conversely, if the table is allowed to be replaced without its commitment,
the same fixed outpoint cheaply accepts a newly recovered row for a different
output script. The executable reproduces that replacement. Moving the table
to uncommitted witness data therefore removes the very binding the lookup
was intended to add. A table hash or Merkle root fixed in the funding script
retains the funding dependency; the numeric seed commitment does not
automatically authenticate such a separate object.

The permitted depositor audit after the full funding transaction is known
can verify a proposed solution to these equations. It does not itself provide
an algorithm for generating one. No amount of cheap post-funding row
generation can be counted as precommitted setup without addressing this
dependency.

The next falsifiable acceptance criterion is an acyclic public procedure, or
a fully charged search below 2^64, that produces one concrete funding
transaction and table satisfying these equations while every row retains the
same exact intended output vector. Only then should this boundary be sent to
Core as an actual funded-spend candidate. No such procedure is supplied here.

Reproduce with:

```
python3 research/covenant-2026-09-17/continuation/r11_lookup_reference.py
```

The packed root comes from [R9](r9_numeric_root.md), its finite domain and
packing checks from [R10](r10_parameter_frontier.md), and its independent
arithmetic/layout audit from [r10_frontier_audit.json](r10_frontier_audit.json).
Their finite root enumeration is not a proof that the presently unmined
combined native table can be generated under the total-work bound.
