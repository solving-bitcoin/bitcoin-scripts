# R8: duplicate-signature multisig binds a digest-scaled nonce portfolio

Date: 2026-09-17. Question: can native legacy/P2WSH checks authenticate the
selected public nonce from R7's portfolio, beyond a signature-size condition,
while preserving a cheap known witness and a mandatory output reference?

The concrete candidate is **one signature duplicated into 2-of-m
CHECKMULTISIG under distinct fixed public keys**. It is small: 23 counted
opcodes for m=20. It imposes an exact native relation, but its nonce portfolio
scales with the unknown transaction digest. Restricting it to the supplied
known nonces changes the cheap R6 interval search into a full scalar match.
Allowing the keys to vary restores cheap signing for every output list.

This is a scoped result for this candidate and its shared-signature context
extension. It does not prove a general nonce-binding impossibility.

Evidence is `locally-reproduced`, deployment `unclassified`. The experiment
checks actual secp256k1 equations and a small raw-fragment stack model, not
Bitcoin Core or the repository's Script executor. No field-library tests or
primitive changes ran. Constructed scalar digests and actual synthetic
transaction sighashes are explicitly distinguished below.

## 1. An executable-shaped native candidate

For distinct, fixed compressed points `P_i=d_i G`, use:

```
# Entry: sigma
0 SWAP DUP 2 <P_0> ... <P_(m−1)> <m> CHECKMULTISIG
```

Both signature arguments are the exact same stack item, so r, s and the
sighash byte coincide. CHECKMULTISIG advances past each matching key; with
distinct group points it cannot satisfy the duplicate signature twice under
the same key. Its two matches therefore correspond to a selected pair i,j.
There is no witness promise about which r was used.

The source of these native behaviors and the m-key opcode surcharge is the
pinned [Core 30.3 interpreter](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp).
Both matches use the same signature hash in either legacy or P2WSH execution.
Legacy FindAndDelete removes the same duplicated item; P2WSH does not use
that deletion rule. Neither behavior parses r into a Script number.

For m<=16, raw size is `34m+6` bytes; for 17<=m<=20 it is `34m+7`.
Counted opcodes are `m+3`, including CHECKMULTISIG's public-key surcharge.
The fragment has one entry signature data item, **zero auxiliary hint
items**, no altstack, and combined peak `m+5`.

At m=20 this is **687 raw bytes, 23 counted opcodes, peak 25**. The 687-byte
script cannot be a P2SH redeem-script stack item because it exceeds 520
bytes; it could instead be a bare script or P2WSH script subject to their
other rules. At m=15, the raw script is 516 bytes and the redeem-script size
obstacle disappears. No actual funded spend for these fixed-key scripts is
claimed, so the latter possibilities remain `unclassified`.

These are raw boundary-fixture counts, not policy-compiled library metrics.
Input pushes, transaction serialization and wrapper checks are not included
in the fixed-key fragment figures.

## 2. Exact relation and the known-witness obstacle

Let `R_i=(zG+rP_i)/s` and `R_j=(zG+rP_j)/s` be the recovered nonce points.
First consider the usual two-root case: r has only one allowable field
x-coordinate, so the possible points are R and −R. Distinct keys give
distinct recovered points; they must be negatives. Thus

```
r(P_i+P_j) = −2zG,
r = −2z / (d_i+d_j) mod n.                 (1)
```

Pairs with `d_i+d_j=0` cannot accept nonzero z in this two-root case. For all
other pairs the condition binds r to **a multiple of the actual digest**, not
to the desired fixed values `x(k_l G)`.

With m fixed keys there are at most `B=m(m−1)/2` such multiples. The fixture
uses `d_i=2^i` for i=0,...,19, whose 190 pair sums are all distinct. For four
known nonce scalars, including `k=1/2 mod n`, it constructs z by (1) for
three selected pairs and computes

```
s = (z+r*d_i)/k mod n,
s <- min(s,n−s).
```

All **12** scalar-level cases satisfy both actual ECDSA equations and the
stack model. These z values are deliberately constructed field scalars,
**not mined transaction digests**. This establishes completeness of the
algebraic family without pretending to solve its native hash constraint.

For a fixed desired nonce r_l, (1) instead requires

```
z = −r_l*(d_i+d_j)/2 mod n.                (2)
```

The right side is an exact scalar target. The R6 four-interval strategy could
vary s for almost arbitrary digest values until the signature was short;
this extra multisig condition removes that freedom. Public knowledge of d_i
does not provide the discrete logarithm of a point whose x-coordinate was
set by an arbitrary observed z through (1).

For an explicit preprocessed portfolio of K known nonces and fixed keys,
there are at most BK target scalars in (2). In the ideal uniform 256-bit hash
model each scalar has at most two raw-digest representatives, giving the
union bound `success <= 2*B*K*Q / 2^256` for Q native hashes. If K construction
or audit and Q both count, relaxing `K+Q<W` yields
`success <= B*W^2 / 2^257`. For B=190 and W<2^64 this is below `2^-121.43`.
This is a bound on the explicitly described fixed-table hash-search strategy,
not on every adaptive group algorithm or choice of setup. Setup keys chosen
to exploit a hash are not silently independent of that hash; their funding
dependency still needs solving.

### Recovery exceptions are not suppressed

If `r+n < p_curve`, a second field x-coordinate can lift. Distinct recovered
points need not be negatives, so (1) need not hold. The script itself does
not exclude this case. The 12 fixtures explicitly use `r > p_curve−n`,
including the special G/2 nonce, so their two-root inference is exact.
The displayed known-portfolio barrier applies to that stated family.
Cross-branch constructions involving very small r remain outside it.

Three or four duplicate signatures under distinct keys can force use of the
larger recovery set, but do not make the required nonce logarithms available.
This is why adding more required matches is not asserted to fix the problem.

## 3. Cheap witness keys permit public replay for every output list

Move two public keys into the witness to make (1) easy to satisfy. The
following complete raw predicate also checks their byte encodings differ:

```
# Entry: sigma P_1 P_2
2DUP EQUAL NOT VERIFY
TOALTSTACK TOALTSTACK
0 SWAP DUP 2 FROMALTSTACK FROMALTSTACK 2 CHECKMULTISIG
```

Its raw hex is `6e8791696b6b007c76526c6c52ae`. For any actual z and any chosen
known nonce k with nonzero r, set

```
d_1 = 1,
d_2 = −2z/r − 1 mod n,
s = (z+r)/k mod n.
```

Outside degenerate zero/equal-key cases, the duplicate signature verifies
under both public keys. There is no hash search. Low-S normalization keeps
the same pair valid. The constructor does not use secret data and the creator
can retain every value.

The fixture fixes that script and one synthetic funding outpoint, then forms
two actual legacy ALL preimages whose recipient scripts differ. For each it
constructs witnesses using k=1/2,1,3,5. All **eight** cases satisfy the native
ECDSA equations and the stack model; changing the digest while retaining a
witness rejects all eight. Thus the individual ALL signatures bind their
transactions, while fresh witness keys re-enable every alternate output at
the same cost. Merely choosing ALL here is not an on-chain flag guard.

Metrics for this complete predicate: **14 raw bytes, 13 counted opcodes,
3 entry data items, 0 hints, combined peak 7**, empty altstack at completion,
one true final item. All three data items coexist at entry; no streaming or
hidden extra hint vector is assumed. The JSON records each complete synthetic
transaction, its scriptSig bytes, zero serialized witness bytes and weight.
The G/2 cases have 144-byte scriptSigs and 904 WU; other nonce signatures have
different DER widths. There is no Core consensus or policy claim.

## 4. Context splitting and complete-signature commitments

Reusing the same signature in a second context with another selected fixed
pair gives, in the same two-root family,

```
r*C_A = −2z_A,     r*C_B = −2z_B,
C_B*z_A = C_A*z_B.
```

Pair selection supplies at most B^2 ratios. It still imposes a full related
digest equality; it does not expose a fixed selected nonce while leaving s
free. When the desired nonce is known and fixed, each digest is separately
fixed by its chosen pair. CODESEPARATOR does not change the signature's
sighash byte or the input/output counts: one duplicated item cannot select
the legacy SINGLE bug in one context and ALL in the other. If the same
input's SINGLE bug applies, both contexts have the constant digest and bind
no output contents. P2WSH lacks that legacy constant-digest shortcut.

A hash commitment to the **whole** signature really can fix r. It also fixes
s and the flag. With a fixed public key, one committed signature permits at
most four digest scalars, corresponding to the full recovery-point set; for
the two-root nonce family there are at most two. A public table of M such
signatures gives at most 4M scalar targets before further restrictions. This
does not restore a freely variable s for the known-nonce length oracle.
Allowing a variable hash-as-signature root instead means its r is variable
again unless an additional checked relation supplies the nonce binding.

Embedding adapted keys or signature commitments after learning the actual
ALL digest changes the funding script, then the funding txid, then that
digest. The pre-funding audit allowance does not erase this dependency.
Leaving them free avoids that loop but gives the explicit replay above.

## Conclusion of the bounded attempt

The duplicate-signature portfolio is a compact native relation worth keeping
separate from mere OP_SIZE. It does not supply the required fixed nonce
selection for the R7 different-slope fingerprint: fixed keys impose full
digest/nonce matching, while free keys work equally for unauthorized outputs.
The four-root exception, new native byte relations, and different known-nonce
solvers remain outside this negative result. No covenant or greater-work
claim for unauthorized outputs was established.

Reproduce with `python3 research/covenant-2026-09-17/continuation/r8_nonce_binding.py`.
