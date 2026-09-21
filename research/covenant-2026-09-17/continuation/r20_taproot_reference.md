# R20: Taproot's input-script commitment does not bind auxiliary witness data

Date: 2026-09-17. Question: can Taproot SIGHASH_DEFAULT make an auxiliary
legacy/BIP143 reference checker mandatory and enforce shared data, without
presigning or key deletion?

**No such construction was found in this bounded interface search.** The
new concrete result separates two obligations. DEFAULT commits to the spent
scriptPubKeys, but this alone neither restricts a retained-key signer to one
script set nor binds another input's unlocking data to the main input's
reference values. The second failure persists even when the exact intended
auxiliary program really is spent and executed.

Artifacts: [Python](r20_taproot_reference.py),
[deterministic host JSON](r20_taproot_reference.json).
Evidence `locally-reproduced`, deployment `unclassified`. The fixture has a
synthetic funding parent, complete transaction bytes, actual Schnorr and
ECDSA equations, and raw stack replay. It makes no Bitcoin Core or complete
covenant claim. The separate [Core follow-up](r20_taproot_reference_core.md)
records the root agent's funded validation when available; its results are
not presumed by this host report.

## Exact interface being tested

For DEFAULT without ANYONECANPAY, BIP341 includes hashes of all input
outpoints, amounts, serialized spent scriptPubKeys and sequences, together
with the outputs. Its script-path extension commits the current leaf and
CODESEPARATOR position. Other inputs' scriptSigs and witness stacks are not
included. See the pinned
[BIP341 signature format](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0341.mediawiki#common-signature-message)
and [BIP342 extension](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0342.mediawiki).

Thus a fixed valid signature rejects a changed committed script set. It does
not follow that a locking script which permits a fresh signature restricts
that script set. Nor does authenticating the same auxiliary program imply
that it consumed the same alpha, nonce or proof transcript supplied to the
main input.

## A two-input example with both programs actually executed

The deterministic funding transaction has three outputs:

1. 900,000 sats to a Taproot output with the published NUMS internal point
   and exactly one leaf.
2. 50,000 sats to the intended P2SH auxiliary program.
3. 50,000 sats to OP_TRUE, used only for the explicit replacement control.

The Taproot leaf is

```
<alpha0> EQUALVERIFY <xonly(7G)> CHECKSIG
```

The main witness supplies a DEFAULT Schnorr signature and its claimed alpha0.
The public leaf signing scalar is deliberately 7. The internal key is the
NUMS point, so this example does not use a known internal-key/key-path bypass.
It uses the leaf that actually executes.

The auxiliary redeemScript runs three native ECDSA checks on a witness
signature and three supplied public keys. At input index 1, with one output,
legacy SIGHASH_SINGLE returns its constant C=`2^248`. Two short canonical
LOW_S signatures are used:

```
alpha0 = DER(r=2,s=1) || 03,
alpha1 = DER(r=2,s=2) || 03.
```

For each signature, the three witness keys are recovered from three distinct
roots among the four nonce points at x=2 and x=2+n:

```
K_R = (sR - C*G)/2.
```

All supplied keys in each row are distinct compressed keys, and all three
ECDSA equations hold. The 11-byte auxiliary fragment itself does not enforce
distinctness; adding a distinctness requirement would not reject either of
these exhibited rows.

The spending transaction consumes funding outputs 0 and 1 and pays 940,000
sats to one specified recipient. Two actual unlocking variants pass:

* The main leaf consumes alpha0, and the auxiliary consumes alpha0 with its
  valid key row.
* The main leaf still consumes alpha0 with **the exact same Schnorr signature**,
  while the auxiliary consumes alpha1 with its different valid key row.

Both variants spend the same two outpoints and their exact same locking
programs. Both execute the main comparison, the Schnorr check and all three
ECDSA checks. Changing the P2SH scriptSig changes the spending transaction's
txid, but leaves the DEFAULT signature message unchanged. There are six
actual successful ECDSA checks across the two variants; the shared Schnorr
signature passes in both.

This is a diagnostic for shared-data binding. It grants no hash provenance
to alpha and does not treat out-of-range SINGLE as output-binding. The
auxiliary is intentionally small so the missing implication can be tested
without any assumed proof verifier or expensive hash search.

## Program replacement and negative controls

Replacing the auxiliary outpoint with the OP_TRUE sibling changes both the
spent script and the DEFAULT message. The old Schnorr signature rejects,
confirming that the commitment is present and the fixture is not ignoring
it. A fresh signature using the retained public leaf key passes the same
funded main leaf, and the replacement input executes OP_TRUE. No ECDSA
auxiliary program runs in that variant.

Three host negative controls pass:

* Changing the main claimed alpha to alpha1 fails its literal comparison.
* Changing the auxiliary signature but keeping its old three keys fails
  native ECDSA verification.
* Keeping the original DEFAULT signature after replacing the auxiliary input
  fails Schnorr verification.

The failed same-signature replacement and successful different-row reuse
are different facts. DEFAULT binds the former fields and omits the latter.

## Precise conditional obstruction

Fix the non-unlocking transaction fields, spent outputs, main Taproot leaf,
its annex status and its own witness. Suppose an auxiliary output admits two
valid unlocking witnesses with different claimed shared data. Substituting
one auxiliary witness for the other leaves the main input's DEFAULT message
and local execution unchanged. Therefore DEFAULT alone cannot cause the main
input to distinguish those two claims.

This does not exclude auxiliary programs whose every accepting witness
proves the same canonical function of the actual transaction, nor a new
cross-family relation binding that function to the main reference. Such a
relation must be supplied explicitly. The example does not prove that all
multi-input covenants are impossible.

## Dependencies and next acceptance criterion

The diagnostic's generation order is acyclic:

```
fixed alpha0 and programs -> funded scripts -> funding txid -> outpoints
  -> DEFAULT message -> public-key Schnorr signature.

constant C plus chosen alpha -> public auxiliary recovery-key row.
```

The missing edge is not a missing hash in DEFAULT. There is no constraint
from the actual auxiliary row to the main leaf's alpha0. When the auxiliary
program is changed, knowledge of the permitted leaf signing key supplies a
fresh authorization for the new message.

Hardcoding the post-search Schnorr signature or its hash into the leaf would
require a separate setup solution:

```
chosen signature -> leaf/commitment -> funding txid -> native message
  -> valid chosen signature.
```

Taproot commits to the full leaf even when a local CODESEPARATOR is used.
This dependency was already identified in R4; it is not a new impossibility
bound and is not solved by the present fixture.

A falsifiable positive result for this route must provide one fixed main
output and an honest spend, then establish both:

1. Every accepting spend includes an actually consumed auxiliary output
   executing the intended checker, despite all retained signing state.
2. Its accepted semantic data equal the main reference values, either through
   an explicit cross-input binding or a proved unique transaction-derived
   value. Merely executing the same program is insufficient.

The full construction must also constrain the intended outputs and charge
all funding, search and audit work. Neither requirement is established here.

## Raw host boundary measurements

The main Taproot scriptPubKey is 34 bytes; its leaf is **45 bytes**, executes
**2 non-push opcodes**, and has combined stack peak **3**. It consumes
**2 data items, 0 hints**, with **4 complete witness items** totaling
**156 serialized witness bytes**. Its one signature costs 50 validation-budget
units against an available budget of 206.

The auxiliary P2SH scriptPubKey is 23 bytes and its redeem fragment is
**11 bytes**, with **9 non-push opcodes** and fragment peak **5**. It consumes
**4 data items and 0 hints**; the scriptSig has **5 pushes including the
redeemScript**, totaling **124 bytes**. Including the P2SH hash wrapper, the
combined main-plus-alt-stack peak is **6** and non-push operation count is
**11**. It has no witness items; its empty per-input witness vector contributes
one byte to this mixed transaction's witness serialization.

Both two-program variants are **406 bytes / 1,147 weight units**, with
157 witness bytes across the inputs plus the two marker/flag bytes. The
OP_TRUE replacement is **282 bytes / 651 weight units**. Inputs execute
separately, so their stack peaks are not added. All hints coexist at entry
only vacuously: the explicit hint count is zero for every invocation.

These are raw host-vector boundaries, not compiler-policy primitive metrics
or consensus validation. No repository library implementation or field test
was changed.

Reproduce with:

```sh
python3 research/covenant-2026-09-17/continuation/r20_taproot_reference.py
```
