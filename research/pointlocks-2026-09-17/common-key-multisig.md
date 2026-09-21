# Common-key multisig point-lock pools

This construction uses the same public verification key `G` for every point
lock. It removes the signature-hash commitment and the per-candidate companion
key. The objective is complete funding-plus-assertion transaction bytes for a
recoverable 256-byte message. It changes how candidate target points are
created; it is not a drop-in signer for arbitrary pre-existing targets.

## Algebra

Let `C` be the scalar represented by the native legacy SINGLE-bug digest and
`n` the secp256k1 group order. For each candidate, privately choose a fresh nonce
`k_i` and compute:

```
r_i = x(k_i G) mod n
s_i = (C + r_i) / k_i mod n
t_i = -2 C / r_i mod n
T_i = t_i G
P_i = T_i - G
```

The ECDSA signature `(r_i,s_i)` verifies under both `G` and `P_i` on digest `C`.
Publish `T_i`/`P_i` during setup, keep the nonce, scalar and signature secret,
and reveal the signature to reveal the selected scalar. Anyone can verify the
public relation `T_i=P_i+G` before funding. Exclude `P_i=G`, `P_i=-G`, duplicate
candidate points, zero signature scalars, and dependent candidate secrets.
No ZKP or interactive setup is introduced.

For *any actual digest* `z`, a signature passing both key checks and the `>57`
length guard has opposite reconstructed nonce points. Consequently:

```
zG + rP_i = -(zG + rG)
r(P_i + G) = -2zG
log_G(T_i) = -2z / r mod n
```

The observer obtains `z` from the actual spending transaction and the signature
sighash byte. The private scalar of the common key `G` is publicly known; the
extracted secret is the scalar of the **sum** `P_i+G`, not of either recovery key
separately. See the independent [sum-lock experiment](../../examples/pointlock_sum_probe.rs)
for algebra and native-hash checks.

## Threshold verifier

The best measured native-multisig layout is:

```
# Initial stack: empty_dummy sigma_1 ... sigma_t
# Copy the complete signature list to altstack, checking SIZE > 57 for each.
<t> <P_1> ... <P_n> <n> CHECKMULTISIGVERIFY
# Restore the same signatures, with a new empty dummy.
<t> <G> DUP ... DUP <t> CHECKMULTISIG
```

The second operation is exactly `t-of-t` with repeated `G`; every copied
signature must verify under `G`. The first matches those same signatures
against distinct slots in the candidate table. With the length guard, one
signature has at most two recovery keys. Since one is `G` and no candidate
key is `G`, it can match at most one distinct candidate key. This establishes
the pair binding that was absent from unrestricted multisig over unrelated
`T_i` and `Q_i` arrays.

All signatures are checked with the same scriptCode. There is no
CODESEPARATOR and the script contains only 33-byte key pushes and small
integers, so a signature item of more than 57 bytes has no signature push to
remove. The two multisig operations also receive exactly the same signature
list. Each signature may have its own actual sighash byte; its two key checks
still use the same digest.

## Measured compiled sizes

The deterministic fixture generator selects low-S, **71-byte** signatures,
including the sighash byte. It tries a fresh nonce until DER uses a 32-byte
positive `r` without a sign-padding byte and 32-byte `s`. This costs roughly
two nonce trials per candidate. It is a modest serialization optimization,
not an exponential search or a reduction of the target secret to a small
integer range.

| Threshold | Redeem bytes | scriptSig bytes | Static non-push ops | Charged legacy ops | Static sigops | Entry items |
|---|---:|---:|---:|---:|---:|---:|
| 3 of 12 | 476 | 696 | 22 | 37 | 15 | 4 |
| 4 of 11 | 451 | 743 | 28 | 43 | 15 | 5 |
| 5 of 10 | 427 | 791 | 35 | 50 | 15 | 6 |

The scriptSig contains one empty dummy, `t` signature pushes, and the
PUSHDATA2 redeem-script push: `redeem_bytes + 4 + 72*t`. Its CompactSize
length, outpoint, sequence, funding output, and transaction framing are not
included in this column. Each pool requires **zero auxiliary hint items**;
the complete data-item count is `t+1`, including the mandatory multisig dummy.
All items coexist at script entry. Analytical combined main-plus-alt stack
peaks are `n+2t+3`: 21, 22, and 23 items for the three rows respectively.
These peaks have not yet been instrumented in a local CHECKMULTISIG interpreter.

An alternative checks each signature against the common `G` using CHECKSIG,
then runs just one threshold CHECKMULTISIG over the candidate keys. Its
3-of-12, 4-of-11 and 5-of-10 redeem scripts are respectively 480, 458 and
436 bytes, and scriptSigs 700, 750 and 800 bytes. Thus the two-multisig layout
is smaller in each of those representative cases. Both charge `n+t` static
sigops; all representative rows reach the 15-sigop P2SH policy limit.

These are legacy inputs: their ECDSA data and redeem scripts receive no
witness discount. A mixed SegWit transaction additionally serializes a one-byte
empty witness vector for each such input. The complete economic comparison,
including the outputs that create the pools and all inputs that consume them,
belongs in [the encoding study](encoding-optimization.md).

## Reproduction and validation boundary

```sh
cargo run --locked --example pointlock_common_key_probe
```

[Source](../../examples/pointlock_common_key_probe.rs) generates candidates
from SHA256 of `pointlock-common-key-{index}-{counter}`, retaining 71-byte
signatures, and compiles every script through `compile_with_policy()`. It
compares both verifier layouts for candidate counts 2–14 and thresholds below
8. It emits [138 complete Core-harness vectors](common-key-vectors.json):
representative first/last subsets and failures for a nonempty dummy, duplicate
signature, signature outside the table, a 57-byte signature, an incorrect
sighash byte, and incorrect signature ordering.

Compiler: `bitcoin-script` `124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`.
The generator reads this identity from embedded Cargo.lock provenance.
Byte sizes and off-chain ECDSA checks are **locally-reproduced**. The exact
138 fixed-pool fixtures were independently checked by Bitcoin Core 30.3,
commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`: all **102 positive**
transactions passed consensus and default mempool policy, and all **36 negative**
transactions were rejected as expected. See the
[Core report](common_key_core_check.json). Its extra 139th case is a separate
regression for an earlier unsound cross-pair shortcut, not part of this
construction. The report records the exact vector-file SHA256, and it matches
the current artifact. Evidence for these six fixed-pool configurations is
**differentially-validated**, deployment class **policy-validated**.

The pinned local `bitcoin-scriptexec` Legacy CHECKMULTISIG arm is unimplemented,
so this experiment does not pretend its multisig scripts passed that
interpreter. Unexecuted configurations in the broader compiled parameter
matrix retain deployment class **unclassified**. The single-lock algebra
experiment and full-transaction Core execution have separate evidence boundaries.

The small nonce-selection optimization is optional. Arbitrary supplied targets
need the more general sum-lock setup and do not automatically permit the same
common-key table. Neither the compiled-size search nor its economic comparison
proves global optimality.

## Variable threshold without padding

A second prototype allows one through `k` signatures against the same
candidate pool. The initial stack depth supplies the actual threshold `t`:
there is no count hint. The script verifies that `1 <= t <= k`, checks each
signature against `G`, and uses `t` as the threshold of one CHECKMULTISIG over
the candidate keys. Small altstack flags control restoration of only the
signatures that were supplied. There are no padded signature or key items.

For the measured `n=5..13`, `k=2..6` domain, the exact compiled sizes are:

```
redeem bytes = 34*n + 24*k + 44
scriptSig bytes = redeem bytes + 4 + 72*t
static non-push ops = 18*k + 7
charged legacy ops = 18*k + 7 + n
static sigops = n + k
```

The scriptSig formula applies when the redeem script exceeds 255 bytes, as all
listed configurations do. Examples fitting the 520-byte and 15-sigop limits
include 1–4 of 11 (514-byte redeem), 1–5 of 10 (504 bytes), and 1–6 of 9
(494 bytes). Each invocation requires **zero hints and `t+1` complete entry
items**, consisting of its actual signatures and the empty multisig dummy.
All entry data coexist. An analytical combined-stack upper bound is
`max(2*t+4, t+k+4, t+n+3)`; no measured local stack peak is claimed.

This variable-cardinality construction is **not sufficient for standalone
publication**. A third party can remove an optional valid signature, lower the
runtime threshold, and leave the P2TR helper signature unchanged because that
signature does not commit to other inputs' scriptSigs. The resulting spend can
consume the funds while an off-chain global-weight decoder rejects the message.
A fixed global number of revelations describes an antichain code, but merely
rejecting other weights does not enforce publication or repair this spend.
The final complete-publication experiment therefore uses fixed thresholds in
every pool. A variable threshold would require an additional protocol mechanism
that prevents or safely handles this erasure; none is supplied here. The
[variable Core vectors](common-key-variable-vectors.json) cover 1–4 of 10,
1–3 of 11, and 1–5 of 9. These exact variable layouts were subsequently checked in
[Bitcoin Core](common_key_variable_core_check.json): all 24 positive cases
passed consensus and policy, and all 48 negatives failed as expected. This is
**differentially-validated**, **policy-validated** execution evidence for the
three layouts, not evidence that variable-cardinality funded publication is
safe against the erasure described above. The report includes one additional
unrelated old cross-pair regression.
