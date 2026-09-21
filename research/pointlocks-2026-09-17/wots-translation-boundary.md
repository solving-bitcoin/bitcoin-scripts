# WOTS translation: label access and the separate public-binding requirement

Question: does the newer WOTS-to-Lamport translation remove the obstacle to
noninteractive, algebraically bound2048-bit label publication below100,000 vB?
It supplies a useful offchain access mechanism, but does not by itself supply
the required public setup verification or native point-scalar extraction.

## Primary-source boundary

[Sergeevitch, Staniec, Tse, Vanjani and Woll, ePrint2026/1684](https://eprint.iacr.org/2026/1684)
describe a checksum-controlled Shamir translation from WOTS openings to binary
labels. The inspected22-page PDF is dated2026-07-27; ePrint metadata records
receipt2026-08-13 and approval2026-08-15. SHA256:
`64911295ba6ffa3e3b23c8075bb074d8995e55f11d1b949c5f17a59e10124745`.

Sections4–9 describe the threshold construction and split checksums.
Section8 calls its arguments informal and defers the full105-bit analysis.
Section10.1 explicitly separates the parties' WOTS seeds; Section10.2 uses
181 garbled circuits with174 audited. Its BABE example covers508 bits,
not2048. Section10.4 reports7.60 seconds setup and636.3 ms evaluation under
those parameters. These are **reported** source measurements, not local
benchmarks or a complete public setup audit for our target.

The10,000-vB constraint discussed there is specifically contextualized by
the TRUC transaction topology in Section10.4. Do not treat it as the general
Bitcoin transaction-size limit. The source's post-opening translation is
noninteractive; that does not establish our entire setup's requirements.

## Local reproduction

[Program](wots_translation_access_probe.py),
[results](wots-translation-access-probe.json).
The bounded reproduction deliberately has no Bitcoin script or native point
lock. All seeds are public deterministic test values. Its127-bit prime field
tests polynomial arithmetic; it is not a proposed secp256k1 secret domain.

For n digits of d bits, set K=2^d-1 and M=nK. A valid message v opens chain
states at v_i and a checksum chain at W=sum_i(K-v_i). For one target bit/side,
let B_v indicate whether that side is selected at digit value v. The tested
rules are

    shift = 1-B_K
    helper_count(v) = B_v-B_(v+1)+1
    threshold = W+shift.

Every other digit contributes K-v_i decryptable points. The target digit
contributes the sum of its accessible helper counts. Subtracting these from
the threshold gives exactly1-B_v. The program exhausts832 messages in four
profiles, with13,056 bit/side deficit checks, including terminal states and
zero checksum. This is an exact combinatorial identity, not a privacy proof.

A second test actually encrypts and reconstructs the polynomials for two
2-bit digits. The public evaluator receives only the ciphertexts, commitments,
and one WOTS signature; the secret setup object is not an evaluator argument.
Across all16 messages it recovers64 selected labels and never selects the
opposite side. There are48 encrypted evaluation rows. State and label indices
domain-separate masks; two helper points under one state get distinct x values.
The test uses additive PRF masks over its field and independent label constants.
It does not instantiate a full free-XOR garbling or the paper's complete
cryptographic proof.

The coefficient boundary matters. For shift0, the constant is derived from
checksum state0. For shift1, coefficient0 is independent and subsequent
coefficients use checksum state m-1. There is no checksum state-1. When W=0
and shift0, the evaluator already knows the constant; interpolation with an
empty point set is not used to manufacture a zero label.

## What the reproduction changes in the search

The fixed-cardinality complement bridge need not be the only compact
offchain translator. The WOTS access structure provides another option, with
an explicit small-chunk tradeoff. For2048 message bits and4-bit digits, the
local algebra gives the following **counts**, not setup timings or vbytes:

| Chunk bits | Chunks/checksum chains | Data chains | Encrypted field elements | Raw16-byte ciphertext payload |
|---:|---:|---:|---:|---:|
|4|512|512|61,440|983,040 B|
|8|256|512|122,880|1,966,080 B|
|128|16|512|1,966,080|31,457,280 B|

Each row uses one checksum chain per chunk. It excludes split-checksum entry
grids, polynomial metadata, chain material, label commitments, garbled copies,
and all transaction data. The small profiles warrant consideration only with
a solution to the missing binding interface; their small payload alone is
not a point-lock construction.

## Malicious tables remain a different question from access privacy

The program changes one encrypted evaluation point for a label selected by
message(0,0). It retains every WOTS endpoint and intended label commitment.
The same signature still passes all WOTS chain/checksum checks, yet evaluation
produces the wrong selected label and fails its hash check. No hash collision,
alternative-message signature, or unauthorized interpolation is involved.

This distinguishes two obligations:

1. An honestly generated table should reveal only the chosen labels.
2. Public setup verification must establish that every future accepted opening
   yields the precommitted labels, even if the table generator is malicious.

The experiment supports the small-instance correctness/access calculation in
the first obligation and exhibits the missing check in a standalone wrapper
for the second. It is **not** an attack on the paper's honest-garbler privacy
claim or its complete BABE protocol with that protocol's audit. Checking label
hashes only after publication detects the failure too late to satisfy the
active goal's extraction requirement. Public polynomial/group commitments
would additionally need to bind their masked evaluations without violating
the user's no-setup-ZKP constraint.

No new transaction cost, point-scalar extractor, complete garbled verifier,
public setup verifier, or setup benchmark is supplied. Evidence for the local
tests: **locally-reproduced**; interface analysis: **inspected**; deployment:
**unclassified**. Script/witness sizes, hint counts, stack peaks, and executed
opcodes are **not applicable**, not zero-valued native measurements.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/wots_translation_access_probe.py
```
