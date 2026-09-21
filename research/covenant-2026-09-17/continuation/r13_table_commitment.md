# R13: deferred recovery-table commitment through one Taproot leaf

Date: 2026-09-17. Question: can a fixed P2TR output defer the R11 table into
its leaf/control block, using internal-key flexibility to construct the table
after funding while still requiring its native output check?

**This concrete candidate does not work.** The control block authenticates
the table, but the unchanged R11 native checks do not constrain outputs in
tapscript: its 33-byte public keys select the unknown-key rule, which accepts
every nonempty signature without ECDSA or Schnorr verification. Bitcoin Core
accepts the same script-path witness spending the same funded outpoint to
two different output vectors on separate local branches. Replacing the keys
with 32-byte x-only keys instead rejects the 32-byte DER signature.

There is also no free internal-key cancellation: fixing the output point Q
and changing the table leaf requires solving

```
P_even + H_TapTweak(x(P_even) || H_TapLeaf(table)) G = ±Q.
```

Computing P from a previously calculated tweak changes the tweak's own hash
input. Both output parities of that proposed cancellation fail in the exact
point fixtures. This is an obstruction to that specific construction, not a
proof that every Taproot commitment strategy requires 2^64 work.

The [Python](r13_table_commitment.py) and [JSON](r13_table_commitment.json)
contain exact commitment inputs, control blocks, full serialized funding and
spending transactions, public point/scalar calculations, and Core results.
Host equations are `locally-reproduced` / `unclassified`; the six actual Core
boundary cases are individually `differentially-validated` and classified
below. No complete covenant was produced.

## 1. Candidate and exact committed bytes

The candidate has one c0 leaf, no sibling branches, and the public NUMS
internal point from BIP341:

```
x(P) = 50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0.
```

Using this fixed point introduces no signing scalar and requires no key
deletion. Unavailability of its logarithm remains the conventional
discrete-log assumption, not an information-theoretic guarantee.

The leaf uses the exact R11 two-row lookup algorithm, with fresh literal
recovery keys for standard recipient scripts. Its native legacy reference
transactions share these ordered outputs and vary only locktime 0/1:

```
400000 sat -> 0014 followed by twenty 11 bytes
590000 sat -> 0014 followed by twenty 22 bytes.
```

The source outpoint for generating these public reference rows is the
synthetic 32-byte value 42...42. Both legacy reference checks pass locally
before the layout is moved into Taproot. This synthetic reference is not
silently treated as the later real funded outpoint.

For the actual 318-byte leaf S, the commitment inputs are:

```
leaf-preimage = c0 || fd3e01 || S
leaf-hash    = 837773dea2e5f8350fedbd7ff757161825fe4e846691a16b3bf6328247f4f3b2
tweak-input  = x(P) || leaf-hash
Q            = P + int(H_TapTweak(tweak-input)) G
scriptPubKey = 51204f5b410a1ca4a6b66ffb497c009923c1430c3259c00ba99ff2dfa6229dd2601c
control      = c0 || x(P).
```

Here fd3e01 is the three-byte CompactSize encoding of 318. Tagged hashes
prepend two copies of SHA256(tag). The witness contains exactly
`[alpha, empty-index-zero, S, control]`; its 33-byte control block has no
Merkle path. The funding output contains only the 34-byte scriptPubKey, but
the output key commits cryptographically to P and S. Core reconstructs and
checks this commitment before executing the leaf. See the pinned
[Core commitment code](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L1720-L1758)
and [BIP341](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0341.mediawiki#script-validation-rules).

Replacing the literal table changes the leaf hash. The old control block
then fails against the original output, as checked by both public point
arithmetic and Core. Moving these bytes into witness therefore does not make
them freely replaceable after funding.

## 2. What internal-key flexibility actually permits

Suppose the new table has leaf hash L1 and the old committed output point is
Q0. A tempting attempt first calculates

```
t1 = H_TapTweak(x(P0) || L1)
P1 = epsilon Q0 - t1 G,             epsilon in {+1,-1}.
```

The formal group equation `P1+t1 G=epsilon Q0` is true. But the control block
reveals x(P1), so validation uses the even lift of P1 and recalculates

```
t_actual = H_TapTweak(x(P1) || L1).
```

Both measured candidates produce different actual output keys from the
fixed funding program. The JSON includes the trial point, its canonical
even lift, assumed and actual tweaks, and resulting output script for both
epsilon values. Parity is included rather than assuming that the output's
x-only encoding fixes a sign.

If P is fixed first, the table determines Q and hence the funding output.
If Q is fixed first, the above equation constrains P and the table jointly;
P is not an independent point offset outside the hash. No acyclic algorithm
or bounded search solving this equation is provided. This is a specific
post-commitment opening obligation beyond simply observing that a txid
contains outputs.

Even a hypothetical replacement by real Schnorr table checks loses another
property used by R11. BIP342 commits each such signature to the **full leaf
hash**, plus the last CODESEPARATOR's opcode position. It does not select a
table-free suffix as legacy CHECKSIG does. In the fixture, two tables have
the same native-check suffix and the same parsed separator position 42,
but different full-leaf message extensions and different TapSighash values.
These extension bytes are reproduced; the unknown-key execution itself
never requests such a hash. See
[BIP342's message extension](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0342.mediawiki#common-signature-message-extension).

## 3. The mandatory-execution failure is independently concrete

The script path does execute the chosen table and its alpha-byte equality
check. However, tapscript CHECKSIG is not the legacy ECDSA opcode. With the
table's 33-byte keys, the consensus dispatch regards each key as an unknown
type; a nonempty alpha gives success and consumes signature budget without
cryptographic verification. This is the actual behavior of the pinned
[Core signature dispatcher](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L322-L357).

The table alpha remains its exact strict-DER, LOW_S, ALL-marked 32-byte value.
That byte pattern no longer causes an ALL transaction hash to be checked.
There is no cryptographic equality to the row's intended legacy digest.

Core validates the following two transactions from the same real outpoint
and with byte-for-byte identical four-item witnesses:

* The prescribed two-output vector above.
* A single 990000-sat output to `0014` followed by twenty 33 bytes.

The first validation block is invalidated only within the isolated test chain
to restore the same UTXO; the second transaction is then validated on the
alternate local branch. Both are consensus-valid. Mempool policy rejects
both specifically for the reserved public-key version, which is recorded
separately from consensus. This is an output-mutation counterexample for this
Taproot table candidate, not a claim that R11's legacy three-key theorem fails.

The straightforward repair of dropping each key's compressed prefix also
does not work. With actual 32-byte keys, Core requires a 64/65-byte Schnorr
signature and rejects alpha with `Invalid Schnorr signature size`. A new
Schnorr primitive would require its own derivation; the ECDSA recovery-key
table and 32-byte root cannot be assumed to transfer.

## 4. Key path cannot be silently omitted

One leaf is not the only possible spending route: the output always has a
key path. The fixed-NUMS variant introduces no known output secret, but a
variant that chooses an ordinary public internal scalar d also knows

```
q = d_even + tweak mod n,
```

with the standard parity normalization when signing for x(Q). Such a
creator can bypass the table entirely using a one-item Schnorr witness.

The fixture takes the explicitly public scalar 7, derives the actual output
scalar, computes BIP341 DEFAULT hashes of fully serialized transactions, and
signs with public deterministic nonces. Core accepts both prescribed and
different output vectors on outputs locked by that same constructed key.
These two cases also pass relay policy. No secret is deleted or concealed;
all scalars and preimages are included in the JSON. Their validity confirms
the host BIP341 message serialization independently through Core.

The controlled NUMS choice avoids this particular known-secret escape but
does not repair the unknown-key table checks or supply the missing delayed
opening algorithm. No optional second input or unbound witness table is used.

## 5. Core evidence, limits, and setup accounting

Core version 30.3, immutable commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`. The release archive and binary
checksums are recorded. The test uses a fresh regtest chain, wallet disabled,
network activity disabled, a separate executable copy, and localhost RPC.

| Case | Expected and observed | Deployment class |
| --- | --- | --- |
| 33-byte keys, prescribed outputs | accepted in a block; policy rejects unknown key type | `consensus-validated` |
| identical witness/outpoint, different outputs | accepted in a block; same policy rejection | `consensus-validated` |
| changed table with original control block | witness-program mismatch | `consensus-incompatible` |
| prefix-stripped 32-byte keys | invalid Schnorr signature size | `consensus-incompatible` |
| public known-key key path, prescribed outputs | accepted by policy and block validation | `policy-validated` |
| public known-key key path, different outputs | accepted by policy and block validation | `policy-validated` |

For the script-path layout: **318 script bytes, 40 executed non-push
operations, 2 argument items, 0 hint items, 4 full witness items, 390
serialized witness bytes, combined main-plus-alt-stack peak 11**. All
arguments coexist at entry; the script introduces its eight literal table
items during execution. Initial BIP342 signature budget is 440, of which
the three nonempty unknown-key checks consume 150. This leaf contains no
OP_SUCCESS opcode. The 201 legacy opcode ceiling is not a tapscript rule;
the measured 40 is informational here.

The prescribed and alternative script-path transactions measure respectively
505 bytes/844 weight units and 474 bytes/720 weight units. The 32-byte-key
variant has a 312-byte script and 384 witness bytes. Each key-path witness has
one 64-byte signature item, zero hints, and 66 serialized witness bytes;
there is no script execution stack. Complete transaction sizes and hashes
are included for every case.

Finite setup uses two public recovery rows, a constant number of curve
operations and tagged hashes, and O(318) script storage. These cheap steps
construct the **failed candidate**. They do not solve the fixed-Q opening
equation, make the table's legacy predicate mandatory, or establish an
honest covenant setup cost below 2^64. No general fixed-point or curve-work
lower bound is inferred from two failed compensation trials.

The falsifiable next step for this particular route would be a concrete
fixed-Q delayed opening that also executes a valid mandatory output-binding
predicate under the actual tapscript signature rules. Producing only a leaf
membership proof or a formal point cancellation does not meet that criterion.

Reproduce the deterministic host calculations and the isolated native checks:

```
python3 research/covenant-2026-09-17/continuation/r13_table_commitment.py --core
```

Omit `--core` for host calculations only. No repository library or field tests
were run. The artifact uses raw R11 boundary bytecode rather than claiming a
policy-compiled primitive metric.
