# Search 2: native contexts, subset deletion, and the funding dependency

Date: 2026-09-17. Question: can legacy native signature contexts implement a
shared computational statement that is cheaply satisfiable only when the
actual output vector equals a vector fixed before funding, using existing
opcodes, no erased state, and less than `2^64` honest total work?

**Result: no complete construction found.** The strongest additional result
is an output-invariance argument for *exact native preimage coincidence*,
extended beyond one input and one sighash byte. A deterministic host experiment
also covers 36,864 contexts. This does not rule out other computational
relations among different hashes, cross-format constructions, or a new
non-native verifier.

## Exact preimages

Let the actual spending transaction be

```
T = (v, [(u_j, seq_j)]_(j=0..m-1), O=[(value_l, spk_l)]_(l=0..q-1), L).
```

The unlocking scripts are omitted from this notation because native legacy
sighashing replaces them. The actual spent outpoint is
`u_i = wire_txid(F) || LE32(vout)`, where `F` is the funding transaction.
For a signature instruction `a`, let `S_a` be the suffix after its most recent
executed `CODESEPARATOR`. If `A` is its list of signatures, define

```
C_a(A) = remove_opcode_CODESEPARATORs(
             FindAndDelete(S_a, Push(A[0]), ..., Push(A[k-1])))
```

This is the processed `scriptCode`, not the executed script. Each
`CHECKMULTISIG` begins again from its original active suffix. Deletion in one
check is not persistent state available to the next check. Matching data
inside a larger push is not recursively deleted.

For full one-byte flag `h`, `b=h&31`, and `acp=(h&128)!=0`, set

```
J = [i] if acp else [0,...,m-1]
I_j = u_j || CompactSize(len(c_j)) || c_j || LE32(s_j)
c_j = C_a(A) if j=i else empty
s_j = 0 if j!=i and b in {2,3}, else seq_j
X_l = LE64(value_l) || CompactSize(len(spk_l)) || spk_l
X_null = ff ff ff ff ff ff ff ff 00

Out_h(T,i) = 00                                  if b=2 (NONE)
           = CompactSize(i+1)||X_null^i||X_i      if b=3 and i<q
           = CompactSize(q)||X_0||...||X_(q-1)    otherwise

M(T,i,a,A,h) = LE32(v)||CompactSize(len(J))||I_J
               ||Out_h(T,i)||LE32(L)||LE32(h)
z = BE256(SHA256(SHA256(M))) mod n
```

For `b=3` and `i>=q`, no such preimage is hashed: the digest bytes are
`01 00...00`, hence the ECDSA scalar is `2^248`, independent of outputs and
the full flag byte. These formulas were inspected against
[Bitcoin Core 30.3](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp),
particularly `EvalChecksigPreTapscript`, the multisig branch,
`CTransactionSignatureSerializer`, and `SignatureHash`.

## An invariance statement stronger than the two-check shortcut

Consider any finite family of the above legacy contexts on one actual
transaction: arbitrary input positions, full flags, suffixes, and selected
signature sets. Hold the input data and output count fixed. Replace all output
amounts and scripts, including their lengths.

**Claim:** the equivalence relation “these two ordinary sighash preimages are
byte-identical” is unchanged. Membership in the exceptional SINGLE-constant
class is also unchanged.

Proof:

1. Distinct full flags give distinct final four bytes, even if the flags use
   identical base semantics. Flags `0`, `1`, `4`, `33`, `65`, and `97`, for
   example, all use ALL semantics but have different trailers.
2. For equal flags, canonical transaction serialization has one parse. Any
   inequality in serialized inputs or their scriptCode fields persists when
   output contents change. Output bytes cannot be reinterpreted as input or
   scriptCode bytes across two equal canonical encodings.
3. ALL inserts exactly the same actual complete output vector in both
   contexts. NONE inserts the same empty output vector. SINGLE inserts `i+1`
   outputs; equality of those counts requires equal input index, after which
   both contexts insert the same actual `X_i`.
4. SINGLE's exceptional condition depends on input index and output count,
   not on amounts or scriptPubKeys.

Thus deliberately arranging equal processed scriptCodes, including elaborate
subset-deletion word equations, can make two checks share a predicate. It
cannot make that sharing specific to the desired output bytes. Placing the
desired output serialization inside a dummy-signature pool does not change
the argument: it remains input-side scriptCode data.

The claim concerns exact preimage equality. It does **not** identify distinct
preimages whose SHA256d hashes collide, agree modulo `n`, or satisfy some
nontrivial curve relation. Those remain different computational problems.
It also does not claim equality of a freely selected signature/key pair
implies equality of hashes; the earlier opposite-nonce counterexample rules
out that inference.

## Fixed signatures and a hypothetical reference context

For a fixed ECDSA signature `(r,s,h)` and a recovery nonce point `R` with
`x(R) mod n=r`, the native check supplies a transaction-bound key

```
Q(T,A) = r^-1 (sR - z(T,A)G).
```

For the fixed `r=s=1` signature and the lift of `x=1`, this is
`Q=epsilon*R-zG`, with `epsilon in {-1,+1}`. A second occurrence of the
same Q can give a meaningful equation, but only after accounting for both
nonce signs. The earlier note already handles its discrete-log consequence.

An intended-output oracle would instead need a digest

```
z_ref = H256(M(v,I,O*,L,C_ref(A),h)) mod n,
```

with `O*` substituted for the actual output list. No existing native context
does that substitution: ALL uses O, SINGLE uses an entry of O, NONE uses no
outputs, and out-of-range SINGLE uses its constant. A witness supplying
`z_ref`, its preimage, or a recovered `Q_ref` supplies a claim unless a
separate verified computation checks this equation.

Two native predicates `P(Q(T,A))` and `P(Q(T,B))` therefore do not automatically
instantiate a good-only shared reference computation. Requiring the same
subset in two rounds adds correlation between their scriptCode choices, but
does not introduce `O*` at the native output position.

## Why retained-state Binohash/QSB authorization does not close the gap

[Binohash](https://robinlinus.com/binohash.pdf), inspected sections 3–6 in the
33-page version retrieved 2026-09-17, uses selected dummy-signature subsets
as a readable digest and authenticates them with hash preimages. The
[QSB source](https://github.com/avihu28/Quantum-Safe-Bitcoin-Transactions/blob/2c9172051d5c150ef0a994ca6b988a08a3ef9e85/paper/QSB.tex)
at commit `2c9172051d5c150ef0a994ca6b988a08a3ef9e85` replaces the short-signature
puzzle with a hash-to-signature gate and fixes its native signature's ALL flag.

Our inference under the requested threat model: a creator retaining every
HORS preimage can authenticate a fresh subset mined for an unauthorized
output vector. Collision or second-preimage resistance of one revealed
digest is not the relevant restriction when every digest remains signable.
Adding more independently solved rounds increases both parties' work; it
does not alone create an intended-output advantage.

Restricting authorization to one predetermined subset pair avoids that
particular attack, but removes the honest party's subset-search freedom.
If the allowed pair is chosen *after* successful search, inserting it into
the locking script changes the funding transaction and invalidates the
searched instance. This is a dependency, not an assertion that every possible
fixed-point search costs a particular number of operations.

Bonus selections retain their original role as freely searchable variables;
they cannot simultaneously be counted as fixed authorization bits.

## Funding dependency and honest work

Let `d` denote a hardcoded allowed digest, subset commitment, recovered-key
commitment, or setup table. The honest search must solve the composed system

```
S = S(O*,d)
F = Fund(S, other_funding_fields)
u = H256(serialize_without_witness(F)) || vout
T* = Spend(u, O*, free_spending_metadata)
d = ExtractOrAuthorize(T*, S).
```

The loop is still present if `d` lies before the final executed
CODESEPARATOR: the local scriptCode may omit it, but `u` commits to the
funding output containing S. ANYONECANPAY retains the current input's
outpoint. Segwit funding excludes funding *witness* data from txid, but it
retains the funded scriptPubKey. P2SH or P2WSH moves the dependency through
a script commitment rather than eliminating it.

Checking the complete prepared spend before broadcasting funding is useful:
it proves existence of that spend. It does not make a later change to S leave
u unchanged, and it does not prevent a retained-state creator from also
preparing another authorized spend. No work performed on the loop may be
classified as free setup under the user's total-work bound.

## Cross-format boundary

BIP143 uses a different serialization and no FindAndDelete. All its ordinary
native contexts still use the actual outputs' hash, one actual output's hash,
or zero; it provides no direct `O*` substitution. The legacy invariance proof
above is deliberately **not** asserted for byte equality between legacy and
BIP143 preimages. That would require separate analysis of two distinct
formats.

There is also an execution obligation: one input cannot select both legacy
and witness-v0 signature semantics. A proposed cross-format solution needs
another input and must force that input's specific verifier program, not
merely its presence. No such authenticating connection is supplied here.

A useful remaining candidate, especially if a stronger fixed-signature
gadget supplies exact digest equality, is the explicit equation

```
M_legacy(T,i,C_a,0x01) = M_143(T,j,C_b,amount_j,0x01)

M_143 = LE32(v)||H256(u_0||...||u_(m-1))
        ||H256(LE32(seq_0)||...||LE32(seq_(m-1)))
        ||u_j||CompactSize(len(C_b))||C_b||LE64(amount_j)
        ||LE32(seq_j)||H256(X_0||...||X_(q-1))||LE32(L)||01000000.
```

Here one format contains actual outputs inline while the other contains their
hash, so the legacy-only invariance theorem does not settle the equation.
An overlapping-format construction would have to assign the fixed script
bytes and actual transaction fields so both parses coincide only for O*,
without paying for an unaccounted hash preimage/funding fixed point. It must
then make the required second input unavoidable. This is an unresolved
candidate, not a demonstrated shortcut or a claimed lower bound.

## Reproduction and evidence

Run:

```
python3 research/covenant-2026-09-17/seven/search2_native_context.py
```

The [saved report](search2_native_context.json) checks 3 input positions ×
256 full flags × 6 script templates × 8 deletion subsets for each of two
different output vectors. All 242,496 equal-context pairs remain equal;
13,441 equivalence classes are unchanged. It additionally tests trailer
domain separation, deletion local to a check, embedded-push boundaries, and
the funding dependency despite identical spend-side scriptCodes.

Evidence: `locally-reproduced` for this host experiment; `inspected` for the
source-based reasoning. Deployment: `unclassified`. No complete Script
spend, hash puzzle, or funding fixed point was mined. No tapscript helper was
used. Host fixtures use zero hint items and zero witness bytes. Locking-script
size, stack peak, and executed-opcode metrics are inapplicable to the
abstract context family and are not reported as zero. Existing repository
files and primitive metrics were not changed; no field tests were run.

Falsifiable next criterion: provide a fixed funded instance plus a native
or Script-verified reference equation containing `O*`, show that the honest
joint instance can be prepared in total work below `2^64`, and exhibit why a
retained-state creator cannot use the same preparation procedure for an
arbitrary different output vector.
