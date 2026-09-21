# R18: exact native hash reuse cannot join two input executions

Date: 2026-09-17. Question: can two native ECDSA contexts share a transaction
hash by arranging CODESEPARATOR, FindAndDelete or SINGLE/ANYONECANPAY, thereby
making a separate reference-verifier input mandatory without embedding a
post-search outpoint or recovery table?

**No mandatory-reference construction found.** There is a narrower exact
result: in one transaction with distinct input outpoints, two actual ordinary
legacy ECDSA checks at distinct input positions cannot have identical sighash
preimages. This closes the apparent empty-scriptCode exception in Search 2's
abstract context enumeration. BIP143 has the same distinct-input result through
its explicit own-outpoint field. This is about equal *preimages*, not a claim
that their hashes or curve-derived values cannot satisfy useful relations.

Artifacts: [Python](r18_mandatory_reference.py),
[JSON](r18_mandatory_reference.json). Evidence `locally-reproduced`, deployment
`unclassified`. The fixture uses deterministic host serialization and
opcode-boundary deletion. No signature witness, complete successful Script,
funded transaction, Core acceptance or library field test is claimed.

## Why the current signature operation cannot erase its own scriptCode

Let `S` be the active suffix beginning just after the last executed
CODESEPARATOR. The CHECKSIG, CHECKSIGVERIFY, CHECKMULTISIG or
CHECKMULTISIGVERIFY currently being evaluated occurs in `S` as an opcode
outside any data push.

Legacy FindAndDelete removes byte sequences encoding pushes of the signature
arguments, starting only at instruction boundaries. Each target is a complete
data-push instruction. It cannot consume a current signature opcode outside
a push. Subsequent removal of CODESEPARATOR opcodes cannot remove that
signature opcode either. Consequently the processed code `C` is nonempty.
Multiple multisig deletion targets do not change this conclusion. A pushed
byte equal to CHECKSIG is data, and its removal does not remove a separate
executing CHECKSIG.

The fixture supplies 20 deletion controls: all four signature opcodes, each
with five signature-byte strings including an empty string, a short DER
string, opcode bytes and a 73-byte value. The current opcode survives every
case; a pushed copy of a signature push remains uninterpreted. These are
byte-deletion controls, not assertions that all supplied signature strings
are valid ECDSA signatures or that the suffixes are successful programs.

The relevant native processing is pinned to
[Core 30.3's interpreter](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp).

## Distinct-input preimage theorem

Consider two actual native checks at input indices `i != j` of the same
transaction, with unique input outpoints. Exclude the legacy out-of-range
SINGLE constant. The active suffixes, signature bytes and full one-byte
sighash flags may otherwise differ.

* Different full flags differ in the four-byte preimage trailer.
* With the same flag and without ANYONECANPAY, the legacy serialization puts
  nonempty `C_i` at input slot `i` and an empty script at slot `j`. The other
  check puts its nonempty `C_j` at slot `j` and an empty script at slot `i`.
  Canonical serialization distinguishes these parses regardless of code
  contents, output contents, and signature deletions.
* With the same flag and ANYONECANPAY, each serialized input vector contains
  the current input alone. Its own 36-byte outpoint is different between the
  two checks. SINGLE additionally retains its index through the output count
  and null-output prefix; this cannot repair differing outpoints.

Thus the ordinary legacy preimages differ. The proof includes all 256 flag
bytes, whether or not a particular flag meets relay policy.

In BIP143, the current input's outpoint occupies bytes 68..103 of every
preimage, independently of code length and ANYONECANPAY. Different flags are
again separated by the trailer, and equal flags at distinct outpoints differ
in that explicit field. This is consistent with the
[pinned BIP143 format](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0143.mediawiki#specification).

The host fixture checks three distinct input positions, 256 flags, and eight
nonempty suffix variants. It obtains **6,080 ordinary legacy contexts and
6,144 BIP143 contexts**, with zero preimages shared across distinct input
positions within either family. Another 64 legacy contexts are the excluded
SINGLE constant. A deliberately abstract empty-code ALL control does share
one preimage across all three positions; that code is not realizable as the
processed suffix of the current native legacy signature check.

For two out-of-range SINGLE positions the constant `01 00...00` really is
shared. That check supplies no commitment to a particular other input or to
output values/scripts. Replacing a coinput while maintaining the relevant
index/output-count inequality leaves the constant unchanged.

## ANYONECANPAY pairing does not authenticate a coinput

For each of ALL|ANYONECANPAY, NONE|ANYONECANPAY and
SINGLE|ANYONECANPAY, the fixture replaces another input's outpoint and also
removes a trailing input, leaving the current input index unchanged. All six
legacy/BIP143 combinations retain the exact same native preimage. These
modes therefore supply no native commitment to the identity or continued
presence of that particular other input.

The SINGLE|ANYONECANPAY distinction is also made explicit: BIP143 preserves
the preimage when the current input and its paired output are moved together
from index 1 to index 0. Legacy does not, because its SINGLE serialization
contains the index-dependent null-output prefix. The BIP143 invariance binds
a pair's own outpoint and output; it does not bind the identity or script of
a separate verifier input. This is a tested application of the documented
pairing rule, not a new signature-hash behavior.

ALL without ANYONECANPAY does commit to other input outpoints. A construction
still has to make satisfying that commitment possible only for an outpoint
whose spending executes the intended verifier. Publicly recovering a fresh
witness key after choosing replacement inputs does not establish that
implication; Search 7 already gives that replacement chronology. Embedding
post-search recovery data in an ancestor reintroduces the dependency recorded
in R14. Those earlier results are not reclassified as new findings here.

## Scope and remaining constructive target

This result rules out free exact-preimage reuse between two actual native
checks *within either ECDSA hashing family*. It does not compare legacy with
BIP143, compare ECDSA with Taproot, rule out collisions or scalar relations,
or prove a general impossibility of mandatory cross-input reference checks.
There is no work bound for the entire covenant in this artifact.

A new candidate must provide an enforced relation that pins the verifier
input (or computes the reference in the same execution), preserves shared
witness semantics, and gives an acyclic setup or a fully charged solution to
its setup equations. R18 supplies no such positive candidate.

Resource boundary: serializer-only, with **0 hint items and 0 witness bytes**;
there is no Script entry stack or complete transaction witness. Locking-script
size, executed opcodes and combined stack peak are inapplicable, not zero.

Reproduce with:

```sh
python3 research/covenant-2026-09-17/continuation/r18_mandatory_reference.py
```
