# R22: a native constant-digest guard for a variable long ECDSA signature

Question: can the constant-digest edges in
[the native relation graph](r22_native_relation.md) use witness signatures
without silently trusting their sighash flags?

**Yes, with an explicit hash-collision qualification.** A 49-byte legacy
redeem script checks the same long signature under two distinct compressed
keys in two different CODESEPARATOR contexts. An accepting spend either
uses the out-of-range SINGLE constant in both contexts or supplies a
collision between distinct legacy preimages after double-SHA256 reduction
modulo the curve order. The program does not read a signature's flag byte.
It does not constrain transaction outputs and is not a complete covenant.

The [host fixture](r22_single_guard.py), [host results](r22_single_guard.json),
[funded Core fixture](r22_single_guard_core.py), and
[Core results](r22_single_guard_core.json) are reproducible. The independent
[audit](r22_single_guard_audit.md) checks the bytecode, stack, and source
semantics. Host controls are `locally-reproduced`; ten actual Core cases
are `differentially-validated`. Four positive cases are
`consensus-validated`, and six negative cases are `consensus-incompatible`.
The general collision-qualified argument is `inspected`.

## Concrete script

At entry the stack is `beta P Q`, with Q at the top. The altstack is empty.

```text
DEPTH 3 EQUALVERIFY
SIZE 33 EQUALVERIFY SWAP SIZE 33 EQUALVERIFY SWAP
2DUP EQUAL NOT VERIFY
2 PICK SIZE 57 GREATERTHAN VERIFY DROP

2 PICK 2 PICK CHECKSIGVERIFY
2 PICK 1 PICK CHECKSIGVERIFY
CODESEPARATOR
2 PICK 2 PICK CHECKSIGVERIFY
2 PICK 1 PICK CHECKSIGVERIFY

2DROP DROP 1
```

The first two signature checks retain all three original items. The later
two use exactly the same signature and keys. Valid signature checks and
the 33-byte guards force canonical compressed public keys; byte inequality
then means distinct group points. The length guard applies to beta including
its trailing sighash byte. Successful DER validation also limits it to
at most 73 bytes. This complete fixture requires exactly three entry items;
it is not an already-composed multi-edge graph.

There is one separator, at byte offset 35. Removing it gives a 48-byte
scriptCode for the first pair of checks; the later pair uses the 13-byte
suffix after it. There are no literal long signature pushes. In particular,
the entire script is shorter than a serialized push of any admitted beta,
so FindAndDelete is vacuous here. The two scriptCodes differ by 35 bytes.

These are intentional raw consensus-boundary vectors. They are not compiled
library generators or optimizer-policy primitive metrics.

## Why a long signature makes the constant enforceable

Let n be the group order and p the field prime. Four ECDSA recovery points
require both x=r and x=r+n to lift, hence `0<r<p-n`. A positive strict-DER
encoding of such an r uses at most 17 payload bytes; a valid s uses at most
33, including the possible positive sign-padding byte. Sequence/integer
overheads plus the flag add seven bytes. Thus a valid four-root signature
has length at most `17+33+7=57` bytes.

For an accepted beta longer than 57 bytes, its two distinct verifying keys
must therefore be the entire antipodal recovery pair. In each context j,

```text
P + Q = -(2*z_j/r)G.
```

The same pair in both contexts implies `z_0=z_1 mod n`. This covers high-S
as well as LOW_S signatures; negating s only swaps the nonce signs.

For every ordinary legacy sighash mode, the actual signing input's processed
scriptCode is serialized, including with ANYONECANPAY or NONE. The two
different scriptCode lengths give different preimages for this same input,
flag, and transaction. The exceptional legacy SINGLE path returns the same
constant without serializing either scriptCode when the input index is at
least the output count. Its digest bytes are `01` followed by 31 zero bytes,
which ECDSA interprets as `C=2^248`.

Consequently an accepting non-bug transcript provides distinct preimages
whose double-SHA256 values agree modulo n. This need not be a bitwise hash
collision: the two 256-bit integers could instead differ by exactly n.
No `2n` difference fits; for a difference of n, the smaller integer must be
below `2^256-n`. The construction explicitly relies on difficulty of this
reduced-hash collision problem. Finite tests do not prove that assumption.

The guard permits all eight consensus flag bytes with low five bits equal
to three: `03,23,43,63,83,a3,c3,e3`. It neither chooses one canonical flag
nor permits ordinary in-range SINGLE except via the collision branch.

The source rules are in pinned
[Core 30.3 interpreter.cpp](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp)
and [public-key verification](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/pubkey.cpp).
The independent audit records the precise relevant code locations.

## Tests and resource boundary

The deterministic host test checks all 256 flag bytes in three contexts:
out-of-range input one with one output, input zero with one output, and
input one with two outputs. All 768 comparisons match the argument. The
eight out-of-range SINGLE flags have equal constant scalars; every ordinary
fixture has different preimages and different digest scalars. Four explicit
ALL/NONE/undefined/ANYONECANPAY witnesses have a valid first pair and fail
the second. A DER boundary check includes maximal high-S length.

Bitcoin Core 30.3, commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`, then
funded the actual P2SH output on a fresh private, peerless regtest chain.
All ten expected outcomes passed:

- SINGLE, SINGLE|ANYONECANPAY, and a consensus-valid undefined upper-bit
  SINGLE flag spend successfully.
- Changing the recipient while retaining the original SINGLE witness also
  succeeds. This explicitly demonstrates the absence of output binding.
- ALL, NONE, and ordinary in-range SINGLE witnesses constructed to satisfy
  the first pair fail at the later context.
- Duplicate keys, a short otherwise-valid signature, and an uncompressed
  second key fail their respective guards.

The same funding outpoints are used throughout. Each accepted test block
is invalidated before testing another spend. Relay policy was tested for
all cases before connecting conflicting spends. Default policy rejects the
positive defined-flag cases for legacy CODESEPARATOR; the undefined flag
is independently nonstandard. The result is consensus-only.

| Metric | Positive complete-spend value |
|---|---:|
| P2SH locking script | 23 bytes |
| Redeem script, including guards and clean truthy termination | 49 bytes |
| Signature / each compressed key | 71 / 33 bytes |
| Redeem entry non-hint data items | 3 |
| Hint items, per invocation and entire fixture | 0 |
| scriptSig pushes, including redeem script | 4 |
| Serialized scriptSig | 190 bytes |
| Combined main-plus-alt-stack peak for the P2SH input | 6 |
| Redeem executed and static non-push opcodes | 32 |
| Additional outer P2SH non-push opcodes | 2 |
| Native ECDSA checks | 4 |
| Complete transaction / weight | 319 bytes / 1,258 WU |

The three data items coexist at redeem entry; the altstack stays empty.
The outer P2SH evaluation peaks at five items, below the redeem peak six.
The separate OP_TRUE P2WSH funding input has one non-hint witness item and
peak one. No stacks are shared. Thus the complete spend has four data
items across two separate executions and zero hints. Its serialized witness
section is four bytes: three for the helper's one-item witness and one for
the legacy input's empty witness vector. Marker and flag add another two
bytes. The legacy input itself has zero witness items. The positive base
transaction is 313 bytes, giving `4*313+4+2=1258` WU. All cases pay 10,000
sats; the ordinary in-range SINGLE negative has two outputs and a larger
transaction. Exact per-case bytes are in the Core JSON.

## What this supplies to the research

The [constant-digest path equations](r22_native_relation.md) previously
needed a separate premise that every variable edge really signs C. This
guard gives a concrete collision-qualified way to enforce that premise
for long signatures. It does not solve their nonce-coordinate equations,
transfer data between inputs, or force an output reference. It also rejects
20-/32-byte hash-derived source signatures by design; it belongs on long
reference edges, not on the short hash-as-signature root.

Next criterion: compose a useful long-signature graph with this actual
guard, within the complete legacy resource limits, and supply signatures
for its genuine funded ALL digest. Then establish a fixed output reference
and a retained-state work gap. A freely recomputable C edge or the present
guard alone does not meet that criterion.

Reproduce the host fixture with `python3 research/covenant-2026-09-17/continuation/r22_single_guard.py`.
The `_core.py` companion uses the locally pinned Core archive and temporary
loopback sockets. No wallet, public network, Rust tests, or field-library
tests are used. The sandbox's loopback restriction required the already
authorized local-regtest escalation; the ten Core cases then completed.
