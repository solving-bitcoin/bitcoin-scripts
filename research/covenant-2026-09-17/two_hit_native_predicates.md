# Native predicates and the two-hit bridge

Question: can the ideal two-hit equality proof in the 2026-09-17 handoff be
instantiated with existing Bitcoin opcodes at honest total work below 2^64?
The creator retains all state. The intended comparison is native transaction
data against a representation whose outputs are fixed, rather than a puzzle
equally cheap to solve for any transaction.

Update: [search 1](seven/search1_nonce_encoding.md) now supplies a compact
native-side pair by fixing the first nonce and using three-opcode routing for
the second. Its 199-opcode candidate is outside the two-symmetric-path family
bounded below. The missing common A/B representation remains unresolved.

Result: no complete construction from this investigation. There is a cheaper
Legacy DER-format gate, but neither the Tapscript predicate nor the common
Big/Small statement is supplied by it. The prefix-sharing calculations below
rule out only the stated ordinary hash-path families, not all Script programs.

## A recovery-free DER predicate

If the top stack item is the result of `OP_SHA256`, its length is necessarily
32. The fragment

```text
OP_0 OP_CHECKSIG OP_NOT
```

checks whether these 32 bytes have a consensus-valid DER signature encoding.
In Legacy/P2WSH, `CheckSignatureEncoding` runs before cryptographic validation.
A malformed nonempty DER signature aborts; a correctly encoded one reaches
ECDSA verification with an empty public key, which returns false; `OP_NOT`
turns that result into true. There is no recovery-key search or curve-lifting
condition. The signature's numerical values may include zero: DER validity
does not imply ECDSA validity.

The separate [Core experiment](core_gate_check.json) now confirms this exact
Legacy P2SH boundary: **locally-reproduced / consensus-validated**, with
policy rejection. The general P2WSH extension remains inspected, unclassified.
The opcode semantics explain the policy rejection:
`STRICTENC` rejects the empty public key and `NULLFAIL` also excludes this use
of nonempty invalid signatures. No relay claim is made.

If this fragment accepts an arbitrary witness item instead of a native hash
output, an empty signature is a trivial bypass. Prepend
`OP_SIZE <32> OP_EQUALVERIFY` in that case. This fragment does not bind its
input to the spending transaction by itself. A preceding native transaction
signature check must supply that binding, and the original representation
bridge obligations still apply.

For uniform 32-byte outputs, six structural bytes are fixed once R/S lengths
are selected. The lengths satisfy `lR + lS = 25`; there are 24 ordered positive
pairs. A one-byte nonnegative minimally encoded integer has probability 1/2;
an integer of length at least two has probability `a = 255/512`. Therefore

```text
p32 = 2^-48 (22 a^2 + a)
    = 780555 / 36893488147419103232
    = 2^-45.42585923361415.

p20 = 2^-48 (10 a^2 + a)
    = 2^-46.42538799564135.
```

All 256 sighash-byte encodings are counted because the gate invokes only
consensus DER constraints. This is a format-counting calculation, not a
measurement of a mined hash preimage. It removes the unnecessary lift/recovery
factor from a DER-only gate; it does not change the fundamental missing link.

Sources inspected at Bitcoin Core commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`:

- [interpreter.cpp: DER parser and EvalChecksigPreTapscript](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp)
- [interpreter.cpp: CheckECDSASignature rejects invalid public keys before computing the sighash](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L1558)

## Why sharing the two nonce-path prefixes does not recover the budget

Consider nonces split into a shared q-bit prefix and two independently chosen
r-bit suffixes. For each candidate value A there are `G = 2^q` groups, each
containing `n = 2^r` nonce values. Both rare hits must occur in the same group.
In the sparse regime `np << 1`, the expected number of acceptable pairs is

```text
G * choose(n, 2) * p^2.
```

A full sweep evaluates `Gn` leaves. Repeating independently over permissible
A values therefore costs approximately `2/((n-1)p^2)` leaf evaluations. The
prefix factor G cancels: the useful exponent is `2W-r`, ignoring constants,
not `2W-(q+r)`. Restricting the two nonces to siblings (`r=1`) essentially
restores the expensive `p^-2` search.

The same exponent is a lower bound for **adaptive** honest searches in the
independent Bernoulli model, not just the cost of a full sweep. Count only
fresh, distinct cells. Each group is a fixed `(A, prefix)` with n suffix cells.
Let Q be the number of queries until the first completed pair, F the number
of first successes in groups, and C the number of queries into groups already
having one success. Assume almost-sure termination and finite E[Q]. Before
the final query every success is a first group success, so the total number
of successes is F+1. Conditional independence (or the stopped Bernoulli
martingale) gives

```text
E[F] = p E[Q] - 1,
p E[C] = 1,
C <= (n-1) F.

Therefore E[Q] >= 1/((n-1)p^2) + 1/p.
```

The pathwise inequality holds even when queries switch adaptively between
arbitrarily many A values and prefix groups: a first hit enables at most n-1
distinct closing queries. An algorithm allowed to stop without a pair, with
success probability delta, instead obeys the same bound multiplied by delta.
This is an ideal-model query bound; correlated concrete hash paths require
their own analysis and are not asserted to satisfy independent Bernoulli cells.

The repository's mixed-hash step uses five counted opcodes:

```text
OP_SWAP OP_IF OP_SHA256 OP_ENDIF OP_RIPEMD160
```

Thus a shared prefix plus two suffixes needs `5(q+2r)` path opcodes alone.
Even granting all 201 Legacy opcodes to the two suffixes gives `r <= 20`.
With the cheaper 32-byte DER gate, the resulting honest search exponent is
at least `2*45.42585923361415 - 20 = 70.8517184672283`, before gate,
canonicalization, terminal predicates, distinctness, or transaction work.

The still more optimistic optional-hash step

```text
OP_SWAP OP_IF OP_SHA256 OP_ENDIF
```

uses four counted opcodes. Giving it one independent nonce bit per step and
ignoring *all* overhead allows only `r <= 25`, hence exponent at least
65.8517184672283. A single repeated optional hash actually collapses to a
hash-iteration count; different selector words with the same popcount alias.
Alternating hash types avoids some aliases but cannot increase entropy beyond
the already overgenerous one-bit-per-step bound. Accepting two different
syntactic encodings of the same hash word would destroy the two-hit claim.

This is a cost exclusion for these direct path encodings. A more efficient
joint nonce function, a different rare predicate, or a different asymmetric
relation would require a fresh analysis. No lower bound on arbitrary Script
constructions is claimed.

## Tapscript predicate audit

- `OP_SIZE` on BIP340 signatures yields 64, or 65 with an explicit sighash
  byte; it supplies no adjustable rare event.
- Native hashes produce fixed 20- or 32-byte elements. ScriptNum arithmetic
  has a four-byte operand limit, and CLTV/CSV a five-byte limit. Passing a hash
  directly to these operators fails on length before any useful prefix test.
- `OP_IF` and `OP_NOTIF` require an empty vector or exactly `01` in Tapscript.
  They cannot inspect a random 20-byte digest. `OP_IFDUP` can expose
  `CastToBool`, but a 20-byte digest is false only for the all-zero or
  negative-zero strings: probability `2^-159` under the random-output model.
- Tapscript rejects invalid nonempty Schnorr signatures immediately. It has
  no Legacy-style `CHECKSIG OP_NOT` encoding gate. An unknown-size public key
  succeeds with every nonempty signature, so it supplies no rare condition.
- Equality against a complete digest is available; free truncation, byte
  slicing, and conversion of a hash to a small ScriptNum are not.

These observations are **inspected / unclassified** protocol reasoning, not
an execution result or an impossibility proof for all Tapscript programs.
See [BIP342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
and the pinned Core interpreter above. The handoff's ColliderScript bridge
remains an alternative, with its separately stated costs and obligations.
