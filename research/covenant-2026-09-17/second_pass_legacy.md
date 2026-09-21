# Second pass: length oracles and point-lock algebra

Question: can publicly known ECDSA keys, short known nonces, or related-key
checks extract enough transaction information to implement an exact-output
covenant below 2^64 honest work, including setup, against its creator?

Three specific candidates were investigated. None supplies a complete
construction. Candidate 1 yields a stronger restricted exclusion than simply
saying that Script cannot parse DER. Candidate 3 identifies the exact loss of
the point lock's cheap honest path when changing from the SINGLE bug to ALL.

## Candidate 1: adaptive DER-length comparisons using shifted public keys

Grant the construction an ideal fixed nonce `k0=1/2 mod n`, with the known
21-byte `r0=x(G/2)`. Under public signing key `d_j`, its scalar is

```text
s_j = 2z + 2r0*d_j mod n.
```

For a fixed-width r0, the complete signature item length is
`28 + DER_integer_length(s_j)`. After low-S normalization, a size at most 59
means

```text
min(s_j, n-s_j) < 2^247.
```

So an offset-key table really can act as an interval oracle: it tests whether
the same hidden transaction digest lies near one of a collection of public
centers. One could try to read a digest progressively, then compare it with an
allowed transaction claim.

The obstacle is stronger than a missing parser. Put `t=2z mod n` and
`b_j=2r0*d_j mod n`. For each fixed key, the length of
`min((t+b_j) mod n, n-((t+b_j) mod n))` has at most **64 interval boundaries**
over the cyclic scalar domain. The boundaries before translation are

```text
0, 1,
2^(8w-1), n-2^(8w-1)+1, for w=1,...,31.
```

Zero is separately marked as an invalid ECDSA scalar. For `m` distinct fixed
offset keys, the union has at most `64m` boundaries. Thus the entire vector of
all length answers has at most `64m` possible values. An adaptive decision
tree using only those keys cannot get additional information: all its answers
are already determined by that complete vector.

**This is O(log m) bits of capacity, not O(m) independent digest bits.**
Even granting fixed nonce enforcement for free, extracting b bits in this
restricted family needs at least `2^b/64` distinct offset keys. A full
128-bit fingerprint would require at least `2^122` keys, incompatible with
the setup budget as an explicit table. Supplying keys through an unchecked
algebraic formula would need a separate executable curve/key binding.

The [exact scalar-domain experiment](second_pass_legacy_lengths.py) enumerates
every interval boundary for equally spaced offsets; it is not Monte Carlo
sampling. For 32 keys it finds 2,048 intervals and only **1,025 different
complete length vectors**, at most about **10.0014 bits**. For 128 keys it
finds 4,097 vectors, at most about 12.0004 bits. The saved
[results](second_pass_legacy_lengths.json) cover every scalar, including the
invalid-zero cases, so discarding those cases cannot increase the bound.
These are support-size bounds, not claims that the information is uniformly
distributed or that the average entropy is that large.

Scope limits: all checks here share the same digest and the G/2 nonce, and
only public-key offsets vary. Different CODESEPARATOR digests or different
nonce multipliers are outside the proof. Different digests can supply
independent fingerprints, but still do not supply a script-enforced allowed
transaction representation. The script does not in fact prove use of G/2;
the original small-R security assumption remains an additional obligation.

Funding dependence:

```text
fixed offset-key set -> locking script -> funding txid -> z -> length answers.
```

Choosing the key offsets after observing z changes the locking script and
funding txid. Choosing an output-specific accepted answer vector after the
search has the same problem. A pre-fixed answer vector can be searched for
equally by the retaining creator using forbidden output transactions.

## Candidate 2: bridge a SINGLE-bug signature to an ALL signature

First grant a stronger primitive than currently available: two signatures
have equal `(r,s)` but select different sighash bytes. Under public keys
`d0G` and `d1G`, the constant bug digest z0 and an ALL digest z satisfy

```text
sR0 = z0 G + r*d0 G
sR1 = z  G + r*d1 G.
```

When r admits only one field x-coordinate, `R1=epsilon R0`, so

```text
z = epsilon*z0 + r*(epsilon*d0-d1) mod n.
```

This is an exact 256-bit scalar relation. With a fixed known small nonce r0
it becomes a fixed whole-hash target. With variable known nonces k, one can
generate r=x(kG) on one side and transaction hashes on the other, but a
generic independent-list match is a 256-bit meet-in-the-middle problem,
requiring roughly 2^128 entries/queries, not 2^64. These are generic work
estimates, not unconditional lower bounds.

More fundamentally, the granted primitive is absent: the sighash byte is
inside the complete signature stack item. A single reused item cannot be
both SINGLE and ALL, and `OP_EQUAL` compares that last byte too. Linking two
otherwise equal variable DER items would itself need a byte-level bridge.
Fixed `(r,s)` constants can be placed in two separately encoded items, but
then the ALL target is completely fixed and there is no signing search
advantage.

Funding dependence: fixed public keys commit before the funding txid and
ALL digest. Adapting a key to a favorable ALL digest afterward recreates the
funding fixed point. Leaving both keys free in the unlocking data permits
the creator to repeat the same adaptation for forbidden outputs.

## Candidate 3: reuse the existing three-check point lock with ALL

Use distinct fixed public scalars d and q with `C=d+q != 0`. The same raw ALL signature
is checked under d in context A, and under d and q in context B. With the
nonce ambiguity excluded, two different keys in context B force opposite
nonce points, hence

```text
2*zB + r*C = 0
r = -2*zB/C mod n.
```

The two checks under d give either

```text
zA = zB
```

or

```text
zA + zB + 2*r*d = 0
zA = (4*d/C - 1)*zB mod n.
```

Thus there is an exact related-digest condition, not a succession of cheap
interval checks. Moreover r is now determined by zB. Knowing d does not
provide the discrete logarithm of a curve point with x-coordinate r, so it
does not immediately provide a signature scalar s.

The repository's point lock chooses `C=-2*z0/r0`. Its cheap honest path has
`zA=zB=z0`, supplied by the out-of-range SINGLE special case, and therefore
`r=r0`. Moving to ALL replaces z0 by a real transaction hash and loses that
fixed known nonce. Finding an ALL transaction with zB=z0 is a whole-hash
preimage problem; keeping zB arbitrary leaves the related-hash/DLP obstacles.

This does not disprove the point lock's actual scalar-revelation property.
It excludes the proposed direct conversion of that cheap honest path into
an exact-output covenant. Public d and q chosen after the ALL digests again
change the funding script; free witness keys again admit creator replay.

## Evidence and reproducibility

The interval partition is `locally-reproduced`; its deployment class is
`unclassified`. It is a host scalar calculation, not an executable script
primitive, not a tapscript experiment, and not Core consensus validation.
Candidates 2 and 3 are inspected algebraic proposals with no complete script.
No hint-item, witness, opcode, or deployability metrics are claimed for them.

```sh
python3 research/covenant-2026-09-17/second_pass_legacy_lengths.py
```

Existing repository construction:
`src/signatures/pointlocks/three_check/README.md` and `mod.rs`.
Legacy DER and sighash semantics:
[Bitcoin Core 30.3, 49faec4f87f5cd19c88db01a82e5c68b087c8227](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp).
The equations, restricted interval bound, and application to these covenant
candidates are the analysis performed here.
