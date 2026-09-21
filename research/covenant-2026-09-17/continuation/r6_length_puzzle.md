# R6: short-signature search with modular wrap and nonce sign

Date: 2026-09-17. Question: what is the complete success set of the known-nonce
Binohash signature-length puzzle? Comparison boundary: one fixed sighash flag,
one fixed public key and nonce points ±G/2; count all fresh digest queries.

**The complete strategy gains almost two bits over the stated zero-prefix
strategy.** A 55-byte signature is available with probability `255/2^48`,
giving expected query work `2^40.00564656` in the uniform 256-bit-digest model.
For 59 bytes it is `255/2^16`, or `2^8.00564656` queries. Four actual Core
spends, one per accepted digest interval, verify the latter case. This is a
native ingredient, **not a complete covenant or a QSB hash-to-DER result**.

## Exact density

Let n be the secp256k1 group order. All scalars are public:

```
k = 2^-1 mod n
r = x(kG) mod n = 0x3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63
d = r^-1 mod n
P = dG
s_raw = 2(z+1) mod n
s = min(s_raw, n-s_raw).
```

Replacing s with n-s corresponds to negating the nonce point and preserves
its x-coordinate r. The smaller value also satisfies LOW_S. The fixed r
takes 21 DER bytes. Exactly L DER bytes for s, with L≥2, means

```
a = 2^(8(L-1)-1)
b = 2^(8L-1)
a <= s < b.
```

This interval already includes DER sign padding. The raw scalar can lie in
either `[a,b)` or `[n-b+1,n-a+1)`. Inverting the signature equation gives

```
z = s_raw/2 - 1                 for even s_raw
z = (s_raw+n)/2 - 1             for odd s_raw.
```

Thus four disjoint intervals of z modulo n accept: one near zero, two on
opposite sides of n/2, and one near n. The model also counts raw digests z+n
when below `2^256`. For the four recorded lengths, the lowest accepted z is
larger than `2^256-n`, so there are no extra copies. The exact accepted raw
digest count is `2(b-a)`. Writing j=32-L for bytes removed from a 60-byte
signature gives

```
p = 2(b-a)/2^256 = (255/256) * 2^(-8j)
E[queries] = 2^(8j) * 256/255.
```

| Signature length | s DER bytes | Exact probability | Expected log2 queries |
| --- | ---: | ---: | ---: |
| 59 B | 31 | 255/65,536 | 8.00565 |
| 58 B | 30 | 255/16,777,216 | 16.00565 |
| 55 B | 27 | 255/281,474,976,710,656 | 40.00565 |
| 54 B | 26 | 255/72,057,594,037,927,936 | 48.00565 |

This is an achievable expected query count for the specified signing
strategy under a uniform digest model, not a lower bound against all nonce
choices or a measured full-protocol cost. Native hashing and modular
arithmetic still cost work. Script does not enforce only the first interval.

The [Binohash paper, §§2.1.4 and 8.1.1](https://robinlinus.com/binohash.pdf)
describes a leading-zero strategy and assigns `8j+2` bits.
It omits the additional modular/sign intervals and accepts some shorter
values when the script asks for exact length. Its upper boundary also
includes `z=b/2−1`, whose s=b is one byte too long. Compared with that stated
query count, the gain is factor `255/64`, approximately 3.984; compared with
an exact-length-filtered search using only the first interval, it is exactly
factor 4. The inspected local PDF has
SHA256 `1be2b63034a86db1f9f4a35c7963248d307583723079ff25284a9fc4affee94a`;
the web version was retrieved on 2026-09-17. This correction does not by
itself recompute the full collision analysis or correlated pinning stages.

## Complete Core boundary vectors

The raw P2SH redeem script is

```
OP_SIZE <59> OP_EQUALVERIFY <P> OP_CHECKSIG
```

It has 39 bytes and three non-push operations. A fresh isolated Core 30.3
regtest chain funds five outputs with this same script. For the first four,
vary nLockTime from zero until the actual native ALL digest lands in the
chosen interval and its public signature has exactly 59 bytes. Inputs have
final sequence, so these locktimes do not prevent finality.

| Accepted interval | Locktime found | Candidate queries | Digest leading zero bits |
| --- | ---: | ---: | ---: |
| small positive raw s, even | 888 | 889 | 11 |
| small positive raw s, odd | 82 | 83 | 0 |
| large raw s, even, normalized | 5,098 | 5,099 | 1 |
| large raw s, odd, normalized | 607 | 608 | 0 |

All four are `policy-validated`, including three discarded by the zero-prefix
strategy. Three negative vectors reject: a valid 60-byte signature, reuse
after changing the output, and an empty signature. The output mutation
confirms ALL binding for a fixed signature; the public key still allows
fresh signatures for other outputs after another length search. Each positive
spends its own funded output, avoiding policy interference from replacement
fees. No production wallet or peer connection is used.

`complete-transaction:` each positive has one P2SH input, one P2WPKH output
and a 10,000-satoshi fee. Metrics: 23-byte funding locking script, 39-byte
redeem script, 100-byte scriptSig containing two pushes, one input data item,
**zero auxiliary hint items**, zero serialized witness bytes, **728 WU**.
Combined main-plus-alt stack peak is **3**, by complete-layout inspection;
altstack is empty. There are three redeem non-push operations and two P2SH
wrapper operations. No batch or hidden streaming hints are involved. The
single signature is present throughout its size check.

These are raw consensus-boundary vectors, not optimized library metrics.
Affine verification and serialization were compared with Core: evidence
`differentially-validated`. Core revision
`49faec4f87f5cd19c88db01a82e5c68b087c8227`, archive and binary hashes, complete
transactions, and all results are in the [JSON](r6_length_puzzle.json).
Host counts are `locally-reproduced`, deployment `unclassified` apart from
the specifically exercised Core cases. **No 55-byte PoW was mined.**

Reproduce with
`python3 research/covenant-2026-09-17/continuation/r6_length_puzzle.py --core`.
Six exhaustive small odd-order models cover modular reduction and raw digest
counts. Boundary checks cover all four intervals for each recorded length
using actual secp256k1 equations. No field-library tests were run.

An independent agent reproduced the host checks and derived the four interval
endpoints separately. It confirmed the counts, raw-digest reduction and
nonce-sign interpretation, then inspected the recorded Core outcomes.

## Scope of the external small-parameter experiments

The forum's [experiment report](https://delvingbitcoin.org/t/binohash-transaction-introspection-without-softforks/2288/3)
was followed to [aaron-recompile/binohash-experiments](https://github.com/aaron-recompile/binohash-experiments/tree/67550443a7783b087205c13a80a0df7788496e94),
commit `67550443a7783b087205c13a80a0df7788496e94` (2026-03-18).
Its parameter sweeps test a Python zero-prefix predicate, with a regtest
payment txid copied into a synthetic transaction. `verify_ok` calls that same
host predicate. Its scriptCode pushes ASCII `sig0`, `sig1`, etc., then OP_1;
it contains no CHECKSIG/CHECKMULTISIG or native PoW gate. Cross-checks compare
FindAndDelete and sighash with python-bitcoinlib. Those scoped serialization
experiments do not measure native enforcement of their target-bit parameter.
The README describes the implementation as educational and transaction-shaped.

This inspection is `inspected`; no external sweeps or wallet/node harness
were executed. The new Core vectors independently exercise the actual length
predicate. Neither construction supplies the missing reference verifier.
The R4/R5 `780555/2^65` SHA256-to-DER probability is a different predicate and
remains unchanged; applying this correction to those root formulas is wrong.
