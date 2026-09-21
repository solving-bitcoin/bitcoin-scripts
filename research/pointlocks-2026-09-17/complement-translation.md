# Threshold complements instead of one row per subset

Question: can four extracted scalars deliver the garbled input labels for a
4-of-50 choice without enumerating all 230,300 subsets? **Yes for an honestly
prepared translation.** The implementation uses 2,450 encrypted shares per
pool and evaluates an actual garbled membership-to-rank decoder. Across all
115 pools, generation plus an audit with every secret disclosed takes
**72.64 ms median**, including the per-pool garbled decoders.

This is useful progress on setup cost, not a complete point-lock solution.
The audit is **not public setup verification**. Binding maliciously prepared
ciphertexts and garblings remains unresolved, as does general point-lock
extraction. Nothing here strengthens the 98,706-vB direct candidate's security.

[Translation source](../../examples/pointlock_complement_translation_probe.rs),
[garbled decoder](../../examples/pointlock_membership_decoder.rs),
[benchmark runner](complement_translation_benchmark.py),
[measurements and provenance](complement-translation-benchmark.json).

## Label delivery

Use the existing independent candidate scalars x_i and points X_i=x_i G.
For one garbling instance, choose a secret random odd 128-bit free-XOR offset
Delta. Derive the one-label A_i^1=KDF(pool,i,x_i), truncated to 128 bits, and
set A_i^0=A_i^1 XOR Delta. No raw zero-label is public. Publish a 256-bit hash
of each label, for checking a delivered label after opening.

For every candidate j, independently choose a degree-three polynomial f_j over
GF(2^128) with constant term A_j^0. Use distinct nonzero evaluation positions
1,...,50. For **i != j only**, publish the 128-bit ciphertext

```
C[i,j] = f_j(i+1) XOR PRF(x_i, pool, i, j).
```

The implementation uses a domain-separated BLAKE3 keyed XOF to supply a sender
row's pads. It stores no diagonal ciphertext C[j,j]. Field representation is
little-endian polynomial basis modulo X^128+X^7+X^2+X+1. The degree-three
coefficients other than the constant must be independently sampled in a real
setup. All program randomness is deterministic, publicly known test data.

Let S be the four distinct selected indices whose scalars were extracted.
For j in S, directly derive A_j^1 from x_j. For j outside S, decrypt four
shares C[i,j], i in S, and interpolate f_j(0)=A_j^0. Thus the evaluator obtains
one label for every one of the 50 membership bits, not both labels for the
selected candidates. The opening routine only receives a public view of the
points and label commitments, the ciphertexts, and the four supplied scalars.
The generator's full secret state is retained separately for the benchmark.

This uses the threshold property of
[Shamir sharing](https://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareASecret.pdf)
and the common-offset relation of
[free-XOR garbling](https://encrypto.de/papers/KS08XOR.pdf).
It is a symmetric-encryption bridge with an algebraic sharing component;
it does not establish the required public algebraic setup check.

## Why the diagonal must be absent

For a selected j, the evaluator can decrypt only three shares of f_j:
those indexed by S excluding j. A degree-three polynomial with any chosen
constant can fit those three shares. Explicitly, adding

```
c * product_{i in S, i != j} (X + (i+1))
```

preserves every disclosed share and, by choosing c, changes the constant to
any desired value. The test constructs these alternative polynomials for
several constants. This is an exact information-theoretic statement about
the disclosed shares alone. Public label hashes, encrypted shares, and the
subsequent garbling additionally require computational assumptions.

Storing the missing diagonal would disclose the fourth share for a selected
j. Then the evaluator would learn both A_j^0 and A_j^1, obtain Delta, and
flip every garbled input label. A focused negative test reproduces that leak.
Publishing all zero-labels would have the same defect; the new construction
specifically avoids that earlier shortcut.

The conditional honest-setup argument uses independent scalar secrets, a
PRF/KDF assumption despite their public curve commitments, preimage-resistant
label commitments, and the usual random-oracle/correlation assumptions for
free-XOR garbling. The reference uses BLAKE3 for these roles; tests do not
prove those assumptions. Recovering an unselected scalar or enough unknown
pads is still outside the intended evaluator's information. Learning full
polynomials for unselected j reveals some PRF outputs, not their unknown
sender keys, under the stated PRF model. The 128-bit labels and 127 random
bits in Delta do not imply an end-to-end 128-bit claim: multi-target effects
and the existing HASH160 setup-binding ceiling still apply.

## Actual garbled decoding

The 50 membership labels feed a Boolean circuit that maintains a one-hot
counter for 0,...,4 selections. It accumulates

```
sum_{j=0..3} C(49-selected_index[j], 4-j)
```

and returns `C(50,4)-1-sum`, the existing lexicographic subset rank, plus an
exact-weight-four validity bit. The output is 18 rank labels and one validity
label per pool. Input order does not create extra encoded messages: the
membership set determines the rank.

XOR gates have no ciphertext table. AND gates use four 16-byte rows, indexed
by the two input labels' permutation bits, with domain-separated gate hashing.
Internal zero-labels come from a **private garbling seed**; only the required
single constant-wire label is published. The evaluator object contains output
label hashes, not both output labels or the seed. Different private seeds
would be needed for different unopened garblings. This is a deliberately simple
reference circuit, not a claim of optimal gate count or a malicious-garbler
proof.

All 256 eight-bit inputs are exercised in a reduced decoder, including every
one of its 70 valid four-element subsets. The validity bit agrees with the
actual weight and every valid rank agrees with an independent combinatorial
formula. The full native-record path evaluates all 115 actual 50-bit garbled
decoders, checks all output labels, reconstructs the existing mixed-radix
integer offchain, and obtains the original 256 bytes.

The subsequent [total message decoder](total-message-decoder.md) implements
the global mixed-radix stage as a garbled circuit, with an explicit modulo
2^2048 rule for every complete valid codeword. Its composed native-record
path produces 2,048 message labels and a global validity label. Complete
translation/decoder generation takes 341.82 ms median and an all-secrets audit
348.66 ms; their combined median is 701.05 ms. Those are new measurements with
a wider boundary, not a replacement of the historical timings below. The
BitVM3 verifier and public malicious-setup checks remain unimplemented.

## Measured full-instance boundary

Apple M5 Pro, 15 logical CPUs, 24 GiB RAM, macOS 26.6.1 arm64; Rust release,
15 workers, five samples. Sources, executable, Cargo.lock, benchmark runner,
and cached Core report have SHA256 provenance in the JSON. All tables are
actually generated and retained in RAM. Worker startup and allocation are
inside the timers; no interpolation or lookup cache is reused across samples.

| Quantity, all 115 pools | Result |
|---|---:|
| Target points | 5,750 |
| Opened scalars | 460 |
| Recovered one / zero labels | 460 / 5,290 |
| Encrypted 128-bit shares | 281,750 |
| Encrypted-share bytes | 4,508,000 |
| Input-label commitment bytes | 368,000 |
| Target-point bytes | 189,750 |
| Decoder AND / XOR gates | 555,795 / 672,520 |
| Decoder ciphertexts, constant labels and output hashes | 35,712,560 bytes |
| Decoder output labels | 2,185 |

The displayed cryptographic payload totals 40,778,310 bytes including target
points. Fixed decoder topology, host object overhead, private generator state
and file-format framing are outside that byte total. Offchain storage is not
the optimization objective. The previous explicit table alone was
7,627,536,000 bytes. The new representation grows as n(n-1), not C(n,4).

| Timing | Median | Minimum–maximum |
|---|---:|---:|
| Points, labels, polynomials, field preparation | 11.62 ms | 11.40–18.64 ms |
| Encrypted-share generation | 0.98 ms | 0.96–1.25 ms |
| Garbled per-pool decoder generation | 27.00 ms | 26.20–29.78 ms |
| Complete generation | **39.42 ms** | 38.80–49.67 ms |
| Audit with every secret disclosed | **33.22 ms** | 31.97–37.13 ms |
| Generation plus that audit | **72.64 ms** | 70.77–86.80 ms |

The first combined sample takes 86.80 ms. The separate serial opening check
for two subsets in each of the 115 pools, including garbled evaluation, takes
133.49 ms median. It is not setup. The cached native-record evaluation is
outside the setup timers. Table and complete-decoder fingerprints agree
across every sample.

Generation includes the same target rejection sampling as the native fixture;
the audit repeats point/scalar checks, KDF/label/polynomial consistency checks,
all ciphertext generation, and all garbled decoder generation. It needs every
scalar, polynomial coefficient and private garbling seed. **Public setup check
time is missing, represented as null in the report.** Point-lock script
construction/checking, full garbled verification, VSS, multiple garbling
copies, process startup, compilation and network/disk transfer are excluded.
Do not add this timing mechanically to an earlier setup benchmark: their
point generation overlaps and the required public check is still absent.

No Bitcoin script or transaction changes in this experiment. There are zero
additional onchain witness hints or items. The linked direct fixture retains
four hints and 33 entry items per input, 460 hints and 3,795 entry items across
115 independent stacks, and its measured 83-item combined peak. Its 98,706-vB
size is a cached honest-execution measurement, not a new Core run or the size
of a now-complete protocol. This experiment's evidence is
**locally-reproduced**, deployment **unclassified**; its native input records
have their separately documented Core evidence.

## What still prevents a solution

A malformed encrypted share can leave every public point and intended label
hash unchanged while causing a later opening to fail. The negative test flips
C[0,4]: opening {0,1,2,3} fails, while an opening not using sender row 0 still
succeeds. Thus checking a few openings does not certify all future messages.
Post-opening label hashes detect the error but do not reverse the accepted
Bitcoin publication. Circuit correctness against a malicious garbler also
needs public verification or a complete protocol argument.

An opened audit cannot simply be reused as cut-and-choose across copies that
share these point scalars. Disclosing every x_i for one audited copy would
also unlock the others. The referenced VSS approach addresses a different
multi-copy opening interface; its cost and binding have not been supplied by
this single-instance experiment.

A tempting public-algebraic repair is to change to the secp256k1 scalar field
and replace PRF pads with public affine masks:

```
c[i,j] = f_j(i+1) + alpha[i,j] * x_i mod n.
```

Coefficient-point commitments would allow public checking of each equation.
But reusing the x_i creates a public linear system. The
[counterexample](complement_linear_mask_counterexample.py) with eight
candidates and threshold four has 56 equations in 40 unknowns and full rank.
It recovers **all eight point scalars and all 32 polynomial coefficients**
from public scalar ciphertexts, with no discrete-log computation. The
[output](complement-linear-mask-counterexample.json) records the result. This
rejects this specific affine-mask repair; it is not an impossibility theorem
for every algebraic bridge or coefficient choice.

The [scalar-linear obstruction](complement-linear-obstruction.md) strengthens
this negative result: for n>=t+2, no direct scalar-linear complement layer can
meet all three reconstruction/privacy requirements, even with a different
rank-deficient coefficient choice. That theorem explicitly excludes the
current PRF-encrypted layer and nonlinear or group-valued alternatives.

The [general subset-classification follow-up](shared-vector-gates.md) extends
the boundary beyond membership bits: no scalar-linear decoder, even with
correlated candidate forms, can give exactly one of two fixed hidden labels
for every 5-of-54 subset while hiding extra candidate scalars. Its N-1-of-N
lookup is constructive at the tight boundary. These results do not apply to
the PRF-encrypted computation measured here or provide its public setup check.

Remaining acceptance criteria are public malicious-setup binding of all
shares and garblings, one-opening label privacy under the full protocol,
all-consensus point-lock extraction, composition of the now-implemented
message decoder with the full garbled verifier, compulsory pool participation
and challenge-graph integration,
and measurements of the complete resulting setup. They remain mandatory.

```sh
cargo test --release --locked --example pointlock_complement_translation_probe -- --skip field_and_interpolation_boundaries
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/complement_translation_benchmark.py
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/complement_linear_mask_counterexample.py
```
