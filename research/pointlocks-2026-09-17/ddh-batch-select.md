# Algebraic compression of a complete input-label vector

Question: can offchain data reduce the secret opening for a future 2048-bit
message to a few secp256k1 scalars, without an exponential table? The local
DDH batch-select experiment reconstructs arbitrary binary labels from one
scalar per block. At block width256, its raw opening is512 bytes and generation
takes696 ms median. **This is not a Bitcoin publication construction.** Native
binding and public malicious-setup verification remain absent. Substituting
separately extracted threshold shares for the aggregate key is demonstrably
unsafe with this bridge.

[Implementation](../../examples/pointlock_ddh_batch_select_probe.rs),
[benchmark runner](ddh_batch_select_benchmark.py),
[measurements/provenance](ddh-batch-select-benchmark.json),
[composition failure](../../knowledge/negative-results/ddh-batch-select-share-disclosure.md).

## Primary-source boundary

[AIKW, *Encoding Functions with Constant Online Rate*](https://eprint.iacr.org/2012/693.pdf),
38-page version dated2014-08-27, sections3.1–3.2, constructs a subset encoding
from key-and-message homomorphic encryption. Its DDH instantiation uses
ElGamal-style group masks and a summed scalar key; section3.5 discusses
blocking. [TinyLabels](https://eprint.iacr.org/2024/2048.pdf), revision2025-03-12,
sections2.1 and6, motivates batch selection and instantiates it over Ring-LWE.
Its reported parameter set has a56-KB ring-element key; that is not one
secp256k1 scalar, and its large-instance timings are not this setup benchmark.

The implementation below is a local affine two-label adaptation over
secp256k1, not the TinyLabels implementation. Source security statements do
not establish adaptive security, malicious setup validity, or native Bitcoin
binding for this adaptation. We test correctness and concrete failed wrappers;
we do not claim a new DDH security theorem or a complete128-bit-secure protocol.

## Local representation and exact correctness

For one block of b bits, choose secret scalars k0,k1,...,kb and private row
randomizers r_i. Publish K_j=k_j G and R_i=r_i G. Choose 128-bit labels
A_i^0,A_i^1 with one secret common XOR offset Delta. Embed each label as a
curve point L_i^v using even Y and x=(integer(A_i^v)<<16)+counter, where counter
is the first valid lift in0,...,65535. Decoding checks this canonical form.
Embedding exhaustion is an explicit error. No input-label point is published
in clear. Public SHA256 label hashes are only checks after decryption.

The public ciphertexts are

```
B_i    = L_i^0 + k0 R_i
D_ij   = k_j R_i                         when i != j
D_ii   = k_i R_i + L_i^1 - L_i^0.
```

For future bit vector y, the sender releases the single canonical scalar

```
k(y) = k0 + sum_j y_j k_j mod n.
```

For every row the receiver computes

```
B_i + sum_j y_j D_ij - k(y) R_i = L_i^(y_i).
```

Thus the recovered labels have exactly the ordinary free-XOR interface. The
receiver does not receive k0, individual k_j, row randomizers, both label
values, or the garbling seed. The test joins these recovered labels to the
existing actual garbled membership decoder and checks all256 eight-bit
inputs. The full2048-bit benchmark opens four complete messages: all zero,
all one, alternating, and a deterministic random fixture. These repeated
openings are correctness tests with public fixture secrets, **not a claim of
multi-use privacy**.

All production secrets would need real private entropy. The experiment's
domain-separated SHA256 fixtures are intentionally public. Setup generation
uses the retained r_i to compute k_j r_i G by fixed-base multiplication;
the independent opened audit recomputes the cells as k_j R_i with variable
bases. The row scalars are kept in a separate private structure.

## Measured full-message costs

Apple M5 Pro,15 logical CPUs,24 GiB RAM,macOS26.6.1 arm64; Rust release build,
15 requested workers, five samples per row. Width256 has only eight blocks
and therefore uses eight actual block workers. Each sample regenerates the
entire instance and performs an audit with all secrets. Source, executable,
Cargo.lock, benchmark runner and imported test-decoder hashes are recorded.
CPU/RAM were read separately with sysctl and supplied to the sandboxed runner.

| Block bits | Scalar openings | Raw message + scalar bytes | Public crypto payload bytes | Generation median | Opened audit median | Combined median |
|---:|---:|---:|---:|---:|---:|---:|
|16|128|4,352|1,419,392|37.51 ms|42.39 ms|79.97 ms|
|32|64|2,304|2,498,624|65.18 ms|81.05 ms|146.75 ms|
|128|16|768|8,985,104|332.73 ms|428.88 ms|762.78 ms|
|256|8|512|17,635,592|695.61 ms|890.47 ms|1,586.51 ms|

Combined medians are medians of per-sample sums. The width16 combined range
is77.38–92.13 ms; width256 is1,579.43–1,595.00 ms. Context initialization is
reported separately and added to the first combined sample in the JSON.
The raw opening is 256 message bytes plus32 bytes per scalar. Public payload
counts 33 bytes per group element, including an internal all-zero infinity
encoding where needed, plus two32-byte label hashes per bit. It excludes
dimensions, file/wire framing and any garbled circuit. Fingerprinting of the
result is outside generation/audit timing. A serial width32 control reproduces
the identical public-data fingerprint.

**None of the raw opening sizes are transaction sizes or vbyte claims.** No
Bitcoin signature, Script, input/output, authorization, or transaction is
included. Neither an all-secrets audit nor fast ciphertext generation is a
full-instance public setup benchmark. The report explicitly sets public setup
verification time to null.

## Two unimplemented bindings

1. A native opening must enforce `kG = K0 + sum_j y_j K_j` and actually reveal
   k, for the same authenticated message y. The prototype checks this equation
   offchain. Neither a spender-supplied aggregate point nor an ordinary
   signature proves that Bitcoin enforces the equation. Enumerating every
   possible block target merely reintroduces an exponential commitment table.
   Existing sum-key locks cannot simply be assumed to wrap these arbitrary
   message-dependent targets with efficient pre-funding setup.
2. Public setup verification must bind B,D to the intended labels and keys
   without disclosing decryption information. The test changes D_00 by a
   nonzero point. All key points and label hashes remain unchanged, public
   shape checks pass, and the valid aggregate key still satisfies its point
   equation. A message with y0=0 opens; one with y0=1 fails its label check.
   Detection after opening is not setup validation or a Bitcoin rejection.

There are three tested failed shortcuts:

- Disclosing r_i makes k_j R_i computable as r_i K_j; both labels of row i
  become public. This cannot turn the opened audit into a public check.
- Publishing relative row scalars r_i/r_j lets an off-diagonal cell supply the
  missing diagonal mask. One valid opening then yields alternative labels.
  Reusing one common row base is the special case ratio1.
- Publishing separately point-locked shares whose sum is k(y) exposes scalar
  coefficient differences. The next section gives an exact failure, even when
  all point commitments and ciphertexts were prepared honestly.

## Why the existing t-of-n opening cannot serve as the compressed key

For a fixed-weight selection of t>=2, the natural wrapper sets

```
x_i = k_i + a,     k0 = t*a,
X_i = K_i + K0/t.
```

Then an opening of the selected x_i yields `sum_selected x_i = k(y)`. Its
public point compatibility is algebraically checkable. However, two selected
shares x_i,x_j expose d=x_i-x_j=k_i-k_j. Since i!=j, D_ij=k_j R_i is public,
so the receiver obtains

```
k_i R_i       = D_ij + d R_i
L_i^1 - L_i^0 = D_ii - (D_ij + d R_i).
```

The valid selected label gives L_i^1. Subtraction and canonical decoding
therefore recover A_i^0 as well. Their XOR yields the global Delta. Every
other delivered label can now be flipped, exposing all alternative labels.
The test reproduces this for all70 four-subsets of an eight-candidate pool,
using only the public table, selected shares and delivered labels inside the
recovery calculation. Private fixtures are used only as expected outputs.

The common shift is forced within this additive wrapper: if
`sum_S x_i = k0 + sum_S k_i` for every t-subset and1<=t<n, exchanging one
index shows all `x_i-k_i` equal the same a, hence k0=t*a. Choosing different
independent shifts does not retain the required equation for all subsets.
Known index weights can be absorbed into the revealed x_i and do not fix it.
This does **not** rule out nonlinear encodings or a native mechanism releasing
only the aggregate key. The t=1 boundary does not give the tested pair attack.

## Evidence and next acceptance criterion

Evidence: **locally-reproduced** correctness, composition counterexamples and
timings; **inspected** algebra and source comparison. Deployment:
**unclassified**. No Script is generated or executed, so script/witness bytes,
hint counts, stack peaks, opcodes, native budgets and transaction vbytes are
not applicable to this offchain probe and must not be inferred as zero.

Eight focused tests pass, including imported decoder correctness. No unrelated
primitive tests or Core checks were run. Reproduce with:

```sh
cargo test --release --locked --example pointlock_ddh_batch_select_probe
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/ddh_batch_select_benchmark.py
```

If sysctl is sandboxed, pass the independently observed `--cpu` and
`--memory-bytes` values. The original goal stays open. The next useful result
must either enforce an aggregate-only native opening with a publicly valid
ciphertext setup, or supply a different compression that remains private when
its constituent point scalars are also revealed. The existing threshold bridge
cannot inherit DDH batch-select guarantees just by summing its openings.

The [linear-disclosure follow-up](ddh-linear-leakage.md) strengthens the
interface restriction: any extra scalar-linear function of `(k0,...,kb)`
outside the span of the intended aggregate gives an explicit recovery of
both labels in some row. It also extends the public-relative-row failure to
general known affine relations between row bases. Independently derived
hash-and-lift bases avoid publishing row logarithms, but do not supply public
ciphertext verification or native aggregate binding. The original timings
above are unchanged and do not measure that follow-up.

The [masked-audit analysis](ddh-masked-audit.md) further shows that disclosing
an informative row action can expose alternative labels even when its scalar
is hidden. Freely chosen mask points can instead absorb false table claims
in the tested fixed-challenge certificate. Its three deterministic tests
supply neither a public setup verifier nor a native aggregate lock.
