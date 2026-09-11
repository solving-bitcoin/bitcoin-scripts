# Ternary mixed-hash integer path

- **Question:** Can a canonical three-valued mixed-hash path authenticate a
  small integer for ternary protocol state?
- **Hypothesis:** Explicit canonical trit checks make the representation safe
  to compose, even if its 31-bit integer cost is dominated by the four-way
  path.
- **Catalog record:** `commitment/ternary-hash-path-integer`
- **Comparison objective:** Compare a 31-bit, 32-byte-preimage ternary path
  with the existing binary and four-way paths under the fragment-only boundary.
- **Repository commit:** record the merge commit in the PR that adds this
  experiment.
- **External source revisions:** `bitcoin-script-locked`, `bitcoin-scriptexec-locked`,
  BIP 342, and FIPS 180-4 as catalog references.
- **Interpreter and execution class:** centralized policy compiler; focused
  correctness tests use the strict local tapscript-context executor; deployment
  is `unclassified`.
- **Deterministic vector:** 32 bytes of `0x42`, value `0x12345678`, 31 bits.

## Reproduction

```sh
cargo test --locked ternary_hash_path --lib
cargo test --locked --test primitive_metrics ternary_hash_path_metrics_are_current
cargo run --locked --example ternary_hash_path_benchmark
```

## Measurement boundary

The verifier and base-3 reconstruction are included. Input pushes, terminal
predicates, transaction framing, and unrelated protocol state are excluded.
The witness includes all 20 canonical trit items, the 32-byte preimage, and
Bitcoin witness serialization framing. There are zero auxiliary hint items.

## Results

The 31-bit representative is 924 policy-produced script bytes, 63 serialized
witness bytes, 21 witness items, and a 24-item combined local peak. It is
larger than the four-way path for this integer objective but preserves a native
three-valued selector. The strict tapscript executor reports
`executed_opcodes=0` because its legacy opcode counter is unavailable in
tapscript; the experiment therefore leaves that metric unclaimed. No raw
private seed is part of the public fixture.

## Falsification attempts

Focused tests cover all codewords, integer boundaries, wrong openings, padded
encodings, and an out-of-range trit. The local strict executor accepts the
valid fixtures and rejects those malformed witnesses. Bitcoin Core differential
validation and policy testing remain open.

## Conclusion and knowledge updates

The hypothesis survived the local correctness boundary. The implementation,
metrics, comparison, catalog, negative result, and open problem are updated;
the construction remains experimental and unclassified for deployment.
