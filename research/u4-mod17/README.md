# Modulo-17 nibble experiment artifacts

The deterministic [report](metrics.json) was generated from the
[benchmark](../../examples/u4_mod17_benchmark.rs) on a branch based on
`bf9ee0b` (current `origin/main` at experiment start). Exact final fragment,
complete-leaf and serialized-data-witness SHA256 values bind each measurement
independently of repository documentation changes. The compiler and interpreter
pins are embedded-lockfile provenance emitted by the binary. The delivered
commit and final test results are recorded in the PR validation description;
this manifest deliberately avoids a self-referential commit hash.

The input generator is `x[i]=(7*i+floor(i/3)) mod16`, bottom to top. The leaf
compares the result with an independently computed conventional base-16 Horner
residue via `expected OP_EQUAL` and ends with one truthy item. No hints are
used; every batch has `n` data items coexisting at entry. Witness bytes include
CompactSize serialization but exclude leaf/control-block/annex. Fragment and
leaf bytes are separately recorded, with stack peak measured from the exact
policy-produced complete leaf and runtime witness.

The report uses the default strict tapscript helper, whose options require
minimal encodings and enforce the combined stack limit. The adversarial shared
suite additionally uses `TapscriptProfile::Consensus`, with minimal-number
policy disabled, to prove that script canonicality validation rejects aliases.
Both have synthetic empty transaction context and data-only budgets. There
are no signature or timelock operations. Execution is `unclassified`, evidence
is `locally-reproduced`; the arithmetic oracle is not independent consensus
validation. Static non-push operations are distinct from dynamic operations,
which the current driver cannot measure and records as null.

All measured scripts receive `CompileOptions::ALL` through the centralized
policy. The [forward baseline](baseline.rs) is comparison-only code, included
by both the benchmark and shared contract suite; it is not a public API.

Reproduce without refreshing other metrics:

```sh
cargo run --locked --example u4_mod17_benchmark > /tmp/u4-mod17-reproduced.json
cmp research/u4-mod17/metrics.json /tmp/u4-mod17-reproduced.json
cargo test --locked --lib arithmetic::u4::mod17
cargo test --locked --test u4_reduction_contract
cargo test --locked --test primitive_metrics u4_mod17_metrics_are_current
```
