# Research workflow

## 1. Frame the question

Choose a primitive class, exact semantics, execution class, and optimization
objective. Record hard limits such as live protocol stack, message length,
number of repeated uses, whether witness hints are allowed, and the available
hint-item budget under the 1,000-item combined stack limit.

## 2. Search the atlas

Search the catalog by class and technique, read comparison pages, then inspect
negative results and open problems. Search the source tree only after the
knowledge layer identifies relevant representations and terminology.

## 3. Establish provenance

Register primary sources in `references/sources.json` using immutable document
versions or commits where possible. Distinguish a source's reported metric
from a locally reproduced metric.

## 4. Reproduce

Use deterministic vectors. Prefer a reference implementation and a script
execution test. Record the exact inclusion boundary from `cost-model.md` and
the execution environment. Preserve raw vectors or a deterministic generator;
large generated scripts should be reproducible from hashes and parameters
rather than committed repeatedly. For a hinted primitive, record exact
per-invocation and cumulative batched hint-item counts, serialized hint bytes,
the complete witness/data item count, and the measured combined stack peak.

## 5. Attempt falsification

Test malformed encodings, boundary values, wrong hints, non-canonical numbers,
over-limit stacks, invalid points, subgroup failures, key reuse, and any
assumption made by the caller. A success-only vector is insufficient evidence
for a verifier.

## 6. Compare and compose

Update the relevant Pareto table. Evaluate coexistence with the surrounding
protocol state and account for setup reuse. For hinted constructions, model all
hints that coexist at script entry and do not estimate repeat capacity from the
hint count without operands, tables, intermediates, outputs, and unrelated live
state. Map the primitive into a complete protocol dependency page before making
deployment claims.

## 7. Record the frontier

Document dominated or failed attempts and add remaining falsifiable questions
to `open-problems.md`. Update `as_of`, run `python3 tools/kb.py validate`, and
run the relevant Rust tests.

## Automated checks

The [research validation workflow](../.github/workflows/knowledge.yml) runs
formatting, knowledge validation, all Python harness tests, the non-field Rust
suite, and the resource, signature and checked-PRINCE Core experiments in
separate jobs. Broad Rust runs retain `--skip fields::`; field arithmetic is
opt-in. Host dev/test optimization is enabled without changing debug assertions
or the repository's Script compilation policy. Actions use immutable commits,
and downloaded Core archives are checked against the pinned release manifest.
Fresh Core reports are uploaded as CI artifacts; committed historical reports
are not overwritten. CI availability and a configured workflow are not evidence
that a particular remote run passed.

For new Rust reports, use `support::provenance::{interpreter, compiler, stack}`
to record the Git packages resolved in the binary's embedded lockfile. Missing,
ambiguous, malformed or non-Git identities fail explicitly. A Python harness
that invokes Cargo should also compare the reported identities with
`cargo metadata --locked` before running its oracle.
