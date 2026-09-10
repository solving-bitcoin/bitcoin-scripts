# Primary-source registry

The machine-readable registry is [`sources.json`](sources.json). Catalog records
refer to source IDs rather than embedding mutable URLs repeatedly.

Source classes include:

- Bitcoin consensus and script-version specifications;
- Bitcoin Core and execution tooling;
- local upstream implementation repositories and pinned dependency revisions;
- cryptographic standards and original papers;
- protocol papers and active upstream implementations.

A rolling branch is discovery evidence, not immutable reproduction provenance.
Before promoting a reported result, record the exact commit or document version
used by the reproduction.

The execution-resource audit uses `bitcoin-core-v30-resource-limits`, pinned
to v30.0 commit `d0f6d9953a15d7c7111d46dcb76ab2bb18e5dee3`.
`ExecuteWitnessScript` and `EvalScript` were inspected for entry and per-step
stack limits, including `OP_SUCCESSx` precedence. The associated local tests
reproduce wrapper corrections; they do not execute Bitcoin Core.

The separate `bitcoin-core-v30.3-regtest` source pins the executable oracle to
`49faec4f87f5cd19c88db01a82e5c68b087c8227` (v30.3). The
[Core differential experiment](../core-validation.md) records verified official
archive and binary SHA256 hashes, block acceptance and policy results for 24
complete Taproot spends. Its evidence is `differentially-validated` within that
fixture scope.

The resource-profile experiment uses `bitcoin-scriptexec-repaired-20260910` at
`4b7269a415f21be3fccee9730547f1426eb80326`, an immutable fork integration of
upstream PRs #18, #19 and #20. The Cargo patch applies to both the lab and its
stack-tracking dependency. The existing `bitcoin-scriptexec-locked` source
remains at `ba96bc2` for historical measurements, including skipped field
experiments; adoption does not rewrite that attribution. The
[support guide](../../src/support/README.md) records the new profiles, supported
scope, regression tests and acceptance criterion for returning upstream.

The current local interpreter uses `bitcoin-scriptexec-signatures-20260910` at
`702544c9a045ac4fc14846da6da6559e2b7cd9d1`. It retains those resource repairs,
adopts Sander Bosma's CODESEPARATOR fix (`4c9bf94`) with additional regression
tests (`474a6b6`), and adds unknown-key empty-signature handling (`f4e05a4`),
invalid-key/multisig errors (`2efd48f`) and SIGHASH_SINGLE error ordering
(`47e0806`). The [funded signature comparison](../tapscript-signature-validation.md)
preserves a `4b7269a4` baseline separately from the repaired integration.
Older catalog configurations and report artifacts retain their recorded pins.

The [checked PRINCE experiment](../prince-core-validation.md) combines the same
Core and interpreter pins with `bitcoin-script-locked` and the independent
`princev2-reference` C vectors at `0c6172dc`. Its three exact valid complete
spends are `policy-validated`. New Rust generator metadata comes from
`support::provenance`, using the lockfile embedded in the binary; the source
registry continues to describe immutable historical evidence.


The Fast Winternitz hash-choice comparison inspects Bitcoin Core **v29.0**
native SHA256/HASH160/HASH256 semantics (`bitcoin-core-v29-hashes`). Its local
compiled measurements use `bitcoin-script-locked` at
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`, including SHA256-pair fusion.
That Core source inspection is not a Core execution or policy reproduction.

The separate `bitcoin-script-unchanged-run-candidate` source records optimizer
commit `eb91d10de3e3adfbcc37c708924306dc9a7e58cd`, submitted upstream as PR #15.
The [compiler experiment](../negative-results/compiler-validation-runtime.md)
compares it against the retained `124b561e` dependency pin. This candidate is
not the compiler used for the catalog's published primitive measurements.

The default Preimage16 discussion uses `nist-hash-security-strengths` for the
distinction between collision, preimage, and second-preimage resistance. The
128-bit initial-secret exhaustive-search ceiling is a local inference from
the 16-byte secret space, before multi-target effects; the NIST table is not
a security proof for the custom Winternitz construction.

The 20-byte constant-sum Winternitz construction cites
`constant-sum-wots-2023` for the established encoding approach. Its mixed
radix selection, Bitcoin Script byte measurements, and whole-vector argument
for omitting individual upper bounds are local results. The paper is not a
security proof for this unkeyed native-hash implementation. The reversible
encoder has an independent Python reproduction in
[`src/signatures/winternitz/constant_sum/tests/vectors.py`](../../src/signatures/winternitz/constant_sum/tests/vectors.py).

Bitcoin Core v29.0 rejects `OP_PICK` indices outside the entire stack in
[`interpreter.cpp`, lines 759–769](https://github.com/bitcoin/bitcoin/blob/v29.0/src/script/interpreter.cpp#L759-L769).
That source inspection is distinct from the historical `ba96bc2` executor's
panic on some out-of-stack positive indices, repaired in the current `4b7269a4`
integration. The later v30.3 differential fixtures
confirm rejection for exact `OP_PICK`/`OP_ROLL` boundaries and the isolated
constant-composition selector; other primitive-specific indices are untested.

The fixed-composition construction uses `nist-dlmf-multiset-permutations`,
NIST DLMF §26.16 version 1.2.7 (2026-06-15), for exact multiset capacity.
Its key-pool verifier, parameter search and Script measurements are local results;
neither that counting reference nor the constant-sum WOTS+ paper proves this
custom unkeyed signature. Independent host vectors are in
[`constant_composition/tests/vectors.py`](../../src/signatures/winternitz/constant_composition/tests/vectors.py).
