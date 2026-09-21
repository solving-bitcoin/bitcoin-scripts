# Overnight research handoff: practical sub-100,000-vB point-lock publication

## User clarification: intended point-lock semantics

The research uses public protocol data and deliberately constructed research fixtures. The desired primitive is analogous to a hash lock, with algebraic properties: a public point T=tG locks a spend, and the opening scalar t is intentionally revealed or extractable from a successful spend. This intentional revelation is the functionality, analogous to revealing a hash preimage, not an attempt to recover an unrelated private key. The research question is how to implement this point-lock functionality efficiently under Bitcoin Script rules while retaining the specified publication and setup requirements. It does not ask for arbitrary discrete-log recovery from public points.

## Objective and non-negotiable scope

Find a construction publishing a signed **arbitrary future 256-byte message**
with **less than 100,000 vB total on-chain cost**, including creation and later
consumption of every publication output and the first P2TR helper output/input.
Retain the point-lock scalar-extraction property required by the BitVM-style
publication protocol. Ordinary signed data publication does not satisfy this.
The message is chosen after setup; it is not a fixed pre-funded message.

Setup must be noninteractive and purely algebraic, with **no setup ZKP**.
Target total setup time is **under 100 ms on a standard MacBook**; 1–2 seconds
is bad but marginally acceptable. Off-chain storage cost is irrelevant, but
computing tables still counts as setup. Record the actual MacBook model/build
and timing distribution when available; cloud timing is preliminary evidence,
not a measurement on a MacBook. Separate setup, funding-dependent preparation,
and per-message opening work. Moving an expensive search between these phases
is not a solution. Large off-chain tables are welcome if cheap to generate.

No complete construction meeting all these constraints has been established.
Do not substitute the conditional 128-byte result or a reduced-security fixture.
Do not treat absence of a construction as an impossibility proof. Persist with
constructive research, independent mathematical review, and reproducible tests.

## First reads

All paths are repository-relative. The uploaded repository contains the working
research, not only committed files. Preserve unrelated changes.

1. `AGENTS.md`, `knowledge/index.md`, `knowledge/bitcoin-script-reference.md`,
   `knowledge/cost-model.md`; run `python3 tools/kb.py search point-lock`.
2. `research/pointlocks-2026-09-17/practical-sub100-search.md`.
3. `research/pointlocks-2026-09-17/anchored-codesep.md` — newest unfinished lead.
4. `src/signatures/pointlocks/sum_key/README.md` and its `mod.rs`.
5. `research/pointlocks-2026-09-17/encoding-optimization.md`,
   `sub100-lookup.md`, `sub100-encoding.md`, `sub100-witness-algebra.md`.
6. Relevant records in `knowledge/negative-results/`, `knowledge/open-problems.md`,
   and `knowledge/catalog.json`. Read linked source before trusting a claim.

Historical notes sometimes retain the superseded “below 2^64 setup” objective.
The MacBook millisecond/second requirement above supersedes it. Some reference
prose also has historical sighash inaccuracies: use pinned Bitcoin Core/BIPs
and actual digest bytes. In particular legacy SINGLE's error digest bytes are
`01` followed by 31 zeros, interpreted by ECDSA as scalar **2^248**, not 1.

## Newest lead: anchored key with separated short-signature contexts

Read `anchored-codesep.md`,
`examples/pointlock_anchored_codesep_size_probe.rs`,
`examples/pointlock_anchored_native_probe.rs`, and
`anchored-codesep-size.json` in the research directory. The related
`pointlock_anchored_tau_size_probe.rs` / `anchored-tau-size.json` and
`anchor-context-size.json` are earlier/adjacent sizing artifacts; identify which
source generated each before comparing them.

For target T=tG, commit a 40-byte ECDSA signature tau=(r,1,ALL), with r=x(T)
and unsigned 32-byte DER r. Public setup checks this relation and encoding;
r>p-n excludes the extra r+n recovery lift. Verify tau under witness-supplied
compressed P at its actual ALL digest z0. This forces
`P=(±T-z0G)/r`. Verify d exact-60-byte signatures under that same P, each after
its own executed CODESEPARATOR. Honest opening knows P's scalar and uses G/2
as nonce. Alternative standard sighash modes may be needed for exact length;
complete availability and timing still need verification.

If any short signature uses G/2, P's scalar, and therefore t, is extractable.
Repeated r at distinct reduced digests likewise permits nonce-reuse extraction,
trying both nonce signs. **The case where all short signatures use different
unknown nonces remains unproved. Repetition is not itself a work-factor proof.**
Consider malicious setup, adaptive transactions, all accepted sighash modes,
and possible equal digests. Exact length does not force the intended nonce.

Current serialization-only screens, including creation and spending:

| Short checks d | Pools | Selection | Total vB | Status |
|---|---:|---|---:|---|
| 3 | 99 | 5-of-48 | 72,740 | Placeholder signatures/keys |
| 4 | 109 | 5-of-38 | **83,880** | Placeholder signatures/keys |
| 5 | 115 | 4-of-50 | **93,085** | Placeholder signatures/keys |
| 6 | 152 | 3-of-42 | 107,268 | Above goal; spend also over policy weight |

All capacities exceed 2048 bits. For d=5, creation=5,056 vB, spend=88,029 vB;
script/pool=1,362 bytes, witness/pool=2,894 bytes, 195 non-push ops,
4 hints and 32 entry data items per pool, analytical combined-stack bound 88.
Across separate input executions: 460 hints, 3,680 entry items, plus one witness
script per input. These are **locally-reproduced sizing, unclassified deployment**,
not valid native publication transactions or a security proof.

The native single-anchor fixture verifies ECDSA equations with rust-bitcoin
sighashes and libsecp256k1 but fails local execution at a short CHECKSIG.
Pinned interpreter `702544c` appears to start SegWit-v0 scriptCode at the
CODESEPARATOR itself; BIP143 starts after it. This is a **suspected interpreter
discrepancy**, not yet Core differential evidence. `anchored-native-local.json`
is empty after the assertion failure; do not count it as a successful report.

## Validated baseline and exact algebra

The sum-key lock checks one signature under distinct P,Q, with length >57:
`SIZE 57 GREATERTHAN VERIFY DUP <P> CHECKSIGVERIFY <Q> CHECKSIG`.
For their actual common digest z, the recovery nonces are opposite, giving
`T=P+Q=(-2z/r)G`; thus extract `t=-2z/r mod n`. Length >57 excludes r+n ambiguity.
The standalone script is 76 bytes. Same-digest and distinct-key conditions are
essential. Common-G setup chooses known nonce k, sets r=x(kG),
`t=-2C/r`, `P=(t-1)G`, `Q=G`, `s=(C+r)/k`, C=2^248.
This jointly generates cheap independent labels; it is not a cheap common-G
opening method for arbitrary existing T.

The full arbitrary-256-byte fixture uses 180 four-of-seventeen pools plus three
three-of-eighteen pools: 183 P2SH outputs, 3,114 candidate points, 729 reveals.
Capacity is 2048.03153 bits. Core 30.3 accepted and mined creation and two spends:
**5,967 + 99,065 + 80,114 = 185,146 vB** actual; worst-case sizing 185,432 vB.
All 729 scalars were independently extracted and the exact 256 bytes recovered.
Evidence: **differentially-validated**, **policy-validated** for this fixture,
not a complete BitVM challenge/refund/input-set-binding protocol.

Artifacts: `publication_core_check.py/.json`, `publication-selection.json`,
`publication-transactions.json`, `sum-pointlock.md`, `sum-lookup.md`,
`sum_lookup_core_check.json`; builders `examples/pointlock_publication_probe.rs`
and `examples/pointlock_sum_lookup_probe.rs`.

## Boundaries already established — avoid rediscovering them

- **Explicit legacy table floor:** even free opcodes/framing and ideal 58-byte
  signatures give >111,573 vB continuous relaxation for 2048 bits when each
  label costs a 21-byte HASH160 entry plus signature/key opening. Measured
  71-byte signature relaxation >119,403 vB. This bounds that explicit family,
  not all Bitcoin constructions. See `sub100-lookup.md`, `sub100-encoding.md`,
  `sub100-table-bound.txt`, negative result `explicit-point-table-size-floor.md`.
- **Rejected windowed small-R:** 39,396 vB sizing needs about 2^63.14 SHA-256
  compressions and lacks a complete alternative-nonce extraction bound.
  User explicitly rejected this setup cost. The actually Core-validated
  cap59 40,656-vB fixture weakens the intended constraint; it is not a solution.
  Read `windowed-publication.md`, `windowed-native-validation.md`,
  `windowed-small-r-review.md`, negative `windowed-pointlock-setup-cost.md`.
- **128-byte conditional result:** 92,706 vB actual works for 128 bytes, with
  possible BN254 compressed-proof integration. It does not carry an arbitrary
  256-byte message; user never approved changing that scope.
  See `conditional-proof-compression.md` and `conditional128-*` artifacts.
- **Variable cardinality:** optional reveals can be erased by a third party;
  other inputs' ALL signatures do not commit those scriptSigs/witnesses.
  CSV repair is conditional on unavoidable authorization binding sequences,
  introduces maturity, and still costs ~174,441 vB. See negative
  `variable-pointlock-subset-malleation.md` and `sum_csv_core_check.json`.
- **HASH160:** malicious setup may prepare colliding valid keys/signatures;
  the assumption is not merely preimage resistance. Generic collision work
  is ~2^80, not 128-bit binding. ECDSA success does not automatically fix it.
- **Native SegWit circularity:** the outpoint commits the funded script even
  if CODESEPARATOR excludes a key prefix. BIP143 SINGLE has no constant-error
  digest. Dynamic recovered-key approaches must solve honest opening as well
  as extraction. Taproot NUMS internal key alone does not rule out malicious
  setup choosing a known-secret tweaked output key and bypassing the leaf.
  See `sub100-witness-algebra.md`.
- **Implicit endpoint graphs:** odd unicyclic graphs cheaply prepare E=V
  labels. Dense graphs require compatible inverse-x nonce relations; public
  linear closure lets a revealed spanning tree derive other edges. Cheap
  sparse graphs do not meet the byte target. GLV orbit/±nonce reuse does not
  supply independent labels. See `endpoint-graph-search.md/.py/.json` and
  `compact-authentication-graphs.md`.
- **Linear-projection alphabet:** cheap off-chain secret-sharing-style labels
  can represent many messages, but Script must bind the chosen coefficients
  and the resulting point. That missing on-chain operation cannot be replaced
  by an off-chain decoder. See `practical-sub100-search.md`.
- No CAT/SPLIT means ordinary Merkle authentication or packed-key reconstruction
  is not free. Hash-chain WOTS needs a public link between scalar point labels
  and hash preimages. HORS hashing the payload needs mandatory on-chain binding.
  Public affine scalar relations can make one reveal open other messages.

## Recommended next work and completion gates

1. Independently assess the anchored candidate's missing extraction argument.
   State exactly what every accepted transcript guarantees and what assumption
   replaces exact extraction, if any. Do not promote honest execution to proof.
2. Reproduce the small native CODESEPARATOR fixture against pinned Core,
   independently inspect BIP143 suffix boundaries, and distinguish an
   interpreter defect from a generator defect. Do not silently patch dependency
   checkouts or use a failed local report as consensus evidence.
3. If the mathematical argument remains plausible, build actual selected-table
   witnesses and fully signed creation/spend transactions, test malformed
   selections/keys/signatures/sighash variants, and extract the original message
   from accepted transaction bytes. Account for complete framing and policy.
4. Benchmark setup and opening in release builds. Record total candidates,
   retries, hash/EC operations, table generation, and public validation work.
   No big grinding budget is acceptable. Off-chain storage itself is free.
5. If this lead fails, seek a genuinely different authenticated implicit-label
   mechanism; record the precise negative result rather than retrying byte-only
   tuning inside the already bounded explicit legacy family.

Use `ScriptCompilation::compile_with_policy()` consistently. Report script,
witness, hints, combined stack peak, opcodes/sigops, full TX weights and rounded
vbytes, execution context and immutable versions. Local default helpers can
use tapscript/unlimited checks; local CHECKMULTISIG is unimplemented. Core
validation is required for claims about these native ECDSA publication scripts.

Focused checks after relevant changes only:

```sh
python3 tools/kb.py validate
cargo test --locked --lib signatures::pointlocks::
cargo test --locked --test pointlock_core_vectors
cargo test --locked --test primitive_metrics pointlock_metrics_are_current
```

Do not run unrelated tests, whole-repository tests, fields tests, or regenerate
all metrics. For a new probe use the corresponding `cargo run --locked --release
--example ...`; inspect its arguments first and write fresh reports under new
names. Existing `publication_core_check.py` demonstrates full Core validation;
`windowed_native_core_check.py` demonstrates actual BIP143 validation.
Core harnesses use fresh isolated regtest, wallets and networking disabled.
Core's local cache path `/private/tmp/covenant-core-30.3` is machine-specific;
the cloud may need the pinned binary/source, not that literal Mac path.

## Primary sources and immutable validation provenance

- Core 30.3 commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`:
  https://github.com/bitcoin/bitcoin/tree/49faec4f87f5cd19c88db01a82e5c68b087c8227
- BIP143: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
  (also consult BIP66/141/340/341/342 as relevant; pin versions in new reports).
- User's interactive Schnorr-adaptor publication reference:
  https://gist.github.com/RobinLinus/0fc7405ad7485c35465efb7996a7b014
  and revision `d68af6b8461ea7bfa24ff0ed4f7738a11bd1d59a`.
- Glock: https://eprint.iacr.org/2025/1485 ; related implementation
  https://github.com/BitVM/garbled-snark-verifier/pull/69 (merged `6d9b725`,
  change `a897c6e`, `src/cac/adaptor_sigs.rs`). Interactive adaptor setup is a
  different assumption; do not import its low byte cost without its transcript.
- Binohash: https://robinlinus.com/binohash.pdf . A coordinate work estimate
  is not automatically a bound for total DER length with adaptive digests.
- Historical private-key-locked transactions:
  https://eprint.iacr.org/2016/1184.pdf ; its OP_AND mechanism is unavailable
  on current Bitcoin.
- ColliderScript/ColliderVM/PQB and earlier covenant search are indexed in
  `knowledge/catalog.json` and `research/covenant-2026-09-17/`; consult them
  rather than assuming they have not been considered.
- Historical compiler pin `124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`, interpreter
  `702544c9a045ac4fc14846da6da6559e2b7cd9d1`. Fresh reports must use actual
  `Cargo.lock` provenance rather than blindly copying these historical pins.

A successful handoff result must distinguish a proven construction, a fully
validated honest fixture, a conditional candidate, and an unresolved problem.
Do not claim the target achieved until all its requirements have evidence.
