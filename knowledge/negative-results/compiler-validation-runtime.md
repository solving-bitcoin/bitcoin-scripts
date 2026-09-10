# Compiler runtime and erased resource probes

## Question and comparison boundary

Can the required non-field validation finish without reducing its input domains,
changing generated primitive code, or weakening the compilation policy? The
2026-09-10 investigation separates repeated compilation in test loops from
repeated work inside a single compiler pass. Compilation time is a host-tooling
measurement, not a Bitcoin validation cost.

The baseline compiler is `124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`.
The candidate is
[`eb91d10de3e3adfbcc37c708924306dc9a7e58cd`](https://github.com/BitVM/rust-bitcoin-script/commit/eb91d10de3e3adfbcc37c708924306dc9a7e58cd),
submitted as [upstream PR #15](https://github.com/BitVM/rust-bitcoin-script/pull/15).
The lab retains the baseline dependency pin and its 32 KiB compilation cutoff.

## Redundant unchanged-run searches

When a maximal fixed-stack-operation run has no shorter replacement, the
baseline optimizer solves the same dynamic program again at every suffix.
The candidate records that unchanged run's end for the current pass. Other
local rules still execute at every instruction; the record resets next pass.
Source instructions and prefix facts are immutable during that pass. Any
profitable suffix would also make the whole run profitable through unchanged
prefix edges, so the first unchanged result already excludes every suffix.

The deterministic fixture is a run of `OP_TOALTSTACK` instructions. Both
versions preserve its exact bytes. Symbolic-window query counts and diagnostic
release timings are:

| Operations | Baseline queries | Candidate queries | Baseline microseconds | Candidate microseconds |
| ---: | ---: | ---: | ---: | ---: |
| 64 | 18,876 | 638 | 24,764 | 440 |
| 128 | 82,588 | 1,342 | 100,129 | 864 |
| 256 | 345,180 | 2,750 | 430,984 | 1,704 |
| 512 | 1,411,036 | 5,566 | 1,404,572 | 3,371 |

Environment: Apple M3 Max, macOS ARM64, rustc 1.98.0
(`88d9e12ae`, 2026-08-18), release profile, rewrite tables warmed, one sample
per size, other validation running concurrently. Dispersion was not measured.
The timings are diagnostic; the regression asserts exact output and query
counts, with no timing threshold. This removes repeated symbolic dynamic
programming on unchanged runs; other compiler scans can still be quadratic.

At the candidate revision, generate the untracked lockfile, record its hash and
resolved versions, then run:

```sh
cargo generate-lockfile
cargo test --locked --workspace --all-features -- --skip fields::
cargo test --locked --release --workspace --all-features benchmark_unchanged_stack_runs -- --ignored --nocapture
```

All 66 upstream tests pass. Three new byte-equivalence groups also pass against
the baseline, while the query-count regression fails there. The local upstream
lockfile SHA256 was
`5d3391b600e50990bd7221a45c80fb4c657d54c28c81c7e6d1422b067cef5da8`
(including `bitcoin` 0.32.102); that upstream repository does not track the file.
Future resolution can differ, so compare the lockfile before treating a rerun
as the same dependency configuration.

An isolated lab checkout at `dad235161ef2b9a59e64ab344b79bcfd98f4d0a6`
with only the compiler source overridden reproduces all five active primitive
metrics without refreshing snapshots. Its 24 deterministic Core fixture
records are byte-identical to baseline JSON, SHA256
`c9b59372f57934e7bff761f4a35a000e0016779fc6ad263c6f23a3916303b50c`.
This comparison checks compiler output; Core itself was not rerun for the
candidate. Evidence is `locally-reproduced`; deployment is
`unclassified`, since these are compiler experiments.

## Constant cleanup erases the resource being tested

The former BLAKE3 maximum-altstack test embedded padding and a known message,
computed its digest, dropped all padding and digest outputs, then returned
`OP_TRUE`. Optimization can remove this unused computation. The resulting
execution cannot test the temporary peak of the source program.

A bounded reproduction uses the 64 literal nibbles of the empty-message
BLAKE3 digest, optionally preceded by 16 repetitions of
`OP_1NEGATE OP_TOALTSTACK`, followed by matching
`OP_FROMALTSTACK OP_DROP` pairs, 64 `OP_DROP`s and `OP_TRUE`.
Both baseline and candidate produce the same one-byte `OP_TRUE` (`51`):

| Padding items | Raw bytes | Raw SHA256 |
| ---: | ---: | --- |
| 0 | 129 | `a85479d65e7e618a4a2a3d31b643df129d25106d4c89e618c7efd8ff75df6f20` |
| 16 | 193 | `ed8f45ac02c146fa1749b708ae5e06d909dd7b8aebb0046f2f0bd25e5be665f8` |

The output SHA256 is
`4ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260`.
The exact 937-padding source is 3,877 bytes, SHA256
`7d8768b281d2edda9d97be4939fec446279ac46b49df4087f3b3ef7020082c81`.
The candidate reduces it to the same one-byte result, whose local execution
peaks at one item. The baseline release probe was stopped after 120 seconds
without producing output, so byte equality for that larger fixture remains
unconfirmed. The smaller baseline comparisons establish the test-design flaw
independently of the candidate's performance change.

These reproductions use zero witness data items and zero auxiliary hints;
padding and digest values are script constants. They are
`locally-reproduced`, deployment `unclassified`. Resource tests must measure the
final policy-produced script with an observable output boundary and disclose
all witness data present at entry. A source-level stack schedule is not a
measurement of optimized execution.

The repaired [BLAKE3 resource test](../../src/hashes/blake3/README.md) uses
canonical zero-message limbs and padding as runtime witness data, with zero
auxiliary hints in every case. All items coexist at entry. It compiles padding
staging and hashing together, keeps the 64 digest outputs, compares every
nibble with host BLAKE3, and checks combined main/alt depth. Normal fragment
completion has no execution error but deliberately fails the complete-leaf
clean-stack convention. The unchanged domain contains 34 limb/length pairs
and 56 executions: supported capacity and one-item overflow neighbors, or
zero-padding rejection for unsupported lengths. Per-execution script bytes,
witness bytes, complete data counts, explicit zero hints and peaks are printed
by the test with `--nocapture`; the README gives exact item/byte formulas.

```sh
cargo test --locked hashes::blake3::tests::test_maximum_alstack_element_calculation -- --exact --nocapture
```

The measured boundary is a fragment, evidence `locally-reproduced` and
deployment `unclassified`; no primitive generator, capacity formula, dependency
pin or metric snapshot is changed by the repair.

With this test repair, the full lab suite under the isolated compiler candidate
passes `cargo test --locked -- --skip fields::`: 409 unit tests, 18 integration
tests and six documentation tests pass; 24 existing tests are ignored and 143
field tests are filtered. Command wall time was 135.316 seconds in one debug
run with other work active, a diagnostic sample without dispersion. The
candidate and primary BLAKE3 source SHA256 was
`fef2cbb2c46bf5eb40f3a63d2b144b48997eec02d7aa4ef7e7e1e7b26c0549f0`.
This complete candidate run does not establish completion of a single broad
run under the lab's unchanged compiler pin.

The final focused test under the unchanged compiler pin also passes all
34 configurations and 56 executions: 185.57 seconds test time, 185.926 seconds
command wall time in one debug run. All 56 measurement rows match the candidate
exactly. The [recorded boundary report](../../tests/data/blake3-resource-boundaries.json)
contains final script sizes, serialized data-witness sizes, explicit hint and
entry counts, combined peaks, configuration parameters and source hashes.
Twenty-two valid probes peak at exactly 1,000; 34 invalid probes reject with
`StackSize`. No complete-leaf deployment classification follows from this
local fragment test. An earlier focused attempt stopped at its 180-second
limit after 23 matching rows; only the final completed run is counted as a pass.
