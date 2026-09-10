# Normalized cost model

Every measurement must state its boundary. A bare number without an inclusion
boundary is not comparable evidence.

## Primary metrics

- **Locking script bytes:** serialized generated fragment or complete leaf, as
  explicitly stated. Input pushes and terminal predicates are excluded unless
  `includes` says otherwise.
- **Unlocking witness bytes:** consensus serialization of the complete witness
  item vector being measured, including item count and CompactSize lengths.
- **Hint stack items:** exact number of mandatory auxiliary witness items for
  the stated boundary. Report the per-invocation count and the cumulative count
  for every repeated or batched configuration; distinguish hints from operands
  and other witness data, and state whether all hints coexist at script entry
  or a narrower fragment boundary is being modeled. Hint-item count, serialized
  hint bytes, complete witness/data item count, and maximum stack items are
  separate metrics; none substitutes for another.
- **Transaction weight:** stripped transaction bytes multiplied by three plus
  total serialized transaction bytes. Equivalently, multiply stripped bytes
  by four and add witness serialization plus the two marker/flag bytes for
  a witness transaction. Record only for a complete transaction; the complete
  Taproot witness already includes the locking script and control block. See
  the [Core-checked example](core-validation.md).
- **Maximum stack items:** peak combined main and alt stack unless a record
  explicitly says main-only. Table memory and unrelated live protocol state
  must be disclosed.
- **Executed opcodes:** actual executed non-push operations for the stated
  branch and input. Static opcode count is a different metric.
- **Validation weight:** tapscript validation budget consumed under the stated
  interpreter and transaction context.
- **Generation/execution time:** wall time is diagnostic, not a consensus
  property. Record CPU, build profile, sample count, and dispersion.

## Boundaries

Use one of these phrases as the start of every `includes` value:

- `fragment-only:` generated operation only.
- `fragment-with-memory:` setup, operation, and cleanup.
- `complete-leaf:` witness-consuming predicate through clean truthy result.
- `complete-transaction:` serialized transaction and prevout context.

Then state whether inputs, constants, hints, tables, cleanup, output comparison,
and witness serialization are included.

## Compilation policy

Repository measurements compile generated scripts through
`support::script::ScriptCompilation::compile_with_policy()`. With the
`rust-bitcoin-script` revision pinned in `Cargo.lock` (`124b561e`), the policy
applies `CompileOptions::ALL` to an unoptimized serialization of at most 32 KiB.
It applies `CompileOptions::NONE` above that cutoff because the optimizer's
fixpoint passes are prohibitively slow on multi-megabyte scripts.

Locking-script bytes and static opcodes refer to the final policy-produced
`ScriptBuf`. Tapleaf hashes, signatures, and byte-level vectors must use that
same final serialization. A measurement above the cutoff must be labeled
unoptimized; it must not be compared as though it received the same rewrite
passes as a smaller row. Independently compiled cost components can differ
from whole-script compilation because the optimizer rewrites across component
boundaries; attribute that delta explicitly so the reported components sum to
the final serialized size.

Resource probes must also preserve the work they intend to measure. A known
computation followed by unused-output cleanup can optimize to `OP_TRUE`,
erasing its temporary stack peak. Use runtime witness inputs and an observable
fragment output, or explicitly identified raw consensus-boundary vectors;
measure the final executed serialization. See the
[BLAKE3 counterexample](negative-results/compiler-validation-runtime.md#constant-cleanup-erases-the-resource-being-tested).

## Setup and amortization

For reusable lookup memory, report setup/cleanup and per-query costs separately.
For `n` uses:

```text
total(n) = setup + cleanup + n * per_use
amortized(n) = total(n) / n
```

State stack coexistence constraints. For each measured `n`, report cumulative
hint items and the complete input item count when hints are used. Every witness
item in a complete leaf is present on the initial stack, and operands, tables,
intermediates, outputs, and unrelated protocol state also count while live, so
do not derive a repetition limit from `floor(1000 / hint_items)` alone. Byte
amortization can select a construction that cannot compose under the 1,000-item
combined main-plus-alt-stack limit.

## Execution environment

Every measured result must identify:

- interpreter and immutable revision;
- script context (legacy, P2WSH, or tapscript);
- enabled consensus checks;
- policy rules, if claimed;
- transaction context, if signature or validation-weight behavior matters.

New Rust experiment generators should obtain resolved Git identities from
[`support::provenance`](../src/support/provenance.rs), which embeds `Cargo.lock`
at build time. Record both interpreter and compiler; do not copy a historical
pin into a fresh run. An old binary retains its embedded lockfile even after
the file on disk changes. This identifies the resolved source, not uncommitted
edits in a Cargo Git checkout. Historical artifacts retain the identities under
which they were actually measured.

The current local metrics primarily use `bitcoin-scriptexec` in tapscript mode.
Some helpers disable the stack limit. Such measurements remain useful for
algorithmic comparison but are classified `research-unlimited` until validated
under strict rules.

The [shared execution wrapper](../src/support/README.md) explicitly records
`stack_limit_enforced`. Since 2026-09-10 it checks entry and every instruction,
including data pushes, and rejects oversized witness elements in both modes.
Its repaired peak statistic includes the failing instruction's live depth.
After adoption of interpreter `4b7269a4`, entry/per-step checks run in that
dependency directly; the duplicate wrapper checks are removed. Historical
reports keep their original interpreter pins. The separate
[`support::tapscript` profiles](../src/support/README.md#explicit-fragment-profiles)
distinguish consensus-oriented options from the supported relay-policy subset.
Their `OP_SUCCESSx` pre-scan outcomes have no executed-stack or validation-budget
statistics; unsupported opcodes produce no local verdict. Neither case may be
reported as ordinary interpreter rejection or silently assigned a measured peak.
Earlier strict-helper success alone did not exclude entry or transient-push
overflow; see [NR-043](negative-results/index.md#nr-043-upstream-stack-limit-enforcement-misses-entry-and-data-pushes).
Even after this repair, local stack enforcement does not establish full
consensus or policy validity, executed-opcode counts, or correctly framed
Taproot signature budgets. Revalidate the specific configuration before
strengthening its evidence or deployment class.

## Ordering objectives

There is no universal “best.” Comparison pages may minimize script bytes,
witness bytes, stack peak, validation weight, setup cost, or a stated weighted
combination. A current-best claim must name its constraints and objective.
