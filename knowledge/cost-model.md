# Normalized cost model

Every measurement must state its boundary. A bare number without an inclusion
boundary is not comparable evidence.

## Primary metrics

- **Locking script bytes:** serialized generated fragment or complete leaf, as
  explicitly stated. Input pushes and terminal predicates are excluded unless
  `includes` says otherwise.
- **Unlocking witness bytes:** consensus serialization of the complete witness
  item vector being measured, including item count and CompactSize lengths.
- **Transaction weight:** base bytes multiplied by four plus witness bytes.
  Record only for a complete transaction.
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
`rust-bitcoin-script` revision pinned in `Cargo.lock` (`db35a663`), the policy
applies `CompileOptions::ALL` to an unoptimized serialization of at most 64 KiB.
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

## Setup and amortization

For reusable lookup memory, report setup/cleanup and per-query costs separately.
For `n` uses:

```text
total(n) = setup + cleanup + n * per_use
amortized(n) = total(n) / n
```

State stack coexistence constraints; byte amortization alone can select a
construction that cannot compose under the 1,000-item limit.

## Execution environment

Every measured result must identify:

- interpreter and immutable revision;
- script context (legacy, P2WSH, or tapscript);
- enabled consensus checks;
- policy rules, if claimed;
- transaction context, if signature or validation-weight behavior matters.

The current local metrics primarily use `bitcoin-scriptexec` in tapscript mode.
Some helpers disable the stack limit. Such measurements remain useful for
algorithmic comparison but are classified `research-unlimited` until validated
under strict rules.

## Ordering objectives

There is no universal “best.” Comparison pages may minimize script bytes,
witness bytes, stack peak, validation weight, setup cost, or a stated weighted
combination. A current-best claim must name its constraints and objective.
