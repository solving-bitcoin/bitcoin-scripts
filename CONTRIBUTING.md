# Contributing research knowledge

Contributions may add code, knowledge, or both. A useful knowledge-only entry is
welcome when an important external construction has no local implementation.

Before contributing, read [`AGENTS.md`](AGENTS.md),
[`knowledge/cost-model.md`](knowledge/cost-model.md), and
[`knowledge/evidence.md`](knowledge/evidence.md).

Enable the repository pre-commit checks once per clone:

```sh
git config core.hooksPath .githooks
```

The hook checks Rust formatting and validates the knowledge base on every
commit. Because these checks read the checkout, the hook requires tracked files
to match the index and rejects every non-ignored untracked file. Ignored files
are outside this guard. The metric suite is available by explicit opt-in:

```sh
RUN_PRIMITIVE_METRICS=1 git commit
```

It is not run automatically on every source or README change because the full
suite is expensive.

## Minimum research contribution

- State exact semantics, assumptions, and comparison objective.
- Cite a primary source and pin an immutable revision when possible.
- Add or update an atomic catalog record and primitive page.
- Label the evidence and execution classes conservatively.
- State measurement inclusion boundaries and use `null`, never zero, for an
  unknown metric.
- Update affected comparisons, protocol maps, negative results, and open
  problems.
- Add deterministic reproduction tests when claiming local reproduction.
- Include malformed and boundary cases for any verifier.

Run:

```sh
python3 tools/kb.py validate
cargo test --locked
```

For implementation changes, update metric snapshots only when the changed
number is intentional and explained. Use:

```sh
UPDATE_PRIMITIVE_METRICS=1 cargo test --test primitive_metrics
```

Do not promote a result to `differentially-validated` merely because a test
compares two functions that share the same implementation logic.
