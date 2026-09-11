# Fixed-width u4 lexicographic comparison

`arithmetic::u4::compare::lexicographic_le` compares two equal-width,
big-endian u4 vectors and returns whether `left <= right`. It range-checks all
hostile input nibbles before looking at the first differing position, consumes
both vectors, and leaves one truthy/falsy result. The primitive is useful for
Taproot node ordering and other fixed-width byte-domain commitments.

## Contract

For `n > 0`:

```text
left[0] ... left[n-1] right[0] ... right[n-1] -> result
```

Each input is one numeric nibble in `0..=15`, ordered most-significant first.
The result is true for equality and for the first differing nibble being lower
on the left. The implementation uses no witness hints; the `2*n` data items
all coexist at script entry.

The range check establishes numeric nibble validity. It does not establish a
unique raw ScriptNum byte encoding under consensus; callers that need byte
canonicality must use a separately specified policy or encoding boundary.

## Measurement

The representative `n=128` fragment includes all numeric range checks, the
first-difference state machine, operand cleanup, and a complete 256-item empty
nibble witness. It excludes any surrounding hash, terminal predicate, or
transaction context.

| Configuration | Script | Witness | Data items | Hints | Peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Two 128-nibble vectors | 7,500 bytes | 259 bytes | 256 | 0 (none) | 259 | 4,354 |

The strict local executor enforces the combined 1,000-item stack limit for the
measurement. Deployment remains `unclassified`: the fragment is below the
10,000-byte script-size ceiling but has more than 201 non-push opcodes and has
not been differentially validated against Bitcoin Core.

## Validation

The focused test exhaustively checks all `256 × 256` two-nibble byte pairs,
rejects an out-of-range nibble, and rejects zero-width generation. Run:

```sh
cargo test --locked arithmetic::u4::compare
cargo test --locked --test primitive_metrics u4_lexicographic_metrics_are_current
python3 tools/kb.py validate
```
