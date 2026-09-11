# ScriptNum canonical-byte boundary

## Question

Can enabled Bitcoin Script opcodes prove that a hostile stack item is the
unique minimally encoded byte representation of a ScriptNum, independent of
relay-policy `MINIMALDATA` enforcement?

## Finding

The current repository exposes `OP_SIZE` and numeric comparisons, but no
enabled byte-slicing primitive (`OP_SPLIT` is disabled) and no `OP_NUM2BIN`
normalization path. Numeric interpretation therefore cannot inspect the
highest serialized byte needed to reject negative-zero and redundant sign
padding for arbitrary-width inputs. A caller can validate a numeric range, but
that does not bind the raw byte representation.

This is an `inspected` boundary result, not an impossibility proof. A future
byte primitive, a fixed-width protocol encoding, or policy-level
`MINIMALDATA` enforcement could change the result. Consensus-sensitive
protocols must not silently promote policy minimality to a consensus property.

## Reproduction

The opcode inventory and existing canonicality notes can be checked with:

```sh
rg -n 'OP_SPLIT|OP_NUM2BIN|OP_BIN2NUM|MINIMALDATA|OP_SIZE' src knowledge
```

Related local code documents numeric-range checks without byte-unique binding
in [`src/arithmetic/u4/README.md`](../../src/arithmetic/u4/README.md) and
[`knowledge/primitives/u4.md`](../../knowledge/primitives/u4.md).

## Acceptance criterion

Close this result only with an executable, consensus-scoped adapter that
rejects negative-zero, redundant sign padding, and boundary-width encodings,
or with a fixed-width protocol design that makes raw-byte uniqueness
unnecessary and measures its conversion cost.
