# Primitive name

One-paragraph scope and threat-model summary.

## Parameters

List every public parameter, its valid range, and its default. Say “no default”
when callers must choose.

## Script metrics

State exactly what each measurement includes. Script and serialized witness
sizes must use metric markers maintained by `tests/primitive_metrics.rs`.

| Configuration | Locking script | Unlocking witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| Default | <!-- metric:key -->0<!-- /metric:key --> bytes | ... | ... |

## Security

State concrete classical security bounds, one-time-use requirements,
assumptions, and whether the construction is non-standard or experimental.

## Script compatibility and standardness

Cover bare script, P2SH, P2WSH, and tapscript separately. Distinguish opcode
compatibility from consensus limits and relay/mining policy. Link to
[`docs/script-types.md`](script-types.md) and
[`docs/standardness.md`](standardness.md).

## Witness and hints

Document item order, encoding, public/secret status, and whether hints are
mandatory.

## Stack contract

Document preconditions, postconditions, main/alt-stack use, and cleanup.

## Operational notes

Document performance, composition constraints, test coverage, and known
limitations.

## Knowledge-base integration

Add or update an atomic record in `knowledge/catalog.json` and a page under
`knowledge/primitives/`. Link the relevant comparisons, techniques, protocol
maps, primary sources, negative results, and open problems. Run
`python3 tools/kb.py validate` before committing.
