# Bitcoin Script primitive atlas

This directory is the knowledge layer of Bitcoin Lab. It maps the known design
space, normalizes evidence and costs, and connects protocol requirements to
reproducible constructions. The local Rust library is one source of evidence;
it is not the boundary of the atlas.

The catalog is explicitly time-scoped. Its current review date is
**2026-09-01**. A record's `as_of` field says when its claims were last checked.
Missing records are unknown coverage, not proof of nonexistence.

## How to answer a research question

1. Identify the primitive class in the [taxonomy](taxonomy.md).
2. Read the applicable [comparison](comparisons/index.md).
3. Filter the [machine-readable catalog](catalog.json) by objective and
   execution class.
4. Check the record's evidence level and follow its source and test links.
5. Check [negative results](negative-results/index.md) and
   [open problems](open-problems.md) before starting new work.
6. For a complete construction, follow the dependency graph in
   [protocol maps](protocols/index.md).

Useful commands:

```sh
python3 tools/kb.py list
python3 tools/kb.py search lookup
python3 tools/kb.py show hash/sha256-u4
python3 tools/kb.py best hash/sha256 script_bytes
python3 tools/kb.py validate
```

## Knowledge map

- [Schema and required fields](schema.md)
- [Terminology and taxonomy](taxonomy.md)
- [Normalized cost model](cost-model.md)
- [Evidence and confidence](evidence.md)
- [Primitive entries](primitives/index.md)
- [Reusable implementation techniques](techniques/index.md)
- [Cross-construction comparisons](comparisons/index.md)
- [Protocol dependency maps](protocols/index.md)
- [Primary-source registry](references/index.md)
- [Negative and dominated results](negative-results/index.md)
- [Open research problems](open-problems.md)
- [Research contribution workflow](research-workflow.md)

## Coverage snapshot

The initial catalog covers all primitive families documented or actively
implemented in this repository: ScriptNum, u4/u32/u31/bigint/RNS/prime-field
arithmetic, integer commitments, SHA-1, SHA-256, RIPEMD-160, BLAKE3, SHAKE256,
AES-128, PRINCEv2, Lamport/HORS/Winternitz one-time constructions, and BN254
field/group/pairing operations.

Most local execution evidence comes from `bitcoin-scriptexec`, frequently in a
tapscript context and sometimes without the consensus stack limit. Therefore
the initial catalog is stronger as a map of constructions and relative local
measurements than as a deployability database. Closing that gap is tracked in
[open problems](open-problems.md).
