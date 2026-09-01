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
