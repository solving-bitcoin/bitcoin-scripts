# Canonical ScriptNum boundary

`scriptint::verify_canonical()` preserves one top-stack ScriptNum only when
its raw item is the unique minimal encoding of an at-most-four-byte value. It
rejects negative zero, redundant sign bytes, and items longer than four bytes.

- **Evidence:** locally reproduced with boundary and malformed-encoding tests.
- **Deployment:** unclassified; the fragment is exercised by the repository's
  local tapscript helper, not differentially validated against Bitcoin Core.
- **Cost:** 5 bytes, one representative 4-byte witness item, and a 4-item
  combined peak.
- **Scope:** this is raw encoding canonicality, not a numeric range check or a
  complete locking script. A caller still needs its own terminal predicate and
  any protocol-specific value bounds.

See the [implementation README](../../src/arithmetic/scriptint/README.md)
and the `arithmetic/scriptnum-canonical` catalog record.
