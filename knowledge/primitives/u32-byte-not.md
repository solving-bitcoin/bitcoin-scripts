# Checked u32 bytewise complement

`arithmetic::u32::stack::u32_not` consumes one u32 represented by four
canonical byte limbs and returns the same word shape with every byte replaced
by `255 - byte`. The least-significant byte remains on top, matching the
normal u32 stack representation.

- **Question:** can the bytewise complement already used inside SHA-256 be
  exposed as a reusable hostile-witness-safe u32 primitive without a lookup
  table?
- **Hypothesis:** four local range checks plus subtraction are smaller and
  simpler than a second Boolean table when callers need only NOT.
- **Comparison:** the checked fragment is compared with the crate-private
  unchecked SHA-256 helper; both use the same four-byte representation, while
  only the public fragment validates hostile limbs.
- **Threat model:** every input limb may be malformed, non-minimal, negative,
  or outside `0..=255`; the primitive checks both canonical ScriptNum encoding
  and numeric range before subtraction. A terminal predicate remains a caller
  obligation.
- **Execution:** `locally-reproduced`, `unclassified`; the local strict
  executor supplies tapscript context and the fragment is not a complete
  locking script.

The representative metric uses four canonical `0xff` data items, no hints,
and measures the checked fragment, output cleanup, and strict combined stack
peak. The SHA-256 kernel keeps using the unchecked helper to avoid changing
the established full-hash cost; that helper is crate-private and is not a
hostile-witness boundary.

See the [u32 overview](u32.md), [implementation README](../../src/arithmetic/u32/README.md),
and catalog record `arithmetic/u32-byte-not`.
