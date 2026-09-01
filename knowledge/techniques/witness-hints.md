# Witness hints

A hint moves expensive computation to the witness, but it is safe only when the
script constrains the relation that makes the hinted value unique or harmless.

For every hinted construction, document:

- hint generation algorithm and serialization order;
- whether the hint is public, secret, or derived;
- the equation checked by Script;
- range and canonicality checks;
- behavior for malformed or adversarial hints;
- whether original operands remain available for binding;
- witness bytes and stack peak attributable to hints.

Local examples include ScriptNum quotient hints and BN254 intermediate field
values. “The reference implementation generated the hint” is test setup, not a
security argument.
