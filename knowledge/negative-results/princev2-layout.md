# PRINCEv2 layout search boundaries

Objective: reduce policy-produced encryption-fragment bytes with a fixed
generation-time key, zero hints, 16 plaintext items and strict tapscript stack
limits. The retained result is documented in the
[primitive page](../primitives/princev2-u4.md).

Removing the separate 16-entry final-pair selector and correcting the shared
selector's pointer at runtime passed focused execution, but increased the
then-current zero/ones/published/random-key fragments from
6,144/6,195/6,292/6,241 to 6,194/6,240/6,336/6,281 bytes. The extra correction
at all 44 quartets outweighed setup, cleanup and shallower-address savings.
That discarded generator is not retained, so this is `inspected` experiment
evidence, not a general impossibility claim. The retained swap placing the
final selector at depth 16 does save bytes.

The earlier inverse-S-box XOR-12 row-removal measurement used an invalid
intermediate layout: downstream addresses and
cleanup still assumed the old table length. Dynamic packing must rebase both
the pair-pointer region and cleanup. Current row selection does this and
compares full changing costs, using smaller memory to break byte-score ties.

The optional `optimized::schedule_tests::compare_stack_schedule_candidates`
experiment searches quartet orders and cyclic orientations. The global
order-only beam shaved three compiled bytes off the corresponding greedy
baseline, while the wider orientation search found nine modeled routing bytes.
Longer preparation prefixes gave no additional improvement in the bounded
search. These tiny gains are not used to justify a more complex production
schedule. The test remains available for subsequent research.

Masked-CNOT and opposite-output sharing sketches did not produce a cheaper
executable core in this pass. A lookup returns one stack item; multi-output
packed values need an explicit, priced decoding circuit. No sub-5,000-byte
claim follows from the algebraic M-hat reformulation alone.
