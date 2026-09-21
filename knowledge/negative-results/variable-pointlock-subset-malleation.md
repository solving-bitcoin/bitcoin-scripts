# Variable point-lock subsets do not enforce a global revelation count

A variable-cardinality P2SH pool verifies one through five selected point
openings and permits empty optional frames. Fixing the total number of
revelations across all pools in an offchain codec creates a combinatorial
antichain, but the individual Bitcoin scripts do not enforce that global
constraint. It is not sufficient to add a decoder-side count check and call
the construction a secure publication mechanism.

For the common-G experiment, 176 pools with exactly 638 selected points have
more than 2^2048 possible codewords. Consider a valid publication with those
638 revelations. At least one pool contains multiple active frames. An
observer can keep one of its openings, remove another, re-encode the remaining
lookup indices, and fill the now unused frame with empty elements. The modified
scriptSig still satisfies that pool's one-through-five predicate. It reveals
637 points globally and is outside the intended codec.

The mutation can preserve every input outpoint, sequence, amount, and output.
The [BIP341 signature message](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#common-signature-message)
does not include other inputs' scriptSigs, so a signed P2TR helper input does
not prevent this mutation. The point-lock signatures themselves use the
legacy SINGLE constant and remain valid. Changing the scriptSig changes the
legacy transaction identifier; it does not invalidate the copied helper
signature. The same observation applies to an authorization signature that
does not commit to this unlocking-data choice.

If the surrounding BitVM3 protocol treats an invalid decoded publication as
a punishable assertion, third-party mutation may cause failure before the
honest transaction confirms. Decoder rejection identifies the malformed
message but does not, by itself, establish safe handling of it. A repair must
bind the relevant count/selection to the authenticated spend or demonstrate
that such mutations cannot harm the publisher in the complete protocol.

The current baseline uses a fixed number of independently authenticated
openings per pool. An attacker cannot remove one and still satisfy its Script
predicate. Canonicalization of equivalent selection orders remains a decoder
task, but it does not change the selected set or its cardinality.

Evidence: `inspected` for the combined mutation argument. Both the larger and
smaller local variable-subset predicates are separately
`differentially-validated`, with positive fixtures `policy-validated`, in the
[Core report](../../research/pointlocks-2026-09-17/sum_lookup_core_check.json).
That report does not exercise the complete signed-helper substitution as one
attack fixture. The failed global-weight protocol composition remains
`unclassified`; it is not a consensus-rule violation, and invalid global
codewords may be perfectly valid Bitcoin spends.

See the [construction and measured limits](../../research/pointlocks-2026-09-17/sum-lookup.md)
and [sum-key extraction](../../research/pointlocks-2026-09-17/sum-pointlock.md).

## Conditional sequence-binding extension

A bounded, tested conditional repair uses a constant CSV check in every inactive
branch. With five slots numbered j=0..4 and mandatory slot zero, inactive slot
j requires `<5-j> CHECKSEQUENCEVERIFY DROP`. A canonical opening with t active
slots sets this input's sequence to `5-t`. Any opening with fewer than t
active slots has a first inactive index at most `t-1`, requiring a sequence
at least `6-t`, so it fails against the original sequence. Holes do not bypass
this inequality and no runtime counter is needed.

Four three-byte checks add exactly twelve compiled bytes: the 507-byte candidate
becomes 519 bytes. The [CSV probe](../../examples/pointlock_sum_csv_probe.rs)
and [Core report](../../research/pointlocks-2026-09-17/sum_csv_core_check.json)
validate all five canonical counts, rejection of removed revelations at a
fixed sequence, and acceptance after increasing the sequence. The report
passes 31 cases, including one historical control. Positive exact fixtures
are `differentially-validated` and `policy-validated`. It requires version two,
appropriate block-based sequence flags, and funding maturity sufficient for
the largest relative sequence value four. See [BIP112](https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki)
and [BIP68](https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki).

The essential extra assumption is **unavoidable authorization binding all
input sequences**. A helper signature has that binding only while its input
is retained. These point-lock scripts cannot require that helper's presence;
omitting or replacing it allows an attacker to raise sequences and use fewer
revealed labels. An outer protocol must prevent or safely handle that spend.
Thus the CSV idea is a conditional component, not a completed protocol repair
or a replacement for the fixed-cardinality baseline.
