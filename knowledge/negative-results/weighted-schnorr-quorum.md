# Weighted quorum scheduling limits

When each weight has one key, group setup and transfer can cost more
than applying each weight directly. At three keys the grouped leaf
uses 125 bytes and 20 executed non-push operations, versus 121 and
19. Both have 132 data-witness bytes, peak five, and 100 validation
units. The respective complete witnesses are 292 and 288 bytes.

Grouping leaves both the dense witness shape and the signature
validation charge unchanged. At 64 keys, both cases run 64 native
signature checks and charge 600 units for the same 12 nonempty
slots. The savings come from routing and weight application.
An early-exit check after reaching quorum would change the
contract by ignoring later nonempty signatures. The focused test
rejects malformed or replayed signatures after enough weight is
already present.

The 995-key grouped fixture has no combined-stack headroom. Its
first group contains a single weight-15 key, triggering the
constant multiplier's worst-case live state. A further preserved
item triggers the local stack-size error. At that width both
leaves are unoptimized under the central 32-KiB cutoff.

See the [matched fixtures](../../src/signatures/quorum/README.md#script-metrics).
Evidence is `locally-reproduced` and execution is `unclassified`.
